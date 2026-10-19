//! Linux-only privileged boundary. No arbitrary commands, promiscuous mode or payload logs.
use crate::{connect, packet};
use std::collections::BTreeMap;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::{
    io::unix::AsyncFd,
    sync::{mpsc, watch},
    time::{self, Instant},
};

const RECEIVE_BYTES: usize = 65535;
const MAX_INTERFACES: usize = 16;

#[derive(Default)]
pub struct Counters {
    pub attempted: AtomicU64,
    pub syn_sent: AtomicU64,
    pub retries_sent: AtomicU64,
    pub resets_sent: AtomicU64,
    pub send_errors: AtomicU64,
    pub received: AtomicU64,
    pub queue_drops: AtomicU64,
}

pub use crate::syn_state::{Job, Kind};
pub struct Sent {
    pub id: usize,
    pub kind: Kind,
    pub at: Instant,
    pub error: Option<i32>,
}
pub enum Received {
    Packet(Box<[u8]>),
    Failure,
}

pub struct Backend {
    pub sources: Vec<Ipv4Addr>,
    sender: OwnedFd,
    captures: Vec<Arc<AsyncFd<OwnedFd>>>,
}

fn fd(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: plain integer arguments; a successful descriptor has exactly one owner.
    let value = unsafe {
        libc::socket(
            domain,
            kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            protocol,
        )
    };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(value) })
    }
}

fn interface(source: Ipv4Addr) -> io::Result<u32> {
    let mut addresses = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the list; all reads precede its single free below.
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut current = addresses;
    let mut index = 0;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null()
            && !entry.ifa_name.is_null()
            && unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
            if address.sin_addr.s_addr.to_ne_bytes() == source.octets() {
                index = unsafe { libc::if_nametoindex(entry.ifa_name) };
                if index != 0 {
                    break;
                }
            }
        }
        current = entry.ifa_next;
    }
    unsafe {
        libc::freeifaddrs(addresses);
    }
    if index == 0 {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "route_interface_unavailable",
        ))
    } else {
        Ok(index)
    }
}

/// Native process CPU/peak userspace RSS; failure remains unknown, not zero.
pub fn process_usage() -> (Option<f64>, Option<u64>) {
    let mut usage: libc::rusage = unsafe { zeroed() };
    // SAFETY: getrusage writes the correctly sized initialized output object.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (None, None);
    }
    let seconds = usage.ru_utime.tv_sec as f64
        + usage.ru_stime.tv_sec as f64
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1_000_000.;
    (
        Some(seconds),
        u64::try_from(usage.ru_maxrss)
            .ok()
            .and_then(|kb| kb.checked_mul(1024)),
    )
}

impl Backend {
    /// All scope, route/source, privilege and capture setup succeeds before any send job.
    pub fn setup(targets: &[IpAddr]) -> io::Result<Self> {
        if targets.iter().any(|ip| !matches!(ip,IpAddr::V4(v) if !v.is_unspecified() && !v.is_multicast() && !v.is_broadcast())) {
            return Err(io::Error::new(io::ErrorKind::Unsupported,"unsupported_syn_scope"));
        }
        let sender = fd(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW)?;
        let mut captures = BTreeMap::new();
        let mut sources = Vec::with_capacity(targets.len());
        for target in targets {
            // UDP connect performs route selection only: never write a payload.
            let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            route.connect((*target, 9))?;
            let source = match route.local_addr()?.ip() {
                IpAddr::V4(value) if !value.is_unspecified() => value,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "route_source_unavailable",
                    ))
                }
            };
            let index = interface(source)?;
            let existing_interfaces = captures.len();
            if let std::collections::btree_map::Entry::Vacant(slot) = captures.entry(index) {
                if existing_interfaces == MAX_INTERFACES {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "too_many_capture_interfaces",
                    ));
                }
                let capture = fd(
                    libc::AF_PACKET,
                    libc::SOCK_DGRAM,
                    (libc::ETH_P_IP as u16).to_be() as i32,
                )?;
                let mut address: libc::sockaddr_ll = unsafe { zeroed() };
                address.sll_family = libc::AF_PACKET as u16;
                address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
                address.sll_ifindex = index as i32;
                // SAFETY: address and option lengths match the corresponding initialized objects.
                if unsafe {
                    libc::bind(
                        capture.as_raw_fd(),
                        &address as *const _ as *const libc::sockaddr,
                        size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                let capacity: i32 = 1_048_576;
                if unsafe {
                    libc::setsockopt(
                        capture.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVBUF,
                        &capacity as *const _ as *const libc::c_void,
                        size_of::<i32>() as libc::socklen_t,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: OwnedFd retains the same valid descriptor until AsyncFd drops it.
                slot.insert(Arc::new(unsafe { AsyncFd::register(capture) }?));
            }
            sources.push(source);
        }
        Ok(Self {
            sources,
            sender,
            captures: captures.into_values().collect(),
        })
    }

    pub fn capture_drops(&self) -> Option<u64> {
        let mut drops = 0u64;
        for capture in &self.captures {
            let mut stats: libc::tpacket_stats = unsafe { zeroed() };
            let mut length = size_of::<libc::tpacket_stats>() as libc::socklen_t;
            // PACKET_STATISTICS resets counters. Read exactly once at finalization.
            if unsafe {
                libc::getsockopt(
                    capture.get_ref().as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_STATISTICS,
                    &mut stats as *mut _ as *mut libc::c_void,
                    &mut length,
                )
            } < 0
                || length as usize != size_of::<libc::tpacket_stats>()
            {
                return None;
            }
            drops += stats.tp_drops as u64;
        }
        Some(drops)
    }

    fn send(&self, probe: packet::Probe, reset: Option<u32>) -> io::Result<()> {
        let bytes = packet::tcp(probe, reset);
        let mut address: libc::sockaddr_in = unsafe { zeroed() };
        address.sin_family = libc::AF_INET as u16;
        address.sin_addr.s_addr = u32::from_ne_bytes(probe.target.octets());
        // SAFETY: initialized fixed-size bytes/address; no pointers outlive this syscall.
        let sent = unsafe {
            libc::sendto(
                self.sender.as_raw_fd(),
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                0,
                &address as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else if sent as usize != bytes.len() {
            Err(io::Error::new(io::ErrorKind::WriteZero, "short_raw_send"))
        } else {
            Ok(())
        }
    }

    pub fn receivers(
        &self,
        output: mpsc::Sender<Received>,
        stats: Arc<Counters>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        self.captures
            .iter()
            .map(|capture| {
                let capture = capture.clone();
                let output = output.clone();
                let stats = stats.clone();
                tokio::spawn(async move {
                    let mut bytes = vec![0u8; RECEIVE_BYTES];
                    let mut quantum = 0;
                    loop {
                        let mut guard = match capture.readable().await {
                            Ok(value) => value,
                            Err(_) => {
                                let _ = output.send(Received::Failure).await;
                                break;
                            }
                        };
                        let packet = guard.try_io(|inner| {
                            // SAFETY: buffer is allocated and bounded; MSG_TRUNC reports oversize explicitly.
                            let size = unsafe {
                                libc::recv(
                                    inner.get_ref().as_raw_fd(),
                                    bytes.as_mut_ptr() as *mut libc::c_void,
                                    bytes.len(),
                                    libc::MSG_TRUNC,
                                )
                            };
                            if size < 0 {
                                Err(io::Error::last_os_error())
                            } else {
                                Ok(size as usize)
                            }
                        });
                        match packet {
                            Err(_) => continue,
                            Ok(Err(_)) => {
                                let _ = output.send(Received::Failure).await;
                                break;
                            }
                            Ok(Ok(size)) => {
                                stats.received.fetch_add(1, Ordering::Relaxed);
                                if size > bytes.len()
                                    || output
                                        .try_send(Received::Packet(
                                            bytes[..size.min(bytes.len())].into(),
                                        ))
                                        .is_err()
                                {
                                    stats.queue_drops.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        quantum += 1;
                        if quantum == 64 {
                            quantum = 0;
                            tokio::task::yield_now().await;
                        }
                    }
                })
            })
            .collect()
    }

    pub async fn transmitter(
        self: Arc<Self>,
        mut jobs: mpsc::Receiver<Job>,
        events: mpsc::Sender<Sent>,
        mut stop: watch::Receiver<bool>,
        rate: f64,
        deadline: Instant,
        stats: Arc<Counters>,
    ) {
        let mut next = Instant::now();
        loop {
            let job = tokio::select! { biased;
                _=stop.changed()=>break,
                _=time::sleep_until(deadline)=>break,
                job=jobs.recv()=>match job {Some(value)=>value,None=>break},
            };
            if *stop.borrow() {
                break;
            }
            tokio::select! { biased;
                _=stop.changed()=>break,
                _=time::sleep_until(deadline)=>break,
                _=time::sleep_until(next)=>{},
            }
            if *stop.borrow() || Instant::now() >= deadline {
                break;
            }
            if job.kind == Kind::Syn {
                stats.attempted.fetch_add(1, Ordering::Relaxed);
            }
            let result = self.send(job.probe, job.remote_sequence);
            let at = Instant::now();
            next = connect::next_start(at, rate);
            match result {
                Ok(()) => match job.kind {
                    Kind::Reset => {
                        stats.resets_sent.fetch_add(1, Ordering::Relaxed);
                    }
                    Kind::Syn | Kind::Retry => {
                        stats.syn_sent.fetch_add(1, Ordering::Relaxed);
                        if job.kind == Kind::Retry {
                            stats.retries_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                },
                Err(_) => {
                    stats.send_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            let event = Sent {
                id: job.id,
                kind: job.kind,
                at,
                error: result.err().map(|error| error.raw_os_error().unwrap_or(0)),
            };
            if events.send(event).await.is_err() {
                break;
            }
        }
    }
}
