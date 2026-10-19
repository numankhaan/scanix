use crate::protocol::Config;
use serde::Serialize;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::watch,
    time::{self, Instant},
};

#[derive(Debug, Serialize)]
pub struct ResultRow {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub id: usize,
    pub target_index: usize,
    pub ip: IpAddr,
    pub port: u16,
    pub state: &'static str,
    pub reason: &'static str,
    pub error_code: Option<i32>,
    pub elapsed_seconds: f64,
}

pub fn classify(error: &io::Error) -> (&'static str, &'static str) {
    use io::ErrorKind::*;
    match error.kind() {
        ConnectionRefused => ("closed", "connection_refused"),
        TimedOut | WouldBlock => ("unknown", "timeout"),
        NetworkUnreachable | HostUnreachable | NetworkDown => ("error", "routing_failure"),
        PermissionDenied => ("error", "permission_denied"),
        OutOfMemory | AddrInUse | AddrNotAvailable => ("error", "resource_exhausted"),
        _ => {
            let code = error.raw_os_error().unwrap_or(0);
            #[cfg(target_os = "linux")]
            let resource = [12, 23, 24, 105];
            #[cfg(target_os = "macos")]
            let resource = [12, 23, 24, 55];
            #[cfg(windows)]
            let resource = [10024, 10055, 10049, 10048];
            #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
            let resource = [-1; 4];
            if resource.contains(&code) {
                ("error", "resource_exhausted")
            } else {
                ("error", "socket_error")
            }
        }
    }
}

pub async fn probe(
    target_index: usize,
    ip: IpAddr,
    port_index: usize,
    cfg: Arc<Config>,
    timeout_ms: f64,
    mut stop: watch::Receiver<bool>,
    attempts: Arc<AtomicU64>,
) -> Option<ResultRow> {
    if *stop.borrow() {
        return None;
    }
    let port = cfg.ports[port_index];
    let start = Instant::now();
    attempts.fetch_add(1, Ordering::Relaxed);
    let response = tokio::select! {
        biased;
        response=time::timeout(Duration::from_secs_f64(timeout_ms/1000.),TcpStream::connect(SocketAddr::new(ip,port))) => response,
        _=stop.changed() => return None,
    };
    let (state, reason, error_code) = match response {
        Ok(Ok(socket)) => {
            drop(socket);
            ("open", "connection_succeeded", None)
        }
        Ok(Err(error)) => {
            let (s, r) = classify(&error);
            (s, r, error.raw_os_error())
        }
        Err(_) => ("unknown", "timeout", None),
    };
    Some(ResultRow {
        kind: "result",
        id: target_index * cfg.ports.len() + port_index,
        target_index,
        ip,
        port,
        state,
        reason,
        error_code,
        elapsed_seconds: start.elapsed().as_secs_f64(),
    })
}

pub struct Adaptive {
    initial: f64,
    min: f64,
    max: f64,
    srtt: Option<f64>,
    variation: f64,
}
impl Adaptive {
    pub fn new(c: &Config) -> Self {
        Self {
            initial: (c.timeout_ms as f64).clamp(c.min_timeout_ms as f64, c.max_timeout_ms as f64),
            min: c.min_timeout_ms as f64,
            max: c.max_timeout_ms as f64,
            srtt: None,
            variation: 0.,
        }
    }
    pub fn value(&self) -> f64 {
        self.srtt
            .map(|s| s + 4. * self.variation)
            .unwrap_or(self.initial)
            .clamp(self.min, self.max)
    }
    pub fn observe(&mut self, millis: f64) {
        match self.srtt {
            None => {
                self.srtt = Some(millis);
                self.variation = millis / 2.;
            }
            Some(old) => {
                self.variation = 0.75 * self.variation + 0.25 * (old - millis).abs();
                self.srtt = Some(0.875 * old + 0.125 * millis);
            }
        }
    }
}

/// Called by the single scheduler after the pacing deadline fires; no burst credit.
pub fn next_start(now: Instant, rate: f64) -> Instant {
    now + Duration::from_secs_f64(1. / rate)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification_and_adaptive_bounds() {
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            ("closed", "connection_refused")
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::TimedOut)),
            ("unknown", "timeout")
        );
        let cfg = crate::protocol::tests::config();
        let mut r = Adaptive::new(&cfg);
        for sample in [0., 100_000., 1., 3.] {
            r.observe(sample);
            assert!((100. ..=5000.).contains(&r.value()));
        }
        let start = Instant::now();
        assert_eq!(next_start(start, 2.) - start, Duration::from_millis(500));
    }
    #[tokio::test]
    async fn loopback_and_pre_cancel() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = crate::protocol::tests::config();
        cfg.ports = vec![listener.local_addr().unwrap().port()];
        let cfg = Arc::new(cfg);
        let (stop, rx) = watch::channel(false);
        let count = Arc::new(AtomicU64::new(0));
        let result = probe(
            0,
            "127.0.0.1".parse().unwrap(),
            0,
            cfg.clone(),
            5000.,
            rx.clone(),
            count.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            (result.state, result.reason),
            ("open", "connection_succeeded")
        );
        stop.send_replace(true);
        assert!(probe(
            0,
            "127.0.0.1".parse().unwrap(),
            0,
            cfg,
            5000.,
            rx,
            count.clone()
        )
        .await
        .is_none());
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }
}
