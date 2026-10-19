//! Linux driver: bounded scheduler, independent paced transmitter and independent receivers.
use crate::{
    diagnostic, emit,
    linux_wire::{Backend, Counters, Received},
    protocol::Config,
    syn_state::State,
    Input, Writer,
};
use serde_json::json;
use std::{
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    time::{self, Instant},
};

pub async fn scan(
    cfg: Arc<Config>,
    targets: &[IpAddr],
    input: &mut mpsc::Receiver<Input>,
    cancel: &watch::Sender<bool>,
    writer: &Writer,
) -> Result<i32, ()> {
    let requested = cfg.requested(targets).map_err(|_| ())?;
    if requested == 0 {
        emit(writer, json!({"type":"ready","requested":0})).await?;
        emit(
            writer,
            json!({"type":"done","status":"complete","requested":0,"completed":0,"attempted":0,
            "peak_outstanding":0,"elapsed_seconds":0.,"reason":null,"syn_sent":0,"retries_sent":0,
            "resets_sent":0,"send_errors":0,"capture_drops":null,"queue_drops":0}),
        )
        .await?;
        return Ok(0);
    }
    let backend = match Backend::setup(targets) {
        Ok(value) => Arc::new(value),
        Err(error) => {
            let code = match error.kind() {
                std::io::ErrorKind::PermissionDenied => "raw_privilege_required",
                std::io::ErrorKind::Unsupported => "unsupported_syn_scope",
                _ => "raw_capture_or_route_setup_failed",
            };
            diagnostic(writer, code).await?;
            if error.kind() == std::io::ErrorKind::Unsupported {
                return Ok(4);
            }
            emit(writer,json!({"type":"done","status":"failed","requested":requested,"completed":0,"attempted":0,
                "peak_outstanding":0,"elapsed_seconds":0.,"reason":code,"syn_sent":0,"retries_sent":0,
                "resets_sent":0,"send_errors":0,"capture_drops":null,"queue_drops":0})).await?;
            return Ok(3);
        }
    };
    // OS entropy is acquired before ready/probe scheduling; never substitute a deterministic seed.
    let mut random = match File::open("/dev/urandom") {
        Ok(value) => value,
        Err(_) => {
            diagnostic(writer, "entropy_unavailable").await?;
            return Ok(3);
        }
    };
    let targets: Vec<Ipv4Addr> = targets
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v) => *v,
            _ => unreachable!(),
        })
        .collect();
    let mut state = State::new(cfg.clone(), targets, backend.sources.clone());
    emit(writer, json!({"type":"ready","requested":requested})).await?;
    let start = Instant::now();
    let deadline = start + Duration::from_millis(cfg.session_timeout_ms);
    let stats = Arc::new(Counters::default());
    let (jobs, job_rx) = mpsc::channel(32);
    let (sent, mut sent_rx) = mpsc::channel(32);
    let (received, mut received_rx) = mpsc::channel(32);
    let mut receivers = backend.receivers(received, stats.clone());
    let tx = tokio::spawn(backend.clone().transmitter(
        job_rx,
        sent,
        cancel.subscribe(),
        cfg.rate,
        deadline,
        stats.clone(),
    ));
    let mut stop = cancel.subscribe();
    let mut open_input = true;
    let mut failure = None;
    let mut drain = None;
    let mut drain_started = None;
    let mut tick = time::interval(Duration::from_millis(1));
    tick.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut output_failed = false;
    loop {
        let now = start.elapsed().as_millis() as u64;
        if Instant::now() >= deadline && drain.is_none() {
            failure = Some("session_budget_exhausted");
            cancel.send_replace(true);
        }
        if *stop.borrow() && drain.is_none() {
            drain_started = Some(Instant::now());
            drain = Some(Instant::now() + Duration::from_millis(200));
        }
        if state.complete() && drain.is_none() {
            drain_started = Some(Instant::now());
            drain = Some(Instant::now() + Duration::from_millis(cfg.cooldown_ms));
        }
        if drain.is_none() && (tx.is_finished() || receivers.iter().any(|task| task.is_finished()))
        {
            failure = Some("raw_worker_failure");
            cancel.send_replace(true);
            continue;
        }
        if drain.is_none() {
            // At most one new work item and one bounded queue admission each turn.
            if state.can_insert() {
                let mut entropy = [0u8; 6];
                if random.read_exact(&mut entropy).is_err() {
                    failure = Some("entropy_unavailable");
                    cancel.send_replace(true);
                    continue;
                }
                let sequence = u32::from_ne_bytes(entropy[..4].try_into().unwrap());
                let mut sport =
                    1024 + (u16::from_ne_bytes(entropy[4..].try_into().unwrap()) % 64512);
                while cfg.ports.binary_search(&sport).is_ok() {
                    sport = if sport == 65535 { 1024 } else { sport + 1 };
                }
                state.insert(sequence, sport);
            }
            if let Some(job) = state.job(now) {
                match jobs.try_send(job) {
                    Ok(()) => state.queued(job),
                    Err(mpsc::error::TrySendError::Full(_)) => {}
                    Err(_) => {
                        failure = Some("transmitter_failure");
                        cancel.send_replace(true);
                    }
                }
            }
            state.expire(now);
        }
        if let Some(row) = state.pop() {
            if emit(writer, row).await.is_err() {
                output_failed = true;
                break;
            }
        }
        if drain.is_some_and(|at| Instant::now() >= at) {
            break;
        }
        tokio::select! { biased;
            sent=sent_rx.recv(),if !tx.is_finished()=>{
                if let Some(sent)=sent {state.sent(sent.id,sent.kind,sent.at.saturating_duration_since(start).as_millis() as u64,sent.error);}
            },
            packet=received_rx.recv()=>{
                match packet {
                    Some(Received::Packet(bytes))=>state.receive(&bytes,start.elapsed().as_millis() as u64),
                    _=>{failure=Some("receiver_failure");cancel.send_replace(true);},
                }
            },
            _=stop.changed()=>{},
            command=input.recv(),if open_input=>{
                match command {Some(Input::Eof)|None=>open_input=false,
                    _=>{failure=Some("unexpected_frame_during_scan");cancel.send_replace(true);},}
            },
            _=tick.tick()=>{},
        }
    }
    let receive_cooldown = drain_started
        .map(|at| at.elapsed().as_millis() as u64)
        .unwrap_or(0);
    // Always stop tasks before inspecting counters or returning, including broken stdout.
    tx.abort();
    let _ = tx.await;
    for receiver in &receivers {
        receiver.abort();
    }
    for receiver in receivers.drain(..) {
        let _ = receiver.await;
    }
    if output_failed {
        return Err(());
    }
    // Drain send acknowledgments already queued before cancellation/worker exit.
    while let Ok(sent) = sent_rx.try_recv() {
        state.sent(
            sent.id,
            sent.kind,
            sent.at.saturating_duration_since(start).as_millis() as u64,
            sent.error,
        );
    }
    while let Ok(event) = received_rx.try_recv() {
        match event {
            Received::Packet(bytes) => state.receive(&bytes, start.elapsed().as_millis() as u64),
            Received::Failure => failure = Some("receiver_failure"),
        }
    }
    state.cancel(start.elapsed().as_millis() as u64);
    while let Some(row) = state.pop() {
        emit(writer, row).await?;
    }
    let drops = backend.capture_drops();
    if failure.is_none()
        && (drops.is_some_and(|v| v > 0) || stats.queue_drops.load(Ordering::Relaxed) > 0)
    {
        failure = Some("capture_loss");
    }
    if failure.is_none() && stats.send_errors.load(Ordering::Relaxed) > 0 {
        failure = Some("transmission_failure");
    }
    let (status, exit) = if failure.is_some() {
        ("failed", 3)
    } else if *cancel.borrow() {
        ("interrupted", 130)
    } else {
        ("complete", 0)
    };
    if let Some(code) = failure {
        diagnostic(writer, code).await?;
    }
    let (cpu, rss) = crate::linux_wire::process_usage();
    emit(writer,json!({"type":"done","status":status,"requested":requested,"completed":state.completed,
        "attempted":stats.attempted.load(Ordering::Relaxed),"peak_outstanding":state.peak,"peak_per_host":state.peak_per_host,
        "elapsed_seconds":start.elapsed().as_secs_f64(),"reason":failure,"syn_sent":stats.syn_sent.load(Ordering::Relaxed),
        "retries_sent":stats.retries_sent.load(Ordering::Relaxed),"resets_sent":stats.resets_sent.load(Ordering::Relaxed),
        "send_errors":stats.send_errors.load(Ordering::Relaxed),"received_packets":stats.received.load(Ordering::Relaxed),
        "matched_responses":state.matched,"duplicate_responses":state.duplicates,"unmatched_packets":state.unmatched,
        "late_responses":state.late,"timeouts":state.timeouts,"queue_drops":stats.queue_drops.load(Ordering::Relaxed),
        "native_cpu_seconds":cpu,"native_peak_rss_bytes":rss,"capture_drops":drops,"cooldown_ms":cfg.cooldown_ms,"receive_cooldown_ms":receive_cooldown})).await?;
    Ok(exit)
}
