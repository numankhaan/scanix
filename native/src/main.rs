mod connect;
#[cfg(target_os = "linux")]
mod linux_wire;
#[cfg(any(target_os = "linux", test))]
mod packet;
mod protocol;
#[cfg(target_os = "linux")]
mod syn;
#[cfg(any(target_os = "linux", test))]
mod syn_state;
use protocol::{Command, Config};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::{self, Instant},
};

const CHANNEL: usize = 32;
enum Input {
    Frame(Command),
    Fault,
    Eof,
}
struct Output {
    value: Value,
    ack: oneshot::Sender<bool>,
}
type Writer = mpsc::Sender<Output>;

async fn emit(writer: &Writer, value: Value) -> Result<(), ()> {
    let (ack, done) = oneshot::channel();
    time::timeout(Duration::from_secs(5), async {
        writer.send(Output { value, ack }).await.map_err(|_| ())?;
        if done.await.map_err(|_| ())? {
            Ok(())
        } else {
            Err(())
        }
    })
    .await
    .map_err(|_| ())?
}
async fn diagnostic(writer: &Writer, code: &str) -> Result<(), ()> {
    emit(
        writer,
        json!({"type":"diagnostic","code":code,"fatal":true}),
    )
    .await
}

async fn scan(
    cfg: Arc<Config>,
    targets: &[IpAddr],
    input: &mut mpsc::Receiver<Input>,
    cancel: &watch::Sender<bool>,
    writer: &Writer,
) -> Result<i32, ()> {
    let requested = cfg.requested(targets).map_err(|_| ())?;
    emit(writer, json!({"type":"ready","requested":requested})).await?;
    let started = Instant::now();
    let deadline = started + Duration::from_millis(cfg.session_timeout_ms);
    let attempts = Arc::new(AtomicU64::new(0));
    let mut completed = 0;
    let mut peak = 0;
    let mut stop = cancel.subscribe();
    let mut next = Instant::now();
    let mut open_input = true;
    let mut failure = None;
    let workers = cfg.concurrency.min(cfg.per_host);
    'hosts: for (index, &ip) in targets.iter().enumerate() {
        let mut jobs: JoinSet<Option<connect::ResultRow>> = JoinSet::new();
        let mut port_index = 0;
        let mut rtt = connect::Adaptive::new(&cfg);
        while port_index < cfg.ports.len() || !jobs.is_empty() {
            while port_index < cfg.ports.len()
                && !cfg.selected(index * cfg.ports.len() + port_index)
            {
                port_index += 1;
            }
            if port_index == cfg.ports.len() && jobs.is_empty() {
                break;
            }
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                biased;
                row=jobs.join_next(),if !jobs.is_empty()=>{
                    match row {
                        Some(Ok(Some(row)))=>{
                            if row.state=="open" || row.state=="closed" { rtt.observe(row.elapsed_seconds*1000.); }
                            completed+=1;emit(writer,serde_json::to_value(row).map_err(|_|())?).await?;
                        },
                        Some(Err(_))=>{failure=Some("worker_failure");cancel.send_replace(true);},
                        _=>{},
                    }
                },
                _=stop.changed()=>{},
                command=input.recv(),if open_input=>{
                    match command {
                        Some(Input::Eof)|None=>open_input=false,
                        _=>{failure=Some("unexpected_frame_during_scan");cancel.send_replace(true);},
                    }
                },
                _=time::sleep_until(deadline)=>{failure=Some("session_budget_exhausted");cancel.send_replace(true);},
                _=time::sleep_until(next),if port_index<cfg.ports.len() && jobs.len()<workers=>{
                    // Check the absolute deadline even if completion traffic is continuously ready.
                    if Instant::now()>=deadline {failure=Some("session_budget_exhausted");cancel.send_replace(true);continue;}
                    next=connect::next_start(Instant::now(),cfg.rate);
                    let timeout=if cfg.adaptive {rtt.value()} else {cfg.timeout_ms as f64};
                    jobs.spawn(connect::probe(index,ip,port_index,cfg.clone(),timeout,stop.clone(),attempts.clone()));
                    port_index+=1;peak=peak.max(jobs.len());
                },
            }
        }
        // Drain completed rows, while unfinished sockets observe cancellation promptly.
        while let Some(row) = jobs.join_next().await {
            match row {
                Ok(Some(row)) => {
                    completed += 1;
                    emit(writer, serde_json::to_value(row).map_err(|_| ())?).await?;
                }
                Err(_) => {
                    failure = Some("worker_failure");
                    cancel.send_replace(true);
                }
                _ => {}
            }
        }
        if *stop.borrow() {
            break 'hosts;
        }
    }
    let interrupted = *cancel.borrow();
    let (status, code) = if failure.is_some() {
        ("failed", 3)
    } else if interrupted {
        ("interrupted", 130)
    } else {
        ("complete", 0)
    };
    if let Some(reason) = failure {
        diagnostic(writer, reason).await?;
    }
    emit(
        writer,
        json!({"type":"done","status":status,"requested":requested,"completed":completed,
        "attempted":attempts.load(Ordering::Relaxed),"peak_outstanding":peak,
        "elapsed_seconds":started.elapsed().as_secs_f64(),"reason":failure}),
    )
    .await?;
    Ok(code)
}

async fn engine(
    input: &mut mpsc::Receiver<Input>,
    cancel: &watch::Sender<bool>,
    writer: &Writer,
) -> Result<i32, ()> {
    emit(writer,json!({"type":"hello","protocol":protocol::VERSION,"engine":"scanix-rust",
        "engine_version":env!("CARGO_PKG_VERSION"),"capabilities":if cfg!(target_os="linux") {vec!["connect","syn_ipv4"]}else{vec!["connect"]},"limits":{
            "frame_bytes":protocol::MAX_FRAME,"targets":protocol::MAX_TARGETS,"ports":protocol::MAX_PORTS,
            "results":protocol::MAX_RESULTS,"channel_capacity":CHANNEL}})).await?;
    let mut startup_stop = cancel.subscribe();
    let first = if *startup_stop.borrow() {
        None
    } else {
        tokio::select! { _=startup_stop.changed()=>None, frame=input.recv()=>frame }
    };
    if *cancel.borrow() {
        emit(writer,json!({"type":"done","status":"interrupted","requested":0,"completed":0,
            "attempted":0,"peak_outstanding":0,"elapsed_seconds":0.,"reason":"cancelled_during_setup"})).await?;
        return Ok(130);
    }
    let mut cfg = match first {
        Some(Input::Frame(Command::Start(c))) => c,
        _ => {
            diagnostic(writer, "expected_start").await?;
            return Ok(2);
        }
    };
    if let Err(code) = cfg.validate() {
        diagnostic(writer, code).await?;
        return Ok(if code == "unsupported_method" { 4 } else { 2 });
    }
    let mut setup_stop = cancel.subscribe();
    let mut targets = Vec::new();
    let mut unique = std::collections::HashSet::new();
    loop {
        if *cancel.borrow() {
            emit(writer,json!({"type":"done","status":"interrupted","requested":targets.len()*cfg.ports.len(),
                "completed":0,"attempted":0,"peak_outstanding":0,"elapsed_seconds":0.,"reason":"cancelled_during_setup"})).await?;
            return Ok(130);
        }
        let command =
            tokio::select! { _=setup_stop.changed()=>continue, command=input.recv()=>command };
        match command {
            Some(Input::Frame(Command::Target { ip })) => {
                if targets.len() >= cfg.max_targets
                    || !unique.insert(ip)
                    || (targets.len() + 1) * cfg.ports.len() > cfg.max_results
                {
                    diagnostic(writer, "invalid_target_scope").await?;
                    return Ok(2);
                }
                targets.push(ip);
            }
            Some(Input::Frame(Command::Completed { ids })) => {
                if ids.is_empty() || ids.len() > 4096 {
                    diagnostic(writer, "invalid_completed_scope").await?;
                    return Ok(2);
                }
                for id in ids {
                    if id >= cfg.max_results || cfg.completed.get(id).copied().unwrap_or(false) {
                        diagnostic(writer, "invalid_completed_scope").await?;
                        return Ok(2);
                    }
                    cfg.completed.resize(cfg.completed.len().max(id + 1), false);
                    cfg.completed[id] = true;
                }
            }
            Some(Input::Frame(Command::Run)) => {
                if let Err(reason) = cfg.requested(&targets) {
                    diagnostic(writer, reason).await?;
                    return Ok(2);
                }
                if cfg.method == "syn" {
                    #[cfg(target_os = "linux")]
                    {
                        return syn::scan(Arc::new(cfg), &targets, input, cancel, writer).await;
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        diagnostic(writer, "unsupported_platform").await?;
                        return Ok(4);
                    }
                }
                return scan(Arc::new(cfg), &targets, input, cancel, writer).await;
            }
            _ => {
                diagnostic(writer, "expected_target_or_run").await?;
                return Ok(2);
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (commands, mut input) = mpsc::channel(CHANNEL);
    let (output, mut frames) = mpsc::channel::<Output>(CHANNEL);
    let (cancel, _) = watch::channel(false);
    let read_cancel = cancel.clone();
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        loop {
            let event = match protocol::read_frame(&mut reader) {
                Ok(Some(Command::Cancel)) => {
                    read_cancel.send_replace(true);
                    continue;
                }
                Ok(Some(command)) => Input::Frame(command),
                Ok(None) => Input::Eof,
                Err(_) => Input::Fault,
            };
            let terminal = matches!(event, Input::Eof | Input::Fault);
            if commands.blocking_send(event).is_err() || terminal {
                break;
            }
        }
    });
    std::thread::spawn(move || {
        let stdout = io::stdout();
        let mut writer = stdout.lock();
        while let Some(frame) = frames.blocking_recv() {
            let ok = serde_json::to_writer(&mut writer, &frame.value).is_ok()
                && writer.write_all(b"\n").is_ok()
                && writer.flush().is_ok();
            let _ = frame.ack.send(ok);
            if !ok {
                break;
            }
        }
    });
    let signal_cancel = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.send_replace(true);
        }
    });
    let code=engine(&mut input,&cancel,&output).await.unwrap_or_else(|_|{
        eprintln!("{{\"type\":\"diagnostic\",\"code\":\"output_failure_or_backpressure\",\"fatal\":true}}");3
    });
    // Stdin can be blocked in a standard reader thread. Do not join it on shutdown.
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn output_backpressure_has_absolute_deadline() {
        let (writer, _frames) = mpsc::channel(32);
        let start = Instant::now();
        assert!(emit(&writer, json!({"type":"hello"})).await.is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(5));
    }
    #[tokio::test]
    async fn cancellation_while_waiting_for_first_request() {
        let (_commands, mut input) = mpsc::channel(32);
        let (writer, mut frames) = mpsc::channel::<Output>(32);
        let (cancel, _) = watch::channel(false);
        let signal = cancel.clone();
        let collect = tokio::spawn(async move {
            let mut values = Vec::new();
            while let Some(frame) = frames.recv().await {
                values.push(frame.value);
                let _ = frame.ack.send(true);
                if values.last().unwrap()["type"] == "done" {
                    break;
                }
                signal.send_replace(true);
            }
            values
        });
        assert_eq!(engine(&mut input, &cancel, &writer).await.unwrap(), 130);
        let values = collect.await.unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1]["completed"], 0);
        assert_eq!(values[1]["status"], "interrupted");
    }
    #[tokio::test]
    async fn invalid_preflight_never_emits_ready_or_results() {
        for unsupported in [false, true] {
            let (commands, mut input) = mpsc::channel(32);
            let (writer, mut frames) = mpsc::channel::<Output>(32);
            let (cancel, _) = watch::channel(false);
            let mut cfg = protocol::tests::config();
            if unsupported {
                cfg.method = "udp".into();
            }
            commands
                .send(Input::Frame(Command::Start(cfg)))
                .await
                .unwrap();
            if !unsupported {
                let ip = "127.0.0.1".parse().unwrap();
                commands
                    .send(Input::Frame(Command::Target { ip }))
                    .await
                    .unwrap();
                commands
                    .send(Input::Frame(Command::Target { ip }))
                    .await
                    .unwrap();
            }
            let collect = tokio::spawn(async move {
                let mut values = Vec::new();
                while let Some(frame) = frames.recv().await {
                    values.push(frame.value);
                    let _ = frame.ack.send(true);
                    if values.last().unwrap()["type"] == "diagnostic" {
                        break;
                    }
                }
                values
            });
            assert_eq!(
                engine(&mut input, &cancel, &writer).await.unwrap(),
                if unsupported { 4 } else { 2 }
            );
            let values = collect.await.unwrap();
            assert_eq!(values.len(), 2);
            assert_eq!(values[0]["type"], "hello");
            assert_eq!(values[1]["type"], "diagnostic");
            assert_eq!(
                values[1]["code"],
                if unsupported {
                    "unsupported_method"
                } else {
                    "invalid_target_scope"
                }
            );
        }
    }
}
