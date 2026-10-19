//! Deterministic SYN work state. Clock values are monotonic milliseconds supplied by the driver.
use crate::{
    connect::Adaptive,
    packet::{self, Evidence, Probe},
    protocol::Config,
};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Syn,
    Retry,
    Reset,
}
#[derive(Clone, Copy, Debug)]
pub struct Job {
    pub id: usize,
    pub probe: Probe,
    pub kind: Kind,
    pub remote_sequence: Option<u32>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Queued,
    Waiting,
    Reset,
    ResetQueued,
}
struct Pending {
    probe: Probe,
    phase: Phase,
    attempts: u8,
    first: Option<u64>,
    last: Option<u64>,
    evidence: Option<Evidence>,
    early: Option<(Evidence, u64)>,
    reset_sent: bool,
    reset_error: Option<i32>,
}

pub struct State {
    cfg: Arc<Config>,
    targets: Vec<Ipv4Addr>,
    sources: Vec<Ipv4Addr>,
    cursor: usize,
    ports: Vec<usize>,
    active: Vec<usize>,
    rtt: Vec<Adaptive>,
    pending: HashMap<usize, Pending>,
    ready: VecDeque<Value>,
    recent: VecDeque<(Probe, bool)>,
    pub completed: usize,
    pub peak: usize,
    pub peak_per_host: usize,
    pub matched: u64,
    pub duplicates: u64,
    pub unmatched: u64,
    pub late: u64,
    pub timeouts: u64,
}
impl State {
    pub fn new(cfg: Arc<Config>, targets: Vec<Ipv4Addr>, sources: Vec<Ipv4Addr>) -> Self {
        let count = targets.len();
        let rtt = (0..count).map(|_| Adaptive::new(&cfg)).collect();
        Self {
            cfg,
            targets,
            sources,
            cursor: 0,
            ports: vec![0; count],
            active: vec![0; count],
            rtt,
            pending: HashMap::new(),
            ready: VecDeque::new(),
            recent: VecDeque::new(),
            completed: 0,
            peak: 0,
            peak_per_host: 0,
            matched: 0,
            duplicates: 0,
            unmatched: 0,
            late: 0,
            timeouts: 0,
        }
    }
    pub fn can_insert(&self) -> bool {
        self.pending.len() + self.ready.len() < self.cfg.concurrency
            && self.ports.iter().enumerate().any(|(host, port)| {
                *port < self.cfg.ports.len() && self.active[host] < self.cfg.per_host
            })
    }
    pub fn insert(&mut self, sequence: u32, sport: u16) -> bool {
        if self.pending.len() + self.ready.len() >= self.cfg.concurrency || self.targets.is_empty()
        {
            return false;
        }
        for _ in 0..self.targets.len() {
            let host = self.cursor;
            self.cursor = (self.cursor + 1) % self.targets.len();
            if self.ports[host] == self.cfg.ports.len() || self.active[host] >= self.cfg.per_host {
                continue;
            }
            let port = self.ports[host];
            self.ports[host] += 1;
            self.active[host] += 1;
            let id = host * self.cfg.ports.len() + port;
            let probe = Probe {
                source: self.sources[host],
                target: self.targets[host],
                sport,
                port: self.cfg.ports[port],
                sequence,
            };
            self.pending.insert(
                id,
                Pending {
                    probe,
                    phase: Phase::New,
                    attempts: 0,
                    first: None,
                    last: None,
                    evidence: None,
                    early: None,
                    reset_sent: false,
                    reset_error: None,
                },
            );
            self.peak = self.peak.max(self.pending.len());
            self.peak_per_host = self.peak_per_host.max(self.active[host]);
            return true;
        }
        false
    }
    fn timeout(&self, id: usize, attempts: u8) -> u64 {
        let base = if self.cfg.adaptive {
            self.rtt[id / self.cfg.ports.len()].value()
        } else {
            self.cfg.timeout_ms as f64
        };
        (base * 2f64.powi(attempts.saturating_sub(1) as i32))
            .min(if self.cfg.adaptive {
                self.cfg.max_timeout_ms as f64
            } else {
                300_000.
            })
            .ceil() as u64
    }
    pub fn job(&self, now: u64) -> Option<Job> {
        let mut candidates: Vec<_> = self.pending.iter().collect();
        candidates.sort_by_key(|(id, p)| (p.phase != Phase::Reset, **id));
        for (&id, p) in candidates {
            let kind = match p.phase {
                Phase::New => Kind::Syn,
                Phase::Reset => Kind::Reset,
                Phase::Waiting
                    if p.attempts <= self.cfg.retries
                        && now >= p.last.unwrap() + self.timeout(id, p.attempts) =>
                {
                    Kind::Retry
                }
                _ => continue,
            };
            return Some(Job {
                id,
                probe: p.probe,
                kind,
                remote_sequence: p.evidence.and_then(|e| e.response_sequence),
            });
        }
        None
    }
    pub fn queued(&mut self, job: Job) {
        let p = self.pending.get_mut(&job.id).unwrap();
        if job.kind == Kind::Reset {
            p.phase = Phase::ResetQueued;
        } else {
            p.phase = Phase::Queued;
            p.attempts += 1;
        }
    }
    pub fn sent(&mut self, id: usize, kind: Kind, now: u64, error: Option<i32>) {
        let Some(p) = self.pending.get_mut(&id) else {
            return;
        };
        if kind == Kind::Reset {
            p.reset_sent = error.is_none();
            p.reset_error = error;
            self.finish(id, now);
            return;
        }
        if error.is_some() && p.evidence.is_none() {
            p.evidence = Some(Evidence {
                state: "error",
                reason: "socket_error",
                response_sequence: None,
                icmp_code: None,
            });
            p.reset_error = error;
            self.finish(id, now);
            return;
        }
        p.first.get_or_insert(now);
        p.last = Some(now);
        if p.evidence.is_none() {
            p.phase = Phase::Waiting;
        }
        if let Some((evidence, received)) = p.early.take() {
            self.apply(id, evidence, received.max(now));
        }
    }
    fn apply(&mut self, id: usize, evidence: Evidence, now: u64) {
        let p = self.pending.get_mut(&id).unwrap();
        if p.evidence.is_some() {
            self.duplicates += 1;
            return;
        }
        self.matched += 1;
        if p.attempts == 1 && matches!(evidence.state, "open" | "closed") {
            self.rtt[id / self.cfg.ports.len()]
                .observe(now.saturating_sub(p.first.unwrap()) as f64);
        }
        p.evidence = Some(evidence);
        if evidence.state == "open" {
            p.phase = Phase::Reset;
        } else {
            self.finish(id, now);
        }
    }
    pub fn receive(&mut self, bytes: &[u8], now: u64) {
        let found = self.pending.iter().find_map(|(&id, p)| {
            if p.attempts == 0 {
                None
            } else {
                packet::classify(p.probe, bytes).map(|e| (id, e))
            }
        });
        if let Some((id, evidence)) = found {
            let p = self.pending.get_mut(&id).unwrap();
            if p.first.is_some() {
                self.apply(id, evidence, now);
            } else if p.early.is_none() {
                p.early = Some((evidence, now));
            } else {
                self.duplicates += 1;
            }
        } else if let Some((_, matched)) = self
            .recent
            .iter()
            .find(|(p, _)| packet::classify(*p, bytes).is_some())
        {
            if *matched {
                self.duplicates += 1;
            } else {
                self.late += 1;
            }
        } else {
            self.unmatched += 1;
        }
    }
    pub fn expire(&mut self, now: u64) {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&id, p)| {
                (p.phase == Phase::Waiting
                    && p.attempts > self.cfg.retries
                    && now >= p.last.unwrap() + self.timeout(id, p.attempts) + self.cfg.cooldown_ms)
                    .then_some(id)
            })
            .collect();
        for id in expired {
            self.timeouts += 1;
            self.finish(id, now);
        }
    }
    fn finish(&mut self, id: usize, now: u64) {
        let p = self.pending.remove(&id).unwrap();
        let matched = p.evidence.is_some_and(|e| e.state != "error");
        let evidence = p.evidence.unwrap_or(Evidence {
            state: "unknown",
            reason: "no_response",
            response_sequence: None,
            icmp_code: None,
        });
        let host = id / self.cfg.ports.len();
        self.active[host] -= 1;
        self.recent.push_back((p.probe, matched));
        if self.recent.len() > 1024 {
            self.recent.pop_front();
        }
        self.ready.push_back(json!({"type":"result","id":id,"target_index":host,"ip":p.probe.target,
            "port":p.probe.port,"state":evidence.state,"reason":evidence.reason,
            "error_code":if evidence.state=="error" {p.reset_error} else {None},
            "elapsed_seconds":now.saturating_sub(p.first.unwrap_or(now)) as f64/1000.,"attempts":p.attempts,
            "evidence":{"matched_response":matched,"icmp_code":evidence.icmp_code,
                "reset_sent":p.reset_sent,"reset_error_code":if evidence.state!="error" {p.reset_error} else {None}}}));
        self.completed += 1;
    }
    pub fn cancel(&mut self, now: u64) {
        let matched: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(&id, p)| p.evidence.map(|_| id))
            .collect();
        for id in matched {
            self.finish(id, now);
        }
        self.pending.clear();
    }
    pub fn pop(&mut self) -> Option<Value> {
        self.ready.pop_front()
    }
    pub fn complete(&self) -> bool {
        self.completed == self.targets.len() * self.cfg.ports.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> State {
        let mut cfg = crate::protocol::tests::config();
        cfg.method = "syn".into();
        cfg.retries = 1;
        cfg.cooldown_ms = 200;
        cfg.adaptive = false;
        cfg.concurrency = 2;
        cfg.per_host = 1;
        State::new(
            Arc::new(cfg),
            vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 3)],
            vec![Ipv4Addr::LOCALHOST; 2],
        )
    }
    fn response(job: Job) -> [u8; 40] {
        let p = job.probe;
        let mut b = packet::tcp(
            Probe {
                source: p.target,
                target: p.source,
                sport: p.port,
                port: p.sport,
                sequence: 10,
            },
            None,
        );
        b[28..32].copy_from_slice(&p.sequence.wrapping_add(1).to_be_bytes());
        b[33] = 0x12;
        b
    }
    #[test]
    fn bounded_round_robin_and_independent_jobs() {
        let mut s = state();
        assert!(s.can_insert());
        assert!(s.insert(1, 40000));
        assert!(s.insert(2, 40001));
        assert!(!s.insert(3, 40002));
        assert!(!s.can_insert());
        let a = s.job(0).unwrap();
        s.queued(a);
        let b = s.job(0).unwrap();
        s.queued(b);
        assert_ne!(a.id / 2, b.id / 2);
        assert_eq!(s.peak, 2);
        assert_eq!(s.peak_per_host, 1);
        s.sent(a.id, a.kind, 0, None);
        s.sent(b.id, b.kind, 0, None);
        assert!(s.job(999).is_none());
        let retry = s.job(1000).unwrap();
        assert_eq!(retry.kind, Kind::Retry);
    }
    #[test]
    fn retry_and_final_cooldown_are_bounded() {
        let mut s = state();
        s.insert(1, 40000);
        let job = s.job(0).unwrap();
        s.queued(job);
        s.sent(job.id, job.kind, 0, None);
        s.expire(1000);
        assert!(s.pop().is_none());
        let retry = s.job(1000).unwrap();
        s.queued(retry);
        s.sent(retry.id, retry.kind, 1000, None);
        s.expire(3199);
        assert!(s.pop().is_none());
        s.expire(3200);
        let row = s.pop().unwrap();
        assert_eq!(row["state"], "unknown");
        assert_eq!(row["attempts"], 2);
        assert_eq!(s.timeouts, 1);
        assert!(s.job(100000).is_none());
    }
    #[test]
    fn reply_before_send_ack_waits_for_actual_send_and_reset() {
        let mut s = state();
        s.insert(1, 40000);
        let job = s.job(0).unwrap();
        s.queued(job);
        let reply = response(job);
        s.receive(&reply, 5);
        assert!(s.pop().is_none());
        s.sent(job.id, job.kind, 1, None);
        assert!(s.pop().is_none());
        let reset = s.job(5).unwrap();
        assert_eq!(reset.kind, Kind::Reset);
        assert_eq!(reset.remote_sequence, Some(10));
        s.queued(reset);
        s.sent(reset.id, Kind::Reset, 10, None);
        let row = s.pop().unwrap();
        assert_eq!(row["state"], "open");
        assert_eq!(row["evidence"]["reset_sent"], true);
        s.receive(&reply, 11);
        assert_eq!(s.duplicates, 1);
        assert!(s.pop().is_none());
    }
    #[test]
    fn send_failure_and_cancellation_never_invent_closed_ports() {
        let mut s = state();
        s.insert(1, 40000);
        let job = s.job(0).unwrap();
        s.queued(job);
        s.receive(&response(job), 2);
        s.sent(job.id, job.kind, 1, Some(13));
        assert_eq!(s.pop().unwrap()["state"], "error");
        s.insert(2, 40001);
        let job = s.job(5).unwrap();
        s.queued(job);
        s.sent(job.id, job.kind, 5, None);
        s.receive(&response(job), 6);
        s.cancel(7);
        let row = s.pop().unwrap();
        assert_eq!(row["state"], "open");
        assert_eq!(row["evidence"]["reset_sent"], false);
        assert!(!s.complete());
        assert!(s.pop().is_none());
    }
    #[test]
    fn ready_rows_count_against_capacity_and_late_replies_do_not_reopen() {
        let mut s = state();
        s.insert(1, 40000);
        s.insert(2, 40001);
        for _ in 0..2 {
            let job = s.job(0).unwrap();
            s.queued(job);
            s.sent(job.id, job.kind, 0, Some(13));
        }
        assert!(!s.can_insert());
        s.pop();
        assert!(s.can_insert());
        let mut s = state();
        s.cfg = Arc::new(Config {
            retries: 0,
            ..(*s.cfg).clone()
        });
        s.insert(3, 40002);
        let job = s.job(0).unwrap();
        s.queued(job);
        s.sent(job.id, job.kind, 0, None);
        s.expire(1200);
        assert_eq!(s.pop().unwrap()["state"], "unknown");
        s.receive(&response(job), 1201);
        assert_eq!(s.late, 1);
        assert!(s.pop().is_none());
    }
}
