use serde::Deserialize;
use std::collections::HashSet;
use std::io::{self, BufRead, Read};
use std::net::IpAddr;

pub const VERSION: u32 = 3;
pub const MAX_FRAME: usize = 65536;
pub const MAX_TARGETS: usize = 65536;
pub const MAX_PORTS: usize = 4096;
pub const MAX_RESULTS: usize = 1_000_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Start(Config),
    Target { ip: IpAddr },
    Completed { ids: Vec<usize> },
    Run,
    Cancel,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protocol: u32,
    pub method: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub min_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub adaptive: bool,
    pub retries: u8,
    pub cooldown_ms: u64,
    pub concurrency: usize,
    pub per_host: usize,
    pub rate: f64,
    pub max_targets: usize,
    pub max_results: usize,
    pub session_timeout_ms: u64,
    #[serde(default)]
    pub shard_index: usize,
    #[serde(default = "one")]
    pub shard_count: usize,
    #[serde(skip)]
    pub completed: Vec<bool>,
}

fn one() -> usize {
    1
}

impl Config {
    pub fn selected(&self, id: usize) -> bool {
        id % self.shard_count == self.shard_index
            && !self.completed.get(id).copied().unwrap_or(false)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.protocol != VERSION {
            return Err("incompatible_protocol");
        }
        if self.method != "connect" && self.method != "syn" {
            return Err("unsupported_method");
        }
        if self.ports.is_empty()
            || self.ports.len() > MAX_PORTS
            || self.ports.contains(&0)
            || !self.ports.windows(2).all(|p| p[0] < p[1])
        {
            return Err("invalid_ports");
        }
        if !(1..=300_000).contains(&self.timeout_ms)
            || !(10..=300_000).contains(&self.min_timeout_ms)
            || self.min_timeout_ms > self.max_timeout_ms
            || self.max_timeout_ms > 300_000
        {
            return Err("invalid_timeout");
        }
        if self.shard_count == 0 || self.shard_count > 1024 || self.shard_index >= self.shard_count
        {
            return Err("invalid_shard");
        }
        if self.retries > 5
            || self.cooldown_ms > 1000
            || !(1..=1024).contains(&self.concurrency)
            || !(1..=1024).contains(&self.per_host)
            || !self.rate.is_finite()
            || self.rate < 0.000001
            || self.rate > 10000.0
            || !(1..=MAX_TARGETS).contains(&self.max_targets)
            || !(1..=MAX_RESULTS).contains(&self.max_results)
            || !(100..=86_400_000).contains(&self.session_timeout_ms)
        {
            return Err("invalid_resource_limit");
        }
        Ok(())
    }

    pub fn requested(&self, targets: &[IpAddr]) -> Result<usize, &'static str> {
        if targets.len() > self.max_targets
            || targets.iter().collect::<HashSet<_>>().len() != targets.len()
        {
            return Err("invalid_target_scope");
        }
        let count = targets
            .len()
            .checked_mul(self.ports.len())
            .ok_or("scope_overflow")?;
        if count > self.max_results {
            return Err("scope_exceeds_result_limit");
        }
        if self
            .completed
            .iter()
            .enumerate()
            .any(|(id, done)| *done && (id >= count || id % self.shard_count != self.shard_index))
        {
            return Err("invalid_completed_scope");
        }
        Ok((0..count).filter(|id| self.selected(*id)).count())
    }
}

/// Never allocate an unbounded line, including a non-terminated malicious input.
pub fn read_frame<R: BufRead>(reader: &mut R) -> io::Result<Option<Command>> {
    let mut bytes = Vec::new();
    let size = reader
        .take((MAX_FRAME + 1) as u64)
        .read_until(b'\n', &mut bytes)?;
    if size == 0 {
        return Ok(None);
    }
    if size > MAX_FRAME || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid_frame_size_or_termination",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid_request_frame"))?;
    if let Some(object) = value.as_object() {
        let expected = match object.get("type").and_then(|v| v.as_str()) {
            Some("run" | "cancel") => Some(1),
            Some("target" | "completed") => Some(2),
            _ => None,
        };
        if expected.is_some_and(|count| object.len() != count) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown_request_fields",
            ));
        }
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid_request_frame"))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Cursor;
    pub fn config() -> Config {
        Config {
            protocol: VERSION,
            method: "connect".into(),
            ports: vec![22, 80],
            timeout_ms: 1000,
            min_timeout_ms: 100,
            max_timeout_ms: 5000,
            adaptive: true,
            retries: 1,
            cooldown_ms: 200,
            concurrency: 8,
            per_host: 4,
            rate: 100.,
            max_targets: 4096,
            max_results: MAX_RESULTS,
            session_timeout_ms: 60_000,
            shard_index: 0,
            shard_count: 1,
            completed: Vec::new(),
        }
    }
    #[test]
    fn shard_resume_partitions_are_disjoint_and_complete() {
        let ip = "127.0.0.1".parse().unwrap();
        let mut coverage = vec![0; 17];
        for shard in 0..7 {
            let mut c = config();
            c.ports = (1..=17).collect();
            c.shard_count = 7;
            c.shard_index = shard;
            for (id, count) in coverage.iter_mut().enumerate() {
                if c.selected(id) {
                    *count += 1;
                }
            }
            let before = c.requested(&[ip]).unwrap();
            c.completed = vec![false; 17];
            c.completed[shard] = true;
            assert_eq!(c.requested(&[ip]).unwrap(), before - 1);
            assert!(!c.selected(shard));
        }
        assert_eq!(coverage, vec![1; 17]);
        let mut c = config();
        c.shard_count = 0;
        assert_eq!(c.validate(), Err("invalid_shard"));
        c.shard_count = 1;
        c.completed = vec![false, false, true];
        assert!(c.requested(&[ip]).is_err());
    }
    #[test]
    fn strict_frames() {
        assert!(matches!(
            read_frame(&mut Cursor::new(b"{\"type\":\"run\"}\n")).unwrap(),
            Some(Command::Run)
        ));
        for data in [
            b"{\"type\":\"run\",\"extra\":1}\n".to_vec(),
            b"{\"type\":\"run\"}".to_vec(),
            vec![b'x'; MAX_FRAME + 100],
            b"{\"type\":\"target\",\"ip\":\"example.com\"}\n".to_vec(),
        ] {
            assert!(read_frame(&mut Cursor::new(data)).is_err());
        }
    }
    #[test]
    fn exact_frame_boundary_and_duplicate_fields() {
        let mut padded = b"{\"type\":\"run\"}".to_vec();
        padded.resize(MAX_FRAME - 1, b' ');
        padded.push(b'\n');
        assert!(matches!(
            read_frame(&mut Cursor::new(&padded)).unwrap(),
            Some(Command::Run)
        ));
        padded.insert(padded.len() - 1, b' ');
        assert!(read_frame(&mut Cursor::new(padded)).is_err());
        for malformed in [
            b"{\"type\":\"run\",\"type\":\"cancel\"}\n".as_slice(),
            b"{\"type\":\"target\",\"ip\":\"127.0.0.1\",\"ip\":\"::1\"}\n".as_slice(),
            b"{\"type\":\"target\",\"ip\":2130706433}\n".as_slice(),
        ] {
            assert!(read_frame(&mut Cursor::new(malformed)).is_err());
        }
    }
    #[test]
    fn config_limits() {
        let base = config();
        assert!(base.validate().is_ok());
        let mut c = base.clone();
        c.ports = vec![80, 80];
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.rate = f64::NAN;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.protocol = 1;
        assert_eq!(c.validate(), Err("incompatible_protocol"));
        let mut c = base.clone();
        c.method = "udp".into();
        assert_eq!(c.validate(), Err("unsupported_method"));
        let mut c = base.clone();
        c.concurrency = 1025;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.session_timeout_ms = 86_400_001;
        assert!(c.validate().is_err());
        let ip = "::1".parse().unwrap();
        assert_eq!(base.requested(&[ip]).unwrap(), 2);
        assert!(base.requested(&[ip, ip]).is_err());
        let mut c = base;
        c.max_results = 1;
        assert!(c.requested(&[ip]).is_err());
    }
}
