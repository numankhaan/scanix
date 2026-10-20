//! Pure, bounded IPv4 SYN construction and correlation. No privileges or I/O.
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Probe {
    pub source: Ipv4Addr,
    pub target: Ipv4Addr,
    pub sport: u16,
    pub port: u16,
    pub sequence: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    pub state: &'static str,
    pub reason: &'static str,
    pub response_sequence: Option<u32>,
    pub icmp_code: Option<u8>,
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += ((pair[0] as u32) << 8) + pair.get(1).copied().unwrap_or(0) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn word(bytes: &[u8], position: usize) -> u16 {
    u16::from_be_bytes([bytes[position], bytes[position + 1]])
}
fn long(bytes: &[u8], position: usize) -> u32 {
    u32::from_be_bytes(bytes[position..position + 4].try_into().unwrap())
}

pub fn tcp(probe: Probe, reset_for: Option<u32>) -> [u8; 40] {
    let mut bytes = [0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&40u16.to_be_bytes());
    bytes[4..6].copy_from_slice(&(probe.sequence as u16).to_be_bytes());
    bytes[6] = 0x40; // No fragmented probes.
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&probe.source.octets());
    bytes[16..20].copy_from_slice(&probe.target.octets());
    bytes[20..22].copy_from_slice(&probe.sport.to_be_bytes());
    bytes[22..24].copy_from_slice(&probe.port.to_be_bytes());
    let sequence = if reset_for.is_some() {
        probe.sequence.wrapping_add(1)
    } else {
        probe.sequence
    };
    bytes[24..28].copy_from_slice(&sequence.to_be_bytes());
    if let Some(remote_sequence) = reset_for {
        bytes[28..32].copy_from_slice(&remote_sequence.wrapping_add(1).to_be_bytes());
    }
    bytes[32] = 0x50;
    bytes[33] = if reset_for.is_some() { 0x14 } else { 2 };
    bytes[34..36].copy_from_slice(&64240u16.to_be_bytes());
    let mut pseudo = [0u8; 32];
    pseudo[..8].copy_from_slice(&bytes[12..20]);
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    pseudo[12..].copy_from_slice(&bytes[20..]);
    let value = checksum(&pseudo);
    bytes[36..38].copy_from_slice(&value.to_be_bytes());
    let value = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&value.to_be_bytes());
    bytes
}

struct Ip<'a> {
    source: Ipv4Addr,
    target: Ipv4Addr,
    protocol: u8,
    payload: &'a [u8],
}

fn ip(bytes: &[u8], quote: bool) -> Option<Ip<'_>> {
    if bytes.len() < 20 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header = (bytes[0] as usize & 15) * 4;
    let length = word(bytes, 2) as usize;
    if header < 20
        || header > bytes.len()
        || length < header
        || (!quote && length > bytes.len())
        || word(bytes, 6) & 0xbfff != 0
        || checksum(&bytes[..header]) != 0
    {
        return None;
    }
    Some(Ip {
        source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        target: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        payload: &bytes[header..length.min(bytes.len())],
    })
}

pub fn classify(probe: Probe, bytes: &[u8]) -> Option<Evidence> {
    let packet = ip(bytes, false)?;
    if packet.target != probe.source {
        return None;
    }
    let payload = packet.payload;
    if packet.protocol == 6 && packet.source == probe.target {
        if payload.len() < 20
            || word(payload, 0) != probe.port
            || word(payload, 2) != probe.sport
            || long(payload, 8) != probe.sequence.wrapping_add(1)
        {
            return None;
        }
        let header = (payload[12] as usize >> 4) * 4;
        if header < 20 || header > payload.len() || payload[13] & 0x10 == 0 {
            return None;
        }
        if payload[13] & 0x07 == 0x04 {
            return Some(Evidence {
                state: "closed",
                reason: "syn_rst_ack",
                response_sequence: None,
                icmp_code: None,
            });
        }
        if payload[13] & 0x07 == 0x02 {
            return Some(Evidence {
                state: "open",
                reason: "syn_ack",
                response_sequence: Some(long(payload, 4)),
                icmp_code: None,
            });
        }
    }
    if packet.protocol == 1 && payload.len() >= 36 && matches!(payload[0], 3 | 11) {
        let quoted = ip(&payload[8..], true)?;
        let tcp = quoted.payload;
        if quoted.protocol != 6
            || quoted.source != probe.source
            || quoted.target != probe.target
            || tcp.len() < 8
            || word(tcp, 0) != probe.sport
            || word(tcp, 2) != probe.port
            || long(tcp, 4) != probe.sequence
        {
            return None;
        }
        let admin = payload[0] == 3 && matches!(payload[1], 9 | 10 | 13);
        return Some(Evidence {
            state: if admin { "filtered" } else { "unknown" },
            reason: if admin {
                "icmp_administratively_prohibited"
            } else {
                "icmp_unreachable_or_path_error"
            },
            response_sequence: None,
            icmp_code: Some(payload[1]),
        });
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn probe() -> Probe {
        Probe {
            source: Ipv4Addr::LOCALHOST,
            target: Ipv4Addr::new(127, 0, 0, 2),
            sport: 45000,
            port: 443,
            sequence: u32::MAX,
        }
    }
    fn repair_ip(bytes: &mut [u8]) {
        bytes[10..12].fill(0);
        let sum = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    fn reply(flags: u8) -> [u8; 40] {
        let p = probe();
        let mut bytes = tcp(
            Probe {
                source: p.target,
                target: p.source,
                sport: p.port,
                port: p.sport,
                sequence: 123,
            },
            None,
        );
        bytes[28..32].copy_from_slice(&p.sequence.wrapping_add(1).to_be_bytes());
        bytes[33] = flags;
        bytes
    }
    #[test]
    fn syn_ack_reset_and_checksums() {
        let p = probe();
        let syn = tcp(p, None);
        assert_eq!(checksum(&syn[..20]), 0);
        let mut pseudo = Vec::from(&syn[12..20]);
        pseudo.extend([0, 6, 0, 20]);
        pseudo.extend(&syn[20..]);
        assert_eq!(checksum(&pseudo), 0);
        let response = reply(0x12);
        let evidence = classify(p, &response).unwrap();
        assert_eq!((evidence.state, evidence.reason), ("open", "syn_ack"));
        let reset = tcp(p, evidence.response_sequence);
        assert_eq!(long(&reset, 24), 0);
        assert_eq!(long(&reset, 28), 124);
        assert_eq!(reset[33], 0x14);
        assert_eq!(classify(p, &reply(0x14)).unwrap().state, "closed");
        assert_eq!(classify(p, &reply(0x52)).unwrap().state, "open");
    }
    #[test]
    fn unrelated_malformed_and_self_packets() {
        let p = probe();
        let good = reply(0x12);
        assert!(classify(p, &tcp(p, None)).is_none());
        for size in 0..good.len() {
            assert!(classify(p, &good[..size]).is_none());
        }
        for position in [12, 16, 20, 22, 28] {
            let mut bad = good;
            bad[position] ^= 1;
            repair_ip(&mut bad);
            assert!(classify(p, &bad).is_none());
        }
        for flags in [0, 2, 4, 0x13, 0x16] {
            let mut bad = good;
            bad[33] = flags;
            assert!(classify(p, &bad).is_none());
        }
        for position in [0, 2, 6, 32] {
            let mut bad = good;
            bad[position] = 0xff;
            if position != 0 {
                repair_ip(&mut bad);
            }
            assert!(classify(p, &bad).is_none());
        }
    }
    #[test]
    fn icmp_requires_exact_quoted_probe() {
        let p = probe();
        let request = tcp(p, None);
        let mut bytes = vec![0u8; 56];
        bytes[..20].copy_from_slice(&reply(0x14)[..20]);
        bytes[2..4].copy_from_slice(&56u16.to_be_bytes());
        bytes[9] = 1;
        bytes[20] = 3;
        bytes[21] = 13;
        bytes[28..].copy_from_slice(&request[..28]);
        repair_ip(&mut bytes);
        assert_eq!(classify(p, &bytes).unwrap().state, "filtered");
        bytes[21] = 1;
        assert_eq!(classify(p, &bytes).unwrap().state, "unknown");
        for index in [40, 44, 48, 50, 52] {
            let mut wrong = bytes.clone();
            wrong[index] ^= 1;
            assert!(classify(p, &wrong).is_none());
        }
        for length in 20..bytes.len() {
            assert!(classify(p, &bytes[..length]).is_none());
        }
    }
    #[test]
    fn duplicate_and_malformed_inputs_are_pure_and_bounded() {
        let p = probe();
        let response = reply(0x12);
        assert_eq!(classify(p, &response), classify(p, &response));
        let mut seed = 1u32;
        for length in 0..1024 {
            let bytes: Vec<u8> = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                    (seed >> 24) as u8
                })
                .collect();
            let _ = classify(p, &bytes);
        }
    }

    #[test]
    fn structured_mutations_never_accept_mismatched_endpoints_or_ack() {
        let p = probe();
        let response = reply(0x12);
        // Repair the outer checksum so mutations reach correlation logic rather
        // than all stopping at the first IP integrity check. Synthetic only.
        for position in (12..24).chain(28..32) {
            for bit in 0..8 {
                let mut bytes = response;
                bytes[position] ^= 1 << bit;
                repair_ip(&mut bytes);
                assert!(classify(p, &bytes).is_none());
            }
        }
        for offset in 0..response.len() {
            for bit in 0..8 {
                let mut bytes = response;
                bytes[offset] ^= 1 << bit;
                repair_ip(&mut bytes);
                assert_eq!(classify(p, &bytes), classify(p, &bytes));
            }
        }
    }
}
