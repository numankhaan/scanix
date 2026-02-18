"""
Syn scan using scapy. Requires root/admin privileges.
It sends SYN and waits for SYN/ACK (open) or RST (closed).
"""

from scapy.all import IP, TCP, sr1, conf
from ..core.utils import safe_print

conf.verb = 0  # scapy quiet


def syn_scan_port(target, port, timeout=1):
    result = {
        "target": target,
        "port": port,
        "protocol": "tcp_syn",
        "status": "filtered",
    }
    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            result["status"] = "filtered|open"
        elif resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN/ACK
                result["status"] = "open"
                # send RST to politely close
                sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=0.5)
            elif tcp_layer.flags == 0x14:  # RST/ACK
                result["status"] = "closed"
        else:
            result["status"] = "filtered"
    except PermissionError:
        safe_print(
            "SYN scan requires root/administrator privileges. Aborting SYN scan.",
            error=True,
        )
        raise
    except Exception as e:
        safe_print(f"SYN scan error on {port}: {e}", warn=True)
        result["status"] = "error"
    return result


def syn_scan_range(target, start_port, end_port, timeout=1):
    results = []
    try:
        for port in range(start_port, end_port + 1):
            r = syn_scan_port(target, port, timeout=timeout)
            results.append(r)
    except PermissionError:
        # bubble up so CLI can handle
        raise
    return results
