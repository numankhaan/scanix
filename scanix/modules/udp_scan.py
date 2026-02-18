# Copyright (c) 2026 Nouman Ali Khan

import socket
from ..core.utils import safe_print


def probe_udp_port(target, port, timeout=2.0):
    """
    Lightweight UDP probe:
    - Send a small datagram
    - If we get a UDP reply -> open
    - If timeout -> open|filtered (common UDP behavior)
    """
    result = {
        "target": target,
        "port": port,
        "protocol": "udp",
        "status": "open|filtered",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        sock.sendto(b"\x00", (target, port))

        try:
            _data, _addr = sock.recvfrom(1024)
            result["status"] = "open"
        except socket.timeout:
            result["status"] = "open|filtered"
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            safe_print(f"UDP probe error on {port}: {e}", warn=True)

        sock.close()
        return result

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        safe_print(f"UDP send error to {port}: {e}", error=True)
        return result


def scan_udp_range(target, start_port, end_port, timeout=2.0):
    results = []
    try:
        for port in range(start_port, end_port + 1):
            results.append(probe_udp_port(target, port, timeout=timeout))
    except KeyboardInterrupt:
        safe_print("\nUDP scan interrupted. Returning partial results.", warn=True)
    return results
