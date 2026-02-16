import socket
import struct
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from .os_fingerprint import guess_os_from_ttl
from .services import get_service_name
from .banner import grab_banner_for_port
from .utils import safe_print

progress_lock = threading.Lock()

def scan_single_port(target, port, do_banner=False):
    result = {"target": target, "port": port, "protocol": "tcp", "status": "closed", "service": get_service_name(port), "banner": None, "os": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        res = sock.connect_ex((target, port))
        if res == 0:
            result["status"] = "open"
            safe_print(f"Port {port} open ({result['service']})", success=True)
            # try banner if requested
            if do_banner:
                banner = grab_banner_for_port(target, port)
                if banner:
                    result["banner"] = banner
                    safe_print(f"    Banner: {banner[:200]}...", info=True)
            # try TTL (best-effort)
            try:
                ttl = struct.unpack("!B", sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1))[0]
                result["os"] = guess_os_from_ttl(ttl)
                if result["os"] != "Unknown":
                    safe_print(f"    OS guess: {result['os']}", info=True)
            except Exception:
                pass
        sock.close()
    except Exception as e:
        safe_print(f"Error scanning port {port}: {e}", error=True)
    return result

def scan_ports(target, start_port, end_port, banner=False, max_workers=100):
    safe_print(f"\n--- Scanix TCP Connect Scanner ---", info=True)
    safe_print(f"Target: {target}  Ports: {start_port}-{end_port}", info=True)
    safe_print(f"Started: {datetime.now()}\n", info=True)

    ports = list(range(start_port, end_port + 1))
    total = len(ports)

    results = []

    # Thread-safe counters
    counter_lock = threading.Lock()
    scanned = 0
    next_progress = 10

    def worker(p):
        nonlocal scanned, next_progress

        r = scan_single_port(target, p, do_banner=banner)
        results.append(r)

        # Thread-safe progress update
        with counter_lock:
            scanned += 1
            percent = int((scanned / total) * 100)

            if percent >= next_progress:
                safe_print(f"Scanning... {next_progress}%", info=True)
                next_progress += 10

    worker_count = min(max_workers, total or 1)

    with ThreadPoolExecutor(max_workers=worker_count) as ex:
        futures = [ex.submit(worker, p) for p in ports]
        for _ in as_completed(futures):
            pass

    safe_print("\nScan completed.", success=True)

    return results