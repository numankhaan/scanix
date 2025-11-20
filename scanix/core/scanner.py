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
    scanned = 0
    progress = 10
    results = []

    def worker(p):
        nonlocal scanned, progress
        r = scan_single_port(target, p, do_banner=banner)
        results.append(r)
        scanned += 1
        percent = int((scanned / total) * 100)
        if percent >= progress:
            safe_print(f"Scanning... {progress}%", info=True)
            progress += 10

    with ThreadPoolExecutor(max_workers=min(max_workers, total or 1)) as ex:
        tasks = [ex.submit(worker, p) for p in ports]
        for _ in as_completed(tasks):
            pass

    safe_print("\nScan completed.", success=True)
    return results