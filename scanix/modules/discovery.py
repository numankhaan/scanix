import subprocess
import platform
import ipaddress
from ..core.utils import safe_print

def ping_host(host, timeout=1000):
    """
    Use system 'ping' to check host reachability.
    timeout is milliseconds on Windows, seconds (float) on Unix depending on flags.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            # -n 1 (one ping), -w timeout in ms
            cmd = ["ping", "-n", "1", "-w", str(timeout), host]
        else:
            # macOS/BSD uses different flags; Linux uses -c and -W (in seconds)
            # We'll use -c 1 and -W 1 for Linux (timeout in sec)
            cmd = ["ping", "-c", "1", "-W", "1", host]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return proc.returncode == 0
    except Exception as e:
        safe_print(f"Ping command failed for {host}: {e}", warn=True)
        return False

def ping_sweep(network_cidr):
    """
    network_cidr: '192.168.1.0/24'
    Returns list of alive hosts.
    """
    net = ipaddress.ip_network(network_cidr, strict=False)
    alive = []
    safe_print(f"Starting ping sweep on {network_cidr} ...", info=True)
    for ip in net.hosts():
        ip_str = str(ip)
        if ping_host(ip_str):
            alive.append(ip_str)
            safe_print(f"{ip_str} is alive", success=True)
    return alive