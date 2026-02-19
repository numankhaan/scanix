import platform
import subprocess
from ..core.utils import safe_print


def traceroute(target, max_hops=30):
    system = platform.system().lower()
    hops = []
    safe_print(f"Running traceroute to {target} (max {max_hops} hops)...", info=True)
    try:
        if system == "windows":
            # tracert output
            cmd = ["tracert", "-d", target]
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout.splitlines():
                hops.append(line.strip())
        else:
            # use traceroute
            cmd = ["traceroute", "-n", "-m", str(max_hops), target]
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout.splitlines():
                hops.append(line.strip())
    except FileNotFoundError:
        safe_print("System traceroute/tracert not found on this machine.", warn=True)
    except Exception as e:
        safe_print(f"Traceroute error: {e}", error=True)
    return hops
