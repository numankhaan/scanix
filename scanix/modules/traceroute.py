"""Legacy system traceroute with validated arguments and a wall-time bound."""
import ipaddress
import platform
import re
import shutil
import subprocess  # nosec B404: fixed system utility, no shell or user-selected executable
from ..core.utils import safe_print


def traceroute(target, max_hops=30):
    if not isinstance(target, str) or not 1 <= len(target) <= 253:
        raise ValueError('traceroute target must be an IP or plain hostname')
    try:
        ipaddress.ip_address(target)
        if '%' in target:
            raise ValueError('scoped addresses are not supported')
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', target):
            raise ValueError('traceroute target must be an IP or plain hostname') from None
    if type(max_hops) is not int or not 1 <= max_hops <= 64:
        raise ValueError('max_hops must be within 1–64')
    windows = platform.system().lower() == 'windows'
    executable = shutil.which('tracert' if windows else 'traceroute')
    if not executable:
        safe_print('System traceroute/tracert not found on this machine.', warn=True)
        return []
    cmd = ([executable, '-d', '-h', str(max_hops), '-w', '1000', target] if windows else
           [executable, '-n', '-m', str(max_hops), '-w', '1', target])
    try:
        # Target cannot start with an option; executable is resolved independently.
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, timeout=max_hops * 4 + 5, check=False)  # nosec B603
        return [line.strip() for line in proc.stdout[:65536].splitlines()]
    except (OSError, subprocess.TimeoutExpired):
        safe_print('System traceroute failed or exceeded its time limit.', error=True)
        return []
