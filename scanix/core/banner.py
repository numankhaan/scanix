import socket
from .utils import safe_print

COMMON_PROBES = {
    "HTTP": b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "SMTP": b"HELO example.com\r\n",
    "POP3": b"\r\n",
    "IMAP": b"\r\n",
}

def grab_banner_for_port(target, port, timeout=2):
    """
    Attempt to connect and read a banner, optionally send a tiny probe for some known services.
    Returns banner string or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # choose small probe if we know the service by port
        probe = None
        if port == 80 or port == 8080:
            probe = COMMON_PROBES["HTTP"]
        elif port in (25, 587):
            probe = COMMON_PROBES["SMTP"]

        if probe:
            try:
                sock.sendall(probe)
            except Exception:
                pass

        try:
            data = sock.recv(2048)
            if not data:
                sock.close()
                return None
            banner = data.decode(errors="ignore").strip()
            sock.close()
            return banner
        except Exception:
            sock.close()
            return None
    except Exception as e:
        # connection failed
        return None