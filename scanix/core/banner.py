"""Bounded best-effort plaintext evidence. No protocol or version confirmation."""
import socket
import re


def grab_banner_for_port(target, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET6 if ':' in target else socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))
            if port in (80, 8080):
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port in (25, 587):
                sock.sendall(b'HELO scanix\r\n')
            data = sock.recv(2048)
            return data.decode('utf-8', errors='replace').strip() or None
    except OSError:
        return None


def parse_service_version(port: int, banner: str):
    """
    Extract product + version hints from banners.
    Returns dict {product, version, extra} or None.
    """
    if not banner:
        return None

    b = banner.strip()

    # SSH example:
    # SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    if port == 22 or b.startswith("SSH-"):
        m = re.search(
            r"^SSH-\d+\.\d+-(?P<prod>[A-Za-z0-9\-_]+?)[_/](?P<ver>[^\s]+)\s*(?P<extra>.*)$",
            b
        )
        if m:
            prod = m.group("prod").replace("_", "")
            ver = m.group("ver")
            extra = (m.group("extra") or "").strip()
            return {"product": prod, "version": ver, "extra": extra or None}

        m2 = re.search(r"OpenSSH[_/](?P<ver>[0-9][^\s]+)", b)
        if m2:
            return {"product": "OpenSSH", "version": m2.group("ver"), "extra": None}

    # HTTP: look for Server header
    if port in (80, 443, 8080, 8000) or b.startswith("HTTP/"):
        m = re.search(r"(?im)^Server:\s*(?P<server>.+?)\s*$", b)
        if m:
            server = m.group("server").strip()
            # nginx/1.22.0, Apache/2.4.57 (Ubuntu), cloudflare, etc.
            m2 = re.match(
                r"(?P<prod>[A-Za-z0-9\-_]+)(?:/(?P<ver>[0-9][^ \t;]+))?\s*(?P<extra>.*)$",
                server
            )
            if m2:
                prod = m2.group("prod")
                ver = m2.group("ver")
                extra = (m2.group("extra") or "").strip()
                return {"product": prod, "version": ver, "extra": extra or None}
            return {"product": server, "version": None, "extra": None}

    # FTP banners often start with 220
    if port == 21 or b.startswith("220"):
        m = re.search(r"\((?P<prod>[A-Za-z0-9\-_]+)\s+(?P<ver>[0-9][^)\s]+)\)", b)
        if m:
            return {"product": m.group("prod"), "version": m.group("ver"), "extra": None}

    # SMTP: 220 ... ESMTP Postfix
    if port in (25, 587) and b.startswith("220"):
        m = re.search(r"ESMTP\s+(?P<prod>[A-Za-z0-9\-_]+)", b)
        if m:
            return {"product": m.group("prod"), "version": None, "extra": None}

    return None
