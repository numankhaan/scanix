"""Bounded best-effort plaintext evidence. No protocol or version confirmation."""
import socket


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
