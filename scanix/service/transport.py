"""Numeric-endpoint-only socket I/O with shared pacing and absolute deadlines."""
from concurrent.futures import CancelledError
import errno
import select
import socket
import ssl
import time


class BudgetExceeded(TimeoutError):
    pass


class Session:
    def __init__(self, endpoint, port, stop, limiter, report, budget, deadline):
        self.endpoint, self.port, self.stop, self.limiter = endpoint, port, stop, limiter
        self.report, self.budget, self.deadline = report, budget, deadline
        self.sock = None

    def check(self):
        if self.stop.is_set():
            raise CancelledError()
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded('service time budget exhausted')

    def pace(self):
        self.check()
        self.limiter.acquire(self.stop, deadline=self.deadline)
        self.check()

    def wait(self, read=False, end=None):
        while True:
            self.check()
            remaining = min(self.deadline, end or self.deadline) - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('response timeout')
            ready = select.select([self.sock] if read else [], [] if read else [self.sock], [], min(.05, remaining))
            if ready[0] or ready[1]:
                return

    def connect(self, udp=False):
        if self.report.attempts >= self.budget['connections']:
            raise BudgetExceeded('connection budget exhausted')
        self.pace()
        self.report.attempts += 1
        family = socket.AF_INET6 if ':' in self.endpoint else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        self.sock.setblocking(False)
        code = self.sock.connect_ex((self.endpoint, self.port))
        if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035, 10036):
            raise OSError(code, 'service connection failed')
        if code:
            self.wait(end=time.monotonic()+self.budget['operation_timeout'])
            code = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if code:
                raise OSError(code, 'service connection failed')
        return self

    def send(self, payload):
        if (self.report.transmissions >= self.budget['transmissions'] or
                self.report.bytes_sent + len(payload) > self.budget['send_bytes']):
            raise BudgetExceeded('transmission budget exhausted')
        self.pace()
        self.report.transmissions += 1
        end = time.monotonic()+self.budget['operation_timeout']
        view = memoryview(payload)
        while view:
            self.check()
            try:
                sent = self.sock.send(view)
                if not sent:
                    raise OSError('connection closed during send')
                self.report.bytes_sent += sent
                view = view[sent:]
            except (ssl.SSLWantWriteError, BlockingIOError):
                self.wait(end=end)
            except ssl.SSLWantReadError:
                self.wait(read=True, end=end)

    def receive(self, limit, *, passive=False, datagram=False):
        limit = min(limit, self.budget['receive_bytes'] - self.report.bytes_received)
        if limit <= 0:
            raise BudgetExceeded('response byte budget exhausted')
        end = time.monotonic() + (self.budget['passive_timeout'] if passive else self.budget['operation_timeout'])
        data = bytearray()
        while len(data) < limit:
            self.check()
            try:
                part = self.sock.recv(min(2048, limit-len(data)))
                if not part:
                    break
                data.extend(part)
                self.report.bytes_received += len(part)
                # One datagram, or a complete protocol response. Parsers enforce framing.
                if datagram or b'\r\n\r\n' in data or data.endswith(b'\r\n') and passive and not (data.startswith(b'220-') and b'\r\n220 ' not in data):
                    break
                if data.endswith(b'\r\n') and (data.startswith((b'SSH-', b'220 ', b'250 ', b'+OK', b'* OK', b'* PREAUTH')) or
                        b'\r\n250 ' in data or b'\r\n211 ' in data or data.endswith(b'\r\n.\r\n') or b'\r\na001 OK ' in data):
                    # POP3 CAPA is multiline despite its +OK first line.
                    if not (data.startswith(b'+OK') and not passive and not data.endswith(b'\r\n.\r\n')):
                        break
            except (ssl.SSLWantReadError, BlockingIOError):
                try:
                    self.wait(read=True, end=end)
                except TimeoutError:
                    break
            except ssl.SSLWantWriteError:
                self.wait(end=end)
        return bytes(data)

    def tls(self, context, name):
        if self.report.transmissions >= self.budget['transmissions']:
            raise BudgetExceeded('transmission budget exhausted')
        self.pace()
        self.report.transmissions += 1
        self.sock = context.wrap_socket(self.sock, server_hostname=name, do_handshake_on_connect=False)
        self.sock.setblocking(False)
        end = time.monotonic()+self.budget['operation_timeout']
        while True:
            self.check()
            try:
                self.sock.do_handshake()
                return self.sock
            except ssl.SSLWantReadError:
                self.wait(read=True, end=end)
            except ssl.SSLWantWriteError:
                self.wait(end=end)

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
