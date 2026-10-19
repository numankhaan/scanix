"""Privileged I/O boundary. No packet interpretation and no connect fallback."""
import ipaddress
import sys
import time
from concurrent.futures import CancelledError
from scapy.all import conf


class BackendUnavailable(RuntimeError):
    pass


def route(destination):
    v6 = ipaddress.ip_address(destination).version == 6
    iface, source, gateway = (conf.route6 if v6 else conf.route).route(destination)
    if not iface or ipaddress.ip_address(source).is_unspecified:
        raise BackendUnavailable('no usable source address/route for target')
    return iface, source, gateway


class PacketTransport:
    def __init__(self, destination, layer2=False):
        self.destination, self.layer2 = destination, layer2
        self.socket = None

    def __enter__(self):
        if sys.platform not in ('linux', 'darwin'):
            raise BackendUnavailable('raw capture supported on Linux/macOS only; use TCP connect on this platform')
        self.iface, self.source, self.gateway = route(self.destination)
        factory = conf.L2socket if self.layer2 else (
            conf.L3socket6 if ipaddress.ip_address(self.destination).version == 6 else conf.L3socket)
        if sys.platform == 'linux' and not self.layer2 and ipaddress.ip_address(self.destination).is_loopback:
            # Linux loopback needs raw IP transmission, rather than Ethernet injection.
            from scapy.supersocket import L3RawSocket, L3RawSocket6
            factory = L3RawSocket6 if ':' in self.destination else L3RawSocket
        # Open capture before any packet can be transmitted. Failure propagates.
        self.socket = factory(iface=self.iface, promisc=False)
        if not hasattr(self.socket, 'select'):
            self.socket.close()
            raise BackendUnavailable('capture backend does not support select')
        return self

    def __exit__(self, *_):
        if self.socket:
            self.socket.close()

    def send(self, packet, limiter, stop):
        limiter.acquire(stop)
        if stop.is_set():
            raise CancelledError()
        sent = self.socket.send(packet)
        if sent is None or (isinstance(sent, int) and sent <= 0):
            raise BackendUnavailable('capture backend did not transmit packet')

    def exchange(self, packet, classifier, timeout, limiter, stop):
        self.send(packet, limiter, stop)
        start = time.monotonic()
        deadline = start + timeout
        while time.monotonic() < deadline and not stop.is_set():
            ready = self.socket.select([self.socket], remain=min(0.05, max(0, deadline - time.monotonic())))
            for capture in ready:
                response = capture.recv()
                # Retain no unrelated packets or duplicate response queues.
                try:
                    evidence = classifier(response)
                except (ValueError, TypeError, IndexError, AttributeError, OverflowError):
                    continue  # malformed/untrusted packet; never turn it into evidence
                if evidence is not None:
                    return evidence, response, time.monotonic() - start
        return None, None, time.monotonic() - start
