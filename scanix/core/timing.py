"""Monotonic, cancellation-aware pacing and bounded RTT estimates."""
from concurrent.futures import CancelledError
import threading
import time


class RateLimiter:
    """No burst credit. All callers share a serialized transmission deadline."""
    def __init__(self, rate, clock=time.monotonic, sleeper=None):
        self.interval = 1.0 / rate
        self.clock = clock
        self.sleeper = sleeper
        self.next_time = 0.0
        self.lock = threading.Lock()

    def acquire(self, stop):
        with self.lock:
            while True:
                if stop.is_set():
                    raise CancelledError()
                delay = self.next_time - self.clock()
                if delay <= 0:
                    self.next_time = self.clock() + self.interval
                    return
                if self.sleeper:
                    self.sleeper(min(delay, 0.05))
                else:
                    stop.wait(min(delay, 0.05))


class AdaptiveTimeout:
    """Jacobson-style EWMA; ambiguous/retried replies never supply RTT samples."""
    def __init__(self, initial, minimum=0.1, maximum=5.0):
        self.minimum, self.maximum = minimum, maximum
        self.initial = min(maximum, max(minimum, initial))
        self.srtt = self.variation = None
        self.lock = threading.Lock()

    def value(self, attempt=0):
        with self.lock:
            base = self.initial if self.srtt is None else self.srtt + 4 * self.variation
            return min(self.maximum, max(self.minimum, base * 2**attempt))

    def observe(self, rtt):
        with self.lock:
            if self.srtt is None:
                self.srtt, self.variation = rtt, rtt / 2
            else:
                self.variation = 0.75 * self.variation + 0.25 * abs(self.srtt - rtt)
                self.srtt = 0.875 * self.srtt + 0.125 * rtt


class Runtime:
    def __init__(self, config, limiter=None):
        rate = config.rate or {'connect': 100, 'syn': 10, 'udp': 1}[config.method]
        self.limiter = limiter or RateLimiter(rate)
        self.timeout = AdaptiveTimeout(config.timeout, config.min_timeout, config.max_timeout)
