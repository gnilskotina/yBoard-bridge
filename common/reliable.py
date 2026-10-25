import threading
import time
from collections import OrderedDict

RECEIPT = b"\x02"


class SendWindow:
    def __init__(self, size=32, timeout=5, retries=6):
        if not 1 <= size <= 256:
            raise ValueError("TUNNEL_STREAM_WINDOW must be 1..256")
        self.size, self.timeout, self.retries = size, timeout, retries
        self.pending = OrderedDict()
        self.lock = threading.Lock()
        self.highest = -1

    def track(self, seq, raw):
        with self.lock:
            if len(self.pending) >= self.size:
                return False
            self.pending[seq] = [raw, None, 0]
            self.highest = max(self.highest, seq)
            return True

    def sent(self, seq):
        with self.lock:
            if seq in self.pending:
                self.pending[seq][1] = time.monotonic()

    def acknowledge(self, seq):
        with self.lock:
            if seq > self.highest:
                return
            for number in list(self.pending):
                if number <= seq:
                    del self.pending[number]

    def empty(self):
        with self.lock:
            return not self.pending

    def due(self):
        now = time.monotonic()
        with self.lock:
            result = []
            for seq, item in self.pending.items():
                raw, sent, retries = item
                if sent is None or now - sent < self.timeout:
                    continue
                if retries >= self.retries:
                    raise ConnectionError("Peer did not acknowledge DATA/FIN")
                item[1], item[2] = now, retries + 1
                result.append((seq, raw))
            return result
