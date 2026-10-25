import logging
import queue
import socket
import threading
import time
from collections import OrderedDict

from common.crypto import Cipher
from common.frame import Frame, OrderedFrames, TYPE_SYN, TYPE_DATA, TYPE_FIN, TYPE_ACK, unpack_batch, MAX_TARGET_BYTES, FLAG_LAST
from common.reliable import RECEIPT, SendWindow

log = logging.getLogger(__name__)


class Stream:
    def __init__(self, server, key):
        self.server = server
        self.dialog_hash, self.sid = key
        self.sock = None
        self.incoming = queue.Queue(2048)
        self.order = OrderedFrames()
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.finished = 0
        self.connected = False
        settings = server.tunnel.settings
        self.outgoing = SendWindow(size=settings.stream_window, timeout=settings.frame_retry,
                                   retries=settings.frame_retries)
        self.consumed = -1

    def send(self, kind, seq=0, payload=b""):
        self.server.send(self.dialog_hash, kind, self.sid, seq, payload)

    def close(self):
        with self.lock:
            self.closed.set()
            if self.sock is not None:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.sock.close()
        self.server.remove(self)

    def done(self):
        with self.lock:
            self.finished += 1
            complete = self.finished == 2
        if complete:
            self.close()

    def connect(self, host, port):
        try:
            sock = socket.create_connection((host, port), timeout=self.server.tunnel.settings.connect_timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # recv периодически проверяет остановку; sendall не висит бесконечно.
            sock.settimeout(30)
            with self.lock:
                if self.closed.is_set():
                    sock.close()
                    return
                self.sock = sock
                self.connected = True
            self.send(TYPE_ACK, payload=b"\x00")
            threading.Thread(target=self.retry_loop, daemon=True).start()
            threading.Thread(target=self.write_loop, daemon=True).start()
            threading.Thread(target=self.read_loop, daemon=True).start()
        except (OSError, RuntimeError) as exc:
            log.info("Не удалось открыть поток %s: %s", self.sid, exc)
            try:
                self.send(TYPE_ACK, payload=b"\x01")
            except (OSError, RuntimeError):
                pass
            self.close()

    def feed(self, frame):
        if self.closed.is_set():
            return
        if frame.seq <= self.consumed:
            try:
                self.send(TYPE_ACK, self.consumed, RECEIPT)
            except (OSError, RuntimeError):
                self.close()
            return
        try:
            self.incoming.put_nowait(frame)
        except queue.Full:
            self.close()

    def write_loop(self):
        last_progress = time.monotonic()
        try:
            while not self.closed.is_set():
                if self.order.pending and time.monotonic() - last_progress > 30:
                    raise ValueError("Пропущен кадр входящего потока")
                try:
                    frame = self.incoming.get(timeout=0.5)
                except queue.Empty:
                    if self.order.pending and time.monotonic() - last_progress > 30:
                        raise ValueError("Пропущен кадр входящего потока")
                    continue
                for item in self.order.feed(frame):
                    last_progress = time.monotonic()
                    if item.type == TYPE_FIN:
                        self.sock.shutdown(socket.SHUT_WR)
                        self.consumed = item.seq
                        self.send(TYPE_ACK, item.seq, RECEIPT)
                        return
                    self.sock.sendall(item.payload)
                    self.consumed = item.seq
                    self.send(TYPE_ACK, item.seq, RECEIPT)
        except (OSError, ValueError, RuntimeError):
            self.close()
        finally:
            self.done()

    def read_loop(self):
        seq = 0
        read_limit = min(self.server.tunnel.settings.chunk_bytes, self.server.tunnel.batch_bytes - 42)
        try:
            while not self.closed.is_set():
                try:
                    data = self.sock.recv(read_limit)
                except socket.timeout:
                    continue
                if not data:
                    break
                self.send(TYPE_DATA, seq, data)
                seq += 1
        except (OSError, RuntimeError):
            self.close()
        finally:
            try:
                self.send(TYPE_FIN, seq)
                while not self.outgoing.empty() and not self.closed.wait(0.01):
                    pass
            except (OSError, RuntimeError):
                pass
            self.done()

    def retry_loop(self):
        try:
            while not self.closed.wait(0.2):
                for seq, raw in self.outgoing.due():
                    self.server._enqueue(self.dialog_hash, raw, self)
                    self.outgoing.sent(seq)
        except (OSError, RuntimeError):
            self.close()


class TunnelServer:
    def __init__(self, cipher, tunnel):
        self.cipher = cipher
        self.tunnel = tunnel
        self.streams = {}
        self.retired = OrderedDict()
        self.pending_syn = {}
        self.lock = threading.Lock()

    def _enqueue(self, dialog, raw, stream=None):
        deadline = time.monotonic() + 60
        while True:
            if stream is not None and stream.closed.is_set():
                raise ConnectionError("Stream closed")
            try:
                self.tunnel.send(raw, dialog_hash=dialog)
                return
            except queue.Full:
                if time.monotonic() >= deadline:
                    raise ConnectionError("Очередь потока не освобождается")
                time.sleep(0.005)

    def send(self, dialog, kind, sid, seq=0, payload=b""):
        frame = Frame(kind, sid, seq, 0, payload).seal(self.cipher)
        raw = frame.pack()
        with self.lock:
            stream = self.streams.get((dialog, sid))
        if kind in (TYPE_DATA, TYPE_FIN) and stream is not None:
            while not stream.outgoing.track(seq, raw):
                if stream.closed.wait(0.005):
                    raise ConnectionError("Stream closed")
        self._enqueue(dialog, raw, stream)
        if kind in (TYPE_DATA, TYPE_FIN) and stream is not None:
            stream.outgoing.sent(seq)

    def remove(self, stream):
        key = (stream.dialog_hash, stream.sid)
        with self.lock:
            if self.streams.get(key) is stream:
                self.streams.pop(key)
                self.retired[key] = stream.consumed
                if len(self.retired) > 10000:
                    self.retired.popitem(last=False)

    def on_message(self, raw, meta):
        dialog = meta.get("opponent")
        if not isinstance(dialog, str) or not dialog:
            return
        try:
            frames = [frame.open(self.cipher) for frame in unpack_batch(raw)]
        except Exception as exc:
            log.debug("Кадр отклонён: %s", exc)
            return
        for frame in frames:
            self._receive(frame, dialog)

    def _receive(self, frame, dialog):
        key = (dialog, frame.stream_id)
        with self.lock:
            stream = self.streams.get(key)
            consumed = self.retired.get(key, -1)
        if stream is None and frame.type in (TYPE_DATA, TYPE_FIN) and frame.seq <= consumed:
            self.send(dialog, TYPE_ACK, frame.stream_id, consumed, RECEIPT)
            return
        if frame.type == TYPE_ACK and frame.payload == RECEIPT:
            if stream:
                stream.outgoing.acknowledge(frame.seq)
            return
        if frame.type == TYPE_SYN:
            if stream is not None:
                if stream.connected:
                    stream.send(TYPE_ACK, payload=b"\x00")
                return
            # Длинное доменное имя помещается в два аутентифицированных SYN.
            with self.lock:
                now = time.monotonic()
                self.pending_syn = {key: value for key, value in self.pending_syn.items()
                                    if now - value[0] < 20}
                if key in self.retired:
                    return
                if frame.seq > 1 or len(frame.payload) > MAX_TARGET_BYTES:
                    return
                if key not in self.pending_syn and len(self.pending_syn) >= 256:
                    return
                created, parts, last = self.pending_syn.setdefault(key, (now, {}, None))
                parts.setdefault(frame.seq, frame.payload)
                if frame.flags & FLAG_LAST:
                    last = frame.seq
                self.pending_syn[key] = (created, parts, last)
                if last is None or any(i not in parts for i in range(last + 1)):
                    return
                target = b"".join(parts[i] for i in range(last + 1))
                self.pending_syn.pop(key, None)
            try:
                if len(target) > 261:
                    raise ValueError("Слишком длинный адрес")
                host, port_text = target.decode("utf-8").rsplit(":", 1)
                port = int(port_text)
                if not host or not 1 <= port <= 65535:
                    raise ValueError("Неверный адрес")
            except (ValueError, UnicodeError):
                self.send(dialog, TYPE_ACK, frame.stream_id, payload=b"\x01")
                return
            with self.lock:
                if key in self.retired or key in self.streams:
                    return
                if len(self.streams) >= 256:
                    rejected = True
                else:
                    rejected = False
                    stream = Stream(self, key)
                    self.streams[key] = stream
            if rejected:
                self.send(dialog, TYPE_ACK, frame.stream_id, payload=b"\x01")
                return
            threading.Thread(target=stream.connect, args=(host, port), daemon=True).start()
        elif stream and frame.type in (TYPE_DATA, TYPE_FIN):
            stream.feed(frame)

    def on_dialog_removed(self, dialog):
        with self.lock:
            streams = [st for st in self.streams.values() if st.dialog_hash == dialog]
            self.pending_syn = {key: value for key, value in self.pending_syn.items() if key[0] != dialog}
        for stream in streams:
            stream.close()

    def close(self):
        with self.lock:
            streams = list(self.streams.values())
            self.pending_syn.clear()
        for stream in streams:
            stream.close()


def main(config, config_path):
    from common.transport_board import BoardTunnel

    cipher = Cipher(config.shared.cipher_key())
    local = config.local
    state_dir = str((config_path.parent / local.state_dir).resolve())
    tunnel = BoardTunnel(config.shared.board_hash, local.guest_name, None,
                          cookies_override=local.cookies, cipher=cipher,
                          settings=config.shared.transport, ws_url=local.ws_url,
                          state_dir=state_dir, debug=local.debug)
    server = TunnelServer(cipher, tunnel)
    tunnel.on_message = server.on_message
    tunnel.on_dialog_removed = server.on_dialog_removed
    tunnel.on_disconnect = server.close
    try:
        tunnel.start()
        log.info("Сервер запущен")
        while not tunnel.wait_stopped(1):
            pass
    finally:
        server.close()
        tunnel.stop()


if __name__ == "__main__":
    try:
        from common.config import bootstrap
        config, config_path, setup_only = bootstrap("server")
        logging.basicConfig(level=logging.DEBUG if config.local.debug else logging.INFO)
        if not setup_only:
            main(config, config_path)
    except KeyboardInterrupt:
        pass
    except (KeyError, ValueError, TypeError, OSError, EOFError) as exc:
        raise SystemExit(f"Ошибка конфигурации/подключения: {exc}") from exc
