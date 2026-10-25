import asyncio
import ipaddress
import logging
import queue
import secrets
import struct
import sys
from collections import OrderedDict
from dataclasses import dataclass, field

from common.crypto import Cipher
from common.frame import Frame, OrderedFrames, TYPE_SYN, TYPE_DATA, TYPE_FIN, TYPE_ACK, unpack_batch, MAX_TARGET_BYTES, FLAG_LAST
from common.reliable import RECEIPT, SendWindow

log = logging.getLogger(__name__)


@dataclass
class Stream:
    opened: asyncio.Future
    incoming: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(2048))
    order: OrderedFrames = field(default_factory=OrderedFrames)
    outgoing: SendWindow = field(default_factory=SendWindow)
    consumed: int = -1
    failed: bool = False
    receipt_task: asyncio.Task | None = None


class SocksClient:
    def __init__(self, cipher, tunnel, dialog_hash):
        self.cipher = cipher
        self.tunnel = tunnel
        self.dialog_hash = dialog_hash
        self.streams = {}
        self.retired = OrderedDict()
        self.loop = asyncio.get_running_loop()

    def on_message(self, raw, meta):
        if meta.get("opponent") != self.dialog_hash:
            return
        try:
            frames = [frame.open(self.cipher) for frame in unpack_batch(raw)]
        except Exception as exc:
            log.debug("Кадр отклонён: %s", exc)
            return
        for frame in frames:
            self.loop.call_soon_threadsafe(self._receive, frame)

    def _receive(self, frame):
        stream = self.streams.get(frame.stream_id)
        if stream is None:
            consumed = self.retired.get(frame.stream_id, -1)
            if frame.type in (TYPE_DATA, TYPE_FIN) and frame.seq <= consumed:
                async def receipt():
                    try:
                        await self.send(TYPE_ACK, frame.stream_id, consumed, RECEIPT)
                    except (OSError, RuntimeError):
                        pass
                self.loop.create_task(receipt())
            return
        if frame.type == TYPE_ACK:
            if frame.payload == RECEIPT:
                stream.outgoing.acknowledge(frame.seq)
                return
            if not stream.opened.done():
                stream.opened.set_result(frame.payload == b"\x00")
        elif frame.type in (TYPE_DATA, TYPE_FIN):
            if frame.seq <= stream.consumed:
                self._receipt(stream, frame.stream_id)
                return
            try:
                for item in stream.order.feed(frame):
                    stream.incoming.put_nowait(item)
            except (ValueError, asyncio.QueueFull):
                self._fail(stream)

    @staticmethod
    def _fail(stream):
        stream.failed = True
        if not stream.opened.done():
            stream.opened.set_result(False)
        while not stream.incoming.empty():
            stream.incoming.get_nowait()
        stream.incoming.put_nowait(None)

    def disconnected(self):
        for stream in list(self.streams.values()):
            self._fail(stream)

    def _receipt(self, stream, sid):
        # Coalesce duplicate receipts instead of creating unbounded tasks.
        if stream.receipt_task is None or stream.receipt_task.done():
            async def emit():
                try:
                    await self.send(TYPE_ACK, sid, stream.consumed, RECEIPT)
                except (OSError, RuntimeError):
                    self._fail(stream)
            stream.receipt_task = self.loop.create_task(emit())

    async def _enqueue(self, raw):
        deadline = self.loop.time() + 60
        while True:
            try:
                self.tunnel.send(raw, dialog_hash=self.dialog_hash)
                return
            except queue.Full:
                if self.loop.time() >= deadline:
                    raise ConnectionError("Очередь потока не освобождается")
                await asyncio.sleep(0.005)

    async def send(self, kind, sid, seq=0, payload=b"", flags=0):
        frame = Frame(kind, sid, seq, flags, payload).seal(self.cipher)
        raw = frame.pack()
        stream = self.streams.get(sid)
        if kind in (TYPE_DATA, TYPE_FIN) and stream is not None:
            while not stream.outgoing.track(seq, raw):
                if stream.failed:
                    raise ConnectionError("Stream closed")
                await asyncio.sleep(0.005)
        await self._enqueue(raw)
        if kind in (TYPE_DATA, TYPE_FIN) and stream is not None:
            stream.outgoing.sent(seq)

    @staticmethod
    async def reply(writer, code):
        writer.write(bytes([5, code, 0, 1]) + b"\x00" * 6)
        await writer.drain()

    async def handshake(self, reader, writer):
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5:
            return None
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return None
        writer.write(b"\x05\x00")
        await writer.drain()
        version, command, reserved, atyp = await reader.readexactly(4)
        if version != 5 or reserved:
            await self.reply(writer, 1)
            return None
        if command != 1:
            await self.reply(writer, 7)
            return None
        if atyp in (1, 4):
            host = str(ipaddress.ip_address(await reader.readexactly(4 if atyp == 1 else 16)))
        elif atyp == 3:
            size = (await reader.readexactly(1))[0]
            if not size:
                await self.reply(writer, 8)
                return None
            host = (await reader.readexactly(size)).decode("ascii")
        else:
            await self.reply(writer, 8)
            return None
        port = struct.unpack(">H", await reader.readexactly(2))[0]
        if not port:
            await self.reply(writer, 1)
            return None
        return f"{host}:{port}"

    async def handle_client(self, reader, writer):
        sid = None
        tasks = []
        retry_task = None
        seq = 0
        sent_fin = False
        try:
            target = await asyncio.wait_for(self.handshake(reader, writer), 15)
            if target is None:
                return
            sid = secrets.randbits(32)
            while sid in self.streams or sid in self.retired:
                sid = secrets.randbits(32)
            settings = self.tunnel.settings
            stream = Stream(self.loop.create_future(), outgoing=SendWindow(
                size=settings.stream_window, timeout=settings.frame_retry, retries=settings.frame_retries))
            self.streams[sid] = stream
            async def retry():
                try:
                    while not stream.failed:
                        await asyncio.sleep(0.2)
                        for number, raw in stream.outgoing.due():
                            await self._enqueue(raw)
                            stream.outgoing.sent(number)
                except (OSError, RuntimeError):
                    self._fail(stream)
            retry_task = asyncio.create_task(retry())
            try:
                target_bytes = target.encode()
                deadline = self.loop.time() + settings.connect_timeout
                while True:
                    for index, offset in enumerate(range(0, len(target_bytes), MAX_TARGET_BYTES)):
                        chunk = target_bytes[offset:offset + MAX_TARGET_BYTES]
                        last = offset + len(chunk) == len(target_bytes)
                        await self.send(TYPE_SYN, sid, index, chunk, FLAG_LAST if last else 0)
                    remaining = deadline - self.loop.time()
                    if remaining <= 0:
                        raise TimeoutError
                    try:
                        opened = await asyncio.wait_for(asyncio.shield(stream.opened), min(2, remaining))
                        break
                    except TimeoutError:
                        if self.loop.time() >= deadline:
                            raise
            except (TimeoutError, ConnectionError, RuntimeError):
                opened = False
            if not opened:
                await self.reply(writer, 5)
                return
            # SOCKS-ответ всегда предшествует данным от удалённого узла
            await self.reply(writer, 0)

            async def upload():
                nonlocal seq, sent_fin
                read_limit = min(self.tunnel.settings.chunk_bytes, self.tunnel.batch_bytes - 42)
                while data := await reader.read(read_limit):
                    await self.send(TYPE_DATA, sid, seq, data)
                    seq += 1
                await self.send(TYPE_FIN, sid, seq)
                sent_fin = True
                while not stream.outgoing.empty():
                    if stream.failed:
                        raise ConnectionError("Stream closed before FIN acknowledgement")
                    await asyncio.sleep(0.01)

            async def download():
                while True:
                    try:
                        frame = await asyncio.wait_for(stream.incoming.get(), 30)
                    except TimeoutError:
                        if stream.order.pending:
                            raise ConnectionError("Пропущен кадр входящего потока")
                        continue
                    if frame is None:
                        raise ConnectionError("Туннель закрыт или буфер переполнен")
                    if frame.type == TYPE_FIN:
                        if writer.can_write_eof():
                            writer.write_eof()
                            await writer.drain()
                        stream.consumed = frame.seq
                        await self.send(TYPE_ACK, sid, frame.seq, RECEIPT)
                        return
                    writer.write(frame.payload)
                    await asyncio.wait_for(writer.drain(), 30)
                    stream.consumed = frame.seq
                    await self.send(TYPE_ACK, sid, frame.seq, RECEIPT)

            tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
            await asyncio.gather(*tasks)
        except (OSError, ValueError, asyncio.IncompleteReadError, TimeoutError) as exc:
            log.debug("SOCKS-поток закрыт: %s", exc)
        finally:
            if retry_task:
                retry_task.cancel()
                await asyncio.gather(retry_task, return_exceptions=True)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if sid is not None:
                stream = self.streams.pop(sid, None)
                if stream and stream.consumed >= 0:
                    self.retired[sid] = stream.consumed
                    if len(self.retired) > 10000:
                        self.retired.popitem(last=False)
                if stream and stream.receipt_task:
                    stream.receipt_task.cancel()
                    await asyncio.gather(stream.receipt_task, return_exceptions=True)
                if not sent_fin:
                    try:
                        await self.send(TYPE_FIN, sid, seq)
                    except (OSError, RuntimeError):
                        pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def run(config, config_path):
    from common.transport_board import BoardTunnel

    cipher = Cipher(config.shared.cipher_key())
    local = config.local
    state_dir = str((config_path.parent / local.state_dir).resolve())
    tunnel = BoardTunnel(config.shared.board_hash, local.guest_name, None,
                          cookies_override=local.cookies, cipher=cipher,
                          settings=config.shared.transport, ws_url=local.ws_url,
                          state_dir=state_dir, debug=local.debug)
    client = None
    try:
        await asyncio.to_thread(tunnel.start)
        dialog = tunnel.create_tunnel()
        client = SocksClient(cipher, tunnel, dialog)
        tunnel.on_message = client.on_message
        tunnel.on_dialog_removed = lambda h: (
            client.loop.call_soon_threadsafe(client.disconnected)
            if h == client.dialog_hash else None
        )
        tunnel.on_disconnect = lambda: client.loop.call_soon_threadsafe(client.disconnected)
        server = await asyncio.start_server(client.handle_client, local.socks_host, local.socks_port)
        log.info("SOCKS5: %s", server.sockets[0].getsockname())
        async with server:
            listener = asyncio.create_task(server.serve_forever())
            stopped = asyncio.create_task(asyncio.to_thread(tunnel.wait_stopped))
            try:
                await asyncio.wait((listener, stopped), return_when=asyncio.FIRST_COMPLETED)
                if listener.done() and not listener.cancelled():
                    listener.result()
            finally:
                listener.cancel()
                tunnel.stop()
                await asyncio.gather(listener, stopped, return_exceptions=True)
    finally:
        if client:
            client.disconnected()
        tunnel.stop()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        from common.config import bootstrap
        config, config_path, setup_only = bootstrap("client")
        logging.basicConfig(level=logging.DEBUG if config.local.debug else logging.INFO)
        if not setup_only:
            asyncio.run(run(config, config_path))
    except KeyboardInterrupt:
        pass
    except (KeyError, ValueError, TypeError, OSError, EOFError) as exc:
        raise SystemExit(f"Ошибка конфигурации/подключения: {exc}") from exc
