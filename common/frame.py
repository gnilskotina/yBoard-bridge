import struct
from dataclasses import dataclass, replace

MAGIC = b"YB"
TYPE_DATA, TYPE_SYN, TYPE_FIN, TYPE_ACK, TYPE_PING, TYPE_PONG = range(1, 7)
FLAG_LAST = 0x01
FLAG_ENCRYPTED = 0x02
HEADER = struct.Struct(">2sBIIBH")
# Лимит относится к content сообщения, включая TUNNEL: и Base64.
TUNNEL_PREFIX = "TUNNEL:"
MAX_CONTENT_CHARS = 350
MAX_TARGET_BYTES = 261
MAX_PAYLOAD = 65535
MAX_PENDING = 2048


@dataclass(frozen=True)
class Frame:
    type: int
    stream_id: int
    seq: int
    flags: int
    payload: bytes

    def header(self, size: int) -> bytes:
        if self.type not in range(1, 7):
            raise ValueError("Неизвестный тип кадра")
        if not 0 <= size <= MAX_PAYLOAD:
            raise ValueError("Слишком большой кадр")
        return HEADER.pack(MAGIC, self.type, self.stream_id, self.seq, self.flags, size)

    def pack(self) -> bytes:
        return self.header(len(self.payload)) + self.payload

    @staticmethod
    def unpack(data: bytes) -> "Frame":
        if len(data) < HEADER.size:
            raise ValueError("Неполный заголовок")
        magic, kind, sid, seq, flags, size = HEADER.unpack_from(data)
        if magic != MAGIC or len(data) != HEADER.size + size:
            raise ValueError("Повреждённый кадр")
        frame = Frame(kind, sid, seq, flags, data[HEADER.size:])
        frame.header(size)
        return frame

    def seal(self, cipher) -> "Frame":
        frame = replace(self, flags=self.flags | FLAG_ENCRYPTED)
        aad = frame.header(len(self.payload) + 28)
        return replace(frame, payload=cipher.encrypt(self.payload, aad))

    def open(self, cipher) -> "Frame":
        if not self.flags & FLAG_ENCRYPTED:
            raise ValueError("Неаутентифицированный кадр")
        plain = cipher.decrypt(self.payload, self.header(len(self.payload)))
        return replace(self, flags=self.flags & ~FLAG_ENCRYPTED, payload=plain)


class OrderedFrames:
    def __init__(self):
        self.next_seq = 0
        self.pending = {}
        self.finished = False

    def feed(self, frame):
        if self.finished or frame.seq < self.next_seq:
            return []
        if frame.type not in (TYPE_DATA, TYPE_FIN):
            raise ValueError("Ожидался DATA или FIN")
        if frame.seq - self.next_seq >= MAX_PENDING:
            raise ValueError("Превышено окно переупорядочивания")
        self.pending.setdefault(frame.seq, frame)
        ready = []
        while self.next_seq in self.pending:
            item = self.pending.pop(self.next_seq)
            ready.append(item)
            self.next_seq += 1
            if item.type == TYPE_FIN:
                self.finished = True
                self.pending.clear()
                break
        return ready


def unpack_batch(data: bytes):
    frames = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < HEADER.size:
            raise ValueError("Неполный заголовок пакета")
        size = HEADER.unpack_from(data, offset)[-1]
        end = offset + HEADER.size + size
        frames.append(Frame.unpack(data[offset:end]))
        offset = end
    return frames
