import base64
import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

from .frame import unpack_batch

log = logging.getLogger(__name__)
TEXT_PREFIX = "YBT1:"
REF_PREFIX = "TUNNEL:O:"
READ_PREFIX = "TUNNEL:D:"
DROP_PREFIX = "TUNNEL:X:"
CLEAN_PREFIX = "TUNNEL:C:"
ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
MAX_IDS = 9  # 9 IDs plus AES-GCM receipt fit within a 350-character comment.
STYLE = "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;"


class TextValue(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []

    def handle_data(self, value):
        self.text.append(value)


class ObjectJournal:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS packets (ids TEXT PRIMARY KEY, dialog TEXT, objects TEXT)")
        self.db.commit()

    def save(self, ids, dialog, objects):
        self.db.execute("INSERT OR REPLACE INTO packets VALUES (?,?,?)",
                        (",".join(ids), dialog, json.dumps(objects, separators=(",", ":"))))
        self.db.commit()

    def remove(self, ids):
        self.db.execute("DELETE FROM packets WHERE ids=?", (",".join(ids),))
        self.db.commit()

    def load(self):
        return [(tuple(ids.split(",")), dialog, json.loads(objects))
                for ids, dialog, objects in self.db.execute("SELECT ids,dialog,objects FROM packets")]


@dataclass
class Outgoing:
    dialog: str
    objects: list
    created: float
    last_sent: float
    deleting: bool = False
    remaining: set = field(default_factory=set)


class ObjectPackets:
    def __init__(self, tunnel, cipher, text_chars=10000, window=128, retry=2, ttl=120):
        if not 512 <= text_chars <= 1000000 or not MAX_IDS <= window <= 4096:
            raise ValueError("Invalid object text/window limits")
        self.tunnel, self.cipher = tunnel, cipher
        self.text_chars, self.window = text_chars, window
        self.chunk_bytes = ((text_chars - len(TEXT_PREFIX) - 7) // 4) * 3
        self.max_packet_bytes = min(65536, self.chunk_bytes * MAX_IDS)
        self.retry, self.ttl = retry, ttl
        self.lock = threading.RLock()
        self.outgoing = OrderedDict()
        self.owned = {}
        self.cache = OrderedDict()
        self.cache_bytes = 0
        self.references = OrderedDict()
        self.completed = OrderedDict()
        self.cache_limit = window * 2
        self.cache_byte_limit = min(64 * 1024 * 1024, window * text_chars * 2)
        self.journal = None
        self.started = False

    def start(self, state_dir):
        with self.lock:
            if self.started:
                return
            if self.cipher is None:
                raise ValueError("Object transport requires the tunnel сipher")
            self.started = True
            if state_dir is None:
                return
            scope = hashlib.sha256((self.tunnel.board_hash + "\0" + self.tunnel.name).encode()).hexdigest()[:24]
            self.journal = ObjectJournal(Path(state_dir) / (scope + ".sqlite3"))
            for ids, dialog, objects in self.journal.load():
                if (not self._ids_valid(ids) or len(objects) != len(ids) or
                        any(self._object_id(obj) != oid for obj, oid in zip(objects, ids))):
                    raise ValueError("Invalid object cleanup journal")
                record = Outgoing(dialog, objects, time.monotonic(), 0, True, set(ids))
                self.outgoing[ids] = record
                for oid in ids:
                    self.owned[oid] = ids
            if self.outgoing:
                log.info("Restored %d packet groups for object cleanup", len(self.outgoing))

    @staticmethod
    def _object_id(obj):
        if not isinstance(obj, dict):
            return None
        attrs = obj.get("_attributes_") or {}
        if not isinstance(attrs, dict):
            return None
        identity = attrs.get("id") or obj.get("hash")
        if not isinstance(identity, str) or not ID_PATTERN.fullmatch(identity):
            return None
        if obj.get("hash", identity) != identity:
            return None
        return identity

    @staticmethod
    def _ids_valid(ids):
        return (1 <= len(ids) <= MAX_IDS and len(set(ids)) == len(ids) and
                all(isinstance(oid, str) and ID_PATTERN.fullmatch(oid) for oid in ids))

    def available(self):
        with self.lock:
            # Reserve a full packet's maximum number of object slots.
            return len(self.owned) + MAX_IDS <= self.window

    def _event(self, action, objects):
        data = {"objects": objects}
        if action == "modify-objects":
            data["valueChanges"] = {self._object_id(obj): False for obj in objects}
        return {"action": action, "data": data,
                "participant": self.tunnel.self_participant_hash or self.tunnel.self_user_hash}

    def publish(self, dialog, raw):
        if self.cipher is None or not raw or len(raw) > self.max_packet_bytes:
            raise ValueError("Invalid object packet")
        creator = self.tunnel.self_participant_hash or self.tunnel.self_user_hash
        ids, objects = [], []
        for offset in range(0, len(raw), self.chunk_bytes):
            identity = os.urandom(16).hex()
            value = "<p>" + TEXT_PREFIX + base64.b64encode(raw[offset:offset + self.chunk_bytes]).decode() + "</p>"
            obj = {"_attributes_": {"id": identity, "value": value, "style": STYLE,
                                    "vertex": "1", "parent": "DASHBOARD", "index": "13",
                                    "type": "textbox", "creatorHash": creator},
                   "mxGeometry": [{"_attributes_": {"x": "0", "y": "0", "width": "1",
                                                       "height": "1", "as": "geometry"}}],
                   "hash": identity}
            ids.append(identity)
            objects.append(obj)
        ids = tuple(ids)
        with self.lock:
            if len(self.owned) + len(ids) > self.window:
                raise ConnectionError("Object window exceeded")
            if self.journal:
                self.journal.save(ids, dialog, objects)
            now = time.monotonic()
            self.outgoing[ids] = Outgoing(dialog, objects, now, now, False, set(ids))
            for oid in ids:
                self.owned[oid] = ids
        self.tunnel._send_dashboard_now(self._event("modify-objects", objects))
        self.tunnel._wrap_comment(dialog, REF_PREFIX + ",".join(ids))

    @staticmethod
    def _aad(kind, dialog, ids):
        return ("YB-OBJECT-" + kind + "\0" + dialog + "\0" + ",".join(ids)).encode()

    def _receipt(self, kind, dialog, ids):
        tag = base64.b64encode(self.cipher.encrypt(b"", self._aad(kind, dialog, ids))).decode()
        prefix = {"read": READ_PREFIX, "drop": DROP_PREFIX, "cleanup": CLEAN_PREFIX}[kind]
        self.tunnel._queue_comment(dialog, prefix + ",".join(ids) + ":" + tag)

    def comment(self, content, meta):
        dialog = meta.get("opponent")
        if not isinstance(dialog, str) or not dialog:
            return True
        if content.startswith(REF_PREFIX):
            ids = tuple(content[len(REF_PREFIX):].split(","))
            if not self._ids_valid(ids):
                return True
            key = (dialog, ids)
            with self.lock:
                self._expire_locked()
                done = key in self.completed
                if not done:
                    if len(self.references) >= self.window and key not in self.references:
                        return True
                    self.references[key] = (time.monotonic(), dict(meta))
            if done:
                self._receipt("read", dialog, ids)
                with self.lock:
                    for oid in ids:
                        self._uncache_locked(oid)
            else:
                self._complete(key)
            return True
        for kind, prefix in (("read", READ_PREFIX), ("drop", DROP_PREFIX), ("cleanup", CLEAN_PREFIX)):
            if not content.startswith(prefix):
                continue
            try:
                body, tag = content[len(prefix):].rsplit(":", 1)
                ids = tuple(body.split(","))
                if not self._ids_valid(ids):
                    return True
                if self.cipher.decrypt(base64.b64decode(tag, validate=True), self._aad(kind, dialog, ids)) != b"":
                    return True
            except Exception:
                log.debug("Unauthenticated object receipt rejected")
                return True
            with self.lock:
                if kind == "cleanup":
                    self.completed[(dialog, ids)] = (time.monotonic(), set(ids))
                    while len(self.completed) > 4096:
                        self.completed.popitem(last=False)
                    return True
                record = self.outgoing.get(ids)
                if not record or record.dialog != dialog:
                    return True
                if kind == "drop":
                    if record.deleting:
                        self._forget_locked(ids)
                    return True
                record.deleting = True
                record.last_sent = time.monotonic()
                event = self._event("drop-objects", record.objects)
            self.tunnel._queue_dashboard(event)
            return True
        return False

    def objects_changed(self, objects):
        if not isinstance(objects, list):
            return
        with self.lock:
            self._expire_locked()
            for obj in objects:
                oid = self._object_id(obj)
                if not oid or oid in self.owned:
                    continue
                attrs = obj.get("_attributes_") or {}
                value = attrs.get("value")
                if attrs.get("type") != "textbox" or not isinstance(value, str) or len(value) > self.text_chars:
                    continue
                parser = TextValue()
                parser.feed(value)
                text = "".join(parser.text)
                if not text.startswith(TEXT_PREFIX):
                    continue
                try:
                    data = base64.b64decode(text[len(TEXT_PREFIX):], validate=True)
                except (ValueError, TypeError):
                    continue
                if not data or len(data) > self.chunk_bytes:
                    continue
                self._uncache_locked(oid)
                while self.cache and (len(self.cache) >= self.cache_limit or
                                      self.cache_bytes + len(data) > self.cache_byte_limit):
                    self._uncache_locked(next(iter(self.cache)))
                self.cache[oid] = (time.monotonic(), data)
                self.cache_bytes += len(data)
            ready = [key for key in self.references if all(oid in self.cache for oid in key[1])]
        for key in ready:
            self._complete(key)

    def _complete(self, key):
        dialog, ids = key
        with self.lock:
            entry = self.references.get(key)
            if entry is None or not all(oid in self.cache for oid in ids):
                return
            raw = b"".join(self.cache[oid][1] for oid in ids)
            try:
                frames = unpack_batch(raw)
                if not frames:
                    raise ValueError("Empty packet")
                for frame in frames:
                    frame.open(self.cipher)
            except Exception:
                self.references.pop(key, None)
                for oid in ids:
                    self._uncache_locked(oid)
                log.debug("Object packet authentication failed")
                return
            if self.tunnel.on_message is None:
                return
            meta = entry[1]
            self.references.pop(key, None)
            self.completed[key] = (time.monotonic(), set(ids))
            while len(self.completed) > 4096:
                self.completed.popitem(last=False)
            for oid in ids:
                self._uncache_locked(oid)
        self.tunnel.on_message(raw, meta)
        self._receipt("read", dialog, ids)

    def objects_dropped(self, objects):
        if not isinstance(objects, list):
            return
        ids = set(filter(None, (self._object_id(obj) for obj in objects)))
        notify = []
        with self.lock:
            for oid in ids:
                self._uncache_locked(oid)
                packet_ids = self.owned.get(oid)
                record = self.outgoing.get(packet_ids)
                if record and record.deleting:
                    record.remaining.discard(oid)
                    if not record.remaining:
                        self._forget_locked(packet_ids)
            for (dialog, packet_ids), (_, remaining) in list(self.completed.items()):
                if ids.intersection(packet_ids):
                    remaining.difference_update(ids)
                    if not remaining:
                        notify.append((dialog, packet_ids))
        for dialog, packet_ids in notify:
            self._receipt("drop", dialog, packet_ids)

    def _forget_locked(self, ids):
        if self.journal:
            self.journal.remove(ids)
        self.outgoing.pop(ids, None)
        for oid in ids:
            self.owned.pop(oid, None)

    def deletion_accepted(self, objects):
        self.objects_dropped(objects)

    def _uncache_locked(self, oid):
        entry = self.cache.pop(oid, None)
        if entry:
            self.cache_bytes -= len(entry[1])

    def _expire_locked(self):
        now = time.monotonic()
        for oid, (created, _) in list(self.cache.items()):
            if now - created > self.ttl:
                self._uncache_locked(oid)
        for key, (created, _) in list(self.references.items()):
            if now - created > self.ttl:
                self.references.pop(key, None)
        for key, (created, _) in list(self.completed.items()):
            if now - created > self.ttl:
                self.completed.pop(key, None)

    def maintenance(self):
        now = time.monotonic()
        resend = []
        stale = False
        with self.lock:
            self._expire_locked()
            for ids, record in self.outgoing.items():
                if now - record.created > self.ttl:
                    stale = True
                    record.deleting = True
                if now - record.last_sent >= self.retry:
                    record.last_sent = now
                    resend.append((ids, record.dialog, record.objects, record.deleting))
        for ids, dialog, objects, deleting in resend:
            action = "drop-objects" if deleting else "modify-objects"
            if deleting:
                tag = base64.b64encode(self.cipher.encrypt(b"", self._aad("cleanup", dialog, ids))).decode()
                self.tunnel._wrap_comment(dialog, CLEAN_PREFIX + ",".join(ids) + ":" + tag)
            self.tunnel._send_dashboard_now(self._event(action, objects))
            if not deleting:
                self.tunnel._wrap_comment(dialog, REF_PREFIX + ",".join(ids))
        if stale:
            raise ConnectionError("Object delivery/cleanup timed out; cleanup remains in local journal")

    def shutdown_events(self):
        with self.lock:
            for record in self.outgoing.values():
                record.deleting = True
            return [self._event("drop-objects", record.objects) for record in self.outgoing.values()]
