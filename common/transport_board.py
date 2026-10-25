import base64
import json
import logging
import os
import queue
import random
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from collections import OrderedDict, deque
from dataclasses import dataclass
from urllib.parse import urlsplit, parse_qs, urlencode

from .frame import Frame, TYPE_SYN, TYPE_ACK, TUNNEL_PREFIX, MAX_CONTENT_CHARS
from .objects import ObjectPackets
from .config import TransportSettings

import requests
import websocket

log = logging.getLogger(__name__)

ORIGIN = "https://boards.yandex.ru"
API    = "https://boards.yandex.ru/api"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0")

SEND_INTERVAL = 0.005
IDLE_SLEEP = 0.002
POLL_OWN_INTERVAL = 0.5
POLL_ACT_INTERVAL = 5



def _b64(obj: dict) -> str:
    return base64.b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).decode()


def socket_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Пустой адрес WebSocket")
    value = value.strip()
    parsed = urlsplit(value if "://" in value else "wss://" + value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Неверный порт WebSocket") from exc
    if (parsed.scheme != "wss" or parsed.username or parsed.password or
            not parsed.hostname or not re.fullmatch(r"[a-z0-9-]+\.boards\.yandex\.ru", parsed.hostname)):
        raise ValueError("Ожидается wss://socketNN.boards.yandex.ru/... или имя узла досок")
    if parsed.path not in ("", "/", "/socket.io", "/socket.io/") or parsed.fragment:
        raise ValueError("Неверный путь Socket.IO")
    query = parse_qs(parsed.query)
    query.update({"EIO": ["4"], "transport": ["websocket"]})
    host = parsed.hostname + (":" + str(port) if port else "")
    return "wss://" + host + "/socket.io/?" + urlencode(query, doseq=True)


def discover_socket_urls(info, page=""):
    found = []
    servers = info.get("socket_servers") or []
    if isinstance(servers, list):
        for entry in servers:
            if isinstance(entry, dict):
                found.extend(entry.get(key) for key in ("ip", "host", "url") if entry.get(key))
            elif isinstance(entry, str):
                found.append(entry)
    for section in (info, info.get("presentation") or {}, (info.get("presentation") or {}).get("properties") or {}):
        if isinstance(section, dict):
            found.extend(section.get(key) for key in ("ws_host", "socket_host") if section.get(key))
    found.extend(re.findall(r"socket\d+\.boards\.yandex\.ru", page))
    result = []
    for value in found:
        try:
            url = socket_url(value)
        except ValueError:
            continue
        if url not in result:
            result.append(url)
    return result


@dataclass
class LoginInfo:
    cookie: str
    user_hash: str
    slide_hash: str | None
    properties: dict
    socket_urls: list


def guest_login(board_hash: str, name: str, cookies_override: str | None = None, ws_override=""):
    with requests.Session() as session:
        session.headers.update({
            "User-Agent": UA, "Origin": ORIGIN,
            "Accept-Language": "ru,en;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
        })
        page = ""
        if cookies_override:
            for pair in cookies_override.split(";"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    session.cookies.set(key.strip(), value.strip(), domain=".yandex.ru")
        else:
            for key in ("yandexuid", "yuidss", "yashr"):
                session.cookies.set(key, str(random.randint(10**18, 10**19 - 1)), domain=".yandex.ru")
            session.cookies.set("i", base64.b64encode(os.urandom(48)).decode(), domain=".yandex.ru")
            guest_url = f"{ORIGIN}/guest/?hash={board_hash}"
            page_response = session.get(guest_url, timeout=15)
            page_response.raise_for_status()
            page = page_response.text
            response = session.post(API, json={
                "action": "request-guest-token",
                "content": _b64({"name": name, "hash": board_hash}),
            }, headers={"Referer": guest_url}, timeout=15)
            response.raise_for_status()
            redirect = response.json().get("redirect")
            if redirect:
                session.get(redirect, timeout=15).raise_for_status()

        response = session.post(API, json={
            "action": "get-whiteboard-info",
            "content": _b64({"hash": board_hash, "name": None}),
        }, headers={"Referer": f"{ORIGIN}/whiteboard/?hash={board_hash}"}, timeout=15)
        response.raise_for_status()
        info = response.json()
        presentation = info["presentation"]
        user_hash = presentation.get("userHash")
        if not user_hash:
            # The Go example gets u from token_<board_hash> when needed.
            for item in session.cookies:
                if item.name == "token_" + board_hash:
                    try:
                        payload = item.value.split(".")[1]
                        user_hash = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("u")
                    except (IndexError, ValueError, TypeError):
                        pass
        properties = presentation.get("properties") or {}
        slide_hash = properties.get("current_slide")
        if not slide_hash and presentation.get("items"):
            items = json.loads(base64.b64decode(presentation["items"]))
            if items:
                slide_hash = items[0]["hash"]
        if not user_hash:
            raise RuntimeError("В ответе сервиса отсутствует userHash")
        cookie = "; ".join(f"{key}={value}" for key, value in session.cookies.get_dict().items())
        urls = [socket_url(ws_override)] if ws_override else discover_socket_urls(info, page)
        if not urls:
            raise ConnectionError("Y.Board не сообщил socket_servers. укажите WebSocket URL в конфиге")
        return LoginInfo(cookie, user_hash, slide_hash, properties, urls)


def _parse_iso(s):
    try:
        value = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


class SendQueue:
    def __init__(self, max_frames=4096, per_stream=128):
        self.flows = OrderedDict()
        self.controls = deque()
        self.max_frames = max_frames
        self.per_stream = per_stream
        self.count = 0
        self.control_run = 0
        self.lock = threading.Lock()

    def put(self, dialog, raw, frame):
        with self.lock:
            if frame.type in (TYPE_SYN, TYPE_ACK):
                if len(self.controls) >= 256:
                    raise queue.Full
                self.controls.append((dialog, raw))
                return
            key = (dialog, frame.stream_id)
            flow = self.flows.get(key)
            if self.count >= self.max_frames or (flow is not None and len(flow) >= self.per_stream):
                raise queue.Full
            self.flows.setdefault(key, deque()).append(raw)
            self.count += 1

    def batch(self, max_bytes):
        with self.lock:
            if not self.controls and not self.flows:
                raise queue.Empty
            chunks = []
            dialog = None
            size = 0
            while True:
                control = bool(self.controls) and (self.control_run < 4 or not self.flows)
                if control:
                    candidate, raw = self.controls[0]
                    key = None
                else:
                    key = next((key for key in self.flows if dialog is None or key[0] == dialog), None)
                    if key is None:
                        break
                    candidate, raw = key[0], self.flows[key][0]
                if dialog is not None and candidate != dialog:
                    break
                if size + len(raw) > max_bytes:
                    break
                dialog = candidate
                if control:
                    self.controls.popleft()
                    self.control_run += 1
                else:
                    flow = self.flows[key]
                    flow.popleft()
                    self.count -= 1
                    if flow:
                        self.flows.move_to_end(key)
                    else:
                        del self.flows[key]
                    self.control_run = 0
                chunks.append(raw)
                size += len(raw)
                if not self.controls and not self.flows:
                    break
            if not chunks:
                raise ValueError("Кадр превышает размер пакета")
            return dialog, b"".join(chunks)

    def size(self):
        with self.lock:
            return self.count + len(self.controls), len(self.flows)


class BoardTunnel:
    def __init__(self, board_hash, name, on_message,
                 on_dialog_created=None, on_dialog_removed=None,
                 cookies_override=None, cipher=None, settings=None, ws_url="",
                 state_dir=".tunnel-state", debug=False):
        self.board_hash = board_hash
        self.name = name
        self.on_message = on_message
        self.on_dialog_created = on_dialog_created
        self.on_dialog_removed = on_dialog_removed
        self.cookies_override = cookies_override
        self.settings = settings or TransportSettings()
        self.settings.validate()
        self.ws_url = socket_url(ws_url) if ws_url else ""
        self.state_dir, self.debug = state_dir, debug
        self._objects = ObjectPackets(self, cipher, text_chars=self.settings.object_chars,
                                      window=self.settings.object_window,
                                      retry=self.settings.object_retry, ttl=self.settings.object_ttl)

        self._my_dialogs = set()
        self._current_dialog = None
        self._dialog_lock = threading.Lock()


        self.self_user_hash = None
        self.self_participant_hash = None
        self.self_session_id = None
        self.slide_hash = None
        self.properties = {}

        self._current_session = None
        self._ack_id = 10
        self._ack_lock = threading.Lock()

        self._known_dialogs = set()
        self._known_lock = threading.Lock()
        self._pending_ack = {}
        self._pending_lock = threading.Lock()
        self._start_time = datetime.now(timezone.utc) - timedelta(seconds=30)

        self._q_high = queue.Queue(4096)
        self._q_data = SendQueue()
        self.batch_bytes = self._objects.max_packet_bytes
        self.send_interval = self.settings.send_interval
        self.ack_window = self.settings.ack_window
        self.ack_timeout = self.settings.ack_timeout
        if not 0.001 <= self.send_interval <= 1 or not 0 <= self.ack_window <= 512 or self.ack_timeout <= 0:
            raise ValueError("Invalid transport pacing/ACK settings")
        self._tx_pending = {}
        self._drop_pending = {}
        self._tx_lock = threading.Lock()

        self._ws = None
        self._stop = False
        self._stopped = threading.Event()
        self._ready = threading.Event()
        self._workers_started = False
        self.on_disconnect = None

    @property
    def current_dialog(self):
        with self._dialog_lock:
            return self._current_dialog

    def wait_stopped(self, timeout=None):
        return self._stopped.wait(timeout)

    def stop(self):
        if self._stopped.is_set():
            return
        self._stop = True
        self._stopped.set()
        self._ready.clear()
        if self._ws is not None:
            if self._objects:
                for event in self._objects.shutdown_events():
                    try:
                        self._send_dashboard_now(event)
                    except Exception:
                        break
            self._ws.close()
        if self.on_disconnect:
            self.on_disconnect()

    def start(self):
        if self._ws is not None or self._stop:
            raise RuntimeError("Создайте новый BoardTunnel для повторного запуска")
        if self._objects:
            self._objects.start(self.state_dir)
        info = guest_login(self.board_hash, self.name, self.cookies_override, self.ws_url)
        self.self_user_hash, self.slide_hash, self.properties = info.user_hash, info.slide_hash, info.properties
        self.ws_url = info.socket_urls[0]
        log.info("WebSocket узел определён: %s", urlsplit(self.ws_url).hostname)

        self._ws = websocket.WebSocketApp(
            self.ws_url,
            header=[f"Cookie: {info.cookie}", f"User-Agent: {UA}"],
            on_open=self._on_open,
            on_message=self._on_message_ws,
            on_error=lambda w, e: log.error("WebSocket: %s", e),
            on_close=self._on_close,
        )
        threading.Thread(target=self._run, daemon=True).start()
        deadline = time.monotonic() + 25
        while not self._ready.wait(0.1):
            if self._stop or time.monotonic() >= deadline:
                self.stop()
                raise ConnectionError("Не удалось дождаться подключения к доске")

    def _run(self):
        try:
            self._ws.run_forever(origin=ORIGIN)
        except Exception:
            log.exception("WebSocket завершился с ошибкой")
        finally:
            self.stop()

    def create_tunnel(self, first_payload: bytes = b"") -> str:
        if not self._ready.is_set():
            raise RuntimeError("Туннель ещё не подключён")
        self._new_dialog()
        if first_payload:
            self.send(first_payload)
        return self._current_dialog

    def _new_dialog(self):
        h = os.urandom(16).hex()
        with self._dialog_lock:
            self._my_dialogs.add(h)
            self._current_dialog = h
        self._send_ack("im", {
            "operation": "im-dialog-messages",
            "user": None,
            "data": {"opponent": h, "limit": 1,
                     "last": None, "additional": {"virtual": True}},
        })
        log.debug("Создан диалог %s", h)
        return h

    def send(self, data: bytes, dialog_hash: str | None = None,
             control: bool = False):
        # FIN остаётся в очереди своего потока после всех DATA.
        if self._stop or not self._ready.is_set():
            raise ConnectionError("Транспорт не подключён")
        h = dialog_hash or self.current_dialog
        if not h:
            raise RuntimeError("Туннель не создан")
        frame = Frame.unpack(data)
        # queue.Full означает замедление производителя, а не обрыв всех потоков.
        if len(data) > self.batch_bytes:
            raise ValueError("Frame exceeds object packet size")
        self._q_data.put(h, data, frame)

    def close_tunnel(self, dialog_hash: str | None = None):
        if dialog_hash:
            with self._dialog_lock:
                self._my_dialogs.discard(dialog_hash)
                if self._current_dialog == dialog_hash:
                    self._current_dialog = None
            self._send_ack("im", {
                "operation": "im-dialog-remove",
                "user": None,
                "data": {"opponent": dialog_hash},
            })
            return
        with self._dialog_lock:
            dialogs = list(self._my_dialogs)
            self._my_dialogs.clear()
            self._current_dialog = None
        for h in dialogs:
            self._send_ack("im", {
                "operation": "im-dialog-remove",
                "user": None,
                "data": {"opponent": h},
            })

    def _wrap_data(self, dialog_hash: str, payload_bytes: bytes):
        self._objects.publish(dialog_hash, payload_bytes)

    def _wrap_comment(self, dialog_hash, content):
        self._ws.send(self._make_comment(dialog_hash, content))

    def _queue_comment(self, dialog_hash, content):
        self._emit_raw(self._make_comment(dialog_hash, content))

    def _make_comment(self, dialog_hash, content):
        if len(content) > MAX_CONTENT_CHARS:
            raise ValueError("content превышает 350 символов")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload = {
            "content": content,
            "attachments": [],
            "messages": [],
            "has_link": False,
            "dashboard": self.slide_hash or self.board_hash,
            "pointer": {"x": 960, "y": 540},
            "linkhash": os.urandom(16).hex(),
            "sender": self.self_participant_hash or self.self_user_hash,
            "sender_name": self.name,
            "opponent": dialog_hash,
            "creationdate": now,
        }
        return self._tracked_event("im", {
            "operation": "im-send-dialog-message", "user": None, "data": payload,
        })

    def _tracked_event(self, event, payload):
        with self._ack_lock:
            self._ack_id += 1
            aid = self._ack_id
        raw = f"42{aid}" + json.dumps([event, payload], ensure_ascii=False, separators=(",", ":"))
        with self._tx_lock:
            now = time.monotonic()
            if not self.ack_window:
                while self._tx_pending:
                    oldest = next(iter(self._tx_pending))
                    if now - self._tx_pending[oldest] < self.ack_timeout:
                        break
                    self._tx_pending.pop(oldest)
            if not self.ack_window and len(self._tx_pending) >= 4096:
                self._tx_pending.pop(next(iter(self._tx_pending)))
            self._tx_pending[aid] = now
            if self._objects and event == "dashboard" and payload.get("action") == "drop-objects":
                self._drop_pending[aid] = [{"hash": obj["hash"]} for obj in payload["data"]["objects"]]
            self._drop_pending = {key: objects for key, objects in self._drop_pending.items()
                                  if key in self._tx_pending}
        return raw

    def _send_dashboard_now(self, payload):
        self._ws.send(self._tracked_event("dashboard", payload))

    def _queue_dashboard(self, payload):
        self._emit_raw(self._tracked_event("dashboard", payload))

    def _can_send(self):
        if self._objects and not self._objects.available():
            return False
        with self._tx_lock:
            if not self.ack_window:
                return True
            if self._tx_pending and time.monotonic() - min(self._tx_pending.values()) > self.ack_timeout:
                raise ConnectionError("Y.Board did not acknowledge message; check ACK format/settings")
            return not self.ack_window or len(self._tx_pending) < self.ack_window

    def _on_close(self, ws, code, reason):
        if self._stop:
            log.debug("WebSocket closed after local stop: code=%s", code)
        else:
            log.warning("WebSocket closed externally: code=%s reason=%s", code, reason)
        self.stop()

    def _send_ack(self, event, payload, pending=None):
        with self._ack_lock:
            self._ack_id += 1
            aid = self._ack_id
        # Зарегистрировать запрос ДО публикации в очередь отправки
        if pending is not None:
            with self._pending_lock:
                now = time.monotonic()
                self._pending_ack = {
                    key: value for key, value in self._pending_ack.items()
                    if now - value[2] < 30
                }
                if len(self._pending_ack) >= 4096:
                    raise ConnectionError("Слишком много запросов без ответа")
                self._pending_ack[aid] = (*pending, now)
        self._emit_raw(f"42{aid}" + json.dumps([event, payload], ensure_ascii=False))
        return aid

    def _emit_raw(self, raw):
        if self._stop:
            return
        try:
            self._q_high.put_nowait(raw)
        except queue.Full:
            self.stop()
            raise ConnectionError("Переполнена служебная очередь")

    def _pump(self):
        next_send = 0.0
        next_stats = time.monotonic() + 5
        next_maintenance = 0
        sent_bytes = sent_messages = 0
        try:
            while not self._stop:
                # Heartbeat не ждёт очереди пользовательских данных
                for _ in range(64):
                    try:
                        raw = self._q_high.get_nowait()
                    except queue.Empty:
                        break
                    self._ws.send(raw)
                if self._objects and self._ready.is_set() and time.monotonic() >= next_maintenance:
                    self._objects.maintenance()
                    next_maintenance = time.monotonic() + 0.25
                if self._ready.is_set() and self._can_send() and time.monotonic() >= next_send:
                    try:
                        h, data = self._q_data.batch(self.batch_bytes)
                    except queue.Empty:
                        pass
                    else:
                        self._wrap_data(h, data)
                        sent_bytes += len(data)
                        sent_messages += 1
                        next_send = time.monotonic() + self.send_interval
                if self.debug and time.monotonic() >= next_stats:
                    queued, flows = self._q_data.size()
                    log.debug("TX за 5с: messages=%d bytes=%d queued_frames=%d active_flows=%d",
                              sent_messages, sent_bytes, queued, flows)
                    sent_bytes = sent_messages = 0
                    next_stats = time.monotonic() + 5
                self._stopped.wait(IDLE_SLEEP)
        except Exception as exc:
            log.error("Ошибка отправки: %s", exc)
            # Потерянный кадр нельзя молча пропускать в TCP-потоке
            self.stop()

    def _send_heartbeat(self):
        hb = {"action": "heartbeat", "data": {},
              "participant": self.self_user_hash or ""}
        self._emit_raw("42" + json.dumps(["dashboard", hb]))

    def _send_in(self):
        self._emit_raw('42["dashboard",{"action":"in","data":{"p":2,"s":0,"n":0}}]')

    def _keepalive_loop(self):
        tick = 0
        while not self._stop:
            self._stopped.wait(5)
            if self._stop:
                return
            tick += 1
            try:
                self._send_in()
                if tick % 4 == 0:
                    self._send_heartbeat()
            except Exception as e:
                log.error("Heartbeat: %s", e)

    def _poll_messages_loop(self):
        self._stopped.wait(0.5)
        while not self._stop:
            try:
                with self._dialog_lock:
                    mine = set(self._my_dialogs)
                with self._known_lock:
                    mine.update(self._known_dialogs)
                for h in mine:
                    self._send_ack("im", {
                        "operation": "im-dialog-messages",
                        "user": None,
                        "data": {
                            "opponent": h,
                            "limit": 100,
                            "last": None,
                            "additional": {"virtual": True},
                        },
                    }, pending=("messages", h))
                    self._stopped.wait(0.05)
            except Exception as e:
                log.error("Опрос сообщений: %s", e)
            self._stopped.wait(POLL_OWN_INTERVAL)

    def _poll_activity_loop(self):
        self._stopped.wait(1)
        while not self._stop:
            try:
                with self._known_lock:
                    dialogs = list(self._known_dialogs)
                self._send_ack("im", {
                    "operation": "im-dialog-recent-activity",
                    "user": None,
                    "data": {"dialogs": dialogs},
                }, pending=("activity", None))
            except Exception as e:
                log.error("Опрос диалогов: %s", e)
            self._stopped.wait(POLL_ACT_INTERVAL)

    def _on_ack(self, ack_id, data):
        with self._tx_lock:
            sent = self._tx_pending.pop(ack_id, None)
            deleted = self._drop_pending.pop(ack_id, None)
        if sent is not None:
            result = self._result(data)
            outer = data[0] if isinstance(data, list) and data else data
            for value in (outer, result):
                if value is False:
                    log.error("Y.Board rejected a message")
                    self.stop()
                    return
                if not isinstance(value, dict):
                    continue
                status = value.get("status", value.get("code"))
                if (value.get("error") or value.get("errors") or value.get("success") is False or
                        isinstance(status, int) and status >= 400 or
                        isinstance(status, str) and status.lower() in ("error", "failed", "fail")):
                    log.error("Y.Board rejected a message; increase TUNNEL_SEND_INTERVAL")
                    self.stop()
                    return
            if deleted and self._objects:
                self._objects.deletion_accepted(deleted)
            return
        with self._pending_lock:
            entry = self._pending_ack.pop(ack_id, None)
        if not entry:
            return
        kind, dialog_hash, _ = entry
        if kind == "activity":
            self._on_activity_ack(data)
        elif kind == "messages":
            self._on_messages_ack(dialog_hash, data)

    @staticmethod
    def _result(data):
        if isinstance(data, list):
            data = data[0] if data else {}
        if not isinstance(data, dict):
            return {}
        result = data.get("result", data)
        return result if isinstance(result, dict) else {}

    def _remember_dialog(self, dialog):
        if not isinstance(dialog, dict):
            return
        h = dialog.get("hash")
        starter = dialog.get("topic_starter") or {}
        if not isinstance(h, str) or not h or not isinstance(starter, dict):
            return
        content = starter.get("content") or ""
        if not isinstance(content, str) or not content.startswith(TUNNEL_PREFIX):
            return
        if _parse_iso(starter.get("creationdate", "")) < self._start_time:
            return
        with self._known_lock:
            is_new = h not in self._known_dialogs
            if is_new:
                if len(self._known_dialogs) >= 1024:
                    return
                self._known_dialogs.add(h)
        if is_new and self.on_dialog_created:
            self.on_dialog_created(dialog)
        self._deliver(starter, h)

    def _on_activity_ack(self, data):
        topics = self._result(data).get("topics") or {}
        if isinstance(topics, dict):
            for h, starter in topics.items():
                self._remember_dialog({"hash": h, "topic_starter": starter})

    def _on_messages_ack(self, dialog_hash, data):
        messages = self._result(data).get("messages") or []
        if isinstance(messages, list):
            for message in messages:
                self._deliver(message, dialog_hash)

    def _deliver(self, message, dialog_hash=None):
        if not isinstance(message, dict):
            return
        content = message.get("content") or ""
        if not isinstance(content, str) or not content.startswith(TUNNEL_PREFIX):
            return
        if message.get("sender") in {self.self_participant_hash, self.self_user_hash}:
            return
        if _parse_iso(message.get("creationdate", "")) < self._start_time:
            return
        if content.startswith(("TUNNEL:O:", "TUNNEL:D:", "TUNNEL:X:", "TUNNEL:C:")):
            meta = dict(message)
            if dialog_hash:
                meta["opponent"] = dialog_hash
            self._objects.comment(content, meta)

    def _on_open(self, ws):
        log.debug("WebSocket подключён")
        threading.Thread(target=self._pump, daemon=True).start()

    def _on_message_ws(self, ws, msg):
        if not isinstance(msg, str):
            return
        if self.debug:
            log.debug("WebSocket получено: %r", msg[:200])

        if msg.startswith("0{"):
            self._emit_raw("40")
            return

        if msg.startswith("40{") or msg == "40":
            try:
                self.self_session_id = json.loads(msg[2:]).get("sid")
            except Exception:
                pass
            self._emit_raw('420["im",{"operation":"subscribe","user":null}]')
            return

        if msg == "2":
            self._emit_raw("3")
            return

        if msg.startswith("43"):
            i = 2
            while i < len(msg) and msg[i].isdigit():
                i += 1
            try:
                ack_id = int(msg[2:i])
                data = json.loads(msg[i:])
            except Exception:
                return
            self._on_ack(ack_id, data)
            return

        if not msg.startswith("42"):
            return

        i = 2
        while i < len(msg) and msg[i].isdigit():
            i += 1
        try:
            arr = json.loads(msg[i:])
        except Exception:
            return
        if not isinstance(arr, list) or not arr:
            return
        ev = arr[0]
        p = arr[1] if len(arr) > 1 else None

        if ev == "subscribed":
            self._on_im_subscribed()
            return
        if not isinstance(p, dict):
            return
        if ev == "dashboard":
            self._on_dashboard(p)

    def _on_im_subscribed(self):
        if self._workers_started:
            return
        self._workers_started = True
        log.debug("Подписка im установлена")
        self._current_session = os.urandom(16).hex()
        uhash = self.self_user_hash or ""

        self._emit_raw('421["dashboard",{"action":"get-client-participant-numbers",'
                       '"data":{},"participant":"' + uhash + '"}]')

        data = {
            "session": self._current_session,
            "dashboard": self.slide_hash or self.board_hash,
            "presentation": self.board_hash,
            "properties": self.properties,
            "participant": uhash,
            "participant_team_role": -1,
            "options": {"type": "landing", "participant": {
                "hash": uhash, "partner": "yandex", "userHash": uhash,
                "name": self.name, "logo": "", "additional": {},
                "module": "yandex", "identityCandidates": {"uidHash": uhash},
                "module_type": "yandex", "participantCaptionName": self.name},
                "intermediate": os.urandom(16).hex(),
                "device": {"screen": "1920 x 1080", "screen_width": 1920,
                           "screen_height": 1080, "browser": "Chrome",
                           "browserVersion": "154.0", "mobile": False,
                           "os": "Windows", "cookies": True,
                           "userAgent": UA, "platform": "Win32"}},
        }
        payload = {"action": "subscribe-slide-dashboard",
                   "data": data, "participant": uhash}
        self._emit_raw("422" + json.dumps(["dashboard", payload]))

        self._send_in()
        self._send_heartbeat()
        threading.Thread(target=self._keepalive_loop, daemon=True).start()
        threading.Thread(target=self._poll_messages_loop, daemon=True).start()
        threading.Thread(target=self._poll_activity_loop, daemon=True).start()

    def _on_dashboard(self, p):
        action = p.get("action")
        data = p.get("data") or {}
        if not isinstance(data, dict):
            return
        if self._objects and action == "drop-objects":
            self._objects.objects_dropped(data.get("objects"))
            return
        if self._objects and isinstance(data.get("objects"), list):
            self._objects.objects_changed(data["objects"])
            log.debug("Object event action=%s count=%d", action, len(data["objects"]))
            return

        if action == "participant-connected":
            part = data.get("participant") or {}
            if not isinstance(part, dict):
                return
            if part.get("session") == self._current_session:
                self.self_participant_hash = part.get("hash")
                if self.self_participant_hash:
                    self._ready.set()
                log.debug("Участник подключён: %s", self.self_participant_hash)
            return

        if action == "im-dialog-created":
            self._remember_dialog(data.get("dialog"))

        elif action == "im-comment":
            self._deliver(data.get("message", {}))

        elif action == "im-dialog-removed":
            h = data.get("hash") or data.get("opponent")
            with self._known_lock:
                self._known_dialogs.discard(h)
            with self._dialog_lock:
                self._my_dialogs.discard(h)
                if self._current_dialog == h:
                    self._current_dialog = None
            if self.on_dialog_removed:
                self.on_dialog_removed(h)

