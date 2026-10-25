import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .keygen import generate_code

SEPARATOR = "( * )( * )"
CONFIG_VERSION = 1
CHARACTERS = ("Вавилен Татарский", "Сергей Морковин", "Гусейн", "Дмитрий Пугин", "Владимир Ханин", "Андрей Гиреев", "Фарсук Сейфуль-Фарсейкин", "Малюта", "Че Гевара", "Иштар", "Пётр Пустота", "Василий Чапаев", "Сердюк", "Мария (Просто Мария)", "Володин", "Тимур Тимурович Канашников", "Анна", "Котовский", "Барон фон Юнгерн", "Арнольд Шварценеггер", "Артур", "Арнольд", "Сэм", "Марина", "Николай (майор)", "Наташа", "Дима", "Митя", "Максим", "Никита", "Омка Кривомазов", "Сёма Аникин", "Иван Гречка", "Дима Матюшевич", "Бамлаг Иванович", "Пхадзер Владиленович", "Майор Иван Трофимович Попадья", "Отто Плуцис", "Собака Лайка", "Демьян-Ландульф Дамилола Карпов", "Кая", "Грым", "Хлоя", "Роман Александрович Шторкин", "Брама", "Гера", "Энлиль Маратович", "Озирис", "Локи", "Бальдр", "Иегова", "А Хули", "Александр Серый", "Михалыч", "Павел Иванович", "Лорд Крикет", "Ринпоче", "Monstradamus", "IsoldA", "Nutscracker", "Organizm", "Theseus (TheZeus)", "Ariadna", "UGLI 666", "Romeo-y-Cohiba", "Граф Т.", "Ариэль", "Владимир Соловьёв", "Обер-прокурор Синода Победоносцев", "Лев Толстой", "Фёдор Достоевский", "Порфирий Петрович", "Маруха Чо", "Александра Орлова", "Со", "Тим", "Фрэнк", "Наоми", "Император Каракалла", "Император Элагабал", "Маня", "Сасаки-сан", "Иван", "Няша", "Атон Гольденштерн", "Шарабан-Мухлюев", "Степан Михайлов", "Георгий Сракандаев", "Мюс Джулиановна", "Кика Нафиков", "Леня Лебедкин", "Иса", "Муса", "Простислав", "Йцукен")


@dataclass
class TransportSettings:
    object_chars: int = 10000
    object_window: int = 128
    chunk_bytes: int = 16384
    stream_window: int = 32
    send_interval: float = 0.005
    ack_window: int = 0
    ack_timeout: float = 20.0
    object_retry: float = 2.0
    object_ttl: float = 120.0
    frame_retry: float = 5.0
    frame_retries: int = 6
    connect_timeout: float = 20.0

    def validate(self):
        limits = {
            "object_chars": (512, 1000000), "object_window": (9, 4096),
            "chunk_bytes": (1, 24576), "stream_window": (1, 256),
            "send_interval": (0.001, 1), "ack_window": (0, 512),
            "ack_timeout": (1, 3600), "object_retry": (0.1, 60),
            "object_ttl": (5, 3600), "frame_retry": (0.1, 120),
            "frame_retries": (1, 100), "connect_timeout": (1, 300),
        }
        defaults = TransportSettings()
        for name, (low, high) in limits.items():
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float)) or
                    not math.isfinite(value) or not low <= value <= high or
                    isinstance(getattr(defaults, name), int) and not isinstance(value, int)):
                raise ValueError(f"{name}: требуется значение от {low} до {high}")
        if self.object_ttl <= self.object_retry:
            raise ValueError("object_ttl должен быть больше object_retry")


@dataclass
class SharedConfig:
    board_hash: str = ""
    tunnel_key: str = ""
    key_format: str = "scrypt-v1"
    kdf_salt: str = ""
    transport: TransportSettings = field(default_factory=TransportSettings)

    def validate(self):
        self.board_hash = board_hash(self.board_hash)
        if not self.tunnel_key or len(self.tunnel_key) > 4096 or any(ord(c) < 32 for c in self.tunnel_key):
            raise ValueError("Ключ должен быть непустой строкой без управляющих символов")
        if SEPARATOR in self.tunnel_key:
            raise ValueError("Ключ содержит разделитель строки подключения")
        if self.key_format == "raw-hex":
            if not re.fullmatch(r"[0-9a-fA-F]{64}", self.tunnel_key):
                raise ValueError("raw-hex требует 64 hex-символа")
        elif self.key_format == "scrypt-v1":
            try:
                salt = base64.b64decode(self.kdf_salt, validate=True)
            except Exception as exc:
                raise ValueError("Неверная соль scrypt") from exc
            if len(salt) != 16:
                raise ValueError("Соль scrypt должна содержать 16 байт")
        else:
            raise ValueError("Неизвестный формат ключа")
        self.transport.validate()

    def cipher_key(self):
        self.validate()
        if self.key_format == "raw-hex":
            return bytes.fromhex(self.tunnel_key)
        return hashlib.scrypt(self.tunnel_key.encode("utf-8"),
                              salt=base64.b64decode(self.kdf_salt),
                              n=16384, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)


@dataclass
class LocalConfig:
    guest_name: str = ""
    state_dir: str = ".tunnel-state"
    ws_url: str = ""
    cookies: str = ""
    debug: bool = False
    socks_host: str = "127.0.0.1"
    socks_port: int = 1080


@dataclass
class AppConfig:
    role: str
    shared: SharedConfig
    local: LocalConfig
    version: int = CONFIG_VERSION

    def validate(self):
        if self.role not in ("client", "server") or self.version != CONFIG_VERSION:
            raise ValueError("Неверная роль или версия конфига")
        self.shared.validate()
        if not isinstance(self.local.guest_name, str) or not 1 <= len(self.local.guest_name) <= 100:
            raise ValueError("guest_name: требуется от 1 до 100 символов")
        for text in (self.local.guest_name, self.local.state_dir, self.local.cookies):
            if not isinstance(text, str) or any(ord(c) < 32 for c in text):
                raise ValueError("Недопустимое значение локального параметра")
        if not self.local.state_dir:
            raise ValueError("state_dir не должен быть пустым")
        if not isinstance(self.local.debug, bool):
            raise ValueError("debug должен быть true/false")
        if self.local.ws_url:
            from .transport_board import socket_url
            socket_url(self.local.ws_url)
        if self.role == "client":
            ipaddress.ip_address(self.local.socks_host)
            if isinstance(self.local.socks_port, bool) or not isinstance(self.local.socks_port, int) or not 1 <= self.local.socks_port <= 65535:
                raise ValueError("SOCKS port: требуется 1..65535")


def board_hash(value):
    if not isinstance(value, str):
        raise ValueError("Неверный hash доски")
    value = value.strip()
    if "://" in value:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or parsed.hostname != "boards.yandex.ru":
            raise ValueError("Нужна ссылка https://boards.yandex.ru/... или hash")
        value = parse_qs(parsed.query).get("hash", [""])[0]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value):
        raise ValueError("Не найден корректный hash доски")
    return value


def connection_line(shared):
    shared.validate()
    other = {"version": CONFIG_VERSION, "key_format": shared.key_format,
             "kdf_salt": shared.kdf_salt, "transport": asdict(shared.transport)}
    return SEPARATOR.join((shared.board_hash, shared.tunnel_key,
                           json.dumps(other, ensure_ascii=True, separators=(",", ":")), ""))


def parse_connection_line(line):
    if len(line) > 20000:
        raise ValueError("Строка подключения слишком длинная")
    parts = line.strip().split(SEPARATOR)
    if len(parts) != 4 or parts[-1] != "":
        raise ValueError("Ожидается board_hash( * )( * )tunnel_key( * )( * )otherconfiginfo( * )( * )")
    try:
        other = json.loads(parts[2])
        if other["version"] != CONFIG_VERSION:
            raise ValueError("Версия строки подключения не поддерживается")
        result = SharedConfig(parts[0], parts[1], other["key_format"], other["kdf_salt"],
                              TransportSettings(**other["transport"]))
        result.validate()
        return result
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Некорректные параметры строки подключения") from exc


def save_config(path, config):
    config.validate()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(asdict(config), out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_config(path, role, validate=True):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("role") != role or data.get("version") != CONFIG_VERSION:
        raise ValueError("Конфиг другой роли или неподдерживаемой версии")
    shared = dict(data["shared"])
    shared["transport"] = TransportSettings(**shared.get("transport", {}))
    result = AppConfig(role, SharedConfig(**shared), LocalConfig(**data["local"]), data["version"])
    if validate:
        result.validate()
    return result


QUESTIONS = (
    ("object_chars", "Символов в текстовом поле"),
    ("object_window", "Незавершённых текстовых полей на сторону"),
    ("chunk_bytes", "Размер чтения TCP, байт"),
    ("stream_window", "Кадров без подтверждения на поток"),
    ("send_interval", "Интервал отправки пакетов, секунд"),
    ("ack_window", "Окно служебных ACK (0 — не требовать)"),
    ("ack_timeout", "Таймаут служебного ACK, секунд"),
    ("object_retry", "Повтор объектов/очистки, секунд"),
    ("object_ttl", "Предельное ожидание доставки/очистки, секунд"),
    ("frame_retry", "Повтор DATA/FIN, секунд"),
    ("frame_retries", "Количество повторов DATA/FIN"),
    ("connect_timeout", "Таймаут открытия TCP, секунд"),
)


def ask(label, default, cast=str, check=None, *, input_fn=input, output_fn=print):
    while True:
        raw = input_fn(f"{label} [{default}]: ").strip()
        try:
            value = cast(raw) if raw else default
            if check:
                check(value)
            return value
        except (ValueError, TypeError):
            output_fn("Некорректное значение, повторите ввод.")


def generated_name():
    return secrets.choice(CHARACTERS) + "_" + secrets.token_hex(3)


def nonempty(value):
    if not value.strip():
        raise ValueError("Пустое значение")


def binary_flag(value):
    if value not in (0, 1):
        raise ValueError("Нужно 0 или 1")


def valid_port(value):
    if not 1 <= value <= 65535:
        raise ValueError("Нужен порт 1..65535")


def configure(role, existing=None, *, new_key=False, input_fn=input, output_fn=print):
    shared = existing.shared if existing else SharedConfig()
    local = existing.local if existing else LocalConfig()
    def prompt(label, default, cast=str, check=None):
        return ask(label, default, cast, check, input_fn=input_fn, output_fn=output_fn)

    if role == "client" and (existing is None or not shared.tunnel_key):
        while True:
            raw = input_fn("Вставьте ключ: ").strip()
            try:
                if SEPARATOR in raw:
                    shared = parse_connection_line(raw)
                elif raw:
                    shared.tunnel_key = raw
                    shared.board_hash = prompt("Hash/ссылка доски", shared.board_hash, check=board_hash)
                    if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
                        shared.key_format, shared.kdf_salt = "raw-hex", ""
                    else:
                        shared.key_format = "scrypt-v1"
                        shared.kdf_salt = prompt("Соль kdf_salt из конфига сервера", shared.kdf_salt)
                    shared.validate()
                else:
                    raise ValueError("Пустая строка")
                break
            except ValueError as exc:
                output_fn(str(exc))
    if role == "server":
        shared.board_hash = board_hash(prompt("Hash или ссылка доски", shared.board_hash, check=board_hash))
        if not shared.tunnel_key or new_key:
            shared.tunnel_key = generate_code()
            shared.key_format = "scrypt-v1"
            shared.kdf_salt = base64.b64encode(secrets.token_bytes(16)).decode()
            output_fn("Ключ шифрования создан кейгеном")
        for name, label in QUESTIONS:
            current = getattr(shared.transport, name)
            def valid(value, name=name):
                candidate = TransportSettings(**{**asdict(shared.transport), name: value})
                candidate.validate()
            setattr(shared.transport, name, prompt(label, current, type(current), valid))

    if not local.guest_name:
        local.guest_name = generated_name()
    output_fn("Имя гостя: " + local.guest_name)
    local.state_dir = prompt("Папка журнала очистки", local.state_dir, check=nonempty)
    def check_ws(value):
        if value:
            from .transport_board import socket_url
            socket_url(value)
    local.ws_url = prompt("WebSocket URL (auto — автоопределение)", local.ws_url,
                          lambda v: "" if v.lower() == "auto" else v, check_ws)
    local.cookies = prompt("Cookie своей сессии (- — гостевой вход)", local.cookies,
                           lambda v: "" if v == "-" else v)
    local.debug = prompt("Подробные логи: 0/1", int(local.debug), int, binary_flag) == 1
    if role == "client":
        local.socks_host = prompt("Адрес локального SOCKS", local.socks_host, check=ipaddress.ip_address)
        local.socks_port = prompt("Порт локального SOCKS", local.socks_port, int, valid_port)
    config = AppConfig(role, shared, local)
    config.validate()
    return config


def bootstrap(role, argv=None, *, input_fn=input, output_fn=print):
    parser = argparse.ArgumentParser(description="Y.Board " + role)
    parser.add_argument("--config", default=f"config.{role}.json")
    parser.add_argument("--configure", action="store_true", help="Повторить вопросы настройки")
    parser.add_argument("--setup-only", action="store_true", help="Сохранить конфиг без подключения")
    if role == "server":
        parser.add_argument("--share", action="store_true", help="Показать строку подключения без сети")
        parser.add_argument("--new-key", action="store_true", help="Создать новый ключ и повторить настройку")
    else:
        parser.add_argument("--import-connection", action="store_true", help="Заменить данные подключения строкой сервера")
    args = parser.parse_args(argv)
    path = Path(args.config).resolve()
    existing = read_config(path, role, validate=False) if path.exists() else None
    if existing and getattr(args, "import_connection", False):
        existing.shared.tunnel_key = ""
    incomplete = existing is None or not existing.shared.tunnel_key
    if incomplete or args.configure or getattr(args, "new_key", False):
        output_fn("Настройка: Enter оставляет значение по умолчанию")
        config = configure(role, existing, new_key=getattr(args, "new_key", False),
                           input_fn=input_fn, output_fn=output_fn)
        save_config(path, config)
        output_fn("Конфиг сохранён: " + str(path))
    else:
        config = existing
        config.validate()
    if role == "server":
        output_fn("Ключ для клиента:")
        output_fn(connection_line(config.shared))
    return config, path, args.setup_only or getattr(args, "share", False)
