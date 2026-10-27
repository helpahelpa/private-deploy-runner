"""Bounded, private-by-default build output for the trusted deployment controller.

Only explicitly selected text commands belong here. Raw stdout/stderr remain private;
the journal is the sole output suitable for forwarding to a GitHub Actions job.
"""
import codecs
import fcntl
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import subprocess
import threading
import time

MAX_JOURNAL = 2 * 1024 * 1024
MAX_LINE = 8192
MAX_CAPTURE = 64 * 1024 * 1024
PAGE_BUDGET = 3200
TRUNCATED = b"[build] Build log limit reached; further output omitted.\n"
OMITTED = "[long line omitted]"
FILE_ENV = "PRIVATE_BUILD_LOG_FILE"
PRIVACY_ENV = "PRIVATE_BUILD_LOG_PRIVACY"
ERROR = "build log privacy validation failed"
_EMIT_LOCK = threading.Lock()
_EMIT_PEM = {}


def _safe_path(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError(ERROR)
    for parent in reversed(path.parents):
        if parent.is_symlink():
            raise ValueError(ERROR)
    if path.is_symlink():
        raise ValueError(ERROR)
    return path


def _open(path, flags):
    path = _safe_path(path)
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError(ERROR)
    return fd


def configure(directory, literals=None):
    """Create an append-only public journal and private redaction configuration.

    Existing journals are retained across retries. These environment variables are
    for trusted host children only and must never be passed into source containers.
    """
    directory = _safe_path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    values = list(literals or []) + [str(Path.home()), socket.gethostname(), getpass.getuser()]
    if any(not isinstance(value, str) or len(value) > 16384 for value in values) or len(values) > 10000:
        raise ValueError(ERROR)
    # Avoid a generic short username damaging every ordinary test name.
    values = sorted({value for value in values if value and len(value) >= 3}, key=len, reverse=True)
    data = json.dumps({"literals": values}, ensure_ascii=True).encode()
    if len(data) > 1024 * 1024:
        raise ValueError(ERROR)
    privacy = directory / "privacy.json"
    fd = _open(privacy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    journal = directory / "journal.log"
    fd = _open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    os.close(fd)
    os.environ[FILE_ENV] = str(journal)
    os.environ[PRIVACY_ENV] = str(privacy)
    return journal


def _settings():
    if FILE_ENV not in os.environ and PRIVACY_ENV not in os.environ:
        return None
    try:
        journal = _safe_path(os.environ[FILE_ENV])
        fd = _open(os.environ[PRIVACY_ENV], os.O_RDONLY)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError(ERROR)
        config = json.loads(data)
        values = config["literals"]
        if (set(config) != {"literals"} or not isinstance(values, list) or len(values) > 10000
                or any(not isinstance(value, str) or not 3 <= len(value) <= 16384 for value in values)):
            raise ValueError(ERROR)
        return journal, values
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError(ERROR) from None


def _append(path, line):
    data = ("[build] " + line + "\n").encode("utf-8")
    fd = _open(path, os.O_RDWR | os.O_APPEND)
    with os.fdopen(fd, "r+b", buffering=0) as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        size = os.fstat(stream.fileno()).st_size
        if size >= MAX_JOURNAL:
            return
        stream.seek(max(0, size - len(TRUNCATED)))
        if stream.read() == TRUNCATED:
            return
        if size + len(data) > MAX_JOURNAL - len(TRUNCATED):
            data = TRUNCATED
        os.write(stream.fileno(), data)


ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6 = re.compile(r"(?<![\w:])\[?[0-9a-fA-F:]*:[0-9a-fA-F:.]+(?:%[\w.-]+)?\]?(?![\w:])")
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
USER_PATH = re.compile(r"(?i)(?:[a-z]:[\\/]|/(?:home|users|root)(?:/|\b)|/mnt/[a-z]/)[^\s\"'<>]*")
URL_AUTH = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@")
CREDENTIAL = re.compile(r"(?i)\b(?:authorization\s*[:=]\s*|bearer\s+|(?:[a-z_]*(?:token|password|passwd|secret|api[_-]?key|credential|signature)[a-z_]*)[\"']?\s*[:=]\s*).*")
KNOWN_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")


def _ip(match):
    value = match.group().strip("[]").split("%", 1)[0]
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return match.group()
    return "[private address]"


class _Lines:
    """A separate incremental decoder, line buffer, and PEM state per stream."""
    def __init__(self, settings):
        self.settings = settings
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.buffer = ""
        self.overflow = False
        self.pem = False
        self.boundary = ""
        self.pending_pem = False

    def line(self, value):
        if self.settings is None:
            return
        if PEM_BEGIN.search(value):
            for match in re.finditer(r"-----((?:BEGIN|END)) [A-Z0-9 ]+-----", value):
                self.pem = match[1] == "BEGIN"
            _append(self.settings[0], "[PEM material omitted]")
            return
        if self.pem:
            if PEM_END.search(value):
                self.pem = False
            return
        if PEM_END.search(value):
            return
        if len(value.encode("utf-8")) > MAX_LINE:
            value = OMITTED
        value = ANSI.sub("", value)
        value = "".join(char for char in value if char == "\t" or
                        (ord(char) >= 32 and not 127 <= ord(char) <= 159))
        # Literal matches happen both before and after control removal, preventing
        # ANSI-wrapped private literals from escaping the configured redactions.
        for literal in self.settings[1]:
            value = value.replace(literal, "[private]")
        value = URL_AUTH.sub(r"\1[private]@", value)
        value = CREDENTIAL.sub("[credentials omitted]", value)
        value = KNOWN_TOKEN.sub("[private token]", value)
        value = EMAIL.sub("[private email]", value)
        value = USER_PATH.sub("[private path]", value)
        value = IPV4.sub(_ip, value)
        value = IPV6.sub(_ip, value)
        # Every rendered line starts with a fixed prefix, including workflow
        # commands emitted by an untrusted compiler/test or a terminal reset.
        _append(self.settings[0], value)

    def feed(self, data, final=False):
        value = self.decoder.decode(data, final=final)
        for part in re.split(r"([\r\n])", value):
            if part in ("\r", "\n"):
                if self.overflow:
                    self.pem = self.pending_pem
                    if self.settings is not None:
                        _append(self.settings[0], OMITTED)
                elif self.buffer:
                    self.line(self.buffer)
                self.buffer = ""
                self.overflow = False
                self.boundary = ""
                self.pending_pem = self.pem
            else:
                # Even an omitted line may begin/end a PEM block. Keep only a
                # bounded suffix for boundaries split across reads.
                scan = self.boundary + part
                for match in re.finditer(r"-----((?:BEGIN|END)) [A-Z0-9 ]+-----", scan):
                    self.pending_pem = match[1] == "BEGIN"
                self.boundary = scan[-96:]
                if not self.overflow:
                    self.buffer += part
                    if len(self.buffer.encode("utf-8")) > MAX_LINE:
                        self.buffer = ""
                        self.overflow = True
        if final:
            if self.overflow:
                self.pem = self.pending_pem
                if self.settings is not None:
                    _append(self.settings[0], OMITTED)
            elif self.buffer:
                self.line(self.buffer)
            self.buffer = ""


def emit(text):
    """Append explicitly safe-selected text after redaction; never print raw data."""
    if not isinstance(text, str):
        raise ValueError(ERROR)
    settings = _settings()
    if settings is not None:
        with _EMIT_LOCK:
            stream = _Lines(settings)
            stream.pem = stream.pending_pem = _EMIT_PEM.get(str(settings[0]), False)
            stream.feed(text.encode("utf-8", errors="replace"), final=True)
            if len(_EMIT_PEM) > 64:
                _EMIT_PEM.pop(next(iter(_EMIT_PEM)))
            _EMIT_PEM[str(settings[0])] = stream.pem


def _private_log(path, stdout, stderr):
    if path is None:
        return
    fd = _open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as stream:
        stream.write(stdout + b"\nSTDERR\n" + stderr)


def run(args, *, timeout, log=None):
    """Capture original bytes privately while forwarding sanitized lines live."""
    settings = _settings()  # Invalid privacy configuration fails before execution.
    if settings is None:
        result = subprocess.run(args, capture_output=True, timeout=timeout)
        _private_log(log, result.stdout, result.stderr)
        return result
    captures = {"stdout": bytearray(), "stderr": bytearray()}
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    for name in captures:
        pipe = getattr(process, name)
        selector.register(pipe, selectors.EVENT_READ, (name, _Lines(settings)))
    started = time.monotonic()
    failure = None
    killed = None
    try:
        while selector.get_map():
            now = time.monotonic()
            if failure is None and now - started > timeout:
                failure = "timeout"
                process.kill()
                killed = now
            if killed is not None and now - killed > 1:
                break  # A descendant must not keep inherited pipes open forever.
            for key, _ in selector.select(0.05):
                name, lines = key.data
                data = os.read(key.fd, 4096)
                if not data:
                    lines.feed(b"", final=True)
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if sum(map(len, captures.values())) + len(data) > MAX_CAPTURE:
                    if failure is None:
                        failure = "limit"
                        process.kill()
                        killed = time.monotonic()
                    continue
                captures[name].extend(data)
                lines.feed(data)
        try:
            process.wait(timeout=2 if failure else max(0.001, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            failure = failure or "timeout"
            process.kill()
            process.wait()
    except BaseException:
        process.kill()
        process.wait()
        raise
    finally:
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()
    stdout, stderr = bytes(captures["stdout"]), bytes(captures["stderr"])
    _private_log(log, stdout, stderr)
    if failure == "timeout":
        raise subprocess.TimeoutExpired(args, timeout, output=stdout, stderr=stderr)
    if failure:
        raise RuntimeError("build output exceeded private capture limit")
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def read_page(path, cursor):
    """Read a bounded UTF-8 page; cursors are byte offsets into the fixed journal."""
    if type(cursor) is not int or cursor < 0:
        raise ValueError(ERROR)
    try:
        try:
            fd = _open(path, os.O_RDONLY)
        except FileNotFoundError:
            if cursor == 0:
                return {"text": "", "cursor": 0, "more": False}
            raise ValueError(ERROR) from None
        with os.fdopen(fd, "rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            if size > MAX_JOURNAL or cursor > size:
                raise ValueError(ERROR)
            stream.seek(cursor)
            raw = stream.read(4096)
        if raw and raw[0] & 0xC0 == 0x80:
            raise ValueError(ERROR)
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        text = decoder.decode(raw, final=cursor + len(raw) == size)
        page = {"text": "", "cursor": cursor, "more": cursor < size}
        for char in text:
            candidate = {"text": page["text"] + char,
                         "cursor": page["cursor"] + len(char.encode("utf-8")),
                         "more": page["cursor"] + len(char.encode("utf-8")) < size}
            if len(json.dumps(candidate).encode("utf-8")) >= PAGE_BUDGET:
                break
            page = candidate
        return page
    except (OSError, ValueError, UnicodeError):
        raise ValueError(ERROR) from None
