"""Loopback HTTP harness for www/includes/api_server.py (shared by
tools/auth_gate_check.py and tools/route_permission_check.py).

The real Handler serves on 127.0.0.1:<random> in this process; the real
session/cookie/gate code runs. Users live in a scratch auth.json (real
PBKDF2 records), sessions are created with the real _create_session, and the
token files (internal token, canary webhook token, agent read token) point
at known values in the scratch dir.

Fail-closed sandbox (sandbox=True): before the module is loaded, every
primitive that could change the host is replaced by a guard that RAISES
SideEffectBlocked and records the attempt against the request that made it:
subprocesses (Popen/run/os.system/exec/spawn/fork), signals, writes and
metadata changes outside the scratch dir (open/os.open in a write mode,
rename/replace/unlink/mkdir/chmod/chown/symlink/truncate/utime, shutil),
and every network connection other than to the harness server itself
(including DNS lookups and unix sockets). Reads are allowed. A handler that
gets as far as a side effect therefore fails (500 / dropped connection)
instead of touching the router, and the caller can assert that a refused
request never attempted one.

Usage:
    h = api_harness.Harness()           # loads the module, starts the server
    r = h.request("GET", "/api/status", role="viewer")
    r.status, r.json, r.headers, r.effects
    h.close()
"""
import builtins
import http.client
import importlib.util
import io
import itertools
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

USERS = (
    # username, role, owner, password (test-only)
    ("boss", "admin", True, "harness-admin-pw-1"),
    ("watcher", "viewer", False, "harness-viewer-pw-1"),
)
INTERNAL_TOKEN = "harness-internal-token-0123456789abcdef0123456789abcdef"
CANARY_TOKEN = "harness-canary-token-0123456789abcdef"
AGENT_TOKEN = "harness-agent-read-token-0123456789abcdef01234"
REQ_HEADER = "X-Harness-Req"


class SideEffectBlocked(Exception):
    """Raised by the sandbox instead of performing a side effect. The
    message never carries the path/command (handlers may echo it)."""

    def __init__(self, kind):
        super().__init__("side effect blocked by the test harness (%s)" % kind)
        self.kind = kind


_tl = threading.local()
_effects = {}            # request tag (or "-") -> [(kind, detail)]
_effects_lock = threading.Lock()
_allowed_dirs = []       # scratch dirs where writes are allowed
_allowed_ports = set()   # loopback ports the sandbox may connect to
_installed = False
_real = {}


def current_tag():
    return getattr(_tl, "req", None)


def _record(kind, detail):
    tag = current_tag() or "-"
    with _effects_lock:
        _effects.setdefault(tag, []).append((kind, str(detail)[:300]))


def effects_for(tag):
    with _effects_lock:
        return list(_effects.get(tag, ()))


def untagged_effects():
    return effects_for("-")


def _inside_scratch(path, dir_fd=None):
    try:
        if isinstance(path, int):
            return True          # an fd: only obtainable through the guarded opens
        p = os.fsdecode(path)
        if dir_fd is not None and not os.path.isabs(p):
            p = os.path.join(os.readlink("/proc/self/fd/%d" % dir_fd), p)
        p = os.path.realpath(p)
    except Exception:
        return False
    return any(p == d or p.startswith(d + os.sep) for d in _allowed_dirs)


def _block(kind, detail):
    if getattr(_tl, "harness_io", False):
        return               # the harness's own scratch bookkeeping
    _record(kind, detail)
    raise SideEffectBlocked(kind)


class _HarnessIO:
    def __enter__(self):
        _tl.harness_io = True

    def __exit__(self, *exc):
        _tl.harness_io = False


def install_sandbox():
    """Idempotent; process-wide (the test process is throwaway)."""
    global _installed
    if _installed:
        return
    _installed = True

    class BlockedPopen:
        def __init__(self, args, *a, **k):
            _block("subprocess", args)

    for name in ("Popen", "run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
        _real["subprocess." + name] = getattr(subprocess, name)
    subprocess.Popen = BlockedPopen
    for name in ("run", "call", "check_call", "check_output", "getoutput", "getstatusoutput"):
        setattr(subprocess, name, (lambda n: lambda *a, **k: _block("subprocess", a[0] if a else k.get("args")))(name))

    for name in ("system", "popen", "fork", "forkpty", "kill", "killpg", "posix_spawn", "posix_spawnp",
                 "execv", "execve", "execl", "execle", "execlp", "execlpe", "execvp", "execvpe",
                 "spawnv", "spawnve", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnvp", "spawnvpe"):
        if hasattr(os, name):
            setattr(os, name, (lambda n: lambda *a, **k: _block("os." + n, a[:1]))(name))
    signal.pthread_kill = lambda *a, **k: _block("signal", a)

    real_open = builtins.open

    def guarded_open(file, mode="r", *a, **k):
        if any(c in mode for c in "wax+") and not _inside_scratch(file):
            _block("write", file)
        return real_open(file, mode, *a, **k)

    builtins.open = guarded_open
    io.open = guarded_open

    real_os_open = os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND

    def guarded_os_open(path, flags, *a, **k):
        if flags & write_flags and not _inside_scratch(path, k.get("dir_fd")):
            _block("write", path)
        return real_os_open(path, flags, *a, **k)

    os.open = guarded_os_open

    def path_guard(name, nargs=1):
        real = getattr(os, name)

        def guarded(*a, **k):
            for p in a[:nargs]:
                if not _inside_scratch(p, k.get("dir_fd") or k.get("src_dir_fd")):
                    _block("os." + name, p)
            return real(*a, **k)
        setattr(os, name, guarded)

    for name in ("remove", "unlink", "rmdir", "chmod", "chown", "lchown", "truncate", "utime",
                 "mkfifo", "mknod", "removedirs", "setxattr", "removexattr"):
        if hasattr(os, name):
            path_guard(name)
    for name in ("rename", "replace", "link", "symlink"):
        path_guard(name, 2)

    real_mkdir = os.mkdir

    def guarded_mkdir(path, *a, **k):
        if not _inside_scratch(path, k.get("dir_fd")) and not os.path.isdir(path):
            _block("os.mkdir", path)
        return real_mkdir(path, *a, **k)

    os.mkdir = guarded_mkdir
    for name in ("copy", "copy2", "copyfile", "copytree", "move", "rmtree", "chown", "copymode", "copystat"):
        real = getattr(shutil, name)

        def guarded(*a, _real=real, _n=name, **k):
            dst = a[1] if len(a) > 1 and _n not in ("rmtree", "chown") else (a[0] if a else None)
            if not _inside_scratch(dst):
                _block("shutil." + _n, dst)
            return _real(*a, **k)
        setattr(shutil, name, guarded)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def allowed_addr(sock, addr):
        if sock.family in (socket.AF_INET, socket.AF_INET6) and isinstance(addr, tuple):
            return addr[0] in ("127.0.0.1", "::1", "localhost") and addr[1] in _allowed_ports
        return False

    def guarded_connect(self, addr):
        if not allowed_addr(self, addr):
            _block("connect", addr)
        return real_connect(self, addr)

    def guarded_connect_ex(self, addr):
        if not allowed_addr(self, addr):
            _block("connect", addr)
        return real_connect_ex(self, addr)

    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    for name in ("sendto", "sendmsg"):
        setattr(socket.socket, name, (lambda n: lambda self, *a, **k: _block("socket." + n, ""))(name))
    real_gai = socket.getaddrinfo

    def guarded_gai(host, *a, **k):
        if host not in ("127.0.0.1", "::1", "localhost", None):
            _block("dns", host)
        return real_gai(host, *a, **k)

    socket.getaddrinfo = guarded_gai

    real_sleep = time.sleep

    def capped_sleep(secs):
        # handler threads only: a request never waits for real time
        real_sleep(min(secs, 0.05) if current_tag() else secs)

    time.sleep = capped_sleep

    real_hook = threading.excepthook

    def quiet_hook(args):
        # background threads started by handlers die on a blocked effect
        if not isinstance(args.exc_value, SideEffectBlocked):
            real_hook(args)

    threading.excepthook = quiet_hook
    try:
        import sqlite3
        real_sq = sqlite3.connect

        def guarded_sq(db, *a, **k):
            if db != ":memory:" and not _inside_scratch(db):
                _block("sqlite", db)
            return real_sq(db, *a, **k)
        sqlite3.connect = guarded_sq
    except ImportError:
        pass


def load_module(target=TARGET, name="api_server_harness", quiet=True):
    spec = importlib.util.spec_from_file_location(name, target)
    mod = importlib.util.module_from_spec(spec)
    if quiet:
        out = sys.stdout
        sys.stdout = io.StringIO()
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.stdout = out
        mod.print = lambda *a, **k: None   # handler log lines (module globals only)
    else:
        spec.loader.exec_module(mod)
    return mod


class Response:
    __slots__ = ("status", "headers", "body", "json", "effects", "error", "tag", "trace")

    def __init__(self):
        self.status = None
        self.headers = {}
        self.body = b""
        self.json = None
        self.effects = []
        self.error = ""
        self.tag = ""
        self.trace = ""

    @property
    def content_type(self):
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()

    def set_cookies(self):
        return [v for k, v in self.headers.get("_all", []) if k == "set-cookie"]


_MISSING = object()
_BASE_TMP = tempfile.gettempdir()     # before any harness points tempfile at its scratch


class Harness:
    """Load api_server (or a mutant copy) and serve it on loopback."""

    SAME = "same"          # origin=Harness.SAME -> http://127.0.0.1:<port>

    def __init__(self, target=TARGET, sandbox=True, name=None, scratch=None):
        with _HarnessIO():
            self.scratch = scratch or tempfile.mkdtemp(prefix="tw-harness-", dir=_BASE_TMP)
        self._own_scratch = scratch is None
        _allowed_dirs.append(os.path.realpath(self.scratch))
        self._prev_tempdir = tempfile.tempdir
        if sandbox:
            install_sandbox()
            tempfile.tempdir = self.scratch
        self.mod = mod = load_module(target, name or "api_server_harness_%d" % id(self))
        self._fixtures()
        self._traces = {}
        harness = self

        class TaggedHandler(mod.Handler):
            def parse_request(self):
                ok = super().parse_request()
                _tl.req = self.headers.get(REQ_HEADER) if ok else None
                return ok

        class Server(mod.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                harness._traces[current_tag() or "-"] = traceback.format_exc()

        self.server = Server(("127.0.0.1", 0), TaggedHandler)
        self.port = self.server.server_address[1]
        _allowed_ports.add(self.port)
        self.origin = "http://127.0.0.1:%d" % self.port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self._seq = itertools.count(1)
        self._tag_prefix = "h%x-" % id(self)

    def _fixtures(self):
        mod, s = self.mod, self.scratch
        mod.AUTH_FILE = os.path.join(s, "auth.json")
        mod.INTERNAL_TOKEN_FILE = os.path.join(s, "internal-token")
        mod.CANARY_TOKEN_FILE = os.path.join(s, "canary-token")
        mod.AGENT_API_TOKEN_DIR = os.path.join(s, "agent")
        mod.AGENT_API_TOKEN_FILE = os.path.join(s, "agent", "api.token")
        os.makedirs(mod.AGENT_API_TOKEN_DIR, exist_ok=True)
        for path, val in ((mod.INTERNAL_TOKEN_FILE, INTERNAL_TOKEN), (mod.CANARY_TOKEN_FILE, CANARY_TOKEN),
                          (mod.AGENT_API_TOKEN_FILE, AGENT_TOKEN)):
            with open(path, "w") as f:
                f.write(val + "\n")
        users = []
        for name, role, owner, pw in USERS:
            rec = mod._new_user(name, pw, role, owner=owner)
            users.append(rec)
        mod._save_users(users)
        self.passwords = {name: pw for name, _r, _o, pw in USERS}
        self.role_user = {"admin": "boss", "viewer": "watcher"}

    def session(self, role):
        """A fresh real session token for role ("admin"/"viewer")."""
        return self.mod._create_session(self.role_user[role], role)

    def request(self, method, path, role=None, origin=_MISSING, body=None, headers=None,
                token=None, timeout=8.0):
        """origin: omitted/None -> no Origin header; Harness.SAME -> the
        harness origin; any other string is sent verbatim."""
        r = Response()
        r.tag = "%sr%d" % (self._tag_prefix, next(self._seq))
        hdrs = {REQ_HEADER: r.tag}
        tok = token or (self.session(role) if role else None)
        if tok:
            hdrs["Cookie"] = "%s=%s" % (self.mod.SESSION_COOKIE, tok)
        if origin is self.SAME or origin == self.SAME:
            hdrs["Origin"] = self.origin
        elif origin not in (_MISSING, None):
            hdrs["Origin"] = origin
        data = None
        if method not in ("GET", "HEAD"):
            # no body by default: a gate that answers before reading it would
            # otherwise close with unread data (RST instead of the answer)
            data = body if isinstance(body, (bytes, bytearray)) else (
                b"" if body is None else json.dumps(body).encode())
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            c.request(method, path, body=data, headers=hdrs)
            resp = c.getresponse()
            r.status = resp.status
            r.headers = {k.lower(): v for k, v in resp.getheaders()}
            r.headers["_all"] = [(k.lower(), v) for k, v in resp.getheaders()]
            r.body = resp.read(1 << 20) if method != "HEAD" else b""
        except Exception as exc:
            r.error = type(exc).__name__
        finally:
            c.close()
        try:
            r.json = json.loads(r.body) if r.body else None
        except ValueError:
            r.json = None
        r.effects = effects_for(r.tag)
        r.trace = self._traces.get(r.tag, "")
        return r

    def refresh(self, r):
        """Effects/traces recorded after the response was read."""
        r.effects = effects_for(r.tag)
        r.trace = self._traces.get(r.tag, "")
        return r

    def close(self):
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
        _allowed_ports.discard(self.port)
        tempfile.tempdir = self._prev_tempdir
        if self._own_scratch:
            with _HarnessIO():
                shutil.rmtree(self.scratch, ignore_errors=True)
            _allowed_dirs.remove(os.path.realpath(self.scratch))
