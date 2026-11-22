"""TuxWall system backups: item catalog, retention, persisted job state,
sanitized export, archive limits, the hardened restore (preview diff,
atomic write, safe permissions, pre-restore copies, audit log; single file,
several files or a whole service), the schedule, integrity (SHA256SUMS
inside every archive + the archive's own sha256), optional gpg encryption
of everything that leaves the box, and the USB copy.

Every path goes through a ``root`` prefix ("" on the router) so
tools/backup_safety_check.py exercises all of it in a temp tree.

Layout under <root>/var/lib/tuxwall/backups/ (dir 0700 where created here):
  system/          archives: system-backup-*, sanitized-*, uploaded-* (0600)
  state.json       last run / success / failure, pinned, per-archive
                   integrity, schedule bookkeeping, USB copy results (0600)
  audit.jsonl      who/what/when of every backup action, never contents (0600)
  pre-restore/<ts>/<path>   live file copies taken before a restore (0700/0600)
  .work/           private scratch (mkstemp, gpg homedirs) (0700)
Owner settings: /etc/tuxwall/backups.json (0600); the encryption passphrase
(if set): /etc/tuxwall/backup-passphrase (0600, never in an archive, never
logged or returned).
"""
import datetime
import difflib
import errno
import fnmatch
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat as _stat
import subprocess
import tarfile
import threading
import time
from collections import deque

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

BACKUP_ROOT = "/var/lib/tuxwall/backups"
SYSTEM_DIR = BACKUP_ROOT + "/system"
STATE_FILE = BACKUP_ROOT + "/state.json"
AUDIT_FILE = BACKUP_ROOT + "/audit.jsonl"
PRE_RESTORE_DIR = BACKUP_ROOT + "/pre-restore"
WORK_DIR = BACKUP_ROOT + "/.work"
LOCK_FILE = BACKUP_ROOT + "/.job.lock"
SCRIPT = "/usr/local/sbin/system-backup.sh"

SYSTEM_RE = re.compile(r"^system-backup-(\d{8})-(\d{6})\.tar\.gz$")
SANITIZED_RE = re.compile(r"^sanitized-\d{8}-\d{6}\.tar\.gz$")
UPLOADED_RE = re.compile(r"^uploaded-\d{8}-\d{6}\.tar\.gz$")

# Retention (grandfather-father-son, restic semantics: the newest backup of
# each of the N most recent days / ISO weeks / months that HAVE backups, so a
# router that was off for a month never loses its last good copies).
RETENTION = {"daily": 7, "weekly": 4, "monthly": 3}
SANITIZED_KEEP = 3
UPLOADED_KEEP = 2
PRE_RESTORE_KEEP = 30

# Archive limits (uploads are untrusted; generated archives are checked too).
UPLOAD_MAX_BYTES = 100 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_TOTAL_BYTES = 768 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
DOWNLOAD_MEMBER_MAX = 64 * 1024 * 1024
PREVIEW_TEXT_MAX = 2 * 1024 * 1024
DIFF_MAX_LINES = 600
STDERR_TAIL_LINES = 30
AUDIT_MAX_BYTES = 2 * 1024 * 1024
JOB_TIMEOUT_S = 1800

MANIFEST_NAME = "SHA256SUMS"
TOP_FILES = ("iptables-save.txt", "ip6tables-save.txt", "manifest.txt", "dpkg-selections.txt",
             "apt-manual.txt", "package-versions.txt", "restore.sh", MANIFEST_NAME)
MEMBER_PREFIXES = ("etc/", "usr/local/", "var/www/html/", "var/lib/tuxwall/", "var/lib/kea/")

# ── catalog ─────────────────────────────────────────────────────────────────
# arc = archive path and the system-backup.sh -i filter key (the script's
# CONFIG_PATHS must contain every arc: tools/backup_safety_check.py checks).
# exclude = basename globs skipped at any depth (rsync --exclude semantics);
# only = the top-level children that are captured (everything else skipped).
WWW_EXCLUDE = ("__pycache__", "logs", "backups", ".git", "*.pyc", "*.bak-*", "*.orig", "*.pre-*",
               "*.tmp", "index.nginx-debian.html")
CROWDSEC_EXCLUDE = ("hub", "patterns", "lists")
GLOBAL_EXCLUDE = ("__pycache__",)  # pruned from every item by the script
TUXWALL_STATE_ONLY = ("fw-snapshots", "firewall-backups", "wireguard.json", "canary-token",
                      "whitelist.json", "rpz.json", "rpz-feeds.json", "blocklists.json",
                      "honeypot.json", "reported-decisions.json")

ITEMS = [
    {"arc": "etc/netplan", "path": "/etc/netplan", "label": "Network interfaces (netplan)", "service": "systemd-networkd"},
    {"arc": "etc/systemd/network", "path": "/etc/systemd/network", "label": "systemd-networkd", "service": "systemd-networkd"},
    {"arc": "etc/kea", "path": "/etc/kea", "label": "KEA DHCP server", "service": "kea-dhcp4-server"},
    {"arc": "etc/unbound", "path": "/etc/unbound", "label": "Unbound DNS resolver", "service": "unbound"},
    {"arc": "etc/ufw", "path": "/etc/ufw", "label": "UFW firewall", "service": "ufw"},
    {"arc": "etc/nginx", "path": "/etc/nginx", "label": "nginx web server", "service": "nginx"},
    {"arc": "etc/systemd/system", "path": "/etc/systemd/system", "label": "systemd units", "service": "daemon-reload"},
    {"arc": "etc/sysctl.d", "path": "/etc/sysctl.d", "label": "Kernel settings (sysctl.d)", "service": "sysctl --system"},
    {"arc": "etc/radvd.conf", "path": "/etc/radvd.conf", "label": "RA/NDP daemon (radvd)", "service": "radvd"},
    {"arc": "etc/wireguard", "path": "/etc/wireguard", "label": "WireGuard VPN", "service": "wg-quick@wg0"},
    {"arc": "etc/cloudflared", "path": "/etc/cloudflared", "label": "cloudflared", "service": "cloudflared"},
    {"arc": "etc/tuxwall", "path": "/etc/tuxwall", "label": "TuxWall", "service": "tuxwall"},
    {"arc": "etc/crowdsec", "path": "/etc/crowdsec", "label": "CrowdSec", "service": "crowdsec",
     "exclude": CROWDSEC_EXCLUDE},
    {"arc": "etc/apt/sources.list", "path": "/etc/apt/sources.list", "label": "APT sources.list", "service": None},
    {"arc": "etc/apt/sources.list.d", "path": "/etc/apt/sources.list.d", "label": "APT sources.list.d", "service": None},
    {"arc": "etc/hosts", "path": "/etc/hosts", "label": "/etc/hosts", "service": None},
    {"arc": "etc/hostname", "path": "/etc/hostname", "label": "/etc/hostname", "service": None},
    {"arc": "etc/fstab", "path": "/etc/fstab", "label": "/etc/fstab", "service": None},
    {"arc": "etc/hosts.allow", "path": "/etc/hosts.allow", "label": "/etc/hosts.allow", "service": None},
    {"arc": "etc/hosts.deny", "path": "/etc/hosts.deny", "label": "/etc/hosts.deny", "service": None},
    {"arc": "usr/local/bin", "path": "/usr/local/bin", "label": "/usr/local/bin scripts", "service": None},
    {"arc": "usr/local/sbin", "path": "/usr/local/sbin", "label": "/usr/local/sbin scripts", "service": None},
    {"arc": "var/www/html", "path": "/var/www/html", "label": "TuxWall dashboard files", "service": "tuxwall",
     "exclude": WWW_EXCLUDE},
    {"arc": "etc/default/ufw", "path": "/etc/default/ufw", "label": "UFW defaults (/etc/default/ufw)", "service": "ufw"},
    {"arc": "etc/nftables.conf", "path": "/etc/nftables.conf", "label": "nftables.conf", "service": None},
    {"arc": "etc/ssh", "path": "/etc/ssh", "label": "SSH server config + host keys", "service": "ssh"},
    {"arc": "etc/letsencrypt", "path": "/etc/letsencrypt", "label": "TLS certificates (Let's Encrypt)", "service": "nginx"},
    {"arc": "etc/suricata", "path": "/etc/suricata", "label": "Suricata IDS", "service": "suricata"},
    {"arc": "etc/opencanaryd", "path": "/etc/opencanaryd", "label": "OpenCanary honeypot", "service": "opencanary"},
    {"arc": "etc/chrony", "path": "/etc/chrony", "label": "Time sync (chrony)", "service": "chrony"},
    {"arc": "etc/systemd/resolved.conf", "path": "/etc/systemd/resolved.conf", "label": "systemd-resolved", "service": "systemd-resolved"},
    {"arc": "etc/sudoers.d", "path": "/etc/sudoers.d", "label": "sudo rules (sudoers.d)", "service": None},
    {"arc": "etc/cron.d", "path": "/etc/cron.d", "label": "Cron jobs (cron.d)", "service": None},
    {"arc": "etc/networkd-dispatcher", "path": "/etc/networkd-dispatcher", "label": "networkd-dispatcher hooks", "service": None},
    {"arc": "etc/modules-load.d", "path": "/etc/modules-load.d", "label": "Kernel modules (modules-load.d)", "service": None},
    {"arc": "var/lib/tuxwall", "path": "/var/lib/tuxwall", "label": "TuxWall state (firewall snapshots, WireGuard peers, lists)",
     "service": "tuxwall", "only": TUXWALL_STATE_ONLY},
    {"arc": "var/lib/kea", "path": "/var/lib/kea", "label": "KEA DHCP leases", "service": "kea-dhcp4-server"},
]
ITEM_BY_ARC = {i["arc"]: i for i in ITEMS}
# radvd's config since the radvd.service drop-in (etc/radvd.conf = stock path,
# still restored on boxes that were not migrated); captured by etc/tuxwall
RADVD_ARC = "etc/tuxwall/radvd.conf"
NOT_INCLUDED = ("databases (CrowdSec/reports/MariaDB: see the USB backup), GeoIP databases, "
                "caches, logs and history files, home directories (incl. the opencode credential store)")


class Refused(Exception):
    def __init__(self, status, payload):
        Exception.__init__(self, payload.get("error", "refused"))
        self.status = status
        self.payload = payload


def P(root, path):
    return (root or "") + path


def _excluded(name, patterns):
    return any(fnmatch.fnmatch(name, pat) for pat in patterns or ())


def item_size(root, item):
    """(exists, bytes) for a catalog item, with the script's exclusions.
    lstat only: symlinks count as 0 and are never followed (usr/local/bin
    holds symlinks to large binaries that the archive stores as links)."""
    base = P(root, item["path"])
    try:
        st = os.lstat(base)
    except OSError:
        return False, 0
    if not os.path.isdir(base) or os.path.islink(base):
        return True, st.st_size if not os.path.islink(base) else 0
    total = 0
    only = item.get("only")
    excl = tuple(item.get("exclude") or ()) + GLOBAL_EXCLUDE
    for dirpath, dirs, files in os.walk(base):
        if dirpath == base and only:
            dirs[:] = [d for d in dirs if d in only]
            files = [f for f in files if f in only]
        dirs[:] = [d for d in dirs if not _excluded(d, excl)]
        for fn in files:
            if _excluded(fn, excl):
                continue
            try:
                s = os.lstat(os.path.join(dirpath, fn))
            except OSError:
                continue
            if not os.path.islink(os.path.join(dirpath, fn)):
                total += s.st_size
    return True, total


def items_listing(root=""):
    out = []
    for item in ITEMS:
        exists, size = item_size(root, item)
        out.append({"arc": item["arc"], "path": item["path"], "label": item["label"],
                    "service": item["service"], "exists": exists, "size": size})
    return out


def service_for(name):
    """Restart hint for an archive member: the longest matching catalog arc."""
    best = None
    for arc, item in ITEM_BY_ARC.items():
        if name == arc or name.startswith(arc + "/"):
            if best is None or len(arc) > len(best):
                best = arc
    svc = ITEM_BY_ARC[best]["service"] if best else None
    if name == RADVD_ARC:
        svc = "radvd"
    if name.startswith("etc/systemd/") and not name.startswith("etc/systemd/network/") \
            and name != "etc/systemd/resolved.conf":
        svc = "daemon-reload"
    return svc


# ── small file helpers ──────────────────────────────────────────────────────

def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _write_private(path, data):
    d = os.path.dirname(path)
    tmp = os.path.join(d, ".%s.%s.tmp" % (os.path.basename(path), secrets.token_hex(4)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def mkstemp_private(root="", prefix="tmp-", suffix=""):
    """Unpredictable private temp file in WORK_DIR (0700). Returns (fd, path)."""
    d = _private_dir(P(root, WORK_DIR))
    for _ in range(20):
        path = os.path.join(d, "%s%s%s" % (prefix, secrets.token_hex(8), suffix))
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            return fd, path
        except FileExistsError:
            continue
    raise OSError("could not create a private temp file")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


# ── audit log ───────────────────────────────────────────────────────────────

_audit_lock = threading.Lock()


def audit(root, action, who="", client="", **fields):
    """Append one JSON line: who/what/when. Never file contents or secrets."""
    entry = {"ts": int(time.time()), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
             "action": action, "who": who or "", "client": client or ""}
    for k, v in fields.items():
        if v is not None:
            entry[k] = v
    line = json.dumps(entry, sort_keys=True) + "\n"
    path = P(root, AUDIT_FILE)
    with _audit_lock:
        _private_dir(os.path.dirname(path))
        try:
            if os.path.getsize(path) > AUDIT_MAX_BYTES:
                os.replace(path, path + ".1")
        except OSError:
            pass
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(line)
    return entry


def audit_tail(root="", n=50):
    try:
        with open(P(root, AUDIT_FILE)) as f:
            lines = deque(f, maxlen=n)
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out[::-1]


# ── persisted job state ─────────────────────────────────────────────────────

_state_lock = threading.RLock()


def _default_state():
    return {"version": 1, "pinned": [], "last_run": None, "last_success": None, "last_failure": None,
            "archives": {}, "schedule": {}, "usb": {}}


def load_state(root=""):
    try:
        with open(P(root, STATE_FILE)) as f:
            st = json.load(f)
        if not isinstance(st, dict):
            raise ValueError
    except (OSError, ValueError):
        st = {}
    base = _default_state()
    base.update(st)
    if not isinstance(base.get("pinned"), list):
        base["pinned"] = []
    for k in ("archives", "schedule", "usb"):
        if not isinstance(base.get(k), dict):
            base[k] = {}
    return base


def update_state(root, fn):
    with _state_lock:
        st = load_state(root)
        fn(st)
        _private_dir(os.path.dirname(P(root, STATE_FILE)))
        _write_private(P(root, STATE_FILE), json.dumps(st, indent=2, sort_keys=True))
        return st


def set_pinned(root, name, pinned, who=""):
    if not SYSTEM_RE.match(os.path.basename(name or "")):
        raise ValueError("Only system backups can be pinned")
    name = os.path.basename(name)

    def fn(st):
        s = [n for n in st["pinned"] if n != name]
        if pinned:
            s.append(name)
        st["pinned"] = sorted(s)
    st = update_state(root, fn)
    audit(root, "pin" if pinned else "unpin", who=who, archive=name)
    return st["pinned"]


class JobLock:
    """Cross-process single-job lock (flock on LOCK_FILE). A scheduled run
    (phase 2) and a dashboard click can never overlap."""

    def __init__(self, root=""):
        self.path = P(root, LOCK_FILE)
        self.fd = None

    def acquire(self):
        _private_dir(os.path.dirname(self.path))
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                return False
        self.fd = fd
        return True

    def release(self):
        if self.fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


def job_is_locked(root=""):
    lk = JobLock(root)
    if lk.acquire():
        lk.release()
        return False
    return True


def reconcile_interrupted(root=""):
    """A run recorded as running whose lock is free died with the API (or
    the box): turn it into a failure so the UI and the incident show it."""
    st = load_state(root)
    run = st.get("last_run") or {}
    if not run.get("running") or job_is_locked(root):
        return st

    def fn(s):
        r = s.get("last_run") or {}
        if r.get("running"):
            r.update({"running": False, "ok": False, "finished": int(time.time()),
                      "error": "Backup was interrupted (the API or router restarted mid-run)"})
            s["last_run"] = r
            s["last_failure"] = dict(r)
    return update_state(root, fn)


def failure_incident(root=""):
    """(title, detail) when the most recent finished run failed, else None.
    Cleared automatically by the next successful run."""
    st = load_state(root)
    fail = st.get("last_failure") or {}
    ok = st.get("last_success") or {}
    if not fail or (ok and ok.get("finished", 0) >= fail.get("finished", 0)):
        return None
    err = str(fail.get("error") or "unknown error")[:300]
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(fail.get("finished") or 0))
    return ("System backup failed",
            "The %s backup at %s failed: %s. Open System > Backups for details."
            % (fail.get("trigger") or "manual", when, err))


def record_failure(root, trigger, error, who=""):
    """Persist a failure that happened outside run_job (e.g. the run could
    not even start), so it raises the backup:failed incident too."""
    now = int(time.time())
    run = {"id": time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2), "started": now, "finished": now,
           "running": False, "ok": False, "trigger": trigger, "who": who or "", "items": "all",
           "error": str(error)[:300], "stderr_tail": ""}

    def fn(s):
        s["last_run"] = dict(run)
        s["last_failure"] = dict(run)
    update_state(root, fn)
    audit(root, "backup-finish", who=who, trigger=trigger, run=run["id"], ok=False, error=run["error"])
    return run


# ── retention ───────────────────────────────────────────────────────────────

def backup_ts(name):
    m = SYSTEM_RE.match(name or "")
    if not m:
        return None
    try:
        return time.mktime(time.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S"))
    except ValueError:
        return None


def retention_plan(names, pinned=(), policy=None):
    """Pure: which system backups to keep (with reasons) and which to delete.
    The newest backup and pinned ones are always kept."""
    policy = dict(RETENTION if policy is None else policy)
    items = sorted(((backup_ts(n), n) for n in names if backup_ts(n) is not None), reverse=True)
    keep = {}
    if items:
        keep.setdefault(items[0][1], []).append("newest")
    for bucket, fmt in (("daily", "%Y-%m-%d"), ("weekly", "%G-W%V"), ("monthly", "%Y-%m")):
        count = int(policy.get(bucket, 0) or 0)
        seen = set()
        for ts, n in items:
            key = time.strftime(fmt, time.localtime(ts))
            if key in seen:
                continue
            if len(seen) >= count:
                break
            seen.add(key)
            keep.setdefault(n, []).append(bucket)
    for n in pinned or ():
        if any(n == x for _t, x in items):
            keep.setdefault(n, []).append("pinned")
    delete = [n for _t, n in sorted(items) if n not in keep]
    return {"keep": keep, "delete": delete}


def prune_system(root=""):
    d = P(root, SYSTEM_DIR)
    try:
        names = [n for n in os.listdir(d) if SYSTEM_RE.match(n)]
    except OSError:
        return []
    plan = retention_plan(names, load_state(root).get("pinned") or ())
    removed = []
    for n in plan["delete"]:
        try:
            os.remove(os.path.join(d, n))
            removed.append(n)
        except OSError:
            pass
    return removed


def prune_simple(root, regex, keep):
    d = P(root, SYSTEM_DIR)
    try:
        names = sorted(n for n in os.listdir(d) if regex.match(n))
    except OSError:
        return []
    removed = []
    for n in names[:-keep] if keep > 0 else names:
        try:
            os.remove(os.path.join(d, n))
            removed.append(n)
        except OSError:
            pass
    return removed


def prune_pre_restore(root=""):
    d = P(root, PRE_RESTORE_DIR)
    try:
        names = sorted(n for n in os.listdir(d) if re.match(r"^\d{8}-\d{6}-[0-9a-f]{4,8}$", n))
    except OSError:
        return []
    drop = names[:-PRE_RESTORE_KEEP] if len(names) > PRE_RESTORE_KEEP else []
    for n in drop:
        shutil.rmtree(os.path.join(d, n), ignore_errors=True)
    return drop


def list_archives(root="", regex=SYSTEM_RE):
    d = P(root, SYSTEM_DIR)
    out = []
    try:
        names = sorted(os.listdir(d), reverse=True)
    except OSError:
        return out
    state = load_state(root)
    pinned = set(state.get("pinned") or ())
    recs = state.get("archives") or {}
    for n in names:
        if not regex.match(n):
            continue
        try:
            st = os.stat(os.path.join(d, n))
        except OSError:
            continue
        rec = recs.get(n) or {}
        out.append({"name": n, "size": st.st_size, "time": int(st.st_mtime), "pinned": n in pinned,
                    "integrity": rec.get("status") or "unchecked", "checked": rec.get("checked"),
                    "sha256": rec.get("sha256")})
    return out


# ── running the backup script ───────────────────────────────────────────────

def run_script(root="", include=None, on_progress=None, script=None, outdir=None, timeout=JOB_TIMEOUT_S):
    """Run system-backup.sh; stdout carries PROGRESS/RESULT lines, stderr is
    kept as a tail for the error message. Returns a result dict."""
    script = script or SCRIPT
    outdir = outdir or P(root, SYSTEM_DIR)
    if not os.path.isfile(script):
        return {"ok": False, "rc": None, "result": None, "stderr_tail": "",
                "error": "Backup script missing (%s). Reinstall the tuxwall package." % script}
    include_path = None
    cmd = [script, "-o", outdir]
    if include:
        fd, include_path = mkstemp_private(root, prefix="include-")
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(include) + "\n")
        cmd += ["-i", include_path]
    tail = deque(maxlen=STDERR_TAIL_LINES)
    result = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                errors="replace")

        def _err():
            for line in proc.stderr:
                line = line.rstrip()
                if line and not line.startswith("System backup: "):
                    tail.append(line[:300])
        t = threading.Thread(target=_err, daemon=True)
        t.start()
        timed_out = []

        def _kill():
            timed_out.append(1)
            try:
                proc.kill()
            except OSError:
                pass
        watchdog = threading.Timer(timeout, _kill)
        watchdog.daemon = True
        watchdog.start()
        try:
            for line in proc.stdout:
                line = line.strip()
                m = re.match(r"^PROGRESS\s+(\d+)\s*(.*)$", line)
                if m:
                    if on_progress:
                        try:
                            on_progress(int(m.group(1)), m.group(2))
                        except Exception:
                            pass
                    continue
                m = re.match(r"^RESULT\s+(\S+)$", line)
                if m:
                    result = m.group(1)
            rc = proc.wait()
        finally:
            watchdog.cancel()
        t.join(5)
        if timed_out:
            tail.append("timed out after %d s" % timeout)
            rc = rc if rc else -9
    finally:
        if include_path:
            try:
                os.unlink(include_path)
            except OSError:
                pass
    stderr_tail = "\n".join(tail)
    if rc != 0 or not result:
        last = [l for l in tail if l.strip()]
        why = last[-1] if last else ("no archive reported" if rc == 0 else "")
        error = "Backup script exited with status %s%s" % (rc, (": " + why) if why else "")
        return {"ok": False, "rc": rc, "result": None, "stderr_tail": stderr_tail, "error": error}
    if not SYSTEM_RE.match(result) or not os.path.isfile(os.path.join(outdir, result)):
        return {"ok": False, "rc": rc, "result": None, "stderr_tail": stderr_tail,
                "error": "Backup script reported %r but no such archive exists" % result[:80]}
    return {"ok": True, "rc": rc, "result": result, "stderr_tail": stderr_tail, "error": None}


def run_job(root="", include=None, who="", trigger="manual", on_progress=None, script=None):
    """One complete backup run: lock, persisted start record, script, archive
    check, retention, persisted finish record, audit. Never raises for
    expected failures; returns the finished run record."""
    lk = JobLock(root)
    if not lk.acquire():
        raise Refused(409, {"ok": False, "error": "A system backup is already running"})
    run = {"id": time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2), "started": int(time.time()),
           "running": True, "trigger": trigger, "who": who or "",
           "items": list(include) if include else "all"}
    try:
        update_state(root, lambda s: s.update(last_run=dict(run)))
        audit(root, "backup-start", who=who, trigger=trigger, run=run["id"],
              items=len(include) if include else "all")
        try:
            res = run_script(root, include=include, on_progress=on_progress, script=script)
        except Exception as exc:
            res = {"ok": False, "rc": None, "result": None, "stderr_tail": "", "error": str(exc)[:300]}
        pruned = []
        if res["ok"]:
            path = os.path.join(P(root, SYSTEM_DIR), res["result"])
            try:
                os.chmod(path, 0o600)
                check_archive(path)
                res["size"] = os.path.getsize(path)
                if on_progress:
                    try:
                        on_progress(97, "Verifying checksums")
                    except Exception:
                        pass
                integ = check_integrity(root, res["result"], path, force=True)
                res["integrity"] = integ["status"]
                res["sha256"] = integ.get("sha256")
                if integ["status"] == "damaged":
                    raise ValueError(integrity_summary(integ))
            except Exception as exc:
                res.update(ok=False, error="Archive check failed: %s" % exc)
        run.update(running=False, finished=int(time.time()), ok=res["ok"], result=res.get("result"),
                   error=res.get("error"), stderr_tail=res.get("stderr_tail", "")[-2000:],
                   size=res.get("size"), integrity=res.get("integrity"), sha256=res.get("sha256"))
        if res["ok"]:
            pruned = prune_system(root)
            run["pruned"] = pruned

        def fin(s):
            s["last_run"] = dict(run)
            if run["ok"]:
                s["last_success"] = dict(run)
            else:
                s["last_failure"] = dict(run)
            s["pinned"] = [n for n in s.get("pinned") or [] if n not in pruned]
            for n in pruned:
                (s.get("archives") or {}).pop(n, None)
        update_state(root, fin)
        audit(root, "backup-finish", who=who, trigger=trigger, run=run["id"], ok=run["ok"],
              archive=run.get("result"), error=run.get("error"), pruned=pruned or None)
        return run
    finally:
        lk.release()


# ── archive safety ──────────────────────────────────────────────────────────

def member_safe(member_name):
    """Normalised archive path if it is a known, traversal-free location."""
    name = (member_name or "").replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/") if name.endswith("/") else name
    if not name or name.startswith("/") or ".." in name.split("/") or "\x00" in name:
        return None
    if name in TOP_FILES or name.startswith(MEMBER_PREFIXES):
        return name
    return None


def check_archive(path, max_members=MAX_MEMBERS, max_total=MAX_TOTAL_BYTES, max_member=MAX_MEMBER_BYTES,
                  strict=False):
    """Stream the headers of a .tar.gz and enforce member-count and
    decompressed-size limits (stops at the first violation, so a bomb is
    never fully inflated). strict (uploads): unsafe paths and device/fifo
    members reject the whole archive. Returns {"members", "total"}."""
    count = total = 0
    try:
        with tarfile.open(path, "r:gz") as tar:
            for m in tar:
                count += 1
                if count > max_members:
                    raise ValueError("Archive has more than %d members" % max_members)
                if m.isreg():
                    if m.size > max_member:
                        raise ValueError("Archive member too large (%d MB)" % (m.size // 1048576))
                    total += m.size
                    if total > max_total:
                        raise ValueError("Archive expands beyond %d MB" % (max_total // 1048576))
                if strict:
                    raw = (m.name or "").replace("\\", "/")
                    if raw.startswith("/") or ".." in raw.split("/"):
                        raise ValueError("Archive contains an unsafe path")
                    if not (m.isreg() or m.isdir() or m.issym() or m.islnk()):
                        raise ValueError("Archive contains a device or fifo member")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Not a readable .tar.gz archive (%s)" % exc.__class__.__name__)
    return {"members": count, "total": total}


def open_member(path, member):
    """(tar, TarInfo, name) for a safe regular-file member. Caller closes tar."""
    name = member_safe(member)
    if not name:
        raise ValueError("Invalid file name")
    tar = tarfile.open(path, "r:gz")
    m = None
    for cand in (name, "./" + name):
        try:
            m = tar.getmember(cand)
            break
        except KeyError:
            continue
    if m is None:
        tar.close()
        raise ValueError("File not found in backup")
    if not m.isreg():
        tar.close()
        raise ValueError("Not a regular file")
    if m.size > MAX_MEMBER_BYTES:
        tar.close()
        raise ValueError("File too large")
    return tar, m, name


def read_member(path, member, limit=MAX_MEMBER_BYTES):
    tar, m, name = open_member(path, member)
    try:
        if m.size > limit:
            raise ValueError("File too large to read (%d MB)" % (m.size // 1048576))
        with tar.extractfile(m) as f:
            return name, m, f.read(limit + 1)[:limit]
    finally:
        tar.close()


def contents(path):
    files = []
    with tarfile.open(path, "r:gz") as tar:
        for m in tar:
            name = member_safe(m.name)
            if not name or not m.isreg():
                continue
            if name in FW_RAW_MAP or name in FW_UFW_MAP:
                kind = "firewall"
            elif name in TOP_FILES:
                kind = "info"
            else:
                kind = "file"
            svc = service_for(name)
            if name in FW_RAW_MAP:
                svc = "firewall snapshot"
            files.append({"name": name, "size": m.size, "service": svc, "kind": kind,
                          "strict": strict_reason(name) is not None})
    files.sort(key=lambda f: f["name"])
    return files


# ── sanitizer ───────────────────────────────────────────────────────────────
# Allowlist-minded: only config locations go into a shareable export
# (EXPORT_PREFIXES + TOP_FILES); binaries are never exported; known secret
# files are dropped by name; every remaining text file is redacted (PEM
# private keys, key=value / key: value / "key": "value" / --flag value with a
# secret-looking key ANYWHERE in a line, URL credentials, plugin fields the
# plugin manifest marks secret); finally the written export is re-scanned
# and discarded if anything secret-looking survived (fail closed).

EXPORT_PREFIXES = ("etc/", "usr/local/bin/", "usr/local/sbin/", "var/lib/tuxwall/")
SECRET_FILE_RES = [re.compile(p) for p in (
    r"(^|/)auth\.json$", r"(^|/)llm\.json$", r"(^|/)opencode(\.local)?\.json\.bak",
    r"^etc/tuxwall/(internal-token|agent-token|backup-passphrase)$", r"(^|/)canary-token$", r"(^|/)api\.token$",
    r"^etc/tuxwall/agent(/|$)", r"(^|/)keys?/", r"^etc/cloudflared/(?!config\.ya?ml$)",
    r"credentials", r"(^|/)private[-_]?key", r"(^|/)privatekey$", r"(^|/)publickey$",
    r"\.key$", r"(^|/)ssh_host_[a-z0-9]+_key$", r"^etc/letsencrypt/(accounts|keys|csr)(/|$)",
    r"(^|/)privkey\d*\.pem$", r"(^|/)cert\.pem$", r"^etc/letsencrypt/.*\.ini$",
    r"\.(p12|pfx|jks|keystore|kdbx|gpg|asc)$", r"(^|/)shadow-?$", r"(^|/)gshadow-?$",
    r"(^|/)\.netrc$", r"(^|/)\.pgpass$", r"(^|/)secrets?(\.[a-z]+)?$",
)]
SECRET_KEY_RE = re.compile(
    r"(?i)^(?:[a-z0-9_.-]*?(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|"
    r"private[_-]?key|preshared[_-]?key|ssh[_-]?key|auth[_-]?key|access[_-]?key|shared[_-]?key|"
    r"signing[_-]?key|encryption[_-]?key|session[_-]?key|credentials?|webhook(?:[_-]?url)?|"
    r"ntfy[_-]?url|bearer)[a-z0-9_.-]*|key|psk|pass|pwd|pin)$")
GENERIC_KEYS = ("key", "psk", "pass", "pwd", "pin")
NO_REDACT_FILES = ("dpkg-selections.txt", "apt-manual.txt", "package-versions.txt")
SAFE_KEY_RE = re.compile(r"(?i)(path|file|files|dir|filename|_type|-type|_mode|_len|_length|_ttl|"
                         r"_header|-header|_name|_enabled|_required|_policy|_format|_prefix|"
                         r"_expires|_expiry|_lifetime|_url_template|_timeout|_hint|_label)$")
REDACTED = "<REDACTED>"
PEM_REDACTED = "-----BEGIN REDACTED PRIVATE KEY-----" + REDACTED + "-----END REDACTED PRIVATE KEY-----"
PEM_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*?)PRIVATE KEY-----.*?-----END \1PRIVATE KEY-----", re.S)
PEM_BODY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\n|\\r|\s)*[A-Za-z0-9+/=]{32}")
PEM_BODY_BYTES_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\\n|\\r|\s)*[A-Za-z0-9+/=]{32}")
_KEY = r"[A-Za-z_][A-Za-z0-9_.-]*"
JSON_KV_RE = re.compile(r'(?P<pre>"(?P<key>' + _KEY + r')"\s*:\s*)"(?P<val>(?:[^"\\\n]|\\.)*)"')
SQ_KV_RE = re.compile(r"(?P<pre>(?:^|(?<=[\s,{;(\[]))'(?P<key>" + _KEY + r")'\s*:\s*)'(?P<val>[^'\n]*)'", re.M)
ASSIGN_RE = re.compile(
    r"(?P<pre>(?:^|(?<=[\s,{;(=\"'\[]))(?:export\s+)?(?P<key>" + _KEY + r")[\"']?\s*(?P<op>[:=])\s*)"
    r"(?:\"(?P<dq>(?:[^\"\\\n]|\\.)*)\"|'(?P<sq>[^'\n]*)'|(?P<uq>[^\s#'\"][^\n'\"]*?))(?=[ \t]+#|[ \t]*$|\"|')",
    re.M)
FLAG_RE = re.compile(r"(?P<pre>--(?P<key>[A-Za-z][A-Za-z0-9_-]*)(?:\s+|=))(?P<val>[^\s\"'\\-][^\s\"'\\]*)")
URL_CRED_RE = re.compile(r"(?P<pre>\b[a-z][a-z0-9+.-]*://[^/\s:@\"']+:)(?P<val>[^/\s@\"']+)(?=@)")
CODE_EXT = (".py", ".js", ".mjs", ".sh", ".bash", ".php", ".pl", ".rb", ".lua", ".html", ".htm",
            ".css", ".ts")


NOT_SECRET_KEYS = ("nopasswd", "passwordauthentication", "permitemptypasswords")


def is_secret_key(key, generic=True):
    k = (key or "").strip().strip("\"'")
    if k.lower() in NOT_SECRET_KEYS or (not generic and k.lower() in GENERIC_KEYS):
        return False
    return bool(SECRET_KEY_RE.match(k)) and not SAFE_KEY_RE.search(k)


def secret_file(name):
    return any(r.search(name) for r in SECRET_FILE_RES)


def is_binary(data):
    if b"\x00" in data[:65536]:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _placeholder(val):
    v = (val or "").strip()
    return (not v or v == REDACTED or (v.startswith("<") and v.endswith(">"))
            or v.startswith("{file:") or v.startswith("{env:") or set(v) <= set("Xx*.-_ ")
            or v.lower() in ("true", "false", "yes", "no", "null", "none", "on", "off", "~")
            or re.match(r"^\d{1,3}$", v) is not None
            or re.match(r"^\$(\(|\{|[A-Za-z_])", v) is not None or "$(" in v
            or re.match(r"^/[A-Za-z0-9_.@+/-]*$", v) is not None)        # a file path, not a secret


def _weak_generic(key, val):
    """A bare "key" field is everywhere (incident keys, schema field names);
    only a credential-looking value (16+ token chars incl. a digit) counts."""
    if (key or "").strip("\"'").lower() != "key":
        return False
    v = str(val or "").strip()
    return not (re.match(r"^[A-Za-z0-9+/=_.~-]{16,}$", v) and re.search(r"\d", v))


def _is_code(name, text):
    return name.endswith(CODE_EXT) or text.startswith("#!")


def redact_text(name, text, plugin_secret_fields=(), json_mode=False):
    """Return (text, n_redactions). Pure; idempotent. json_mode: the file
    parsed as JSON and its key/value pairs were already redacted structurally
    (only schema "key" field names are left to keep)."""
    n = 0
    if name in NO_REDACT_FILES:
        return text, 0
    code = _is_code(name, text)
    generic = not code
    shell = name.endswith((".sh", ".bash")) or bool(re.match(r"#!\s*/(usr/)?bin/(env\s+)?(ba|da|z)?sh\b", text))

    def pem(m):
        nonlocal n
        if m.group(0) == PEM_REDACTED:
            return m.group(0)
        n += 1
        return PEM_REDACTED
    text = PEM_RE.sub(pem, text)

    def kv(m):
        nonlocal n
        key = m.group("key")
        val = m.group("val")
        if not (is_secret_key(key, generic) or key in plugin_secret_fields) or _placeholder(val):
            return m.group(0)
        if (json_mode and key == "key") or (key not in plugin_secret_fields and _weak_generic(key, val)):
            return m.group(0)
        n += 1
        return m.group("pre") + '"' + REDACTED + '"'
    text = JSON_KV_RE.sub(kv, text)

    def skv(m):
        nonlocal n
        if (not is_secret_key(m.group("key"), generic) or _placeholder(m.group("val"))
                or _weak_generic(m.group("key"), m.group("val"))):
            return m.group(0)
        n += 1
        return m.group("pre") + "'" + REDACTED + "'"
    text = SQ_KV_RE.sub(skv, text)

    def assign(m):
        nonlocal n
        key = m.group("key")
        if not (is_secret_key(key, generic) or key in plugin_secret_fields):
            return m.group(0)
        if json_mode and key == "key":
            return m.group(0)
        if shell and (m.group("op") == ":" or re.search(r"\s[:=]|[:=]\s", m.group("pre")[m.end("key") - m.start():])):
            return m.group(0)             # shell assignments are KEY=value; anything else is prose
        dq, sq, uq = m.group("dq"), m.group("sq"), m.group("uq")
        fval = (uq.rstrip().rstrip(",;") if uq is not None else (dq if dq is not None else sq))
        if key not in plugin_secret_fields and _weak_generic(key, fval):
            return m.group(0)
        if uq is not None:
            val = uq.rstrip().rstrip(",;")
            if code and not shell:
                return m.group(0)         # identifier/expression in code, not a literal
            if shell and (val.startswith(("$", "`", "(")) or "$(" in val):
                return m.group(0)
            if _placeholder(val) or (shell and "$" in val):
                return m.group(0)
            n += 1
            return m.group("pre") + REDACTED + uq[len(val):]
        val = dq if dq is not None else sq
        if _placeholder(val) or (code and ("$" in val or "{" in val)):
            return m.group(0)
        q = '"' if dq is not None else "'"
        n += 1
        return m.group("pre") + q + REDACTED + q
    # Not re.sub: a non-secret key must not swallow the rest of the line
    # (Environment=FOO_TOKEN=x, "# note: a=1 password=x", "{user: a, password: x}").
    out, pos = [], 0
    while True:
        m = ASSIGN_RE.search(text, pos)
        if not m:
            break
        rep = assign(m)
        if rep == m.group(0):
            out.append(text[pos:m.start("key") + 1])
            pos = m.start("key") + 1
        else:
            out.append(text[pos:m.start()] + rep)
            pos = m.end()
    out.append(text[pos:])
    text = "".join(out)

    def flag(m):
        nonlocal n
        if not is_secret_key(m.group("key")) or _placeholder(m.group("val")) or m.group("val").startswith("$"):
            return m.group(0)
        n += 1
        return m.group("pre") + REDACTED
    text = FLAG_RE.sub(flag, text)

    def url(m):
        nonlocal n
        if m.group("val") == REDACTED or m.group("val").startswith("$"):
            return m.group(0)
        n += 1
        return m.group("pre") + REDACTED
    text = URL_CRED_RE.sub(url, text)
    return text, n


def _schema_dict(obj):
    """A settings-schema entry ({"key": "port", "label": ..., "type": ...}):
    its "key" names a field, it is not a credential."""
    return isinstance(obj, dict) and ("label" in obj or "type" in obj or "options" in obj)


def _redact_json_obj(obj, secret_fields=(), under_secret=False):
    n = 0
    if isinstance(obj, dict):
        out = {}
        schema = _schema_dict(obj)
        for k, v in obj.items():
            sec = under_secret or k in secret_fields or (
                is_secret_key(k) and not (schema and k == "key") and not (
                    not isinstance(v, (dict, list)) and _weak_generic(k, v)))
            if isinstance(v, (dict, list)):
                out[k], c = _redact_json_obj(v, (), sec)
                n += c
            elif sec and v not in (None, "", True, False) and not (isinstance(v, str) and _placeholder(v)):
                out[k] = REDACTED
                n += 1
            elif isinstance(v, str) and PEM_BODY_RE.search(v):
                out[k] = REDACTED
                n += 1
            else:
                out[k] = v
        return out, n
    if isinstance(obj, list):
        out = []
        for v in obj:
            if isinstance(v, (dict, list)):
                r, c = _redact_json_obj(v, (), under_secret)
                n += c
                out.append(r)
            elif (under_secret and v not in (None, "", True, False)
                  and not (isinstance(v, str) and _placeholder(v))) or (isinstance(v, str) and PEM_BODY_RE.search(v)):
                out.append(REDACTED)
                n += 1
            else:
                out.append(v)
        return out, n
    return obj, 0


def plugin_secret_fields(manifest_bytes):
    """Field keys a plugin manifest (plugin.json) declares secret/password."""
    try:
        man = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return set()
    fields = man.get("config") or man.get("settings") or []
    out = set()
    if isinstance(fields, list):
        for f in fields:
            if isinstance(f, dict) and f.get("key") and (f.get("secret") or f.get("type") == "password"):
                out.add(str(f["key"]))
    return out


def sanitize_member(name, data, secret_fields=()):
    """('drop', reason) or ('keep', bytes, n_redactions) for one regular file."""
    if not (name in TOP_FILES or name.startswith(EXPORT_PREFIXES)):
        return ("drop", "outside the export allowlist")
    if secret_file(name):
        return ("drop", "secret file")
    if is_binary(data):
        return ("drop", "binary")
    text = data.decode("utf-8")
    n = 0
    obj = None
    if name.endswith(".json"):
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if obj is not None:
            obj, n = _redact_json_obj(obj, secret_fields)
            text = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    text, n2 = redact_text(name, text, secret_fields, json_mode=obj is not None)
    n += n2
    if find_secrets(name, text.encode("utf-8"), secret_fields):
        return ("drop", "could not be redacted safely")
    return ("keep", text.encode("utf-8"), n)


def find_secrets(name, data, secret_fields=()):
    """Reasons a member of a shareable export still looks secret ([] = clean)."""
    reasons = []
    if secret_file(name):
        reasons.append("secret file name")
    if is_binary(data):
        if PEM_BODY_BYTES_RE.search(data):
            reasons.append("private key block")
        reasons.append("binary")
        return reasons
    text = data.decode("utf-8")
    if PEM_BODY_RE.search(text):
        reasons.append("private key block")
    parsed = False
    if name.endswith(".json"):
        try:
            obj = json.loads(text)
            parsed = True
            if _redact_json_obj(obj, secret_fields)[1]:
                reasons.append("secret json field")
        except ValueError:
            pass
    if redact_text(name, text, secret_fields, json_mode=parsed)[1]:
        reasons.append("secret key/value")
    return reasons


def _plugin_fields_from_tar(tar):
    out = {}
    for m in tar:
        name = member_safe(m.name)
        if name and m.isreg() and re.match(r"^etc/tuxwall/plugins/[^/]+/plugin\.json$", name) and m.size < 1048576:
            with tar.extractfile(m) as f:
                out[name.rsplit("/", 1)[0]] = plugin_secret_fields(f.read())
    return out


def sanitize_archive(src_path, out_fileobj, source_name=""):
    """Write a sanitized .tar.gz of src_path to out_fileobj. Returns a summary.
    Raises ValueError if the self-check of the written export fails."""
    dropped = []
    redacted = 0
    kept = 0
    with tarfile.open(src_path, "r:gz") as src:
        pfields = _plugin_fields_from_tar(src)
    buf_names = set()
    sums = []
    with tarfile.open(src_path, "r:gz") as src, tarfile.open(fileobj=out_fileobj, mode="w:gz") as dst:
        for m in src:
            name = member_safe(m.name)
            if not name or name in buf_names or name == MANIFEST_NAME:
                continue  # the source SHA256SUMS hashes secret files: a fresh one is written below
            if m.isdir():
                if name.startswith(EXPORT_PREFIXES) and not secret_file(name + "/"):
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.DIRTYPE
                    info.mode = m.mode & 0o755
                    info.mtime = m.mtime
                    dst.addfile(info)
                continue
            if m.issym():
                if name.startswith(EXPORT_PREFIXES) and not secret_file(name):
                    info = tarfile.TarInfo(name)
                    info.type = tarfile.SYMTYPE
                    info.linkname = m.linkname
                    info.mtime = m.mtime
                    dst.addfile(info)
                continue
            if not m.isreg():
                continue
            if not (name in TOP_FILES or name.startswith(EXPORT_PREFIXES)):
                continue  # not part of a shareable template (dashboard code, leases)
            if secret_file(name) or m.size > PREVIEW_TEXT_MAX * 4:
                dropped.append(name)
                continue
            with src.extractfile(m) as f:
                data = f.read()
            sfields = ()
            pm = re.match(r"^(etc/tuxwall/plugins/[^/]+)/", name)
            if pm:
                sfields = pfields.get(pm.group(1), set())
            res = sanitize_member(name, data, sfields)
            if res[0] == "drop":
                if res[1] != "binary":
                    dropped.append(name)
                continue
            body = res[1]
            redacted += res[2]
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mode = m.mode & 0o755
            info.mtime = m.mtime
            dst.addfile(info, io.BytesIO(body))
            buf_names.add(name)
            sums.append((name, sha256_bytes(body)))
            kept += 1
        note = ("TuxWall sanitized export\nCreated: %s\nSource: %s\n"
                "Kept %d config file(s); dropped %d secret file(s); redacted %d value(s).\n"
                "Removed: private keys (PEM/WireGuard/SSH host keys), tokens (dashboard/agent/"
                "cloudflared/canary), auth.json, LLM/opencode keys, CrowdSec credentials, plugin "
                "secrets, passwords/API keys/webhook URLs anywhere in a line.\n"
                "Not included: dashboard code (var/www/html), DHCP leases, binaries.\n"
                "Verify before sharing.\n"
                % (time.strftime("%Y-%m-%d %H:%M:%S"), source_name, kept, len(dropped), redacted))
        info = tarfile.TarInfo("SANITIZED.txt")
        info.size = len(note.encode())
        info.mtime = int(time.time())
        info.mode = 0o644
        dst.addfile(info, io.BytesIO(note.encode()))
        sums.append(("SANITIZED.txt", sha256_bytes(note.encode())))
        body = format_sums(sums).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST_NAME)
        info.size = len(body)
        info.mtime = int(time.time())
        info.mode = 0o644
        dst.addfile(info, io.BytesIO(body))
    return {"dropped": dropped, "redacted": redacted, "kept": kept}


def verify_export(fileobj_or_path):
    """Re-scan a written export. Returns [(member, reasons)] (empty = clean)."""
    bad = []
    kw = {"fileobj": fileobj_or_path} if hasattr(fileobj_or_path, "read") else {"name": fileobj_or_path}
    with tarfile.open(mode="r:gz", **kw) as tar:
        pf = {}
        members = []
        for m in tar:
            members.append(m)
        for m in members:
            n = m.name
            if m.isreg() and re.match(r"^etc/tuxwall/plugins/[^/]+/plugin\.json$", n):
                pf[n.rsplit("/", 1)[0]] = plugin_secret_fields(tar.extractfile(m).read())
        for m in members:
            if not m.isreg() or m.name in ("SANITIZED.txt", MANIFEST_NAME):
                continue
            pm = re.match(r"^(etc/tuxwall/plugins/[^/]+)/", m.name)
            r = find_secrets(m.name, tar.extractfile(m).read(), pf.get(pm.group(1), ()) if pm else ())
            if r:
                bad.append((m.name, r))
    return bad


def sanitize_to_dir(root, src_path, source_name="", who=""):
    """Create sanitized-<ts>.tar.gz next to the archives (0600), verified."""
    d = P(root, SYSTEM_DIR)
    out_name = "sanitized-" + time.strftime("%Y%m%d-%H%M%S") + ".tar.gz"
    tmp = os.path.join(d, ".%s.%s.partial" % (out_name, secrets.token_hex(4)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            summary = sanitize_archive(src_path, f, source_name)
        bad = verify_export(tmp)
        if bad:
            raise ValueError("Sanitizer self-check failed for %d file(s) (%s); no export was written"
                             % (len(bad), ", ".join(b[0] for b in bad[:3])))
        os.replace(tmp, os.path.join(d, out_name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    prune_simple(root, SANITIZED_RE, SANITIZED_KEEP)
    audit(root, "sanitize", who=who, archive=source_name, export=out_name,
          dropped=len(summary["dropped"]), redacted=summary["redacted"])
    return dict(summary, name=out_name)


# ── uploads ─────────────────────────────────────────────────────────────────

def store_upload(root, raw, who="", passphrase=None, gpg=None):
    """Store an uploaded backup: a .tar.gz, or an OpenPGP-encrypted one
    (decrypted with ``passphrase`` or else the stored one). The archive is
    limit-checked and its SHA256SUMS verified; a damaged upload is refused."""
    if not raw or len(raw) < 64:
        raise ValueError("Upload is empty")
    if len(raw) > UPLOAD_MAX_BYTES:
        raise ValueError("Upload is larger than %d MB" % (UPLOAD_MAX_BYTES // 1048576))
    encrypted = looks_encrypted(raw)
    if raw[:2] != b"\x1f\x8b" and not encrypted:
        raise ValueError("Not a .tar.gz archive or an encrypted TuxWall backup (.gpg)")
    d = P(root, SYSTEM_DIR)
    os.makedirs(d, exist_ok=True)
    name = "uploaded-" + time.strftime("%Y%m%d-%H%M%S") + ".tar.gz"
    tmp = os.path.join(d, ".%s.%s.partial" % (name, secrets.token_hex(4)))
    enc_tmp = None
    try:
        if encrypted:
            pw = passphrase or read_passphrase(root)
            if not pw:
                raise Refused(400, {"ok": False, "need_passphrase": True,
                                    "error": "This backup is encrypted. Enter the passphrase it was encrypted with."})
            fd, enc_tmp = mkstemp_private(root, prefix="upload-", suffix=".gpg")
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                try:
                    gpg_decrypt_stream(root, enc_tmp, pw, out.write, cap=UPLOAD_MAX_BYTES * 2, gpg=gpg)
                except DecryptError as exc:
                    if exc.kind == "passphrase":
                        raise Refused(400, {"ok": False, "need_passphrase": True,
                                            "error": "Wrong passphrase: this backup could not be decrypted"
                                                     + ("" if passphrase else " with the stored one")
                                                     + ". Enter the passphrase it was encrypted with."})
                    raise ValueError(str(exc))
            with open(tmp, "rb") as f:
                if f.read(2) != b"\x1f\x8b":
                    raise ValueError("The decrypted upload is not a .tar.gz archive")
        else:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
        info = check_archive(tmp, strict=True)
        integ = verify_members(tmp)
        if integ["status"] == "damaged":
            raise ValueError("The uploaded backup is damaged: %s" % integrity_summary(integ))
        files = contents(tmp)
        if not files:
            raise ValueError("No restorable TuxWall files in this archive")
        sha = sha256_file(tmp)
        os.replace(tmp, os.path.join(d, name))
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        err = exc.payload.get("error") if isinstance(exc, Refused) else str(exc)
        audit(root, "upload", who=who, ok=False, error=str(err)[:200], bytes=len(raw), encrypted=encrypted)
        raise
    finally:
        if enc_tmp:
            try:
                os.unlink(enc_tmp)
            except OSError:
                pass
    record_integrity(root, name, integ, sha, os.path.getsize(os.path.join(d, name)))
    removed = prune_simple(root, UPLOADED_RE, UPLOADED_KEEP)
    if removed:
        update_state(root, lambda s: [(s.get("archives") or {}).pop(n, None) for n in removed])
    audit(root, "upload", who=who, ok=True, archive=name, bytes=len(raw), members=info["members"],
          encrypted=encrypted, integrity=integ["status"])
    return {"ok": True, "name": name, "files": files, "members": info["members"], "total": info["total"],
            "encrypted": encrypted, "integrity": integ["status"], "sha256": sha}


# ── restore ─────────────────────────────────────────────────────────────────
# Firewall files never restore raw: they become an uploaded fw snapshot and
# go through Firewall > Snapshots (preview, guard, 60 s confirm-or-revert).
FW_UFW_MAP = {
    "etc/ufw/user.rules": "user.rules", "etc/ufw/user6.rules": "user6.rules",
    "etc/ufw/before.rules": "before.rules", "etc/ufw/before6.rules": "before6.rules",
    "etc/ufw/after.rules": "after.rules", "etc/ufw/after6.rules": "after6.rules",
    "etc/ufw/sysctl.conf": "sysctl.conf", "etc/default/ufw": "ufw.default",
}
FW_RAW_MAP = {"iptables-save.txt": "iptables.save", "ip6tables-save.txt": "ip6tables.save"}
FW_LIVE = {"sysctl.conf": "/etc/ufw/sysctl.conf", "ufw.default": "/etc/default/ufw"}
FW_REQUIRED = ("user.rules", "user6.rules", "before.rules")

STRICT_PREFIXES = (
    ("usr/local/", "replaces a program or script that runs as root"),
    ("etc/systemd/", "changes how services start (systemd)"),
    ("var/www/html/includes/", "replaces executable dashboard code"),
    ("var/www/html/scripts/", "replaces executable dashboard code"),
    ("etc/sudoers.d/", "changes sudo rules (a syntax error can break sudo)"),
    ("etc/ssh/", "changes SSH access"),
    ("etc/ufw/", "changes firewall settings"),
    ("etc/netplan/", "changes network interfaces (can cut the LAN on next apply)"),
    ("etc/nftables.conf", "changes firewall settings"),
    ("etc/fstab", "changes mounts (a bad fstab can stop boot)"),
)
SECRET_DIRS = ("etc/tuxwall/", "etc/wireguard/", "etc/ssh/", "etc/letsencrypt/", "etc/cloudflared/",
               "var/lib/tuxwall/")
SECRETISH_RE = re.compile(r"(?i)(key|token|secret|credential|password|passwd|private|auth\.json|llm\.json|\.pem$)")


def strict_reason(name):
    for pre, why in STRICT_PREFIXES:
        if name == pre.rstrip("/") or name.startswith(pre):
            return why
    return None


def is_firewall_member(name):
    return name in FW_UFW_MAP or name in FW_RAW_MAP


def default_mode(name, member_mode=0o644):
    if name.startswith("etc/sudoers.d/"):
        return 0o440
    if name.startswith(SECRET_DIRS) or secret_file(name) or SECRETISH_RE.search(name.rsplit("/", 1)[-1]):
        return 0o600
    if name.startswith(("usr/local/bin/", "usr/local/sbin/")) and member_mode & 0o111:
        return 0o755
    return 0o644


def _owner_name(uid, gid):
    try:
        import pwd
        import grp
        return "%s:%s" % (pwd.getpwuid(uid).pw_name, grp.getgrgid(gid).gr_name)
    except Exception:
        return "%d:%d" % (uid, gid)


def _walk_parent(root, name, create=False):
    """Open the parent directory of /<name> under root component by component
    with O_NOFOLLOW, refusing symlinked directories. Returns (dir_fd, base,
    missing_dirs) - dir_fd is None when a directory is missing and create is
    False. Caller closes dir_fd."""
    parts = name.split("/")
    base = parts[-1]
    fd = os.open(root or "/", os.O_RDONLY | os.O_DIRECTORY)
    missing = []
    try:
        for i, comp in enumerate(parts[:-1]):
            try:
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                missing = parts[i:-1]
                if not create:
                    os.close(fd)
                    return None, base, missing
                mode = 0o700 if ("/".join(parts[:i + 1]) + "/").startswith(SECRET_DIRS) else 0o755
                os.mkdir(comp, mode, dir_fd=fd)
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except (NotADirectoryError, OSError) as exc:
                if os.path.islink(os.path.join(root or "/", *parts[:i + 1])):
                    raise Refused(409, {"ok": False, "error": "/%s is a symlink; restore refused"
                                        % "/".join(parts[:i + 1])})
                raise Refused(409, {"ok": False, "error": "Cannot open /%s (%s)"
                                    % ("/".join(parts[:i + 1]), exc.__class__.__name__)})
            os.close(fd)
            fd = nfd
        return fd, base, missing
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _live_state(root, name):
    """{'exists', 'data', 'mode', 'uid', 'gid', 'missing_dirs'} without following symlinks."""
    dfd, base, missing = _walk_parent(root, name, create=False)
    if dfd is None:
        return {"exists": False, "missing_dirs": missing}
    try:
        try:
            st = os.stat(base, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return {"exists": False, "missing_dirs": []}
        import stat as _st
        if _st.S_ISLNK(st.st_mode):
            raise Refused(409, {"ok": False, "error": "/%s is a symlink; restore refused" % name})
        if not _st.S_ISREG(st.st_mode):
            raise Refused(409, {"ok": False, "error": "/%s is not a regular file; restore refused" % name})
        fd = os.open(base, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        with os.fdopen(fd, "rb") as f:
            data = f.read(MAX_MEMBER_BYTES + 1)
        return {"exists": True, "data": data, "mode": st.st_mode & 0o7777, "uid": st.st_uid,
                "gid": st.st_gid, "missing_dirs": []}
    finally:
        os.close(dfd)


def _diff(old, new, name, limit=DIFF_MAX_LINES):
    lines = list(difflib.unified_diff(old.splitlines(), new.splitlines(), "live/" + name,
                                      "backup/" + name, lineterm="", n=3))
    trunc = len(lines) > limit
    return "\n".join(lines[:limit]), trunc, len(lines)


def restore_preview(root, archive_path, archive_name, member):
    """What a single-file restore would do. Read-only."""
    name, m, new = read_member(archive_path, member)
    return dict(_preview_body(root, name, m, new), ok=True, archive=archive_name)


def _preview_body(root, name, m, new, diff_limit=DIFF_MAX_LINES):
    out = {"member": name, "target": "/" + name,
           "new_size": len(new), "new_sha256": sha256_bytes(new), "restart_hint": service_for(name)}
    if is_firewall_member(name):
        out.update(kind="firewall", restorable=False, firewall=True,
                   message="Firewall files are never restored raw. Import them as a firewall snapshot, "
                           "then preview and restore it in Firewall > Settings > Snapshots (guard check, "
                           "automatic snapshot first, 60 s confirm-or-revert).")
        return out
    if name in TOP_FILES:
        out.update(kind="info", restorable=False,
                   message="This is an information file of the backup; download it instead.")
        return out
    live = _live_state(root, name)
    strict = strict_reason(name)
    out.update(firewall=False, restorable=True, strict=bool(strict), strict_reason=strict,
               old_sha256=sha256_bytes(live["data"]) if live["exists"] else "absent")
    if live["exists"]:
        mode, uid, gid, src = live["mode"], live["uid"], live["gid"], "kept from the live file"
    else:
        mode, uid, gid, src = default_mode(name, m.mode), 0, 0, "default for a new file"
    out["perms"] = {"mode": "%04o" % mode, "owner": _owner_name(uid, gid), "source": src}
    if live.get("missing_dirs"):
        out["creates_dirs"] = "/" + "/".join(name.split("/")[:-1])
    if not live["exists"]:
        out["kind"] = "new"
        out["old_size"] = 0
    elif live["data"] == new:
        out["kind"] = "identical"
        out["old_size"] = len(live["data"])
    else:
        out["kind"] = "modified"
        out["old_size"] = len(live["data"])
    old = live.get("data") or b""
    if is_binary(new) or (live["exists"] and is_binary(old)):
        out["binary"] = True
        out["diff"] = ""
    elif len(new) > PREVIEW_TEXT_MAX or len(old) > PREVIEW_TEXT_MAX:
        out["binary"] = False
        out["diff"] = ""
        out["diff_note"] = "File too large to diff"
    else:
        out["binary"] = False
        if out["kind"] == "modified":
            d, trunc, total = _diff(old.decode("utf-8"), new.decode("utf-8"), name, diff_limit)
            out.update(diff=d, diff_truncated=trunc, diff_lines=total)
        elif out["kind"] == "new":
            d, trunc, total = _diff("", new.decode("utf-8"), name, diff_limit)
            out.update(diff=d, diff_truncated=trunc, diff_lines=total)
        else:
            out["diff"] = ""
    return out


def restore_apply(root, archive_path, archive_name, member, who="", client="", confirm_strict=False,
                  expect_new=None, expect_old=None):
    """Atomic single-file restore. Requires the hashes from restore_preview
    (so the user saw exactly this change and the live file did not change
    since); strict paths need confirm_strict. The previous live file is
    copied to PRE_RESTORE_DIR first; the write is temp + fsync + rename in
    the target directory (opened without following symlinks)."""
    def refuse(status, payload):
        audit(root, "restore-file", who=who, client=client, archive=archive_name, member=member,
              ok=False, error=payload.get("error"))
        raise Refused(status, payload)

    name = member_safe(member)
    if not name:
        refuse(400, {"ok": False, "error": "Invalid file name"})
    if is_firewall_member(name):
        refuse(409, {"ok": False, "firewall": True,
                     "error": "Firewall files are restored through Firewall > Snapshots, never raw. "
                              "Use 'Import as firewall snapshot'."})
    if name in TOP_FILES:
        refuse(409, {"ok": False, "error": "Information files of the backup cannot be restored"})
    why = strict_reason(name)
    if why and not confirm_strict:
        refuse(409, {"ok": False, "strict": True, "strict_reason": why,
                     "error": "This file %s; resubmit with the second confirmation." % why})
    name, m, new = read_member(archive_path, name)
    if not expect_new or expect_new != sha256_bytes(new):
        refuse(409, {"ok": False, "error": "Preview the restore first (the backup content does not match the preview)."})
    with _restore_lock:
        try:
            live = _live_state(root, name)
        except Refused as exc:
            refuse(exc.status, exc.payload)
        cur = sha256_bytes(live["data"]) if live["exists"] else "absent"
        if expect_old != cur:
            refuse(409, {"ok": False, "error": "The live file changed since the preview; preview again."})
        stamp = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)
        pre_path = None
        if live["exists"]:
            _private_dir(P(root, PRE_RESTORE_DIR))
            pre_dir = _private_dir(os.path.join(P(root, PRE_RESTORE_DIR), stamp))
            pre_path = os.path.join(pre_dir, name)
            _private_dir(os.path.dirname(pre_path))
            _write_private(pre_path, live["data"])
            _write_private(os.path.join(pre_dir, "meta.json"), json.dumps({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"), "who": who, "archive": archive_name,
                "member": name, "target": "/" + name, "mode": "%04o" % live["mode"],
                "owner": "%d:%d" % (live["uid"], live["gid"]), "sha256_before": cur,
                "sha256_after": expect_new}, indent=2))
        if live["exists"]:
            mode, uid, gid = live["mode"], live["uid"], live["gid"]
        else:
            mode, uid, gid = default_mode(name, m.mode), 0, 0
        try:
            _atomic_write(root, name, new, mode, uid, gid)
        except BaseException as exc:
            audit(root, "restore-file", who=who, client=client, archive=archive_name, member=name,
                  ok=False, error=str(exc)[:200])
            raise
    prune_pre_restore(root)
    rel_pre = os.path.relpath(pre_path, P(root, "/")) if pre_path else None
    audit(root, "restore-file", who=who, client=client, archive=archive_name, member=name,
          target="/" + name, ok=True, created=not live["exists"], mode="%04o" % mode,
          owner="%d:%d" % (uid, gid), sha256_before=cur, sha256_after=expect_new,
          pre_restore=("/" + rel_pre) if rel_pre else None)
    return {"ok": True, "restored": name, "target": "/" + name, "created": not live["exists"],
            "mode": "%04o" % mode, "owner": _owner_name(uid, gid),
            "pre_restore": ("/" + rel_pre) if rel_pre else None,
            "restart_required": service_for(name)}


SANDBOX_MSG = ("/%s cannot be written by the dashboard: tuxwall.service runs sandboxed (ProtectSystem=full) "
               "and can only replace files inside the directories listed in its ReadWritePaths (a file "
               "directly in /etc is never one of them). Restore it from a root shell instead: "
               "tar -xzf <archive> -C / %s")


def _atomic_write(root, name, data, mode, uid, gid):
    """_atomic_write_at, with a clear refusal instead of a bare EROFS/EBUSY
    when the target is outside the service's writable paths (temp file in a
    read-only directory, or rename onto a single-file bind mount)."""
    try:
        _atomic_write_at(root, name, data, mode, uid, gid)
    except OSError as exc:
        if exc.errno in (errno.EROFS, errno.EBUSY):
            raise Refused(409, {"ok": False, "sandbox": True, "error": SANDBOX_MSG % (name, name)})
        raise


def _atomic_write_at(root, name, data, mode, uid, gid):
    """temp + fsync + rename next to /<name>, parent opened without
    following symlinks (missing directories are created)."""
    dfd, base, _missing = _walk_parent(root, name, create=True)
    tmp = None
    try:
        for _ in range(10):
            cand = ".%s.tuxwall-restore-%s" % (base[:100], secrets.token_hex(6))
            try:
                fd = os.open(cand, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                             dir_fd=dfd)
                tmp = cand
                break
            except FileExistsError:
                continue
        if tmp is None:
            raise OSError("could not create a temp file next to the target")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if os.geteuid() == 0:
                os.fchown(f.fileno(), uid, gid)
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.rename(tmp, base, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = None
        try:
            os.fsync(dfd)
        except OSError:
            pass
    finally:
        if tmp:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        os.close(dfd)


def _unlink_target(root, name):
    dfd, base, _missing = _walk_parent(root, name, create=False)
    if dfd is None:
        return
    try:
        os.unlink(base, dir_fd=dfd)
    except FileNotFoundError:
        pass
    finally:
        os.close(dfd)


_restore_lock = threading.Lock()


def firewall_snapshot_files(root, archive_path):
    """fw_snap files/raw dicts built from a system backup, plus notes.
    Missing ufw.default/sysctl.conf (older backups) come from the live box."""
    files, raw, notes = {}, {}, []
    with tarfile.open(archive_path, "r:gz") as tar:
        for m in tar:
            name = member_safe(m.name)
            if not name or not m.isreg() or m.size > 1024 * 1024:
                continue
            if name in FW_UFW_MAP:
                files[FW_UFW_MAP[name]] = tar.extractfile(m).read().decode("utf-8", errors="replace")
            elif name in FW_RAW_MAP:
                raw[FW_RAW_MAP[name]] = tar.extractfile(m).read().decode("utf-8", errors="replace")
    missing = [k for k in FW_REQUIRED if not files.get(k)]
    if missing:
        raise Refused(409, {"ok": False, "error": "This backup has no ufw rule files (%s missing), so it "
                            "cannot become a firewall snapshot. Its iptables dump is reference only: "
                            "download it to compare." % ", ".join(missing)})
    for k, live in FW_LIVE.items():
        if not files.get(k):
            try:
                with open(P(root, live)) as f:
                    files[k] = f.read()
                notes.append("%s is not in this backup; the current %s was used" % (k, live))
            except OSError:
                files[k] = ""
    for k in ("before6.rules", "after.rules", "after6.rules"):
        files.setdefault(k, "")
    return files, raw, notes


# ── restore: several files or a whole service ───────────────────────────────
# One preview listing every diff, one apply: all live hashes are checked
# first, every live file is copied into ONE pre-restore folder, then each
# file is written atomically; if any write fails the files already written
# are put back (created ones removed). Services are never restarted here:
# the result lists the affected units (unit_plan) for the owner to apply.
RESTORE_MANY_MAX = 400
PREVIEW_MANY_DIFF_LINES = 6000


def read_members(path, names):
    """{name: (TarInfo, bytes)} for the given safe members, in one pass."""
    want = set(names)
    out = {}
    total = 0
    with tarfile.open(path, "r:gz") as tar:
        for m in tar:
            n = member_safe(m.name)
            if n not in want or n in out:
                continue
            if not (m.isreg() or m.islnk()):
                raise ValueError("/%s is not a regular file in this backup" % n)
            f = tar.extractfile(m)
            if f is None:
                raise ValueError("/%s cannot be read from this backup" % n)
            with f:
                data = f.read(MAX_MEMBER_BYTES + 1)
            if len(data) > MAX_MEMBER_BYTES:
                raise ValueError("/%s is too large" % n)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("The selection is too large to restore at once")
            out[n] = (m, data)
    missing = sorted(want - set(out))
    if missing:
        raise ValueError("Not in this backup: %s" % ", ".join("/" + n for n in missing[:3]))
    return out


def services_in(files):
    """Service groups of a contents() listing: [{service, files, firewall}]."""
    groups = {}
    for f in files:
        svc = f.get("service")
        if not svc or f.get("kind") == "info":
            continue
        g = groups.setdefault(svc, {"service": svc, "files": 0, "firewall": 0})
        if f.get("kind") == "firewall":
            g["firewall"] += 1
        else:
            g["files"] += 1
    return sorted(groups.values(), key=lambda g: g["service"])


def members_for_service(path, service):
    return [f["name"] for f in contents(path) if f.get("service") == service and f.get("kind") != "info"]


def _clean_names(members):
    if not isinstance(members, list) or not members:
        raise ValueError("Select at least one file")
    if len(members) > RESTORE_MANY_MAX:
        raise ValueError("Select at most %d files at once" % RESTORE_MANY_MAX)
    names = []
    for raw in members:
        n = member_safe(raw if isinstance(raw, str) else "")
        if not n:
            raise ValueError("Invalid file name: %s" % str(raw)[:80])
        if n not in names:
            names.append(n)
    return names


def restore_preview_many(root, archive_path, archive_name, members=None, service=None):
    """Read-only preview of restoring several files (or every file of one
    service): one entry per file with kind/diff/perms/hashes."""
    if service:
        members = members_for_service(archive_path, service)
        if not members:
            raise ValueError("No files of %s in this backup" % service)
    names = _clean_names(members)
    fw = [n for n in names if is_firewall_member(n)]
    info = [n for n in names if n in TOP_FILES and n not in fw]
    files = [n for n in names if n not in fw and n not in info]
    data = read_members(archive_path, files) if files else {}
    items = []
    budget = PREVIEW_MANY_DIFF_LINES
    for n in sorted(files):
        m, new = data[n]
        try:
            item = _preview_body(root, n, m, new, diff_limit=max(0, min(DIFF_MAX_LINES, budget)))
        except Refused as exc:
            items.append({"member": n, "target": "/" + n, "kind": "refused", "restorable": False,
                          "error": exc.payload.get("error")})
            continue
        if budget <= 0 and item.get("kind") in ("new", "modified") and not item.get("binary"):
            item["diff"] = ""
            item["diff_note"] = "Diff not shown (preview limit reached); the file is still restored as listed"
        budget -= min(item.get("diff_lines") or 0, DIFF_MAX_LINES)
        items.append(item)
    changing = [i for i in items if i.get("restorable") and i.get("kind") in ("new", "modified")]
    return {"ok": True, "archive": archive_name, "service": service or None, "items": items,
            "firewall": fw, "info": info, "changes": len(changing),
            "strict": sorted({i["strict_reason"] for i in changing if i.get("strict")}),
            "units": unit_plan(service_for(i["member"]) for i in changing)}


def restore_apply_many(root, archive_path, archive_name, files, who="", client="", confirm_strict=False):
    """Restore several files in one go. files: [{"file", "expect_sha256",
    "expect_live_sha256"}] taken from restore_preview_many."""
    batch = time.strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(2)

    def refuse(status, payload):
        audit(root, "restore-files", who=who, client=client, archive=archive_name, batch=batch,
              files=len(files) if isinstance(files, list) else None, ok=False, error=payload.get("error"))
        raise Refused(status, payload)

    if not isinstance(files, list) or not files or not all(isinstance(f, dict) for f in files):
        refuse(400, {"ok": False, "error": "Select at least one file"})
    try:
        names = _clean_names([f.get("file") for f in files])
    except ValueError as exc:
        refuse(400, {"ok": False, "error": str(exc)})
    if len(names) != len(files):
        refuse(400, {"ok": False, "error": "A file is listed twice"})
    expect = {member_safe(f.get("file")): (f.get("expect_sha256"), f.get("expect_live_sha256")) for f in files}
    fw = [n for n in names if is_firewall_member(n)]
    if fw:
        refuse(409, {"ok": False, "firewall": True,
                     "error": "Firewall files (%s) are restored through Firewall > Snapshots, never raw. "
                              "Use 'Import as firewall snapshot'." % ", ".join(fw[:3])})
    info = [n for n in names if n in TOP_FILES]
    if info:
        refuse(409, {"ok": False, "error": "Information files of the backup cannot be restored"})
    strict = sorted({strict_reason(n) for n in names if strict_reason(n)})
    if strict and not confirm_strict:
        refuse(409, {"ok": False, "strict": True, "strict_reasons": strict,
                     "error": "The selection includes files that %s; resubmit with the second confirmation."
                              % "; ".join(strict)})
    try:
        data = read_members(archive_path, names)
    except ValueError as exc:
        refuse(400, {"ok": False, "error": str(exc)})
    for n in names:
        if not expect[n][0] or expect[n][0] != sha256_bytes(data[n][1]):
            refuse(409, {"ok": False, "error": "Preview the restore first (the backup content of /%s does not "
                                               "match the preview)." % n})
    done, unchanged = [], []
    with _restore_lock:
        lives = {}
        for n in names:
            try:
                live = _live_state(root, n)
            except Refused as exc:
                refuse(exc.status, exc.payload)
            cur = sha256_bytes(live["data"]) if live["exists"] else "absent"
            if expect[n][1] != cur:
                refuse(409, {"ok": False, "error": "/%s changed since the preview; preview again." % n})
            live["sha"] = cur
            lives[n] = live
        todo = [n for n in names if not (lives[n]["exists"] and lives[n]["data"] == data[n][1])]
        unchanged = [n for n in names if n not in todo]
        pre_dir = None
        if any(lives[n]["exists"] for n in todo):
            _private_dir(P(root, PRE_RESTORE_DIR))
            pre_dir = _private_dir(os.path.join(P(root, PRE_RESTORE_DIR), batch))
            meta = []
            for n in todo:
                lv = lives[n]
                if lv["exists"]:
                    p = os.path.join(pre_dir, n)
                    _private_dir(os.path.dirname(p))
                    _write_private(p, lv["data"])
                meta.append({"member": n, "target": "/" + n, "existed": lv["exists"],
                             "mode": "%04o" % lv["mode"] if lv["exists"] else None,
                             "owner": "%d:%d" % (lv["uid"], lv["gid"]) if lv["exists"] else None,
                             "sha256_before": lv["sha"], "sha256_after": expect[n][0]})
            _write_private(os.path.join(pre_dir, "meta.json"), json.dumps({
                "time": time.strftime("%Y-%m-%d %H:%M:%S"), "who": who, "archive": archive_name,
                "batch": batch, "files": meta}, indent=2))
        written = []
        try:
            for n in todo:
                lv = lives[n]
                if lv["exists"]:
                    mode, uid, gid = lv["mode"], lv["uid"], lv["gid"]
                else:
                    mode, uid, gid = default_mode(n, data[n][0].mode), 0, 0
                _atomic_write(root, n, data[n][1], mode, uid, gid)
                written.append(n)
                done.append({"member": n, "target": "/" + n, "created": not lv["exists"], "mode": "%04o" % mode,
                             "owner": _owner_name(uid, gid), "sha256_before": lv["sha"],
                             "sha256_after": expect[n][0]})
        except BaseException as exc:
            failed_at = todo[len(written)] if len(written) < len(todo) else "?"
            rollback_errors = []
            for n in reversed(written):
                lv = lives[n]
                try:
                    if lv["exists"]:
                        _atomic_write(root, n, lv["data"], lv["mode"], lv["uid"], lv["gid"])
                    else:
                        _unlink_target(root, n)
                except Exception as rexc:
                    rollback_errors.append("/%s (%s)" % (n, rexc.__class__.__name__))
            msg = ("Restore failed at /%s (%s). %d file(s) already written were put back%s."
                   % (failed_at, str(exc)[:160], len(written) - len(rollback_errors),
                      ("; could NOT put back: " + ", ".join(rollback_errors)) if rollback_errors else ""))
            refuse(500, {"ok": False, "error": msg, "rolled_back": len(written) - len(rollback_errors)})
    prune_pre_restore(root)
    rel_pre = ("/" + os.path.relpath(pre_dir, P(root, "/"))) if pre_dir else None
    for d in done:
        audit(root, "restore-file", who=who, client=client, archive=archive_name, member=d["member"],
              target=d["target"], ok=True, created=d["created"], mode=d["mode"], batch=batch,
              sha256_before=d["sha256_before"], sha256_after=d["sha256_after"], pre_restore=rel_pre)
    audit(root, "restore-files", who=who, client=client, archive=archive_name, batch=batch, ok=True,
          files=len(done), unchanged=len(unchanged) or None, pre_restore=rel_pre)
    return {"ok": True, "restored": done, "unchanged": unchanged, "pre_restore": rel_pre, "batch": batch,
            "units": unit_plan(service_for(d["member"]) for d in done)}


# ── applying a restore: reload/restart affected units (never automatic) ─────
# Only units a catalog item maps to; config checks run first where a
# checker exists; network-critical units need an explicit confirmation.
UNIT_ACTIONS = {
    "systemd-networkd": {"label": "Network (netplan / systemd-networkd)", "action": "reload", "critical": True,
                         "check": ["netplan", "generate"], "cmd": ["networkctl", "reload"],
                         "warning": "Re-applies the interface configuration: if the restored network config "
                                    "is wrong, the LAN, the WAN and this dashboard session can drop."},
    "kea-dhcp4-server": {"label": "KEA DHCP server", "action": "restart", "critical": True,
                         "check": ["kea-dhcp4", "-t", "/etc/kea/kea-dhcp4.conf"],
                         "warning": "DHCP pauses for a moment; a bad config leaves new devices without an address."},
    "unbound": {"label": "Unbound DNS", "action": "restart", "critical": True, "check": ["unbound-checkconf"],
                "warning": "DNS for the whole LAN stops for a few seconds; a bad config stops name resolution."},
    "wg-quick@wg0": {"label": "WireGuard VPN (wg0)", "action": "restart", "critical": True,
                     "warning": "Disconnects every VPN client, including you if you are connected over WireGuard."},
    "nginx": {"label": "nginx web server", "action": "reload", "critical": True, "check": ["nginx", "-t"],
              "warning": "nginx serves this dashboard: a bad config can make it unreachable."},
    "tuxwall": {"label": "TuxWall dashboard API", "action": "reload", "critical": True, "self": True,
                "warning": "Restarts this dashboard's API in place; the page reconnects after a few seconds."},
    "cloudflared": {"label": "Cloudflare tunnel", "action": "restart", "critical": True,
                    "warning": "Remote access through the Cloudflare tunnel drops briefly."},
    "ssh": {"label": "SSH server", "action": "reload", "critical": False, "check": ["sshd", "-t"],
            "warning": "Open SSH sessions stay connected; new logins use the restored config."},
    "crowdsec": {"label": "CrowdSec", "action": "restart", "critical": False, "warning": ""},
    "suricata": {"label": "Suricata IDS", "action": "restart", "critical": False,
                 "warning": "The IDS is blind for the minute it takes to load its rules."},
    "opencanary": {"label": "OpenCanary honeypot", "action": "restart", "critical": False, "warning": ""},
    "chrony": {"label": "Time sync (chrony)", "action": "restart", "critical": False, "warning": ""},
    "radvd": {"label": "IPv6 router advertisements (radvd)", "action": "restart", "critical": False,
              "warning": "IPv6 clients re-learn their prefix."},
    "systemd-resolved": {"label": "systemd-resolved", "action": "restart", "critical": False,
                         "warning": "The router's own name lookups pause briefly."},
    "daemon-reload": {"label": "systemd unit definitions", "action": "daemon-reload", "critical": False,
                      "cmd": ["systemctl", "daemon-reload"],
                      "warning": "Reloads unit files; restart the changed services yourself afterwards."},
    "sysctl --system": {"label": "Kernel settings (sysctl.d)", "action": "apply", "critical": True,
                        "cmd": ["sysctl", "--system"],
                        "warning": "Re-applies every kernel setting: a wrong value (e.g. IP forwarding) can stop "
                                   "routing for the whole LAN."},
    "ufw": {"label": "UFW firewall", "manual": "Firewall rules are applied from Firewall > Settings (guard check, "
                                               "automatic snapshot, confirm-or-revert), never from here."},
}


def unit_plan(services):
    out = []
    seen = set()
    for svc in services:
        if not svc or svc in seen:
            continue
        seen.add(svc)
        spec = UNIT_ACTIONS.get(svc)
        if spec is None:
            out.append({"unit": svc, "label": svc, "manual": "Restart it yourself if needed."})
            continue
        out.append({"unit": svc, "label": spec["label"], "action": spec.get("action"),
                    "critical": bool(spec.get("critical")), "warning": spec.get("warning", ""),
                    "check": " ".join(spec["check"]) if spec.get("check") else None,
                    "manual": spec.get("manual")})
    return out


def _unit_cmd(unit, spec):
    if spec.get("cmd"):
        return list(spec["cmd"])
    return ["systemctl", spec["action"], unit]


def run_unit_action(root, unit, confirm_critical=False, who="", client="", runner=None, defer=None):
    """Run the reload/restart for one affected unit after its config check.
    ``defer(cmd)`` runs commands that would kill this process (tuxwall)."""
    runner = runner or subprocess.run
    spec = UNIT_ACTIONS.get(unit or "")
    if spec is None:
        raise Refused(400, {"ok": False, "error": "Not a service a restore can affect"})
    if spec.get("manual"):
        raise Refused(409, {"ok": False, "manual": True, "error": spec["manual"]})
    if spec.get("critical") and not confirm_critical:
        raise Refused(409, {"ok": False, "critical": True, "warning": spec.get("warning"),
                            "error": "%s is network-critical: confirm first. %s" % (spec["label"], spec.get("warning", ""))})
    out = {"ok": True, "unit": unit, "action": spec["action"]}
    if spec.get("check"):
        exe = shutil.which(spec["check"][0], path="/usr/sbin:/usr/bin:/sbin:/bin")
        if exe:
            try:
                p = runner([exe] + spec["check"][1:], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                p = None
            if p is None or p.returncode != 0:
                tail = "" if p is None else ((p.stderr or "") + (p.stdout or "")).strip()[-600:]
                audit(root, "service-action", who=who, client=client, unit=unit, op=spec["action"], ok=False,
                      error="config check failed")
                raise Refused(409, {"ok": False, "check_failed": True, "output": tail,
                                    "error": "Config check (%s) failed, so %s was NOT %sed. Fix the config first."
                                             % (" ".join(spec["check"]), unit, spec["action"].rstrip("e"))})
            out["check"] = "passed"
        else:
            out["check"] = "skipped (%s not installed)" % spec["check"][0]
    cmd = _unit_cmd(unit, spec)
    if spec.get("self") and defer is not None:
        defer(cmd)
        audit(root, "service-action", who=who, client=client, unit=unit, op=spec["action"], ok=True,
              deferred=True)
        out.update(pending=True, message="The dashboard API reloads in a moment; the page reconnects by itself.")
        return out
    try:
        p = runner(cmd, capture_output=True, text=True, timeout=120)
        rc, err = p.returncode, ((p.stderr or "") + (p.stdout or "")).strip()[-600:]
    except subprocess.TimeoutExpired:
        rc, err = None, "timed out"
    ok = rc == 0
    audit(root, "service-action", who=who, client=client, unit=unit, op=spec["action"], ok=ok,
          error=None if ok else err[:200])
    if not ok:
        raise Refused(500, {"ok": False, "output": err,
                            "error": "%s %s failed: %s" % (spec["action"], unit, (err or "exit %s" % rc)[-200:])})
    if spec["action"] in ("restart", "reload") and not spec.get("cmd"):
        try:
            st = runner(["systemctl", "is-active", unit], capture_output=True, text=True, timeout=15)
            out["active"] = (st.stdout or "").strip()
        except Exception:
            pass
    return out


# ── settings: schedule, USB-after-backup, stale threshold ───────────────────
SETTINGS_FILE = "/etc/tuxwall/backups.json"
PASSPHRASE_FILE = "/etc/tuxwall/backup-passphrase"
STALE_DAYS_DEFAULT = 8
STALE_DAYS_RANGE = (1, 90)
DEFAULT_SCHEDULE = {"enabled": True, "freq": "daily", "weekday": 6, "time": "03:30"}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")


def _bool(v, what):
    if isinstance(v, bool):
        return v
    raise ValueError("%s must be true or false" % what)


def validate_schedule(s, base=None):
    if not isinstance(s, dict):
        raise ValueError("Invalid schedule")
    out = dict(base or DEFAULT_SCHEDULE)
    if "enabled" in s:
        out["enabled"] = _bool(s["enabled"], "enabled")
    if "freq" in s:
        if s["freq"] not in ("daily", "weekly"):
            raise ValueError("Frequency must be daily or weekly")
        out["freq"] = s["freq"]
    if "weekday" in s:
        try:
            wd = int(s["weekday"])
        except (TypeError, ValueError):
            raise ValueError("Invalid weekday")
        if not 0 <= wd <= 6 or isinstance(s["weekday"], bool):
            raise ValueError("Invalid weekday")
        out["weekday"] = wd
    if "time" in s:
        m = _TIME_RE.match(str(s["time"]).strip())
        if not m:
            raise ValueError("Time must be HH:MM (24 h)")
        out["time"] = "%02d:%s" % (int(m.group(1)), m.group(2))
    return out


def load_settings(root=""):
    try:
        with open(P(root, SETTINGS_FILE)) as f:
            raw = json.load(f)
        if not isinstance(raw, dict):
            raw = {}
    except (OSError, ValueError):
        raw = {}
    out = {"schedule": dict(DEFAULT_SCHEDULE), "usb_after": False, "stale_days": STALE_DAYS_DEFAULT}
    try:
        out["schedule"] = validate_schedule(raw.get("schedule") or {})
    except ValueError:
        pass
    if isinstance(raw.get("usb_after"), bool):
        out["usb_after"] = raw["usb_after"]
    sd = raw.get("stale_days")
    if isinstance(sd, int) and not isinstance(sd, bool) and STALE_DAYS_RANGE[0] <= sd <= STALE_DAYS_RANGE[1]:
        out["stale_days"] = sd
    return out


def save_settings(root, patch, who=""):
    if not isinstance(patch, dict):
        raise ValueError("Invalid settings")
    cur = load_settings(root)
    new = json.loads(json.dumps(cur))
    if "schedule" in patch:
        new["schedule"] = validate_schedule(patch["schedule"], cur["schedule"])
    if "usb_after" in patch:
        new["usb_after"] = _bool(patch["usb_after"], "usb_after")
    if "stale_days" in patch:
        try:
            sd = int(patch["stale_days"])
        except (TypeError, ValueError):
            raise ValueError("Stale threshold must be a number of days")
        if isinstance(patch["stale_days"], bool) or not STALE_DAYS_RANGE[0] <= sd <= STALE_DAYS_RANGE[1]:
            raise ValueError("Stale threshold must be %d-%d days" % STALE_DAYS_RANGE)
        new["stale_days"] = sd
    path = P(root, SETTINGS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _write_private(path, json.dumps(new, indent=2, sort_keys=True) + "\n")
    changed = sorted(k for k in new if new[k] != cur[k])
    if new["schedule"] != cur["schedule"]:
        # a changed schedule never fires for a slot that is already past
        update_state(root, lambda s: s.setdefault("schedule", {}).update(since=int(time.time())))
    audit(root, "settings", who=who, changed=changed or None,
          schedule=describe_schedule(new["schedule"]) if "schedule" in changed else None,
          usb_after=new["usb_after"] if "usb_after" in changed else None,
          stale_days=new["stale_days"] if "stale_days" in changed else None)
    return new


# ── schedule (pure math + the due check the API thread polls) ───────────────

def describe_schedule(s):
    if not s.get("enabled"):
        return "off"
    if s.get("freq") == "weekly":
        return "weekly on %s at %s" % (WEEKDAYS[int(s.get("weekday", 6))], s.get("time"))
    return "daily at %s" % s.get("time")


def schedule_slots(sched, now):
    """(previous, next): the latest scheduled time <= now and the first one
    > now, in local time (DST-safe via mktime). (None, None) when off."""
    if not sched.get("enabled"):
        return None, None
    hh, mm = (int(x) for x in sched["time"].split(":"))
    today = datetime.date.fromtimestamp(now)
    prev = nxt = None
    for d in range(-8, 9):
        day = today + datetime.timedelta(days=d)
        if sched.get("freq") == "weekly" and day.weekday() != int(sched.get("weekday", 6)):
            continue
        ts = time.mktime((day.year, day.month, day.day, hh, mm, 0, 0, 0, -1))
        if ts <= now:
            prev = ts
        elif nxt is None:
            nxt = ts
    return prev, nxt


def due_slot(sched, now, since, last_slot=None, last_full_started=None):
    """Pure: the slot a scheduled run is due for, or None.
    - one run per slot (last_slot), retried only if it could not start;
    - a slot before ``since`` (schedule created/changed later) never fires;
    - a missed slot (router off) still fires once, at the next check;
    - a full backup that started at/after the slot already covers it."""
    prev, _nxt = schedule_slots(sched, now)
    if prev is None or since is None or prev <= since:
        return None
    if last_slot and last_slot >= prev:
        return None
    if last_full_started and last_full_started >= prev:
        return None
    return prev


def schedule_due(root="", now=None):
    now = time.time() if now is None else now
    sched = load_settings(root)["schedule"]
    st = load_state(root)
    sc = st.get("schedule") or {}
    if sc.get("since") is None:
        update_state(root, lambda s: s.setdefault("schedule", {}).update(since=int(now)))
        return None
    ls = st.get("last_success") or {}
    full = ls.get("started") if ls.get("items") == "all" else None
    return due_slot(sched, now, sc.get("since"), sc.get("last_slot"), full)


def mark_slot(root, slot, run):
    def fn(s):
        sc = s.setdefault("schedule", {})
        sc.update(last_slot=int(slot), last_attempt=int(time.time()),
                  last_ok=bool(run and run.get("ok")), last_result=(run or {}).get("result"),
                  last_error=(run or {}).get("error"))
    update_state(root, fn)


def schedule_info(root="", now=None):
    now = time.time() if now is None else now
    settings = load_settings(root)
    prev, nxt = schedule_slots(settings["schedule"], now)
    sc = load_state(root).get("schedule") or {}
    return dict(settings["schedule"], describe=describe_schedule(settings["schedule"]),
                next=int(nxt) if nxt else None, last_slot=sc.get("last_slot"),
                last_attempt=sc.get("last_attempt"), last_ok=sc.get("last_ok"),
                last_result=sc.get("last_result"), last_error=sc.get("last_error"))


# ── integrity: SHA256SUMS inside + the archive's own sha256 ─────────────────
INTEGRITY_OK = ("verified", "no-manifest")


def format_sums(pairs):
    """sha256sum-compatible text for [(name, hexdigest)] (escaping like coreutils)."""
    lines = []
    for name, hexd in sorted(pairs):
        if "\\" in name or "\n" in name or "\r" in name:
            esc = name.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
            lines.append("\\%s  %s" % (hexd, esc))
        else:
            lines.append("%s  %s" % (hexd, name))
    return "\n".join(lines) + "\n"


def parse_sums(text):
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        escaped = line.startswith("\\")
        if escaped:
            line = line[1:]
        m = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
        if not m:
            raise ValueError("malformed SHA256SUMS line")
        name = m.group(2)
        if escaped:
            name = re.sub(r"\\(.)", lambda x: {"n": "\n", "r": "\r", "\\": "\\"}.get(x.group(1), x.group(0)), name)
        while name.startswith("./"):
            name = name[2:]
        out[name] = m.group(1).lower()
    return out


def _norm(name):
    name = name or ""
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def verify_members(path):
    """Decompress the whole archive (gzip CRC included) and check every
    regular file against SHA256SUMS. status: verified | damaged |
    no-manifest (older backups: readable, but nothing to compare with)."""
    hashes = {}
    sums_text = None
    count = total = 0
    try:
        with open(path, "rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                for m in tar:
                    count += 1
                    if count > MAX_MEMBERS:
                        raise ValueError("more than %d members" % MAX_MEMBERS)
                    name = _norm(m.name)
                    if m.islnk():
                        hashes[name] = hashes.get(_norm(m.linkname))
                        continue
                    if not m.isreg():
                        continue
                    total += m.size
                    if m.size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                        raise ValueError("archive exceeds the size limits")
                    f = tar.extractfile(m)
                    h = hashlib.sha256()
                    buf = b"" if name == MANIFEST_NAME else None
                    for chunk in iter(lambda: f.read(1048576), b""):
                        h.update(chunk)
                        if buf is not None and len(buf) < 16 * 1048576:
                            buf += chunk
                    if buf is not None:
                        sums_text = buf.decode("utf-8", errors="replace")
                    else:
                        hashes[name] = h.hexdigest()
            while gz.read(1048576):
                pass
    except Exception as exc:
        return {"status": "damaged", "files": len(hashes),
                "error": "The archive cannot be read to the end (%s: %s)" % (exc.__class__.__name__, str(exc)[:120])}
    if sums_text is None:
        return {"status": "no-manifest", "files": len(hashes)}
    try:
        sums = parse_sums(sums_text)
    except ValueError as exc:
        return {"status": "damaged", "files": len(hashes), "error": "SHA256SUMS is unreadable (%s)" % exc}
    bad = sorted(n for n in sums if n in hashes and hashes[n] != sums[n])
    missing = sorted(n for n in sums if n not in hashes)
    extra = sorted(n for n in hashes if n not in sums)
    res = {"status": "verified" if not (bad or missing or extra) else "damaged", "files": len(hashes),
           "nbad": len(bad), "nmissing": len(missing), "nextra": len(extra),
           "bad": bad[:20], "missing": missing[:20], "extra": extra[:20]}
    return res


def integrity_summary(res):
    if res.get("status") == "verified":
        return "all %d files match SHA256SUMS" % res.get("files", 0)
    if res.get("status") == "no-manifest":
        return "older backup without SHA256SUMS: readable, but its files cannot be checked"
    if res.get("error"):
        return res["error"]
    parts = []
    if res.get("nbad"):
        parts.append("%d file(s) differ from SHA256SUMS (%s)" % (res["nbad"], ", ".join(res["bad"][:3])))
    if res.get("nmissing"):
        parts.append("%d listed file(s) missing" % res["nmissing"])
    if res.get("nextra"):
        parts.append("%d unlisted file(s) added (%s)" % (res["nextra"], ", ".join(res["extra"][:3])))
    return "; ".join(parts) or "damaged"


def record_integrity(root, name, res, sha, size):
    def fn(s):
        recs = s.setdefault("archives", {})
        old = recs.get(name) or {}
        rec = {"status": res["status"], "checked": int(time.time()), "size": size, "files": res.get("files"),
               "sha256": old.get("sha256") or sha, "summary": integrity_summary(res)[:300]}
        if old.get("sha256") and old["sha256"] != sha:
            rec["seen_sha256"] = sha
        recs[name] = rec
    update_state(root, fn)


def check_integrity(root, name, path, force=False):
    """Integrity of a stored archive. The sha256 recorded when it was created
    (or first seen) must still match; otherwise or when forced, the members
    are re-checked against SHA256SUMS. Returns the result (+ sha256)."""
    sha = sha256_file(path)
    size = os.path.getsize(path)
    rec = (load_state(root).get("archives") or {}).get(name) or {}
    if rec.get("sha256") and rec["sha256"] != sha:
        res = verify_members(path)
        res.update(status="damaged", error="The archive changed after it was created (its sha256 no longer "
                                           "matches the one recorded then)")
        record_integrity(root, name, res, sha, size)
        return dict(res, sha256=sha, recorded_sha256=rec["sha256"])
    if not force and rec.get("status") in INTEGRITY_OK and rec.get("sha256") == sha:
        return {"status": rec["status"], "files": rec.get("files"), "sha256": sha, "cached": True,
                "checked": rec.get("checked")}
    res = verify_members(path)
    record_integrity(root, name, res, sha, size)
    return dict(res, sha256=sha, checked=int(time.time()))


def require_intact(root, name, path):
    res = check_integrity(root, name, path)
    if res["status"] == "damaged":
        raise Refused(409, {"ok": False, "damaged": True, "integrity": res["status"],
                            "error": "This backup is damaged (%s). Restore refused - use another backup."
                                     % integrity_summary(res)})
    return res


def forget_archive(root, name):
    update_state(root, lambda s: (s.get("archives") or {}).pop(name, None))


# ── encryption (OpenPGP symmetric via GnuPG) ────────────────────────────────
# AES-256, SHA-512 iterated+salted S2K, integrity-protected packets (MDC: gpg
# refuses to output a manipulated message). The passphrase goes to gpg over
# a pipe fd (never argv/env), gpg runs with a throwaway 0700 homedir and no
# agent cache. Local archives stay plaintext (root-only, next to the live
# config they mirror); everything that leaves the box is encrypted.
PASSPHRASE_MIN = 10
PASSPHRASE_MAX = 512
GPG_COMMON = ["--batch", "--yes", "--no-tty", "--quiet", "--pinentry-mode", "loopback", "--no-symkey-cache",
              "--no-permission-warning"]
GPG_ENCRYPT = ["--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
               "--s2k-count", "65011712", "--compress-algo", "none"]
GPG_TIMEOUT = 900


class DecryptError(ValueError):
    def __init__(self, kind, msg):
        ValueError.__init__(self, msg)
        self.kind = kind


def gpg_path():
    return shutil.which("gpg", path="/usr/bin:/bin:/usr/local/bin")


_gpg_version_cache = {}


def gpg_version(gpg=None):
    gpg = gpg or gpg_path()
    if not gpg:
        return None
    if gpg not in _gpg_version_cache:
        try:
            out = subprocess.run([gpg, "--version"], capture_output=True, text=True, timeout=10).stdout
            _gpg_version_cache[gpg] = out.splitlines()[0].strip() if out else None
        except Exception:
            return None
    return _gpg_version_cache[gpg]


def looks_encrypted(head):
    if head[:27] == b"-----BEGIN PGP MESSAGE-----":
        return True
    return bool(head) and head[0] in (0x8c, 0x8d, 0x8e, 0xc3)   # (old/new format) symmetric-key session packet


def validate_passphrase(pw):
    if not isinstance(pw, str):
        raise ValueError("Passphrase missing")
    if len(pw) < PASSPHRASE_MIN:
        raise ValueError("Use a passphrase of at least %d characters" % PASSPHRASE_MIN)
    if len(pw) > PASSPHRASE_MAX:
        raise ValueError("Passphrase too long")
    if any(ord(c) < 32 or ord(c) == 127 for c in pw):
        raise ValueError("The passphrase cannot contain control characters or line breaks")
    return pw


def read_passphrase(root=""):
    path = P(root, PASSPHRASE_FILE)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or (os.geteuid() == 0 and st.st_uid != 0):
            return None   # not root-only: ignore rather than use a possibly planted key
        with os.fdopen(fd, "rb") as f:
            fd = None
            pw = f.read(PASSPHRASE_MAX * 4 + 2).decode("utf-8", errors="strict").rstrip("\n")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        if fd is not None:
            os.close(fd)
    return pw or None


def encryption_info(root=""):
    path = P(root, PASSPHRASE_FILE)
    on = read_passphrase(root) is not None
    try:
        set_at = int(os.path.getmtime(path)) if on else None
    except OSError:
        set_at = None
    gpg = gpg_path()
    return {"enabled": on, "set_at": set_at, "available": bool(gpg),
            "tool": "GnuPG (OpenPGP symmetric, AES-256)", "version": gpg_version(gpg) if gpg else None,
            "file": PASSPHRASE_FILE}


def _gpg_home(root):
    base = _private_dir(P(root, WORK_DIR))
    return _private_dir(os.path.join(base, "gpg-" + secrets.token_hex(6)))


def _pass_pipe(passphrase):
    r, w = os.pipe()
    try:
        os.write(w, passphrase.encode("utf-8") + b"\n")
    finally:
        os.close(w)
    return r


def _gpg_env():
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}


def gpg_encrypt(root, src_path, out_file, passphrase, gpg=None):
    """Encrypt src_path into the open binary file out_file."""
    gpg = gpg or gpg_path()
    if not gpg:
        raise ValueError("gpg is not installed (apt install gnupg)")
    home = _gpg_home(root)
    r = _pass_pipe(passphrase)
    try:
        with open(src_path, "rb") as inp:
            p = subprocess.run([gpg, "--homedir", home] + GPG_COMMON + ["--passphrase-fd", str(r)] + GPG_ENCRYPT +
                               ["--output", "-"], stdin=inp, stdout=out_file, stderr=subprocess.PIPE,
                               pass_fds=(r,), timeout=GPG_TIMEOUT, env=_gpg_env())
        if p.returncode != 0:
            raise ValueError("Encryption failed (gpg exit %d)" % p.returncode)
        out_file.flush()
        os.fsync(out_file.fileno())
    finally:
        os.close(r)
        shutil.rmtree(home, ignore_errors=True)


def gpg_decrypt_stream(root, src_path, passphrase, sink, cap=None, gpg=None):
    """Decrypt src_path, feeding plaintext chunks to sink(bytes). The output
    is capped (a compressed packet cannot inflate past it). Raises
    DecryptError(kind=passphrase|damaged|format|limit)."""
    gpg = gpg or gpg_path()
    if not gpg:
        raise DecryptError("format", "gpg is not installed (apt install gnupg)")
    home = _gpg_home(root)
    r = _pass_pipe(passphrase)
    err = []
    try:
        p = subprocess.Popen([gpg, "--homedir", home] + GPG_COMMON + ["--passphrase-fd", str(r), "--decrypt",
                              "--output", "-", src_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             pass_fds=(r,), env=_gpg_env())
        os.close(r)
        r = None
        t = threading.Thread(target=lambda: err.append(p.stderr.read()), daemon=True)
        t.start()
        total = 0
        over = False
        try:
            for chunk in iter(lambda: p.stdout.read(1048576), b""):
                total += len(chunk)
                if cap is not None and total > cap:
                    over = True
                    p.kill()
                    break
                sink(chunk)
        finally:
            try:
                rc = p.wait(timeout=GPG_TIMEOUT)
            except subprocess.TimeoutExpired:
                p.kill()
                rc = p.wait()
            t.join(5)
            p.stdout.close()
        if over:
            raise DecryptError("limit", "The decrypted data is larger than allowed")
        if rc != 0:
            msg = (err[0] if err else b"").decode("utf-8", errors="replace")
            if "Bad session key" in msg or "bad passphrase" in msg.lower():
                raise DecryptError("passphrase", "Wrong passphrase")
            if "manipulated" in msg or "MDC" in msg or "CRC" in msg or "invalid packet" in msg:
                raise DecryptError("damaged", "The encrypted file is damaged or was modified")
            if "no valid OpenPGP data" in msg:
                raise DecryptError("format", "Not an OpenPGP-encrypted file")
            if "No secret key" in msg or "public key" in msg:
                raise DecryptError("format", "Encrypted to a key, not with a passphrase: not a TuxWall backup")
            raise DecryptError("format", "Decryption failed (gpg exit %d)" % rc)
    finally:
        if r is not None:
            os.close(r)
        shutil.rmtree(home, ignore_errors=True)


def set_passphrase(root, passphrase, who="", gpg=None):
    validate_passphrase(passphrase)
    gpg = gpg or gpg_path()
    if not gpg:
        raise ValueError("gpg is not installed (apt install gnupg)")
    fd, probe = mkstemp_private(root, prefix="probe-")
    enc = probe + ".gpg"
    try:
        sample = secrets.token_bytes(256)
        with os.fdopen(fd, "wb") as f:
            f.write(sample)
        with os.fdopen(os.open(enc, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as out:
            gpg_encrypt(root, probe, out, passphrase, gpg=gpg)
        got = []
        gpg_decrypt_stream(root, enc, passphrase, got.append, cap=4096, gpg=gpg)
        if b"".join(got) != sample:
            raise ValueError("Encryption self-test failed")
    finally:
        for p in (probe, enc):
            try:
                os.unlink(p)
            except OSError:
                pass
    existed = read_passphrase(root) is not None
    path = P(root, PASSPHRASE_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _write_private(path, passphrase.encode("utf-8"))
    audit(root, "encryption-change" if existed else "encryption-set", who=who)
    return encryption_info(root)


def clear_passphrase(root, who=""):
    try:
        os.unlink(P(root, PASSPHRASE_FILE))
        audit(root, "encryption-remove", who=who)
    except FileNotFoundError:
        pass
    return encryption_info(root)


def encrypted_copy(root, src_path, passphrase, gpg=None):
    """Private temp file holding src_path encrypted. Caller unlinks it."""
    fd, tmp = mkstemp_private(root, prefix="enc-", suffix=".gpg")
    try:
        with os.fdopen(fd, "wb") as out:
            gpg_encrypt(root, src_path, out, passphrase, gpg=gpg)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp


# ── USB copy (stick labelled TUXWALL-BACKUP) ────────────────────────────────
# Picked by filesystem label only (lsblk, blkid as fallback), never a disk
# that holds a system mount; re-probed (blkid -p) right before mounting;
# mounted nodev,nosuid,noexec at /mnt/tuxwall-backup; only files in
# tuxwall-backups/ that match our own names are ever written or deleted.
# Never formats anything.
USB_LABEL = "TUXWALL-BACKUP"
USB_MOUNT = "/mnt/tuxwall-backup"
USB_SUBDIR = "tuxwall-backups"
USB_KEEP = 10
USB_FSTYPES = ("ext4", "ext3", "ext2", "xfs", "btrfs", "vfat", "exfat")
USB_FAT = ("vfat", "exfat")
USB_TYPES = ("part", "disk", "loop")
USB_FILE_RE = re.compile(r"^system-backup-(\d{8})-(\d{6})\.tar\.gz(\.gpg)?$")
SYSTEM_MOUNTS = ("/", "/boot", "/boot/efi", "/usr", "/var", "/home", "/srv", "/opt", "/tmp", "[SWAP]")
LSBLK_COLS = "NAME,PATH,TYPE,LABEL,FSTYPE,SIZE,TRAN,RM,HOTPLUG,MODEL,VENDOR,MOUNTPOINTS,UUID"


def _flatten(devs, top=None, parent=None):
    for d in devs or []:
        d = dict(d)
        d["_top"] = top or d.get("name")
        d["_parent"] = parent
        yield d
        for c in _flatten(d.get("children"), d["_top"], d):
            yield c


def _mounts_of(d):
    mp = d.get("mountpoints")
    if mp is None and d.get("mountpoint"):
        mp = [d.get("mountpoint")]
    return [m for m in (mp or []) if m]


def usb_pick(lsblk, blkid_paths=()):
    """Pure: (device dict, error) for the one block device labelled
    TUXWALL-BACKUP that is safe to use; (None, None) when there is none."""
    devs = list(_flatten((lsblk or {}).get("blockdevices")))
    system_tops = {d["_top"] for d in devs if any(m in SYSTEM_MOUNTS for m in _mounts_of(d))}
    cands, notes = [], []
    for d in devs:
        if d.get("label") != USB_LABEL and d.get("path") not in blkid_paths:
            continue
        if d.get("type") not in USB_TYPES:
            notes.append("%s is a %s device" % (d.get("path"), d.get("type")))
            continue
        if d["_top"] in system_tops:
            notes.append("%s is on the system disk" % d.get("path"))
            continue
        cands.append(d)
    if not cands:
        return None, ("A device labelled %s was ignored: %s" % (USB_LABEL, "; ".join(notes))) if notes else None
    if len(cands) > 1:
        return None, ("Several devices are labelled %s (%s): attach only one"
                      % (USB_LABEL, ", ".join(c.get("path") or "?" for c in cands)))
    d = cands[0]
    if (d.get("fstype") or "") not in USB_FSTYPES:
        return None, "%s has an unsupported filesystem (%s); TuxWall never formats it" % (d.get("path"), d.get("fstype") or "none")
    tran = d.get("tran")
    p = d.get("_parent")
    while not tran and p:
        tran = p.get("tran")
        p = p.get("_parent")
    model = d.get("model") or ((d.get("_parent") or {}).get("model"))
    out = {"path": d.get("path"), "name": d.get("name"), "type": d.get("type"), "fstype": d.get("fstype"),
           "size": d.get("size"), "uuid": d.get("uuid"), "tran": tran or None,
           "model": (model or "").strip() or None, "mounts": _mounts_of(d)}
    return out, None


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def usb_detect():
    try:
        p = _run(["lsblk", "-J", "-b", "-o", LSBLK_COLS], timeout=15)
        data = json.loads(p.stdout or "{}") if p.returncode == 0 else {}
    except Exception:
        data = {}
    paths = ()
    try:
        b = _run(["blkid", "-c", "/dev/null", "-o", "device", "-t", "LABEL=" + USB_LABEL], timeout=20)
        paths = tuple(x.strip() for x in (b.stdout or "").splitlines() if x.strip())
    except Exception:
        pass
    return usb_pick(data, paths)


def _ext_free(dev):
    try:
        p = _run(["dumpe2fs", "-h", dev], timeout=15)
    except Exception:
        return None
    vals = {}
    for line in (p.stdout or "").splitlines():
        k, _, v = line.partition(":")
        vals[k.strip()] = v.strip()
    try:
        return int(vals["Free blocks"]) * int(vals["Block size"])
    except (KeyError, ValueError):
        return None


def usb_status(root="", detect=None):
    dev, err = (detect or usb_detect)()
    out = {"label": USB_LABEL, "mount": USB_MOUNT, "folder": USB_SUBDIR, "keep": USB_KEEP,
           "present": bool(dev), "error": err}
    if dev:
        out["device"] = dict(dev)
        if (dev.get("fstype") or "").startswith("ext"):
            out["device"]["free"] = _ext_free(dev["path"])
    st = load_state(root).get("usb") or {}
    for k in ("last_copy", "last_error", "last_check"):
        out[k] = st.get(k)
    return out


def _unoctal(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def _mounted_at(target):
    """(major:minor, source) of what is mounted at target, or None."""
    try:
        with open("/proc/self/mountinfo") as f:
            lines = f.readlines()
    except OSError:
        return None
    found = None
    for line in lines:
        parts = line.split()
        if len(parts) < 10 or _unoctal(parts[4]) != target:
            continue
        sep = parts.index("-") if "-" in parts else -1
        found = (parts[2], _unoctal(parts[sep + 2]) if sep > 0 and len(parts) > sep + 2 else "")
    return found


def _blkdev(path):
    real = os.path.realpath(path or "")
    if not real.startswith("/dev/"):
        raise Refused(409, {"ok": False, "error": "Unexpected device path"})
    st = os.stat(real)
    if not _stat.S_ISBLK(st.st_mode):
        raise Refused(409, {"ok": False, "error": "%s is not a block device" % real})
    return real, "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev))


def _usb_mount(root, dev, readonly=False):
    """Mount the stick; returns True if we mounted it (False: it already was)."""
    real, majmin = _blkdev(dev["path"])
    probe = _run(["blkid", "-p", "-o", "export", real], timeout=20)
    kv = dict(line.split("=", 1) for line in (probe.stdout or "").splitlines() if "=" in line)
    if kv.get("LABEL") != USB_LABEL or kv.get("TYPE") != dev.get("fstype"):
        raise Refused(409, {"ok": False, "error": "%s no longer carries the %s label; nothing was mounted"
                                                  % (real, USB_LABEL)})
    try:
        st = os.lstat(USB_MOUNT)
        if not _stat.S_ISDIR(st.st_mode):
            raise Refused(409, {"ok": False, "error": "%s is not a directory" % USB_MOUNT})
    except FileNotFoundError:
        os.makedirs(USB_MOUNT, mode=0o700)
    cur = _mounted_at(USB_MOUNT)
    if cur:
        if cur[0] == majmin or os.path.realpath(cur[1] or "x") == real:
            return False
        raise Refused(409, {"ok": False, "error": "Something else is mounted at %s (%s); unmount it first"
                                                  % (USB_MOUNT, cur[1] or cur[0])})
    if any(m != USB_MOUNT for m in dev.get("mounts") or []):
        raise Refused(409, {"ok": False, "error": "The stick is already mounted at %s; unmount it first"
                                                  % ", ".join(dev["mounts"])})
    opts = "nodev,nosuid,noexec,noatime" + (",ro" if readonly else "")
    if dev.get("fstype") in USB_FAT:
        opts += ",uid=0,gid=0,fmask=0177,dmask=0077"
    update_state(root, lambda s: s.setdefault("usb", {}).update(mounted_by_us=real))
    p = _run(["mount", "-t", dev["fstype"], "-o", opts, real, USB_MOUNT], timeout=60)
    if p.returncode != 0:
        update_state(root, lambda s: s.setdefault("usb", {}).pop("mounted_by_us", None))
        raise Refused(500, {"ok": False, "error": "Mounting %s failed: %s" % (real, (p.stderr or "").strip()[-200:])})
    return True


def _usb_umount(root):
    try:
        os.sync()
    except Exception:
        pass
    err = ""
    for i in range(4):
        p = _run(["umount", USB_MOUNT], timeout=60)
        if p.returncode == 0 or not _mounted_at(USB_MOUNT):
            update_state(root, lambda s: s.setdefault("usb", {}).pop("mounted_by_us", None))
            return None
        err = (p.stderr or "").strip()[-200:]
        time.sleep(1 + i)
    return "Could not unmount %s (%s); do not unplug the stick yet" % (USB_MOUNT, err)


def usb_cleanup(root=""):
    """After a crash/re-exec mid-copy: unmount what we mounted."""
    st = load_state(root).get("usb") or {}
    if st.get("mounted_by_us") and _mounted_at(USB_MOUNT):
        return _usb_umount(root)
    if st.get("mounted_by_us"):
        update_state(root, lambda s: s.setdefault("usb", {}).pop("mounted_by_us", None))
    return None


def _fresh_sha256(path):
    """sha256 of what is on the device, not the page cache."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            os.fsync(fd)
        except OSError:
            pass
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except (AttributeError, OSError):
            pass
        h = hashlib.sha256()
        with os.fdopen(fd, "rb") as f:
            fd = None
            for chunk in iter(lambda: f.read(1048576), b""):
                h.update(chunk)
        return h.hexdigest()
    finally:
        if fd is not None:
            os.close(fd)


def usb_plan_prune(names, keep=USB_KEEP):
    """Pure: which of our files on the stick to delete (oldest first)."""
    ours = sorted((n for n in names if USB_FILE_RE.match(n)),
                  key=lambda n: (USB_FILE_RE.match(n).group(1) + USB_FILE_RE.match(n).group(2), n), reverse=True)
    return sorted(ours[keep:])


def _usb_dir(base):
    d = os.path.join(base, USB_SUBDIR)
    try:
        st = os.lstat(d)
        if not _stat.S_ISDIR(st.st_mode):
            raise Refused(409, {"ok": False, "error": "%s on the stick is not a folder" % USB_SUBDIR})
    except FileNotFoundError:
        os.mkdir(d, 0o700)
    return d


def _usb_list(d):
    out = []
    for n in sorted(os.listdir(d)):
        if USB_FILE_RE.match(n):
            try:
                st = os.lstat(os.path.join(d, n))
            except OSError:
                continue
            if _stat.S_ISREG(st.st_mode):
                out.append({"name": n, "size": st.st_size, "time": int(st.st_mtime), "encrypted": n.endswith(".gpg")})
    return out


def _read_sidecar(path):
    try:
        with open(path + ".sha256") as f:
            m = re.match(r"^([0-9a-f]{64})\s", f.read(200))
            return m.group(1) if m else None
    except OSError:
        return None


def usb_copy_to(root, base, archive_path, archive_name, archive_sha, passphrase=None, gpg=None, keep=USB_KEEP):
    """Copy (encrypting if a passphrase is given) one archive into
    <base>/tuxwall-backups/, verify it on the medium, prune ours to keep.
    ``base`` is the mounted stick (a plain directory in tests)."""
    d = _usb_dir(base)
    target = archive_name + (".gpg" if passphrase else "")
    dst = os.path.join(d, target)
    enc_tmp = None
    result = {"file": target, "encrypted": bool(passphrase), "skipped": False}
    try:
        if os.path.lexists(dst):
            side = _read_sidecar(dst)
            if side and os.path.isfile(dst) and not os.path.islink(dst) and _fresh_sha256(dst) == side:
                result.update(skipped=True, sha256=side, verified=True)
        if not result["skipped"]:
            src = archive_path
            if passphrase:
                enc_tmp = encrypted_copy(root, archive_path, passphrase, gpg=gpg)
                src = enc_tmp
            want = sha256_file(src)
            need = os.path.getsize(src)
            vfs = os.statvfs(d)
            if vfs.f_bavail * vfs.f_frsize < need + 1048576:
                for n in usb_plan_prune(os.listdir(d), keep=max(1, keep - 1)):
                    for p in (os.path.join(d, n), os.path.join(d, n + ".sha256")):
                        try:
                            os.unlink(p)
                        except FileNotFoundError:
                            pass
                vfs = os.statvfs(d)
                if vfs.f_bavail * vfs.f_frsize < need + 1048576:
                    raise Refused(507, {"ok": False, "error": "Not enough free space on the stick (%d MB needed)"
                                                              % (need // 1048576 + 1)})
            part = os.path.join(d, ".%s.%s.partial" % (target, secrets.token_hex(4)))
            try:
                fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
                    shutil.copyfileobj(inp, out, 1048576)
                    out.flush()
                    os.fsync(out.fileno())
                got = _fresh_sha256(part)
                if got != want:
                    raise Refused(500, {"ok": False, "error": "The copy on the stick is damaged (sha256 mismatch "
                                                              "after writing); the stick may be failing"})
                if passphrase:
                    h = hashlib.sha256()
                    try:
                        gpg_decrypt_stream(root, part, passphrase, h.update, cap=MAX_TOTAL_BYTES, gpg=gpg)
                    except DecryptError as exc:
                        raise Refused(500, {"ok": False, "error": "The encrypted copy does not decrypt (%s)" % exc})
                    if h.hexdigest() != archive_sha:
                        raise Refused(500, {"ok": False, "error": "The encrypted copy does not decrypt to the backup"})
                os.replace(part, dst)
                part = None
            finally:
                if part:
                    try:
                        os.unlink(part)
                    except OSError:
                        pass
            _write_private(dst + ".sha256", "%s  %s\n" % (want, target))
            try:
                dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
                os.fsync(dfd)
                os.close(dfd)
            except OSError:
                pass
            result.update(sha256=want, verified=True)
    finally:
        if enc_tmp:
            try:
                os.unlink(enc_tmp)
            except OSError:
                pass
    pruned = []
    for n in usb_plan_prune(os.listdir(d), keep=keep):
        if n == target:
            continue
        for p in (os.path.join(d, n), os.path.join(d, n + ".sha256")):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
        pruned.append(n)
    vfs = os.statvfs(d)
    result.update(pruned=pruned, copies=len(_usb_list(d)), free=vfs.f_bavail * vfs.f_frsize,
                  total=vfs.f_blocks * vfs.f_frsize)
    return result


def latest_system_backup(root=""):
    names = sorted(n for n in os.listdir(P(root, SYSTEM_DIR)) if SYSTEM_RE.match(n)) \
        if os.path.isdir(P(root, SYSTEM_DIR)) else []
    return names[-1] if names else None


def usb_copy(root="", name=None, who="", trigger="manual", detect=None, gpg=None):
    """Copy the latest (or the named) system backup to the stick and verify
    it. Holds the job lock (no overlap with a backup run)."""
    def fail(msg, status=500, record=True, **extra):
        if record:   # "no stick attached" is not a failed copy
            rec = {"time": int(time.time()), "trigger": trigger, "who": who or "", "error": msg[:300]}
            update_state(root, lambda s: s.setdefault("usb", {}).update(last_error=rec))
        audit(root, "usb-copy", who=who, trigger=trigger, ok=False, error=msg[:200])
        raise Refused(status, dict({"ok": False, "error": msg}, **extra))

    lk = JobLock(root)
    if not lk.acquire():
        raise Refused(409, {"ok": False, "error": "A backup job is running; try again when it has finished"})
    try:
        dev, err = (detect or usb_detect)()
        if not dev:
            fail(err or "No USB stick labelled %s is attached" % USB_LABEL, 404, record=bool(err), absent=not err)
        name = name or latest_system_backup(root)
        if not name or not SYSTEM_RE.match(name):
            fail("There is no system backup to copy yet", 409)
        path = os.path.join(P(root, SYSTEM_DIR), name)
        if not os.path.isfile(path):
            fail("System backup not found", 404)
        integ = check_integrity(root, name, path)
        if integ["status"] == "damaged":
            fail("%s is damaged (%s); not copied" % (name, integrity_summary(integ)), 409)
        pw = read_passphrase(root)
        try:
            ours = _usb_mount(root, dev)
        except Refused as exc:
            fail(exc.payload.get("error") or "mount failed", exc.status)
        res = None
        error = None
        try:
            res = usb_copy_to(root, USB_MOUNT, path, name, integ["sha256"], passphrase=pw, gpg=gpg)
        except Refused as exc:
            error = (exc.payload.get("error"), exc.status)
        except Exception as exc:
            error = ("Copy to the stick failed: %s" % str(exc)[:200], 500)
        finally:
            um = _usb_umount(root) if ours else None
        if error:
            fail(error[0] + ((" (" + um + ")") if um else ""), error[1])
        rec = {"time": int(time.time()), "trigger": trigger, "who": who or "", "archive": name,
               "file": res["file"], "encrypted": res["encrypted"], "sha256": res["sha256"], "verified": True,
               "skipped": res["skipped"], "copies": res["copies"], "free": res["free"], "total": res["total"],
               "device": dev["path"], "model": dev.get("model"), "unmounted": um is None and ours,
               "integrity": integ["status"]}
        if um:
            rec["warning"] = um

        def fn(s):
            u = s.setdefault("usb", {})
            u["last_copy"] = rec
            u.pop("last_error", None)
        update_state(root, fn)
        audit(root, "usb-copy", who=who, trigger=trigger, ok=True, archive=name, file=res["file"],
              encrypted=res["encrypted"], skipped=res["skipped"] or None, pruned=len(res["pruned"]) or None)
        return dict(rec, ok=True, pruned=res["pruned"])
    finally:
        lk.release()


def usb_check(root="", detect=None):
    """Mount read-only, list our copies and verify each against its .sha256."""
    lk = JobLock(root)
    if not lk.acquire():
        raise Refused(409, {"ok": False, "error": "A backup job is running; try again when it has finished"})
    try:
        dev, err = (detect or usb_detect)()
        if not dev:
            raise Refused(404, {"ok": False, "absent": not err,
                                "error": err or "No USB stick labelled %s is attached" % USB_LABEL})
        ours = _usb_mount(root, dev, readonly=True)
        try:
            d = os.path.join(USB_MOUNT, USB_SUBDIR)
            files = []
            if os.path.isdir(d) and not os.path.islink(d):
                for f in _usb_list(d):
                    side = _read_sidecar(os.path.join(d, f["name"]))
                    if not side:
                        f["status"] = "unverified"
                    else:
                        f["status"] = "verified" if _fresh_sha256(os.path.join(d, f["name"])) == side else "damaged"
                    files.append(f)
            vfs = os.statvfs(USB_MOUNT)
            free, total = vfs.f_bavail * vfs.f_frsize, vfs.f_blocks * vfs.f_frsize
        finally:
            um = _usb_umount(root) if ours else None
        rec = {"time": int(time.time()), "device": dev["path"], "copies": len(files), "free": free, "total": total,
               "damaged": sum(1 for f in files if f["status"] == "damaged")}
        update_state(root, lambda s: s.setdefault("usb", {}).update(last_check=rec))
        audit(root, "usb-check", ok=True, copies=len(files), damaged=rec["damaged"] or None)
        return dict(rec, ok=True, files=files[::-1], warning=um)
    finally:
        lk.release()


def usb_failure_incident(root=""):
    """(title, detail) while the newest automatic USB copy failed, else None
    (a failed manual copy is shown to whoever clicked)."""
    u = load_state(root).get("usb") or {}
    err = u.get("last_error") or {}
    ok = u.get("last_copy") or {}
    if not err or err.get("trigger") != "scheduled" or (ok and ok.get("time", 0) >= err.get("time", 0)):
        return None
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(err.get("time") or 0))
    return ("USB backup copy failed",
            "The %s copy to the %s stick at %s failed: %s. Open System > Backups for details."
            % (err.get("trigger") or "manual", USB_LABEL, when, err.get("error") or "unknown error"))
