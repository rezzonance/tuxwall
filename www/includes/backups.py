"""TuxWall system backups: item catalog, retention, persisted job state,
sanitized export, archive limits and the hardened single-file restore
(preview diff, atomic write, safe permissions, pre-restore copies, audit log).

Every path goes through a ``root`` prefix ("" on the router) so
tools/backup_safety_check.py exercises all of it in a temp tree.

Layout under <root>/var/lib/tuxwall/backups/ (dir 0700 where created here):
  system/          archives: system-backup-*, sanitized-*, uploaded-* (0600)
  state.json       last run / last success / last failure / pinned (0600)
  audit.jsonl      who/what/when of every backup action, never contents (0600)
  pre-restore/<ts>/<path>   live file copies taken before a restore (0700/0600)
  .work/           private scratch (mkstemp) for include lists (0700)
"""
import difflib
import fnmatch
import hashlib
import io
import json
import os
import re
import secrets
import shutil
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

TOP_FILES = ("iptables-save.txt", "ip6tables-save.txt", "manifest.txt", "dpkg-selections.txt",
             "apt-manual.txt", "package-versions.txt", "restore.sh")
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
    return {"version": 1, "pinned": [], "last_run": None, "last_success": None, "last_failure": None}


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
    pinned = set(load_state(root).get("pinned") or ())
    for n in names:
        if not regex.match(n):
            continue
        try:
            st = os.stat(os.path.join(d, n))
        except OSError:
            continue
        out.append({"name": n, "size": st.st_size, "time": int(st.st_mtime), "pinned": n in pinned})
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
            except Exception as exc:
                res.update(ok=False, error="Archive check failed: %s" % exc)
        run.update(running=False, finished=int(time.time()), ok=res["ok"], result=res.get("result"),
                   error=res.get("error"), stderr_tail=res.get("stderr_tail", "")[-2000:],
                   size=res.get("size"))
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
    r"(^|/)auth\.json$", r"(^|/)llm\.json$", r"(^|/)opencode\.json\.bak",
    r"^etc/tuxwall/(internal-token|agent-token)$", r"(^|/)canary-token$", r"(^|/)api\.token$",
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
    with tarfile.open(src_path, "r:gz") as src, tarfile.open(fileobj=out_fileobj, mode="w:gz") as dst:
        for m in src:
            name = member_safe(m.name)
            if not name or name in buf_names:
                continue
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
            if not m.isreg() or m.name == "SANITIZED.txt":
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

def store_upload(root, raw, who=""):
    if not raw or len(raw) < 64:
        raise ValueError("Upload is empty")
    if len(raw) > UPLOAD_MAX_BYTES:
        raise ValueError("Upload is larger than %d MB" % (UPLOAD_MAX_BYTES // 1048576))
    if raw[:2] != b"\x1f\x8b":
        raise ValueError("Not a .tar.gz archive")
    d = P(root, SYSTEM_DIR)
    os.makedirs(d, exist_ok=True)
    name = "uploaded-" + time.strftime("%Y%m%d-%H%M%S") + ".tar.gz"
    tmp = os.path.join(d, ".%s.%s.partial" % (name, secrets.token_hex(4)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        info = check_archive(tmp, strict=True)
        files = contents(tmp)
        if not files:
            raise ValueError("No restorable TuxWall files in this archive")
        os.replace(tmp, os.path.join(d, name))
    except BaseException as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        audit(root, "upload", who=who, ok=False, error=str(exc)[:200], bytes=len(raw))
        raise
    prune_simple(root, UPLOADED_RE, UPLOADED_KEEP)
    audit(root, "upload", who=who, ok=True, archive=name, bytes=len(raw), members=info["members"])
    return {"ok": True, "name": name, "files": files, "members": info["members"], "total": info["total"]}


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
    out = {"ok": True, "archive": archive_name, "member": name, "target": "/" + name,
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
            d, trunc, total = _diff(old.decode("utf-8"), new.decode("utf-8"), name)
            out.update(diff=d, diff_truncated=trunc, diff_lines=total)
        elif out["kind"] == "new":
            d, trunc, total = _diff("", new.decode("utf-8"), name)
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
                f.write(new)
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
        except BaseException as exc:
            if tmp:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
            audit(root, "restore-file", who=who, client=client, archive=archive_name, member=name,
                  ok=False, error=str(exc)[:200])
            raise
        finally:
            os.close(dfd)
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
