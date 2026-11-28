#!/usr/bin/env python3
"""tuxwall.service sandbox: every path the dashboard API writes is writable.

  python3 tools/unit_paths_check.py              static checks (CI)
  sudo python3 tools/unit_paths_check.py --sandbox [--scratch DIR]
        also replays the firewall snapshot restore + 60 s rollback, a backup
        restore and an interface-assignment write inside real systemd
        sandboxes (systemd-run, ProtectSystem=full, RootDirectory= a scratch
        tree, so /etc/default/ufw etc. are fixture files): once with the
        unit's own ReadWritePaths (must fail like the VM did: EROFS on
        /etc/default/ufw.tuxwall-tmp) and once with the shipped drop-ins
        (must succeed). Nothing on the host's /etc or firewall is touched.

tuxwall.service runs with ProtectSystem=full: /usr, /boot, /efi and /etc
are read-only for the API and for everything it runs (ufw, netplan, the
tripwire CLI ...), except the ReadWritePaths of the unit and its drop-ins
(pkg/etc/systemd/system/tuxwall.service{,.d/*.conf}). The VM test found the
snapshot rollback writing /etc/default/ufw, which was not in the list, so an
unconfirmed restore could not roll itself back.

The API writes temp file + rename (or creates/deletes entries) in the
target's DIRECTORY, so a write site counts as covered only when a directory
entry covers it; single-file entries (/etc/hosts ...) only allow in-place
writes and do not count.

Checked statically:
- the effective ReadWritePaths (unit + drop-ins, systemd semantics) cover
  every write site in WRITES (the audit list, partly read from the modules'
  own constants: fw_snap.UFW_FILES, canary_egress.FILES, topology, kea_conf,
  fw_edit, backups, api_server) and every Backups catalog item;
- every /etc, /usr, /boot, /efi string literal in the API code (includes/, plugins,
  the tripwire CLI it runs) is either covered, read-only (READ_ONLY) or a
  documented gap (KNOWN_GAPS) - a new write target must be classified here;
- KNOWN_GAPS are really not covered (no stale entries);
- ProtectSystem=full / PrivateTmp=true still hold (the check's premise);
- systemd/ mirrors pkg/ for the unit and drop-ins; drop-ins are conffiles;
- backups._atomic_write turns EROFS/EBUSY into a clear 409 "sandbox" refusal.
"""
import ast
import errno
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INC = os.path.join(ROOT_DIR, "www", "includes")
sys.path.insert(0, INC)
UNIT_DIR = os.path.join(ROOT_DIR, "pkg", "etc", "systemd", "system")
UNIT = os.path.join(UNIT_DIR, "tuxwall.service")
DROPIN_DIR = UNIT + ".d"
MIRROR_DIR = os.path.join(ROOT_DIR, "systemd")
CONFFILES = os.path.join(ROOT_DIR, "pkg", "DEBIAN", "conffiles")
TRIPWIRE_CLI = os.path.join(ROOT_DIR, "pkg", "usr", "local", "sbin", "tuxwall-tripwire")

PROTECTED = ("/etc", "/usr", "/boot", "/efi")  # ProtectSystem=full

# Single-file entries of the unit: in-place writes only (no temp + rename).
FILE_ENTRIES = {"/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/hostname", "/etc/fstab"}

# ── the audit: write site -> path (directory writes: "dir:<path>") ─────────
# Module constants are resolved below; "api:NAME" = a module-level constant
# of api_server.py (read with ast, the module is not imported).
WRITES = [
    # firewall
    ("fw_snap._write_ufw_files: snapshot restore + 60 s rollback (all UFW_FILES)", "fw_snap.UFW_FILES"),
    ("api set_firewall_default: `ufw default` rewrites /etc/default/ufw", "/etc/default/ufw"),
    ("api ufw allow/delete/insert/enable/logging + ufw.backend move: /etc/ufw/user*.rules, ufw.conf",
     "dir:/etc/ufw"),
    ("canary_egress.apply: containment in before*.rules", "canary_egress.FILES"),
    ("fw_edit side state (disabled rules)", "fw_edit.DISABLED_FILE"),
    ("api save_firewall_baseline (legacy baseline dir)", "dir:api:FW_BASELINE_DIR"),
    # interface assignments (assign_apply._write: mkstemp in the target dir)
    ("assign: netplan files", "dir:topology.NETPLAN_DIR"),
    ("assign: kea", "topology.KEA_CONF"),
    ("assign: radvd (/etc/tuxwall/radvd.conf, read by radvd through its TuxWall drop-in)", "topology.RADVD_CONF"),
    ("assign: unbound conf.d", "dir:topology.UNBOUND_DIR"),
    ("assign: before.rules", "topology.UFW_BEFORE"),
    ("assign: user.rules/user6.rules", "topology.UFW_USER"),
    ("assign: tuxwall-nat drop-in", "dir:topology.NAT_DROPIN"),
    ("assign: avahi", "topology.AVAHI_CONF"),
    ("assign: suricata", "topology.SURICATA_CONF"),
    ("assign: sqm", "topology.SQM_CONF"),
    ("assign/topology.write: interfaces.json", "topology.CONF"),
    ("assign: vlans.json", "topology.VLAN_FILE"),
    ("assign_plan.run_validators: kea temp file", "dir:/etc/kea"),
    ("kea_conf.write", "kea_conf.KEA_CONF"),
    # backups
    ("backups settings", "backups.SETTINGS_FILE"),
    ("backups passphrase", "backups.PASSPHRASE_FILE"),
    ("backups restore (single / many / service): every catalog item", "backups.ITEMS"),
    # api_server
    ("api _write_kea / write_config(kea) + .bak copies", "api:KEA_CONF"),
    ("api domains", "api:DOMAINS_CONF_PATH"),
    ("api domains unbound include", "api:DOMAINS_INCLUDE"),
    ("api custom banlist", "api:CUSTOM_BLOCKLIST_FILE"),
    ("api community auto state", "api:COMMUNITY_AUTO_STATE"),
    ("api llm.json + .bak", "api:LLM_CONF_PATH"),
    ("api reporting.json", "api:REPORTING_CONF_FILE"),
    ("api WireGuard wg0.conf", "api:WG_CONF"),
    ("api WireGuard DNS access-control", "/etc/unbound/unbound.conf.d/90-wireguard-dns.conf"),
    ("api RPZ include", "api:RPZ_INCLUDE"),
    ("api RPZ feeds conf + .bak", "api:RPZ_FEEDS_CONF"),
    ("api ui.json", "api:UI_CONF_FILE"),
    ("api device monitoring: names/expected/local indicators/abuse.ch key (mkstemp in dir)",
     "dir:api:DEVICES_CONF_DIR"),
    ("api auth.json", "api:AUTH_FILE"),
    ("api internal token", "api:INTERNAL_TOKEN_FILE"),
    ("api agent api.token (mkstemp in dir)", "api:AGENT_API_TOKEN_FILE"),
    ("api opencode.json + .bak (mkstemp in dir; only without the 3.3.5 drop-in)", "api:OPENCODE_CONF"),
    ("api opencode.local.json + .bak (mkstemp in dir)", "api:OPENCODE_LOCAL_CONF"),
    ("api agent keys", "dir:api:AGENT_KEYS_DIR"),
    ("api baselines.json", "api:BASELINES_FILE"),
    ("api sqm.conf", "api:SQM_CONF"),
    ("api router-dns.conf + .bak", "api:UNBOUND_ROUTER_CONF"),
    ("api log-local-actions.conf", "api:UNBOUND_LOCAL_ACTIONS_CONF"),
    ("api rsyslog drop rule (best-effort self-heal; the postinst installs it)", "api:UNBOUND_RSYSLOG_RULE"),
    ("api portforward.json", "api:PF_PERSIST"),
    ("api dmz.json", "api:DMZ_PERSIST"),
    ("api vlans.json", "api:VLAN_PERSIST_FILE"),
    ("api VLAN netplan file", "/etc/netplan/99-tuxwall-vlans.yaml"),
    ("api plugins (install/update/remove/config)", "dir:api:PLUGINS_DIR"),
    ("api incidents.json", "api:INCIDENTS_FILE"),
    ("api alerts.json", "api:ALERT_CONFIG_FILE"),
    ("api _ensure_service_reload (legacy unit rewrite)", "api:TUXWALL_SERVICE_FILE"),
    ("tripwire CLI (run by the API): config/state", "dir:/etc/tuxwall"),
    # dashboard HTTPS (Settings -> Security -> HTTPS, interface Apply hook)
    ("https_tls: CA + server certificate (work dir + rename inside it), lock", "dir:/etc/tuxwall/tls"),
    ("https_tls: settings", "/etc/tuxwall/https.json"),
    ("https_tls: nginx snippet (temp + rename, .tuxwall-prev backup)", "dir:/etc/nginx/snippets"),
]

# Backups catalog: which items are single files (restored by temp + rename
# in the parent directory) and which are directories. A new catalog item
# must be added to one of these.
BACKUP_FILE_ITEMS = {"/etc/radvd.conf", "/etc/apt/sources.list", "/etc/hosts", "/etc/hostname", "/etc/fstab",
                     "/etc/hosts.allow", "/etc/hosts.deny", "/etc/default/ufw", "/etc/nftables.conf",
                     "/etc/systemd/resolved.conf"}
BACKUP_DIR_ITEMS = {"/etc/netplan", "/etc/systemd/network", "/etc/kea", "/etc/unbound", "/etc/ufw", "/etc/nginx",
                    "/etc/systemd/system", "/etc/sysctl.d", "/etc/wireguard", "/etc/cloudflared", "/etc/tuxwall",
                    "/etc/crowdsec", "/etc/apt/sources.list.d", "/usr/local/bin", "/usr/local/sbin",
                    "/var/www/html", "/etc/ssh", "/etc/letsencrypt", "/etc/suricata", "/etc/opencanaryd",
                    "/etc/chrony", "/etc/sudoers.d", "/etc/cron.d", "/etc/networkd-dispatcher",
                    "/etc/modules-load.d", "/var/lib/tuxwall", "/var/lib/kea"}

# Deliberately NOT writable. A temp file directly in /etc (or /etc/systemd)
# would need all of /etc writable; single-file binds also go stale when the
# host replaces the file by rename. backups restore refuses these with
# backups.SANDBOX_MSG (restore from a root shell instead).
_RESTORE_GAP = "backups restore: file directly in a read-only dir; refused with SANDBOX_MSG"
KNOWN_GAPS = {
    "/etc/hosts": _RESTORE_GAP,
    "/etc/hostname": _RESTORE_GAP,
    "/etc/fstab": _RESTORE_GAP,
    "/etc/hosts.allow": _RESTORE_GAP,
    "/etc/hosts.deny": _RESTORE_GAP,
    "/etc/nftables.conf": _RESTORE_GAP,
    "/etc/systemd/resolved.conf": _RESTORE_GAP,
    # the stock path: radvd reads topology.RADVD_CONF (/etc/tuxwall) once the
    # postinst installed the radvd.service drop-in; still the restore target
    # of old archives and of boxes the migration skipped
    "/etc/radvd.conf": _RESTORE_GAP,
    "/etc/rsyslog.d/45-tuxwall-unbound.conf": "postinst-owned since 3.3.5 (rsyslog_unbound_rule); the API "
                                              "re-creates it only after a delete, and under the sandbox "
                                              "that write fails - skipped quietly, logged once",
    # Zeek checksum switch (3.3.7): the API runs zeek-site-setup.sh, which
    # edits the site dir of the Zeek install it finds. The binary packages'
    # /opt/zeek is writable under ProtectSystem=full; source/distro layouts
    # under /usr are not - the job fails with the script's message and the
    # script still works from a root shell
    "/usr/local/zeek/share/zeek/site": "Zeek checksum switch: a Zeek under /usr is read-only in the sandbox; "
                                       "the job reports the error (run zeek-site-setup.sh as root instead)",
    "/usr/share/zeek/site": "Zeek checksum switch: a Zeek under /usr is read-only in the sandbox; "
                            "the job reports the error (run zeek-site-setup.sh as root instead)",
}

# /etc, /usr, /boot literals in the API code that are only read (or are
# PATH strings / mount points / binaries it executes).
READ_ONLY = {
    "/etc/aide/aide.conf", "/etc/cron.daily/dailyaidecheck", "/etc/os-release", "/etc/passwd",
    "/etc/resolv.conf", "/etc/chrony/chrony.conf",
    "/boot", "/boot/efi", "/usr",
    "/usr/bin/aide", "/usr/bin/avahi-browse", "/usr/bin/cscli", "/usr/bin/dig", "/usr/bin/fastfetch",
    "/usr/bin/ssh", "/usr/bin/sshpass", "/usr/sbin/nft", "/usr/sbin/ip", "/usr/share/ieee-data/oui.csv",
    "/usr/share/ieee-data/oui.txt",  # devicewatch.py vendor lookup (the engine's own unit, read-only)
    "/usr/bin:/bin", "/usr/bin:/bin:/usr/local/bin", "/usr/sbin:/usr/bin:/sbin:/bin",
    "/usr/lib/systemd/system/tuxwall-agent.service.d/20-local-config.conf",
    "/usr/local/share/tuxwall/scripts/zeek-site-setup.sh",  # executed by the Zeek checksum switch
    "/etc",  # https_tls._path_ok: an owner-provided certificate must live under /etc (prefix test only)
}

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


# ── unit parsing ─────────────────────────────────────────────────────────────

def unit_lines(path):
    """[(key, value)] of the [Service] section, continuation lines joined."""
    out, sect, buf = [], None, ""
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            if buf:
                line = buf + line.lstrip()
                buf = ""
            if line.endswith("\\"):
                buf = line[:-1] + " "
                continue
            s = line.strip()
            if not s or s[0] in "#;":
                continue
            if s.startswith("["):
                sect = s.strip("[]")
                continue
            if sect == "Service" and "=" in s:
                k, v = s.split("=", 1)
                out.append((k.strip(), v.strip()))
    return out


def effective(unit, dropins):
    """systemd semantics: list settings accumulate, an empty assignment
    resets; drop-ins apply in file-name order after the unit."""
    rw, other = [], {}
    for p in [unit] + sorted(dropins, key=os.path.basename):
        for k, v in unit_lines(p):
            if k == "ReadWritePaths":
                if not v:
                    rw = []
                    continue
                rw += v.split()
            else:
                other[k] = v
    entries = []
    for e in rw:
        opt = e.startswith("-")
        entries.append((opt, e.lstrip("-+").rstrip("/") or "/"))
    return entries, other


def make_cover(entries):
    dirs = [p for _o, p in entries if p not in FILE_ENTRIES]

    def under(path):
        return any(path == d or path.startswith(d + "/") for d in dirs)

    def protected(path):
        return any(path == p or path.startswith(p + "/") for p in PROTECTED)

    def covered(path, is_dir=False):
        """A file: its directory must be writable (temp + rename); a
        directory: itself (entries are created / removed in it)."""
        if not protected(path):
            return True
        return under(path) if is_dir else under(os.path.dirname(path))
    return covered


# ── resolving the audit list ─────────────────────────────────────────────────

def api_constants():
    src = open(os.path.join(INC, "api_server.py")).read()
    tree = ast.parse(src)
    env = {}

    def ev(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.Name):
            return env.get(n.id)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            a, b = ev(n.left), ev(n.right)
            return a + b if a is not None and b is not None else None
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "join"
                and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "path"):
            parts = [ev(a) for a in n.args]
            return os.path.join(*parts) if parts and None not in parts else None
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            v = ev(node.value)
            if v is not None:
                env[node.targets[0].id] = v
    return env


def resolve(spec, api):
    """spec -> [(path, is_dir)]"""
    is_dir = spec.startswith("dir:")
    if is_dir:
        spec = spec[4:]
    if spec.startswith("api:"):
        name = spec[4:]
        if name not in api:
            raise KeyError("api_server.py has no module constant %s" % name)
        return [(api[name], is_dir)]
    if spec.startswith("/"):
        return [(spec, is_dir)]
    mod, attr = spec.split(".", 1)
    m = __import__(mod)
    v = getattr(m, attr)
    if attr == "ITEMS":
        out = []
        for it in v:
            p = it["path"]
            if p in BACKUP_FILE_ITEMS:
                out.append((p, False))
            elif p in BACKUP_DIR_ITEMS:
                out.append((p, True))
            else:
                raise KeyError("backups catalog item %s is not classified in BACKUP_FILE_ITEMS / "
                               "BACKUP_DIR_ITEMS" % p)
        return out
    if isinstance(v, dict):
        v = list(v.values())
    if isinstance(v, (list, tuple)):
        return [(p, is_dir) for p in v]
    return [(v, is_dir)]


def code_literals():
    """{path: [file, ...]} of /etc, /usr, /boot, /efi string literals."""
    files = (sorted(glob.glob(os.path.join(INC, "*.py"))) + [TRIPWIRE_CLI]
             + sorted(glob.glob(os.path.join(ROOT_DIR, "plugins", "*", "main.py"))))
    out = {}
    for fp in files:
        try:
            tree = ast.parse(open(fp).read())
        except SyntaxError as exc:
            check(False, "parse %s: %s" % (fp, exc))
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                s = n.value
                if any(s == p or s.startswith(p + "/") for p in PROTECTED) and "\n" not in s and " " not in s:
                    out.setdefault(s.rstrip("/") or "/", []).append(os.path.basename(fp))
    return out


# ── static checks ────────────────────────────────────────────────────────────

def t_static():
    dropins = sorted(glob.glob(os.path.join(DROPIN_DIR, "*.conf")))
    check(dropins, "tuxwall.service.d drop-ins shipped")
    entries, other = effective(UNIT, dropins)
    check(other.get("ProtectSystem") == "full",
          "ProtectSystem=full (this check models 'full'; update PROTECTED if it changes): %r"
          % other.get("ProtectSystem"))
    check(other.get("PrivateTmp") in ("true", "yes"), "PrivateTmp=true")
    paths = [p for _o, p in entries]
    check(len(paths) == len(set(paths)), "no duplicate ReadWritePaths: %s"
          % sorted(p for p in set(paths) if paths.count(p) > 1))
    check(all(p.startswith("/") and p != "/etc" and p != "/usr" for p in paths),
          "no relative path, no whole /etc or /usr: %s" % paths)
    base, _ = effective(UNIT, [])
    for opt, p in entries:
        if (opt, p) not in base:
            check(opt, "new entry %s is optional ('-' prefix: a missing path must not stop the unit)" % p)
    covered = make_cover(entries)

    api = api_constants()
    seen = {}
    for why, spec in WRITES:
        try:
            targets = resolve(spec, api)
        except (KeyError, AttributeError, ImportError) as exc:
            check(False, "resolve %s (%s): %s" % (spec, why, exc))
            continue
        for path, is_dir in targets:
            seen[path] = why
            if path in KNOWN_GAPS:
                continue
            check(covered(path, is_dir), "%s -> %s is writable under the sandbox" % (why, path))
    check("/etc/default/ufw" in seen and covered("/etc/default/ufw"),
          "/etc/default/ufw (snapshot rollback) is writable")

    for path, reason in KNOWN_GAPS.items():
        check(reason, "gap %s has a reason" % path)
        check(not covered(path), "known gap %s is now covered: drop it from KNOWN_GAPS" % path)

    lits = code_literals()
    for path, where in sorted(lits.items()):
        ok = (path in READ_ONLY or path in KNOWN_GAPS or path in seen
              or covered(path) or covered(path, is_dir=True))
        check(ok, "unclassified path literal %s (%s): writable dir, READ_ONLY or KNOWN_GAPS?"
              % (path, ", ".join(sorted(set(where)))))
    for path in READ_ONLY:
        check(path in lits, "READ_ONLY %s no longer appears in the code: drop it" % path)

    # mirror + packaging
    for p in [UNIT] + dropins:
        rel = os.path.relpath(p, UNIT_DIR)
        m = os.path.join(MIRROR_DIR, rel)
        check(os.path.isfile(m) and open(m).read() == open(p).read(), "systemd/%s mirrors pkg" % rel)
    mirror_dropins = sorted(os.path.basename(p) for p in glob.glob(os.path.join(MIRROR_DIR, "tuxwall.service.d", "*")))
    check(mirror_dropins == [os.path.basename(p) for p in dropins], "systemd/tuxwall.service.d has no extra files")
    conf = open(CONFFILES).read().split()
    for p in dropins:
        check("/" + os.path.relpath(p, os.path.join(ROOT_DIR, "pkg")) in conf, "%s listed in conffiles" % p)


def t_restore_refusal():
    import backups as B
    real = B._atomic_write_at
    try:
        for code in (errno.EROFS, errno.EBUSY):
            def boom(*_a, code=code):
                raise OSError(code, os.strerror(code))
            B._atomic_write_at = boom
            try:
                B._atomic_write("", "etc/hosts", b"x", 0o644, 0, 0)
                check(False, "errno %d -> Refused" % code)
            except B.Refused as exc:
                check(exc.status == 409 and exc.payload.get("sandbox")
                      and "/etc/hosts cannot be written by the dashboard" in exc.payload["error"]
                      and "tar -xzf <archive> -C / etc/hosts" in exc.payload["error"],
                      "errno %d -> clear sandbox refusal" % code)

        def other(*_a):
            raise OSError(errno.ENOSPC, "full")
        B._atomic_write_at = other
        try:
            B._atomic_write("", "etc/kea/x", b"x", 0o644, 0, 0)
            check(False, "ENOSPC passes through")
        except B.Refused:
            check(False, "ENOSPC passes through (not a sandbox refusal)")
        except OSError as exc:
            check(exc.errno == errno.ENOSPC, "ENOSPC passes through")
    finally:
        B._atomic_write_at = real


# ── --sandbox: replay under real systemd sandboxes ──────────────────────────

INNER = r'''
import errno, json, os, shutil, sys
sys.dont_write_bytecode = True
sys.path.insert(0, "/opt/tw/tools")
import firewall_safety_check as F
S, G = F.S, F.G
sys.path.insert(0, "/opt/tw/www/includes")
import backups as B
import assign_apply as A

res = {}
def err(exc):
    return {"ok": False, "errno": getattr(exc, "errno", None), "error": str(exc)[:300],
            "sandbox": bool(getattr(exc, "payload", {}).get("sandbox"))}

# 1. the VM repro: snapshot, change, restore (forward), no confirm -> revert
ctx, run = F.mkctx("")
m_old = S.create(ctx, note="old", kind="manual", who="t", version="test")
for n in ("user.rules", "user6.rules", "before.rules", "before6.rules"):
    shutil.copy("/opt/tw/cur/" + n, "/etc/ufw/" + n)
before = {k: open(p).read() for k, p in S.UFW_FILES.items()}
sched = {}
try:
    r = S.restore(ctx, m_old["id"], who="t", reapply=[("noop", lambda: None)],
                  schedule=lambda cid, d, fn, ttl: sched.setdefault(cid, fn))
    res["forward"] = {"ok": bool(r.get("ok")), "needs_confirmation": bool(r.get("needs_confirmation")),
                      "wrote_default": "ufw.default" in (r.get("plan") or {}).get("writes", [])}
except Exception as exc:
    res["forward"] = err(exc)
if sched:
    try:
        list(sched.values())[0]()
        now = {k: open(p).read() for k, p in S.UFW_FILES.items()}
        res["revert"] = {"ok": now == before}
    except Exception as exc:
        res["revert"] = err(exc)
res["tmp_left"] = os.path.exists("/etc/default/ufw.tuxwall-tmp")

# 2. `ufw default` (ufw.util.close_files: shutil.copy over the file, in place)
try:
    shutil.copy("/etc/default/ufw", "/tmp/ufw.copy")
    shutil.copy("/tmp/ufw.copy", "/etc/default/ufw")
    res["ufw_default"] = {"ok": True}
except Exception as exc:
    res["ufw_default"] = err(exc)

# 3. backups restore: a directory item and a file directly in /etc
for key, name in (("restore_ssh", "etc/ssh/sshd_config"), ("restore_hosts", "etc/hosts")):
    try:
        B._atomic_write("", name, b"# restored\n", 0o644, 0, 0)
        res[key] = {"ok": open("/" + name).read() == "# restored\n"}
    except Exception as exc:
        res[key] = err(exc)

# 4. interface assignments: suricata (new dir entry), radvd (its TuxWall path;
#    the stock /etc/radvd.conf stays read-only)
for key, path in (("assign_suricata", "/etc/suricata/suricata.yaml"), ("assign_radvd", "/etc/tuxwall/radvd.conf"),
                  ("assign_radvd_legacy", "/etc/radvd.conf")):
    try:
        A._write(path, "# assigned\n", 0o644)
        res[key] = {"ok": True}
    except Exception as exc:
        res[key] = err(exc)

# 5. still read-only
for key, path in (("etc_root", "/etc/.tuxwall-rwtest"), ("etc_rsyslog", "/etc/rsyslog.d/.tuxwall-rwtest"),
                  ("boot", "/boot/.tuxwall-rwtest"), ("usr_bin", "/usr/bin/.tuxwall-rwtest")):
    try:
        open(path, "w").close()
        os.unlink(path)
        res[key] = {"ok": True}
    except Exception as exc:
        res[key] = err(exc)
print("RESULT " + json.dumps(res, sort_keys=True))
'''


def _build_rootfs(scratch, entries):
    import firewall_safety_check as F
    rootfs = os.path.join(scratch, "rootfs")
    os.makedirs(rootfs)
    for d in ("usr/bin", "usr/sbin", "usr/lib", "usr/lib64", "usr/share", "usr/local/bin", "usr/local/sbin",
              "proc", "sys", "dev", "run", "tmp", "var/tmp", "boot", "opt/tw/cur", "etc/rsyslog.d",
              "etc/ssh", "etc/suricata"):
        os.makedirs(os.path.join(rootfs, d), exist_ok=True)
    for name, target in (("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        os.symlink(target, os.path.join(rootfs, name))
    # the VM's state: old snapshot target + current rules (firewall_safety_check fixtures)
    old_specs = [s for s in F.BASE_SPECS if "canary" not in s.get("comment", "")
                 and s.get("dport") != 445 and "policy" not in s.get("comment", "")] + [
        {"in": F.LAN, "proto": "tcp", "dport": 8080, "comment": "old user rule"}]
    old = F.make_root(specs=old_specs, before=F.BEFORE_OLD)
    cur = F.make_root(specs=F.BASE_SPECS + [{"in": F.LAN, "proto": "tcp", "dport": 9000, "comment": "new"}])
    shutil.copytree(old, rootfs, dirs_exist_ok=True, symlinks=True)
    for n in ("user.rules", "user6.rules", "before.rules", "before6.rules"):
        shutil.copy(os.path.join(cur, "etc/ufw", n), os.path.join(rootfs, "opt/tw/cur", n))
    shutil.rmtree(old)
    shutil.rmtree(cur)
    for p, text in (("etc/ssh/sshd_config", "Port 22\n"), ("etc/suricata/suricata.yaml", "%YAML 1.1\n"),
                    ("etc/hosts", "127.0.0.1 localhost\n"), ("etc/radvd.conf", "# radvd\n")):
        with open(os.path.join(rootfs, p), "w") as f:
            f.write(text)
    # every non-optional unit entry must exist or the namespace setup fails
    for opt, p in entries:
        full = rootfs + p
        if opt or os.path.lexists(full):
            continue
        if p in FILE_ENTRIES:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
        else:
            os.makedirs(full, exist_ok=True)
    shutil.copytree(INC, os.path.join(rootfs, "opt/tw/www/includes"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pre-*", "*.bak*"))
    os.makedirs(os.path.join(rootfs, "opt/tw/tools"))
    shutil.copy(os.path.join(ROOT_DIR, "tools", "firewall_safety_check.py"), os.path.join(rootfs, "opt/tw/tools"))
    with open(os.path.join(rootfs, "opt/tw/inner.py"), "w") as f:
        f.write(INNER)
    return rootfs


def _run_sandbox(scratch, entries, label):
    rootfs = _build_rootfs(os.path.join(scratch, label), entries)
    # "+" = relative to RootDirectory (the scratch tree), "-" = optional
    rw = " ".join(("-+" if o else "+") + p for o, p in entries)
    cmd = ["systemd-run", "--wait", "--pipe", "--collect", "--quiet",
           "-p", "RootDirectory=" + rootfs, "-p", "MountAPIVFS=yes",
           "-p", "ProtectSystem=full", "-p", "PrivateTmp=yes", "-p", "NoNewPrivileges=yes",
           "-p", "BindReadOnlyPaths=/usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/share",
           "-p", "ReadWritePaths=" + rw,
           "-p", "Environment=PYTHONDONTWRITEBYTECODE=1",
           "/usr/bin/python3", "/opt/tw/inner.py"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    line = [ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
    if not line:
        print(p.stdout[-2000:], p.stderr[-2000:])
        check(False, "%s: sandbox run produced a result (rc %d)" % (label, p.returncode))
        return {}
    res = json.loads(line[-1][7:])
    print("%s: ReadWritePaths=%s" % (label, rw))
    for k in sorted(res):
        print("  %-16s %s" % (k, json.dumps(res[k], sort_keys=True)))
    return res


def t_sandbox(scratch):
    dropins = sorted(glob.glob(os.path.join(DROPIN_DIR, "*.conf")))
    unit_only, _ = effective(UNIT, [])
    full, _ = effective(UNIT, dropins)
    a = _run_sandbox(scratch, unit_only, "unit-only")
    b = _run_sandbox(scratch, full, "with-drop-ins")
    if not (a and b):
        return
    ro = lambda r: (not r.get("ok")) and r.get("errno") == errno.EROFS  # noqa: E731
    # without the drop-in: exactly the VM failure
    check(a["forward"].get("ok") and a["forward"].get("needs_confirmation") and not a["forward"].get("wrote_default"),
          "unit-only: forward restore works (writes only changed /etc/ufw files)")
    check(ro(a["revert"]) and "/etc/default/ufw.tuxwall-tmp" in a["revert"]["error"],
          "unit-only: rollback fails with EROFS on /etc/default/ufw.tuxwall-tmp (the VM finding)")
    check(ro(a["ufw_default"]), "unit-only: `ufw default` cannot write /etc/default/ufw")
    check(not a["restore_ssh"].get("ok") and a["restore_ssh"].get("sandbox"),
          "unit-only: /etc/ssh restore refused as sandbox")
    check(ro(a["assign_suricata"]), "unit-only: suricata.yaml not writable")
    # with the drop-ins: fixed
    check(b["forward"].get("ok") and b["forward"].get("needs_confirmation"), "drop-ins: forward restore works")
    check(b["revert"].get("ok") is True, "drop-ins: 60 s rollback restores every ufw file incl. /etc/default/ufw")
    check(not b["tmp_left"], "drop-ins: no ufw.tuxwall-tmp left behind")
    check(b["ufw_default"].get("ok") is True, "drop-ins: `ufw default` can write /etc/default/ufw")
    check(b["restore_ssh"].get("ok") is True, "drop-ins: /etc/ssh restore works")
    check(b["assign_suricata"].get("ok") is True, "drop-ins: suricata.yaml writable")
    for r, label in ((a, "unit-only"), (b, "drop-ins")):
        check(not r["restore_hosts"].get("ok") and r["restore_hosts"].get("sandbox"),
              "%s: /etc/hosts restore refused with the sandbox message" % label)
        check(r["assign_radvd"].get("ok") is True, "%s: /etc/tuxwall/radvd.conf writable (radvd drop-in path)" % label)
        check(ro(r["assign_radvd_legacy"]), "%s: stock /etc/radvd.conf stays read-only" % label)
        for k in ("etc_root", "etc_rsyslog", "boot", "usr_bin"):
            check(ro(r[k]), "%s: %s stays read-only" % (label, k))


def main():
    t_static()
    t_restore_refusal()
    if "--sandbox" in sys.argv:
        if os.geteuid() != 0 or not shutil.which("systemd-run"):
            print("--sandbox needs root and systemd-run")
            sys.exit(2)
        if "--scratch" in sys.argv:
            base = sys.argv[sys.argv.index("--scratch") + 1]
            os.makedirs(base, exist_ok=True)
            scratch = tempfile.mkdtemp(prefix="twrw-", dir=base)
        else:
            scratch = tempfile.mkdtemp(prefix="twrw-")
        try:
            t_sandbox(scratch)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
    print("unit_paths_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
