#!/usr/bin/env python3
"""Package maintainer-script decisions (pkg/DEBIAN/postinst, prerm), sandboxed:

  python3 tools/pkg_scripts_check.py

The postinst functions are cut out of the script and run with bash against
a fake `systemctl` (first in PATH, records its calls) and a temp marker:

- tripwire_unit_setup: the unit is enabled ONCE by the package (marker
  /var/lib/tuxwall/.tripwire-enabled-once), whatever tripwire.json holds -
  incl. a legacy v1 config without an enabled unit (VM test B, finding 3);
  an already enabled unit is only marked; once marked, a unit the owner
  disabled is never re-enabled; a failed enable leaves no marker.
- bouncer_migration: runs the nftables migration helper on upgrades only
  (previous version set), never fails the postinst.
- prerm remove: forgets the marker when it disables an enabled unit, keeps
  it when the owner had disabled the unit.
- radvd_migration: /etc/radvd.conf -> /etc/tuxwall/radvd.conf + drop-in;
  local scripts writing /etc/radvd.conf block it, path-aware ones (drop-in
  -> /etc/tuxwall/radvd.conf) and backup copies do not.
- kea_hook_migration (finding 8.2): adds the lease_cmds hook to an
  installer-written Kea config (header kept, kea-dhcp4 -t first, restart,
  rollback), idempotent; skips foreign configs / missing library.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTINST = os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postinst")
PRERM = os.path.join(ROOT_DIR, "pkg", "DEBIAN", "prerm")

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


SRC = open(POSTINST).read()


def func(name):
    m = re.search(r"^%s\(\) \{.*?^\}\n" % re.escape(name), SRC, re.M | re.S)
    return m.group(0) if m else ""


FAKE = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$1" in
  is-enabled) [ "$FAKE_ENABLED" = yes ] && exit 0; exit 1 ;;
  enable) exit "${FAKE_ENABLE_RC:-0}" ;;
esac
exit 0
"""


def sandbox():
    d = tempfile.mkdtemp(prefix="pkg-scripts-")
    os.makedirs(d + "/bin")
    with open(d + "/bin/systemctl", "w") as f:
        f.write(FAKE)
    os.chmod(d + "/bin/systemctl", 0o755)
    return d


def run(d, script, enabled="no", enable_rc=0, args=()):
    env = dict(os.environ, PATH=d + "/bin:" + os.environ.get("PATH", ""), FAKE_LOG=d + "/calls",
               FAKE_ENABLED=enabled, FAKE_ENABLE_RC=str(enable_rc))
    if os.path.exists(d + "/calls"):
        os.unlink(d + "/calls")
    p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script, "x"] + list(args), env=env,
                       capture_output=True, text=True, timeout=30)
    calls = open(d + "/calls").read().splitlines() if os.path.exists(d + "/calls") else []
    return p.returncode, calls, p.stdout + p.stderr


def t_tripwire():
    fns = func("tripwire_unit_action") + func("tripwire_unit_setup")
    check("tripwire_unit_action" in fns and "tripwire_unit_setup" in fns, "postinst defines the tripwire functions")
    check("tripwire.json" not in fns, "decision does not depend on tripwire.json")
    for marker, en, want in (("no", "no", "enable"), ("no", "yes", "mark"), ("yes", "no", "restart"),
                             ("yes", "yes", "restart")):
        d = sandbox()
        try:
            m = d + "/marker"
            if marker == "yes":
                open(m, "w").close()
            rc, calls, out = run(d, fns + 'tripwire_unit_action "%s" %s' % (m, en))
            check(rc == 0 and out.strip() == want, "action marker=%s enabled=%s -> %s (%r)" % (marker, en, want, out))
        finally:
            shutil.rmtree(d)
    cases = [
        # (name, marker exists, enabled now, enable rc, legacy v1 config, expect calls, expect marker after)
        ("fresh install", False, "no", 0, False,
         ["is-enabled --quiet tuxwall-tripwire.service", "enable tuxwall-tripwire.service",
          "restart tuxwall-tripwire.service"], True),
        ("legacy v1 tripwire.json, unit never enabled", False, "no", 0, True,
         ["is-enabled --quiet tuxwall-tripwire.service", "enable tuxwall-tripwire.service",
          "restart tuxwall-tripwire.service"], True),
        ("upgrade, unit already enabled (no marker yet)", False, "yes", 0, True,
         ["is-enabled --quiet tuxwall-tripwire.service", "try-restart tuxwall-tripwire.service"], True),
        ("owner disabled after the marker", True, "no", 0, True,
         ["is-enabled --quiet tuxwall-tripwire.service", "try-restart tuxwall-tripwire.service"], True),
        ("marker + enabled: restart only", True, "yes", 0, False,
         ["is-enabled --quiet tuxwall-tripwire.service", "try-restart tuxwall-tripwire.service"], True),
        ("enable fails: no marker, retried next time", False, "no", 1, False,
         ["is-enabled --quiet tuxwall-tripwire.service", "enable tuxwall-tripwire.service"], False),
    ]
    for name, mk, en, erc, legacy, want, after in cases:
        d = sandbox()
        try:
            m = d + "/state/.tripwire-enabled-once"
            os.makedirs(d + "/state")
            if mk:
                open(m, "w").close()
            if legacy:
                with open(d + "/tripwire.json", "w") as f:
                    f.write('{"mode": "logonly"}\n')
            rc, calls, out = run(d, fns + 'tripwire_unit_setup "%s"' % m, enabled=en, enable_rc=erc)
            check(rc == 0 and calls == want and os.path.exists(m) == after,
                  "tripwire (%s): rc=%s calls=%s marker=%s %s" % (name, rc, calls, os.path.exists(m), out))
        finally:
            shutil.rmtree(d)
    body = SRC.split('case "$1" in', 1)[1]
    check('tripwire_unit_setup "$STATE_DIR/.tripwire-enabled-once"' in body, "configure calls tripwire_unit_setup")
    check("! -e /etc/tuxwall/tripwire.json" not in SRC, "old config-file condition removed")


def t_bouncer():
    fn = func("bouncer_migration")
    check(fn != "", "postinst defines bouncer_migration")
    d = sandbox()
    try:
        helper = d + "/helper"
        with open(helper, "w") as f:
            f.write("#!/bin/sh\necho ran >> %s/helper.log\nexit ${HELPER_RC:-0}\n" % d)
        os.chmod(helper, 0o644)      # postinst restores the exec bit
        log = d + "/helper.log"

        def ran():
            n = len(open(log).read().splitlines()) if os.path.exists(log) else 0
            if os.path.exists(log):
                os.unlink(log)
            return n
        rc, _c, out = run(d, fn + 'bouncer_migration "" "%s"' % helper)
        check(rc == 0 and ran() == 0, "bouncer: fresh install (no previous version) -> helper not run")
        rc, _c, out = run(d, fn + 'bouncer_migration "3.3.1" "%s"' % helper)
        check(rc == 0 and ran() == 1 and os.access(helper, os.X_OK), "bouncer: upgrade -> helper run")
        rc, _c, out = run(d, "export HELPER_RC=1\n" + fn + 'bouncer_migration "3.3.1" "%s"' % helper)
        check(rc == 0 and ran() == 1 and "left as it was" in out, "bouncer: helper failure never fails postinst")
        rc, _c, out = run(d, fn + 'bouncer_migration "3.3.1" "%s/missing"' % d)
        check(rc == 0 and ran() == 0, "bouncer: helper missing -> skipped")
    finally:
        shutil.rmtree(d)
    body = SRC.split('case "$1" in', 1)[1]
    check('bouncer_migration "${2:-}"' in body and body.index("bouncer_migration") < body.index("step 7 "),
          "configure runs the migration before the dashboard restart")
    check(re.search(r"^STEP_TOTAL=(\d+)", SRC, re.M).group(1) == str(len(re.findall(r"^    step \S+ ", SRC, re.M))),
          "STEP_TOTAL matches the number of steps")


def t_prerm():
    src = open(PRERM).read()
    for en, kept in (("yes", False), ("no", True)):
        d = sandbox()
        try:
            os.makedirs(d + "/state")
            m = d + "/state/.tripwire-enabled-once"
            open(m, "w").close()
            script = src.replace("/var/lib/tuxwall/", d + "/state/").replace("set -euo pipefail", "")
            rc, calls, out = run(d, script, enabled=en, args=["remove"])
            check(rc == 0 and os.path.exists(m) == kept and "disable tuxwall-tripwire.service" in calls,
                  "prerm remove (enabled=%s): marker kept=%s calls=%s %s" % (en, os.path.exists(m), calls, out))
            open(m, "w").close()
            rc, calls, out = run(d, script, enabled=en, args=["upgrade"])
            check(rc == 0 and os.path.exists(m) and not any("tripwire" in c for c in calls),
                  "prerm upgrade (enabled=%s): tripwire untouched" % en)
        finally:
            shutil.rmtree(d)


RADVD_FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
st="$FAKE_DIR/radvd-active"
case "$1" in
  is-active) [ "$(cat "$st" 2>/dev/null)" = yes ] && exit 0; exit 3 ;;
  restart)
    if [ -n "$FAKE_FAIL_WITH_DROPIN" ] && [ -e "$FAKE_ROOT/etc/systemd/system/radvd.service.d/10-tuxwall.conf" ]; then
      echo no > "$st"; exit 1
    fi
    echo yes > "$st"; exit 0 ;;
esac
exit 0
"""
RADVD_FAKE = """#!/bin/sh
echo "radvd $*" >> "$FAKE_LOG"
f=""
while [ $# -gt 0 ]; do [ "$1" = --config ] && f=$2; shift; done
[ -n "$f" ] && [ -f "$f" ] && ! grep -q BROKEN "$f"
"""
SHIPPED_DROPIN = os.path.join(ROOT_DIR, "pkg", "usr", "share", "tuxwall", "radvd", "10-tuxwall.conf")
LEGACY_RADVD = "interface enp6s0 {\n    AdvSendAdvert on;\n    prefix fd00:1::/64 { };\n};\n"


def t_radvd():
    consts = "".join(m.group(0) for m in re.finditer(r"^RADVD_[A-Z_]+=\S+\n", SRC, re.M))
    fns = consts + func("radvd_foreign_writers") + func("radvd_migration")
    check("radvd_migration" in fns and "RADVD_DROPIN=" in consts, "postinst defines the radvd migration")

    def box(legacy=LEGACY_RADVD, active=True, new=None, src=True, mode=0o640):
        d = sandbox()
        os.makedirs(d + "/root/etc/tuxwall")
        os.makedirs(d + "/root/usr/local/sbin")
        for name, text in (("systemctl", RADVD_FAKE_SYSTEMCTL), ("radvd", RADVD_FAKE)):
            with open(d + "/bin/" + name, "w") as f:
                f.write(text)
            os.chmod(d + "/bin/" + name, 0o755)
        if legacy is not None:
            with open(d + "/root/etc/radvd.conf", "w") as f:
                f.write(legacy)
            os.chmod(d + "/root/etc/radvd.conf", mode)
        if new is not None:
            with open(d + "/root/etc/tuxwall/radvd.conf", "w") as f:
                f.write(new)
        if src:
            os.makedirs(d + "/root/usr/share/tuxwall/radvd")
            shutil.copy(SHIPPED_DROPIN, d + "/root/usr/share/tuxwall/radvd/10-tuxwall.conf")
        with open(d + "/radvd-active", "w") as f:
            f.write("yes\n" if active else "no\n")
        return d

    def go(d, extra=""):
        os.environ.update(FAKE_DIR=d, FAKE_ROOT=d + "/root")
        try:
            return run(d, extra + fns + 'radvd_migration "%s/root"' % d)
        finally:
            for k in ("FAKE_DIR", "FAKE_ROOT", "FAKE_FAIL_WITH_DROPIN"):
                os.environ.pop(k, None)

    def state(d):
        r = d + "/root"
        new = r + "/etc/tuxwall/radvd.conf"
        drop = r + "/etc/systemd/system/radvd.service.d/10-tuxwall.conf"
        return {"new": open(new).read() if os.path.exists(new) else None,
                "new_mode": os.stat(new).st_mode & 0o777 if os.path.exists(new) else None,
                "dropin": open(drop).read() if os.path.exists(drop) else None,
                "legacy": open(r + "/etc/radvd.conf").read() if os.path.exists(r + "/etc/radvd.conf") else None,
                "active": open(d + "/radvd-active").read().strip()}

    shipped = open(SHIPPED_DROPIN).read()
    # 1. upgrade: copy (content + mode), configtest the copy, drop-in, restart
    d = box()
    try:
        rc, calls, out = go(d)
        s = state(d)
        check(rc == 0 and "now reads /etc/tuxwall/radvd.conf" in out, "radvd upgrade: migrated (%s)" % out)
        check(s["new"] == LEGACY_RADVD and s["new_mode"] == 0o640 and s["legacy"] == LEGACY_RADVD,
              "radvd upgrade: content + mode copied, /etc/radvd.conf left as it was")
        check(s["dropin"] == shipped and s["active"] == "yes", "radvd upgrade: shipped drop-in installed, radvd up")
        check(calls.index("radvd --configtest --config %s/root/etc/tuxwall/radvd.conf" % d) < calls.index("daemon-reload")
              < calls.index("restart radvd.service"), "radvd upgrade: configtest, daemon-reload, restart (%s)" % calls)
        rc, calls, out = go(d)
        check(rc == 0 and "already" in out and calls == [], "radvd: second run is a no-op (%s)" % calls)
    finally:
        shutil.rmtree(d)
    # 2. skips: a local script writes /etc/radvd.conf, opt-out, broken config, nothing to migrate, no drop-in shipped
    for name, setup, want in (
            ("foreign writer", lambda d: open(d + "/root/usr/local/sbin/sync-ipv6-pd.sh", "w").write(
                'RADVD_CONF="/etc/radvd.conf"\n'), "written by /usr/local/sbin/sync-ipv6-pd.sh"),
            ("opt-out", lambda d: open(d + "/root/etc/tuxwall/no-radvd-migration", "w").close(), "opted out"),
            ("configtest fails", lambda d: open(d + "/root/etc/radvd.conf", "a").write("BROKEN\n"), "configtest"),
            ("no config", lambda d: os.unlink(d + "/root/etc/radvd.conf"), "nothing to migrate"),
            ("no drop-in shipped", lambda d: shutil.rmtree(d + "/root/usr/share/tuxwall/radvd"), "not shipped")):
        d = box()
        try:
            setup(d)
            rc, calls, out = go(d)
            s = state(d)
            check(rc == 0 and want in out and s["new"] is None and s["dropin"] is None
                  and not [c for c in calls if not c.startswith("radvd --configtest")] and s["active"] == "yes",
                  "radvd skip (%s): nothing changed (%s %s)" % (name, out, calls))
        finally:
            shutil.rmtree(d)
    # TuxWall's own files naming /etc/radvd.conf are not foreign writers
    d = box()
    try:
        for n in ("system-backup.sh", "tuxwall-nat-ensure"):
            with open(d + "/root/usr/local/sbin/" + n, "w") as f:
                f.write("/etc/radvd.conf\n")
        rc, calls, out = go(d)
        check("now reads" in out, "radvd: system-backup.sh / tuxwall-* do not block the migration (%s)" % out)
    finally:
        shutil.rmtree(d)
    # a path-aware script (picks the file via the drop-in) and backup copies do not block; partial awareness does
    for name, files, want in (
            ("path-aware script + backups", {
                "sync-ipv6-pd.sh": 'RADVD_DROPIN="/etc/systemd/system/radvd.service.d/10-tuxwall.conf"\n'
                                   'if [ -e "$RADVD_DROPIN" ]; then RADVD_CONF="/etc/tuxwall/radvd.conf"; '
                                   'else RADVD_CONF="/etc/radvd.conf"; fi\n',
                "sync-ipv6-pd.sh.bak": 'RADVD_CONF="/etc/radvd.conf"\n',
                "x.bak.20261016": "/etc/radvd.conf\n", "x.orig": "/etc/radvd.conf\n",
                "x.pre-radvdlive": "/etc/radvd.conf\n", "x~": "/etc/radvd.conf\n"}, "now reads"),
            ("drop-in path only", {"other.sh": "/etc/radvd.conf\n"
                                   "/etc/systemd/system/radvd.service.d/10-tuxwall.conf\n"},
             "written by /usr/local/sbin/other.sh"),
            ("new path only", {"other.sh": "/etc/radvd.conf /etc/tuxwall/radvd.conf\n"},
             "written by /usr/local/sbin/other.sh")):
        d = box()
        try:
            for n, text in files.items():
                with open(d + "/root/usr/local/sbin/" + n, "w") as f:
                    f.write(text)
            rc, calls, out = go(d)
            check(rc == 0 and want in out, "radvd foreign writers (%s): %s" % (name, out))
            if want != "now reads":
                check(state(d)["dropin"] is None, "radvd foreign writers (%s): not migrated" % name)
        finally:
            shutil.rmtree(d)
    # 3. radvd does not come up with the new path: everything put back
    d = box()
    try:
        os.environ["FAKE_FAIL_WITH_DROPIN"] = "1"
        rc, calls, out = go(d)
        s = state(d)
        check(rc == 0 and "rolled back" in out and s["new"] is None and s["dropin"] is None
              and s["legacy"] == LEGACY_RADVD and s["active"] == "yes" and calls.count("restart radvd.service") == 2
              and calls.count("daemon-reload") == 2, "radvd: failed restart rolls back (%s %s %s)" % (out, calls, s))
    finally:
        shutil.rmtree(d)
    # 4. radvd not running: drop-in only, no restart
    d = box(active=False)
    try:
        rc, calls, out = go(d)
        check("now reads" in out and "restart radvd.service" not in calls and state(d)["dropin"] == shipped,
              "radvd inactive: migrated without a restart (%s)" % calls)
    finally:
        shutil.rmtree(d)
    # 5. fresh install: the new file exists (installer / postinst), no stock file
    d = box(legacy=None, new=LEGACY_RADVD, active=False)
    try:
        rc, calls, out = go(d)
        s = state(d)
        check("now reads" in out and s["new"] == LEGACY_RADVD and s["dropin"] == shipped and s["legacy"] is None,
              "radvd fresh: drop-in installed for the new file (%s)" % out)
    finally:
        shutil.rmtree(d)
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check('install -o root -g root -m 0644 "$TMP" "$RADVD_NEW"' in body and "-s $RADVD_OLD" in body,
          "postinst: fresh basic radvd config goes to /etc/tuxwall/radvd.conf (only when neither exists)")
    check(body.index('"$RADVD_NEW"') < body.index("radvd_migration") < body.index("enable --now radvd"),
          "postinst: write, migrate (drop-in), then enable radvd")
    # the installer writes the same drop-in itself (the package may be older)
    inst = open(os.path.join(ROOT_DIR, "tuxwall-install.sh")).read()
    m = re.search(r"^radvd_dropin\(\) \{.*?^\}\n", inst, re.M | re.S)
    out = subprocess.run(["bash", "-c", m.group(0) + "radvd_dropin"], capture_output=True, text=True).stdout if m else ""
    check(out == shipped, "installer radvd_dropin == pkg/usr/share/tuxwall/radvd/10-tuxwall.conf")
    w = re.search(r"^write_radvd\(\) \{.*?^\}\n", inst, re.M | re.S)
    check(w and "local f=$RADVD_CONF " in w.group(0) and 'radvd_dropin >"$RADVD_DROPIN"' in w.group(0)
          and "/etc/radvd.conf" not in w.group(0), "installer writes /etc/tuxwall/radvd.conf + the drop-in")
    for line in shipped.splitlines():
        if line.startswith(("ExecStart=/", "ExecStartPre=/", "ExecReload=/usr")):
            check("--config /etc/tuxwall/radvd.conf" in line, "drop-in: %s uses the new path" % line)
    check(shipped.count("ExecStart=\n") == 1 and "ConditionPathExists=\n" in shipped,
          "drop-in clears ExecStart= and the stock ConditionPathExists=")


KEA_FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
st="$FAKE_DIR/kea-active"
case "$1" in
  is-active) [ "$(cat "$st" 2>/dev/null)" = yes ] && exit 0; exit 3 ;;
  restart)
    if [ -n "$FAKE_FAIL_WITH_HOOK" ] && grep -q lease_cmds "$FAKE_ROOT/etc/kea/kea-dhcp4.conf"; then
      echo no > "$st"; exit 1
    fi
    echo yes > "$st"; exit 0 ;;
esac
exit 0
"""
KEA_FAKE_TEST = """#!/bin/sh
echo "kea-dhcp4 $*" >> "$FAKE_LOG"
[ "$1" = -t ] && [ -f "$2" ] && [ -z "$FAKE_KEA_T_FAIL" ]
"""
KEA_FAKE_RUNUSER = """#!/bin/sh
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
exec "$@"
"""


def installer_kea_json(lib):
    inst = open(os.path.join(ROOT_DIR, "tuxwall-install.sh")).read()
    fn = re.search(r"^kea_json\(\) \{.*?^KEA\n\}\n", inst, re.M | re.S).group(0)
    return subprocess.run(
        ["bash", "-c", fn + 'INSTALLER_MARK="Generated by the TuxWall installer"; KEA_LEASE_CMDS_LIB="%s"; LAN=eth1;'
         ' NET_CIDR=192.168.100.0/24; NET_POOL_LO=192.168.100.100; NET_POOL_HI=192.168.100.200;'
         ' NET_GW=192.168.100.1; DOMAIN=home.arpa; kea_json socket-name' % lib],
        capture_output=True, text=True, timeout=10).stdout


def t_kea_hook():
    sys.path.insert(0, os.path.join(ROOT_DIR, "www", "includes"))
    sys.dont_write_bytecode = True
    import kea_conf as K
    consts = "".join(m.group(0) for m in re.finditer(r"^KEA_[A-Z_]+=\S+\n", SRC, re.M))
    fns = consts + func("kea_hook_migration")
    check("kea_hook_migration" in fns and "KEA_LEASE_CMDS_LIB=" in consts, "postinst defines the Kea hook migration")
    lib = re.search(r"^KEA_LEASE_CMDS_LIB=(\S+)", consts, re.M).group(1)
    old_gen = installer_kea_json(lib + ".missing")       # what v331 wrote: no hooks-libraries
    new_gen = installer_kea_json(os.path.abspath(__file__))   # any existing file -> hook block
    check("hooks-libraries" not in old_gen and "hooks-libraries" in new_gen, "installer kea_json old/new shapes")
    head = K.split_header(old_gen)[0]

    def box(text=old_gen, active=True, libfile=True, mode=0o640):
        d = sandbox()
        r = d + "/root"
        os.makedirs(r + "/etc/kea")
        os.makedirs(r + "/var/www/html/includes")
        shutil.copy(os.path.join(ROOT_DIR, "www", "includes", "kea_conf.py"), r + "/var/www/html/includes/")
        for name, body in (("systemctl", KEA_FAKE_SYSTEMCTL), ("kea-dhcp4", KEA_FAKE_TEST),
                           ("runuser", KEA_FAKE_RUNUSER), ("sleep", "#!/bin/sh\nexit 0\n")):
            with open(d + "/bin/" + name, "w") as f:
                f.write(body)
            os.chmod(d + "/bin/" + name, 0o755)
        if libfile:
            os.makedirs(os.path.dirname(r + lib))
            open(r + lib, "w").close()
        if text is not None:
            with open(r + "/etc/kea/kea-dhcp4.conf", "w") as f:
                f.write(text)
            os.chmod(r + "/etc/kea/kea-dhcp4.conf", mode)
        with open(d + "/kea-active", "w") as f:
            f.write("yes\n" if active else "no\n")
        return d

    def go(d, **env):
        os.environ.update(FAKE_DIR=d, FAKE_ROOT=d + "/root", **env)
        try:
            return run(d, fns + 'kea_hook_migration "%s/root"' % d)
        finally:
            for k in ["FAKE_DIR", "FAKE_ROOT"] + list(env):
                os.environ.pop(k, None)

    def conf(d):
        p = d + "/root/etc/kea/kea-dhcp4.conf"
        return open(p).read() if os.path.exists(p) else None

    def backups(d):
        b = d + "/root/var/backups/tuxwall"
        return sorted(os.listdir(b)) if os.path.isdir(b) else []

    def clean(d):
        return os.listdir(d + "/root/etc/kea") == ["kea-dhcp4.conf"]

    want = K.loads(new_gen)
    want["Dhcp4"]["hooks-libraries"] = [{"library": lib}]
    # 1. upgrade from a v331 installer config: hook added, -t before the swap, restart, idempotent
    d = box()
    try:
        rc, calls, out = go(d)
        txt = conf(d)
        check(rc == 0 and "lease_cmds hook added" in out, "kea hook: added (%s)" % out)
        check(K.loads(txt) == want, "kea hook: result == the new installer's kea_json output")
        check(txt.startswith(head) and K.EDIT_MARK not in txt, "kea hook: installer header kept verbatim, no edit mark")
        check(os.stat(d + "/root/etc/kea/kea-dhcp4.conf").st_mode & 0o777 == 0o640, "kea hook: file mode kept")
        b = backups(d)
        check(len(b) == 1 and b[0].startswith("kea-dhcp4.conf.pre-lease-cmds.")
              and open(d + "/root/var/backups/tuxwall/" + b[0]).read() == old_gen, "kea hook: backup of the old file")
        t = [i for i, c in enumerate(calls) if c.startswith("kea-dhcp4 -t ")]
        check(len(t) == 1 and t[0] < calls.index("restart kea-dhcp4-server")
              and "/root/etc/kea/.tuxwall-kea-hook." in calls[t[0]], "kea hook: kea-dhcp4 -t on the candidate, then restart (%s)" % calls)
        check(clean(d), "kea hook: no temp file left")
        rc, calls, out = go(d)
        check(rc == 0 and "already loaded" in out and calls == [] and conf(d) == txt and len(backups(d)) == 1 and clean(d),
              "kea hook: second run is a no-op (%s %s)" % (out, calls))
    finally:
        shutil.rmtree(d)
    # 2. dashboard-edited installer config (edit mark + reservation): hook added, edits kept
    data = K.loads(old_gen)
    data["Dhcp4"]["subnet4"][0]["reservations"] = [{"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.168.100.50"}]
    edited = K.dumps(data, head)
    d = box(edited)
    try:
        rc, calls, out = go(d)
        txt = conf(d)
        data["Dhcp4"]["hooks-libraries"] = [{"library": lib}]
        check("hook added" in out and K.loads(txt) == data and txt.startswith(K.split_header(edited)[0]),
              "kea hook: dashboard-edited config keeps reservations + header (%s)" % out)
    finally:
        shutil.rmtree(d)
    # 3. other hooks already configured: lease_cmds appended
    data = K.loads(old_gen)
    data["Dhcp4"]["hooks-libraries"] = [{"library": "/x/libdhcp_stat_cmds.so"}]
    d = box(K.dumps(data, head))
    try:
        rc, calls, out = go(d)
        check(K.loads(conf(d))["Dhcp4"]["hooks-libraries"] == [{"library": "/x/libdhcp_stat_cmds.so"}, {"library": lib}],
              "kea hook: appended to existing hooks-libraries (%s)" % out)
    finally:
        shutil.rmtree(d)
    # 4. skips: nothing changed, Kea not restarted
    plain = json.dumps(K.loads(old_gen), indent=4) + "\n"
    with_body_comment = old_gen.replace('"valid-lifetime": 7200,', '"valid-lifetime": 7200,  // two hours')
    for name, kw, env, msg in (
            ("not TuxWall-managed (postinst/hand-written)", {"text": plain}, {}, "not written by the TuxWall installer"),
            ("library missing", {"libfile": False}, {}, "not installed"),
            ("no config", {"text": None}, {}, "no config"),
            ("comments inside the JSON", {"text": with_body_comment}, {}, "comments inside the JSON"),
            ("kea-dhcp4 -t fails", {}, {"FAKE_KEA_T_FAIL": "1"}, "failed kea-dhcp4 -t"),
            ("broken JSON", {"text": head + '{"Dhcp4": '}, {}, "not readable")):
        d = box(**kw)
        try:
            before = conf(d)
            rc, calls, out = go(d, **env)
            check(rc == 0 and msg in out and conf(d) == before and not backups(d)
                  and not any(c.startswith("restart") for c in calls) and (before is None or clean(d)),
                  "kea hook skip (%s): %s %s" % (name, out, calls))
        finally:
            shutil.rmtree(d)
    # 5. Kea not running: file updated, no restart
    d = box(active=False)
    try:
        rc, calls, out = go(d)
        check("hook added" in out and "lease_cmds" in conf(d) and "restart kea-dhcp4-server" not in calls,
              "kea hook: Kea inactive -> updated without a restart (%s)" % calls)
    finally:
        shutil.rmtree(d)
    # 6. Kea does not come back with the hook: old file restored, restarted again
    d = box()
    try:
        rc, calls, out = go(d, FAKE_FAIL_WITH_HOOK="1")
        check(rc == 0 and "old config restored" in out and conf(d) == old_gen
              and calls.count("restart kea-dhcp4-server") == 2 and open(d + "/kea-active").read().strip() == "yes",
              "kea hook: failed restart rolls back (%s %s)" % (out, calls))
    finally:
        shutil.rmtree(d)
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check('{ "library": "$KEA_LEASE_CMDS_LIB" }' in body, "postinst fresh Kea config uses KEA_LEASE_CMDS_LIB")
    check("kea_hook_migration" in body and body.index("kea_hook_migration") < body.index("step 7 "),
          "configure runs the Kea hook migration before the dashboard restart")


def main():
    for p in (POSTINST, PRERM, os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postrm")):
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        check(r.returncode == 0, "bash -n %s %s" % (os.path.basename(p), r.stderr))
    t_tripwire()
    t_bouncer()
    t_prerm()
    t_radvd()
    t_kea_hook()
    print("pkg_scripts_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
