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
"""
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


def main():
    for p in (POSTINST, PRERM, os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postrm")):
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        check(r.returncode == 0, "bash -n %s %s" % (os.path.basename(p), r.stderr))
    t_tripwire()
    t_bouncer()
    t_prerm()
    t_radvd()
    print("pkg_scripts_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
