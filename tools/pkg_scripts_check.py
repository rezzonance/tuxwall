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


def main():
    for p in (POSTINST, PRERM, os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postrm")):
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        check(r.returncode == 0, "bash -n %s %s" % (os.path.basename(p), r.stderr))
    t_tripwire()
    t_bouncer()
    t_prerm()
    print("pkg_scripts_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
