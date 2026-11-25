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
- unbound_apply (3.3.3): unbound restarted only after unbound-checkconf
  passes; a rejected config puts the backed-up files back (new ones removed)
  and leaves unbound running; a failed restart rolls back and restarts.
- fresh-install firewall (3.3.3): SSH/dashboard on the LAN interface(s) +
  wg0 only (installer comments), never the WAN; RFC1918/ULA sources when no
  LAN is known; upgrades and installer runs add nothing.
- nginx_listen_render: listen include rendered before nginx -t / reload,
  never fails the postinst.
- plugins_dir_perms (3.3.3): /etc/tuxwall/plugins 0755 (no group write),
  plugin dirs 0755, files 0644, settings/pin/secret data 0600; hidden
  entries and symlinks untouched, a missing dir is not created.
- tuxwall-nat-ensure: idempotent (-C first), a failed -A exits 1 with the
  reason on stderr (stubbed iptables).
- agent_setup_step (3.3.4, finding 8.3): the shipped setup script runs only
  when the opencode binary is missing, honours /etc/tuxwall/no-agent, every
  failure is a warning with the re-run command; agents_md_install runs after
  it and never clobbers an edited AGENTS.md.
- rsyslog_unbound_rule (3.3.5): /etc/rsyslog.d/45-tuxwall-unbound.conf is
  postinst-owned: installed when absent (no restart when dpkg just removed
  3.2.2-3.3.4's identical package copy), an older TuxWall copy updated, a
  local edit kept; rsyslog restarted only on a change that rsyslogd -N1
  accepts, else the previous state is put back. postrm removes it unless
  edited.
- agent_config_split (3.3.5): runs opencode_config.py migrate; restarts the
  agent only after a move (rc 10); a left-alone config is a note, a helper
  failure a warning; never fails the postinst.
- devicewatch_setup (3.3.7): system user created once, added only to the
  groups that exist (zeek, _kea, systemd-journal), units enabled ONCE
  (marker) and the first feed download started without blocking; upgrades
  only try-restart; a failed useradd/enable never fails the postinst.
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


def fakebin(d, files):
    os.makedirs(d + "/fbin", exist_ok=True)
    for name, body in files.items():
        with open(d + "/fbin/" + name, "w") as f:
            f.write(body)
        os.chmod(d + "/fbin/" + name, 0o755)


def bash_run(d, script, env=None, path_extra=True):
    e = dict(os.environ, FAKE_LOG=d + "/calls")
    e["PATH"] = d + "/fbin:" + (os.environ.get("PATH", "") if path_extra else "/usr/bin:/bin")
    e.update(env or {})
    if os.path.exists(d + "/calls"):
        os.unlink(d + "/calls")
    p = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script, "x"], env=e,
                       capture_output=True, text=True, timeout=60)
    calls = open(d + "/calls").read().splitlines() if os.path.exists(d + "/calls") else []
    return p.returncode, calls, p.stdout, p.stderr


UB_FAKES = {
    "unbound-checkconf": '#!/bin/sh\necho "checkconf" >> "$FAKE_LOG"\n'
                         'if grep -rqs BROKEN "$UB_DIR"; then echo "$UB_DIR/x.conf:3: error: syntax error" >&2; exit 1; fi\n'
                         'echo "unbound-checkconf: no errors"; exit 0\n',
    "systemctl": '#!/bin/sh\necho "$*" >> "$FAKE_LOG"\n'
                 'case "$1" in\n'
                 '  restart) n=$(cat "$UB_DIR/../restarts" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$UB_DIR/../restarts"\n'
                 '           [ "$n" -le "${FAKE_RESTART_FAILS:-0}" ] && exit 1; exit 0 ;;\n'
                 '  is-active) n=$(cat "$UB_DIR/../restarts" 2>/dev/null || echo 0); [ "$n" -le "${FAKE_RESTART_FAILS:-0}" ] && exit 3; exit 0 ;;\n'
                 'esac\nexit 0\n',
}


def t_unbound_apply():
    fns = func("unbound_txn_begin") + func("unbound_backup") + func("unbound_restore") + func("unbound_apply")
    check(all(n in fns for n in ("unbound_txn_begin", "unbound_backup", "unbound_restore", "unbound_apply")),
          "postinst defines the unbound transaction functions")
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check("unbound-checkconf || true" not in body and "systemctl restart unbound || true" not in body,
          "configure no longer restarts unbound unchecked")
    lines = body.splitlines()
    writes = [i for i, l in enumerate(lines)
              if re.search(r"(cat >|: >|^\s*cp ).*(/etc/unbound/unbound\.conf\.d/|/var/lib/unbound/)", l)]
    check(len(writes) >= 5, "found the unbound writes in configure (%d)" % len(writes))
    for i in writes:
        prev = "\n".join(lines[max(0, i - 2):i])
        check("unbound_backup" in prev, "unbound write backed up first: %s" % lines[i].strip())
    begin = next(i for i, l in enumerate(lines) if l.strip().startswith("unbound_txn_begin "))
    apply_ = next(i for i, l in enumerate(lines) if "$(unbound_apply)" in l)
    check(begin < writes[0] and apply_ > writes[-1],
          "transaction begins before the first write, applied after the last")

    def box(old_main="server:\n    verbosity: 1\n", old_extra=None):
        d = tempfile.mkdtemp(prefix="pkg-unbound-")
        fakebin(d, UB_FAKES)
        os.makedirs(d + "/conf.d")
        with open(d + "/conf.d/99-blocklists.conf", "w") as f:
            f.write(old_main)
        if old_extra is not None:
            with open(d + "/conf.d/extra.conf", "w") as f:
                f.write(old_extra)
        return d

    def go(d, new_main, new_file="server:\n    # new\n", env=None):
        script = fns + (
            'unbound_txn_begin "$D/bk"\n'
            'unbound_backup "$D/conf.d/99-blocklists.conf"\n'
            'printf "%s" "$NEWMAIN" > "$D/conf.d/99-blocklists.conf"\n'
            'unbound_backup "$D/conf.d/router-dns.conf"\n'
            'printf "%s" "$NEWFILE" > "$D/conf.d/router-dns.conf"\n'
            'unbound_backup "$D/conf.d/99-blocklists.conf"\n'   # second backup of the same file: first state wins
            'unbound_apply\n'
            'echo "TXN=$UNBOUND_TXN"\n')
        e = {"D": d, "UB_DIR": d + "/conf.d", "NEWMAIN": new_main, "NEWFILE": new_file}
        e.update(env or {})
        rc, calls, out, err = bash_run(d, script, e)
        return rc, calls, out, err

    def read(d, name):
        try:
            return open(d + "/conf.d/" + name).read()
        except FileNotFoundError:
            return None

    # 1. good config: checked, restarted, backups removed
    d = box()
    try:
        rc, calls, out, err = go(d, "server:\n    verbosity: 2\n")
        check(rc == 0 and calls[:2] == ["checkconf", "restart unbound"] and "checked" in out,
              "unbound: valid config -> checkconf then restart (%s %s)" % (calls, out))
        txn = out.split("TXN=")[-1].strip()
        check(txn and not os.path.exists(txn), "unbound: backups removed after a good restart")
        check(read(d, "router-dns.conf") == "server:\n    # new\n", "unbound: new files kept")
    finally:
        shutil.rmtree(d)
    # 2. broken config: no restart, previous files back, new file removed, rejected copies kept
    d = box()
    try:
        rc, calls, out, err = go(d, "server:\n    BROKEN\n")
        check(rc == 0 and not any(c.startswith("restart") for c in calls), "unbound: rejected config -> no restart (%s)" % calls)
        check(read(d, "99-blocklists.conf") == "server:\n    verbosity: 1\n" and read(d, "router-dns.conf") is None,
              "unbound: previous files restored, created file removed")
        check("NOT restarted" in out and "previous config restored" in out and "syntax error" in out,
              "unbound: clear message (%s)" % out.strip())
        txn = out.split("TXN=")[-1].strip()
        check(any(f.endswith(".rejected") for f in os.listdir(txn)), "unbound: rejected files kept for diagnosis")
        check(calls.count("checkconf") == 2, "unbound: restored config re-checked")
    finally:
        shutil.rmtree(d)
    # 3. config already broken before the postinst: restored as it was, not restarted
    d = box(old_extra="BROKEN before\n")
    try:
        rc, calls, out, err = go(d, "server:\n    verbosity: 2\n")
        check(rc == 0 and "even with the previous files" in out and not any(c.startswith("restart") for c in calls)
              and read(d, "99-blocklists.conf") == "server:\n    verbosity: 1\n",
              "unbound: pre-existing broken config -> files restored, no restart (%s)" % out.strip())
    finally:
        shutil.rmtree(d)
    # 4. valid config but unbound does not come back: rolled back and restarted again
    d = box()
    try:
        rc, calls, out, err = go(d, "server:\n    verbosity: 2\n", env={"FAKE_RESTART_FAILS": "1"})
        check(rc == 0 and calls.count("restart unbound") == 2 and "did not come back" in out
              and read(d, "99-blocklists.conf") == "server:\n    verbosity: 1\n" and read(d, "router-dns.conf") is None,
              "unbound: failed restart -> previous files + restart (%s %s)" % (calls, out.strip()))
    finally:
        shutil.rmtree(d)
    # 5. no backup possible (txn dir unavailable): broken config is still never restarted
    d = box()
    try:
        script = fns + 'UNBOUND_TXN=""\nprintf "BROKEN" > "$D/conf.d/99-blocklists.conf"\nunbound_apply\n'
        rc, calls, out, err = bash_run(d, script, {"D": d, "UB_DIR": d + "/conf.d"})
        check(rc == 0 and "NOT restarted" in out and not any(c.startswith("restart") for c in calls),
              "unbound: no backup + broken config -> not restarted (%s)" % out.strip())
    finally:
        shutil.rmtree(d)


FW_FAKES = {
    "ufw": '#!/bin/sh\nif [ "$1" = show ] && [ "$2" = added ]; then echo "Added user rules:"; '
           'cat "$FAKE_UFW_ADDED" 2>/dev/null; exit 0; fi\necho "$*" >> "$FAKE_LOG"\nexit 0\n',
    "ip": '#!/bin/sh\n[ "$1 $2 $3" = "link show wg0" ] && [ "${FAKE_WG:-0}" = 1 ] && exit 0\nexit 1\n',
    "sshd": '#!/bin/sh\n[ "$1" = -T ] || exit 1\nprintf "port 22\\nport 2222\\naddressfamily any\\n"\n',
}


def t_firewall_fresh():
    fns = func("fw_lan_ifaces") + func("fw_ssh_ports") + func("fw_has_port_rule") + func("fw_fresh_allow")
    check(all(n + "()" in fns for n in ("fw_lan_ifaces", "fw_ssh_ports", "fw_has_port_rule", "fw_fresh_allow")),
          "postinst defines the fresh-install firewall functions")
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check("ufw allow OpenSSH" not in body and "ufw allow 80/tcp" not in body, "no interface-less SSH/80 allow left")
    d = tempfile.mkdtemp(prefix="pkg-fw-")
    try:
        fakebin(d, FW_FAKES)
        roles = d + "/interfaces.json"
        with open(roles, "w") as f:
            json.dump({"wan": {"device": "enp5s0"}, "lan": {"device": "enp6s0"},
                       "opt": [{"device": "enp6s0.10"}], "vpn": [{"device": "wg0"}]}, f)

        def ifaces(wan, detected, roles_path, wg="0", wgconf="/nonexistent/wg0.conf"):
            rc, calls, out, err = bash_run(d, fns + 'fw_lan_ifaces "$1" "$2" "$3" "$4"\n'.replace(
                '"$1" "$2" "$3" "$4"', '"%s" "%s" "%s" "%s"' % (wan, detected, roles_path, wgconf)), {"FAKE_WG": wg})
            return out.split()

        check(ifaces("enp5s0", "eth1", roles) == ["enp6s0", "wg0"], "LAN/VPN from interfaces.json (no OPT/VLAN)")
        check(ifaces("enp5s0", "eth1", d + "/none") == ["eth1"], "detected LAN without interfaces.json")
        check(ifaces("enp5s0", "eth1", d + "/none", wg="1") == ["eth1", "wg0"], "wg0 when it exists")
        open(d + "/wg0.conf", "w").close()
        check(ifaces("enp5s0", "", d + "/none", wgconf=d + "/wg0.conf") == ["wg0"], "wg0 when configured")
        check(ifaces("enp5s0", "", d + "/none") == [], "nothing found -> empty")
        check(ifaces("enp6s0", "eth1", roles) == ["wg0"], "the WAN is never returned")
        rc, calls, out, err = bash_run(d, fns + 'fw_ssh_ports "$D/fbin/sshd"\n', {"D": d})
        check(out.split() == ["22", "2222"], "SSH ports from sshd -T (%r)" % out)
        rc, calls, out, err = bash_run(d, fns + 'fw_ssh_ports /nonexistent/sshd\n')
        check(out.strip() == "", "no SSH server -> no SSH ports")

        def allow(args, added=""):
            with open(d + "/added", "w") as f:
                f.write(added)
            rc, calls, out, err = bash_run(d, fns + "fw_fresh_allow %s\n" % args, {"FAKE_UFW_ADDED": d + "/added"})
            return rc, calls, out

        rc, calls, out = allow("22 ssh enp5s0 enp6s0 wg0")
        check(calls == ["allow in on enp6s0 to any port 22 proto tcp comment TuxWall: SSH from LAN",
                        "allow in on wg0 to any port 22 proto tcp comment TuxWall: SSH from VPN"],
              "SSH on LAN + VPN only, installer comments (%s)" % calls)
        rc, calls, out = allow("80 dashboard enp5s0 enp6s0")
        check(calls == ["allow in on enp6s0 to any port 80 proto tcp comment TuxWall dashboard (LAN)"],
              "dashboard on the LAN only (%s)" % calls)
        rc, calls, out = allow("22 ssh enp5s0 enp5s0")
        check(len(calls) == 4 and all(c.startswith("allow proto tcp from ") and " to any port 22 " in c for c in calls)
              and {c.split()[4] for c in calls} == {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"}
              and "WARNING" in out, "no LAN -> RFC1918/ULA sources only + warning (%s)" % calls)
        rc, calls, out = allow("22 ssh enp5s0")
        check(not any(" on enp5s0" in c for c in calls) and not any(re.match(r"allow (22|OpenSSH)", c) for c in calls),
              "never a WAN or internet-wide SSH rule")
        for added, port, want in (("ufw allow in on enp6s0 to any port 22 proto tcp\n", 22, 0),
                                  ("ufw allow OpenSSH\n", 22, 0), ("ufw allow 2222/tcp\n", 22, 1),
                                  ("ufw allow 80/tcp\n", 80, 0), ("ufw allow in on wg0 to any port 8080 proto tcp\n", 80, 1)):
            with open(d + "/added", "w") as f:
                f.write(added)
            rc, _c, _o, _e = bash_run(d, fns + "fw_has_port_rule %d\n" % port, {"FAKE_UFW_ADDED": d + "/added"})
            check(rc == want, "fw_has_port_rule %d with %r -> %d" % (port, added.strip(), want))
        # the configure block itself: fresh install adds LAN rules, upgrades add nothing
        m = re.search(r"    if \[\[ \$\{TUXWALL_INSTALLER_FIREWALL:-\} != 1 && -z \$\{2:-\} \]\]; then\n.*?\n    fi\n",
                      body, re.S)
        check(m is not None, "fresh-only firewall block present in configure")
        block = m.group(0) if m else ""
        # host-independent: no real interfaces.json / wg0.conf, one SSH port
        stub = ('fw_ssh_ports() { echo 22; }\n'
                'eval "$(declare -f fw_lan_ifaces | sed \'1s/fw_lan_ifaces/_fw_lan_real/\')"\n'
                'fw_lan_ifaces() { _fw_lan_real "$1" "$2" /nonexistent/roles.json /nonexistent/wg0.conf; }\n')
        for prev, inst, expect in (("", "", True), ("3.3.2", "", False), ("", "1", False)):
            with open(d + "/added", "w") as f:
                f.write("")
            script = fns + stub + 'WAN_IF_D=enp5s0; LAN_IF_D=enp6s0\nset -- configure "%s"\n' % prev + block
            rc, calls, out, err = bash_run(d, script, {"FAKE_UFW_ADDED": d + "/added", "TUXWALL_INSTALLER_FIREWALL": inst})
            if expect:
                check(rc == 0 and calls == ["allow in on enp6s0 to any port 22 proto tcp comment TuxWall: SSH from LAN",
                                            "allow in on enp6s0 to any port 80 proto tcp comment TuxWall dashboard (LAN)"],
                      "fresh apt install: SSH + dashboard on the LAN (%s %s)" % (calls, err))
            else:
                check(rc == 0 and calls == [], "prev=%r installer=%r: rules untouched (%s)" % (prev, inst, calls))
        with open(d + "/added", "w") as f:
            f.write("ufw allow in on enp6s0 to any port 22 proto tcp\n")
        script = fns + stub + 'WAN_IF_D=enp5s0; LAN_IF_D=enp6s0\nset -- configure ""\n' + block
        rc, calls, out, err = bash_run(d, script, {"FAKE_UFW_ADDED": d + "/added", "TUXWALL_INSTALLER_FIREWALL": ""})
        check(calls == ["allow in on enp6s0 to any port 80 proto tcp comment TuxWall dashboard (LAN)"]
              and "already has a rule" in out, "existing SSH rule left as is (%s)" % calls)
    finally:
        shutil.rmtree(d)


def t_nginx_listen_render():
    fn = func("nginx_listen_render")
    check("nginx_listen_render()" in fn, "postinst defines nginx_listen_render")
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    step5 = body[body.index('step 5 '):body.index('step 6 ')]
    check("nginx_listen_render" in step5 and step5.index("nginx_listen_render") < step5.index("if nginx -t"),
          "step 5 renders the listen include before nginx -t / reload")
    d = tempfile.mkdtemp(prefix="pkg-nginx-")
    try:
        fakebin(d, {"nginx": "#!/bin/sh\nexit 0\n"})
        for rc_r, want in ((0, "nginx: listen include written"), (1, "listen include left as it was")):
            r = d + "/render%d" % rc_r
            with open(r, "w") as f:
                f.write("import sys\nprint('%s (x): 192.168.1.1:80')\nsys.exit(%d)\n"
                        % ("listen include written" if rc_r == 0 else "nginx -t failed - previous state kept", rc_r))
            rc, calls, out, err = bash_run(d, fn + 'nginx_listen_render "%s"\n' % r)
            check(rc == 0 and want in out, "render rc=%d -> %r (%s)" % (rc_r, want, out.strip()))
        rc, calls, out, err = bash_run(d, fn + 'nginx_listen_render /nonexistent\n')
        check(rc == 0 and "missing" in out, "renderer missing -> message, no failure")
        os.unlink(d + "/fbin/nginx")
        rc, calls, out, err = bash_run(d, fn + 'nginx_listen_render "%s/render0"\n' % d, path_extra=False)
        check(rc == 0 and "not installed" in out, "nginx missing -> message, no failure (%s)" % out.strip())
    finally:
        shutil.rmtree(d)


def t_plugins_dir_perms():
    fn = func("plugins_dir_perms")
    check("plugins_dir_perms()" in fn and 'PLUGINS_DIR=/etc/tuxwall/plugins' in SRC,
          "postinst defines plugins_dir_perms for /etc/tuxwall/plugins")
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check("plugins_dir_perms" in body and body.index("plugins_dir_perms") < body.index("systemctl restart tuxwall.service"),
          "configure fixes the plugins dir before the API restarts")
    d = tempfile.mkdtemp(prefix="pkg-plugins-")
    try:
        me = "%d:%d" % (os.getuid(), os.getgid())
        p = d + "/plugins"
        tree = {"demo/main.py": 0o664, "demo/plugin.json": 0o666, "demo/config.json": 0o644,
                "demo/.provenance.json": 0o644, "demo/api_secret.txt": 0o644, "demo/Secret_helper.py": 0o600,
                "demo/web/plugin.js": 0o664, "demo/web/.config.json.ab12.tmp": 0o644, "demo/run.sh": 0o755}
        for rel, mode in tree.items():
            os.makedirs(os.path.dirname(os.path.join(p, rel)), exist_ok=True)
            with open(os.path.join(p, rel), "w") as f:
                f.write("x\n")
            os.chmod(os.path.join(p, rel), mode)
        os.makedirs(p + "/.staging-x")
        os.chmod(p + "/.staging-x", 0o700)
        os.chmod(p + "/demo/web", 0o775)
        os.chmod(p + "/demo", 0o777)
        os.chmod(p, 0o775)
        os.symlink(p + "/demo/main.py", p + "/demo/link.py")
        rc, calls, out, err = bash_run(d, fn + 'plugins_dir_perms "%s" "%s"\n' % (p, me))
        mode = lambda rel: os.lstat(os.path.join(p, rel) if rel else p).st_mode & 0o7777
        check(rc == 0 and "was 775" in out and mode("") == 0o755, "top dir 0755, previous mode reported (%s)" % out.strip())
        check(mode("demo") == 0o755 and mode("demo/web") == 0o755, "plugin directories 0755")
        want = {"demo/main.py": 0o644, "demo/plugin.json": 0o644, "demo/config.json": 0o600,
                "demo/.provenance.json": 0o600, "demo/api_secret.txt": 0o600, "demo/Secret_helper.py": 0o644,
                "demo/web/plugin.js": 0o644, "demo/web/.config.json.ab12.tmp": 0o600, "demo/run.sh": 0o644}
        got = {rel: mode(rel) for rel in want}
        check(got == want, "files 0644, settings/pin/secret data 0600 (%s)"
              % {k: oct(v) for k, v in got.items() if v != want[k]})
        check(mode(".staging-x") == 0o700 and os.path.islink(p + "/demo/link.py"), "hidden top-level entries and symlinks untouched")
        rc, calls, out, err = bash_run(d, fn + 'plugins_dir_perms "%s/none" "%s"\n' % (d, me))
        check(rc == 0 and "does not exist" in out and not os.path.exists(d + "/none"), "missing dir -> nothing created")
        os.symlink(p, d + "/plink")
        rc, calls, out, err = bash_run(d, fn + 'plugins_dir_perms "%s/plink" "%s"\n' % (d, me))
        check(rc == 0 and "symlink" in out, "symlinked dir -> left alone")
        rc, calls, out, err = bash_run(d, fn + 'plugins_dir_perms "%s" "nosuchuser:nosuchgroup"\n' % p)
        check(rc == 0 and "could not set" in out, "chown failure -> message, no failure (%s)" % out.strip())
    finally:
        shutil.rmtree(d)


def t_nat_ensure():
    src = open(os.path.join(ROOT_DIR, "pkg", "usr", "local", "sbin", "tuxwall-nat-ensure")).read()
    check("export PATH=/usr/sbin:/usr/bin:/sbin:/bin" in src, "nat-ensure pins PATH")
    d = tempfile.mkdtemp(prefix="pkg-nat-")
    try:
        fakebin(d, {"iptables": '#!/bin/sh\necho "$*" >> "$FAKE_LOG"\n'
                                'case " $* " in\n'
                                '  *" -C "*) exit "${FAKE_C_RC:-1}" ;;\n'
                                '  *" -A "*) [ "${FAKE_A_RC:-0}" = 0 ] && exit 0\n'
                                '            echo "iptables: No chain/target/match by that name." >&2; exit "$FAKE_A_RC" ;;\n'
                                'esac\nexit 0\n'})
        script = d + "/nat-ensure"
        with open(script, "w") as f:
            f.write(src.replace("export PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                                "export PATH=%s/fbin:/usr/sbin:/usr/bin:/sbin:/bin" % d))
        os.chmod(script, 0o755)

        def go(**env):
            e = dict(os.environ, FAKE_LOG=d + "/calls", TUXWALL_WAN_IFACE="eth9", TUXWALL_NAT_WAIT="0")
            e.update(env)
            if os.path.exists(d + "/calls"):
                os.unlink(d + "/calls")
            p = subprocess.run(["sh", script], env=e, capture_output=True, text=True, timeout=30)
            calls = open(d + "/calls").read().splitlines() if os.path.exists(d + "/calls") else []
            return p.returncode, calls, p.stdout, p.stderr

        rc, calls, out, err = go(FAKE_C_RC="0")
        check(rc == 0 and calls == ["-w 10 -t nat -C POSTROUTING -o eth9 -j MASQUERADE"], "nat: rule present -> no add (%s)" % calls)
        rc, calls, out, err = go(FAKE_C_RC="1", FAKE_A_RC="0")
        check(rc == 0 and calls[-1] == "-w 10 -t nat -A POSTROUTING -o eth9 -j MASQUERADE" and len(calls) == 2
              and "added" in out, "nat: missing -> added once, exit 0 (%s)" % calls)
        rc, calls, out, err = go(FAKE_C_RC="1", FAKE_A_RC="4")
        check(rc == 1 and "could not add" in err and "No chain/target" in err and "eth9" in err,
              "nat: failed add -> exit 1 with the reason on stderr (rc=%s %r)" % (rc, err))
    finally:
        shutil.rmtree(d)


def t_agent_setup_step():
    fn = func("agent_setup_step")
    check("agent_setup_step()" in fn and "AGENT_SETUP=/usr/local/share/tuxwall/scripts/setup-opencode-agent.sh" in SRC
          and "AGENT_BIN=/home/tuxwall-agent/.opencode/bin/opencode" in SRC, "postinst defines agent_setup_step")
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    step9 = body[body.index('step 9 '):]
    check("agent_setup_step" in step9 and "agents_md_install" in step9
          and step9.index("agent_setup_step") < step9.index("agents_md_install") < step9.index("api.token"),
          "step 9: agent setup, then AGENTS.md, then the token group")
    check("setup-opencode-agent.sh not shipped" not in SRC and "already active; no action needed" not in SRC
          and "/var/www/html/scripts/setup-opencode-agent.sh" not in SRC, "no misleading SKIP message / web-root lookup")
    check(not re.search(r"^\s+agents_md_install\b|AGENTS_DST_DIR|install [^\n]*AGENTS\.md", body[:body.index('step 9 ')], re.M),
          "AGENTS.md is not installed before the agent user exists")
    d = tempfile.mkdtemp(prefix="pkg-agent-")
    try:
        script = d + "/setup.sh"
        binp = d + "/bin/opencode"
        optout = d + "/no-agent"

        def go(script_rc=None, have_bin=False, opt=False, have_script=True):
            if os.path.exists(script):
                os.unlink(script)
            if have_script:
                with open(script, "w") as f:
                    f.write('echo "setup $*" >> "%s/calls"\necho "[+] fake setup"\nexit %d\n' % (d, script_rc or 0))
            os.makedirs(d + "/bin", exist_ok=True)
            if have_bin:
                with open(binp, "w") as f:
                    f.write("#!/bin/sh\n")
                os.chmod(binp, 0o755)
            elif os.path.exists(binp):
                os.unlink(binp)
            if opt:
                open(optout, "w").close()
            elif os.path.exists(optout):
                os.unlink(optout)
            return bash_run(d, fn + 'agent_setup_step "%s" "%s" "%s"\necho done\n' % (script, binp, optout))

        rc, calls, out, err = go(have_bin=True)
        check(rc == 0 and not calls and "already installed - unchanged" in out,
              "binary present -> setup not run, nothing changed (%s)" % calls)
        rc, calls, out, err = go(script_rc=0)
        check(rc == 0 and calls == ["setup "] and "opencode agent ready" in out,
              "binary missing -> setup runs without arguments (%s)" % calls)
        for src_rc in (1, 2, 3, 4):
            rc, calls, out, err = go(script_rc=src_rc)
            check(rc == 0 and "WARNING: AI assistant not installed" in out and "sudo bash " + script in out
                  and out.rstrip().endswith("done"), "setup exit %d -> warning + command, postinst continues" % src_rc)
        rc, calls, out, err = go(opt=True)
        check(rc == 0 and not calls and "no-agent" in out and "sudo bash " + script in out, "opt-out -> skipped with the command")
        rc, calls, out, err = go(have_script=False)
        check(rc == 0 and "missing" in out and out.rstrip().endswith("done"), "script missing -> warning, no failure")
    finally:
        shutil.rmtree(d)


def t_agents_md_install():
    fn = func("agents_md_install")
    check("agents_md_install()" in fn, "postinst defines agents_md_install")
    d = tempfile.mkdtemp(prefix="pkg-agentsmd-")
    try:
        me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        src = d + "/AGENTS.md"
        with open(src, "w") as f:
            f.write("# agent\n")
        home = d + "/home"
        os.makedirs(home)
        rc, calls, out, err = bash_run(d, fn + 'agents_md_install "%s" "%s" "%s"\n' % (src, home, me))
        dst = home + "/.config/opencode/AGENTS.md"
        check(rc == 0 and os.path.isfile(dst) and "installed AGENTS.md" in out, "fresh home -> AGENTS.md installed (%s)" % err)
        check(os.stat(home + "/.config/opencode").st_mode & 0o777 == 0o700 and os.stat(dst).st_mode & 0o777 == 0o644,
              "config dir 0700, AGENTS.md 0644")
        with open(dst, "w") as f:
            f.write("edited\n")
        rc, calls, out, err = bash_run(d, fn + 'agents_md_install "%s" "%s" "%s"\n' % (src, home, me))
        check(rc == 0 and open(dst).read() == "edited\n" and not out.strip(), "an edited AGENTS.md is never clobbered")
        rc, calls, out, err = bash_run(d, fn + 'agents_md_install "%s" "%s/none" nosuchuser-tw\necho done\n' % (src, d))
        check(rc == 0 and out.strip() == "done" and not os.path.exists(d + "/none"), "no agent user -> nothing, no failure")
    finally:
        shutil.rmtree(d)


RSYSLOG_FAKES = {
    "rsyslogd": '#!/bin/sh\necho "rsyslogd $*" >> "$FAKE_LOG"\nexit "${FAKE_N1_RC:-0}"\n',
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$FAKE_LOG"\nexit 0\n',
}


def t_rsyslog_rule():
    fn = func("rsyslog_unbound_rule")
    check("rsyslog_unbound_rule()" in fn, "postinst defines rsyslog_unbound_rule")
    pre = "\n".join(l for l in SRC.splitlines() if l.startswith(("RSYSLOG_RULE_SRC=", "RSYSLOG_RULE=",
                                                                   "RSYSLOG_RULE_OLD="))) + "\n"
    body = SRC.split('case "$1" in\n  configure)', 1)[1]
    check('rsyslog_unbound_rule "${2:-}"' in body, "configure runs rsyslog_unbound_rule with the previous version")
    shipped = os.path.join(ROOT_DIR, "pkg/usr/share/tuxwall/rsyslog/45-tuxwall-unbound.conf")
    check(os.path.isfile(shipped), "rule ships under /usr/share/tuxwall/rsyslog")
    check(not os.path.exists(os.path.join(ROOT_DIR, "pkg/etc/rsyslog.d")), "no dpkg-tracked copy under pkg/etc/rsyslog.d")
    want = open(shipped).read()
    api = open(os.path.join(ROOT_DIR, "www/includes/api_server.py")).read()
    m = re.search(r"^UNBOUND_RSYSLOG_CONTENT = \(.*?^\)\n", api, re.M | re.S)
    ns = {}
    exec(m.group(0) if m else "", ns)
    check(ns.get("UNBOUND_RSYSLOG_CONTENT") == want, "API self-heal writes the packaged bytes")
    old_api = ("# TuxWall 2026-11-03: unbound's always_nxdomain block notifications feed\n"
               "# the dashboard Traffic Monitor via JOURNALD (journalctl -u unbound), not\n"
               "# from this file. Duplicating them into /var/log/syslog wrote ~583k\n"
               "# lines/day of noise for nothing. Drop them here; journald is unaffected\n"
               "# (and rate/size-capped by systemd).\n"
               "if $programname == 'unbound' and $msg contains 'always_nxdomain' then stop\n")

    def go(prev="", existing=None, n1_rc=0, rsyslog=True, mode=0o644):
        d = tempfile.mkdtemp(prefix="pkg-rsyslog-")
        fakebin(d, RSYSLOG_FAKES if rsyslog else {"systemctl": RSYSLOG_FAKES["systemctl"]})
        os.makedirs(d + "/rsyslog.d")
        dst = d + "/rsyslog.d/45-tuxwall-unbound.conf"
        if existing is not None:
            with open(dst, "w") as f:
                f.write(existing)
            os.chmod(dst, mode)
        rc, calls, out, err = bash_run(d, pre + fn + 'rsyslog_unbound_rule "%s" "%s" "%s"\n' % (prev, shipped, dst),
                                       env={"FAKE_N1_RC": str(n1_rc)}, path_extra=rsyslog)
        content = open(dst).read() if os.path.exists(dst) else None
        shutil.rmtree(d)
        return rc, calls, out.strip(), content

    rc, calls, out, c = go()
    check(rc == 0 and c == want and "rsyslogd -N1" in calls and "systemctl try-restart rsyslog.service" in calls,
          "fresh install: installed, checked, rsyslog restarted (%s %s)" % (out, calls))
    rc, calls, out, c = go(prev="3.3.4")
    check(rc == 0 and c == want and calls == [] and "not restarted" in out,
          "upgrade from 3.3.4 (dpkg removed its copy): restored, no restart (%s %s)" % (out, calls))
    rc, calls, out, c = go(prev="3.1.0")
    check(c == want and "systemctl try-restart rsyslog.service" in calls,
          "upgrade from a version that never shipped it: installed + restart (%s)" % calls)
    rc, calls, out, c = go(prev="3.3.4", existing=want)
    check(rc == 0 and c == want and calls == [] and "up to date" in out, "identical: untouched, no restart")
    rc, calls, out, c = go(prev="3.3.4", existing=old_api)
    check(c == want and calls == ["rsyslogd -N1", "systemctl try-restart rsyslog.service"],
          "older TuxWall copy: updated, checked, restarted (%s)" % calls)
    edited = want + "# mine\n"
    rc, calls, out, c = go(prev="3.3.4", existing=edited)
    check(rc == 0 and c == edited and calls == [] and "local edits" in out, "local edit: kept, no restart (%s)" % out)
    rc, calls, out, c = go(n1_rc=1)
    check(rc == 0 and c is None and calls == ["rsyslogd -N1"] and "previous state kept" in out,
          "rsyslogd -N1 rejects a new file: removed again, no restart (%s %s)" % (out, calls))
    rc, calls, out, c = go(prev="3.3.4", existing=old_api, n1_rc=1)
    check(rc == 0 and c == old_api and "systemctl try-restart rsyslog.service" not in calls,
          "rsyslogd -N1 rejects an update: old copy put back, no restart")
    rc, calls, out, c = go(rsyslog=False)
    check(rc == 0 and c is None and "not installed" in out, "no rsyslogd: skipped (%s)" % out)

    postrm = open(os.path.join(ROOT_DIR, "pkg/DEBIAN/postrm")).read()
    for arg, content, gone in (("remove", want, True), ("purge", old_api, True), ("remove", edited, False),
                               ("upgrade", want, False)):
        d = tempfile.mkdtemp(prefix="pkg-postrm-")
        fakebin(d, RSYSLOG_FAKES)
        dst = d + "/45-tuxwall-unbound.conf"
        with open(dst, "w") as f:
            f.write(content)
        script = postrm.replace("/etc/rsyslog.d/45-tuxwall-unbound.conf", dst)
        script = script.split('case "$1" in\n  purge)', 1)[0] + "exit 0\n"
        with open(d + "/postrm", "w") as f:
            f.write(script)
        e = dict(os.environ, FAKE_LOG=d + "/calls", PATH=d + "/fbin:" + os.environ.get("PATH", ""))
        p = subprocess.run(["bash", d + "/postrm", arg], env=e, capture_output=True, text=True, timeout=30)
        check(p.returncode == 0 and os.path.exists(dst) != gone,
              "postrm %s: rule %s" % (arg, "removed" if gone else "kept"))
        shutil.rmtree(d)


def t_agent_config_split():
    fn = func("agent_config_split")
    check("agent_config_split()" in fn, "postinst defines agent_config_split")
    d = tempfile.mkdtemp(prefix="pkg-ocsplit-")
    try:
        fakebin(d, {"systemctl": '#!/bin/sh\necho "systemctl $*" >> "$FAKE_LOG"\nexit 0\n'})
        helper = d + "/helper.py"
        for rc_h, msg, restart, want in ((0, "x is the shipped default", False, "shipped default"),
                                         (10, "moving providers.unsloth", True, "opencode.local.json"),
                                         (3, "lists differ - left as it is", False, "NOTE"),
                                         (1, "boom", False, "WARNING")):
            with open(helper, "w") as f:
                f.write("import sys\nassert sys.argv[1:] == ['migrate']\nprint(%r)\nsys.exit(%d)\n" % (msg, rc_h))
            rc, calls, out, err = bash_run(d, fn + 'agent_config_split "%s"\n' % helper)
            check(rc == 0 and want in out and msg in out, "split rc=%d -> %r (%s)" % (rc_h, want, out.strip()))
            check(("systemctl try-restart tuxwall-agent.service" in calls) == restart,
                  "split rc=%d: agent restarted only after a move (%s)" % (rc_h, calls))
        rc, calls, out, err = bash_run(d, fn + 'agent_config_split /nonexistent\n')
        check(rc == 0 and "missing" in out and calls == [], "helper missing -> skipped")
    finally:
        shutil.rmtree(d)


DW_FAKES = {
    # getent: users/groups listed in $FAKE_DB ("passwd NAME" / "group NAME" lines)
    "getent": '#!/bin/sh\ngrep -qx "$1 $2" "$FAKE_DB"\n',
    "useradd": '#!/bin/sh\necho "useradd $*" >> "$FAKE_LOG"\n[ -n "$FAKE_USERADD_FAIL" ] && exit 1\n'
               'for a; do last=$a; done; echo "passwd $last" >> "$FAKE_DB"\n',
    "usermod": '#!/bin/sh\necho "usermod $*" >> "$FAKE_LOG"\n',
    "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$FAKE_LOG"\n'
                 '[ "$1" = is-active ] && { echo active; exit 0; }\n'
                 '[ "$1" = enable ] && [ -n "$FAKE_ENABLE_FAIL" ] && exit 1\nexit 0\n',
}


def t_devicewatch_setup():
    fn = func("devicewatch_setup")
    check("devicewatch_setup()" in fn, "postinst defines devicewatch_setup")
    body = SRC[SRC.index('step 7 "'):]
    check('devicewatch_setup "$STATE_DIR/.devicewatch-enabled-once"' in body,
          "configure runs devicewatch_setup with the enable-once marker")

    def go(db, marker_exists=False, env=None):
        d = tempfile.mkdtemp(prefix="pkg-dw-")
        fakebin(d, DW_FAKES)
        with open(d + "/db", "w") as f:
            f.write("".join(x + "\n" for x in db))
        marker = d + "/marker"
        if marker_exists:
            open(marker, "w").close()
        os.makedirs(d + "/conf")
        with open(d + "/conf/abuse-ch.key", "w") as f:
            f.write("k\n")
        os.chmod(d + "/conf/abuse-ch.key", 0o644)
        rc, calls, out, err = bash_run(d, fn + 'devicewatch_setup "%s" "%s/conf"\n' % (marker, d),
                                       env=dict({"FAKE_DB": d + "/db"}, **(env or {})))
        res = (rc, calls, out, os.path.exists(marker), os.stat(d + "/conf/abuse-ch.key").st_mode & 0o777)
        shutil.rmtree(d)
        return res

    rc, calls, out, marked, kmode = go(["group zeek", "group systemd-journal"])
    check(rc == 0 and any(c.startswith("useradd --system --user-group") and c.endswith("tuxwall-devicewatch")
                          for c in calls), "fresh: system user created (%s)" % calls)
    check("usermod -a -G zeek tuxwall-devicewatch" in calls and "usermod -a -G systemd-journal tuxwall-devicewatch" in calls
          and not any("_kea" in c for c in calls), "groups added only where they exist (%s)" % calls)
    check("systemctl enable tuxwall-devicewatch.service tuxwall-devicewatch-feeds.timer" in calls and marked
          and "systemctl start --no-block tuxwall-devicewatch-feeds.service" in calls
          and "systemctl restart tuxwall-devicewatch.service" in calls, "fresh: enabled once, started, feeds in background")
    check(kmode == 0o600 and "zeek systemd-journal" in out, "key file tightened to 0600; status line names the groups (%r)" % out)
    rc, calls, out, marked, _k = go(["passwd tuxwall-devicewatch", "group _kea"], marker_exists=True)
    check(rc == 0 and not any(c.startswith(("useradd", "systemctl enable", "systemctl restart")) for c in calls)
          and "systemctl try-restart tuxwall-devicewatch.service" in calls,
          "upgrade (marker set): never re-enabled (owner choice kept), running engine restarted (%s)" % calls)
    rc, calls, out, marked, _k = go([], env={"FAKE_USERADD_FAIL": "1"})
    check(rc == 0 and not any(c.startswith("systemctl") for c in calls) and "not started" in out,
          "useradd failure: no units touched, postinst continues")
    rc, calls, out, marked, _k = go(["passwd tuxwall-devicewatch"], env={"FAKE_ENABLE_FAIL": "1"})
    check(rc == 0 and not marked and "systemctl restart tuxwall-devicewatch.service" not in calls,
          "failed enable: no marker (retried on the next upgrade)")
    prerm = open(PRERM).read()
    check("tuxwall-devicewatch.service" in prerm and ".devicewatch-enabled-once" in prerm, "prerm stops/disables device monitoring")
    postrm = open(os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postrm")).read()
    check("rm -rf /etc/tuxwall/devices" in postrm and "userdel tuxwall-devicewatch" in postrm,
          "postrm purge: overlays/key and the service user removed")


def main():
    for p in (POSTINST, PRERM, os.path.join(ROOT_DIR, "pkg", "DEBIAN", "postrm")):
        r = subprocess.run(["bash", "-n", p], capture_output=True, text=True)
        check(r.returncode == 0, "bash -n %s %s" % (os.path.basename(p), r.stderr))
    t_tripwire()
    t_bouncer()
    t_prerm()
    t_radvd()
    t_kea_hook()
    t_unbound_apply()
    t_firewall_fresh()
    t_nginx_listen_render()
    t_plugins_dir_perms()
    t_nat_ensure()
    t_agent_setup_step()
    t_agents_md_install()
    t_rsyslog_rule()
    t_agent_config_split()
    t_devicewatch_setup()
    print("pkg_scripts_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
