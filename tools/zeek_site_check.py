#!/usr/bin/env python3
"""pkg/usr/local/share/tuxwall/scripts/zeek-site-setup.sh against a fake
Zeek site directory and a fake zeekctl / systemd-detect-virt (temp dirs only).

- mac-logging policy written + loaded from local.zeek once, local.zeek
  backed up (.pre-tuxwall), zeekctl check then deploy while Zeek runs;
- a second run changes nothing and calls no zeekctl;
- ignore_checksums only on a VM or with --ignore-checksums (then kept);
  --checksums on|off (the dashboard switch): explicit, off wins over the VM
  default, mac-logging always stays, the previous policy kept as .prev;
  a bad value / unknown option exits 2 without touching anything;
- a failed `zeekctl deploy` restores both files and redeploys them (exit 2);
- a failed `zeekctl check` restores both files (exit 1);
- Zeek stopped / --no-deploy: files written, no deploy; no Zeek: exit 0.

    python3 tools/zeek_site_check.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "pkg", "usr", "local", "share", "tuxwall", "scripts", "zeek-site-setup.sh")
PASS = FAIL = 0
TMP = tempfile.mkdtemp(prefix="zeek-site-")
LOCAL = "@load misc/loaded-scripts\n@load policy/tuning/json-logs\n"

ZEEKCTL = """#!/bin/sh
echo "zeekctl $*" >> "$FAKE_LOG"
case "$1" in
  status) [ -n "$FAKE_STOPPED" ] && { echo "worker-1 worker localhost stopped"; exit 1; }
          echo "worker-1 worker localhost running 123"; exit 0 ;;
  check) [ -n "$FAKE_CHECK_FAIL" ] && { echo "error in local.zeek"; exit 1; }; echo "worker-1 scripts are ok."; exit 0 ;;
  deploy) [ -n "$FAKE_DEPLOY_FAIL" ] && { echo "deploy failed"; exit 1; }; exit 0 ;;
esac
exit 0
"""
VIRT = """#!/bin/sh
echo "systemd-detect-virt $*" >> "$FAKE_LOG"
[ -n "$FAKE_VM" ] && exit 0
exit 1
"""


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def site(name, local=LOCAL):
    d = os.path.join(TMP, name)
    os.makedirs(os.path.join(d, "site"))
    os.makedirs(os.path.join(d, "bin"))
    with open(os.path.join(d, "site", "local.zeek"), "w") as f:
        f.write(local)
    for n, body in (("zeekctl", ZEEKCTL), ("systemd-detect-virt", VIRT)):
        p = os.path.join(d, "bin", n)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)
    return d


def run(d, *args, env=None):
    e = dict(os.environ, FAKE_LOG=os.path.join(d, "calls"), ZEEKCTL=os.path.join(d, "bin", "zeekctl"),
             PATH=os.path.join(d, "bin") + ":/usr/bin:/bin")
    e.update(env or {})
    if os.path.exists(e["FAKE_LOG"]):
        os.unlink(e["FAKE_LOG"])
    p = subprocess.run(["bash", SCRIPT] + list(args) + [os.path.join(d, "site")], capture_output=True, text=True,
                       env=e, timeout=60)
    calls = open(e["FAKE_LOG"]).read().splitlines() if os.path.exists(e["FAKE_LOG"]) else []
    return p.returncode, p.stdout + p.stderr, [c for c in calls if c.startswith("zeekctl")]


def read(d, name):
    p = os.path.join(d, "site", name)
    return open(p).read() if os.path.exists(p) else None


def main():
    check(os.access(SCRIPT, os.X_OK), "script is executable")
    d = site("bare")
    rc, out, calls = run(d)
    pol, loc = read(d, "tuxwall-devicewatch.zeek"), read(d, "local.zeek")
    check(rc == 0 and "@load policy/protocols/conn/mac-logging" in pol and "ignore_checksums" not in pol,
          "bare metal: mac-logging, no ignore_checksums (%r)" % out)
    check(loc.startswith(LOCAL) and loc.count("@load ./tuxwall-devicewatch.zeek") == 1
          and read(d, "local.zeek.pre-tuxwall") == LOCAL, "local.zeek loads the policy once; backup kept")
    check(calls == ["zeekctl status", "zeekctl check", "zeekctl deploy"] and "deployed" in out,
          "running Zeek: check, then deploy (%r)" % calls)
    check(oct(os.stat(os.path.join(d, "site", "tuxwall-devicewatch.zeek")).st_mode & 0o777) == oct(0o644), "policy 0644")
    rc, out, calls = run(d)
    check(rc == 0 and not calls and "up to date" in out and read(d, "local.zeek") == loc,
          "second run: nothing to do, Zeek untouched")
    # a site whose local.zeek already loads the policy (by hand)
    d = site("byhand", LOCAL + "@load tuxwall-devicewatch\n")
    run(d)
    check(read(d, "local.zeek").count("tuxwall-devicewatch") == 1, "an existing @load line is recognised")
    # VM: ignore_checksums
    d = site("vm")
    rc, out, _c = run(d, env={"FAKE_VM": "1"})
    check(rc == 0 and "redef ignore_checksums = T;" in read(d, "tuxwall-devicewatch.zeek") and "ignore_checksums" in out,
          "virtual machine: ignore_checksums added")
    # chosen by hand, kept on the next (postinst) run
    d = site("forced")
    run(d, "--ignore-checksums")
    rc, out, calls = run(d)
    check("redef ignore_checksums = T;" in read(d, "tuxwall-devicewatch.zeek") and not calls,
          "--ignore-checksums kept on later runs without the flag")
    # the dashboard switch: --checksums on|off
    d = site("switch")
    run(d)
    rc, out, calls = run(d, "--checksums", "on")
    pol = read(d, "tuxwall-devicewatch.zeek")
    check(rc == 0 and "redef ignore_checksums = T;" in pol and "mac-logging" in pol
          and calls == ["zeekctl status", "zeekctl check", "zeekctl deploy"]
          and "ignore_checksums" not in (read(d, "tuxwall-devicewatch.zeek.prev") or "x"),
          "--checksums on: added, checked, deployed, previous policy kept as .prev (%r)" % out)
    rc, out, calls = run(d, "--checksums", "off")
    pol = read(d, "tuxwall-devicewatch.zeek")
    check(rc == 0 and "ignore_checksums" not in pol and "@load policy/protocols/conn/mac-logging" in pol
          and "zeekctl deploy" in calls, "--checksums off: removed again, mac-logging stays")
    rc, out, calls = run(d, "--checksums=off")
    check(rc == 0 and not calls and "up to date" in out, "--checksums=off again: nothing to do")
    d = site("vmoff")
    rc, out, _c = run(d, "--checksums", "off", env={"FAKE_VM": "1"})
    check(rc == 0 and "ignore_checksums" not in read(d, "tuxwall-devicewatch.zeek"),
          "--checksums off wins over the virtual-machine default")
    d = site("badarg")
    for args in (("--checksums", "maybe"), ("--checksums",), ("--bogus",)):
        rc, out, calls = run(d, *args)
        check(rc == 2 and not calls and read(d, "tuxwall-devicewatch.zeek") is None and read(d, "local.zeek") == LOCAL,
              "%r: exit 2, nothing touched" % (args,))
    # zeekctl deploy fails: files restored, the old policy deployed again
    d = site("deployfail")
    run(d)
    before = (read(d, "local.zeek"), read(d, "tuxwall-devicewatch.zeek"))
    rc, out, calls = run(d, "--checksums", "on", env={"FAKE_DEPLOY_FAIL": "1"})
    check(rc == 2 and (read(d, "local.zeek"), read(d, "tuxwall-devicewatch.zeek")) == before
          and calls.count("zeekctl deploy") == 2 and "restored" in out,
          "failed deploy: previous files restored and redeployed (%r %r)" % (calls, out))
    # zeekctl check fails: both files restored
    d = site("fail")
    rc, out, calls = run(d, env={"FAKE_CHECK_FAIL": "1"})
    check(rc == 1 and read(d, "local.zeek") == LOCAL and read(d, "tuxwall-devicewatch.zeek") is None
          and "zeekctl deploy" not in calls and "restored" in out, "failed check: previous files restored, no deploy")
    # stopped Zeek / --no-deploy
    d = site("stopped")
    rc, out, calls = run(d, env={"FAKE_STOPPED": "1"})
    check(rc == 0 and calls == ["zeekctl status"] and "not running" in out and read(d, "tuxwall-devicewatch.zeek"),
          "Zeek stopped: written, not deployed")
    d = site("nodeploy")
    rc, out, calls = run(d, "--no-deploy")
    check(rc == 0 and not calls and "next 'zeekctl deploy'" in out, "--no-deploy: written only")
    # no Zeek at all
    e = os.path.join(TMP, "none")
    os.makedirs(os.path.join(e, "site"))
    os.makedirs(os.path.join(e, "bin"))
    rc, out, calls = run(e)
    check(rc == 0 and "not installed" in out and not os.listdir(os.path.join(e, "site")), "no Zeek: exit 0, nothing written")
    post = open(os.path.join(ROOT, "pkg", "DEBIAN", "postinst")).read()
    check("FRESH_INSTALL" in post and "zeek-site-setup.sh" in post, "postinst runs it on fresh installs")
    shutil.rmtree(TMP, ignore_errors=True)
    print("zeek_site_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
