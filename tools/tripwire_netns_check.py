#!/usr/bin/env python3
"""Recovery-mode firewall + DNS validation in throwaway network namespaces
(root only, NOT part of CI). Never touches the live firewall or unbound:

  twr  "router"  WAN veth 203.0.113.2/24 + 2001:db8:f::2/64, LAN veth
                 10.99.0.1/24 + fd99::1/64, forwarding on, its OWN unbound
                 (an unconfined copy of the binary, control socket in a temp
                 dir) forwarding to the WAN DNS stub
  tww  "WAN"     gateway .1 / ::1, DNS stub 192.0.2.53 (allowed.test,
                 cdn.allowed.test -> CNAME, ntfy.test, denied.test), TLS
                 server :443 on every endpoint address, plain TCP :80
  twl  "LAN"     client 10.99.0.10 / fd99::10, fake local model :3000

The engine runs inside twr with TUXWALL_TRIPWIRE_ROOT (temp paths),
_NETNS=twr (real iptables/ipset inside the namespace) and
_UNBOUND_CONTROL pointing at the test unbound. Medium and high strength:
trip -> recovery (allowlist reachable v4+v6, denied blocked, DNS refused
for other names, LAN forwarding still blocked) -> extend -> expiry ->
end -> daemon re-apply/expiry -> resolve (everything removed). Before/after
snapshots of the live iptables/ip6tables/ipset/unbound zones must match.

  sudo python3 tools/tripwire_netns_check.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "pkg", "usr", "local", "sbin", "tuxwall-tripwire")
HELPERS = os.path.join(HERE, "tripwire_netns_helpers.py")
NS = ("twr", "tww", "twl")
PASS = FAIL = 0
RESULTS = []


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append(("ok  " if cond else "FAIL") + " " + name)
    print(RESULTS[-1], flush=True)


def sh(cmd, check_rc=False, **kw):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True,
                       timeout=kw.pop("timeout", 30), **kw)
    if check_rc and p.returncode != 0:
        raise RuntimeError("%s -> %s %s" % (cmd, p.returncode, p.stderr.strip()[-300:]))
    return p


def ns(name, cmd, **kw):
    return sh(["ip", "netns", "exec", name] + cmd, **kw)


def live_snapshot():
    def norm(txt):
        out = []
        for ln in txt.splitlines():
            if ln.startswith("#"):
                continue
            out.append(re.sub(r"\[\d+:\d+\]", "[0:0]", ln))
        return "\n".join(out)
    zones = sh("unbound-control list_local_zones | wc -l").stdout.strip()
    root = sh("unbound-control list_local_zones | awk '$1==\".\"' | wc -l").stdout.strip()
    return {"v4": norm(sh(["iptables-save"]).stdout), "v6": norm(sh(["ip6tables-save"]).stdout),
            "ipset": sh(["ipset", "list", "-n"]).stdout, "zones": zones, "root_zone": root,
            "netns": sh(["ip", "netns", "list"]).stdout}


class Env:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="tw4-netns-", dir="/tmp/opencode"
                                    if os.path.isdir("/tmp/opencode") else None)
        os.chmod(self.tmp, 0o755)
        self.root = os.path.join(self.tmp, "root")
        self.procs = []
        self.daemon = None

    # -- topology ---------------------------------------------------------
    def up(self):
        for n in NS:
            sh(["ip", "netns", "add", n], check_rc=True)
            ns(n, ["ip", "link", "set", "lo", "up"], check_rc=True)
        # created directly inside the namespaces: nothing ever appears in the
        # host namespace (networkd never sees the veths)
        ns("twr", "ip link add twr-wan type veth peer name tww-r netns tww".split(),
           check_rc=True)
        ns("twr", "ip link add twr-lan type veth peer name twl-r netns twl".split(),
           check_rc=True)
        cmds = {
            "twr": ["ip addr add 203.0.113.2/24 dev twr-wan",
                    "ip -6 addr add 2001:db8:f::2/64 dev twr-wan nodad",
                    "ip addr add 10.99.0.1/24 dev twr-lan",
                    "ip -6 addr add fd99::1/64 dev twr-lan nodad",
                    "ip link set twr-wan up", "ip link set twr-lan up",
                    "ip route add default via 203.0.113.1",
                    "ip -6 route add default via 2001:db8:f::1",
                    "sysctl -qw net.ipv4.ip_forward=1",
                    "sysctl -qw net.ipv6.conf.all.forwarding=1"],
            "tww": ["ip addr add 203.0.113.1/24 dev tww-r",
                    "ip -6 addr add 2001:db8:f::1/64 dev tww-r nodad",
                    "ip link set tww-r up", "ip link add ep type dummy", "ip link set ep up",
                    "ip route add 10.99.0.0/24 via 203.0.113.2",
                    "ip -6 route add fd99::/64 via 2001:db8:f::2"]
            + ["ip addr add 192.0.2.%d/32 dev ep" % i for i in (10, 11, 20, 30, 53)]
            + ["ip -6 addr add 2001:db8:a::%d/128 dev ep nodad" % i for i in (10, 11, 20, 30)],
            "twl": ["ip addr add 10.99.0.10/24 dev twl-r",
                    "ip -6 addr add fd99::10/64 dev twl-r nodad", "ip link set twl-r up",
                    "ip route add default via 10.99.0.1",
                    "ip -6 route add default via fd99::1"],
        }
        for n, cl in cmds.items():
            for c in cl:
                ns(n, c.split(), check_rc=True)

    def start_services(self):
        cert, key = os.path.join(self.tmp, "c.pem"), os.path.join(self.tmp, "k.pem")
        sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=test", "-keyout", key, "-out", cert], check_rc=True)
        self.dnslog = os.path.join(self.tmp, "dns.log")
        py = sys.executable
        self.spawn("tww", [py, "-B", HELPERS, "dns", "192.0.2.53", self.dnslog])
        self.spawn("tww", [py, "-B", HELPERS, "https", cert, key, "443"])
        self.spawn("tww", [py, "-B", HELPERS, "tcp", "80"])
        self.spawn("twl", [py, "-B", HELPERS, "tcp", "3000"])
        self.spawn("twr", [py, "-B", HELPERS, "tcp", "2222"])
        # the router's resolver: an unconfined copy of unbound (the AppArmor
        # profile is attached to /usr/sbin/unbound's path)
        ud = os.path.join(self.tmp, "unbound")
        os.makedirs(ud)
        os.chmod(ud, 0o755)
        shutil.copy2("/usr/sbin/unbound", os.path.join(ud, "unbound-test"))
        self.uconf = os.path.join(ud, "unbound.conf")
        with open(self.uconf, "w") as f:
            f.write("""server:
  interface: 127.0.0.1
  interface: ::1
  interface: 10.99.0.1
  port: 53
  access-control: 0.0.0.0/0 allow
  access-control: ::/0 allow
  do-ip6: yes
  username: "unbound"
  chroot: ""
  directory: "%(d)s"
  pidfile: "%(d)s/unbound.pid"
  use-syslog: no
  logfile: ""
  verbosity: 0
  module-config: "iterator"
  qname-minimisation: no
  local-zone: "test." nodefault
  local-zone: "home.arpa." static
  local-data: "router.home.arpa. A 10.99.0.1"
remote-control:
  control-enable: yes
  control-interface: %(d)s/ctl.sock
  control-use-cert: no
forward-zone:
  name: "."
  forward-addr: 192.0.2.53
""" % {"d": ud})
        os.chmod(self.uconf, 0o644)
        self.spawn("twr", [os.path.join(ud, "unbound-test"), "-d", "-c", self.uconf])
        self.ubc = "unbound-control -c %s" % self.uconf
        for _ in range(50):
            if sh(self.ubc + " status").returncode == 0:
                break
            time.sleep(0.2)
        time.sleep(0.5)

    def spawn(self, n, cmd):
        self.procs.append(subprocess.Popen(["ip", "netns", "exec", n] + cmd,
                                           stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL))

    def engine_env(self):
        return dict(
            os.environ, TUXWALL_TRIPWIRE_ROOT=self.root, TUXWALL_TRIPWIRE_NETNS="twr",
            TUXWALL_TRIPWIRE_WAN="twr-wan", TUXWALL_TRIPWIRE_DNS="127.0.0.1",
            TUXWALL_TRIPWIRE_UNBOUND_CONTROL=self.ubc,
            TUXWALL_TRIPWIRE_PUSH_FILE=os.path.join(self.tmp, "push.jsonl"),
            TUXWALL_TRIPWIRE_OWN_IPS="203.0.113.2/24 10.99.0.1/24 127.0.0.1/8",
            TUXWALL_TRIPWIRE_LAN_NETS="10.99.0.1/24 fd99::1/64",
            TUXWALL_TRIPWIRE_KERNEL_CMD="tail -n 0 -F %s" % os.path.join(self.tmp, "kern.log"),
            TUXWALL_TRIPWIRE_EVE=os.path.join(self.tmp, "eve.json"),
            TUXWALL_TRIPWIRE_TICK="0.5", TUXWALL_TRIPWIRE_ENFORCE_S="1",
            TUXWALL_TRIPWIRE_RECOVERY_REFRESH="3")

    def engine(self, *args, stdin=""):
        p = sh(["ip", "netns", "exec", "twr", sys.executable, "-B", ENGINE] + list(args),
               input=stdin, env=self.engine_env(), timeout=90)
        try:
            return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return p.returncode, p.stdout + p.stderr

    def configure(self):
        os.makedirs(self.root + "/etc/tuxwall", exist_ok=True)
        os.makedirs(self.root + "/var/log/tuxwall", exist_ok=True)
        with open(self.root + "/etc/tuxwall/opencode.json", "w") as f:
            json.dump({"model": "custom/m1", "providers": {
                "custom": {"settings": {"baseURL": "https://allowed.test/v1"}, "models": {"m1": {}}},
                "cdn": {"settings": {"baseURL": "https://cdn.allowed.test/v1"}},
                "lan": {"name": "LAN model", "settings": {"baseURL": "http://10.99.0.10:3000/v1"},
                        "models": {"q": {}}}}}, f)
        with open(self.root + "/etc/tuxwall/alerts.json", "w") as f:
            json.dump({"enabled": True, "ntfy_url": "https://ntfy.test/topic"}, f)
        with open(self.root + "/etc/tuxwall/tripwire.json", "w") as f:
            json.dump({"mode": "logonly"}, f)
        open(os.path.join(self.tmp, "kern.log"), "w").close()
        open(os.path.join(self.tmp, "eve.json"), "w").close()

    def state(self):
        try:
            with open(self.root + "/etc/tuxwall/tripwire-state.json") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def set_state(self, fn):
        st = self.state()
        fn(st)
        with open(self.root + "/etc/tuxwall/tripwire-state.json", "w") as f:
            json.dump(st, f)

    def down(self):
        if self.daemon:
            self.daemon.terminate()
            try:
                self.daemon.wait(10)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        for n in NS:
            sh(["ip", "netns", "del", n])
        shutil.rmtree(self.tmp, ignore_errors=True)


# -- probes ------------------------------------------------------------------
def curl(n, url, fam=None, resolve=None, t=4):
    cmd = ["curl", "-sk", "--max-time", str(t), "-o", "/dev/null", "-w", "%{http_code}"]
    if fam:
        cmd.append("-" + fam)
    if resolve:
        cmd += ["--resolve", resolve]
    return ns(n, cmd + [url], timeout=t + 5).stdout.strip() == "200"


def tcp(n, host, port, t=3):
    code = ("import socket,sys\ntry:\n socket.create_connection((%r,%d),%d).close()\n"
            "except OSError: sys.exit(1)" % (host, port, t))
    return ns(n, [sys.executable, "-c", code], timeout=t + 5).returncode == 0


def dig(n, name, server="127.0.0.1", qtype="A"):
    out = ns(n, ["dig", "+time=2", "+tries=1", "@" + server, name, qtype]).stdout
    m = re.search(r"status: (\w+)", out)
    ans = re.findall(r"^\S+\s+\d+\s+IN\s+(?:A|AAAA|CNAME)\s+(\S+)", out, re.M)
    return (m.group(1) if m else "TIMEOUT"), ans


def rules(n="twr"):
    return ns(n, ["iptables-save"]).stdout + ns(n, ["ip6tables-save"]).stdout


def lan_blocked():
    return (not curl("twl", "https://192.0.2.10/", t=3)
            and not curl("twl", "https://[2001:db8:a::10]/", t=3))


def recovery_checks(E, tag, high):
    st = E.state()
    check(st.get("recovery", {}).get("active"), "%s: recovery active in state" % tag)
    check(lan_blocked(), "%s: LAN forwarding still blocked (v4+v6)" % tag)
    check(curl("twr", "https://allowed.test/", "4") and curl("twr", "https://allowed.test/", "6"),
          "%s: router -> allowed endpoint over HTTPS (v4 + v6)" % tag)
    check(curl("twr", "https://cdn.allowed.test/", "4"), "%s: CNAME'd allowed name" % tag)
    check(curl("twr", "https://ntfy.test/", "4"), "%s: router -> ntfy allowed" % tag)
    check(not curl("twr", "https://denied.test/", t=3), "%s: denied name fails" % tag)
    check(dig("twr", "denied.test")[0] == "REFUSED", "%s: DNS refuses denied names" % tag)
    s, a = dig("twr", "allowed.test")
    check(s == "NOERROR" and "192.0.2.10" in a, "%s: DNS answers allowed names" % tag)
    check(not curl("twr", "https://denied.test/", "4", "denied.test:443:192.0.2.20", t=3)
          and not curl("twr", "https://denied.test/", "6", "denied.test:443:[2001:db8:a::20]",
                       t=3), "%s: denied IP blocked even without DNS (v4 + v6)" % tag)
    check(not tcp("twr", "192.0.2.10", 80), "%s: allowed host, other port blocked" % tag)
    check(dig("twr", "allowed.test", server="192.0.2.53")[0] == "TIMEOUT",
          "%s: direct DNS to the internet blocked (only the resolver's uid)" % tag)
    check(dig("twl", "denied.test", server="10.99.0.1")[0] == "REFUSED"
          and "10.99.0.1" in dig("twl", "router.home.arpa", server="10.99.0.1")[1],
          "%s: LAN DNS: denied refused, router local zone still answers" % tag)
    r = rules()
    check("TUXWALL-TRIPWIRE-RECOVERY" in r and "--comment TUXWALL-TRIPWIRE -j DROP" in r,
          "%s: recovery rules on top of the trip block" % tag)
    if high:
        check(not tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router new connection blocked"
              % tag)


def full_block_checks(E, tag, high):
    r = rules()
    check("TUXWALL-TRIPWIRE-RECOVERY" not in r and "--comment TUXWALL-TRIPWIRE -j DROP" in r,
          "%s: recovery rules gone, trip block kept" % tag)
    check(ns("twr", ["ipset", "list", "-n"]).stdout.strip() == "", "%s: sets destroyed" % tag)
    check(lan_blocked(), "%s: LAN still blocked" % tag)
    s, a = dig("twr", "denied.test")
    check(s == "NOERROR", "%s: DNS restriction lifted" % tag)
    check(curl("twr", "https://denied.test/", "4"),
          "%s: router back to the trip state (its own egress is not restricted by a trip)" % tag)
    if high:
        check(not tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router still blocked" % tag)


def scenario(E, mode):
    high = mode == "high"
    tag = mode.upper()
    rc, out = E.engine("trip", "netns test", "--mode", mode)
    check("TRIPPED" in str(out), "%s: trip" % tag)
    check(lan_blocked(), "%s: tripped: LAN blocked" % tag)
    if not high:
        check(tcp("tww", "203.0.113.2", 2222), "MEDIUM: WAN -> router stays reachable")
    rc, js = E.engine("recovery-start", "--minutes", "15", "--by", "netns", stdin="{}")
    check(rc == 0 and isinstance(js, dict) and js.get("phase") == "recovery",
          "%s: recovery-start (%s)" % (tag, str(js)[:200]))
    rec = (js or {}).get("recovery") or {} if isinstance(js, dict) else {}
    check({h["host"] for h in rec.get("hosts", [])} >= {"allowed.test", "cdn.allowed.test",
                                                         "ntfy.test"},
          "%s: allowlist from the opencode config + alerts.json" % tag)
    check(any(e["host"] == "10.99.0.10" and e["reachable"] for e in rec.get("local", [])),
          "%s: LAN model reachable (no internet needed)" % tag)
    check(rec.get("dns", {}).get("state") == "restricted", "%s: DNS restricted" % tag)
    q0 = open(E.dnslog).read().count("denied.test")
    recovery_checks(E, tag, high)
    check(open(E.dnslog).read().count("denied.test") == q0,
          "%s: no upstream query for denied names during recovery" % tag)
    exp = E.state()["recovery"]["expires"]
    rc, js = E.engine("recovery-extend", "--minutes", "30", "--by", "netns")
    check(rc == 0 and abs(E.state()["recovery"]["expires"] - exp - 1800) < 2,
          "%s: extend +30 min" % tag)
    # expiry (ExecStartPre / ufw-reload path)
    E.set_state(lambda s: s["recovery"].__setitem__("expires", time.time() - 1))
    rc, out = E.engine("enforce")
    check("recovery: expired" in str(out) and "recovery" not in E.state(),
          "%s: expiry -> back to full block" % tag)
    full_block_checks(E, tag + " expired", high)
    # end recovery
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    recovery_checks(E, tag + " #2", high)
    rc, js = E.engine("recovery-end", "--by", "netns")
    check(rc == 0 and js.get("ended"), "%s: recovery-end" % tag)
    full_block_checks(E, tag + " ended", high)
    # daemon: re-apply after a flush and an unbound restart, then expiry
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    E.daemon = subprocess.Popen(["ip", "netns", "exec", "twr", sys.executable, "-B", ENGINE,
                                 "run"], env=E.engine_env(), stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
    time.sleep(2)
    for ipt in ("iptables", "ip6tables"):
        for ln in ns("twr", [ipt, "-S", "OUTPUT"]).stdout.splitlines():
            if "TUXWALL-TRIPWIRE-RECOVERY" in ln:
                ns("twr", [ipt] + ["-D"] + ln.split()[1:])
    sh(E.ubc + " local_zone_remove .")
    sh(E.ubc + " local_zone_remove tuxwall-recovery.invalid.")
    check(dig("twr", "denied.test")[0] == "NOERROR", "%s: (simulated unbound restart)" % tag)
    ok = False
    for _ in range(30):
        time.sleep(0.5)
        if ("TUXWALL-TRIPWIRE-RECOVERY" in rules()
                and dig("twr", "denied.test")[0] == "REFUSED"):
            ok = True
            break
    check(ok, "%s: daemon re-applies the rules and the DNS restriction" % tag)
    check(curl("twr", "https://allowed.test/", "4") and not curl("twr", "https://denied.test/",
                                                                 t=3),
          "%s: allowlist works again after re-apply" % tag)
    E.set_state(lambda s: s["recovery"].__setitem__("expires", time.time() + 2))
    ok = False
    for _ in range(30):
        time.sleep(0.5)
        if "recovery" not in E.state() and "TUXWALL-TRIPWIRE-RECOVERY" not in rules():
            ok = True
            break
    check(ok and E.state().get("recovery_last", {}).get("how") == "expired",
          "%s: daemon timer expires recovery" % tag)
    full_block_checks(E, tag + " daemon-expired", high)
    E.daemon.terminate()
    E.daemon.wait(10)
    E.daemon = None
    # resolve from recovery
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    rc, js = E.engine("restore", "--by", "netns", stdin=json.dumps({"checklist": {
        "findings": True, "cause": True}}))
    check(rc == 2 and E.state().get("tripped"), "%s: restore refuses an incomplete checklist"
          % tag)
    rc, js = E.engine("restore", "--by", "netns", stdin=json.dumps({"checklist": {
        "findings": True, "cause": True, "confirm": True}, "note": "netns"}))
    check(rc == 0 and not E.state().get("tripped"), "%s: restore (resolve)" % tag)
    r = rules()
    check("TUXWALL" not in r, "%s: resolve removes every tripwire/recovery rule" % tag)
    check(ns("twr", ["ipset", "list", "-n"]).stdout.strip() == "", "%s: no sets left" % tag)
    check(dig("twr", "denied.test")[0] == "NOERROR", "%s: DNS unrestricted" % tag)
    check(curl("twl", "https://192.0.2.10/") and curl("twl", "https://[2001:db8:a::10]/"),
          "%s: LAN forwarding restored (v4 + v6)" % tag)
    check(tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router reachable again" % tag)


def main():
    if os.geteuid() != 0:
        print("run as root")
        return 2
    existing = sh(["ip", "netns", "list"]).stdout.split()
    if any(n in existing for n in NS):
        print("test namespaces already exist - refusing")
        return 2
    before = live_snapshot()
    E = Env()
    try:
        E.up()
        E.start_services()
        E.configure()
        check(curl("twl", "https://192.0.2.10/") and curl("twl", "https://[2001:db8:a::10]/"),
              "baseline: LAN -> WAN forwarding works (v4 + v6)")
        check(curl("twr", "https://denied.test/", "4") and curl("twr", "https://allowed.test/",
                                                                "6"),
              "baseline: router resolves + reaches every endpoint")
        check(tcp("tww", "203.0.113.2", 2222), "baseline: WAN -> router reachable")
        for mode in ("medium", "high"):
            scenario(E, mode)
    finally:
        E.down()
    after = live_snapshot()
    for k in ("v4", "v6", "ipset", "zones", "root_zone", "netns"):
        check(before[k] == after[k], "live %s unchanged" % k)
    print("tripwire_netns_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
