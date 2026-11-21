#!/usr/bin/env python3
"""Tripwire containment (trip, tripped egress, recovery, resolve) validated
with the real rules in throwaway network namespaces (root only, NOT part of
CI). Never touches the live firewall, nftables or unbound:

  twr  "router"  WAN veth 203.0.113.2/24 + 2001:db8:f::2/64, LAN veth
                 10.99.0.1/24 + fd99::1/64, "VLAN" veth 10.97.0.1/24 +
                 fd97::1/64, WireGuard wg0 10.98.0.1/24 (:51820 on the WAN),
                 forwarding on, its OWN unbound (an unconfined copy of the
                 binary, control socket in a temp dir) forwarding to the WAN
                 DNS stub, ufw-style canary containment (uid nobody: LOG
                 [TUXWALL-CANARY-EGRESS] + REJECT in ufw-before-output) and
                 CrowdSec-style nftables tables (ip crowdsec / ip6 crowdsec6 /
                 inet tuxwall_crowdsec_ranges, input hook priority -10)
  tww  "WAN"     gateway .1 / ::1, DNS stub 192.0.2.53 (allowed.test,
                 cdn.allowed.test -> CNAME, ntfy.test, denied.test), TLS
                 :443 on every endpoint address, TCP :80 and :4460 (NTS-KE),
                 UDP echo :123 (NTP), :67 (DHCP), :547 (DHCPv6); a banned
                 source 203.0.113.66
  twl  "LAN"     client 10.99.0.10 / fd99::10, fake local model :3000
  twi  "VLAN"    IoT host 10.97.0.10 / fd97::10, :3000
  twv  "VPN"     road-warrior WireGuard client 10.98.0.2 behind the
                 internet (198.51.100.50 via tww)

The engine runs inside twr with TUXWALL_TRIPWIRE_ROOT (temp paths),
_NETNS=twr (real iptables/ipset inside the namespace) and
_UNBOUND_CONTROL pointing at the test unbound. Medium and high strength:
trip (LAN<->WAN both ways v4+v6, medium: VPN->LAN + LAN<->VLAN still pass;
router egress only DNS-from-unbound / NTP-from-chrony / DHCP / ND / push
target; canary still logged by its own containment) -> recovery (AI
allowlist widened, DNS restricted) -> extend -> expiry / end (back to the
tripped egress) -> daemon re-applies flushed / out-of-order rules -> resolve
(everything removed). The CrowdSec nft tables must stay identical and keep
dropping the banned source. Before/after snapshots of the live
iptables/ip6tables/ipset/nft crowdsec tables/unbound zones must match.

  sudo python3 tools/tripwire_netns_check.py
"""
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ENGINE = os.path.join(HERE, "..", "pkg", "usr", "local", "sbin", "tuxwall-tripwire")
HELPERS = os.path.join(HERE, "tripwire_netns_helpers.py")
NS = ("twr", "tww", "twl", "twi", "twv")
CS_TABLES = (("ip", "crowdsec"), ("ip6", "crowdsec6"), ("inet", "tuxwall_crowdsec_ranges"))
NTP_USER = "_chrony" if any(p.pw_name == "_chrony" for p in pwd.getpwall()) else "nobody"
CANARY_USER = "nobody"
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


def as_user(user):
    pw = pwd.getpwnam(user)
    return ["setpriv", "--reuid", str(pw.pw_uid), "--regid", str(pw.pw_gid), "--clear-groups"]


def _strip_nft(txt):
    out = []
    for ln in txt.splitlines():
        ln = re.sub(r"counter packets \d+ bytes \d+", "counter", ln)
        ln = re.sub(r"^\s*packets \d+ bytes \d+\s*$", "", ln)
        if ln.strip():
            out.append(ln.rstrip())
    return "\n".join(out)


def nft_tables(n=None):
    """The CrowdSec tables (terse: no set elements), counters stripped."""
    out = {}
    for fam, name in CS_TABLES:
        cmd = ["nft", "-t", "list", "table", fam, name]
        p = ns(n, cmd) if n else sh(cmd)
        out["%s %s" % (fam, name)] = _strip_nft(p.stdout) if p.returncode == 0 else "(absent)"
    return out


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
            "ipset": sh(["ipset", "list"]).stdout, "nft-crowdsec": json.dumps(nft_tables()),
            "zones": zones, "root_zone": root, "netns": sh(["ip", "netns", "list"]).stdout}


class Env:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="tw5-netns-", dir="/tmp/opencode"
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
        for a, b, peer in (("twr", "twr-wan", "tww-r tww"), ("twr", "twr-lan", "twl-r twl"),
                           ("twr", "twr-iot", "twi-r twi"), ("tww", "tww-v", "twv-w twv")):
            p, pn = peer.split()
            ns(a, ["ip", "link", "add", b, "type", "veth", "peer", "name", p, "netns", pn],
               check_rc=True)
        cmds = {
            "twr": ["ip addr add 203.0.113.2/24 dev twr-wan",
                    "ip -6 addr add 2001:db8:f::2/64 dev twr-wan nodad",
                    "ip addr add 10.99.0.1/24 dev twr-lan",
                    "ip -6 addr add fd99::1/64 dev twr-lan nodad",
                    "ip addr add 10.97.0.1/24 dev twr-iot",
                    "ip -6 addr add fd97::1/64 dev twr-iot nodad",
                    "ip link set twr-wan up", "ip link set twr-lan up", "ip link set twr-iot up",
                    "ip route add default via 203.0.113.1",
                    "ip -6 route add default via 2001:db8:f::1",
                    "sysctl -qw net.ipv4.ip_forward=1",
                    "sysctl -qw net.ipv6.conf.all.forwarding=1"],
            "tww": ["ip addr add 203.0.113.1/24 dev tww-r",
                    "ip addr add 203.0.113.66/24 dev tww-r",
                    "ip -6 addr add 2001:db8:f::1/64 dev tww-r nodad",
                    "ip addr add 198.51.100.1/24 dev tww-v",
                    "ip link set tww-r up", "ip link set tww-v up",
                    "ip link add ep type dummy", "ip link set ep up",
                    "ip route add 10.99.0.0/24 via 203.0.113.2",
                    "ip route add 10.97.0.0/24 via 203.0.113.2",
                    "ip route add 10.98.0.0/24 via 203.0.113.2",
                    "ip -6 route add fd99::/64 via 2001:db8:f::2",
                    "ip -6 route add fd97::/64 via 2001:db8:f::2",
                    "sysctl -qw net.ipv4.ip_forward=1"]
            + ["ip addr add 192.0.2.%d/32 dev ep" % i for i in (10, 11, 20, 30, 53, 123)]
            + ["ip -6 addr add 2001:db8:a::%d/128 dev ep nodad" % i for i in (10, 11, 20, 30, 123)],
            "twl": ["ip addr add 10.99.0.10/24 dev twl-r",
                    "ip -6 addr add fd99::10/64 dev twl-r nodad", "ip link set twl-r up",
                    "ip route add default via 10.99.0.1",
                    "ip -6 route add default via fd99::1"],
            "twi": ["ip addr add 10.97.0.10/24 dev twi-r",
                    "ip -6 addr add fd97::10/64 dev twi-r nodad", "ip link set twi-r up",
                    "ip route add default via 10.97.0.1",
                    "ip -6 route add default via fd97::1"],
            "twv": ["ip addr add 198.51.100.50/24 dev twv-w", "ip link set twv-w up",
                    "ip route add default via 198.51.100.1"],
        }
        for n, cl in cmds.items():
            for c in cl:
                ns(n, c.split(), check_rc=True)
        self.wireguard()
        self.router_firewall()

    def wireguard(self):
        # an unconfined copy: the wg AppArmor profile only reads keys under
        # /etc/wireguard
        wg = os.path.join(self.tmp, "wg-test")
        shutil.copy2("/usr/bin/wg", wg)
        keys = {}
        for who in ("r", "c"):
            priv = sh([wg, "genkey"], check_rc=True).stdout.strip()
            path = os.path.join(self.tmp, "wg-%s.key" % who)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(priv + "\n")
            keys[who] = (path, sh([wg, "pubkey"], input=priv + "\n", check_rc=True).stdout.strip())
        for n, me, peer, extra in (
                ("twr", "r", "c", ["listen-port", "51820"]),
                ("twv", "c", "r", [])):
            ns(n, ["ip", "link", "add", "wg0", "type", "wireguard"], check_rc=True)
            peer_opts = (["allowed-ips", "10.98.0.2/32"] if n == "twr" else
                         ["endpoint", "203.0.113.2:51820",
                          "allowed-ips", "10.98.0.0/24,10.99.0.0/24,192.0.2.0/24"])
            ns(n, [wg, "set", "wg0"] + extra + ["private-key", keys[me][0], "peer", keys[peer][1]]
               + peer_opts, check_rc=True)
            ns(n, ["ip", "addr", "add", "10.98.0.%d/24" % (1 if n == "twr" else 2), "dev", "wg0"],
               check_rc=True)
            ns(n, ["ip", "link", "set", "wg0", "up"], check_rc=True)
        for net in ("10.99.0.0/24", "192.0.2.0/24"):
            ns("twv", ["ip", "route", "add", net, "dev", "wg0"], check_rc=True)

    def router_firewall(self):
        """ufw-style canary containment + the CrowdSec nft tables."""
        uid = str(pwd.getpwnam(CANARY_USER).pw_uid)
        for ipt, chain in (("iptables", "ufw-before-output"), ("ip6tables", "ufw6-before-output")):
            ns("twr", [ipt, "-N", chain], check_rc=True)
            ns("twr", [ipt, "-A", "OUTPUT", "-j", chain], check_rc=True)
            ns("twr", [ipt, "-A", chain, "-o", "lo", "-j", "ACCEPT"], check_rc=True)
            ns("twr", [ipt, "-A", chain, "-m", "owner", "--uid-owner", uid, "-m", "conntrack",
                       "--ctstate", "NEW", "-j", "LOG", "--log-prefix", "[TUXWALL-CANARY-EGRESS] "],
               check_rc=True)
            ns("twr", [ipt, "-A", chain, "-m", "owner", "--uid-owner", uid, "-j", "REJECT"],
               check_rc=True)
        conf = """
table ip crowdsec {
  set crowdsec-blacklists-cscli { type ipv4_addr; flags timeout; elements = { 203.0.113.66 timeout 1d } }
  chain crowdsec-chain-input { type filter hook input priority filter - 10; policy accept;
    ip saddr @crowdsec-blacklists-cscli counter drop
  }
}
table ip6 crowdsec6 {
  set crowdsec6-blacklists-cscli { type ipv6_addr; flags timeout; }
  chain crowdsec6-chain-input { type filter hook input priority filter - 10; policy accept;
    ip6 saddr @crowdsec6-blacklists-cscli counter drop
  }
}
table inet tuxwall_crowdsec_ranges {
  set ranges4 { type ipv4_addr; flags interval,timeout; }
  chain input { type filter hook input priority filter - 10; policy accept;
    ip saddr @ranges4 counter drop comment "tuxwall: CrowdSec Range bans"
  }
}
"""
        ns("twr", ["nft", "-f", "-"], input=conf, check_rc=True)

    def start_services(self):
        cert, key = os.path.join(self.tmp, "c.pem"), os.path.join(self.tmp, "k.pem")
        sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=test", "-keyout", key, "-out", cert], check_rc=True)
        self.dnslog = os.path.join(self.tmp, "dns.log")
        py = sys.executable
        self.spawn("tww", [py, "-B", HELPERS, "dns", "192.0.2.53", self.dnslog])
        self.spawn("tww", [py, "-B", HELPERS, "https", cert, key, "443"])
        for port in ("80", "4460"):
            self.spawn("tww", [py, "-B", HELPERS, "tcp", port])
        for port, addrs in (("123", ["192.0.2.123", "2001:db8:a::123"]), ("67", ["203.0.113.1"]),
                            ("547", ["2001:db8:f::1"])):
            self.spawn("tww", [py, "-B", HELPERS, "udp", port] + addrs)
        self.spawn("twl", [py, "-B", HELPERS, "tcp", "3000"])
        self.spawn("twi", [py, "-B", HELPERS, "tcp", "3000"])
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
            TUXWALL_TRIPWIRE_CANARY_USER=CANARY_USER, TUXWALL_TRIPWIRE_NTP_USERS=NTP_USER,
            TUXWALL_TRIPWIRE_PUSH_FILE=os.path.join(self.tmp, "push.jsonl"),
            TUXWALL_TRIPWIRE_OWN_IPS="203.0.113.2/24 10.99.0.1/24 10.97.0.1/24 10.98.0.1/24 "
                                     "127.0.0.1/8",
            TUXWALL_TRIPWIRE_LAN_NETS="10.99.0.1/24 fd99::1/64 10.97.0.1/24 fd97::1/64 "
                                      "10.98.0.1/24",
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

    def start_daemon(self):
        self.daemon = subprocess.Popen(["ip", "netns", "exec", "twr", sys.executable, "-B", ENGINE,
                                        "run"], env=self.engine_env(), stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)

    def stop_daemon(self):
        if self.daemon:
            self.daemon.terminate()
            try:
                self.daemon.wait(10)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
            self.daemon = None

    def down(self):
        self.stop_daemon()
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
def curl(n, url, fam=None, resolve=None, t=4, user=None):
    cmd = ["curl", "-sk", "--max-time", str(t), "-o", "/dev/null", "-w", "%{http_code}"]
    if fam:
        cmd.append("-" + fam)
    if resolve:
        cmd += ["--resolve", resolve]
    return ns(n, (as_user(user) if user else []) + cmd + [url],
              timeout=t + 5).stdout.strip() == "200"


def tcp(n, host, port, t=3, user=None, src=None):
    code = ("import socket,sys\ntry:\n socket.create_connection((%r,%d),%d,source_address=%r).close()\n"
            "except OSError: sys.exit(1)" % (host, port, t, (src, 0) if src else None))
    return ns(n, (as_user(user) if user else []) + [sys.executable, "-c", code],
              timeout=t + 5).returncode == 0


def udp(n, host, port, sport=0, t=2, user=None):
    code = ("import socket,sys\nf=socket.AF_INET6 if ':' in %r else socket.AF_INET\n"
            "s=socket.socket(f,socket.SOCK_DGRAM)\ns.settimeout(%d)\n"
            "s.bind(('::' if f==socket.AF_INET6 else '0.0.0.0',%d))\n"
            "try:\n s.sendto(b'ping',(%r,%d))\n sys.exit(0 if s.recvfrom(64)[0]==b'ping' else 1)\n"
            "except OSError: sys.exit(1)" % (host, t, sport, host, port))
    return ns(n, (as_user(user) if user else []) + [sys.executable, "-c", code],
              timeout=t + 5).returncode == 0


def dig(n, name, server="127.0.0.1", qtype="A"):
    out = ns(n, ["dig", "+time=2", "+tries=1", "@" + server, name, qtype]).stdout
    m = re.search(r"status: (\w+)", out)
    ans = re.findall(r"^\S+\s+\d+\s+IN\s+(?:A|AAAA|CNAME)\s+(\S+)", out, re.M)
    return (m.group(1) if m else "TIMEOUT"), ans


def rules(n="twr"):
    return ns(n, ["iptables-save"]).stdout + ns(n, ["ip6tables-save"]).stdout


def chain(ipt, name, n="twr"):
    return [ln for ln in ns(n, [ipt, "-S", name]).stdout.splitlines() if ln.startswith("-A ")]


def sets(n="twr"):
    return sorted(ns(n, ["ipset", "list", "-n"]).stdout.split())


def canary_logged():
    out = ns("twr", ["iptables", "-L", "ufw-before-output", "-v", "-x", "-n"]).stdout
    m = re.search(r"^\s*(\d+)\s+\d+\s+LOG\b", out, re.M)
    return int(m.group(1)) if m else -1


def rej_skips(ipt):
    return any("! --uid-owner" in ln and "EGRESS -j REJECT" in ln for ln in chain(ipt, "OUTPUT"))


def lan_wan_blocked():
    return (not curl("twl", "https://192.0.2.10/", t=3)
            and not curl("twl", "https://[2001:db8:a::10]/", t=3)
            and not tcp("tww", "10.99.0.10", 3000) and not tcp("tww", "fd99::10", 3000))


def lan_wan_open():
    return (curl("twl", "https://192.0.2.10/") and curl("twl", "https://[2001:db8:a::10]/")
            and tcp("tww", "10.99.0.10", 3000) and tcp("tww", "fd99::10", 3000))


def internal_open():
    return (tcp("twl", "10.97.0.10", 3000) and tcp("twi", "10.99.0.10", 3000)
            and tcp("twl", "fd97::10", 3000) and tcp("twi", "fd99::10", 3000))


def internal_blocked():
    return (not tcp("twl", "10.97.0.10", 3000) and not tcp("twi", "10.99.0.10", 3000)
            and not tcp("twl", "fd97::10", 3000) and not tcp("twi", "fd99::10", 3000))


def vpn_lan():
    return tcp("twv", "10.99.0.10", 3000, t=4)


def banned_dropped():
    return (not tcp("tww", "203.0.113.2", 2222, src="203.0.113.66")
            and "203.0.113.66" in ns("twr", ["nft", "list", "set", "ip", "crowdsec",
                                             "crowdsec-blacklists-cscli"]).stdout)


def router_egress_checks(tag, recovery):
    """What the router itself may reach on the internet while tripped."""
    ns("twr", ["ip", "-6", "neigh", "flush", "dev", "twr-wan"])
    check(curl("twr", "https://ntfy.test/", "4") and curl("twr", "https://ntfy.test/", "6"),
          "%s: router -> push target (ntfy) v4 + v6 (v6 after a neighbour flush: ND works)" % tag)
    check(curl("twr", "https://allowed.test/", "4") == recovery
          and curl("twr", "https://allowed.test/", "6") == recovery,
          "%s: router -> AI endpoint %s" % (tag, "allowed (recovery)" if recovery else "blocked"))
    check(not curl("twr", "https://denied.test/", "4", "denied.test:443:192.0.2.20", t=3)
          and not curl("twr", "https://denied.test/", "6", "denied.test:443:[2001:db8:a::20]", t=3),
          "%s: router -> other HTTPS blocked (v4 + v6)" % tag)
    check(not tcp("twr", "192.0.2.30", 80), "%s: push host, other port blocked" % tag)
    check(dig("twr", "allowed.test", server="192.0.2.53")[0] == "TIMEOUT",
          "%s: direct DNS from root blocked (only the resolver's uid)" % tag)
    s, a = dig("twr", "allowed.test")
    check(s == "NOERROR" and "192.0.2.10" in a, "%s: unbound resolves (DNS from its uid)" % tag)
    check(dig("twr", "denied.test")[0] == ("REFUSED" if recovery else "NOERROR")
          and dig("twl", "denied.test", server="10.99.0.1")[0] == ("REFUSED" if recovery
                                                                   else "NOERROR"),
          "%s: router + LAN DNS for other names: %s" % (tag, "refused (recovery)" if recovery
                                                        else "answered (open while tripped)"))
    check(udp("twr", "192.0.2.123", 123, user=NTP_USER) and udp("twr", "2001:db8:a::123", 123,
                                                               user=NTP_USER)
          and tcp("twr", "192.0.2.123", 4460, user=NTP_USER),
          "%s: NTP (+ NTS-KE) from the time daemon's uid v4 + v6" % tag)
    check(not udp("twr", "192.0.2.123", 123) and not tcp("twr", "192.0.2.123", 4460),
          "%s: NTP from another uid blocked" % tag)
    check(udp("twr", "203.0.113.1", 67, sport=68) and udp("twr", "2001:db8:f::1", 547, sport=546),
          "%s: WAN DHCPv4 + DHCPv6 out (and the answer back)" % tag)
    check(not udp("twr", "203.0.113.1", 67, sport=6800), "%s: other UDP out blocked" % tag)
    before = canary_logged()
    check(not curl("twr", "https://ntfy.test/", "4", "ntfy.test:443:192.0.2.30", t=3, user=CANARY_USER)
          and canary_logged() > before,
          "%s: canary uid -> push host rejected by ITS containment (logged for the canary check)" % tag)
    check(tcp("twr", "10.99.0.10", 3000) and tcp("twr", "127.0.0.1", 2222),
          "%s: router -> LAN and local services unaffected" % tag)


def tripped_checks(E, tag, high, recovery=False):
    check(lan_wan_blocked(), "%s: LAN <-> WAN blocked both ways (v4 + v6)" % tag)
    check(not curl("twi", "https://192.0.2.10/", t=3), "%s: VLAN -> WAN blocked" % tag)
    check(not tcp("twv", "192.0.2.10", 443), "%s: VPN -> internet blocked" % tag)
    if high:
        check(internal_blocked(), "%s: LAN <-> VLAN blocked (all forwarding)" % tag)
        check(not vpn_lan(), "%s: VPN -> LAN blocked" % tag)
        check(not tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router new connection blocked" % tag)
    else:
        check(internal_open(), "%s: LAN <-> VLAN still pass (v4 + v6)" % tag)
        check(vpn_lan(), "%s: VPN -> LAN still passes (WireGuard over the restricted WAN)" % tag)
        check(tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router stays reachable (replies out)"
              % tag)
    check(banned_dropped(), "%s: CrowdSec nft ban still drops the banned source" % tag)
    router_egress_checks(tag, recovery)
    r = rules()
    check("TUXWALL-TRIPWIRE-EGRESS -j REJECT" in r, "%s: egress REJECT in place" % tag)
    plain = "-A FORWARD -m comment --comment TUXWALL-TRIPWIRE -j DROP" in r
    check(plain == high, "%s: %s" % (tag, "all forwarding dropped" if high
                                      else "only WAN forwarding dropped (no plain FORWARD drop)"))
    for ipt in ("iptables", "ip6tables"):
        for ch in ("FORWARD", "OUTPUT") + (("INPUT",) if high else ()):
            lines = chain(ipt, ch)
            ours = [i for i, ln in enumerate(lines) if "TUXWALL-TRIPWIRE" in ln]
            ok = bool(ours) and ours == list(range(len(ours)))
            kinds = [ln.split("--comment ")[1].split()[0].endswith("-ALLOW") for ln in lines[:len(ours)]]
            check(ok and kinds == sorted(kinds, reverse=True),
                  "%s: %s %s: ours first, ALLOWs above the DROP/REJECT" % (tag, ipt, ch))
    check(sets()[:2] == ["tw-egress4", "tw-egress6"] or {"tw-egress4", "tw-egress6"} <= set(sets()),
          "%s: egress sets present" % tag)
    st = E.state()
    hosts = {h["host"] for h in (st.get("egress") or {}).get("hosts", [])}
    check(hosts == {"ntfy.test"}, "%s: egress allowlist = the push target (%s)" % (tag, hosts))


def recovery_checks(E, tag, high):
    st = E.state()
    check(st.get("recovery", {}).get("active"), "%s: recovery active in state" % tag)
    check(curl("twr", "https://cdn.allowed.test/", "4"), "%s: CNAME'd allowed name" % tag)
    s, a = dig("twr", "allowed.test")
    check(s == "NOERROR" and "192.0.2.10" in a, "%s: DNS answers allowed names" % tag)
    check(not tcp("twr", "192.0.2.10", 80), "%s: allowed host, other port blocked" % tag)
    check("10.99.0.1" in dig("twl", "router.home.arpa", server="10.99.0.1")[1],
          "%s: LAN DNS: router local zone still answers" % tag)
    r = rules()
    check("TUXWALL-TRIPWIRE-RECOVERY-ALLOW" in r and "TUXWALL-TRIPWIRE-EGRESS -j REJECT" in r,
          "%s: recovery ACCEPT on top of the tripped egress policy" % tag)
    check({"tw-recovery4", "tw-recovery6", "tw-egress4", "tw-egress6"} <= set(sets()),
          "%s: recovery + egress sets" % tag)
    tripped_checks(E, tag, high, recovery=True)


def back_to_tripped(E, tag, high):
    r = rules()
    check("TUXWALL-TRIPWIRE-RECOVERY" not in r and "TUXWALL-TRIPWIRE-EGRESS -j REJECT" in r,
          "%s: recovery rules gone, tripped egress kept" % tag)
    check(sets() == ["tw-egress4", "tw-egress6"], "%s: recovery sets destroyed (%s)" % (tag, sets()))
    tripped_checks(E, tag, high, recovery=False)


def resolved_checks(E, tag):
    r = rules()
    check("TUXWALL" not in r.replace("TUXWALL-CANARY-EGRESS", ""),
          "%s: resolve removes every tripwire/egress/recovery rule" % tag)
    check(sets() == [], "%s: no sets left" % tag)
    check("egress" not in E.state(), "%s: egress state cleared" % tag)
    check(dig("twr", "denied.test")[0] == "NOERROR", "%s: DNS unrestricted" % tag)
    check(lan_wan_open(), "%s: LAN <-> WAN restored (v4 + v6, both ways)" % tag)
    check(internal_open() and vpn_lan() and tcp("twv", "192.0.2.10", 443),
          "%s: LAN <-> VLAN, VPN -> LAN and VPN -> internet" % tag)
    check(curl("twr", "https://denied.test/", "4") and curl("twr", "https://allowed.test/", "6"),
          "%s: router egress unrestricted" % tag)
    check(tcp("tww", "203.0.113.2", 2222), "%s: WAN -> router reachable again" % tag)
    check(banned_dropped(), "%s: CrowdSec ban still in force" % tag)


def watchdog_checks(E, tag, high):
    """With the daemon running: a foreign ACCEPT on top of FORWARD, a
    deleted egress REJECT (v6) and an ALLOW moved below the REJECT are all
    repaired; flushed recovery rules + a restarted unbound too."""
    ns("twr", ["iptables", "-I", "FORWARD", "1", "-j", "ACCEPT"])
    for ln in chain("ip6tables", "OUTPUT"):
        if "TUXWALL-TRIPWIRE-EGRESS -j REJECT" in ln:
            ns("twr", ["ip6tables", "-D"] + ln.split()[1:])
            break
    al = next(ln for ln in chain("iptables", "OUTPUT") if "tw-egress4" in ln)
    ns("twr", ["iptables", "-D"] + al.split()[1:])
    ns("twr", ["iptables", "-A"] + al.split()[1:])
    for ipt in ("iptables", "ip6tables"):
        for ln in chain(ipt, "OUTPUT"):
            if "TUXWALL-TRIPWIRE-RECOVERY" in ln:
                ns("twr", [ipt, "-D"] + ln.split()[1:])
    sh(E.ubc + " local_zone_remove .")
    sh(E.ubc + " local_zone_remove tuxwall-recovery.invalid.")
    check(dig("twr", "denied.test")[0] == "NOERROR", "%s: (simulated unbound restart)" % tag)

    def repaired():
        f = chain("iptables", "FORWARD")
        o6 = chain("ip6tables", "OUTPUT")
        o4 = chain("iptables", "OUTPUT")
        rej4 = [i for i, ln in enumerate(o4) if "EGRESS -j REJECT" in ln]
        al4 = [i for i, ln in enumerate(o4) if "tw-egress4" in ln]
        return (f and "TUXWALL-TRIPWIRE" in f[0] and "-A FORWARD -j ACCEPT" in f
                and any("EGRESS -j REJECT" in ln for ln in o6) and al4 and rej4 and al4[0] < rej4[0]
                and any("TUXWALL-TRIPWIRE-RECOVERY" in ln for ln in o4)
                and dig("twr", "denied.test")[0] == "REFUSED")
    ok = False
    for _ in range(40):
        time.sleep(0.5)
        if repaired():
            ok = True
            break
    check(ok, "%s: daemon re-applies: ours back on top of a foreign ACCEPT, missing REJECT, "
          "misordered ALLOW, recovery rules, DNS restriction" % tag)
    ns("twr", ["iptables", "-D", "FORWARD", "-j", "ACCEPT"])
    check(lan_wan_blocked() and curl("twr", "https://allowed.test/", "4")
          and not curl("twr", "https://denied.test/", t=3), "%s: containment works again" % tag)
    h = {}
    try:
        with open(E.root + "/run/tuxwall-tripwire/health.json") as f:
            h = json.load(f)
    except (OSError, ValueError):
        pass
    check(h.get("ts") and time.time() - h["ts"] < 10, "%s: daemon heartbeat while tripped" % tag)


def scenario(E, mode):
    high = mode == "high"
    tag = mode.upper()
    cs0 = nft_tables("twr")
    rc, out = E.engine("trip", "netns test", "--mode", mode)
    check("TRIPPED" in str(out), "%s: trip" % tag)
    pushes = open(os.path.join(E.tmp, "push.jsonl")).read() if os.path.exists(
        os.path.join(E.tmp, "push.jsonl")) else ""
    check("TRIPWIRE TRIPPED" in pushes, "%s: trip push recorded (sent before enforcing)" % tag)
    tripped_checks(E, tag + " tripped", high)
    # canary containment missing -> its uid is rejected by the egress policy
    uid = str(pwd.getpwnam(CANARY_USER).pw_uid)
    ns("twr", ["iptables", "-D", "ufw-before-output", "-m", "owner", "--uid-owner", uid, "-j",
               "REJECT"])
    E.engine("enforce")
    b = canary_logged()
    check(not curl("twr", "https://ntfy.test/", "4", "ntfy.test:443:192.0.2.30", t=3, user=CANARY_USER)
          and canary_logged() == b and rej_skips("ip6tables") and not rej_skips("iptables")
          and all("! --uid-owner %s" % uid in ln for ln in chain("iptables", "OUTPUT")
                  if "--match-set" in ln),
          "%s: canary containment missing (v4) -> the egress REJECT covers its uid "
          "(never the push allowlist)" % tag)
    ns("twr", ["iptables", "-A", "ufw-before-output", "-m", "owner", "--uid-owner", uid, "-j",
               "REJECT"])
    E.engine("enforce")
    check(rej_skips("iptables"), "%s: containment back -> canary uid left to it again" % tag)

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
    recovery_checks(E, tag + " recovery", high)
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
          "%s: expiry -> back to the tripped policy" % tag)
    back_to_tripped(E, tag + " expired", high)
    # end recovery
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    rc, js = E.engine("recovery-end", "--by", "netns")
    check(rc == 0 and js.get("ended"), "%s: recovery-end" % tag)
    back_to_tripped(E, tag + " ended", high)
    # daemon: repairs + expiry
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    E.start_daemon()
    time.sleep(2)
    watchdog_checks(E, tag + " daemon", high)
    E.set_state(lambda s: s["recovery"].__setitem__("expires", time.time() + 2))
    ok = False
    for _ in range(30):
        time.sleep(0.5)
        if "recovery" not in E.state() and "TUXWALL-TRIPWIRE-RECOVERY" not in rules():
            ok = True
            break
    check(ok and E.state().get("recovery_last", {}).get("how") == "expired",
          "%s: daemon timer expires recovery" % tag)
    back_to_tripped(E, tag + " daemon-expired", high)
    E.stop_daemon()
    # resolve from recovery
    E.engine("recovery-start", "--minutes", "15", stdin="{}")
    rc, js = E.engine("restore", "--by", "netns", stdin=json.dumps({"checklist": {
        "findings": True, "cause": True}}))
    check(rc == 2 and E.state().get("tripped"), "%s: restore refuses an incomplete checklist"
          % tag)
    rc, js = E.engine("restore", "--by", "netns", stdin=json.dumps({"checklist": {
        "findings": True, "cause": True, "confirm": True}, "note": "netns"}))
    check(rc == 0 and not E.state().get("tripped"), "%s: restore (resolve)" % tag)
    resolved_checks(E, tag + " resolved", )
    check(nft_tables("twr") == cs0, "%s: CrowdSec nft tables untouched" % tag)


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
        check(lan_wan_open(), "baseline: LAN <-> WAN (v4 + v6, both ways)")
        check(internal_open(), "baseline: LAN <-> VLAN (v4 + v6)")
        check(vpn_lan() and tcp("twv", "192.0.2.10", 443), "baseline: VPN -> LAN + internet")
        check(curl("twr", "https://denied.test/", "4") and curl("twr", "https://allowed.test/",
                                                                "6"),
              "baseline: router resolves + reaches every endpoint")
        check(tcp("tww", "203.0.113.2", 2222), "baseline: WAN -> router reachable")
        check(banned_dropped(), "baseline: CrowdSec nft ban drops the banned source")
        check(all(v != "(absent)" for v in nft_tables("twr").values()), "baseline: nft tables")
        for mode in ("medium", "high"):
            scenario(E, mode)
    finally:
        E.down()
    after = live_snapshot()
    for k in ("v4", "v6", "ipset", "nft-crowdsec", "zones", "root_zone", "netns"):
        check(before[k] == after[k], "live %s unchanged" % k)
    print("tripwire_netns_check: %d passed, %d failed" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
