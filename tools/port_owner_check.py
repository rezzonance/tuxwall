#!/usr/bin/env python3
"""Port-ownership incident checks (www/includes/api_server.py), pure:

  python3 tools/port_owner_check.py

Feeds synthetic `ss -tlnp` / `ss -ulnp` and `systemctl list-sockets`
output through the listener attribution (_systemd_socket_listeners,
_parse_ss_listeners) and the incident rules (_port_owner_incidents).
Nothing is executed on the host: /proc lookups are stubbed.

Covers the false "Port 22/tcp is contested" alert after every reboot:
with ssh.socket activation, ss shows the LAN/VPN :22 listeners held by
systemd (pid 1) alone until the first connection. They must count as
sshd, while a real stranger, systemd without a matching socket unit, a
socket-activated stranger service, and a socket-activated sshd on a
wildcard or the WAN address must all still alert.
"""
import importlib.util
import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT_DIR, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


spec = importlib.util.spec_from_file_location("api_server_ports", TARGET)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)

WAN = "203.0.113.209"
CLAIMED = {(22, "tcp"): "the deception layer (canary)", (53, "udp"): "Unbound DNS",
           (53, "tcp"): "Unbound DNS"}
COMMS = {5812: "twistd", 11681: "sshd", 777: "dropbear", 1: "systemd", 900: "unbound"}

SS_HDR = ("State  Recv-Q Send-Q   Local Address:Port   Peer Address:Port Process\n")


def ss(*rows):
    return SS_HDR + "\n".join(rows) + "\n"


def row(local, users, state="LISTEN"):
    return "%s 0 4096 %s 0.0.0.0:* users:(%s)" % (state, local, users)


LIST_SOCKETS = """\
10.0.0.1:22                                  Stream           ssh.socket                           ssh.service
192.168.1.1:22                               Stream           ssh.socket                           ssh.service
audit 1                                      Netlink          systemd-journald-audit.socket        systemd-journald.service
/run/dbus/system_bus_socket                  Stream           dbus.socket                          dbus.service
/run/ssh-unix-local/socket                   Stream           sshd-unix-local.socket               -
"""

CANARY = row(WAN + ":22", '("twistd",pid=5812,fd=10)')


def run(ss_tcp, sockets_text, ss_udp=""):
    sockets = A._systemd_socket_listeners(sockets_text)
    listeners = A._parse_ss_listeners("tcp", ss_tcp, sockets, comm_of=COMMS.get)
    listeners += A._parse_ss_listeners("udp", ss_udp, sockets, comm_of=COMMS.get)
    return listeners, A._port_owner_incidents(listeners, CLAIMED, set(),
                                              A.PORT_EXPECTED_COMMS, {WAN})


# --- list-sockets parsing -------------------------------------------------
socks = A._systemd_socket_listeners(LIST_SOCKETS)
check(socks.get(("tcp", "192.168.1.1", 22)) == ("ssh.socket", "sshd"), "ssh.socket -> sshd")
check(len(socks) == 2, "only IP listeners are mapped (unix/netlink lines ignored): %r" % socks)
socks = A._systemd_socket_listeners(
    "[::]:22  Stream  ssh.socket  ssh@.service\n"
    "0.0.0.0:5353  Datagram  foo.socket  -\n")
check(socks.get(("tcp", "[::]", 22)) == ("ssh.socket", "sshd"), "Accept=yes ssh@.service -> sshd")
check(socks.get(("udp", "0.0.0.0", 5353)) == ("foo.socket", "foo"),
      "no ACTIVATES: the socket's own name, Datagram -> udp")

# --- 1. reboot state: socket-activated, LAN/VPN only -> no alert -----------
listeners, inc = run(ss(row("192.168.1.1:22", '("systemd",pid=1,fd=106)'),
                        CANARY,
                        row("10.0.0.1:22", '("systemd",pid=1,fd=104)')), LIST_SOCKETS)
check(inc == {}, "socket-activated LAN-only sshd: no incident, got %r" % inc)
check(("tcp", "192.168.1.1", 22, 1, "sshd", "ssh.socket") in listeners,
      "pid-1 listener attributed to sshd via ssh.socket: %r" % listeners)

# --- 2. after the first connection: sshd + systemd share the socket ---------
listeners, inc = run(ss(row("192.168.1.1:22", '("sshd",pid=11681,fd=4),("systemd",pid=1,fd=106)'),
                        CANARY,
                        row("10.0.0.1:22", '("systemd",pid=1,fd=104),("sshd",pid=11681,fd=3)')),
                     LIST_SOCKETS)
check(inc == {}, "running socket-activated sshd: no incident, got %r" % inc)
check(all(l[3] == 11681 and l[4] == "sshd" and l[5] == "" for l in listeners if l[1] != WAN),
      "non-systemd user preferred whatever the order: %r" % listeners)

# --- 3. ssh.socket on 0.0.0.0:22 -> sshd:wan ---------------------------------
_, inc = run(ss(row("0.0.0.0:22", '("systemd",pid=1,fd=50)')),
             "0.0.0.0:22  Stream  ssh.socket  ssh.service\n")
check(inc.get("sshd:wan", ("",))[0] == "critical", "socket on 0.0.0.0:22 alerts: %r" % inc)
check("ssh.socket" in inc.get("sshd:wan", ("", "", ""))[2], "detail names the socket unit")

# --- 4. ssh.socket on the WAN address -> sshd:wan ----------------------------
_, inc = run(ss(row(WAN + ":22", '("systemd",pid=1,fd=50)')),
             WAN + ":22  Stream  ssh.socket  ssh.service\n")
check("sshd:wan" in inc, "socket on the WAN address alerts: %r" % inc)

# --- 5. dual-stack ListenStream=22: ss "*", list-sockets "[::]" -------------
_, inc = run(ss(row("*:22", '("systemd",pid=1,fd=50)')),
             "[::]:22  Stream  ssh.socket  ssh.service\n")
check("sshd:wan" in inc, "dual-stack socket (*:22) alerts: %r" % inc)

# --- 6. a running sshd on the wildcard still alerts (unchanged) -------------
_, inc = run(ss(row("0.0.0.0:22", '("sshd",pid=11681,fd=3)')), "")
check("sshd:wan" in inc and "pid 11681" in inc["sshd:wan"][2], "plain sshd on 0.0.0.0: %r" % inc)

# --- 7. a real stranger next to the canary -> contested ----------------------
_, inc = run(ss(row("192.168.1.1:22", '("dropbear",pid=777,fd=3)'), CANARY), LIST_SOCKETS)
sev, title, _ = inc.get("portowner:22/tcp", ("", "", ""))
check(sev == "warning" and "dropbear (pid 777)" in title, "stranger contests 22: %r" % inc)

# --- 8. a stranger alone on a claimed port -> critical -----------------------
_, inc = run(ss(row("192.168.1.1:22", '("dropbear",pid=777,fd=3)')), "")
check(inc.get("portowner:22/tcp", ("",))[0] == "critical", "stranger holds 22: %r" % inc)

# --- 9. systemd (pid 1) with no matching socket unit stays a stranger -------
_, inc = run(ss(row("192.168.1.1:22", '("systemd",pid=1,fd=106)'), CANARY), "")
check("systemd (pid 1)" in inc.get("portowner:22/tcp", ("", "", ""))[1],
      "unmapped pid-1 listener is a stranger: %r" % inc)

# --- 10. a socket-activated stranger service on DNS -> critical, named ------
_, inc = run("", "0.0.0.0:53  Datagram  dnsmasq.socket  dnsmasq.service\n",
             ss_udp=ss(row("0.0.0.0:53", '("systemd",pid=1,fd=60)', state="UNCONN")))
sev, title, detail = inc.get("portowner:53/udp", ("", "", ""))
check(sev == "critical" and "dnsmasq.socket" in title and "dnsmasq.socket" in detail,
      "socket-activated stranger on 53/udp: %r" % inc)

# --- 11. the expected owner next to a socket-activated stranger --------------
_, inc = run("", "192.168.1.1:53  Datagram  dnsmasq.socket  dnsmasq.service\n",
             ss_udp=ss(row("127.0.0.1:53", '("unbound",pid=900,fd=5)', state="UNCONN"),
                       row("192.168.1.1:53", '("systemd",pid=1,fd=60)', state="UNCONN")))
check(inc.get("portowner:53/udp", ("",))[0] == "warning", "partial conflict on 53/udp: %r" % inc)

# --- 12. lines without process info are ignored by the owner rules ----------
_, inc = run(ss("LISTEN 0 4096 192.168.1.1:22 0.0.0.0:*"), "")
check(inc == {}, "no users -> no attribution, no incident: %r" % inc)

print("port_owner_check: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
