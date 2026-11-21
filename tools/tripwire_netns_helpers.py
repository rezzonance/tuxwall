#!/usr/bin/env python3
"""Throwaway servers for tools/tripwire_netns_check.py (run inside the test
network namespaces only):

  dns  ADDR LOGFILE        authoritative stub for the *.test names (UDP+TCP 53)
  https CERT KEY PORT      TLS server on [::]:PORT (dual stack), answers "ok"
  tcp  PORT                plain TCP listener on [::]:PORT, answers "ok"
  udp  PORT ADDR...        UDP echo on ADDR:PORT, one socket per address so
                           replies leave from the address that was asked
                           (NTP / DHCP stand-ins)
"""
import socket
import socketserver
import ssl
import struct
import sys
import threading

ZONE = {
    "allowed.test": {1: ["192.0.2.10"], 28: ["2001:db8:a::10"]},
    "edge.cdnnet.test": {1: ["192.0.2.11"], 28: ["2001:db8:a::11"]},
    "ntfy.test": {1: ["192.0.2.30"], 28: ["2001:db8:a::30"]},
    "denied.test": {1: ["192.0.2.20"], 28: ["2001:db8:a::20"]},
}
CNAME = {"cdn.allowed.test": "edge.cdnnet.test"}


def enc(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def answer(data, log):
    qid, flags = data[:2], struct.unpack(">H", data[2:4])[0]
    off, labels = 12, []
    while data[off]:
        n = data[off]
        labels.append(data[off + 1:off + 1 + n].decode().lower())
        off += 1 + n
    qtype = struct.unpack(">H", data[off + 1:off + 3])[0]
    question = data[12:off + 5]
    name = ".".join(labels)
    with open(log, "a") as f:
        f.write("%s %d\n" % (name, qtype))
    rrs, rcode, target = [], 0, name
    if name in CNAME:
        target = CNAME[name]
        rrs.append(enc(name) + struct.pack(">HHIH", 5, 1, 30, len(enc(target))) + enc(target))
    if target in ZONE:
        for a in ZONE[target].get(qtype, []):
            fam = socket.AF_INET if qtype == 1 else socket.AF_INET6
            rd = socket.inet_pton(fam, a)
            rrs.append(enc(target) + struct.pack(">HHIH", qtype, 1, 30, len(rd)) + rd)
    elif name not in CNAME:
        rcode = 3
    fl = 0x8400 | (flags & 0x0100) | rcode
    return qid + struct.pack(">HHHHH", fl, 1, len(rrs), 0, 0) + question + b"".join(rrs)


def dns(addr, log):
    class U(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(answer(data, log), self.client_address)

    class T(socketserver.BaseRequestHandler):
        def handle(self):
            ln = struct.unpack(">H", self.request.recv(2))[0]
            out = answer(self.request.recv(ln), log)
            self.request.sendall(struct.pack(">H", len(out)) + out)
    u = socketserver.ThreadingUDPServer((addr, 53), U)
    t = socketserver.ThreadingTCPServer((addr, 53), T)
    threading.Thread(target=t.serve_forever, daemon=True).start()
    u.serve_forever()


class V6Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def serve(port, ctx=None):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            try:
                if ctx:
                    s = ctx.wrap_socket(s, server_side=True)
                s.settimeout(3)
                try:
                    s.recv(4096)
                except OSError:
                    pass
                s.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (OSError, ssl.SSLError):
                pass
    V6Server(("::", port), H).serve_forever()


def udp_echo(port, addrs):
    def loop(addr):
        s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((addr, port))
        while True:
            data, peer = s.recvfrom(2048)
            s.sendto(data, peer)
    for a in addrs[1:]:
        threading.Thread(target=loop, args=(a,), daemon=True).start()
    loop(addrs[0])


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "dns":
        dns(sys.argv[2], sys.argv[3])
    elif mode == "https":
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(sys.argv[2], sys.argv[3])
        serve(int(sys.argv[4]), c)
    elif mode == "udp":
        udp_echo(int(sys.argv[2]), sys.argv[3:])
    else:
        serve(int(sys.argv[2]))
