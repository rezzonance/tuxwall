"""OpenWrt access-point plugin for TuxWall.

Queries dumb-AP OpenWrt devices over SSH (dropbear) with a single
round-trip per AP, then renders a UniFi-compatible overview. Read-only
unless AP management is explicitly enabled in the plugin config.

  actions:
    test        -> per-AP connectivity + board summary
    overview    -> aps[] + clients[] (also answers to "refresh")
    incidents   -> offline APs, down radios, weak-signal clients
    events      -> connect/disconnect/roam timeline from hostapd logs
    rf          -> neighbour scan, channel load and recommendations
    wlan-*      -> list / add / save / delete SSIDs across all APs
    vlan-*      -> list / add / save / delete switch VLANs across all APs
    radio-channel -> set one radio's channel (management mode only)
"""
import json
import os
import re
import subprocess
import tempfile
import threading
import time

WEAK_SIGNAL_DBM = -75


def _cfg(req):
    cfg = req.get("config") or {}
    raw_hosts = str(cfg.get("hosts") or "")
    hosts = []
    for part in re.split(r"[,\s]+", raw_hosts):
        part = part.strip().strip(";")
        if part and part not in hosts:
            hosts.append(part)
    try:
        port = int(str(cfg.get("port") or "22").strip() or 22)
    except ValueError:
        port = 22
    try:
        timeout = max(2, min(15, int(str(cfg.get("connect_timeout") or 6).strip() or 6)))
    except ValueError:
        timeout = 6
    return {
        "hosts": hosts,
        "username": str(cfg.get("username") or "root").strip() or "root",
        "port": port,
        "mode": str(cfg.get("auth_mode") or "key").strip(),
        "key": str(cfg.get("ssh_key") or ""),
        "password": str(cfg.get("password") or ""),
        "timeout": timeout,
        "manage_enabled": bool(cfg.get("manage_enabled")),
    }


# ── SSH transport ───────────────────────────────────────────────────────────

REMOTE_SCRIPT = r"""
echo "@@BOARD"
ubus call system board 2>/dev/null || echo '{}'
echo "@@INFO"
ubus call system info 2>/dev/null || echo '{}'
echo "@@WIRELESS"
ubus call network.wireless status 2>/dev/null || echo '{}'
echo "@@MAC"
cat /sys/class/net/br-lan/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null || echo ''
echo "@@NEIGH"
ip neigh show 2>/dev/null || true
echo "@@UCIWIRELESS"
uci show wireless 2>/dev/null || true
for d in /sys/class/net/*; do
  n=${d##*/}
  [ -d "/sys/class/net/$n/phy80211" ] || continue
  echo "@@IWINFO:$n"
  iwinfo "$n" info 2>/dev/null
  echo "@@ASSOC:$n"
  iwinfo "$n" assoclist 2>/dev/null
  echo "@@UBUSCLI:$n"
  ubus call "hostapd.$n" get_clients 2>/dev/null || echo '{}'
done
echo "@@HOSTAPDLOG"
logread 2>/dev/null | grep -E 'AP-STA-(CONNECTED|DISCONNECTED)' | tail -n 500 || true
echo "@@DONE"
"""


def _ssh_argv(cfg, dest, known_hosts):
    argv = [
        "/usr/bin/ssh",
        "-F", "/dev/null",
        "-p", str(cfg["port"]),
        "-o", "ConnectTimeout=%d" % cfg["timeout"],
        "-o", "UserKnownHostsFile=%s" % known_hosts,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
    ]
    if cfg["mode"] == "password":
        if not os.path.exists("/usr/bin/sshpass"):
            raise RuntimeError("password auth selected but /usr/bin/sshpass is not installed")
        if not cfg["password"]:
            raise RuntimeError("SSH password is not configured")
        return ["/usr/bin/sshpass", "-p", cfg["password"]] + argv + [dest]
    if not cfg["key"]:
        raise RuntimeError("SSH private key is not configured")
    return argv + [
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        dest,
    ]


def _collect_host(cfg, dest, key_path, script=None):
    """One SSH round-trip. Returns raw stdout."""
    workdir = tempfile.mkdtemp(prefix="tuxwall-openwrt-")
    known_hosts = os.path.join(workdir, "known_hosts")
    argv = _ssh_argv(cfg, "%s@%s" % (cfg["username"], dest), known_hosts)
    if key_path:
        argv = argv[:-1] + ["-i", key_path, argv[-1]]
    try:
        proc = subprocess.run(
            argv, input=script or REMOTE_SCRIPT, capture_output=True, text=True,
            timeout=cfg["timeout"] + 10,
        )
    finally:
        try:
            os.unlink(known_hosts)
            os.rmdir(workdir)
        except OSError:
            pass
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else "ssh exited %s" % proc.returncode)
    return proc.stdout


REMOTE_UCI_SCRIPT = """echo "@@BOARD"
ubus call system board 2>/dev/null || echo '{}'
echo "@@UCIWIRELESS"
uci show wireless 2>/dev/null || true
echo "@@UCINETWORK"
uci show network 2>/dev/null || true
echo "@@UCIDHCP"
uci show dhcp 2>/dev/null || true
echo "@@DONE"
"""


def _gather(cfg, script=None):
    """SSH to every configured AP in parallel. Returns {host: text|Error}."""
    key_path = ""
    results = {}
    if not cfg["hosts"]:
        raise RuntimeError("No access points configured — add IPs under plugin settings")
    if cfg["mode"] == "key":
        if not cfg["key"]:
            raise RuntimeError("SSH private key is not configured")
        key_text = cfg["key"].replace("\\n", "\n")
        if "PRIVATE KEY" not in key_text:
            raise RuntimeError("The configured SSH key does not look like an OpenSSH private key")
        fd, key_path = tempfile.mkstemp(prefix="tuxwall-openwrt-key-")
        with os.fdopen(fd, "w") as f:
            f.write(key_text if key_text.endswith("\n") else key_text + "\n")
        os.chmod(key_path, 0o600)

    def worker(dest):
        try:
            results[dest] = _collect_host(cfg, dest, key_path, script=script)
        except Exception as exc:
            results[dest] = exc

    threads = [threading.Thread(target=worker, args=(h,)) for h in cfg["hosts"]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(5, cfg["timeout"] + 12))
    if key_path:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    return results


def _mgmt_context(cfg):
    """Lightweight per-AP context for management actions."""
    results = _gather(cfg, script=REMOTE_UCI_SCRIPT)
    out = []
    for host in cfg["hosts"]:
        res = results.get(host)
        if isinstance(res, Exception) or res is None:
            out.append({"host": host, "error": str(res) if res else "no response"})
            continue
        sec = _sections(res)
        board = _json(sec.get("@@BOARD", "{}"))
        out.append({
            "host": host,
            "name": board.get("hostname") or host,
            "wmap": _wireless_map(sec.get("@@UCIWIRELESS", "")),
            "nmap": _network_map(sec.get("@@UCINETWORK", "")),
            "dmap": _dhcp_map(sec.get("@@UCIDHCP", "")),
        })
    return out


UCI_NET_LINE = re.compile(r"^[a-z]+\.([^.]+)\.([a-zA-Z0-9_]+)='([^']*)'")


def _uci_sections(text):
    sections = {}
    for line in (text or "").splitlines():
        m = UCI_NET_LINE.match(line.strip())
        if not m:
            continue
        # list options render as repeated quoted values — keep the first
        sections.setdefault(m.group(1), {}).setdefault(m.group(2), m.group(3))
    return sections


def _network_map(text):
    """uci show network -> switch vlans, bridges, interfaces."""
    sections = _uci_sections(text)
    switch = ""
    vlans, physical_ports, cpu_port = [], [], ""
    for name, opts in sections.items():
        if (name.startswith("@switch") or name.startswith("switch")) \
                and not name.startswith("@switch_vlan") and not name.startswith("switch_vlan"):
            switch = switch or opts.get("name") or name.split("[")[0].lstrip("@")
        if name.startswith("@switch_vlan") or name.startswith("switch_vlan"):
            switch = switch or opts.get("device") or ""
            vid = opts.get("vid") or opts.get("vlan") or ""
            ports = (opts.get("ports") or "").split()
            for p in ports:
                if p.endswith("t") and len(p) <= 3:
                    cpu_port = cpu_port or p
                elif p.isdigit():
                    physical_ports.append(p)
            vlans.append({"section": name, "vlan": str(vid), "ports": ports,
                          "description": opts.get("description") or ""})
    bridges, interfaces = {}, {}
    for name, opts in sections.items():
        if opts.get("type") == "bridge":
            bridges[opts.get("name") or name] = {"section": name,
                                                 "ports": (opts.get("ports") or "").split()}
    for name, opts in sections.items():
        if "device" in opts and "proto" in opts and not name.startswith("@"):
            interfaces[name] = {"device": opts.get("device") or "",
                                "proto": opts.get("proto") or ""}
    return {"switch": switch, "vlans": vlans, "bridges": bridges,
            "interfaces": interfaces, "physical_ports": sorted(set(physical_ports)),
            "cpu_port": cpu_port}


def _dhcp_map(text):
    sections = _uci_sections(text)
    out = {}
    for name, opts in sections.items():
        iface = opts.get("interface")
        if iface and not name.startswith("@"):
            out[iface] = {"section": name, "ignore": opts.get("ignore") == "1",
                          "ra": opts.get("ra") or "", "dhcpv6": opts.get("dhcpv6") or ""}
    return out


def _apply_network(cfg, commands_by_host):
    """Apply network + dhcp config, with a detached reload so the SSH session
    confirms cleanly before the network stack restarts."""
    results = {}
    if cfg["mode"] == "key":
        key_text = cfg["key"].replace("\\n", "\n")
        fd, key_path = tempfile.mkstemp(prefix="tuxwall-openwrt-key-")
        with os.fdopen(fd, "w") as f:
            f.write(key_text if key_text.endswith("\n") else key_text + "\n")
        os.chmod(key_path, 0o600)
    else:
        key_path = ""

    def worker(dest, commands):
        script = "\n".join(commands) + """
uci commit network
uci commit dhcp
nohup sh -c 'sleep 1; service network restart' >/dev/null 2>&1 &
echo @@APPLIED
"""
        try:
            out = _collect_host(cfg, dest, key_path, script=script)
            results[dest] = {"ok": "@@APPLIED" in out}
            if "@@APPLIED" not in out:
                results[dest] = {"ok": False,
                                 "error": (out.strip().splitlines() or ["no output"])[-1][:200]}
        except Exception as exc:
            results[dest] = {"ok": False, "error": str(exc)[:200]}

    threads = [threading.Thread(target=worker, args=(h, c))
               for h, c in commands_by_host.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(10, cfg["timeout"] + 15))
    if key_path:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    return results


# ── RF environment scan (on-demand) ─────────────────────────────────────────
#
# Scanning takes the radio off-channel for a couple of seconds, so this is a
# separate, user-triggered round-trip — never part of the periodic overview.
# 5GHz scans can fail on live AP interfaces ("Scan aborted by kernel"),
# which is common on mac80211 builds while serving clients; we retry and
# report the gap instead of failing the whole action.

REMOTE_RF_SCRIPT = r"""
echo "@@WIRELESS"
ubus call network.wireless status 2>/dev/null || echo '{}'
first5=''; first2=''
for d in /sys/class/net/*; do
  n=${d##*/}
  [ -d "/sys/class/net/$n/phy80211" ] || continue
  b=${n%%-*}
  if [ "$b" = "phy0" ]; then
    [ -z "$first5" ] && first5=$n
  else
    [ -z "$first2" ] && first2=$n
  fi
done
do_scan() {
  n=$1; out=$2; t=1
  while [ $t -le 2 ]; do
    o=$(iwinfo "$n" scan 2>/dev/null)
    if [ -n "$o" ] && printf '%s\n' "$o" | grep -q 'Cell'; then
      { echo "@@SCAN:$n"; printf '%s\n' "$o"; } > "$out"
      return
    fi
    t=$((t + 1))
  done
  echo "@@SCANFAIL:$n" > "$out"
}
f5=$(mktemp 2>/dev/null) || f5=/tmp/_rf5
f2=$(mktemp 2>/dev/null) || f2=/tmp/_rf2
: > "$f5"; : > "$f2"
[ -n "$first5" ] && do_scan "$first5" "$f5" &
[ -n "$first2" ] && do_scan "$first2" "$f2" &
wait
cat "$f5" "$f2"
rm -f "$f5" "$f2"
echo "@@DONE"
"""


def _rf_collect_host(cfg, dest, key_path):
    workdir = tempfile.mkdtemp(prefix="tuxwall-openwrt-")
    known_hosts = os.path.join(workdir, "known_hosts")
    argv = _ssh_argv(cfg, "%s@%s" % (cfg["username"], dest), known_hosts)
    if key_path:
        argv = argv[:-1] + ["-i", key_path, argv[-1]]
    try:
        proc = subprocess.run(
            argv, input=REMOTE_RF_SCRIPT, capture_output=True, text=True,
            timeout=cfg["timeout"] + 25,
        )
    finally:
        try:
            os.unlink(known_hosts)
            os.rmdir(workdir)
        except OSError:
            pass
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        raise RuntimeError(err[-1] if err else "ssh exited %s" % proc.returncode)
    return proc.stdout


def _rf_gather(cfg):
    key_path = ""
    results = {}
    if cfg["mode"] == "key":
        key_text = cfg["key"].replace("\\n", "\n")
        fd, key_path = tempfile.mkstemp(prefix="tuxwall-openwrt-key-")
        with os.fdopen(fd, "w") as f:
            f.write(key_text if key_text.endswith("\n") else key_text + "\n")
        os.chmod(key_path, 0o600)

    def worker(dest):
        try:
            results[dest] = _rf_collect_host(cfg, dest, key_path)
        except Exception as exc:
            results[dest] = exc

    threads = [threading.Thread(target=worker, args=(h,)) for h in cfg["hosts"]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(10, cfg["timeout"] + 30))
    if key_path:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    return results


SCAN_CELL = re.compile(r"^Cell\s+\d+\s+-\s+Address:\s*([0-9A-Fa-f:]{17})", re.IGNORECASE)
SCAN_SSID = re.compile(r'^\s*ESSID:\s*"(.*)"', re.IGNORECASE)
SCAN_SIGNAL = re.compile(r"^\s*Signal:\s*(-?\d+)\s*dBm", re.IGNORECASE)
# Channel appears inline on the "Mode: ... Channel: N" line, before the
# HT Operation block repeats it as "Primary Channel" — take first match only.
SCAN_CHAN = re.compile(r"Channel:\s*(\d+)", re.IGNORECASE)
SCAN_SEC_OFFSET = re.compile(r"^\s*Secondary Channel Offset:\s*(\S+)", re.IGNORECASE)
SCAN_WIDTH = re.compile(r"^\s*Channel Width:\s*(\d+)\s*MHz", re.IGNORECASE)


def _parse_scan(text):
    cells = []
    cur = None
    for line in text.splitlines():
        m = SCAN_CELL.match(line)
        if m:
            cur = {"bssid": m.group(1).upper(), "ssid": "", "signal": None,
                   "channel": None, "width": 20, "sec_offset": ""}
            cells.append(cur)
            continue
        if cur is None:
            continue
        m = SCAN_SSID.match(line)
        if m:
            cur["ssid"] = m.group(1)
            continue
        m = SCAN_SIGNAL.match(line)
        if m:
            cur["signal"] = int(m.group(1))
            continue
        if cur["channel"] is None:
            m = SCAN_CHAN.search(line)
            if m:
                cur["channel"] = int(m.group(1))
                continue
        m = SCAN_SEC_OFFSET.match(line)
        if m:
            cur["sec_offset"] = m.group(1).lower()
            continue
        m = SCAN_WIDTH.match(line)
        if m and cur["width"] < int(m.group(1)):
            cur["width"] = int(m.group(1))
    return [c for c in cells if c["channel"] is not None]


def _channels_affected(cell):
    """Channels a cell pollutes given its width and secondary offset."""
    ch, w = cell["channel"], cell["width"]
    if w >= 80:
        return [ch, ch + 4, ch + 8, ch + 12]
    if w >= 40:
        if cell["sec_offset"] == "below":
            return [ch - 4, ch]
        if cell["sec_offset"] == "above":
            return [ch, ch + 4]
        return [ch - 4, ch, ch + 4]
    return [ch]


def _penalty(cells):
    """Weighted interference score per channel. Strong neighbors hurt more."""
    out = {}
    for cell in cells:
        if cell["signal"] is None:
            continue
        weight = max(0.0, (cell["signal"] + 90) / 10.0)
        for ch in _channels_affected(cell):
            out[ch] = round(out.get(ch, 0.0) + weight, 1)
    return out


BAND_CHANNELS = {
    "2g": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
    "5g": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
           116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161],
}
DFS_CHANNELS = set(range(52, 145))
CANDIDATES = {"2g": [1, 6, 11],
              "5g": [36, 44, 52, 100, 149, 157]}


def _ours_channels(ch, htmode):
    """Channels our own radio occupies, expanded by its width."""
    ht = str(htmode or "")
    try:
        ch = int(ch)
    except (TypeError, ValueError):
        return []
    if "80" in ht:
        return [ch, ch + 4, ch + 8, ch + 12]
    if "40" in ht:
        return [ch - 4, ch, ch + 4]
    return [ch]


def _recommend(band, penalty, ours):
    """Least-interference candidate channel, excluding channels we already use.

    Prefers non-DFS channels; falls back to DFS only when the best non-DFS
    option is heavily polluted (score >= 15 and DFS is far cleaner).
    """
    options = []
    for ch in CANDIDATES.get(band, []):
        if ch in ours:
            continue
        options.append({"channel": ch, "score": penalty.get(ch, 0.0),
                        "dfs": ch in DFS_CHANNELS})
    non_dfs = [o for o in options if not o["dfs"]]
    dfs = [o for o in options if o["dfs"]]
    note = ""
    if non_dfs:
        best = min(non_dfs, key=lambda o: o["score"])
        if best["score"] >= 15 and dfs:
            best_dfs = min(dfs, key=lambda o: o["score"])
            if best_dfs["score"] < best["score"] * 0.25:
                best = best_dfs
                note = "DFS channel — expect a 1-10 min radar check when switching."
    elif dfs:
        best = min(dfs, key=lambda o: o["score"])
        note = "Only DFS channels remain free — expect a 1-10 min radar check when switching."
    else:
        best = None
    alternatives = sorted(options, key=lambda o: o["score"])[:3]
    return {"channel": best["channel"] if best else None,
            "score": best["score"] if best else None,
            "dfs": bool(best and best["dfs"]), "note": note,
            "alternatives": alternatives}


def _band_of_iface(ifname, band_map=None):
    """Band for a VAP interface. Prefer the AP's own radio config (phy0 is
    2.4GHz on some platforms and 5GHz on others - the prefix alone has
    produced swapped bands in the field); fall back to the prefix heuristic
    only when the map has no entry."""
    if band_map and ifname in band_map:
        return band_map[ifname]
    return "5g" if ifname.startswith("phy0") else "2g"


def _rf(cfg):
    results = _rf_gather(cfg)
    # pass 1: our own channels per band, across all APs
    ours_by_band = {}
    parsed = {}
    for host in cfg["hosts"]:
        res = results.get(host)
        if isinstance(res, Exception) or res is None:
            parsed[host] = None
            continue
        sec = _sections(res)
        parsed[host] = sec
        wireless = _json(sec.get("@@WIRELESS", "{}"))
        ifname_band = {}
        for _rn, _rd in (wireless or {}).items():
            _b = _band_for((_rd or {}).get("config") or {})
            for _if in (_rd or {}).get("interfaces") or []:
                if _if.get("ifname"):
                    ifname_band[_if["ifname"]] = _b
        for radio_name, radio in sorted(wireless.items()):
            radio_cfg = radio.get("config") or {}
            band = _band_for(radio_cfg)
            ch = radio_cfg.get("channel")
            if ch:
                try:
                    for c in _ours_channels(int(str(ch)), radio_cfg.get("htmode")):
                        ours_by_band.setdefault(band, set()).add(c)
                except ValueError:
                    pass

    # pass 2: build the per-AP report
    report = []
    for host in cfg["hosts"]:
        sec = parsed.get(host)
        entry = {"ap": host, "bands": [], "scan_errors": []}
        if sec is None:
            res = results.get(host)
            entry["scan_errors"] = [{"band": "", "error": str(res) if res else "no response"}]
            report.append(entry)
            continue
        for key, text in sorted(sec.items()):
            if key.startswith("@@SCANFAIL:"):
                entry["scan_errors"].append({
                    "band": _band_of_iface(key.split(":", 1)[1], ifname_band),
                    "error": "scan failed after 3 attempts (common on live 5GHz AP interfaces)",
                })
            elif key.startswith("@@SCAN:"):
                ifname = key.split(":", 1)[1]
                band = _band_of_iface(ifname, ifname_band)
                cells = _parse_scan(text)
                pen = _penalty(cells)
                ours = ours_by_band.setdefault(band, set())
                entry["bands"].append({
                    "band": band,
                    "ifname": ifname,
                    "cells": cells,
                    "channels": [
                        {"channel": ch,
                         "score": pen.get(ch, 0.0),
                         "networks": sorted(
                             (c for c in cells if ch in _channels_affected(c)),
                             key=lambda c: c["signal"] or 0, reverse=True)[:6],
                         "ours": ch in ours}
                        for ch in BAND_CHANNELS.get(band, [])
                    ],
                    "recommendation": _recommend(band, pen, ours),
                })
        report.append(entry)
    return {"ok": True, "aps": report, "note": "Scans take each radio off-channel for a couple of seconds."}


# ── Remote output parsing ───────────────────────────────────────────────────

SECTION_RE = re.compile(r"^@@[A-Z]+(?::\S+)?$")


def _sections(text):
    out = {}
    cur = "@@HEADER"
    for line in text.splitlines():
        if SECTION_RE.match(line):
            cur = line
            out.setdefault(cur, [])
            continue
        out.setdefault(cur, []).append(line)
    body = {k: "\n".join(v).strip() for k, v in out.items()}
    # keep marker-only sections (e.g. @@SCANFAIL) — they carry meaning
    return {k: v for k, v in body.items()
            if v or (k != "@@HEADER" and SECTION_RE.match(k))}


def _json(text, default=None):
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else (default if default is not None else {})
    except ValueError:
        return default if default is not None else {}


ASSOC_HEAD = re.compile(
    r"^([0-9A-Fa-f:]{17})\s+(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", re.IGNORECASE)
ASSOC_RATE = re.compile(r"^\s*(RX|TX):\s*([0-9.]+)\s*MBit/s", re.IGNORECASE)
IWINFO_CHAN = re.compile(r"^\s*Channel:\s*(\d+)", re.MULTILINE)
IWINFO_TXPWR = re.compile(r"^\s*Tx-Power:\s*([0-9.]+)\s*dBm", re.MULTILINE)
IWINFO_BSSID = re.compile(r"^\s*Access Point:\s*([0-9A-Fa-f:]{17})", re.MULTILINE | re.IGNORECASE)


def _parse_assoc(text):
    clients = {}
    current = None
    for line in text.splitlines():
        m = ASSOC_HEAD.match(line)
        if m:
            current = m.group(1).upper()
            clients[current] = {"signal": int(m.group(2))}
            continue
        if current:
            r = ASSOC_RATE.match(line)
            if r:
                clients[current]["rx_rate" if r.group(1).lower() == "rx" else "tx_rate"] = \
                    round(float(r.group(2)), 1)
    return clients


def _parse_neigh(text):
    """MAC -> most recent reachable/any IPv4 from the AP's neighbor table."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[1] != "dev":
            continue
        try:
            ip = parts[0]
        except ValueError:
            continue
        if ":" in ip or "." not in ip:
            continue
        mac = ""
        llidx = None
        for i, p in enumerate(parts):
            if p == "lladdr" and i + 1 < len(parts):
                llidx = i + 1
        if llidx:
            mac = parts[llidx].upper()
        if mac:
            out[mac] = ip
    return out


def _local_arp():
    """MAC -> IP from the firewall's own ARP table (world-readable).

    Covers both VLANs and is fresher than the APs' bridge neighbor tables,
    which only learn entries for hosts the AP itself talks to.
    """
    out = {}
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()[1:]
    except OSError:
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3]
        if flags != "0x2" or not mac or mac == "00:00:00:00:00:00":
            continue
        if "." not in ip:
            continue
        out[mac.upper()] = ip
    return out


def _reverse_names(ips):
    """Reverse-DNS via unbound on the firewall, parallel with a hard deadline.

    Sequential lookups cost ~0.3s per client and pushed the whole overview
    dangerously close to the plugin worker's 20s budget — so resolve in a
    small thread pool and give up gracefully past the deadline.
    """
    names = {}
    unique = sorted({ip for ip in ips if ip})
    if not unique:
        return names

    def lookup(ip):
        try:
            proc = subprocess.run(
                ["/usr/bin/dig", "+short", "+time=1", "+tries=1", "-x", ip, "@127.0.0.1"],
                capture_output=True, text=True, timeout=2,
            )
            for line in (proc.stdout or "").splitlines():
                line = line.strip().rstrip(".")
                if line and not line.isdigit() and ";" not in line:
                    return ip, (line.split(".")[0] if "." in line else line)
        except Exception:
            pass
        return ip, None

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as pool:
            for ip, name in pool.map(lookup, unique):
                if name:
                    names[ip] = name
    except Exception:
        pass
    return names


def _uptime(seconds):
    if not seconds:
        return "—"
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return "—"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, _ = divmod(s, 60)
    if d:
        return "%dd %dh" % (d, h)
    if h:
        return "%dh %dm" % (h, m)
    return "%dm" % m


def _band_for(radio_cfg):
    band = str((radio_cfg or {}).get("band") or "")
    if band:
        return band
    ht = str((radio_cfg or {}).get("htmode") or "")
    return "5g" if ht.startswith("VHT") or ht.startswith("HE") and "80" in ht else "2g"


def _width_for(radio_cfg):
    ht = str((radio_cfg or {}).get("htmode") or "")
    m = re.search(r"(?:VHT|HE|EHT)?(\d+)$", ht)
    return (m.group(1) + " MHz") if m else ht or ""


def _build_ap(host, text):
    sec = _sections(text)
    board = _json(sec.get("@@BOARD", "{}"))
    info = _json(sec.get("@@INFO", "{}"))
    wireless = _json(sec.get("@@WIRELESS", "{}"))
    mac = (sec.get("@@MAC") or "").strip().upper()
    neigh = _parse_neigh(sec.get("@@NEIGH", ""))

    ap = {
        "name": board.get("hostname") or host,
        "model": board.get("model") or "OpenWrt device",
        "ip": host,
        "mac": mac,
        "serial": "",
        "state": 1,
        "uptime": _uptime(info.get("uptime")),
        "uptime_seconds": int(info.get("uptime") or 0),
        "version": (board.get("release") or {}).get("version") or "",
        "clients": 0,
        "tx_bytes": None, "rx_bytes": None,
        "cpu": None, "mem": None,
        "load": info.get("loadavg") or [],
        "radios": [],
        "vaps": [],
        "uplink": {"type": "wired", "up": True},
        "errors": [],
    }

    clients = {}

    for radio_name in sorted(wireless.keys()):
        radio = wireless[radio_name] or {}
        radio_cfg = radio.get("config") or {}
        radio_clients = 0
        radio_tx_power = None
        for iface in radio.get("interfaces") or []:
            ifname = iface.get("ifname") or ""
            if not ifname:
                continue
            iface_cfg = iface.get("config") or {}
            iw_txt = sec.get("@@IWINFO:" + ifname, "")
            txp = IWINFO_TXPWR.search(iw_txt)
            if txp:
                radio_tx_power = txp.group(1)
            assoc = _parse_assoc(sec.get("@@ASSOC:" + ifname, ""))
            ubus_cli = _json(sec.get("@@UBUSCLI:" + ifname, "{}")).get("clients") or {}
            merged = {}
            for cmac, cdata in ubus_cli.items():
                cmac = str(cmac).upper()
                entry = dict(cdata) if isinstance(cdata, dict) else {}
                merged[cmac] = entry
            for cmac, cdata in assoc.items():
                merged.setdefault(cmac, {}).update(cdata)
            for cmac, entry in merged.items():
                if entry.get("assoc") is False:
                    continue
                row = clients.get(cmac) or {"mac": cmac, "ap": ap["name"], "ap_mac": mac}
                sig = entry.get("signal", entry.get("sig"))
                if isinstance(sig, (int, float)):
                    row["signal"] = int(abs(float(sig)) * -1) if float(sig) > 0 else int(sig)
                if entry.get("rx_rate") is not None:
                    row.setdefault("rx_rate", entry["rx_rate"])
                if entry.get("tx_rate") is not None:
                    row.setdefault("tx_rate", entry["tx_rate"])
                if entry.get("connected_time"):
                    row["connected_time"] = int(entry["connected_time"])
                row["ssid"] = iface_cfg.get("ssid") or row.get("ssid") or ""
                row["ifname"] = ifname
                row["network"] = (iface_cfg.get("network") or [""])[0] if iface_cfg.get("network") else ""
                row["band"] = _band_for(radio_cfg)
                row["ap"] = ap["name"]
                clients[cmac] = row
                radio_clients += 1
            ap["vaps"].append({
                "ssid": iface_cfg.get("ssid") or ifname,
                "ifname": ifname,
                "network": row_network(iface_cfg),
                "bssid": (IWINFO_BSSID.search(iw_txt).group(1).upper()
                          if IWINFO_BSSID.search(iw_txt) else ""),
                "channel": (IWINFO_CHAN.search(iw_txt).group(1)
                            if IWINFO_CHAN.search(iw_txt) else str(radio_cfg.get("channel") or "")),
                "clients": len(merged),
                "up": bool(radio.get("up")),
            })
        ap["radios"].append({
            "name": radio_name,
            "radio": _band_for(radio_cfg),
            "channel": str(radio_cfg.get("channel") or ""),
            "width": _width_for(radio_cfg),
            "tx_power": radio_tx_power,
            "clients": radio_clients,
            "up": bool(radio.get("up")),
        })

    ap["clients"] = len(clients)
    for row in clients.values():
        row["ip"] = neigh.get(row["mac"], "")
    ap["_clients_raw"] = clients
    ap["_neigh"] = neigh
    ap["_log"] = sec.get("@@HOSTAPDLOG", "")
    ap["_uci_wireless"] = sec.get("@@UCIWIRELESS", "")
    return ap


def row_network(iface_cfg):
    net = iface_cfg.get("network") or []
    return net[0] if isinstance(net, list) and net else (net or "")


# ── Config parity & flap detection ──────────────────────────────────────────

UCI_LINE = re.compile(r"^wireless\.([^.]+)\.([a-zA-Z0-9_]+)='(.*)'$")


def _normalize_wireless(text):
    """`uci show wireless` -> {radios: {...}, ssids: {band: {...}}} (no secrets)."""
    radios, ifaces = {}, {}
    for line in (text or "").splitlines():
        m = UCI_LINE.match(line.strip())
        if not m:
            continue
        section, opt, value = m.group(1), m.group(2), m.group(3)
        if section.startswith("radio") or section.startswith("@wifi-device"):
            radios.setdefault(section, {})[opt] = value
        elif section != "globals":
            ifaces.setdefault(section, {})[opt] = value
    out_radios = {}
    for name, opts in radios.items():
        band = opts.get("band") or ("5g" if "VHT" in opts.get("htmode", "") else "2g")
        out_radios[band] = {"htmode": opts.get("htmode") or "", "disabled": opts.get("disabled") or "0"}
    out_ssids = {}
    for name, opts in ifaces.items():
        ssid = opts.get("ssid")
        if not ssid:
            continue
        band = "5g" if opts.get("device", "").endswith("0") or "radio0" in opts.get("device", "") else "2g"
        out_ssids.setdefault(band, {})[ssid] = {
            "mode": opts.get("mode") or "ap",
            "encryption": opts.get("encryption") or "",
            "network": (opts.get("network") or "").split(" ")[0],
            "disabled": opts.get("disabled") or "0",
            "key": opts.get("key") or "",
        }
    return {"radios": out_radios, "ssids": out_ssids}


def _parity(uci_by_ap):
    """Compare normalized wireless configs across APs. Never returns keys."""
    if len(uci_by_ap) < 2:
        return {"match": True, "mismatches": [], "compared": len(uci_by_ap)}
    norms = {ap: _normalize_wireless(text) for ap, text in uci_by_ap.items()}
    names = list(norms)
    ref = norms[names[0]]
    mismatches = []

    all_ssids = {}
    for ap, n in norms.items():
        for band, ssids in n["ssids"].items():
            for ssid in ssids:
                all_ssids.setdefault((band, ssid), []).append(ap)
    for (band, ssid), aps in sorted(all_ssids.items()):
        if len(aps) < len(names):
            missing = [a for a in names if a not in aps]
            mismatches.append(
                '"%s" (%s) missing on %s' % (ssid, band, ", ".join(missing)))

    for band, ssids in sorted(ref["ssids"].items()):
        for ssid, spec in sorted(ssids.items()):
            for other in names[1:]:
                ospec = norms[other]["ssids"].get(band, {}).get(ssid)
                if not ospec:
                    continue
                for field, label in (("mode", "mode"), ("encryption", "encryption"),
                                     ("network", "network binding"), ("disabled", "enabled state")):
                    if spec[field] != ospec[field]:
                        mismatches.append('"%s" (%s) %s differs: %s=%r vs %s=%r' % (
                            ssid, band, label, names[0], spec[field], other, ospec[field]))
                if spec["key"] != ospec["key"]:
                    mismatches.append('"%s" (%s) key differs between %s and %s' % (
                        ssid, band, names[0], other))
    for band, rspec in sorted(ref["radios"].items()):
        for other in names[1:]:
            ospec = norms[other]["radios"].get(band)
            if not ospec:
                mismatches.append('%s radio missing on %s' % (band, other))
                continue
            if rspec["htmode"] != ospec["htmode"]:
                mismatches.append('%s channel width differs: %s=%s vs %s=%s' % (
                    band, names[0], rspec["htmode"], other, ospec["htmode"]))
            if rspec["disabled"] != ospec["disabled"]:
                mismatches.append('%s radio enabled state differs (%s vs %s)' % (
                    band, names[0], other))
    return {"match": not mismatches, "mismatches": mismatches, "compared": len(names)}


FLAP_DISCONNECTS = 6


def _flaps(log_by_ap):
    """Clients bouncing repeatedly, from the hostapd log window (~24h)."""
    out = []
    for ap, log in log_by_ap.items():
        counts = {}
        for line in (log or "").splitlines():
            m = LOG_LINE.match(line.strip())
            if not m:
                continue
            mac = m.group(4).upper()
            counts.setdefault(mac, {"connects": 0, "disconnects": 0})
            if m.group(3) == "AP-STA-DISCONNECTED":
                counts[mac]["disconnects"] += 1
            else:
                counts[mac]["connects"] += 1
        for mac, c in sorted(counts.items()):
            if c["disconnects"] >= FLAP_DISCONNECTS:
                out.append({"mac": mac, "ap": ap,
                            "connects": c["connects"], "disconnects": c["disconnects"]})
    out.sort(key=lambda f: -f["disconnects"])
    return out


# ── Client name enrichment ──────────────────────────────────────────────────
#
# Hostnames come from three sources, best-first:
#   1. Kea DHCP leases (authoritative, covers every DHCP client) — requires a
#      one-time root-side mirror of the lease file, see README.
#   2. mDNS announcements via avahi-browse (works unprivileged; covers IoT:
#      Shelly, ESPHome, HomeKit, printers…). Cached ~60s to keep refreshes fast.
#   3. Reverse DNS via unbound (usually empty on stock setups).

MDNS_CACHE = "/tmp/tuxwall-openwrt-mdns.json"
MDNS_TTL = 60
KEA_LEASE_PATHS = ("/var/lib/tuxwall/kea-leases.csv", "/var/lib/kea/kea-leases4.csv")


KEA_CTRL_SOCKET = "/run/kea/kea4-ctrl-socket"


def _kea_names_socket():
    """MAC -> {ip, hostname} straight from Kea's control socket.

    The live lease store - every lease the daemon holds, including ones
    whose rows have not yet been (re)written to the CSV. Preferred over
    the CSV: Kea's LFC pass can leave the on-disk file nearly empty for
    hours (observed in the field - a 65-lease store behind an 11-row
    CSV) while the socket always tells the truth."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(KEA_CTRL_SOCKET)
        s.sendall(json.dumps({"command": "lease4-get-all"}).encode())
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        resp = json.loads(data.decode())
        if isinstance(resp, list):
            resp = resp[0] if resp else {}
        leases = ((resp.get("arguments") or {}).get("leases")) or []
        out = {}
        for l in leases:
            mac = (l.get("hw-address") or "").strip().upper()
            hostname = (l.get("hostname") or "").strip()
            if mac and hostname:
                out[mac] = {"ip": l.get("ip-address") or "",
                            "hostname": hostname}
        return out if out else None
    except Exception:
        return None


def _kea_names():
    """MAC -> {ip, hostname} from Kea, best source first:
    1. names handed over by the tuxwall parent (works in the demoted
       worker where the Kea socket is unreachable),
    2. the Kea control socket directly (root/dev context),
    3. the lease CSV files (fallback; the on-disk file can lag Kea's
       in-memory store for hours after an LFC pass)."""
    if _PASSED_LEASES:
        return _PASSED_LEASES
    socket_names = _kea_names_socket()
    if socket_names is not None:
        return socket_names
    for path in KEA_LEASE_PATHS:
        try:
            with open(path) as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        out = {}
        for line in lines:
            parts = line.split(",")
            # Kea lease CSV: address,hwaddr,client_id,valid_lifetime,expire,
            # subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
            # hostname is column 8 — parts[7] is the fqdn_rev 0/1 flag, which
            # is how every client ended up with hostname "0".
            if len(parts) < 9 or parts[0] == "address":
                continue
            ip, mac, hostname = parts[0].strip(), parts[1].strip().upper(), parts[8].strip()
            if mac and hostname:
                out[mac] = {"ip": ip, "hostname": hostname}
        if out:
            return out
    return {}


def _unescape_avahi(text):
    return (text.replace("\\032", " ").replace("\\064", "@")
                .replace("\\058", ":").replace("\\043", "#")
                .replace("\\.", "."))


def _mdns_names():
    """IP -> hostname from local mDNS announcements, with a small cache."""
    try:
        with open(MDNS_CACHE) as f:
            cached = json.load(f)
        if time.time() - cached.get("ts", 0) < MDNS_TTL:
            return cached.get("names") or {}
    except Exception:
        pass
    try:
        proc = subprocess.run(
            ["/usr/bin/avahi-browse", "-artp"],
            capture_output=True, text=True, timeout=8,
        )
    except Exception:
        return {}
    names = {}
    for line in (proc.stdout or "").splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 8 or parts[2] != "IPv4":
            continue
        name = _unescape_avahi(parts[3]) or _unescape_avahi(parts[6]).rstrip(".local")
        addr = parts[7]
        if name and addr and "." in addr:
            names.setdefault(addr, name)
    try:
        with open(MDNS_CACHE + ".tmp", "w") as f:
            json.dump({"ts": time.time(), "names": names}, f)
        os.replace(MDNS_CACHE + ".tmp", MDNS_CACHE)
    except OSError:
        pass
    return names


def _enriched_names(clients):
    """Hostname per MAC, merging Kea > mDNS > reverse DNS. Also fills IPs."""
    kea = _kea_names()
    ips = {c.get("ip") for c in clients if c.get("ip")}
    for c in clients:
        k = kea.get(c.get("mac")) or {}
        if not c.get("ip") and k.get("ip"):
            c["ip"] = k["ip"]
            ips.add(k["ip"])
    mdns = _mdns_names() if ips else {}
    ptr = _reverse_names(sorted(ips)) if ips else {}
    out = {}
    for c in clients:
        mac, ip = c.get("mac"), c.get("ip")
        k = kea.get(mac) or {}
        name = k.get("hostname") or (mdns.get(ip) if ip else None) \
            or (ptr.get(ip) if ip else None)
        if name:
            out[mac] = name
    return out


# ── Wireless management (opt-in writes) ─────────────────────────────────────
#
# SSIDs are addressed by (band, ssid) — never by uci section names, which
# differ per AP. Every change is applied to ALL configured APs in one pass
# (per-AP results reported), using `uci commit wireless` + `wifi reload`.
# `wifi reload` only restarts hostapd — it never touches bridges or the
# management interface, unlike a full network restart.

ENCRYPTIONS = {"psk2": "psk2", "sae": "sae", "sae-mixed": "sae-mixed",
               "psk-mixed": "sae-mixed", "wpa2": "psk2", "wpa3": "sae",
               "wpa2-mixed": "sae-mixed", "none": "none"}
NETWORK_RE = re.compile(r"^[a-z0-9_]{1,15}$")


def _writable(cfg):
    if not cfg.get("manage_enabled"):
        raise RuntimeError("AP management is disabled — enable it in the plugin settings "
                           "(write access to your access points).")


def _validate_wlan(ssid, encryption, key, network):
    ssid = str(ssid or "").strip()
    if not (1 <= len(ssid) <= 32) or not all(32 <= ord(c) < 127 for c in ssid) \
            or any(q in ssid for q in ("'", '"', "\\")):
        raise RuntimeError("SSID must be 1-32 printable characters without quotes")
    enc = ENCRYPTIONS.get(str(encryption or "").strip().lower())
    if not enc:
        raise RuntimeError("Encryption must be one of: psk2, sae-mixed, sae, none")
    if not NETWORK_RE.match(str(network or "")):
        raise RuntimeError("Network must be a valid interface name (e.g. lan, iot)")
    if enc == "none":
        return ssid, enc, None, network
    key = str(key or "")
    if not (8 <= len(key) <= 63) or "'" in key or '"' in key or "\\" in key:
        raise RuntimeError("Password must be 8-63 characters without quotes "
                           "(required for %s)" % enc)
    return ssid, enc, key, network


def _wireless_map(text):
    """uci show wireless -> {radios: {band: section}, ifaces: {(band, ssid): [sections]}}."""
    sections = {}
    for line in (text or "").splitlines():
        m = UCI_LINE.match(line.strip())
        if not m:
            continue
        sections.setdefault(m.group(1), {})[m.group(2)] = m.group(3)
    radios, band_of_radio = {}, {}
    for name, opts in sections.items():
        if name.startswith("radio") or name.startswith("@wifi-device"):
            band = opts.get("band") or ("5g" if "VHT" in opts.get("htmode", "") else "2g")
            radios.setdefault(band, name)
            band_of_radio[name] = band
    ifaces = {}
    for name, opts in sections.items():
        if name.startswith("radio") or name.startswith("@wifi-device") or name == "globals":
            continue
        ssid = opts.get("ssid")
        if not ssid:
            continue
        band = band_of_radio.get(opts.get("device", ""), "2g")
        ifaces.setdefault((band, ssid), []).append(name)
    return {"radios": radios, "ifaces": ifaces, "sections": sections}


def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def _apply_wireless(cfg, commands_by_host):
    """Run uci commands + commit + wifi reload on each AP. Returns per-host result."""
    results = {}
    if cfg["mode"] == "key":
        key_text = cfg["key"].replace("\\n", "\n")
        fd, key_path = tempfile.mkstemp(prefix="tuxwall-openwrt-key-")
        with os.fdopen(fd, "w") as f:
            f.write(key_text if key_text.endswith("\n") else key_text + "\n")
        os.chmod(key_path, 0o600)
    else:
        key_path = ""

    def worker(dest, commands):
        script = "\n".join(commands) + "\nuci commit wireless\nwifi reload\necho @@APPLIED\n"
        try:
            out = _collect_host(cfg, dest, key_path, script=script)
            results[dest] = {"ok": "@@APPLIED" in out}
            if "@@APPLIED" not in out:
                results[dest] = {"ok": False,
                                 "error": (out.strip().splitlines() or ["no output"])[-1][:200]}
        except Exception as exc:
            results[dest] = {"ok": False, "error": str(exc)[:200]}

    threads = [threading.Thread(target=worker, args=(h, c))
               for h, c in commands_by_host.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(10, cfg["timeout"] + 15))
    if key_path:
        try:
            os.unlink(key_path)
        except OSError:
            pass
    return results


def _wlan_list(cfg):
    contexts = _mgmt_context(cfg)
    networks = {}
    ap_names = []
    for ctx in contexts:
        if ctx.get("error"):
            continue
        ap_names.append(ctx["name"])
        for (band, ssid), secs in ctx["wmap"]["ifaces"].items():
            sec = ctx["wmap"]["sections"][secs[0]]
            net = {"band": band, "ssid": ssid,
                   "encryption": sec.get("encryption") or "",
                   "network": (sec.get("network") or "").split(" ")[0],
                   "disabled": sec.get("disabled") == "1",
                   "keys": []}
            key = networks.setdefault((band, ssid), net)
            key.setdefault("aps", []).append(ctx["name"])
            key["keys"].append(sec.get("key") or "")
    out = []
    for (band, ssid), net in sorted(networks.items()):
        out.append({
            "band": band, "ssid": ssid,
            "encryption": net["encryption"], "network": net["network"],
            "disabled": net["disabled"],
            "aps": net.get("aps", []),
            "keys_match": len(set(net["keys"])) <= 1,
            "key_set": any(net["keys"]),
        })
    return {"ok": True, "networks": out, "aps": sorted(set(ap_names)),
            "manage_enabled": bool(cfg.get("manage_enabled"))}


def _wlan_save(cfg, payload):
    _writable(cfg)
    confirm = bool(payload.get("confirm"))
    new_ssid = str(payload.get("new_ssid") or "").strip()
    old_ssid = str(payload.get("ssid") or "").strip()
    if not old_ssid:
        raise RuntimeError("Current SSID is required")
    band = payload.get("band")
    if band not in ("2g", "5g"):
        raise RuntimeError("Band must be 2g or 5g")
    ssid, enc, _, network = _validate_wlan(
        new_ssid or old_ssid, payload.get("encryption"), "placeholder-key",
        payload.get("network"))
    key = str(payload.get("key") or "")
    if key:
        if not (8 <= len(key) <= 63) or any(q in key for q in ("'", '"', "\\")):
            raise RuntimeError("Password must be 8-63 characters without quotes")
    if not confirm:
        impact = []
        if new_ssid and new_ssid != old_ssid:
            impact.append("renaming disconnects every client on it")
        if key:
            impact.append("all clients must re-enter the new password")
        if payload.get("disabled"):
            impact.append("the network will stop broadcasting")
        return {"ok": False, "needs_confirm": True,
                "error": "This change applies to every AP%s — confirm to apply."
                % (" and " + " / ".join(impact) if impact else "")}
    contexts = _mgmt_context(cfg)
    commands_by_host, notes = {}, []
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            notes.append("%s unreachable" % ctx["host"])
            continue
        wmap = ctx["wmap"]
        secs = wmap["ifaces"].get((band, old_ssid), [])
        if not secs:
            commands_by_host[ctx["host"]] = ["echo 'SSID not found on this AP — NOT applied'"]
            notes.append("%s: %s/%s missing" % (ctx["name"], band, old_ssid))
            continue
        cmds = []
        for sec in secs:
            cmds.append("uci set wireless.%s.ssid=%s" % (sec, _shell_quote(ssid)))
            cmds.append("uci set wireless.%s.encryption=%s" % (sec, _shell_quote(enc)))
            if key:
                cmds.append("uci set wireless.%s.key=%s" % (sec, _shell_quote(key)))
            cmds.append("uci set wireless.%s.network=%s" % (sec, _shell_quote(network)))
            cmds.append("uci set wireless.%s.disabled=%s"
                        % (sec, "1" if payload.get("disabled") else "0"))
        commands_by_host[ctx["host"]] = cmds
    applied = _apply_wireless(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied, "notes": notes}


def _wlan_add(cfg, payload):
    _writable(cfg)
    ssid, enc, key, network = _validate_wlan(
        payload.get("ssid"), payload.get("encryption"), payload.get("key"), payload.get("network"))
    band = payload.get("band")
    if band not in ("2g", "5g"):
        raise RuntimeError("Band must be 2g or 5g")
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "This creates the SSID on every AP — send confirm:true to apply."}
    contexts = _mgmt_context(cfg)
    commands_by_host = {}
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            continue
        wmap = ctx["wmap"]
        radio = wmap["radios"].get(band)
        if not radio:
            commands_by_host[ctx["host"]] = ["echo 'No %s radio on this AP — NOT applied'" % band]
            continue
        if (band, ssid) in wmap["ifaces"]:
            commands_by_host[ctx["host"]] = ["echo 'SSID already exists on this AP — NOT applied'"]
            continue
        cmds = ["uci add wireless wifi-iface",
                "uci set wireless.@wifi-iface[-1].device=%s" % _shell_quote(radio),
                "uci set wireless.@wifi-iface[-1].mode='ap'",
                "uci set wireless.@wifi-iface[-1].ssid=%s" % _shell_quote(ssid),
                "uci set wireless.@wifi-iface[-1].encryption=%s" % _shell_quote(enc)]
        if key is not None:
            cmds.append("uci set wireless.@wifi-iface[-1].key=%s" % _shell_quote(key))
        cmds.append("uci set wireless.@wifi-iface[-1].network=%s" % _shell_quote(network))
        commands_by_host[ctx["host"]] = cmds
    applied = _apply_wireless(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied}


def _wlan_delete(cfg, payload):
    _writable(cfg)
    band, ssid = payload.get("band"), str(payload.get("ssid") or "").strip()
    if not ssid:
        raise RuntimeError("SSID is required")
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "Deleting an SSID disconnects every client on it — "
                         "send confirm:true to apply."}
    contexts = _mgmt_context(cfg)
    commands_by_host = {}
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            continue
        secs = ctx["wmap"]["ifaces"].get((band, ssid), [])
        if not secs:
            commands_by_host[ctx["host"]] = ["echo 'SSID not found on this AP — nothing to do'"]
            continue
        commands_by_host[ctx["host"]] = ["uci delete wireless.%s" % s for s in secs]
    applied = _apply_wireless(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied}


def _radio_channel(cfg, payload):
    _writable(cfg)
    band = payload.get("band")
    channel = str(payload.get("channel") or "").strip()
    target = str(payload.get("ap") or "").strip()
    if band not in ("2g", "5g") or not channel.isdigit():
        raise RuntimeError("band (2g/5g) and numeric channel are required")
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "Changing the channel briefly blips clients on that radio — "
                         "send confirm:true to apply."}
    contexts = _mgmt_context(cfg)
    commands_by_host = {}
    for ctx in contexts:
        if ctx.get("error"):
            continue
        if target and ctx["name"] != target and ctx["host"] != target:
            continue
        radio = ctx["wmap"]["radios"].get(band)
        if not radio:
            continue
        commands_by_host[ctx["host"]] = ["uci set wireless.%s.channel=%s"
                                         % (radio, _shell_quote(channel))]
    if not commands_by_host:
        raise RuntimeError("No matching access point for channel change")
    applied = _apply_wireless(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied}


def _vlan_view(ctx):
    """One AP's network map -> normalized VLAN rows."""
    nmap = ctx["nmap"]
    dmap = ctx["dmap"]
    rows = []
    for v in nmap["vlans"]:
        vid = v["vlan"]
        base = _base_eth(nmap)
        tag_if = "%s.%s" % (base, vid) if base else ""
        bridge = ""
        for bname, b in nmap["bridges"].items():
            if tag_if and tag_if in b["ports"]:
                bridge = bname
                break
        interface, proto, dhcp_ignore = "", "", False
        for iname, i in nmap["interfaces"].items():
            if (bridge and i["device"] == bridge) or (tag_if and i["device"] == tag_if):
                interface, proto = iname, i["proto"]
                dhcp_ignore = (dmap.get(iname) or {}).get("ignore", False)
                break
        rows.append({"vlan": vid, "ports": v["ports"],
                     "description": v["description"], "bridge": bridge,
                     "interface": interface, "proto": proto,
                     "dhcp_ignore": dhcp_ignore, "section": v["section"]})
    return rows


def _base_eth(nmap):
    """Base ethernet name (e.g. eth0) from the management bridge's port."""
    for bname, b in nmap["bridges"].items():
        for p in b["ports"]:
            m = re.match(r"^(eth\d+)\.1$", p)
            if m:
                return m.group(1)
    return ""


def _validate_vlan_ports(tokens, nmap):
    cpu = nmap["cpu_port"]
    if not cpu:
        raise RuntimeError("Could not identify the CPU port from the switch config")
    seen = set()
    for t in tokens:
        if not re.match(r"^\d{1,2}t?$", t) or t in seen:
            raise RuntimeError("Invalid or duplicate port token: %r" % t)
        seen.add(t)
    if cpu not in tokens:
        raise RuntimeError("The CPU port (%s) must be included, tagged" % cpu)
    if not any(not t.endswith("t") for t in tokens) and not any(
            t.endswith("t") and t != cpu for t in tokens):
        raise RuntimeError("At least one physical port must carry the VLAN")
    return tokens


def _vlan_list(cfg):
    contexts = _mgmt_context(cfg)
    merged, ap_names = {}, []
    for ctx in contexts:
        if ctx.get("error"):
            continue
        ap_names.append(ctx["name"])
        for row in _vlan_view(ctx):
            key = str(row["vlan"])
            m = merged.setdefault(key, {"vlan": key, "aps": [], "variants": []})
            m["aps"].append(ctx["name"])
            m["variants"].append(row)
    vlans = []
    for key, m in sorted(merged.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
        ref = m["variants"][0]
        consistent = all(_same_vlan(v, ref) for v in m["variants"])
        vlans.append({
            "vlan": key, "description": ref["description"], "ports": ref["ports"],
            "bridge": ref["bridge"], "interface": ref["interface"], "proto": ref["proto"],
            "dhcp_guard": ref["dhcp_ignore"], "aps": sorted(set(m["aps"])),
            "consistent": consistent, "protected": key == "1",
        })
    nmap0 = next((c["nmap"] for c in contexts if not c.get("error")), {})
    return {"ok": True, "vlans": vlans, "aps": sorted(set(ap_names)),
            "physical_ports": nmap0.get("physical_ports") or [],
            "cpu_port": nmap0.get("cpu_port") or "",
            "manage_enabled": bool(cfg.get("manage_enabled"))}


def _same_vlan(a, b):
    if sorted(a.get("ports") or []) != sorted(b.get("ports") or []):
        return False
    return all(a.get(f) == b.get(f) for f in ("description", "bridge", "interface", "proto", "dhcp_ignore"))


def _vlan_add(cfg, payload):
    _writable(cfg)
    try:
        vid = int(str(payload.get("vlan") or "").strip())
    except ValueError:
        raise RuntimeError("VLAN ID must be a number")
    if not (2 <= vid <= 4094):
        raise RuntimeError("VLAN ID must be 2-4094 (1 is the management VLAN)")
    name = str(payload.get("name") or "").strip().lower()
    if not NETWORK_RE.match(name) or name in ("lan", "loopback", "wan"):
        raise RuntimeError("Name must be a unique interface name (not lan/wan)")
    desc = str(payload.get("description") or "").strip()
    ports = str(payload.get("ports") or "").strip().split()
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "This creates the VLAN, bridge, interface and DHCP guards on "
                         "every AP, then restarts their network stack (~15s). Send confirm:true."}
    contexts = _mgmt_context(cfg)
    commands_by_host, notes = {}, []
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            continue
        nmap = ctx["nmap"]
        base = _base_eth(nmap)
        if not base or not nmap["switch"]:
            commands_by_host[ctx["host"]] = ["echo 'Switch/base interface not detected — NOT applied'"]
            notes.append("%s: no switch config detected" % ctx["name"])
            continue
        if any(v["vlan"] == str(vid) for v in nmap["vlans"]):
            commands_by_host[ctx["host"]] = ["echo 'VLAN %d already exists — NOT applied'" % vid]
            continue
        if name in nmap["interfaces"]:
            commands_by_host[ctx["host"]] = ["echo 'Interface %s already exists — NOT applied'" % name]
            continue
        try:
            _validate_vlan_ports(ports, nmap)
        except RuntimeError as exc:
            commands_by_host[ctx["host"]] = ["echo %s" % _shell_quote("Error: %s — NOT applied" % exc)]
            continue
        switch = nmap["switch"]
        cmds = [
            "uci add network switch_vlan",
            "uci set network.@switch_vlan[-1].device=%s" % _shell_quote(switch),
            "uci set network.@switch_vlan[-1].vlan=%s" % _shell_quote(str(vid)),
            "uci set network.@switch_vlan[-1].ports=%s" % _shell_quote(" ".join(ports)),
            "uci add network device",
            "uci set network.@device[-1].name=%s" % _shell_quote("br-" + name),
            "uci set network.@device[-1].type='bridge'",
            "uci set network.@device[-1].ports=%s" % _shell_quote("%s.%d" % (base, vid)),
            "uci set network.%s=interface" % name,
            "uci set network.%s.device=%s" % (name, _shell_quote("br-" + name)),
            "uci set network.%s.proto='dhcp'" % name,
            "uci set dhcp.%s=dhcp" % name,
            "uci set dhcp.%s.interface=%s" % (name, _shell_quote(name)),
            "uci set dhcp.%s.ignore='1'" % name,
            "uci set dhcp.%s.ra='disabled'" % name,
            "uci set dhcp.%s.dhcpv6='disabled'" % name,
        ]
        if desc:
            cmds.append("uci set network.@switch_vlan[-1].description=%s" % _shell_quote(desc))
        commands_by_host[ctx["host"]] = cmds
    applied = _apply_network(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied, "notes": notes,
            "message": "VLANs created; APs restart their network stack (~15s)."}


def _vlan_save(cfg, payload):
    _writable(cfg)
    try:
        vid = int(str(payload.get("vlan") or "").strip())
    except ValueError:
        raise RuntimeError("VLAN ID must be a number")
    if vid == 1:
        raise RuntimeError("VLAN 1 is the management VLAN — edit it over SSH instead")
    desc = str(payload.get("description") or "").strip()
    ports = str(payload.get("ports") or "").strip().split()
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "Port/description changes restart the APs' network stack "
                         "(~15s). Send confirm:true."}
    contexts = _mgmt_context(cfg)
    commands_by_host, notes = {}, []
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            continue
        nmap = ctx["nmap"]
        target = next((v for v in nmap["vlans"] if v["vlan"] == str(vid)), None)
        if not target:
            commands_by_host[ctx["host"]] = ["echo 'VLAN %d not found — NOT applied'" % vid]
            continue
        try:
            _validate_vlan_ports(ports, nmap)
        except RuntimeError as exc:
            commands_by_host[ctx["host"]] = ["echo %s" % _shell_quote("Error: %s — NOT applied" % exc)]
            continue
        cmds = ["uci set network.%s.ports=%s" % (target["section"], _shell_quote(" ".join(ports)))]
        if desc:
            cmds.append("uci set network.%s.description=%s" % (target["section"], _shell_quote(desc)))
        commands_by_host[ctx["host"]] = cmds
    applied = _apply_network(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied, "notes": notes}


def _vlan_delete(cfg, payload):
    _writable(cfg)
    try:
        vid = int(str(payload.get("vlan") or "").strip())
    except ValueError:
        raise RuntimeError("VLAN ID must be a number")
    if vid == 1:
        raise RuntimeError("VLAN 1 is the management VLAN — it cannot be deleted")
    if not payload.get("confirm"):
        return {"ok": False, "needs_confirm": True,
                "error": "This removes the VLAN, bridge and interface from every AP. "
                         "Send confirm:true."}
    contexts = _mgmt_context(cfg)
    commands_by_host, notes = {}, []
    for ctx in contexts:
        if ctx.get("error"):
            commands_by_host[ctx["host"]] = ["echo 'AP unreachable — NOT applied'"]
            continue
        nmap, wmap = ctx["nmap"], ctx["wmap"]
        target = next((v for v in nmap["vlans"] if v["vlan"] == str(vid)), None)
        if not target:
            commands_by_host[ctx["host"]] = ["echo 'VLAN %d not found — nothing to do'" % vid]
            continue
        # refuse if any SSID is bound to this VLAN's interface
        view = {r["vlan"]: r for r in _vlan_view(ctx)}
        iface = view.get(str(vid), {}).get("interface")
        if iface:
            bound = [ssid for (band, ssid), _ in wmap["ifaces"].items()
                     if any(wmap["sections"][s].get("network", "") == iface
                            for s in wmap["ifaces"][(band, ssid)])]
            if bound:
                commands_by_host[ctx["host"]] = [
                    "echo %s" % _shell_quote("Error: SSIDs bound to interface '%s' (%s) — "
                                             "move or delete them first" % (iface, ", ".join(bound)))]
                notes.append("%s: SSIDs depend on this VLAN" % ctx["name"])
                continue
        cmds = ["uci delete network.%s" % target["section"]]
        if iface:
            cmds.append("uci delete network.%s" % iface)
            cmds.append("uci -q delete dhcp.%s >/dev/null 2>&1 || true" % iface)
        base = _base_eth(nmap)
        bridge = view.get(str(vid), {}).get("bridge")
        if bridge and bridge in nmap["bridges"]:
            cmds.append("uci delete network.%s" % nmap["bridges"][bridge]["section"])
        commands_by_host[ctx["host"]] = cmds
    applied = _apply_network(cfg, commands_by_host)
    return {"ok": all(r.get("ok") for r in applied.values()) and applied,
            "results": applied, "notes": notes}


# ── Actions ─────────────────────────────────────────────────────────────────

def _test(cfg):
    results = _gather(cfg)
    out = []
    for host, res in results.items():
        if isinstance(res, Exception):
            out.append({"host": host, "ok": False, "error": str(res)})
            continue
        board = _json(_sections(res).get("@@BOARD", "{}"))
        wireless = _json(_sections(res).get("@@WIRELESS", "{}"))
        radios = [k for k, v in wireless.items() if v.get("up")]
        out.append({
            "host": host, "ok": True,
            "hostname": board.get("hostname") or host,
            "model": board.get("model") or "",
            "version": (board.get("release") or {}).get("version") or "",
            "radios_up": len(radios),
        })
    ok = all(r.get("ok") for r in out) and out
    return {"ok": bool(ok), "results": out,
            "message": ("Connected to all %d access points." % len(out)) if ok
            else "One or more access points failed — see results."}


def _overview(cfg):
    results = _gather(cfg)
    aps, clients, errors = [], [], []
    for host in cfg["hosts"]:
        res = results.get(host)
        if isinstance(res, Exception) or res is None:
            errors.append({"host": host, "error": str(res) if res else "no response"})
            continue
        try:
            aps.append(_build_ap(host, res))
        except Exception as exc:
            errors.append({"host": host, "error": "parse error: %s" % exc})

    all_clients = {}
    local_arp = _local_arp()
    uci_by_ap, log_by_ap = {}, {}
    for ap in aps:
        ap_neigh = ap.pop("_neigh") or {}
        uci_by_ap[ap["name"]] = ap.pop("_uci_wireless", "")
        log_by_ap[ap["name"]] = ap.pop("_log", "")
        for cmac, row in (ap.pop("_clients_raw") or {}).items():
            row["ip"] = local_arp.get(cmac) or row.get("ip") or ap_neigh.get(cmac, "")
            all_clients.setdefault(cmac, row)
    parity = _parity(uci_by_ap)
    flaps = _flaps(log_by_ap)
    rows = list(all_clients.values())
    hostnames = _enriched_names(rows)

    out_clients = []
    for c in rows:
        cmac = c["mac"]
        ip = c.get("ip") or ""
        hostname = hostnames.get(cmac, "")
        out_clients.append({
            "name": hostname or cmac,
            "hostname": hostname,
            "ip": ip,
            "mac": cmac,
            "ssid": c.get("ssid") or "",
            "ap": c.get("ap") or "",
            "ap_mac": c.get("ap_mac") or "",
            "signal": c.get("signal"),
            "rx_rate": c.get("rx_rate"),
            "tx_rate": c.get("tx_rate"),
            "tx_retries": None,
            "uptime": _uptime(c.get("connected_time")),
            "uptime_seconds": c.get("connected_time") or 0,
            "wired": False,
            "vlan": c.get("network") or "",
            "network": c.get("network") or "",
        })
    out_clients.sort(key=lambda x: (x["name"] or "").lower())
    return {"ok": not errors, "aps": aps, "clients": out_clients,
            "errors": errors, "parity": parity, "flaps": flaps,
            "source": "openwrt-ssh"}


def _incidents(cfg):
    data = _overview(cfg)
    incidents = []
    for err in data.get("errors") or []:
        incidents.append({
            "key": "ap-offline:" + err["host"],
            "severity": "warning",
            "title": "Access point unreachable: %s" % err["host"],
            "detail": "SSH collection failed: %s" % err["error"][:200],
        })
    for ap in data.get("aps") or []:
        for radio in ap.get("radios") or []:
            if radio.get("up") is False:
                incidents.append({
                    "key": "ap-radio:%s:%s" % (ap.get("mac") or ap["name"], radio["name"]),
                    "severity": "warning",
                    "title": "Radio down on %s" % ap["name"],
                    "detail": "%s (%s) is not up." % (radio["name"], radio.get("radio") or "radio"),
                })
    weak = [c["name"] for c in data.get("clients") or []
            if isinstance(c.get("signal"), int) and c["signal"] <= WEAK_SIGNAL_DBM]
    if weak:
        incidents.append({
            "key": "weak-wifi-clients",
            "severity": "warning",
            "title": "%d WiFi client%s with weak signal" % (len(weak), "" if len(weak) == 1 else "s"),
            "detail": "Signal ≤ %d dBm: %s%s" % (WEAK_SIGNAL_DBM, ", ".join(weak[:8]),
                                                  "…" if len(weak) > 8 else ""),
        })
    parity = data.get("parity") or {}
    if parity and not parity.get("match", True):
        mism = parity.get("mismatches") or []
        incidents.append({
            "key": "ap-config-parity",
            "severity": "warning",
            "title": "AP wireless configs have drifted apart",
            "detail": "; ".join(mism[:6]) + ("…" if len(mism) > 6 else ""),
        })
    for flap in data.get("flaps") or []:
        incidents.append({
            "key": "flapping-client:" + flap["mac"],
            "severity": "warning",
            "title": "Flapping client %s" % flap["mac"],
            "detail": "%d disconnects / %d connects on %s in the log window — check signal, "
                      "power or interference." % (flap["disconnects"], flap["connects"], flap["ap"]),
        })
    return {"ok": True, "incidents": incidents}


LOG_LINE = re.compile(
    r"^(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+.*hostapd[^:]*:\s+"
    r"(phy[^:]*|wlan[^:]*):\s+(AP-STA-CONNECTED|AP-STA-DISCONNECTED)\s+"
    r"([0-9A-Fa-f:]{17})(?:\s+auth_alg=(\S+))?", re.IGNORECASE)


def _events(cfg, limit=100):
    results = _gather(cfg)
    iface_ssid = {}
    events = []
    for host in cfg["hosts"]:
        res = results.get(host)
        if isinstance(res, Exception):
            continue
        ap = _build_ap(host, res)
        ap_name = ap["name"]
        for vap in ap["vaps"]:
            iface_ssid[vap["ifname"]] = vap["ssid"]
        for line in (ap.pop("_log") or "").splitlines():
            m = LOG_LINE.match(line.strip())
            if not m:
                continue
            try:
                ts = int(time.mktime(time.strptime(m.group(1), "%a %b %d %H:%M:%S %Y")))
            except ValueError:
                continue
            iface = m.group(2)
            connected = m.group(3) == "AP-STA-CONNECTED"
            mac = m.group(4).upper()
            events.append({
                "time": ts,
                "title": "Client connected" if connected else "Client disconnected",
                "severity": "info" if connected else "warning",
                "client": mac,
                "mac": mac,
                "ap": ap_name,
                "ssid": iface_ssid.get(iface, iface),
                "ifname": iface,
                "auth": m.group(5) or "",
                "wired": False,
            })
    events.sort(key=lambda e: e["time"], reverse=True)
    try:
        limit = max(1, min(int(limit), 300))
    except (TypeError, ValueError):
        limit = 100
    return {"ok": True, "events": events[:limit], "source": "openwrt-logread"}


# Lease names handed over by the tuxwall root parent (it queries Kea -
# the demoted plugin worker cannot reach the control socket). Set per
# request in handle(); takes priority over every local source.
_PASSED_LEASES = {}


def handle(req):
    global _PASSED_LEASES
    _PASSED_LEASES = req.get("leases") or {}
    cfg = _cfg(req)
    action = req.get("action") or ""
    try:
        if not cfg["hosts"]:
            return {"ok": False, "configured": False,
                    "error": "No access points configured — add AP IPs in the plugin settings."}
        if action == "test":
            return _test(cfg)
        if action == "rf":
            return _rf(cfg)
        if action == "wlan-list":
            return _wlan_list(cfg)
        if action == "wlan-save":
            return _wlan_save(cfg, req.get("payload") or {})
        if action == "wlan-add":
            return _wlan_add(cfg, req.get("payload") or {})
        if action == "wlan-delete":
            return _wlan_delete(cfg, req.get("payload") or {})
        if action == "radio-channel":
            return _radio_channel(cfg, req.get("payload") or {})
        if action == "vlan-list":
            return _vlan_list(cfg)
        if action == "vlan-add":
            return _vlan_add(cfg, req.get("payload") or {})
        if action == "vlan-save":
            return _vlan_save(cfg, req.get("payload") or {})
        if action == "vlan-delete":
            return _vlan_delete(cfg, req.get("payload") or {})
        if action == "parity":
            results = _gather(cfg)
            uci_by_ap = {}
            for host in cfg["hosts"]:
                res = results.get(host)
                if isinstance(res, Exception) or res is None:
                    continue
                ap = _build_ap(host, res)
                uci_by_ap[ap["name"]] = ap.pop("_uci_wireless", "")
            return {"ok": True, **_parity(uci_by_ap)}
        if action == "incidents":
            return _incidents(cfg)
        if action == "events":
            return _events(cfg, (req.get("payload") or {}).get("limit") or 100)
        if action in ("overview", "refresh", ""):
            return _overview(cfg)
        return {"ok": False, "error": "Unknown action: %s" % action}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
