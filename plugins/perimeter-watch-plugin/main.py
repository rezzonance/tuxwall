"""TuxWall Perimeter Watch plugin (perimeter-watch).

External security audit of your own perimeter, contributed to the shared
TuxWall incidents system via the standard plugin alerts contract.

Sources (both keyless):
- Shodan InternetDB (https://internetdb.shodan.io/<ip>): what the internet
  currently observes open on your WAN IP - ports, CPEs, hostnames, tags,
  known CVEs. Observed ports are compared against the EXPECTED list
  (everything you intentionally open: services + honeypot + canary
  traps); anything outside it is a critical exposure incident.
- CrowdSec CTI smoke (https://cti.crowdsec.net/api/v2/smoke/<ip>):
  whether your IP is listed as an attacker (categories, scores). This is
  optional and fails gracefully: some networks (including TuxWall boxes
  with aggressive DNS blocklists) cannot resolve cti.crowdsec.net, and a
  soft unreachability must never become incident spam.

Workers are stateless per poll (the host caches results for its incident
TTL, ~5 minutes), so external API pacing comes from that cycle.
"""

import json
import re
import subprocess
import urllib.request
from datetime import datetime, timezone


IPIFY_URL = "https://api.ipify.org"
INTERNETDB_URL = "https://internetdb.shodan.io/"
CTI_URL = "https://cti.crowdsec.net/api/v2/smoke/"
UA = "tuxwall-perimeter-watch/1.0"


def _get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace") or "{}")


def _ips(cfg):
    out = []
    try:
        out.append(_get_text(IPIFY_URL))
    except Exception as exc:
        return None, "could not determine WAN IP (%s)" % exc
    extra = str(cfg.get("extra_ips") or "")
    for part in re.split(r"[,\s]+", extra):
        part = part.strip()
        if part and part not in out:
            out.append(part)
    return out, None


def _get_text(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace").strip()


def _expected_ports(cfg):
    raw = str(cfg.get("expected_ports") or "")
    out = set()
    for part in re.split(r"[,\s]+", raw):
        part = part.strip()
        if part.isdigit():
            out.add(int(part))
    return out


def _shodan(ip):
    try:
        data = _get(INTERNETDB_URL + ip, timeout=12)
        return {
            "ports": [int(p) for p in (data.get("ports") or []) if str(p).isdigit()],
            "cpes": data.get("cpes") or [],
            "hostnames": data.get("hostnames") or [],
            "tags": data.get("tags") or [],
            "vulns": data.get("vulns") or [],
        }, None
    except Exception as exc:
        return None, str(exc)


def _cti(ip):
    """CrowdSec reputation. Returns (data|None, error|None, skipped)."""
    try:
        data = _get(CTI_URL + ip, timeout=12)
    except Exception as exc:
        return None, str(exc), False
    attacks = data.get("attacks") or {}
    scores = data.get("scores") or {}
    if not attacks and not scores:
        return {"listed": False}, None, False
    return {
        "listed": True,
        "categories": sorted(k for k, v in attacks.items() if v),
        "scores": scores,
    }, None, False


def _incidents(cfg):
    incidents = []
    expected = _expected_ports(cfg)
    ips, err = _ips(cfg)
    if err:
        incidents.append({
            "key": "wan:detect-failed",
            "severity": "warning",
            "title": "Perimeter check could not determine WAN IP",
            "detail": err[:600],
        })
        return {"ok": True, "incidents": incidents}
    for ip in ips:
        sh, sh_err = _shodan(ip)
        if sh_err:
            incidents.append({
                "key": "shodan:%s:unreachable" % ip,
                "severity": "warning",
                "title": "Exposure check failed for %s" % ip,
                "detail": ("Shodan InternetDB unreachable (%s). If your DNS "
                           "blocks internetdb.shodan.io, exposure checking "
                           "cannot work from this network." % sh_err)[:600],
            })
            continue
        unexpected = [p for p in sh["ports"] if p not in expected]
        if unexpected:
            incidents.append({
                "key": "exposed:%s:unexpected" % ip,
                "severity": "critical",
                "title": "Unexpected open port(s) on %s: %s" % (
                    ip, ", ".join(str(p) for p in unexpected)),
                "detail": ("Shodan observes port(s) %s open on %s that are not "
                           "in your expected list. Either close them at the "
                           "firewall, or add them to the plugin's expected "
                           "ports if they are intentional. Observed: %s. "
                           "Expected: %s."
                           % (", ".join(str(p) for p in unexpected), ip,
                              ", ".join(str(p) for p in sh["ports"]) or "none",
                              ", ".join(str(p) for p in sorted(expected)) or "none"))[:600],
            })
        if sh["vulns"]:
            incidents.append({
                "key": "vulns:%s" % ip,
                "severity": "critical",
                "title": "Known vulnerability on an exposed service (%s)" % ip,
                "detail": ("Shodan reports %s on your exposed services at %s. "
                           "Update or close the affected service."
                           % (", ".join(sh["vulns"][:8]), ip))[:600],
            })
        if cfg.get("check_cti", True):
            rep, rep_err, _ = _cti(ip)
            if rep and rep.get("listed"):
                incidents.append({
                    "key": "reputation:%s" % ip,
                    "severity": "warning",
                    "title": "%s is listed in CrowdSec threat intel" % ip,
                    "detail": ("Attack categories: %s. Either a device inside "
                               "your network is compromised and attacking "
                               "others, or your ISP recycled a previously "
                               "abused address. Scores: %s."
                               % (", ".join(rep.get("categories") or []) or "?",
                                  json.dumps(rep.get("scores") or {})))[:600],
                })
            # rep_err (unreachable) is deliberately NOT an incident: it
            # would recur forever on networks that block cti.crowdsec.net.
            # It is surfaced in the web view instead.
    return {"ok": True, "incidents": incidents}


def _refresh(cfg):
    expected = _expected_ports(cfg)
    ips, err = _ips(cfg)
    if err:
        return {"ok": True, "error": err, "ips": [], "results": []}
    results = []
    for ip in ips:
        entry = {"ip": ip, "shodan": None, "shodan_error": None,
                 "reputation": None, "reputation_error": None,
                 "reputation_checked": bool(cfg.get("check_cti", True))}
        sh, sh_err = _shodan(ip)
        if sh_err:
            entry["shodan_error"] = sh_err
        else:
            sh["unexpected"] = [p for p in sh["ports"] if p not in expected]
            sh["expected"] = [p for p in sh["ports"] if p in expected]
            entry["shodan"] = sh
        if entry["reputation_checked"]:
            rep, rep_err, _ = _cti(ip)
            entry["reputation"] = rep
            entry["reputation_error"] = rep_err
        results.append(entry)
    return {"ok": True, "ips": ips, "expected": sorted(expected),
            "results": results,
            "generated": datetime.now(timezone.utc).isoformat()}


def handle(request):
    action = (request.get("action") or "").strip()
    cfg = request.get("config") or {}
    if action == "incidents":
        return _incidents(cfg)
    if action == "refresh":
        return _refresh(cfg)
    if action == "ping":
        return {"ok": True, "plugin": "perimeter-watch"}
    return {"ok": False, "error": "unknown action: %r" % action}
