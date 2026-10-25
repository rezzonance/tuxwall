"""TuxWall Certificate Watch plugin (cert-watch).

Contributes TLS-certificate conditions to the shared TuxWall incidents
system (the same machinery UniFi feeds): the host polls the "incidents"
action on its cycle, and this worker answers with per-endpoint
certificate expiry states.

Design notes:
- It checks the certificate each endpoint ACTUALLY PRESENTS by making a
  TLS connection (openssl s_client -> x509). No file access and no
  privileges are needed, and it verifies the thing that breaks when a
  cert expires: what the service serves. /etc/letsencrypt is root-only,
  so a sandboxed worker could not read cert files directly anyway.
- Healthy certificates stay silent; the severity ladder is
    expired or <= critical_days  -> critical (also fires webhooks)
    <= warning_days              -> warning
    <= 30 days                   -> info nudge
- Each incident key is stable per endpoint, so a renewed certificate
  resolves its own incident on the next poll.
- Renewal guidance: Let's Encrypt issuers get an automatic certbot
  command; the configured renewal_hint is always appended.
"""

import json
import re
import subprocess
from datetime import datetime, timezone


def _endpoints(cfg):
    raw = str(cfg.get("endpoints") or "127.0.0.1:443")
    out = []
    for part in re.split(r"[,\n]", raw):
        part = part.strip()
        if part:
            out.append(part)
    # stable order, deduped
    seen = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def _int_setting(cfg, key, default):
    try:
        return int(str(cfg.get(key) or "").strip() or default)
    except ValueError:
        return default


def _probe(endpoint):
    """Connect to host:port and return the presented certificate fields.

    Returns (info dict, None) on success or (None, error message).
    """
    host, _, port = endpoint.partition(":")
    port = port or "443"
    try:
        # get the served cert
        conn = subprocess.run(
            ["openssl", "s_client", "-connect", "%s:%s" % (host, port),
             "-servername", host],
            input=b"", capture_output=True, timeout=8)
        if conn.returncode != 0 or not conn.stdout:
            # openssl s_client "fails" with nonzero exit on some servers
            # while still printing the cert; only give up on empty output
            pass
        parsed = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate",
             "-ext", "subjectAltName"],
            input=conn.stdout, capture_output=True, timeout=8)
        text = parsed.stdout.decode("utf-8", "replace")
        if "notAfter" not in text:
            detail = (conn.stderr or b"").decode("utf-8", "replace").strip()
            return None, detail or "no certificate presented"
    except subprocess.TimeoutExpired:
        return None, "connection timed out"
    except Exception as exc:
        return None, str(exc)

    def field(pattern):
        m = re.search(pattern, text)
        return m.group(1).strip() if m else ""

    subject = field(r"subject\s*=\s*(.+)")
    issuer = field(r"issuer\s*=\s*(.+)")
    not_after = field(r"notAfter\s*=\s*(.+)")
    sans = field(r"subjectAltName\s*=\s*(.+)")
    if not not_after:
        return None, "certificate without notAfter date"
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None, "unparseable expiry date: %s" % not_after
    expires = expires.replace(tzinfo=timezone.utc)
    return {
        "endpoint": endpoint,
        "host": host,
        "port": port,
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "not_after": not_after,
        "expires_ts": expires.timestamp(),
        "expires_iso": expires.isoformat(),
    }, None


def _days_left(info):
    from datetime import datetime as dt
    return int((info["expires_ts"] - dt.now(timezone.utc).timestamp()) / 86400)


def _renewal_guidance(info, cfg):
    parts = []
    issuer = (info.get("issuer") or "").lower()
    if "let's encrypt" in issuer or "lets encrypt" in issuer or "r3" == issuer[:2] or "e1" == issuer[:2]:
        parts.append("Let's Encrypt certificate - renew with: "
                     "sudo certbot renew && sudo systemctl reload nginx")
    hint = str(cfg.get("renewal_hint") or "").strip()
    if hint:
        parts.append("Renewal: %s" % hint)
    return " | ".join(parts)


def _incidents(cfg):
    critical_days = _int_setting(cfg, "critical_days", 7)
    warning_days = _int_setting(cfg, "warning_days", 14)
    incidents = []
    for endpoint in _endpoints(cfg):
        info, err = _probe(endpoint)
        if err is not None:
            incidents.append({
                "key": "tls-check:%s" % endpoint,
                "severity": "warning",
                "title": "TLS check failed for %s" % endpoint,
                "detail": ("Could not read a certificate from %s (%s). "
                           "If the service is intentionally down, disable "
                           "this endpoint in plugin settings."
                           % (endpoint, err[:200])),
            })
            continue
        days = _days_left(info)
        guidance = _renewal_guidance(info, cfg)
        if days < 0:
            incidents.append({
                "key": "cert:%s" % endpoint,
                "severity": "critical",
                "title": "Certificate EXPIRED %d day(s) ago for %s" % (-days, endpoint),
                "detail": ("%s presented by %s expired %s. Clients are "
                           "already seeing errors. %s"
                           % (info["subject"] or "Certificate", endpoint,
                              info["not_after"], guidance))[:600],
            })
        elif days <= critical_days:
            incidents.append({
                "key": "cert:%s" % endpoint,
                "severity": "critical",
                "title": "Certificate for %s expires in %d day(s)" % (endpoint, days),
                "detail": ("%s (%s) expires %s. Renew NOW. %s"
                           % (info["subject"] or "Certificate",
                              info["issuer"] or "unknown issuer",
                              info["not_after"], guidance))[:600],
            })
        elif days <= warning_days:
            incidents.append({
                "key": "cert:%s" % endpoint,
                "severity": "warning",
                "title": "Certificate for %s expires in %d day(s)" % (endpoint, days),
                "detail": ("%s (%s) expires %s. %s"
                           % (info["subject"] or "Certificate",
                              info["issuer"] or "unknown issuer",
                              info["not_after"], guidance))[:600],
            })
        elif days <= 30:
            incidents.append({
                "key": "cert:%s" % endpoint,
                "severity": "info",
                "title": "Certificate for %s renews in %d day(s)" % (endpoint, days),
                "detail": ("%s (%s) expires %s. Healthy - reminder only. %s"
                           % (info["subject"] or "Certificate",
                              info["issuer"] or "unknown issuer",
                              info["not_after"], guidance))[:600],
            })
        # healthy (> 30 days): silent
    return {"ok": True, "incidents": incidents}


def _refresh(cfg):
    certs = []
    problems = []
    for endpoint in _endpoints(cfg):
        info, err = _probe(endpoint)
        if err is not None:
            problems.append({"endpoint": endpoint, "error": err[:300]})
            continue
        info["days"] = _days_left(info)
        info["renewal"] = _renewal_guidance(info, cfg)
        certs.append(info)
    return {"ok": True, "certs": certs, "problems": problems,
            "checked": _endpoints(cfg)}


def handle(request):
    action = (request.get("action") or "").strip()
    cfg = request.get("config") or {}
    if action == "incidents":
        return _incidents(cfg)
    if action == "refresh":
        return _refresh(cfg)
    if action == "ping":
        return {"ok": True, "plugin": "cert-watch",
                "endpoints": _endpoints(cfg)}
    return {"ok": False, "error": "unknown action: %r" % action}
