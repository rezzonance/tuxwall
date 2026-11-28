#!/usr/bin/env python3
""""What to do" guidance for TuxWall device monitoring findings (3.3.7).

One table, keyed by guidance key (the finding kind; ids_alert is split into
"ids_alert:outbound" - traffic the device started or an attack response it
sent - and "ids_alert:inbound" - an attack it only received) and device
class (computer / phone / iot / vpn / unknown, from the engine's type
guess). Each entry has:
    meaning        1-2 plain sentences (str, or {class: str})
    steps          {"default": [...], class: [...]}: 2-4 short steps
    expected_hint  optional "known cause?" hint (str or None)
Used by the API only (device panel, Security > Local rows, the push alert's
first step, Home Assistant events); the engine does not import it. Texts
never contain links - details are in the README section "Device monitoring".
Phase 2 detector kinds plug in by adding an entry; a kind without one gets
the "_generic" entry, so every finding always has guidance.
"""

DEVICE_CLASSES = ("computer", "phone", "iot", "vpn", "unknown")
CLASS_OF_TYPE = {
    "computer": "computer", "nas": "computer",
    "phone": "phone", "tablet": "phone",
    "tv": "iot", "speaker": "iot", "camera": "iot", "printer": "iot", "iot": "iot", "console": "iot",
    "network": "iot",
    "vpn-client": "vpn",
}
MEANING_MAX = 260
STEP_MAX = 170
HINT_MAX = 170
STEPS_MIN, STEPS_MAX = 2, 4
MORE = "README: Device monitoring"

_SCAN_PC = "Run a full malware scan (the built-in antivirus, ideally its offline scan) or reinstall the system."
_PW_CLEAN = "From a clean device, change the passwords used on it and turn on two-factor sign-in."
_FW_IOT = "Install the latest firmware, or factory-reset the device and set it up again."
_PW_IOT = "Change its admin password and switch off remote access, UPnP and port forwards you do not need."
_WHO = "Find out which device this is (name, vendor and MAC on the Clients page)."
_PORTS = "Check port forwards and the DMZ on the Firewall page and close what you do not need."

GUIDANCE = {
    "c2_connection": {
        "meaning": "This device connected to a server that a threat feed lists as a botnet control (C2) server. "
                   "That usually means malware on the device is checking in for orders.",
        "steps": {
            "default": ["Quarantine it now (Isolate) so it cannot reach the internet or other devices.",
                        _SCAN_PC, _PW_CLEAN,
                        "Release the quarantine only when the scan is clean and the finding does not come back."],
            "phone": ["Quarantine it now (Isolate).",
                      "Remove apps you do not recognise or installed recently and update the system; "
                      "if it continues, back it up and factory-reset it.",
                      "From a clean device, change the passwords used on the phone.",
                      "Release the quarantine when the finding does not come back."],
            "iot": ["Quarantine it now (Isolate).", _FW_IOT, _PW_IOT,
                    "Release it when the finding stops; an IoT VLAN keeps such devices away from your computers."],
            "vpn": ["Quarantine the peer (or disable it on the WireGuard page) so it cannot reach your network.",
                    "Check the device behind this peer for malware: scan, updates, unknown apps.",
                    "If you do not know who uses this peer, delete it and create a new one."],
            "unknown": ["Quarantine it now (Isolate).", _WHO,
                        "Not yours: keep it blocked and change the Wi-Fi password. "
                        "Yours: scan or factory-reset and update it before you release it."],
        },
        "expected_hint": None,
    },
    "intel_connection": {
        "meaning": "This device completed a connection to an address that a threat feed lists as a malware host "
                   "(often a site that hands out malware). Something harmful may have been downloaded.",
        "steps": {
            "default": ["Check what was opened around that time: browser history, downloads, email attachments.",
                        _SCAN_PC + " Delete suspicious downloads.",
                        "If the scan finds something or the finding repeats, quarantine the device until it is clean."],
            "phone": ["Check apps installed and links opened around that time.",
                      "Update the system and remove apps you do not trust.",
                      "If the finding repeats, quarantine the phone until it is clean."],
            "iot": ["A smart device should not visit malware hosts: " + _FW_IOT[0].lower() + _FW_IOT[1:], _PW_IOT,
                    "If the finding repeats, quarantine it (Isolate)."],
            "vpn": ["Check the device behind this VPN peer: scan it, review downloads and apps.",
                    "If the finding repeats or you do not know the peer, quarantine or disable it."],
            "unknown": [_WHO, "Scan or update it; if the finding repeats, quarantine it."],
        },
        "expected_hint": "Known cause (a shared hosting or cloud address)? Mark expected, or Silence the indicator.",
    },
    "dns_lookup": {
        "meaning": "This device looked up a domain that a threat feed lists as malicious, and the lookup was answered "
                   "- it may have connected to it afterwards.",
        "steps": {
            "default": ["Check what was opened around that time: browser history, downloads, email links.",
                        _SCAN_PC,
                        "If the finding repeats, quarantine the device until it is clean."],
            "phone": ["Check apps installed and links opened around that time.",
                      "Update the system and remove apps you do not trust.",
                      "If the finding repeats, quarantine the phone until it is clean."],
            "iot": [_FW_IOT, _PW_IOT, "If the finding repeats, quarantine it (Isolate)."],
            "vpn": ["Check the device behind this VPN peer: scan it, review downloads and apps.",
                    "If the finding repeats or you do not know the peer, quarantine or disable it."],
            "unknown": [_WHO, "Scan or update it; if the finding repeats, quarantine it."],
        },
        "expected_hint": "Known, harmless domain (listed by mistake)? Mark expected, or Silence the domain.",
    },
    "intel_attempt": {
        "meaning": "This device tried to reach an address that a threat feed lists as malicious but got no answer "
                   "(the server is down or was blocked). Something on the device still tried.",
        "steps": {
            "default": ["Check which program or website was in use at that time.", _SCAN_PC,
                        "If it keeps trying, quarantine the device until it is clean."],
            "phone": ["Check which app was in use at that time; remove apps you do not trust.",
                      "Update the system.", "If it keeps trying, quarantine the phone until it is clean."],
            "iot": [_FW_IOT, _PW_IOT, "If it keeps trying, quarantine it (Isolate)."],
            "vpn": ["Check the device behind this VPN peer: scan it and review its apps.",
                    "If it keeps trying, quarantine or disable the peer."],
            "unknown": [_WHO, "Scan or update it; if it keeps trying, quarantine it."],
        },
        "expected_hint": "Known cause (a shared cloud address)? Mark expected.",
    },
    "intel_inbound": {
        "meaning": "A listed malicious address connected to this device from the internet. That is usually a scanner "
                   "probing an open port, not an infection.",
        "steps": {
            "default": [_PORTS,
                        "Keep the software on the device up to date and use strong passwords on anything reachable "
                        "from the internet.",
                        "Nothing else to do when the device has no port forward."],
            "vpn": ["Check which of your services the VPN peers can reach.",
                    "Keep those services up to date and protected by passwords.",
                    "Nothing else to do when the finding stops."],
        },
        "expected_hint": "A server you expose on purpose? Mark expected, or Silence the kind for this device.",
    },
    "dns_blocked": {
        "meaning": "The router's DNS blocklist stopped this device from looking up a listed domain, so nothing was "
                   "reached. A one-off is often an ad or a clicked link.",
        "steps": {
            "default": ["No action needed for a single lookup.",
                        "If it repeats every day, find the program or website behind it."],
            "phone": ["No action needed for a single lookup - often an ad inside an app.",
                      "If it repeats, find the app behind it (free games and recently installed apps are common) "
                      "and remove it."],
            "iot": ["No action needed for a single lookup.",
                    "If it repeats, update the device's firmware or remove its companion app or skill."],
        },
        "expected_hint": "A known chatty app? Silence the domain on all devices.",
    },
    "ids_alert:outbound": {
        "meaning": "Suricata saw traffic from this device that matches a malware or attack signature, on a "
                   "connection the device started. Treat the device as possibly compromised.",
        "steps": {
            "default": ["Quarantine it (Isolate) while you check.", _SCAN_PC + " Remove programs you do not know.",
                        _PW_CLEAN, "Release it when the scan is clean and the alert stops."],
            "phone": ["Quarantine it (Isolate) while you check.",
                      "Remove apps you do not recognise and update the system; if it continues, factory-reset it.",
                      "Release it when the alert stops."],
            "iot": ["Quarantine it (Isolate) while you check.", _FW_IOT, _PW_IOT],
            "vpn": ["Quarantine or disable the peer while you check.",
                    "Scan the device behind it and remove programs you do not know.",
                    "If you do not know who uses this peer, delete it and create a new one."],
            "unknown": ["Quarantine it (Isolate).", _WHO,
                        "Not yours: keep it blocked and change the Wi-Fi password."],
        },
        "expected_hint": "A known false alarm for this signature? Suppress the rule (Security > Sensors) or "
                         "Mark expected.",
    },
    "ids_alert:inbound": {
        "meaning": "Suricata saw an attack against this device from outside - the device was the target, for "
                   "example a scan of a service you expose. It does not mean the device is infected.",
        "steps": {
            "default": [_PORTS,
                        "Update what is exposed (web server, NAS, camera firmware) and use strong passwords.",
                        "Repeat attackers are banned by CrowdSec; nothing else to do if the alert stays low."],
            "vpn": ["Check which services the VPN peers can reach and keep them up to date.",
                    "Nothing else to do if the alert stays low."],
        },
        "expected_hint": "A noisy signature? Suppress the rule on Security > Sensors, or Mark expected.",
    },
    "new_device": {
        "meaning": "A device joined the network for the first time.",
        "steps": {
            "default": ["Check the name, vendor and network: is it yours (a new device, a guest)?",
                        "Yours: Rename it so you recognise it later.",
                        "Not yours: block it (Access column or Quarantine) and change the Wi-Fi password."],
            "phone": ["Check the name and vendor: phones use a random (private) MAC per network, so a known phone "
                      "can show up as new after a reset.",
                      "Yours: Rename it so you recognise it later.",
                      "Not yours: block it (Access column or Quarantine) and change the Wi-Fi password."],
            "vpn": ["A new WireGuard peer connected: check on the WireGuard page that you created it.",
                    "Not yours: delete the peer and create new keys for the others."],
        },
        "expected_hint": "Yours? Dismiss the row on Security > Local.",
    },
    "_generic": {
        "meaning": "A detector flagged unusual activity on this device.",
        "steps": {
            "default": ["Look at what the finding names (destination, time) in the device panel.",
                        "If you do not recognise it, scan or update the device; quarantine it if the finding repeats."],
        },
        "expected_hint": "Known cause? Mark expected, or Silence it.",
    },
}


def device_class(dev_type):
    return CLASS_OF_TYPE.get(str(dev_type or "").strip().lower(), "unknown")


def guidance_key(finding):
    """The table key of a finding dict (or a bare kind string)."""
    if isinstance(finding, str):
        kind, f = finding, {}
    else:
        f = finding if isinstance(finding, dict) else {}
        kind = str(f.get("kind") or "")
    if kind == "ids_alert":
        det = f.get("details") if isinstance(f.get("details"), dict) else {}
        title = str(f.get("title") or "").upper()
        sent = title.startswith(("ET ATTACK_RESPONSE", "GPL ATTACK_RESPONSE")) or \
            str(det.get("category") or "").startswith("Successful")
        outbound = det.get("direction") == "outbound" or (sent and f.get("severity") not in ("low", "info", None))
        return "ids_alert:outbound" if outbound else "ids_alert:inbound"
    return kind if kind in GUIDANCE else "_generic"


def guidance(finding, dev_type=None):
    """-> {"key", "device_class", "meaning", "steps", "expected_hint", "more"}."""
    key = guidance_key(finding)
    cls = device_class(dev_type)
    g = GUIDANCE[key]
    meaning = g["meaning"]
    if isinstance(meaning, dict):
        meaning = meaning.get(cls) or meaning["default"]
    steps = g["steps"].get(cls) or g["steps"]["default"]
    return {"key": key, "device_class": cls, "meaning": meaning, "steps": list(steps),
            "expected_hint": g.get("expected_hint"), "more": MORE}


def first_step(finding, dev_type=None):
    """One line for a push alert / Home Assistant event."""
    return guidance(finding, dev_type)["steps"][0]


def table_problems():
    """Every key x device class must resolve to a bounded, link-free text
    (tools/devicewatch_check.py)."""
    out = []
    for key, g in GUIDANCE.items():
        if "default" not in g.get("steps", {}):
            out.append("%s: no default steps" % key)
            continue
        for cls in DEVICE_CLASSES:
            m = (g["meaning"].get(cls) or g["meaning"]["default"]) if isinstance(g["meaning"], dict) else g["meaning"]
            steps = g["steps"].get(cls) or g["steps"]["default"]
            texts = [m] + list(steps) + ([g["expected_hint"]] if g.get("expected_hint") else [])
            if not (isinstance(m, str) and 20 <= len(m) <= MEANING_MAX):
                out.append("%s/%s: meaning length %d" % (key, cls, len(m or "")))
            if not STEPS_MIN <= len(steps) <= STEPS_MAX:
                out.append("%s/%s: %d steps" % (key, cls, len(steps)))
            for s in steps:
                if not (isinstance(s, str) and 10 <= len(s) <= STEP_MAX):
                    out.append("%s/%s: step length %d: %s" % (key, cls, len(s or ""), (s or "")[:40]))
            if g.get("expected_hint") and len(g["expected_hint"]) > HINT_MAX:
                out.append("%s: hint too long" % key)
            for t in texts:
                low = t.lower()
                if "http" in low or "www." in low or "://" in low or "<" in t or "&" in t:
                    out.append("%s/%s: link or markup in %r" % (key, cls, t[:40]))
        for cls in g["steps"]:
            if cls != "default" and cls not in DEVICE_CLASSES:
                out.append("%s: unknown class %s" % (key, cls))
    return out
