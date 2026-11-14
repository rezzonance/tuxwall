#!/usr/bin/env python3
"""TuxWall canary (opencanary) egress containment in /etc/ufw/before*.rules.

The canary runs as the ``opencanary`` system user. These owner-match rules in
ufw-before-output let it reach only the dashboard webhook and local DNS (plus
replies on its own sessions); everything else it initiates is logged with the
[TUXWALL-CANARY-EGRESS] prefix (the tripwire watches for it) and rejected.

One definition shared by the installer, the package postinst,
scripts/opencanary/deploy-opencanary.sh and the firewall guard (fw_guard's
repair plan for ``canary-egress-missing``).

Containment is "present" when the output chain has an unconditional
``--uid-owner opencanary|<uid> ... -j REJECT``; marker comments are not
trusted (the 3.3.1 installer looked for "Tuxwall canary egress", which its own
comment does not contain, so every run inserted another copy).

  python3 canary_egress.py --check            exit 0 present (both files), 1 missing
  python3 canary_egress.py --plan             print the insertion as a diff
  python3 canary_egress.py --apply [--no-reload] [--root DIR]
        insert where missing (idempotent, only when the opencanary user
        exists), then `ufw reload` best-effort. Never exits non-zero for a
        missing user or an unexpected file layout.
"""
import difflib
import os
import re
import subprocess
import sys

MARK = "# --- Tuxwall canary (opencanary) egress containment ---"
MARK6 = "# --- Tuxwall canary (opencanary) egress containment (IPv6) ---"
_LOG = '-m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[TUXWALL-CANARY-EGRESS] "'

LINES = {
    "v4": [
        MARK,
        "-A ufw-before-output -m owner --uid-owner opencanary -p tcp -d 127.0.0.1 --dport 8008 -j ACCEPT",
        "-A ufw-before-output -m owner --uid-owner opencanary -p udp -d 127.0.0.1 --dport 53 -j ACCEPT",
        "-A ufw-before-output -m owner --uid-owner opencanary -p tcp -d 127.0.0.1 --dport 53 -j ACCEPT",
        "-A ufw-before-output -m owner --uid-owner opencanary -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "# only connections the canary initiates (ctstate NEW, not from its service ports) are logged",
        "-A ufw-before-output -m owner --uid-owner opencanary -p tcp -m conntrack --ctstate NEW "
        "-m multiport ! --sports 22,5900,1433,6379 " + _LOG,
        "-A ufw-before-output -m owner --uid-owner opencanary -p udp -m conntrack --ctstate NEW "
        "! --sport 161 " + _LOG,
        "-A ufw-before-output -m owner --uid-owner opencanary -j REJECT",
    ],
    "v6": [
        MARK6,
        "-A ufw6-before-output -m owner --uid-owner opencanary -p udp -d ::1 --dport 53 -j ACCEPT",
        "-A ufw6-before-output -m owner --uid-owner opencanary -p tcp -d ::1 --dport 53 -j ACCEPT",
        "-A ufw6-before-output -m owner --uid-owner opencanary -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "-A ufw6-before-output -m owner --uid-owner opencanary -m conntrack --ctstate NEW " + _LOG,
        "-A ufw6-before-output -m owner --uid-owner opencanary -j REJECT",
    ],
}
FILES = {"v4": "/etc/ufw/before.rules", "v6": "/etc/ufw/before6.rules"}
ANCHORS = {"v4": "-A ufw-before-output -o lo -j ACCEPT", "v6": "-A ufw6-before-output -o lo -j ACCEPT"}


def _owner_re(uid=None):
    who = "opencanary" + ("|" + re.escape(str(uid)) if uid else "")
    return re.compile(r"--uid-owner (?:%s)(?:\s|$)" % who)


def _is_catch_all_reject(line):
    """-j REJECT with no destination/protocol/port restriction."""
    f = line.split()
    return ("-j" in f and f[f.index("-j") + 1] == "REJECT"
            and not any(x in f for x in ("-d", "-p", "--dport", "--dports", "-o")))


def containment_lines(text, family, uid=None):
    chain = "-A ufw-before-output " if family == "v4" else "-A ufw6-before-output "
    rx = _owner_re(uid)
    return [l for l in (text or "").splitlines() if l.startswith(chain) and rx.search(l)]


def present(text, family, uid=None):
    """True when the owner-match catch-all REJECT for the canary is there."""
    return any(_is_catch_all_reject(l) for l in containment_lines(text, family, uid))


def has_log(text, family, uid=None):
    return any("TUXWALL-CANARY-EGRESS" in l for l in containment_lines(text, family, uid))


def copies(text, family, uid=None):
    """Number of catch-all REJECT lines (more than one = duplicated block)."""
    return sum(1 for l in containment_lines(text, family, uid) if _is_catch_all_reject(l))


def insert(text, family):
    """(new_text, changed). Inserts the block right before the lo-ACCEPT
    anchor of the output chain; unchanged when present or the anchor is not
    exactly once in the file."""
    if present(text, family):
        return text, False
    anchor = ANCHORS[family]
    lines = text.split("\n")
    idx = [i for i, l in enumerate(lines) if l.strip() == anchor]
    if len(idx) != 1:
        return text, False
    lines[idx[0]:idx[0]] = LINES[family]
    return "\n".join(lines), True


def plan(texts):
    """{family: unified diff} for the files that would change."""
    out = {}
    for fam, path in FILES.items():
        old = texts.get(fam) or ""
        new, changed = insert(old, fam)
        if changed:
            out[fam] = "".join(difflib.unified_diff(
                old.splitlines(True), new.splitlines(True), path, path + " (with containment)", n=2))
    return out


def user_exists(root=""):
    try:
        with open(root + "/etc/passwd") as f:
            return any(l.split(":", 1)[0] == "opencanary" for l in f)
    except OSError:
        return False


def _read(p):
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return None


def apply(root="", reload=True, log=print):
    """Insert where missing. Returns the list of families changed."""
    if not user_exists(root):
        log("canary egress: no opencanary user - nothing to do")
        return []
    changed = []
    for fam, path in FILES.items():
        p = root + path
        text = _read(p)
        if text is None:
            log("canary egress: %s not found - skipped" % path)
            continue
        new, did = insert(text, fam)
        if not did:
            if not present(text, fam):
                log("canary egress: %s has no single '%s' anchor - not changed" % (path, ANCHORS[fam]))
            continue
        st = os.stat(p)
        tmp = p + ".tuxwall-tmp"
        with open(tmp, "w") as f:
            f.write(new)
        os.chmod(tmp, st.st_mode & 0o777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.replace(tmp, p)
        changed.append(fam)
        log("canary egress: containment added to %s" % path)
    if changed and reload and not root:
        try:
            subprocess.run(["ufw", "reload"], capture_output=True, timeout=60)
        except Exception as exc:  # best effort
            log("canary egress: ufw reload failed: %s" % exc)
    return changed


def main(argv):
    root = ""
    if "--root" in argv:
        root = argv[argv.index("--root") + 1].rstrip("/")
    texts = {fam: _read(root + p) or "" for fam, p in FILES.items()}
    if "--check" in argv:
        ok = all(present(texts[f], f) for f in FILES)
        print("present" if ok else "missing")
        return 0 if ok else 1
    if "--plan" in argv:
        for fam, d in plan(texts).items():
            sys.stdout.write(d)
        return 0
    if "--apply" in argv:
        try:
            apply(root, reload="--no-reload" not in argv)
        except Exception as exc:  # never fail an install
            print("canary egress: %s" % exc)
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
