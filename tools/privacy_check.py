#!/usr/bin/env python3
"""Privacy gate: the maintainer's own domain and public address ranges must
not appear in any tracked file (they leaked into nginx examples, a test
fixture and API help text before 3.3.5). Use example.com / router.example.com
and documentation addresses instead.

    python3 tools/privacy_check.py
"""
import os
import subprocess
import sys

# Built from pieces so this file does not match itself.
NEEDLES = (
    "house" + "network",
    "73.175" + ".203.",
    "2601" + ":985:",
    "2001:558" + ":6031:",
)

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def hits(text):
    low = text.lower()
    return [n for n in NEEDLES if n in low]


def main():
    check(hits("see router." + "house" + "network.site") == ["house" + "network"], "fixture: domain is found")
    check(hits("WAN 73.175" + ".203.9") and hits("prefix 2601" + ":985:aa::/56"), "fixture: addresses are found")
    check(not hits("router.example.com 192.0.2.1 2001:db8::1"), "fixture: documentation values pass")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout.decode()
    files = [f for f in out.split("\0") if f]
    check(len(files) > 100, "git ls-files listed the repository ({} files)".format(len(files)))
    for rel in files:
        check(not hits(rel), "file name: " + rel)
        path = os.path.join(root, rel)
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        with open(path, "rb") as f:
            data = f.read()
        found = hits(data.decode("utf-8", "replace"))
        if found:
            lines = [str(i) for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1)
                     if hits(line)]
            check(False, "{}:{} contains a private value".format(rel, ",".join(lines[:10])))
    print("privacy_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
