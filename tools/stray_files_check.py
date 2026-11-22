#!/usr/bin/env python3
"""Stray-file gate: no editor/backup leftovers in what ships.

www/index.html.bak-20261028-215551 and friends sat in the working tree next
to the real files; anything that copies www/ or pkg/ wholesale (a local
package build, a hand deploy) would carry them onto routers. This fails when
such a file is tracked in www/, pkg/, scripts/ or nginx/, or when one is
inside a built .deb.

    python3 tools/stray_files_check.py              # git ls-files of those dirs
    python3 tools/stray_files_check.py --deb X.deb  # also the package listing
"""
import os
import re
import subprocess
import sys

DIRS = ("www", "pkg", "scripts", "nginx")
# *.bak*  *.orig  *.rej  *.pre-*  *~  *.swp/.swo  (+ bytecode in packages)
STRAY_RE = re.compile(r"(\.bak|\.orig$|\.rej$|\.pre-|~$|\.sw[po]$|\.dpkg-(old|dist|new|bak)$)")
DEB_EXTRA_RE = re.compile(r"(/__pycache__/|\.pyc$)")

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def is_stray(path, deb=False):
    name = os.path.basename(path.rstrip("/"))
    if STRAY_RE.search(name):
        return True
    return bool(deb and DEB_EXTRA_RE.search(path))


def self_test():
    for p in ("www/index.html.bak-20261028-215551", "www/css/bento.css.bak", "pkg/x.orig",
              "scripts/a.rej", "www/includes/api_server.py.pre-335", "nginx/t.conf~",
              "www/scripts/.dashboard.js.swp", "pkg/etc/tuxwall/opencode.json.dpkg-dist"):
        check(is_stray(p), "fixture should be flagged: " + p)
    for p in ("www/index.html", "pkg/DEBIAN/prerm", "scripts/tuxwall-sqm.sh",
              "pkg/usr/local/sbin/tuxwall-bouncer-nft-migrate", "www/includes/backups.py",
              "pkg/usr/share/tuxwall/unbound/98-local-domains.conf", "nginx/tuxwall-https.conf.in"):
        check(not is_stray(p), "fixture must not be flagged: " + p)
    check(is_stray("./var/www/html/includes/__pycache__/x.cpython-314.pyc", deb=True),
          "bytecode in a .deb is flagged")
    check(not is_stray("./var/www/html/includes/api_server.py", deb=True), "real .deb file passes")


def tracked():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", *DIRS],
                         capture_output=True, check=True).stdout.decode()
    files = [f for f in out.split("\0") if f]
    check(len(files) > 50, "git ls-files returned the shipped trees ({} files)".format(len(files)))
    bad = [f for f in files if is_stray(f)]
    check(not bad, "stray files tracked: " + ", ".join(bad))


def deb_listing(deb):
    out = subprocess.run(["dpkg-deb", "-c", deb], capture_output=True, text=True, check=True).stdout
    paths = [line.split(None, 5)[-1].split(" -> ")[0] for line in out.splitlines() if line.strip()]
    check(len(paths) > 50, "dpkg-deb -c listed the package ({} entries)".format(len(paths)))
    bad = [p for p in paths if is_stray(p, deb=True)]
    check(not bad, "stray files inside {}: {}".format(deb, ", ".join(bad)))


def main(argv):
    self_test()
    tracked()
    if "--deb" in argv:
        deb_listing(argv[argv.index("--deb") + 1])
    print("stray_files_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
