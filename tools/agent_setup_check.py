#!/usr/bin/env python3
"""AI assistant install (3.3.4, finding 8.3), sandboxed:

  python3 tools/agent_setup_check.py

- packaging: every file the maintainer scripts, tuxwall-install.sh and the
  shipped units name under /usr/local/share/tuxwall, /usr/local/sbin,
  /usr/local/lib/tuxwall, /usr/share/tuxwall and /var/www/html/scripts is in
  the package tree (pkg/ or www/), executables with mode 0755. 3.3.3 looked
  for setup-opencode-agent.sh but never shipped it.
- setup-opencode-agent.sh (sourced, curl/uname stubbed, temp dirs only): an
  installed binary is never downloaded again; uname -m -> npm target
  (x86_64 avx2 / baseline, aarch64, unsupported -> skip); pinned version +
  per-target SHA-256; a checksum mismatch, a version override without a
  hash or an archive without the binary is refused and installs nothing; no
  internet -> message with the re-run command; no pipe-to-shell; config and
  unit install-if-absent; web root only with TUXWALL_AGENT_EDIT_WEBROOT=1.
- the unit drop-in (package file, not a conffile) skips tuxwall-agent.service
  while the binary the unit starts is missing.
- the dashboard API reports installed:false + the install command when the
  binary is missing.
- bash -n on the script and the installer.
- agent password (3.3.8): no unit, drop-in, maintainer script, installer or
  helper puts a secret-looking variable (PASSWORD|SECRET|TOKEN|KEY) into an
  Environment= line (systemd shows Environment= to every local user via
  `systemctl show`). agent_password_setup (fixtures under a temp root,
  dummy values only): one root-only env file (0600) with the same value for
  OPENCODE_SERVER_PASSWORD and TUXWALL_AGENT_PASSWORD, both drop-ins only
  EnvironmentFile= (the agent's without "-": no start without a password);
  3.3.7's Environment= drop-ins -> a NEW password, old drop-ins and
  agent-token gone, the old value nowhere under the root; idempotent
  (second run rc 0, value kept); bad modes / mismatched values repaired;
  the password is never printed; --password-only needs root (or a test root).
"""
import hashlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "pkg")
SCRIPT_REL = "usr/local/share/tuxwall/scripts/setup-opencode-agent.sh"
SCRIPT = os.path.join(PKG, SCRIPT_REL)
DROPIN = os.path.join(PKG, "usr/lib/systemd/system/tuxwall-agent.service.d/10-installed.conf")
UNIT = os.path.join(PKG, "etc/systemd/system/tuxwall-agent.service")
INSTALLER = os.path.join(ROOT, "tuxwall-install.sh")
AGENT_BIN = "/home/tuxwall-agent/.opencode/bin/opencode"
SETUP_CMD = "sudo bash /usr/local/share/tuxwall/scripts/setup-opencode-agent.sh"

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def read(p):
    with open(p) as f:
        return f.read()


# ── (a) packaging ─────────────────────────────────────────────────────────
PATH_RE = re.compile(r"/(?:usr/local/share/tuxwall|usr/local/sbin|usr/local/lib/tuxwall|usr/share/tuxwall"
                     r"|var/www/html/scripts)/[A-Za-z0-9_./-]*")
# Named but deliberately not in the .deb (each with the reason):
NOT_SHIPPED = {
    # fallback candidate only; /var/www/html/scripts/install-speedtest.sh ships
    "/usr/local/share/tuxwall/scripts/install-speedtest.sh",
}
EXEC_DIRS = ("/usr/local/sbin/", "/usr/local/lib/tuxwall/")


def pkg_path(abs_path):
    if abs_path.startswith("/var/www/html/"):
        return os.path.join(ROOT, "www", abs_path[len("/var/www/html/"):])
    return os.path.join(PKG, abs_path.lstrip("/"))


def git_mode(rel):
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files", "-s", "--", rel],
                             capture_output=True, text=True, timeout=30).stdout
    except OSError:
        return None
    return out.split()[0] if out.strip() else None


def t_packaging():
    sources = [os.path.join(PKG, "DEBIAN", n) for n in ("postinst", "prerm", "postrm")] + [INSTALLER]
    unit_dir = os.path.join(PKG, "etc", "systemd", "system")
    sources += [os.path.join(unit_dir, n) for n in sorted(os.listdir(unit_dir)) if n.endswith((".service", ".timer"))]
    named = {}
    for src in sources:
        for m in PATH_RE.finditer(read(src)):
            named.setdefault(m.group(0).rstrip("."), set()).add(os.path.basename(src))
    check("/" + SCRIPT_REL in named, "postinst/installer name /%s" % SCRIPT_REL)
    check("/var/www/html/scripts/setup-opencode-agent.sh" not in named,
          "nothing looks for the agent setup in the web root any more")
    for path, where in sorted(named.items()):
        if path in NOT_SHIPPED:
            check(not os.path.exists(pkg_path(path)), "%s is listed as not shipped but is in the tree" % path)
            continue
        target = pkg_path(path)
        if path.endswith("/"):
            check(os.path.isdir(target), "%s (named in %s) is a directory in the package" % (path, ", ".join(sorted(where))))
            continue
        check(os.path.isfile(target), "%s (named in %s) is shipped" % (path, ", ".join(sorted(where))))
        if os.path.isfile(target) and (path.startswith(EXEC_DIRS) or path.endswith(".sh")):
            mode = os.stat(target).st_mode
            check(mode & 0o111 == 0o111 and not mode & 0o002, "%s executable, not world-writable (%o)" % (path, mode & 0o777))
            rel = os.path.relpath(target, ROOT)
            gm = git_mode(rel)
            check(gm in (None, "100755"), "%s is 100755 in git (%s)" % (rel, gm))
    check(not os.path.exists(os.path.join(ROOT, "scripts", "setup-opencode-agent.sh")),
          "single copy of setup-opencode-agent.sh (pkg/ is the source)")
    conffiles = read(os.path.join(PKG, "DEBIAN", "conffiles")).split()
    check(not any("tuxwall-agent.service.d" in c for c in conffiles), "the agent drop-in is not a conffile")


# ── (b) setup script with stubs ───────────────────────────────────────────
FAKE_CURL = r"""#!/bin/bash
echo "curl $*" >> "$FAKE_LOG"
[ -n "${FAKE_CURL_FAIL:-}" ] && { echo "curl: (6) Could not resolve host" >&2; exit 6; }
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2 ;; *) shift ;; esac; done
cp "$FAKE_TGZ" "$out"
"""
FAKE_UNAME = '#!/bin/sh\n[ "$1" = -m ] && { echo "${FAKE_MACHINE:-x86_64}"; exit 0; }\nexec /usr/bin/uname "$@"\n'


def make_tgz(path, with_bin=True, body=b"#!/bin/sh\necho 'opencode v9.9.9'\n"):
    with tarfile.open(path, "w:gz") as tf:
        def add(name, data, mode):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = mode
            tf.addfile(ti, io.BytesIO(data))
        add("package/package.json", b'{"name":"@opencode/cli-linux-x64"}\n', 0o644)
        if with_bin:
            add("package/bin/opencode", body, 0o755)
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def run_fn(d, call, env=None):
    e = dict(os.environ, FAKE_LOG=d + "/calls", TMPDIR=d + "/tmp")
    e["PATH"] = d + "/fbin:" + os.environ.get("PATH", "")
    for k in ("TUXWALL_OPENCODE_VERSION", "TUXWALL_OPENCODE_SHA256", "FAKE_CURL_FAIL"):
        e.pop(k, None)
    e.update(env or {})
    if os.path.exists(d + "/calls"):
        os.unlink(d + "/calls")
    p = subprocess.run(["bash", "-c", 'source "$1"; set +e; ' + call + '; echo "rc=$?"', "x", SCRIPT],
                       env=e, capture_output=True, text=True, timeout=60)
    calls = read(d + "/calls").splitlines() if os.path.exists(d + "/calls") else []
    m = re.search(r"rc=(\d+)\s*$", p.stdout)
    return (int(m.group(1)) if m else -1), calls, p.stdout + p.stderr


def t_setup_script():
    src = read(SCRIPT)
    r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
    check(r.returncode == 0, "bash -n setup-opencode-agent.sh %s" % r.stderr)
    check(not re.search(r"curl[^\n]*\|\s*(ba)?sh", src), "no pipe-to-shell install")
    check(re.search(r'^OPENCODE_VERSION_PIN="\d+\.\d+\.\d+"$', src, re.M) is not None, "opencode version pinned")
    pins = dict(re.findall(r"^\s+(linux-[a-z0-9-]+)\)\s+echo ([0-9a-f]{64}) ;;$", src, re.M))
    check(set(pins) == {"linux-x64", "linux-x64-baseline", "linux-arm64"} and len(set(pins.values())) == 3,
          "one SHA-256 per target (%s)" % sorted(pins))
    check('"${BASH_SOURCE[0]}" == "$0"' in src, "main only runs when executed (sourcing is side-effect free)")
    check("! -e /etc/tuxwall/opencode.json" in src, "opencode.json is installed only when absent")
    check("! -e /etc/systemd/system/tuxwall-agent.service" in src, "the unit is installed only when absent")
    check(re.search(r'if \[\[ \$\{TUXWALL_AGENT_EDIT_WEBROOT:-0\} == 1[^\n]*\]\]; then\n\s+chown -R "\$AGENT_USER":www-data', src)
          is not None, "web root handed to the agent only with TUXWALL_AGENT_EDIT_WEBROOT=1")
    check("AGENT_BIN=\"$AGENT_HOME/.opencode/bin/opencode\"" in src and 'AGENT_HOME="/home/$AGENT_USER"' in src,
          "the script installs the binary the unit starts")

    d = tempfile.mkdtemp(prefix="agent-setup-")
    try:
        os.makedirs(d + "/fbin")
        os.makedirs(d + "/tmp")
        for name, body in (("curl", FAKE_CURL), ("uname", FAKE_UNAME)):
            with open(d + "/fbin/" + name, "w") as f:
                f.write(body)
            os.chmod(d + "/fbin/" + name, 0o755)
        me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        good = d + "/good.tgz"
        good_sha = make_tgz(good)
        nobin = d + "/nobin.tgz"
        nobin_sha = make_tgz(nobin, with_bin=False)
        dest = d + "/home/.opencode/bin/opencode"
        os.makedirs(d + "/home")

        # target selection
        with open(d + "/cpu-avx2", "w") as f:
            f.write("flags\t\t: fpu sse2 avx avx2 bmi2\n")
        with open(d + "/cpu-old", "w") as f:
            f.write("flags\t\t: fpu sse2 avx\n")
        for mach, cpu, want in (("x86_64", "cpu-avx2", "linux-x64"), ("x86_64", "cpu-old", "linux-x64-baseline"),
                                ("amd64", "cpu-avx2", "linux-x64"), ("aarch64", "cpu-old", "linux-arm64"),
                                ("arm64", "cpu-old", "linux-arm64"), ("riscv64", "cpu-avx2", ""),
                                ("armv7l", "cpu-avx2", ""), ("i686", "cpu-avx2", "")):
            rc, calls, out = run_fn(d, 'printf "[%%s]" "$(opencode_target %s %s/%s)"' % (mach, d, cpu))
            check("[%s]" % want in out, "uname -m %s (%s) -> %r (%s)" % (mach, cpu, want, out.strip()))

        # unsupported machine: clear message, no download
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), {"FAKE_MACHINE": "riscv64", "FAKE_TGZ": good})
        check(rc == 4 and not calls and "no Linux build" in out and not os.path.exists(dest),
              "unsupported machine -> rc 4, skipped, no download (%s)" % out.strip())

        # pinned version: the fake archive is not the pinned one -> refused
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), {"FAKE_TGZ": good})
        pin = re.search(r'^OPENCODE_VERSION_PIN="([^"]+)"', src, re.M).group(1)
        url = [c for c in calls if c.startswith("curl ")]
        check(rc == 3 and "checksum mismatch" in out and not os.path.exists(dest),
              "pinned hash checked: other archive refused (%s)" % out.strip())
        check(len(url) == 1 and ("https://registry.npmjs.org/@opencode/cli-linux-x64/-/cli-linux-x64-%s.tgz" % pin) in url[0],
              "pinned npm tarball URL (%s)" % url)
        check(SETUP_CMD in out, "refusal names the re-run command")
        check(os.listdir(d + "/tmp") == [], "no temp files left after a refusal")

        # override with the right hash -> installed 0755, atomically
        env = {"FAKE_TGZ": good, "TUXWALL_OPENCODE_VERSION": "v9.9.9", "TUXWALL_OPENCODE_SHA256": good_sha.upper()}
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), env)
        check(rc == 0 and os.path.isfile(dest) and os.stat(dest).st_mode & 0o777 == 0o755
              and "sha256 verified" in out, "verified archive installed 0755 (%s)" % out.strip())
        check(any("cli-linux-x64-9.9.9.tgz" in c for c in calls), "override version used (leading v stripped)")
        check(not os.path.exists(dest + ".new") and os.listdir(d + "/tmp") == [], "no .new / temp leftovers")
        if os.path.isfile(dest):
            r = subprocess.run([dest, "--version"], capture_output=True, text=True)
            check("v9.9.9" in r.stdout, "installed binary runs")

        # binary present -> never downloaded again (upgrades)
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), {"FAKE_TGZ": good, "FAKE_CURL_FAIL": "1"})
        check(rc == 0 and not calls and "already installed" in out, "binary present -> no download (%s)" % calls)
        shutil.rmtree(d + "/home/.opencode")

        # tampered: override hash does not match the download
        env = {"FAKE_TGZ": good, "TUXWALL_OPENCODE_VERSION": "9.9.9", "TUXWALL_OPENCODE_SHA256": nobin_sha}
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), env)
        check(rc == 3 and not os.path.exists(dest) and "expected sha256 " + nobin_sha in out
              and "got      sha256 " + good_sha in out, "tampered download refused, nothing installed")

        # override version without a hash -> refused before any download
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), {"FAKE_TGZ": good, "TUXWALL_OPENCODE_VERSION": "9.9.9"})
        check(rc == 3 and not calls and "needs TUXWALL_OPENCODE_SHA256" in out, "version override needs a hash")

        # verified archive without the binary -> refused
        env = {"FAKE_TGZ": nobin, "TUXWALL_OPENCODE_VERSION": "9.9.9", "TUXWALL_OPENCODE_SHA256": nobin_sha}
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), env)
        check(rc == 3 and not os.path.exists(dest) and os.listdir(d + "/tmp") == [], "archive without the binary refused")

        # no internet -> rc 2, warning + exact re-run command
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), {"FAKE_TGZ": good, "FAKE_CURL_FAIL": "1"})
        check(rc == 2 and "no internet" in out and SETUP_CMD in out and not os.path.exists(dest)
              and os.listdir(d + "/tmp") == [], "offline -> rc 2, message + re-run command (%s)" % out.strip())

        # arm64 picks the arm64 tarball
        env = {"FAKE_TGZ": good, "FAKE_MACHINE": "aarch64", "TUXWALL_OPENCODE_VERSION": "9.9.9", "TUXWALL_OPENCODE_SHA256": good_sha}
        rc, calls, out = run_fn(d, 'ensure_opencode "%s" %s' % (dest, me), env)
        check(rc == 0 and any("/@opencode/cli-linux-arm64/-/cli-linux-arm64-9.9.9.tgz" in c for c in calls),
              "aarch64 -> cli-linux-arm64 (%s)" % calls)

        # executed as non-root: refuses with the command, changes nothing
        if os.geteuid() != 0:
            p = subprocess.run(["bash", SCRIPT], capture_output=True, text=True, timeout=30,
                               env=dict(os.environ, PATH=d + "/fbin:" + os.environ.get("PATH", "")))
            check(p.returncode == 1 and "Run as root" in p.stdout, "non-root run refused")
    finally:
        shutil.rmtree(d)


# ── (b2) agent password: never in Environment= ─────────────────────────────
SECRET_ENV_RE = re.compile(r"Environment=[\"']?(?:[A-Za-z0-9_]+=\S*\s+)*[A-Za-z0-9_]*"
                           r"(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY)[A-Za-z0-9_]*=", re.I)
SECRET_ENV_SOURCES = ("pkg", "systemd", "scripts", "image", "www/includes", "www/scripts", "tuxwall-install.sh")
PW_ENV = "/etc/tuxwall/agent-password.env"
PW_DROPINS = {"agent": "/etc/systemd/system/tuxwall-agent.service.d/password.conf",
              "dashboard": "/etc/systemd/system/tuxwall.service.d/agent-password.conf"}


def secret_environment_lines(text):
    """Lines (not comments) that put a secret-looking variable into Environment=."""
    out = []
    for n, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith(("#", ";", "//")):
            continue
        if SECRET_ENV_RE.search(ln):
            out.append((n, ln.strip()[:120]))
    return out


def t_no_secret_environment():
    # the detector itself
    for bad in ("Environment=OPENCODE_SERVER_PASSWORD=x", "Environment=\"API_TOKEN=x\"",
                "Environment=A=1 MY_SECRET=2", "printf '[Service]\\nEnvironment=TUXWALL_AGENT_PASSWORD=%s\\n'",
                "Environment=abuse_key=x"):
        check(secret_environment_lines(bad), "detector flags %r" % bad)
    for ok in ("EnvironmentFile=/etc/tuxwall/agent-password.env", "Environment=OPENCODE_CONFIG=/etc/tuxwall/opencode.json",
               "# Environment=FOO_TOKEN=x (comment)", "Environment=PYTHONUNBUFFERED=1"):
        check(not secret_environment_lines(ok), "detector leaves %r alone" % ok)
    files = []
    for rel in SECRET_ENV_SOURCES:
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            files.append(p)
        for dp, dn, fn in os.walk(p):
            dn[:] = [x for x in dn if x not in ("__pycache__", ".git", "node_modules")]
            files += [os.path.join(dp, f) for f in fn]
    scanned = 0
    for f in sorted(files):
        try:
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1
        for n, ln in secret_environment_lines(text):
            check(False, "%s:%d puts a secret into Environment= (readable by every local user "
                         "via systemctl show; use a root-only EnvironmentFile=): %s" % (os.path.relpath(f, ROOT), n, ln))
    check(scanned > 100, "secret-in-Environment= scan covered the units and scripts (%d files)" % scanned)


def pw_tree(root):
    """{relative path: bytes} of every file under root."""
    out = {}
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = fh.read()
    return out


def pw_env(root):
    try:
        text = read(root + PW_ENV)
    except OSError:
        return None, None
    a = re.findall(r"^OPENCODE_SERVER_PASSWORD=(.*)$", text, re.M)
    b = re.findall(r"^TUXWALL_AGENT_PASSWORD=(.*)$", text, re.M)
    return (a[0] if len(a) == 1 else None), (b[0] if len(b) == 1 else None)


def pw_state_ok(root, label):
    """env file 0600 with one shared value, drop-ins EnvironmentFile= only -> the value."""
    a, b = pw_env(root)
    check(a is not None and a == b and re.fullmatch(r"[0-9a-f]{48}", a or "") is not None,
          "%s: env file has one 48-hex value for both variables" % label)
    st = os.stat(root + PW_ENV) if os.path.exists(root + PW_ENV) else None
    check(st is not None and st.st_mode & 0o777 == 0o600 and st.st_uid == os.geteuid(),
          "%s: env file 0600, owned by the caller (root on a router)" % label)
    for who, path in PW_DROPINS.items():
        body = read(root + path) if os.path.exists(root + path) else ""
        lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        want = "EnvironmentFile=%s%s" % ("" if who == "agent" else "-", PW_ENV)
        check(lines == ["[Service]", want], "%s: %s drop-in is [Service] %s (%s)" % (label, who, want, lines))
        check(not secret_environment_lines(body) and (a or "x") not in body, "%s: %s drop-in holds no secret" % (label, who))
        check(os.stat(root + path).st_mode & 0o777 == 0o644 if body else False, "%s: %s drop-in 0644" % (label, who))
    leftovers = [p for p in pw_tree(root) if re.search(r"\.[A-Za-z0-9]{6}$", p) and not p.endswith((".token", ".json"))]
    check(not leftovers, "%s: no temp files left (%s)" % (label, leftovers))
    return a


def t_agent_password():
    src = read(SCRIPT)
    check(not re.search(r"Environment=(OPENCODE_SERVER|TUXWALL_AGENT)_PASSWORD", src),
          "setup script no longer writes the password into Environment=")
    old_pw = "0123456789abcdef" * 3             # dummy fixture values, not a real password
    old_tok = "fedcba9876543210" * 2
    d = tempfile.mkdtemp(prefix="agent-pw-")
    try:
        os.makedirs(d + "/fbin")
        os.makedirs(d + "/tmp")

        def run(root, fake_openssl=None):
            env = {}
            ob = d + "/fbin/openssl"
            if os.path.exists(ob):
                os.unlink(ob)
            if fake_openssl is not None:
                with open(ob, "w") as f:
                    f.write(fake_openssl)
                os.chmod(ob, 0o755)
            return run_fn(d, 'agent_password_setup "%s"' % root, env)

        def legacy(root, with_env=None):
            for who, path in PW_DROPINS.items():
                os.makedirs(os.path.dirname(root + path), exist_ok=True)
                var = "OPENCODE_SERVER_PASSWORD" if who == "agent" else "TUXWALL_AGENT_PASSWORD"
                with open(root + path, "w") as f:
                    f.write("[Service]\nEnvironment=%s=%s\n" % (var, old_pw))
                os.chmod(root + path, 0o600)
            os.makedirs(root + "/etc/tuxwall", exist_ok=True)
            with open(root + "/etc/tuxwall/agent-token", "w") as f:
                f.write(old_tok)
            if with_env:
                with open(root + PW_ENV, "w") as f:
                    f.write(with_env)

        # fresh: nothing there yet
        r1 = d + "/fresh"
        os.makedirs(r1)
        rc, _, out = run(r1)
        check(rc == 10, "fresh: rc 10 (written) (%s)" % out.strip())
        pw1 = pw_state_ok(r1, "fresh")
        check(pw1 is not None and pw1 not in out, "fresh: password not printed")
        before = pw_tree(r1)
        rc, _, out = run(r1)
        check(rc == 0 and pw_tree(r1) == before, "fresh: second run rc 0, nothing changed (%s)" % out.strip())

        # 3.3.7 install: Environment= drop-ins + agent-token -> rotated
        r2 = d + "/legacy"
        legacy(r2)
        rc, _, out = run(r2)
        check(rc == 10, "legacy: rc 10 (%s)" % out.strip())
        pw2 = pw_state_ok(r2, "legacy")
        check(pw2 is not None and pw2 != old_pw and pw2 != old_tok, "legacy: a NEW password (old one was readable)")
        check(not os.path.exists(r2 + "/etc/tuxwall/agent-token"), "legacy: old agent-token removed")
        tree = pw_tree(r2)
        check(not any(old_pw.encode() in v or old_tok.encode() in v for v in tree.values()),
              "legacy: the old value is nowhere under the root (no backups)")
        check(pw2 not in out and old_pw not in out, "legacy: no password printed")
        rc, _, out = run(r2)
        check(rc == 0 and pw_tree(r2) == tree, "legacy: second run idempotent (rc %d)" % rc)

        # legacy drop-ins next to a valid env file: still rotated (the value may be the leaked one)
        r3 = d + "/legacy-env"
        legacy(r3, "OPENCODE_SERVER_PASSWORD=%s\nTUXWALL_AGENT_PASSWORD=%s\n" % (old_pw, old_pw))
        rc, _, out = run(r3)
        pw3 = pw_state_ok(r3, "legacy+env")
        check(rc == 10 and pw3 != old_pw, "legacy drop-ins + env file -> rotated anyway")

        # repairs without rotation: modes, a missing / edited drop-in
        os.chmod(r1 + PW_ENV, 0o644)
        os.unlink(r1 + PW_DROPINS["dashboard"])
        with open(r1 + PW_DROPINS["agent"], "a") as f:
            f.write("# edited\n")
        rc, _, out = run(r1)
        check(rc == 10 and pw_state_ok(r1, "repair") == pw1, "drop-ins rewritten, mode fixed, password kept")
        os.chmod(r1 + PW_ENV, 0o640)
        rc, _, out = run(r1)
        check(rc == 0 and os.stat(r1 + PW_ENV).st_mode & 0o777 == 0o600, "mode-only repair: rc 0, 0600 again")

        # mismatched / short values -> new password
        for bad in ("OPENCODE_SERVER_PASSWORD=%s\nTUXWALL_AGENT_PASSWORD=%s\n" % (old_pw, old_tok),
                    "OPENCODE_SERVER_PASSWORD=short\nTUXWALL_AGENT_PASSWORD=short\n", ""):
            with open(r1 + PW_ENV, "w") as f:
                f.write(bad)
            rc, _, out = run(r1)
            pwx = pw_state_ok(r1, "bad env %r" % bad[:30])
            check(rc == 10 and pwx not in (old_pw, old_tok, "short"), "bad env file %r -> new password" % bad[:30])

        # no usable openssl -> /dev/urandom fallback, still 48 hex
        r4 = d + "/noopenssl"
        os.makedirs(r4)
        rc, _, out = run(r4, "#!/bin/sh\nexit 1\n")
        check(rc == 10 and pw_state_ok(r4, "no openssl") is not None, "openssl failing -> urandom fallback")

        # unwritable root -> rc 1 (the postinst turns it into a warning)
        r5 = d + "/ro"
        os.makedirs(r5 + "/etc")
        os.chmod(r5 + "/etc", 0o555)
        if os.geteuid() != 0:
            rc, _, out = run(r5)
            check(rc == 1, "unwritable -> rc 1 (%s)" % rc)
        os.chmod(r5 + "/etc", 0o755)

        # executed: --password-only with a test root works as non-root, without one it needs root
        r6 = d + "/exec"
        legacy(r6)
        p = subprocess.run(["bash", SCRIPT, "--password-only", r6], capture_output=True, text=True, timeout=30)
        check(p.returncode == 10 and pw_state_ok(r6, "exec") not in (None, old_pw), "--password-only ROOT -> rc 10")
        check(pw_env(r6)[0] not in p.stdout + p.stderr, "--password-only prints no password")
        if os.geteuid() != 0:
            p = subprocess.run(["bash", SCRIPT, "--password-only"], capture_output=True, text=True, timeout=30)
            check(p.returncode == 1 and "Run as root" in p.stdout, "--password-only without root refused")
        check('agent_password_setup || pw_rc=$?' in src and src.index("agent_password_setup || pw_rc") < src.index("systemctl restart tuxwall-agent.service"),
              "main() writes the password before it (re)starts the agent")
    finally:
        for dp, dn, fn in os.walk(d):
            for x in dn:
                os.chmod(os.path.join(dp, x), 0o755)
        shutil.rmtree(d)


# ── (c) unit drop-in ──────────────────────────────────────────────────────
def t_dropin():
    check(os.path.isfile(DROPIN), "drop-in shipped: /usr/lib/systemd/system/tuxwall-agent.service.d/10-installed.conf")
    if not os.path.isfile(DROPIN):
        return
    body = [ln.strip() for ln in read(DROPIN).splitlines() if ln.strip() and not ln.strip().startswith("#")]
    check(body == ["[Unit]", "ConditionFileIsExecutable=" + AGENT_BIN], "drop-in: [Unit] ConditionFileIsExecutable (%s)" % body)
    m = re.search(r"^ExecStart=(\S+)", read(UNIT), re.M)
    check(m is not None and m.group(1) == AGENT_BIN, "the condition names the binary the unit starts")
    mode = os.stat(DROPIN).st_mode
    check(mode & 0o444 == 0o444 and not mode & 0o111 and not mode & 0o002, "drop-in readable, not executable (%o)" % (mode & 0o777))


# ── API: installed:false + command ────────────────────────────────────────
def t_api():
    target = os.path.join(ROOT, "www", "includes", "api_server.py")
    spec = importlib.util.spec_from_file_location("api_server_agent_check", target)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)
    H = mod.Handler
    check(H.AGENT_BIN == AGENT_BIN and H.AGENT_SETUP_CMD == SETUP_CMD, "API names the binary and the install command")
    h = H.__new__(H)
    d = tempfile.mkdtemp(prefix="agent-api-")
    try:
        h.AGENT_BIN = d + "/none"
        e = h._agent_error(mod.AgentError("connection refused", status=0))
        check(e.get("ok") is False and e.get("installed") is False and e.get("fix") == SETUP_CMD
              and SETUP_CMD in e.get("hint", ""), "binary missing -> installed:false + fix command (%s)" % e)
        b = d + "/opencode"
        with open(b, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(b, 0o755)
        h.AGENT_BIN = b
        e = h._agent_error(mod.AgentError("connection refused", status=0))
        check(e.get("ok") is False and "installed" not in e and "journalctl" in e.get("hint", ""),
              "binary present -> the usual error (%s)" % e)
    finally:
        shutil.rmtree(d)
    src = read(target)
    check(src.count('{"ok": True, "installed": True, "server": health}') == 2, "status (GET + POST) reports installed:true")


# ── installer ─────────────────────────────────────────────────────────────
def t_installer():
    r = subprocess.run(["bash", "-n", INSTALLER], capture_output=True, text=True)
    check(r.returncode == 0, "bash -n tuxwall-install.sh %s" % r.stderr)
    src = read(INSTALLER)
    fn = re.search(r"^step_agent\(\) \{.*?^\}\n", src, re.M | re.S)
    fn = fn.group(0) if fn else ""
    check("/usr/local/share/tuxwall/scripts/setup-opencode-agent.sh" in fn
          and "$REPO_DIR/pkg/usr/local/share/tuxwall/scripts/setup-opencode-agent.sh" in fn,
          "step_agent: packaged script, repo pkg/ copy as fallback (--source local)")
    check('TUXWALL_AGENT_EDIT_WEBROOT="$AGENT_EDIT_WEBROOT"' in fn, "step_agent passes --agent-edit-webroot through")
    pk = re.search(r"^step_package\(\) \{.*?^\}\n", src, re.M | re.S)
    pk = pk.group(0) if pk else ""
    check("touch /etc/tuxwall/no-agent" in pk and pk.index("no-agent") < pk.index("apt-get install"),
          "--no-agent opt-out written before the package installs")


def main():
    t_packaging()
    t_setup_script()
    t_no_secret_environment()
    t_agent_password()
    t_dropin()
    t_api()
    t_installer()
    print("agent_setup_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
