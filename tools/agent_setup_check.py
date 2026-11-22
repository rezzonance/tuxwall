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
    # tuxwall-install.sh puts it there (local builds + step_post); the API
    # reports "SQM script missing" without it. Shipping it would overwrite
    # hand-installed copies - an owner decision, not part of 3.3.4.
    "/usr/local/sbin/tuxwall-sqm.sh",
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
    t_dropin()
    t_api()
    t_installer()
    print("agent_setup_check: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
