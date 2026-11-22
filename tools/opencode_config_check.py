#!/usr/bin/env python3
"""AI agent config split (3.3.5): package defaults + owner additions.

/etc/tuxwall/opencode.json stays the package's defaults (dpkg conffile);
custom providers and the default model go to /etc/tuxwall/opencode.local.json,
which opencode merges over it (OPENCODE_CONFIG_CONTENT via the package drop-in
tuxwall-agent.service.d/20-local-config.conf). Sandboxed tests (temp dirs,
systemctl stubbed):

- packaging: drop-in, helper 0755, pristine default copy == the conffile,
  the local file is not shipped / not a conffile, postinst runs the split;
- migration (opencode_config.py migrate): unmodified default -> nothing (no
  local file); owner-added provider -> moved losslessly, opencode.json gets
  the shipped bytes back, backup 0600; ambiguous (list changed, default key
  removed, comments, conflicting local list) -> left alone; --check;
- env (ExecStartPre): systemd single-quote line round-trips any JSON;
  missing/invalid/oversized local file -> empty env, exit 0;
- API: without the drop-in it edits opencode.json (hot reload, no restart);
  with it, writes go to the local file (+ .bak), opencode.json is untouched,
  the view is merged, the agent is restarted, package providers are listed
  as such and cannot be removed.

    python3 tools/opencode_config_check.py
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "pkg")
HELPER = os.path.join(PKG, "usr/local/lib/tuxwall/opencode_config.py")
DEFAULT = os.path.join(PKG, "usr/share/tuxwall/opencode.default.json")
CONFFILE = os.path.join(PKG, "etc/tuxwall/opencode.json")
DROPIN = os.path.join(PKG, "usr/lib/systemd/system/tuxwall-agent.service.d/20-local-config.conf")

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


oc = load_module("opencode_config_t", HELPER)
DFLT = json.load(open(DEFAULT))
DFLT_BYTES = open(DEFAULT, "rb").read()


def t_packaging():
    check(os.path.isfile(DROPIN), "drop-in ships: " + DROPIN)
    d = open(DROPIN).read() if os.path.isfile(DROPIN) else ""
    for line in ("RuntimeDirectory=tuxwall-agent",
                 "ExecStartPre=-/usr/bin/python3 /usr/local/lib/tuxwall/opencode_config.py env "
                 "/run/tuxwall-agent/local-config.env",
                 "EnvironmentFile=-/run/tuxwall-agent/local-config.env"):
        check(line in d.splitlines(), "drop-in has: " + line)
    check(os.stat(HELPER).st_mode & stat.S_IXUSR, "helper is executable")
    idx = subprocess.run(["git", "-C", ROOT, "ls-files", "-s", "pkg/usr/local/lib/tuxwall/opencode_config.py"],
                         capture_output=True, text=True).stdout
    check(idx.startswith("100755"), "git records the helper as 0755")
    check(DFLT_BYTES == open(CONFFILE, "rb").read(),
          "usr/share/tuxwall/opencode.default.json == etc/tuxwall/opencode.json (pristine copy for the postinst)")
    conffiles = open(os.path.join(PKG, "DEBIAN/conffiles")).read().split()
    check("/etc/tuxwall/opencode.json" in conffiles, "opencode.json stays a conffile")
    check("/etc/tuxwall/opencode.local.json" not in conffiles, "the local file is not a conffile")
    check(not os.path.exists(os.path.join(PKG, "etc/tuxwall/opencode.local.json")), "the local file is not shipped")
    post = open(os.path.join(PKG, "DEBIAN/postinst")).read()
    body = post.split('case "$1" in\n  configure)', 1)[1]
    check("agent_config_split" in body and body.index("agent_setup_step") < body.index("agent_config_split"),
          "postinst runs agent_config_split after the agent setup")
    unit = open(os.path.join(PKG, "etc/systemd/system/tuxwall-agent.service")).read()
    check("Environment=OPENCODE_CONFIG=/etc/tuxwall/opencode.json" in unit, "the unit keeps OPENCODE_CONFIG")


class Box:
    def __init__(self, conf=None, local=None, conf_bytes=None):
        self.d = tempfile.mkdtemp(prefix="oc-split-")
        self.conf = self.d + "/opencode.json"
        self.local = self.d + "/opencode.local.json"
        self.bk = self.d + "/backups"
        if conf_bytes is not None:
            open(self.conf, "wb").write(conf_bytes)
        elif conf is not None:
            open(self.conf, "w").write(json.dumps(conf, indent=2) + "\n")
        if local is not None:
            open(self.local, "w").write(json.dumps(local, indent=2) + "\n")
        self.orig = open(self.conf, "rb").read() if os.path.exists(self.conf) else None

    def migrate(self, *extra):
        p = subprocess.run([sys.executable, HELPER, "migrate", "--conf", self.conf, "--default", DEFAULT,
                            "--local", self.local, "--backup-dir", self.bk, *extra],
                           capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout + p.stderr).strip()

    def read_local(self):
        return json.load(open(self.local)) if os.path.exists(self.local) else None

    def close(self):
        shutil.rmtree(self.d, ignore_errors=True)


def live_like():
    """The live router's shape: a custom provider added and two keys moved
    to another position by an older dashboard (semantically the same)."""
    cur = {"$schema": DFLT["$schema"], "model": DFLT["model"], "small_model": DFLT["small_model"],
           "providers": {"unsloth": {"name": "Unsloth", "package": "@opencode/ai/providers/openai-compatible",
                                     "settings": {"baseURL": "http://192.0.2.12:3000/v1",
                                                  "apiKey": "{file:/etc/tuxwall/agent/keys/unsloth.key}"},
                                     "models": {"unsloth/Qwen3.5-9B-GGUF": {"name": "Qwen3.5 9B"}}}}}
    for k in ("instructions", "skills"):
        cur[k] = DFLT[k]
    for k, v in DFLT.items():
        cur.setdefault(k, v)
    return cur


def t_migrate():
    b = Box(conf_bytes=DFLT_BYTES)
    rc, out = b.migrate()
    check(rc == 0 and b.read_local() is None and open(b.conf, "rb").read() == DFLT_BYTES,
          "unmodified default: nothing to do, no local file (%s %s)" % (rc, out))
    b.close()

    cur = live_like()
    b = Box(conf=cur)
    rc, out = b.migrate("--check")
    check(rc == 10 and "would:" in out and b.read_local() is None and open(b.conf, "rb").read() == b.orig,
          "--check reports and changes nothing (%s)" % out)
    rc, out = b.migrate()
    loc = b.read_local()
    check(rc == 10 and "providers.unsloth" in out, "owner provider: migrated (%s %s)" % (rc, out))
    check(loc == {"providers": cur["providers"]}, "local file holds exactly the owner's additions")
    check(open(b.conf, "rb").read() == DFLT_BYTES, "opencode.json got the shipped bytes back (dpkg: unmodified)")
    check(oc.deep_merge(DFLT, loc) == cur, "lossless: defaults + local == the previous file")
    bks = os.listdir(b.bk) if os.path.isdir(b.bk) else []
    check(len(bks) == 1 and open(os.path.join(b.bk, bks[0]), "rb").read() == b.orig
          and stat.S_IMODE(os.stat(os.path.join(b.bk, bks[0])).st_mode) == 0o600,
          "previous opencode.json backed up 0600")
    check(stat.S_IMODE(os.stat(b.local).st_mode) == stat.S_IMODE(os.stat(b.conf).st_mode),
          "local file takes opencode.json's mode")
    rc, out = b.migrate()
    check(rc == 0 and b.read_local() == loc, "re-run: nothing to do (%s)" % out)
    b.close()

    cur = dict(DFLT, model="unsloth/x")
    b = Box(conf=cur)
    rc, out = b.migrate()
    check(rc == 10 and b.read_local() == {"model": "unsloth/x"}, "changed default model: moved (%s)" % out)
    b.close()

    perms = list(DFLT["permissions"]) + [{"action": "shell", "resource": "rm *", "effect": "allow"}]
    for name, cur, raw in (
            ("permissions list edited", dict(DFLT, permissions=perms), None),
            ("a default key removed", {k: v for k, v in DFLT.items() if k != "skills"}, None),
            ("JSONC comments", None, b"// mine\n" + DFLT_BYTES),
            ("not JSON", None, b"{\"model\": "),
            ("object replaced by a string", dict(DFLT, mcp="off"), None)):
        b = Box(conf=cur, conf_bytes=raw)
        rc, out = b.migrate()
        check(rc == 3 and b.read_local() is None and open(b.conf, "rb").read() == b.orig
              and not os.path.isdir(b.bk), "ambiguous (%s): left alone (%s %s)" % (name, rc, out))
        b.close()

    cur = live_like()
    b = Box(conf=cur, local={"model": "unsloth/unsloth/Qwen3.5-9B-GGUF"})
    rc, out = b.migrate()
    check(rc == 10 and b.read_local() == {"providers": cur["providers"], "model": "unsloth/unsloth/Qwen3.5-9B-GGUF"},
          "existing local file: owner keys merged into it (%s)" % out)
    b.close()
    b = Box(conf=dict(DFLT, instructions=["/x.md"]), local={"instructions": ["/y.md"]})
    rc, out = b.migrate()
    check(rc == 3 and open(b.conf, "rb").read() == b.orig, "same list in both files: left alone (%s)" % out)
    b.close()

    b = Box(conf_bytes=(json.dumps(DFLT, indent=4) + "\n").encode())   # same JSON, other formatting
    check(b.orig != DFLT_BYTES, "fixture: reformatted default differs in bytes")
    rc, out = b.migrate()
    check(rc == 10 and b.read_local() is None and open(b.conf, "rb").read() == DFLT_BYTES,
          "formatting-only change: shipped bytes restored, no local file (%s)" % out)
    b.close()

    b = Box()
    rc, out = b.migrate()
    check(rc == 0 and b.read_local() is None, "no opencode.json: nothing to do")
    b.close()


def parse_env_line(text):
    """systemd EnvironmentFile: KEY='verbatim'."""
    key, _, val = text.rstrip("\n").partition("=")
    assert val.startswith("'") and val.endswith("'") and "'" not in val[1:-1]
    return key, val[1:-1]


def t_env():
    d = tempfile.mkdtemp(prefix="oc-env-")
    try:
        tricky = {"$schema": "x", "providers": {"x": {"name": "Jeff's \"box\" $HOME `id` \\ ünï %h",
                                                      "models": {"a/b:c@d": {"name": "n\nl"}}}}, "model": "x/a/b:c@d"}
        open(d + "/l.json", "w").write(json.dumps(tricky))
        p = subprocess.run([sys.executable, HELPER, "env", d + "/out.env", "--local", d + "/l.json"],
                           capture_output=True, text=True)
        text = open(d + "/out.env").read()
        key, val = parse_env_line(text)
        want = dict(tricky)
        want.pop("$schema")
        check(p.returncode == 0 and key == "OPENCODE_CONFIG_CONTENT" and json.loads(val) == want,
              "env line round-trips (quotes, $, backslash, unicode); $schema dropped")
        check(text.count("\n") == 1 and text.isascii(), "one ASCII line")
        check(stat.S_IMODE(os.stat(d + "/out.env").st_mode) == 0o600, "env file 0600")
        for name, content in (("missing", None), ("invalid", "{\"a\":"), ("array", "[1]"), ("empty object", "{}"),
                              ("oversized", json.dumps({"x": "y" * (70 * 1024)}))):
            if os.path.exists(d + "/l.json"):
                os.unlink(d + "/l.json")
            if content is not None:
                open(d + "/l.json", "w").write(content)
            p = subprocess.run([sys.executable, HELPER, "env", d + "/out.env", "--local", d + "/l.json"],
                               capture_output=True, text=True)
            check(p.returncode == 0 and open(d + "/out.env").read() == "",
                  "%s local file -> empty env, exit 0" % name)
        p = subprocess.run([sys.executable, HELPER, "env", d + "/no/such/dir/out.env", "--local", d + "/l.json"],
                           capture_output=True, text=True)
        check(p.returncode == 0, "unwritable env path still exits 0 (ExecStartPre never blocks the agent)")
    finally:
        shutil.rmtree(d)


def t_api():
    api = load_module("api_server_occheck", os.path.join(ROOT, "www/includes/api_server.py"))
    d = tempfile.mkdtemp(prefix="oc-api-")
    calls = []
    real_run = api.subprocess.run
    real_fchown = os.fchown
    if os.geteuid() != 0:   # the API runs as root and chowns the .bak to root
        os.fchown = lambda fd, uid, gid: None
    api.subprocess.run = lambda *a, **k: calls.append(list(a[0])) or subprocess.CompletedProcess(a[0], 0, "", "")
    try:
        api.OPENCODE_CONF = d + "/opencode.json"
        api.OPENCODE_LOCAL_CONF = d + "/opencode.local.json"
        api.AGENT_LOCAL_CONF_DROPIN = d + "/20-local-config.conf"
        base = dict(DFLT, providers={"pkgp": {"name": "Pkg", "settings": {"baseURL": "http://127.0.0.1:1/v1"},
                                              "models": {"m": {"name": "m"}}}})
        open(api.OPENCODE_CONF, "w").write(json.dumps(base))
        os.chmod(api.OPENCODE_CONF, 0o644)
        base_bytes = open(api.OPENCODE_CONF, "rb").read()

        # legacy: no drop-in -> opencode.json as before, no restart
        check(api._oc_conf_path() == api.OPENCODE_CONF, "no drop-in: the dashboard edits opencode.json")
        conf = api._oc_conf_read()
        conf["model"] = "pkgp/m"
        api._oc_conf_write(conf)
        check(json.load(open(api.OPENCODE_CONF))["model"] == "pkgp/m" and os.path.exists(api.OPENCODE_CONF + ".bak"),
              "no drop-in: opencode.json written (+ .bak)")
        check(api._oc_conf_apply() is False and calls == [], "no drop-in: no agent restart (opencode hot-reloads)")
        open(api.OPENCODE_CONF, "wb").write(base_bytes)
        os.unlink(api.OPENCODE_CONF + ".bak")

        # local mode
        open(api.AGENT_LOCAL_CONF_DROPIN, "w").write("[Service]\n")
        check(api._oc_conf_path() == api.OPENCODE_LOCAL_CONF, "drop-in: the dashboard edits opencode.local.json")
        check(api._oc_conf_read() == {}, "missing local file reads as {}")
        conf = api._oc_conf_read()
        conf["providers"] = {"mine": {"name": "Mine", "settings": {"baseURL": "http://127.0.0.1:2/v1"},
                                      "models": {"q": {"name": "q"}}}}
        conf["model"] = "mine/q"
        api._oc_conf_write(conf)
        check(open(api.OPENCODE_CONF, "rb").read() == base_bytes, "opencode.json untouched")
        check(json.load(open(api.OPENCODE_LOCAL_CONF)) == conf, "local file written")
        check(stat.S_IMODE(os.stat(api.OPENCODE_LOCAL_CONF).st_mode) == 0o644, "new local file takes opencode.json's mode")
        check(not os.path.exists(api.OPENCODE_LOCAL_CONF + ".bak"), "no .bak for a file that did not exist")
        api._oc_conf_write(dict(conf, model="pkgp/m"))
        check(os.path.exists(api.OPENCODE_LOCAL_CONF + ".bak")
              and stat.S_IMODE(os.stat(api.OPENCODE_LOCAL_CONF + ".bak").st_mode) == 0o600, "second write keeps .bak 0600")
        api._oc_conf_write(conf)
        view = api._oc_conf_view()
        check(set(view["providers"]) == {"pkgp", "mine"} and view["model"] == "mine/q"
              and view["permissions"] == DFLT["permissions"], "view = defaults with the local file merged over")
        check(api._oc_conf_apply() is True and calls[-1] == ["systemctl", "try-restart", "tuxwall-agent.service"],
              "drop-in: a change restarts the agent (try-restart)")
        lst = {c["id"]: c for c in api.Handler._agent_custom_list()}
        check(lst.get("pkgp", {}).get("source") == "opencode.json" and lst.get("mine", {}).get("source") == "local",
              "custom list marks package vs local providers")

        h = api.Handler.__new__(api.Handler)
        h._agent_log = lambda msg: None
        h._agent_wait_provider = lambda *a, **k: (True, 0)
        code, res = h._agent_providers_post("/api/agent/providers/custom/remove", {"id": "pkgp"})
        check(code == 409 and "package defaults" in res.get("error", ""), "package provider cannot be removed (%s)" % res)
        code, res = h._agent_providers_post("/api/agent/providers/custom/remove", {"id": "mine"})
        check(code == 409 and "default" in res.get("error", ""), "default model's provider: remove refused first")
        api._oc_conf_write(dict(conf, model="pkgp/m"))
        calls[:] = []
        code, res = h._agent_providers_post("/api/agent/providers/custom/remove", {"id": "mine"})
        loc = json.load(open(api.OPENCODE_LOCAL_CONF))
        check(code == 200 and res.get("restarted") is True and "providers" not in loc and loc.get("model") == "pkgp/m",
              "local provider removed from the local file, agent restarted (%s %s)" % (code, res))
        check(open(api.OPENCODE_CONF, "rb").read() == base_bytes, "remove never touches opencode.json")
        code, res = h._agent_providers_post("/api/agent/providers/custom/remove", {"id": "nope"})
        check(code == 404, "unknown provider -> 404")
    finally:
        api.subprocess.run = real_run
        os.fchown = real_fchown
        shutil.rmtree(d)


def main():
    t_packaging()
    t_migrate()
    t_env()
    t_api()
    print("opencode_config_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
