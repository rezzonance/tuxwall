#!/usr/bin/env python3
"""Plugin file permissions, pinning and integrity checks (sandboxed):

  python3 tools/plugin_security_check.py

www/includes/api_server.py is imported as a module; PLUGINS_DIR and the TOFU
marker point into a temp dir and GitHub is answered from in-memory zip
archives (branch -> commit SHA -> archive). Checks:

- permissions: code/assets 0644, directories 0755, config.json and
  .provenance.json 0600 after install, update and config save (atomic, no
  temp file left); a 0644 config.json from an older version becomes 0600.
- pinning: install resolves the branch to a commit and downloads by SHA;
  .provenance.json records repo/path/commit/content hash; an update is a
  preview first (nothing changes), a wrong confirmation is refused, the
  confirmed content is installed with config kept.
- integrity: tampered code, an unpinned plugin after the first start, a
  group-writable file or a symlink -> the worker never runs, assets are not
  served, list_plugins shows the error, the incident monitor raises
  plugin:<id>:integrity; admin re-pin needs the exact current hash.
- TOFU: plugins without a pin are pinned once at the first start (marker),
  v1 pins are re-recorded in the length-framed v2 hash.
- worker: no preexec_fn (subprocess user/group/extra_groups/umask instead),
  config reaches the worker over stdin.
"""
import importlib.util
import inspect
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "www", "includes", "api_server.py")
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("api_server_plugin_check", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

PASS = FAIL = 0


def check(cond, name):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", name)


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


MAIN_V1 = '''
def handle(req):
    return {"ok": True, "action": req.get("action"), "token": req.get("config", {}).get("token", ""),
            "uid": __import__("os").getuid()}
'''
MAIN_V2 = MAIN_V1 + "\n# v2\n"
MANIFEST = {"id": "demo", "name": "Demo", "version": "1.0.0", "api": 1,
            "settings": [{"key": "token", "label": "Token", "secret": True},
                         {"key": "host", "label": "Host"}]}


def make_zip(sha, main_src, version="1.0.0", extra=None):
    buf = io.BytesIO()
    top = "tuxwall-%s/plugins/demo-plugin/" % sha
    m = dict(MANIFEST, version=version)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("tuxwall-%s/README.md" % sha, "repo readme")
        z.writestr(top + "plugin.json", json.dumps(m))
        z.writestr(top + "main.py", main_src)
        z.writestr(top + "web/plugin.js", "console.log('demo');")
        z.writestr(top + "config.json", '{"token": "shipped-should-be-dropped"}')
        for name, data in (extra or {}).items():
            z.writestr(top + name, data)
    return buf.getvalue()


SHA1 = "1" * 40
SHA2 = "2" * 40
GH = {"head": SHA1, "zips": {SHA1: make_zip(SHA1, MAIN_V1)}, "calls": []}


def fake_get(url, accept=None, limit=None, timeout=None):
    GH["calls"].append(url)
    if url.startswith("https://api.github.com/repos/") and "/commits/" in url:
        assert accept == "application/vnd.github.sha"
        return GH["head"].encode()
    if url.startswith("https://api.github.com/repos/"):
        return json.dumps({"default_branch": "main"}).encode()
    if url.startswith("https://codeload.github.com/"):
        sha = url.rsplit("/", 1)[-1]
        if "refs/heads" in url or sha not in GH["zips"]:
            raise ValueError("GitHub: repository, branch or commit not found")
        return GH["zips"][sha]
    raise AssertionError("unexpected URL " + url)


URL = "https://github.com/rezzonance/tuxwall/tree/main/plugins/demo-plugin"


def setup():
    tmp = tempfile.mkdtemp(prefix="plugin-sec-")
    mod.PLUGINS_DIR = os.path.join(tmp, "plugins")
    mod.PLUGIN_TOFU_MARKER = os.path.join(tmp, "plugin-pins-tofu.done")
    mod._plugin_http_get = fake_get
    mod._PLUGIN_PIN_CACHE.clear()
    mod._PLUGIN_INCIDENTS_CACHE.clear()
    mod._plugin_lease_names = lambda: {}
    GH.update(head=SHA1, zips={SHA1: make_zip(SHA1, MAIN_V1)}, calls=[])
    return tmp


def t_install_perms_and_pin():
    tmp = setup()
    try:
        res = mod.install_plugin_from_github({"url": URL}, "admin1")
        check(res.get("ok") and not res.get("updated"), "fresh install ok (%r)" % res)
        pdir = os.path.join(mod.PLUGINS_DIR, "demo")
        check(any("/commits/main" in u for u in GH["calls"]), "branch resolved to a commit via the API")
        check(any(u.endswith("/zip/" + SHA1) for u in GH["calls"]), "archive downloaded by commit SHA")
        check(not any("refs/heads" in u for u in GH["calls"]), "never downloads a branch head")
        check(mode(pdir) == 0o755 and mode(pdir + "/web") == 0o755, "dirs 0755")
        check(mode(pdir + "/main.py") == 0o644 and mode(pdir + "/web/plugin.js") == 0o644, "code/assets 0644")
        check(mode(pdir + "/.provenance.json") == 0o600, "pin file 0600")
        check(not os.path.exists(pdir + "/config.json"), "a config.json shipped in the package is dropped")
        pin = json.load(open(pdir + "/.provenance.json"))
        check(pin.get("repo") == "rezzonance/tuxwall" and pin.get("path") == "plugins/demo-plugin"
              and pin.get("commit") == SHA1 and pin.get("hash_v") == 2, "pin records repo/path/commit (%r)" % pin)
        check(pin.get("content_sha256") == mod._plugin_content_hash(pdir), "pin = content hash of the code")
        check(res["plugin"]["commit"] == SHA1 and res["plugin"]["content_sha256"] == pin["content_sha256"],
              "install answer carries commit + hash")
        check(not [d for d in os.listdir(mod.PLUGINS_DIR) if d.startswith(".")], "no staging dir left")
        # config save: 0600, atomic, pin unaffected
        mod._plugin_save_config("demo", {"config": {"token": "s3cret", "host": "10.0.0.2"}})
        check(mode(pdir + "/config.json") == 0o600, "config.json 0600 after config save")
        check(not [f for f in os.listdir(pdir) if f.endswith(".tmp")], "no temp file left after config save")
        mod._plugin_save_config("demo", {"enabled": False})
        check(mode(pdir + "/config.json") == 0o600, "config.json 0600 after enable/disable")
        mod._plugin_save_config("demo", {"enabled": True})
        check(mod._plugin_pin_status("demo")["state"] == "ok", "config changes do not break the pin")
        # worker gets the config over stdin and runs
        out = mod.plugin_action("demo", "overview", {})
        check(out.get("ok") and out.get("token") == "s3cret" and out.get("action") == "overview",
              "worker runs with config from stdin (%r)" % out)
        lst = mod.list_plugins()["plugins"][0]
        check(lst["pin"]["state"] == "ok" and lst["error"] == "" and lst["enabled"], "list shows pinned ok")
        check(mod.plugin_asset_path("demo", "plugin.js").endswith("web/plugin.js"), "assets served when pinned")
    finally:
        shutil.rmtree(tmp)


def t_update_flow():
    tmp = setup()
    try:
        mod.install_plugin_from_github({"url": URL})
        pdir = os.path.join(mod.PLUGINS_DIR, "demo")
        mod._plugin_save_config("demo", {"config": {"token": "keep-me"}})
        os.chmod(pdir + "/config.json", 0o644)     # as written by 3.3.2
        before = open(pdir + "/main.py").read()
        old_pin = json.load(open(pdir + "/.provenance.json"))
        GH["head"] = SHA2
        GH["zips"][SHA2] = make_zip(SHA2, MAIN_V2, "1.1.0", {"web/new.css": "a{}"})
        prev = mod.install_plugin_from_github({"url": URL})
        check(prev.get("confirm_required") is True, "update without confirmation is a preview")
        check(prev["new"]["commit"] == SHA2 and prev["current"]["commit"] == SHA1, "preview: old/new commit")
        check(prev["current"]["content_sha256"] == old_pin["content_sha256"], "preview: current hash")
        check(prev["changes"]["changed"] == ["main.py", "plugin.json"] and prev["changes"]["added"] == ["web/new.css"],
              "preview: diff summary (%r)" % prev["changes"])
        check(open(pdir + "/main.py").read() == before, "preview changes nothing on disk")
        check(not [d for d in os.listdir(mod.PLUGINS_DIR) if d.startswith(".")], "preview leaves no staging dir")
        try:
            mod.install_plugin_from_github({"url": URL, "commit": SHA2, "confirm_sha256": "0" * 64})
            check(False, "wrong confirmation refused")
        except ValueError:
            check(open(pdir + "/main.py").read() == before, "wrong confirmation refused, nothing changed")
        # upstream moved again between preview and confirm: confirmed commit is installed
        GH["head"] = "3" * 40
        res = mod.install_plugin_from_github({"url": URL, "commit": prev["new"]["commit"],
                                              "confirm_sha256": prev["new"]["content_sha256"]})
        check(res.get("ok") and res.get("updated"), "confirmed update installed (%r)" % res)
        pin = json.load(open(pdir + "/.provenance.json"))
        check(pin["commit"] == SHA2 and pin["content_sha256"] == prev["new"]["content_sha256"]
              and pin.get("previous_commit") == SHA1, "new pin = previewed commit/hash")
        check(open(pdir + "/main.py").read() == MAIN_V2, "new code in place")
        check(json.load(open(pdir + "/config.json")).get("token") == "keep-me", "config kept over the update")
        check(mode(pdir + "/config.json") == 0o600, "config.json 0600 after update (was 0644)")
        check(mode(pdir + "/.provenance.json") == 0o600 and mode(pdir + "/main.py") == 0o644, "perms after update")
        check(not [d for d in os.listdir(mod.PLUGINS_DIR) if d.startswith(".")], "no .old/.staging dir left")
        check(mod._plugin_pin_status("demo")["state"] == "ok", "updated plugin verifies")
    finally:
        shutil.rmtree(tmp)


def t_tamper_and_repin():
    tmp = setup()
    try:
        mod.install_plugin_from_github({"url": URL})
        pdir = os.path.join(mod.PLUGINS_DIR, "demo")
        mod.plugin_action("demo", "overview", {})
        with open(pdir + "/main.py", "a") as f:
            f.write("\nimport os  # injected\n")
        out = mod.plugin_action("demo", "overview", {})
        check(out.get("ok") is False and out.get("integrity") == "refused" and "changed since it was pinned"
              in out.get("error", ""), "tampered main.py: worker refused (%r)" % out)
        lst = mod.list_plugins()["plugins"][0]
        check(lst["enabled"] is False and "refused" in lst["error"] and lst["pin"]["state"] == "mismatch",
              "tampered: list shows the refusal, plugin not loaded")
        try:
            mod.plugin_asset_path("demo", "plugin.js")
            check(False, "tampered: assets refused")
        except ValueError:
            check(True, "tampered: assets refused")
        inc = mod._plugin_incident_conditions()
        check(inc.get("plugin:demo:integrity", ("",))[0] == "critical", "tampered: critical incident (%r)" % inc)
        # tampered web asset too
        with open(pdir + "/main.py", "w") as f:
            f.write(MAIN_V1)
        check(mod._plugin_pin_status("demo")["state"] == "ok", "restored file verifies again")
        with open(pdir + "/web/plugin.js", "a") as f:
            f.write("fetch('/x')")
        check(mod._plugin_pin_status("demo")["state"] == "mismatch", "tampered web asset detected")
        # admin re-pin: preview, stale confirm refused, exact confirm pins
        q = mod.plugin_repin("demo", {}, "admin1")
        check(q.get("confirm_required") and q["content_sha256"] == mod._plugin_content_hash(pdir), "re-pin preview")
        try:
            mod.plugin_repin("demo", {"confirm_sha256": "f" * 64})
            check(False, "re-pin with a stale hash refused")
        except ValueError:
            check(True, "re-pin with a stale hash refused")
        r = mod.plugin_repin("demo", {"confirm_sha256": q["content_sha256"]}, "admin1")
        pin = json.load(open(pdir + "/.provenance.json"))
        check(r.get("ok") and pin.get("pinned_by") == "admin" and pin.get("local_changes") and pin["commit"] == SHA1,
              "re-pinned (commit kept, marked local changes)")
        check(mod.plugin_action("demo", "x", {}).get("ok") is True, "re-pinned plugin runs")
        check(mode(pdir + "/.provenance.json") == 0o600, "re-pin keeps the pin file 0600")
        # group-writable file / symlink: unsafe, never pinned
        os.chmod(pdir + "/main.py", 0o664)
        check(mod._plugin_pin_status("demo")["state"] == "unsafe", "group-writable file -> unsafe")
        check(mod.plugin_action("demo", "x", {}).get("ok") is False, "unsafe: worker refused")
        try:
            mod.plugin_repin("demo", {})
            check(False, "unsafe tree cannot be re-pinned")
        except ValueError:
            check(True, "unsafe tree cannot be re-pinned")
        os.chmod(pdir + "/main.py", 0o644)
        os.symlink("/etc/passwd", pdir + "/web/link.js")
        check(mod._plugin_pin_status("demo")["state"] == "unsafe", "symlink -> unsafe")
        os.unlink(pdir + "/web/link.js")
        check(mod._plugin_pin_status("demo")["state"] == "ok", "clean again")
        # removed pin file -> unpinned
        os.unlink(pdir + "/.provenance.json")
        check(mod._plugin_pin_status("demo")["state"] == "unpinned", "missing pin -> unpinned")
        check(mod.plugin_action("demo", "x", {}).get("ok") is False, "unpinned: worker refused")
        check(mod._plugin_incident_conditions().get("plugin:demo:integrity", ("",))[0] == "warning",
              "unpinned: warning incident")
    finally:
        shutil.rmtree(tmp)


def write_plugin(pdir, main_src=MAIN_V1, cfg=None):
    os.makedirs(pdir + "/web", exist_ok=True)
    json.dump(MANIFEST, open(pdir + "/plugin.json", "w"))
    open(pdir + "/main.py", "w").write(main_src)
    open(pdir + "/web/plugin.js", "w").write("x")
    if cfg is not None:
        json.dump(cfg, open(pdir + "/config.json", "w"))
    for base, dirs, files in os.walk(pdir):
        os.chmod(base, 0o755)
        for f in files:
            os.chmod(os.path.join(base, f), 0o644)


def t_tofu_and_v1():
    tmp = setup()
    try:
        pdir = os.path.join(mod.PLUGINS_DIR, "demo")
        write_plugin(pdir, cfg={"token": "t"})      # pre-3.3.3 install: 0644 config, no pin
        check(mode(pdir + "/config.json") == 0o644, "fixture: legacy 0644 config")
        mod._plugin_pins_startup()
        check(mode(pdir + "/config.json") == 0o600, "startup: legacy config.json -> 0600")
        pin = json.load(open(pdir + "/.provenance.json"))
        check(pin.get("pinned_by") == "tofu" and pin["content_sha256"] == mod._plugin_content_hash(pdir),
              "startup: TOFU pin recorded")
        check(os.path.exists(mod.PLUGIN_TOFU_MARKER) and "demo" in open(mod.PLUGIN_TOFU_MARKER).read(),
              "TOFU marker written with the pinned ids")
        check(mod.plugin_action("demo", "x", {}).get("ok") is True, "TOFU-pinned plugin runs")
        # a plugin appearing after the first start is NOT trusted automatically
        p2 = os.path.join(mod.PLUGINS_DIR, "late")
        write_plugin(p2)
        json.dump(dict(MANIFEST, id="late"), open(p2 + "/plugin.json", "w"))
        mod._plugin_pins_startup()
        check(not os.path.exists(p2 + "/.provenance.json"), "after the marker: no TOFU for new plugins")
        check(mod._plugin_pin_status("late")["state"] == "unpinned", "late plugin refused (unpinned)")
        # v1 pin (3.3.0-3.3.2 install) -> re-recorded as v2 when it matches
        os.unlink(pdir + "/.provenance.json")
        v1 = mod._plugin_content_hash(pdir, 1)
        mod._plugin_write_pin(pdir, {"content_sha256": v1, "source_url": URL, "version": "1.0.0"})
        check(mod._plugin_pin_status("demo")["state"] == "ok", "v1 pin verifies")
        mod._plugin_pins_startup()
        pin = json.load(open(pdir + "/.provenance.json"))
        check(pin.get("hash_v") == 2 and pin.get("content_sha256_v1") == v1
              and pin["content_sha256"] == mod._plugin_content_hash(pdir), "v1 pin re-recorded in v2")
        # TOFU never pins an unsafe tree
        tmp2 = setup()
        try:
            p3 = os.path.join(mod.PLUGINS_DIR, "demo")
            write_plugin(p3)
            os.chmod(p3 + "/main.py", 0o666)
            mod._plugin_pins_startup()
            check(not os.path.exists(p3 + "/.provenance.json"), "TOFU skips a world-writable plugin")
        finally:
            shutil.rmtree(tmp2)
    finally:
        shutil.rmtree(tmp)


def t_hash_and_worker():
    tmp = tempfile.mkdtemp(prefix="plugin-hash-")
    try:
        a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
        os.makedirs(a)
        os.makedirs(b)
        open(a + "/m", "w").write("ain.py")
        open(b + "/main.py", "w").write("")
        check(mod._plugin_content_hash(a, 1) == mod._plugin_content_hash(b, 1), "fixture: v1 framing is ambiguous")
        check(mod._plugin_content_hash(a) != mod._plugin_content_hash(b), "v2 framing is not")
        open(a + "/config.json", "w").write("x")
        open(a + "/.provenance.json", "w").write("y")
        open(a + "/.config.json.abc.tmp", "w").write("z")
        h = mod._plugin_content_hash(a)
        os.makedirs(a + "/web")
        open(a + "/web/config.json", "w").write("asset")
        check(mod._plugin_content_hash(a) != h, "nested config.json is code (hashed); top-level one is not")
    finally:
        shutil.rmtree(tmp)
    for name, secret in (("config.json", True), (".provenance.json", True), ("api-secret.txt", True),
                         ("secrets.py", False), ("main.py", False), ("plugin.json", False)):
        check(mod._plugin_secret_name(name) is secret, "secret file classification: %s" % name)
    src = inspect.getsource(mod.plugin_action)
    check("preexec_fn=" not in src, "plugin worker: no preexec_fn")
    check('"extra_groups": []' in src and "umask=0o077" in src and '"user": uid' in src,
          "plugin worker: subprocess user/group/extra_groups/umask")
    check("RLIMIT_CORE" in mod.PLUGIN_WORKER_CODE, "plugin worker: no core dumps")


t_install_perms_and_pin()
t_update_flow()
t_tamper_and_repin()
t_tofu_and_v1()
t_hash_and_worker()
print("plugin security: %d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
