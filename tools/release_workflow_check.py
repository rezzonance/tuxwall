#!/usr/bin/env python3
"""GitHub Releases from the apt workflow (3.3.5).

1. Structure of .github/workflows/apt.yml: YAML parses; workflow token is
   read-only, contents: write only on the jobs that need it; the release job
   runs after publish, fetches annotated tags + gh-pages, backfills
   v3.3.2-v3.3.4; workflow_dispatch takes an optional tag; the apt publish
   steps are byte-for-byte the ones v3.3.4 shipped (pinned digest, and the
   v3.3.4 tag itself when the clone has it).
2. tools/github-release.sh end to end in a temp dir: a throwaway GPG key, a
   git repo with annotated tags and a gh-pages branch carrying signed apt
   indexes, and a fake `gh` that records calls and stores assets. Create,
   update (empty notes, missing assets), skip when complete, --force, owner
   notes kept, latest flag, tampered .deb refused, "computed at backfill"
   when the index is gone, lightweight tag / wrong signing key refused.
3. The "images" job (install images, 3.3.7): runs after the release job on
   tags (and workflow_dispatch tag + images), builds the netinstall ISO + VM
   qcow2 from the tag, verifies them, attaches them with
   github-release.sh --assets: SHA256SUMS = the release's signed list + the
   images, re-signed; notes get an images list; a release re-run keeps the
   image lines; > 2 GiB, bad .sha256, missing release, unsigned list refused.

    python3 tools/release_workflow_check.py
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github/workflows/apt.yml")
SCRIPT = os.path.join(ROOT, "tools/github-release.sh")
# sha256 of the canonical JSON of jobs.publish.steps as released in v3.3.4
PUBLISH_STEPS_V334 = "f1e487ea65269d3063da5a32809c361b286b5dfec88f217bc7c7cefc2d95b544"

PASS = FAIL = 0


def check(cond, msg):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print("FAIL:", msg)


def steps_digest(steps):
    return hashlib.sha256(json.dumps(steps, sort_keys=True).encode()).hexdigest()


def t_structure():
    wf = yaml.safe_load(open(WF))
    on = wf.get(True) or wf.get("on")
    check(on["push"]["tags"] == ["v*"], "runs on v* tags")
    check("tag" in (on.get("workflow_dispatch") or {}).get("inputs", {}), "workflow_dispatch has a tag input")
    check(wf.get("permissions") == {"contents": "read"}, "workflow-level token is read-only")
    jobs = wf["jobs"]
    pub, rel = jobs.get("publish", {}), jobs.get("release", {})
    check(pub.get("permissions") == {"contents": "write"}, "publish job: contents: write (gh-pages push)")
    check(rel.get("permissions") == {"contents": "write"}, "release job: contents: write, nothing else")
    check(rel.get("needs") == "publish", "release runs after publish")
    check("needs.publish.result == 'success'" in rel.get("if", ""), "release only after a successful publish")
    check(rel.get("env", {}).get("GH_TOKEN") == "${{ github.token }}", "gh uses the job token")
    check(set((rel.get("env", {}).get("BACKFILL_TAGS") or "").split()) == {"v3.3.2", "v3.3.3", "v3.3.4"},
          "backfill tags v3.3.2 v3.3.3 v3.3.4")
    rsteps = rel.get("steps", [])
    co = next((s for s in rsteps if str(s.get("uses", "")).startswith("actions/checkout")), {})
    check((co.get("with") or {}).get("fetch-depth") == 0, "release checkout has full history")
    runs = "\n".join(s.get("run", "") for s in rsteps)
    check("git fetch --force --tags origin" in runs and "git fetch origin gh-pages" in runs,
          "annotated tags + gh-pages fetched")
    check("tools/github-release.sh" in runs and "${{" not in runs, "release step calls the script; no inline ${{ }}")
    check("echo \"$APT_GPG_PRIVATE_KEY\"" not in runs.replace("printf '%s\\n' \"$APT_GPG_PRIVATE_KEY\" | gpg", ""),
          "the key only goes into gpg --import")
    check("publish" in pub.get("if", "") or "inputs.tag == ''" in pub.get("if", ""),
          "publish skipped when only a release is requested")

    img = jobs.get("images", {})
    check(img.get("needs") == "release", "images job runs after the release job")
    iif = img.get("if", "")
    check("needs.release.result == 'success'" in iif and "github.ref_type == 'tag'" in iif
          and "inputs.tag != ''" in iif and "inputs.images" in iif,
          "images job: only for a tag, after a successful release (push or dispatch with tag + images)")
    check(img.get("permissions") == {"contents": "write"}, "images job: contents: write, nothing else")
    check((on.get("workflow_dispatch") or {}).get("inputs", {}).get("images", {}).get("type") == "boolean",
          "workflow_dispatch has an images switch")
    isteps = img.get("steps", [])
    ico = next((x for x in isteps if str(x.get("uses", "")).startswith("actions/checkout")), {})
    check((ico.get("with") or {}).get("ref") == "${{ inputs.tag || github.ref }}", "images are built from the tag")
    iruns = "\n".join(x.get("run", "") for x in isteps)
    check("${{" not in iruns, "images job: no inline ${{ }} in run steps")
    order = [k for k in ("image/netinstall/build.sh", "image/vm/build.sh --latest", "image/verify-images.sh",
                         "tools/github-release.sh --assets") if k in iruns]
    check(order == ["image/netinstall/build.sh", "image/vm/build.sh --latest", "image/verify-images.sh",
                    "tools/github-release.sh --assets"]
          and iruns.index("image/verify-images.sh") < iruns.index("tools/github-release.sh --assets"),
          "images job: build ISO, build VM image, verify, then attach")
    check('[ "$TAG" != "v$VERSION" ]' in iruns, "images job: tag must match the package version")
    check("predates the install images" in iruns, "images job: tags without image/ are skipped")
    check("ubuntu-cloudimage-keyring" in iruns and "qemu-utils" in iruns and "xorriso" in iruns,
          "images job installs the build tools + Ubuntu keyrings")
    check(img.get("env", {}).get("GH_TOKEN") == "${{ github.token }}", "images job: gh uses the job token")
    ver = open(os.path.join(ROOT, "image/verify-images.sh")).read()
    check("MAX_BYTES=$((2 * 1024 * 1024 * 1024 - 1))" in ver and "BIOS" in ver and "UEFI" in ver
          and "check -q" in ver and "-TEST" in ver, "verify-images.sh: 2 GiB, BIOS+UEFI, qemu-img check, no TEST image")

    steps = pub.get("steps", [])
    digest = steps_digest(steps)
    check(digest == PUBLISH_STEPS_V334, "apt publish steps unchanged since v3.3.4 (digest %s)" % digest)
    old = subprocess.run(["git", "-C", ROOT, "show", "v3.3.4:.github/workflows/apt.yml"],
                         capture_output=True, text=True)
    if old.returncode == 0:
        old_steps = yaml.safe_load(old.stdout)["jobs"]["publish"]["steps"]
        check(old_steps == steps, "apt publish steps == v3.3.4's (names, commands, env)")
        check(steps_digest(old_steps) == PUBLISH_STEPS_V334, "pinned digest is v3.3.4's")
    else:
        print("note: v3.3.4 not in this clone - compared against the pinned digest only")


FAKE_GH = r'''#!/usr/bin/env python3
import json, os, shutil, sys
st = os.environ["GH_STATE"]
a = sys.argv[1:]
open(os.path.join(st, "calls.log"), "a").write(json.dumps(a) + "\n")
def rel(tag):
    p = os.path.join(st, tag + ".json")
    return json.load(open(p)) if os.path.exists(p) else None
def save(tag, d):
    json.dump(d, open(os.path.join(st, tag + ".json"), "w"))
def files(args):
    out = [x for x in args if os.path.isfile(x)]
    return out
def opt(args, name):
    return args[args.index(name) + 1] if name in args else None
assert a[0] == "release", a
cmd, tag = a[1], a[2]
if cmd == "download":
    adir = os.path.join(st, "assets", tag)
    pats = [a[i + 1] for i, x in enumerate(a) if x == "-p"]
    dest = opt(a, "-D") or "."
    got = [n for n in pats if os.path.isfile(os.path.join(adir, n))]
    if not got:
        print("no assets match", file=sys.stderr); sys.exit(1)
    for n in got:
        shutil.copy(os.path.join(adir, n), os.path.join(dest, n))
    sys.exit(0)
if cmd == "view":
    d = rel(tag)
    if d is None:
        print("release not found", file=sys.stderr); sys.exit(1)
    print(json.dumps({"name": d["name"], "body": d["body"], "isDraft": False,
                      "assets": [{"name": n} for n in sorted(d["assets"])]}))
    sys.exit(0)
d = rel(tag) or {"name": "", "body": "", "assets": {}}
if cmd in ("create", "edit"):
    if opt(a, "--title") is not None: d["name"] = opt(a, "--title")
    nf = opt(a, "--notes-file")
    if nf: d["body"] = open(nf).read()
if cmd in ("create", "upload"):
    adir = os.path.join(st, "assets", tag); os.makedirs(adir, exist_ok=True)
    for f in files([x for x in a[3:] if x != (opt(a, "--notes-file") or "")]):
        shutil.copy(f, os.path.join(adir, os.path.basename(f)))
        d["assets"][os.path.basename(f)] = True
save(tag, d)
'''


def sh(cmd, cwd=None, env=None, check_rc=True, inp=None):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, input=inp, timeout=120)
    if check_rc and p.returncode != 0:
        raise RuntimeError("{} -> {}: {}".format(cmd, p.returncode, p.stderr[-800:]))
    return p


class Lab:
    def __init__(self):
        self.d = tempfile.mkdtemp(prefix="relchk-")
        self.gnupg = self.d + "/gnupg"
        os.makedirs(self.gnupg, mode=0o700)
        self.env = dict(os.environ, GNUPGHOME=self.gnupg, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL="/dev/null",
                        GIT_CONFIG_NOSYSTEM="1")
        sh(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "Test Repo <t@example.com>", "ed25519",
            "sign", "never"], env=self.env)
        out = sh(["gpg", "--batch", "--list-secret-keys", "--with-colons"], env=self.env).stdout
        self.fpr = next(l.split(":")[9] for l in out.splitlines() if l.startswith("fpr:"))
        self.repo = self.d + "/repo"
        os.makedirs(self.repo)
        g = lambda *a: sh(["git", "-C", self.repo, *a], env=self.env)
        self.g = g
        g("init", "-q", "-b", "main")
        open(self.repo + "/apt-public.asc", "w").write(
            sh(["gpg", "--batch", "--armor", "--export", self.fpr], env=self.env).stdout)
        g("add", "-A")
        g("commit", "-q", "-m", "init")
        for v in ("1.0.0", "1.0.1"):
            open(self.repo + "/v", "w").write(v)
            g("add", "v")
            g("commit", "-q", "-m", "TuxWall " + v)
            g("tag", "-a", "v" + v, "-m", "TuxWall {}\n\nNotes for {}: fixed things.".format(v, v))
        g("tag", "v1.0.9")   # lightweight
        self.debs = {}
        g("checkout", "-q", "--orphan", "gh-pages")
        g("rm", "-rqf", ".")
        for v in ("0.9.0", "1.0.0", "1.0.1"):
            self.publish(v)
        g("checkout", "-q", "main")
        # 0.9.0's index is gone: drop its publish commit message
        self.state = self.d + "/ghstate"
        os.makedirs(self.state)
        os.makedirs(self.d + "/bin")
        open(self.d + "/bin/gh", "w").write(FAKE_GH)
        os.chmod(self.d + "/bin/gh", 0o755)

    def publish(self, v, msg=None):
        pool = self.repo + "/pool/main/t/tuxwall"
        dists = self.repo + "/dists/stable/main/binary-amd64"
        os.makedirs(pool, exist_ok=True)
        os.makedirs(dists, exist_ok=True)
        data = ("deb payload " + v).encode()
        self.debs[v] = data
        open("{}/tuxwall_{}_all.deb".format(pool, v), "wb").write(data)
        pk = "Package: tuxwall\nVersion: {}\nFilename: pool/main/t/tuxwall/tuxwall_{}_all.deb\nSHA256: {}\n".format(
            v, v, hashlib.sha256(data).hexdigest())
        open(dists + "/Packages", "w").write(pk)
        rel = "Origin: TuxWall\nSHA256:\n {} {} main/binary-amd64/Packages\n".format(
            hashlib.sha256(pk.encode()).hexdigest(), len(pk))
        open(self.repo + "/dists/stable/Release", "w").write(rel)
        sh(["gpg", "--batch", "--yes", "--local-user", self.fpr, "--clearsign", "--output",
            self.repo + "/dists/stable/InRelease", self.repo + "/dists/stable/Release"], env=self.env)
        self.g("add", "-A")
        self.g("commit", "-q", "-m", msg or "apt: publish tuxwall " + v)

    def run(self, *args, fpr=None, extra=None):
        e = dict(self.env, PATH=self.d + "/bin:" + os.environ["PATH"], GH_STATE=self.state,
                 PAGES_REF="gh-pages", PAGES_URL="http://127.0.0.1:9/none", APT_KEY="apt-public.asc",
                 EXPECT_FPR=self.fpr, GPG_FPR=fpr or self.fpr, GH_REPO="t/t")
        e.update(extra or {})
        if os.path.exists(self.state + "/calls.log"):
            os.unlink(self.state + "/calls.log")
        p = subprocess.run(["bash", SCRIPT, *args], cwd=self.repo, env=e, capture_output=True, text=True, timeout=300)
        calls = [json.loads(l) for l in open(self.state + "/calls.log")] if os.path.exists(self.state + "/calls.log") else []
        return p.returncode, p.stdout + p.stderr, [c for c in calls if c[1] != "view"]

    def rel(self, tag):
        p = self.state + "/" + tag + ".json"
        return json.load(open(p)) if os.path.exists(p) else None

    def asset(self, tag, name):
        return open(os.path.join(self.state, "assets", tag, name), "rb").read()

    def close(self):
        shutil.rmtree(self.d, ignore_errors=True)


def t_script():
    if not shutil.which("gpg") or not shutil.which("gpgv"):
        print("note: gpg/gpgv missing - script test skipped")
        return
    lab = Lab()
    try:
        rc, out, calls = lab.run("--force", "v1.0.1")
        r = lab.rel("v1.0.1")
        check(rc == 0 and r is not None, "create: rc 0 (%s)" % out[-400:])
        create = next((c for c in calls if c[1] == "create"), [])
        check("--latest=true" in create and "--verify-tag" in create and "TuxWall 1.0.1" in create,
              "create: title, --verify-tag, newest tag marked latest (%s)" % create)
        check(set(r["assets"]) == {"tuxwall_1.0.1_all.deb", "SHA256SUMS", "SHA256SUMS.asc"}, "create: three assets")
        deb = lab.asset("v1.0.1", "tuxwall_1.0.1_all.deb")
        sums = lab.asset("v1.0.1", "SHA256SUMS").decode()
        check(deb == lab.debs["1.0.1"], "the attached .deb is the published file")
        check(sums == "{}  tuxwall_1.0.1_all.deb\n".format(hashlib.sha256(deb).hexdigest()), "SHA256SUMS content")
        d = tempfile.mkdtemp(dir=lab.d)
        for n in ("SHA256SUMS", "SHA256SUMS.asc"):
            open(os.path.join(d, n), "wb").write(lab.asset("v1.0.1", n))
        sh(["gpg", "--batch", "--yes", "--dearmor", "-o", d + "/k.gpg", lab.repo + "/apt-public.asc"], env=lab.env)
        v = sh(["gpgv", "--keyring", d + "/k.gpg", d + "/SHA256SUMS.asc", d + "/SHA256SUMS"], env=lab.env, check_rc=False)
        check(v.returncode == 0 and lab.asset("v1.0.1", "SHA256SUMS.asc").startswith(b"-----BEGIN PGP SIGNATURE"),
              "SHA256SUMS.asc: armored detached signature by the apt key")
        check("Notes for 1.0.1: fixed things." in r["body"] and hashlib.sha256(deb).hexdigest() in r["body"]
              and "Verified against the signed apt index" in r["body"] and "<!-- tuxwall-release-assets -->" in r["body"],
              "notes = tag message + checksum + verification")

        rc, out, calls = lab.run("v1.0.1")
        check(rc == 0 and "complete - skipped" in out and not [c for c in calls if c[1] in ("create", "upload")]
              and ["release", "edit", "v1.0.1", "--latest"] in calls, "complete release: skipped, stays latest")

        json.dump({"name": "TuxWall 1.0.0", "body": "", "assets": {}}, open(lab.state + "/v1.0.0.json", "w"))
        rc, out, calls = lab.run("v1.0.0")
        r = lab.rel("v1.0.0")
        edit = next((c for c in calls if c[1] == "edit"), [])
        check(rc == 0 and "--notes-file" in edit and "--latest" not in edit and "--title" not in edit,
              "existing empty release: notes filled, not latest, title kept (%s)" % edit)
        check(set(r["assets"]) == {"tuxwall_1.0.0_all.deb", "SHA256SUMS", "SHA256SUMS.asc"}
              and any(c[1] == "upload" and "--clobber" in c for c in calls), "missing assets uploaded")
        rc, out, calls = lab.run("--force", "v1.0.0")
        check(rc == 0 and any(c[1] == "upload" for c in calls), "--force re-uploads a complete release")

        json.dump({"name": "", "body": "Hand-written notes.", "assets": {}}, open(lab.state + "/v1.0.0.json", "w"))
        rc, out, calls = lab.run("v1.0.0")
        r = lab.rel("v1.0.0")
        check(rc == 0 and r["body"] == "Hand-written notes." and r["name"] == "TuxWall 1.0.0",
              "owner notes kept, empty title filled")

        # a version whose publish index is gone -> computed at backfill
        lab.g("tag", "-a", "v0.9.0", "-m", "TuxWall 0.9.0")
        log = lab.g("log", "--format=%H %s", "gh-pages").stdout
        check("apt: publish tuxwall 0.9.0" in log, "fixture: 0.9.0 has a publish commit")
        rc, out, calls = lab.run("v0.9.0", extra={"PAGES_REF": "gh-pages"})
        r = lab.rel("v0.9.0")
        check(rc == 0 and r and "Verified against" in r["body"], "older tag with its index in history: verified")
        create = next((c for c in calls if c[1] == "create"), [])
        check("--latest=false" in create, "older tag: not marked latest")

        lab.g("checkout", "-q", "gh-pages")
        open(lab.repo + "/pool/main/t/tuxwall/tuxwall_0.9.0_all.deb", "wb").write(b"tampered")
        lab.g("commit", "-q", "-am", "oops")
        lab.g("checkout", "-q", "main")
        os.unlink(lab.state + "/v0.9.0.json")
        rc, out, calls = lab.run("--force", "v0.9.0")
        check(rc == 1 and "!=" in out and not [c for c in calls if c[1] in ("create", "upload")],
              "tampered .deb (sha != signed index): refused, nothing published")

        lab.g("tag", "-a", "v0.8.0", "-m", "TuxWall 0.8.0")
        lab.g("checkout", "-q", "gh-pages")
        open(lab.repo + "/pool/main/t/tuxwall/tuxwall_0.8.0_all.deb", "wb").write(b"old payload")
        lab.g("add", "-A")
        lab.g("commit", "-q", "-m", "pool: keep 0.8.0")
        lab.g("checkout", "-q", "main")
        rc, out, calls = lab.run("v0.8.0")
        r = lab.rel("v0.8.0")
        check(rc == 0 and r and "Checksums computed at backfill" in r["body"]
              and hashlib.sha256(b"old payload").hexdigest() in r["body"], "no index for it: computed at backfill")

        rc, out, calls = lab.run("v1.0.9")
        check(rc == 1 and "not an annotated tag" in out and not calls, "lightweight tag refused")
        rc, out, calls = lab.run("--force", "v1.0.1", fpr="0" * 40)
        check(rc == 1 and "signing key" in out and not [c for c in calls if c[1] in ("create", "upload")],
              "a signing key other than the apt key is refused")
        rc, out, calls = lab.run("v1.2.3")
        check(rc == 1 and not calls, "tag that does not exist: error, nothing published")
        rc, out, calls = lab.run("v1.0.1", "v1.2.3")
        check(rc == 1 and "complete - skipped" in out, "one bad tag fails the run but the others still run")
        t_assets(lab)
    finally:
        lab.close()


def t_assets(lab):
    img = os.path.join(lab.d, "images")
    os.makedirs(img)
    names = ("tuxwall-netinstall-1.0.1-amd64.iso", "tuxwall-vm-1.0.1-amd64.qcow2")
    for n in names:
        open(os.path.join(img, n), "wb").write(("image " + n).encode())
        sh(["sh", "-c", "sha256sum %s > %s.sha256" % (n, n)], cwd=img)
    deb = lab.asset("v1.0.1", "tuxwall_1.0.1_all.deb")
    rc, out, calls = lab.run("--assets", img, "v1.0.1")
    r = lab.rel("v1.0.1")
    check(rc == 0 and set(names) <= set(r["assets"]), "--assets: images attached (%s)" % out[-500:])
    sums = lab.asset("v1.0.1", "SHA256SUMS").decode()
    want = ["{}  tuxwall_1.0.1_all.deb".format(hashlib.sha256(deb).hexdigest())] + [
        "{}  {}".format(hashlib.sha256(("image " + n).encode()).hexdigest(), n) for n in names]
    check(sums.splitlines() == want, "--assets: SHA256SUMS = deb line + image lines\n" + sums)
    d = tempfile.mkdtemp(dir=lab.d)
    for n in ("SHA256SUMS", "SHA256SUMS.asc"):
        open(os.path.join(d, n), "wb").write(lab.asset("v1.0.1", n))
    sh(["gpg", "--batch", "--yes", "--dearmor", "-o", d + "/k.gpg", lab.repo + "/apt-public.asc"], env=lab.env)
    v = sh(["gpgv", "--keyring", d + "/k.gpg", d + "/SHA256SUMS.asc", d + "/SHA256SUMS"], env=lab.env, check_rc=False)
    check(v.returncode == 0, "--assets: SHA256SUMS re-signed with the apt key")
    body = r["body"]
    check(body.count("<!-- tuxwall-images -->") == 1 and all(n in body for n in names)
          and body.index("<!-- tuxwall-images -->") < body.index("<!-- tuxwall-release-assets -->")
          and "Notes for 1.0.1" in body, "--assets: notes list the images above the marker")
    ups = [c for c in calls if c[1] == "upload"]
    check(len(ups) == 2 and ups[-1][-2:] and os.path.basename(ups[-1][-1]) == "SHA256SUMS.asc"
          and "--clobber" in ups[0], "--assets: images uploaded first, then SHA256SUMS(.asc)")
    rc, out, calls = lab.run("--assets", img, "v1.0.1")
    r = lab.rel("v1.0.1")
    check(rc == 0 and r["body"].count("<!-- tuxwall-images -->") == 1
          and lab.asset("v1.0.1", "SHA256SUMS").decode().splitlines() == want, "--assets re-run: same list, one images section")
    rc, out, calls = lab.run("--force", "v1.0.1")
    r = lab.rel("v1.0.1")
    check(rc == 0 and lab.asset("v1.0.1", "SHA256SUMS").decode().splitlines() == want
          and "kept in SHA256SUMS" in out and r["body"].count("<!-- tuxwall-images -->") == 1,
          "release re-run (--force) keeps the image lines + images list\n" + out[-400:])
    # refusals: nothing uploaded
    open(os.path.join(img, names[1]), "ab").write(b"x")
    rc, out, calls = lab.run("--assets", img, "v1.0.1")
    check(rc == 1 and "does not match" in out and not [c for c in calls if c[1] in ("upload", "edit")],
          "--assets: image not matching its .sha256 refused")
    open(os.path.join(img, names[1]), "wb").write(("image " + names[1]).encode())
    with open(os.path.join(img, names[0]), "r+b") as f:
        f.truncate(2 * 1024 ** 3)
    rc, out, calls = lab.run("--assets", img, "v1.0.1")
    check(rc == 1 and "2 GiB" in out and not [c for c in calls if c[1] in ("upload", "edit")],
          "--assets: image over 2 GiB refused")
    os.unlink(os.path.join(img, names[0]))
    os.unlink(os.path.join(img, names[0] + ".sha256"))
    rc, out, calls = lab.run("--assets", img, "v1.0.0")
    check(rc == 1 and "no tuxwall-netinstall-1.0.0" in out and not calls, "--assets: images of another version refused")
    img2 = os.path.join(lab.d, "images2")
    os.makedirs(img2)
    n = "tuxwall-vm-0.9.0-amd64.qcow2"
    open(os.path.join(img2, n), "wb").write(b"vm")
    sh(["sh", "-c", "sha256sum %s > %s.sha256" % (n, n)], cwd=img2)
    json.dump({"name": "TuxWall 0.9.0", "body": "x", "assets": {}}, open(lab.state + "/v0.9.0.json", "w"))
    rc, out, calls = lab.run("--assets", img2, "v0.9.0")
    check(rc == 1 and "run the release job first" in out and not [c for c in calls if c[1] in ("upload", "edit")],
          "--assets: release without deb/SHA256SUMS refused")
    adir = os.path.join(lab.state, "assets", "v1.0.1")
    open(os.path.join(adir, "SHA256SUMS"), "a").write("0" * 64 + "  evil.iso\n")
    os.unlink(os.path.join(img, names[1] + ".sha256"))
    sh(["sh", "-c", "sha256sum %s > %s.sha256" % (names[1], names[1])], cwd=img)
    rc, out, calls = lab.run("--assets", img, "v1.0.1")
    check(rc == 1 and "does not verify" in out and not [c for c in calls if c[1] in ("upload", "edit")],
          "--assets: a release SHA256SUMS whose signature fails is refused")


def main():
    t_structure()
    t_script()
    print("release_workflow_check: {} passed, {} failed".format(PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
