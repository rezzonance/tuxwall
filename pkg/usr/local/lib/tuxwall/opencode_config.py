#!/usr/bin/env python3
"""TuxWall AI agent config split (3.3.5): package defaults + owner additions.

  /etc/tuxwall/opencode.json        package defaults (dpkg conffile; never
                                    written by the dashboard any more)
  /etc/tuxwall/opencode.local.json  owner additions: custom providers, the
                                    default model (dashboard: AI > Models)

opencode merges the two itself. tuxwall-agent.service runs opencode with
OPENCODE_CONFIG=/etc/tuxwall/opencode.json; the package drop-in
/usr/lib/systemd/system/tuxwall-agent.service.d/20-local-config.conf runs
`opencode_config.py env` before start, which hands the local file to
opencode as OPENCODE_CONFIG_CONTENT - a config layer above OPENCODE_CONFIG
in opencode 2.x (objects deep-merge, the local value wins). It is read at
start, so a change needs an agent restart (the dashboard does that).

Because the dashboard no longer edits the conffile, package updates of the
defaults never stop at a dpkg conffile prompt.

  opencode_config.py env OUT [--local PATH]
      write OUT as a systemd EnvironmentFile (OPENCODE_CONFIG_CONTENT=...);
      a missing/invalid local file -> an empty OUT (opencode runs on the
      defaults). Never fails (exit 0).
  opencode_config.py migrate [--conf P] [--default P] [--local P]
                             [--backup-dir D] [--check]
      postinst: move owner additions out of a modified opencode.json into
      opencode.local.json ONLY when that is lossless (the merged result is
      exactly the current file); then opencode.json gets the shipped bytes
      back. Anything else (lists changed, default keys deleted, comments,
      invalid JSON, conflicting local file) is left alone with a note.
      Exit 0 = nothing to do, 10 = migrated (restart the agent),
      3 = left alone, 1 = error. --check only reports.
  opencode_config.py merged [--conf P] [--local P]
      print the merged view (read-only; for support).
"""
import json
import os
import sys
import tempfile
import time

CONF = "/etc/tuxwall/opencode.json"
LOCAL = "/etc/tuxwall/opencode.local.json"
DEFAULT = "/usr/share/tuxwall/opencode.default.json"
BACKUP_DIR = "/var/backups/tuxwall"
ENV_VAR = "OPENCODE_CONFIG_CONTENT"
MAX_LOCAL = 64 * 1024

RC_NOTHING, RC_MIGRATED, RC_LEFT, RC_ERROR = 0, 10, 3, 1


class Ambiguous(Exception):
    pass


def load(path):
    """Strict JSON object, or raise ValueError/OSError."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("not a JSON object")
    return data


def deep_merge(base, over):
    """opencode's merge for what TuxWall writes: objects merge key by key
    (recursively), any other value from `over` replaces."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = deep_merge(base[k], v) if k in base else v
        return out
    return over


def owner_additions(cur, dflt, path="$"):
    """What `cur` adds to / changes in `dflt`, as a document that
    deep_merge(dflt, result) turns back into `cur`. Raises Ambiguous for
    changes a higher layer cannot express or whose merge is not plain
    replace/deep-merge (deleted keys, changed lists)."""
    if isinstance(cur, dict) and isinstance(dflt, dict):
        for k in dflt:
            if k not in cur:
                raise Ambiguous("{}.{} was removed from the defaults".format(path, k))
        out = {}
        for k, v in cur.items():
            if k not in dflt:
                out[k] = v
            elif v != dflt[k]:
                out[k] = owner_additions(v, dflt[k], "{}.{}".format(path, k))
        return out
    if isinstance(cur, list) or isinstance(dflt, list):
        raise Ambiguous("{} (a list) differs from the defaults".format(path))
    if isinstance(dflt, dict):
        raise Ambiguous("{} replaces an object of the defaults".format(path))
    return cur


def has_list_diff(a, b):
    """True when merging b over a would replace a list (merge order unclear)."""
    if isinstance(a, dict) and isinstance(b, dict):
        return any(has_list_diff(a[k], b[k]) for k in b if k in a)
    return (isinstance(a, list) or isinstance(b, list)) and a != b


def write_atomic(path, data, mode, uid=None, gid=None):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=d)
    try:
        os.fchmod(fd, mode)
        if uid is not None:
            os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def env_line(doc):
    """One EnvironmentFile line. systemd takes a single-quoted value verbatim;
    a ' can only occur inside JSON strings, so \\u0027 keeps it equivalent."""
    text = json.dumps(doc, ensure_ascii=True, separators=(",", ":")).replace("'", "\\u0027")
    return "{}='{}'\n".format(ENV_VAR, text)


def cmd_env(out, local=LOCAL):
    line = ""
    try:
        if os.path.getsize(local) > MAX_LOCAL:
            raise ValueError("larger than {} bytes".format(MAX_LOCAL))
        doc = load(local)
        doc.pop("$schema", None)
        if doc:
            line = env_line(doc)
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        print("opencode_config: ignoring {} ({}); the agent runs on the defaults".format(local, exc),
              file=sys.stderr)
    try:
        write_atomic(out, line.encode("ascii"), 0o600)
    except OSError as exc:
        print("opencode_config: cannot write {}: {}".format(out, exc), file=sys.stderr)
    return 0


def plan_migration(conf_path, default_path, local_path):
    """-> (rc, message, new_local or None). Reads only."""
    try:
        with open(conf_path, "rb") as f:
            cur_bytes = f.read()
    except FileNotFoundError:
        return RC_NOTHING, "{} absent - nothing to do".format(conf_path), None
    try:
        with open(default_path, "rb") as f:
            dflt_bytes = f.read()
        dflt = load(default_path)
    except (OSError, ValueError) as exc:
        return RC_ERROR, "shipped defaults {} unreadable ({})".format(default_path, exc), None
    if cur_bytes == dflt_bytes:
        return RC_NOTHING, "{} is the shipped default".format(conf_path), None
    try:
        cur = json.loads(cur_bytes.decode("utf-8"))
        if not isinstance(cur, dict):
            raise ValueError("not a JSON object")
    except ValueError as exc:
        return RC_LEFT, "{} is not plain JSON ({}) - left as it is".format(conf_path, exc), None
    try:
        existing = load(local_path) if os.path.exists(local_path) else {}
    except (OSError, ValueError) as exc:
        return RC_LEFT, "{} unreadable ({}) - {} left as it is".format(local_path, exc, conf_path), None
    try:
        add = owner_additions(cur, dflt)
    except Ambiguous as exc:
        return RC_LEFT, "{}: {} - left as it is (owner changes cannot move losslessly)".format(
            conf_path, exc), None
    if has_list_diff(add, existing):
        return RC_LEFT, "{} and {} both set the same list - left as they are".format(conf_path, local_path), None
    new_local = deep_merge(add, existing)
    before = deep_merge(cur, existing)
    after = deep_merge(dflt, new_local)
    if before != after:
        return RC_LEFT, "moving the owner keys would change the merged config - {} left as it is".format(
            conf_path), None
    keys = sorted(_leaf_paths(add))
    if not keys:
        return RC_MIGRATED, "{} equals the shipped default (formatting only) - restoring its bytes".format(
            conf_path), new_local if new_local != existing else None
    return RC_MIGRATED, "moving {} from {} to {}".format(", ".join(keys), conf_path, local_path), new_local


def _leaf_paths(doc, prefix=""):
    """providers.unsloth, model ... (two levels deep is enough for a note)."""
    out = []
    for k, v in doc.items():
        p = prefix + k
        if isinstance(v, dict) and not prefix and k in ("providers", "provider", "agents", "mcp"):
            out.extend(_leaf_paths(v, p + "."))
        else:
            out.append(p)
    return out


def cmd_migrate(conf=CONF, default=DEFAULT, local=LOCAL, backup_dir=BACKUP_DIR, check=False):
    rc, msg, new_local = plan_migration(conf, default, local)
    if rc != RC_MIGRATED or check:
        print(("would: " if check and rc == RC_MIGRATED else "") + msg)
        return rc
    try:
        st = os.stat(conf)
        with open(conf, "rb") as f:
            cur_bytes = f.read()
        with open(default, "rb") as f:
            dflt_bytes = f.read()
        os.makedirs(backup_dir, mode=0o700, exist_ok=True)
        backup = os.path.join(backup_dir, "opencode.json.pre-split-" + time.strftime("%Y%m%d-%H%M%S"))
        write_atomic(backup, cur_bytes, 0o600, 0 if os.geteuid() == 0 else None, 0)
        if new_local is not None:
            lst = os.stat(local) if os.path.exists(local) else st
            data = (json.dumps(new_local, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
            write_atomic(local, data, lst.st_mode & 0o7777 or 0o644,
                         lst.st_uid if os.geteuid() == 0 else None, lst.st_gid)
        write_atomic(conf, dflt_bytes, st.st_mode & 0o7777, st.st_uid if os.geteuid() == 0 else None, st.st_gid)
    except OSError as exc:
        print("opencode config split failed ({}) - {} left as it is".format(exc, conf))
        return RC_ERROR
    print("{} (previous file: {})".format(msg, backup))
    return RC_MIGRATED


def cmd_merged(conf=CONF, local=LOCAL):
    doc = load(conf)
    if os.path.exists(local):
        doc = deep_merge(doc, load(local))
    print(json.dumps(doc, indent=2, ensure_ascii=False))
    return 0


def _opt(args, name, default):
    if name in args:
        i = args.index(name)
        val = args[i + 1]
        del args[i:i + 2]
        return val
    return default


def main(argv):
    args = list(argv)
    if not args:
        print(__doc__)
        return 2
    cmd = args.pop(0)
    if cmd == "env":
        local = _opt(args, "--local", LOCAL)
        if len(args) != 1:
            print("usage: opencode_config.py env OUT [--local PATH]", file=sys.stderr)
            return 0
        return cmd_env(args[0], local)
    if cmd == "migrate":
        check = "--check" in args
        if check:
            args.remove("--check")
        return cmd_migrate(_opt(args, "--conf", CONF), _opt(args, "--default", DEFAULT),
                           _opt(args, "--local", LOCAL), _opt(args, "--backup-dir", BACKUP_DIR), check)
    if cmd == "merged":
        return cmd_merged(_opt(args, "--conf", CONF), _opt(args, "--local", LOCAL))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
