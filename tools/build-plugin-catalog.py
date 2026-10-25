#!/usr/bin/env python3
"""Regenerate plugins/catalog.json from the plugin source folders.

Each folder under plugins/ with a valid plugin.json contributes one entry.
The catalog is what dashboards browse ("Available plugins") - it is
published to gh-pages by .github/workflows/plugins-catalog.yml whenever
plugins/ changes on main, and fetched by the API server's
/api/plugins/available proxy.

Usage: python3 tools/build-plugin-catalog.py [repo_root]
Writes <repo_root>/plugins/catalog.json. Never touches anything else.
"""
import json
import os
import sys
import time

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else
                       os.path.join(os.path.dirname(__file__), ".."))
PLUGINS_DIR = os.path.join(REPO, "plugins")
GITHUB_BASE = "https://github.com/rezzonance/tuxwall/tree/main/plugins/"

REQUIRED = ("id", "name", "version")


def main():
    entries = []
    if not os.path.isdir(PLUGINS_DIR):
        print("no plugins/ directory", file=sys.stderr)
        sys.exit(1)
    for name in sorted(os.listdir(PLUGINS_DIR)):
        manifest = os.path.join(PLUGINS_DIR, name, "plugin.json")
        if not os.path.isfile(manifest):
            continue
        try:
            with open(manifest, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"skip {name}: bad manifest ({exc})", file=sys.stderr)
            continue
        if not all(k in data for k in REQUIRED):
            print(f"skip {name}: manifest missing {REQUIRED}", file=sys.stderr)
            continue
        entries.append({
            "id": str(data["id"]),
            "name": str(data["name"]),
            "version": str(data["version"]),
            "description": str(data.get("description") or ""),
            "nav": data.get("nav") or {},
            # Install URL in the exact format the dashboard's
            # install-from-GitHub flow parses (repo tree/subpath).
            "url": GITHUB_BASE + name,
        })
    catalog = {
        "ok": True,
        "generated": int(time.time()),
        "plugins": entries,
    }
    out = os.path.join(PLUGINS_DIR, "catalog.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=2)
        fh.write("\n")
    print(f"catalog.json: {len(entries)} plugin(s) -> {out}")


if __name__ == "__main__":
    main()
