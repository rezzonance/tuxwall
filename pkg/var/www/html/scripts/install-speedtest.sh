#!/usr/bin/env bash
# TuxWall — install official Ookla Speedtest CLI without snap or apt repo.
#
# Why not the apt repo or vendoring?
#   - Ookla's packagecloud repo has no builds past jammy; on noble/resolute
#     and later `script.deb.sh` writes a codename with no Packages file, so
#     `apt install speedtest` 404s (Ookla's own workaround is to pin "jammy").
#   - The `speedtest` snap is an unofficial third-party wrapper (Proprietary,
#     publisher: Yuzukosho), pulls in snapd, and is best avoided on a gateway.
#   - The binary itself is proprietary — committing it to git or the .deb
#     would redistribute it and break the `Architecture: all` package.
#
# This script downloads the official static tarball from Ookla at install
# time (the user fetches from Ookla, we don't redistribute), picks the
# right architecture, and installs to /usr/local/bin/speedtest.
#
# Usage:
#   sudo bash scripts/install-speedtest.sh [--check] [--version 1.2.0] [--force]
#   --check   exit 0 if a working `speedtest` is already on PATH, 1 otherwise
#   --force   re-download even if a working binary exists
#
# Best-effort by design: never fail a larger installer over this — the
# dashboard degrades to manual caps with an install hint when absent.
set -euo pipefail

VERSION="1.2.0"
FORCE=0
CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --version=*) VERSION="${arg#--version=}" ;;
    --version) shift || true ;; # value handled positionally below if ever needed
    --force) FORCE=1 ;;
    --check) CHECK_ONLY=1 ;;
    *) echo "Unknown arg: $arg (see header)" >&2; exit 2 ;;
  esac
done

have_speedtest() {
  command -v speedtest >/dev/null 2>&1 && speedtest --version >/dev/null 2>&1
}

if [[ "$CHECK_ONLY" -eq 1 ]]; then
  have_speedtest && exit 0 || exit 1
fi

if [[ "$FORCE" -eq 0 ]] && have_speedtest; then
  echo "speedtest already installed: $(command -v speedtest) ($(speedtest --version 2>/dev/null | head -n1))"
  exit 0
fi

# Map dpkg arch -> Ookla tarball arch suffix.
ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
  amd64|x86_64)   TARCH="x86_64" ;;
  arm64|aarch64)  TARCH="aarch64" ;;
  armhf)          TARCH="armhf" ;;
  armel)          TARCH="armel" ;;
  i386|i686)      TARCH="i386" ;;
  *) echo "Unsupported architecture for Ookla speedtest: $ARCH" >&2; exit 1 ;;
esac

URL="https://install.speedtest.net/app/cli/ookla-speedtest-${VERSION}-linux-${TARCH}.tgz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading official Ookla speedtest ${VERSION} (${TARCH})..."
if ! curl -fsSL --max-time 120 --retry 3 -o "$TMP/speedtest.tgz" "$URL"; then
  echo "Download failed: $URL" >&2
  echo "Fallbacks: sudo snap install speedtest, or Ookla's apt repo (https://www.speedtest.net/apps/cli)" >&2
  exit 1
fi

tar -xzf "$TMP/speedtest.tgz" -C "$TMP"
BIN="$TMP/speedtest"
[[ -x "$BIN" ]] || BIN="$TMP/ookla-speedtest-${VERSION}-linux-${TARCH}/speedtest"
[[ -x "$BIN" ]] || { echo "Tarball did not contain a speedtest binary" >&2; exit 1; }

install -m 0755 "$BIN" /usr/local/bin/speedtest
hash -r 2>/dev/null || true

if ! speedtest --version >/dev/null 2>&1; then
  echo "Installed but 'speedtest --version' failed" >&2
  exit 1
fi
echo "Installed: $(speedtest --version 2>/dev/null | head -n1) -> /usr/local/bin/speedtest"
