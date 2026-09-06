#!/usr/bin/env bash
# TuxWall APT repository installer.
#
# One-line install:
#   curl -fsSL https://rezzonance.github.io/tuxwall/install-repo.sh | sudo bash
#
# Adds the signed TuxWall repository and installs the tuxwall package.
# Safe to re-run (idempotent).
set -euo pipefail

REPO_URL="https://rezzonance.github.io/tuxwall"
KEYRING="/usr/share/keyrings/tuxwall.gpg"
LIST="/etc/apt/sources.list.d/tuxwall.list"

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must run as root (try: curl -fsSL ${REPO_URL}/install-repo.sh | sudo bash)" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer requires a Debian/Ubuntu system with apt." >&2
  exit 1
fi

for tool in curl gpg; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "This installer needs '$tool' (try: sudo apt install -y curl gnupg)." >&2
    exit 1
  fi
done

echo "==> Adding TuxWall signing key (${KEYRING})"
[[ -f "${KEYRING}" ]] && cp -a "${KEYRING}" "${KEYRING}.bak"
if ! curl -fsSL --max-time 60 --retry 3 "${REPO_URL}/public.asc" \
    | gpg --dearmor -o "${KEYRING}"; then
  echo "Failed to fetch the TuxWall signing key (network?)." >&2
  [[ -f "${KEYRING}.bak" ]] && mv -f "${KEYRING}.bak" "${KEYRING}"
  exit 1
fi
rm -f "${KEYRING}.bak"

echo "==> Adding APT source (${LIST})"
echo "deb [signed-by=${KEYRING}] ${REPO_URL} stable main" > "${LIST}"

echo "==> Running apt update"
apt-get update -qq

echo "==> Installing tuxwall"
DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::="--force-confold" tuxwall

echo
echo "tuxwall installed. Dashboard: http://<this-host>/"
echo "Future updates: sudo apt update && sudo apt upgrade tuxwall"
