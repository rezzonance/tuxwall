#!/usr/bin/env bash
###############################################################################
#  TuxWall — opencode AI agent setup
#  ---------------------------------------------------------------------------
#  Provisions the opencode agent that powers the dashboard's AI assistant:
#    1. Dedicated 'tuxwall-agent' system user (owns the web root, can edit it)
#    2. opencode binary (official per-user installer)
#    3. /etc/tuxwall/opencode.json (models + permission allowlist)
#    4. tuxwall-agent.service listening on 127.0.0.1:4096
#    5. Shared auth token between dashboard API and agent (root-only drop-ins)
#    6. Restricted sudo so the agent can run read-only gateway diagnostics
#
#  Idempotent: safe to re-run (existing token/config are preserved).
#
#  Usage:
#    sudo bash setup-opencode-agent.sh [opencode.json] [tuxwall-agent.service]
#
#    opencode.json            source config (default: keep/ship /etc/tuxwall)
#    tuxwall-agent.service    source unit file (default: keep installed one)
###############################################################################
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "[!] Run as root: sudo bash $0"; exit 1; }

AGENT_USER="tuxwall-agent"
AGENT_HOME="/home/$AGENT_USER"
AGENT_BIN="$AGENT_HOME/.opencode/bin/opencode"
CFG_SRC="${1:-}"
UNIT_SRC="${2:-}"

echo "[+] Setting up the TuxWall opencode agent..."

# ── 1. Dedicated agent user ─────────────────────────────────────────────────
if ! id "$AGENT_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$AGENT_USER"
    echo "[+] created user $AGENT_USER"
fi

# ── 2. opencode binary (official installer, per-user) ───────────────────────
if [[ ! -x "$AGENT_BIN" ]]; then
    echo "[+] installing opencode for $AGENT_USER (needs internet)..."
    if ! su -l "$AGENT_USER" -c 'curl -fsSL https://opencode.ai/install | bash'; then
        echo "[!] opencode installer failed — install it manually for $AGENT_USER"
        echo "    see https://opencode.ai/docs — then re-run this script"
        exit 1
    fi
else
    echo "[+] opencode already installed at $AGENT_BIN"
fi

# ── 3. Config (models + permission allowlist) ───────────────────────────────
mkdir -p /etc/tuxwall
if [[ -n "$CFG_SRC" && -f "$CFG_SRC" ]]; then
    [[ -f /etc/tuxwall/opencode.json ]] && cp -a /etc/tuxwall/opencode.json /etc/tuxwall/opencode.json.bak-$(date +%Y%m%d%H%M%S)
    install -m 644 "$CFG_SRC" /etc/tuxwall/opencode.json
fi
# opencode's global config (per-user) wins for provider/model settings, so
# keep it in sync with the tuxwall-managed copy
install -d -m 700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config/opencode"
install -m 644 -o "$AGENT_USER" -g "$AGENT_USER" \
    /etc/tuxwall/opencode.json "$AGENT_HOME/.config/opencode/opencode.json"

# ── 4. systemd unit ─────────────────────────────────────────────────────────
if [[ -n "$UNIT_SRC" && -f "$UNIT_SRC" ]]; then
    install -m 644 "$UNIT_SRC" /etc/systemd/system/tuxwall-agent.service
fi
[[ -f /etc/systemd/system/tuxwall-agent.service ]] || {
    echo "[!] tuxwall-agent.service is missing — pass it as the 2nd argument"
    exit 1
}

# ── 5. Shared auth token (dashboard API <-> agent server) ───────────────────
TOKEN_FILE="/etc/tuxwall/agent-token"
if [[ ! -s "$TOKEN_FILE" ]]; then
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"
AGENT_PW="$(cat "$TOKEN_FILE")"

install -d -m 755 /etc/systemd/system/tuxwall-agent.service.d /etc/systemd/system/tuxwall.service.d
printf '[Service]\nEnvironment=OPENCODE_SERVER_PASSWORD=%s\n' "$AGENT_PW" \
    > /etc/systemd/system/tuxwall-agent.service.d/password.conf
printf '[Service]\nEnvironment=TUXWALL_AGENT_PASSWORD=%s\n' "$AGENT_PW" \
    > /etc/systemd/system/tuxwall.service.d/agent-password.conf
chmod 600 /etc/systemd/system/tuxwall-agent.service.d/password.conf \
          /etc/systemd/system/tuxwall.service.d/agent-password.conf

# ── 6. Web-root ownership: agent edits, nginx (www-data) reads ──────────────
chown -R "$AGENT_USER":www-data /var/www/html
find /var/www/html -type d -exec chmod 775 {} +
find /var/www/html -type f -exec chmod 664 {} +
chmod 755 /var/www/html/includes/api_server.py /var/www/html/scripts/*.sh 2>/dev/null || true

# ── 7. Restricted sudo for read-only gateway diagnostics ────────────────────
# Mirrors the "allow" list in opencode.json permission.bash
SUDOERS_FILE=/etc/sudoers.d/tuxwall-agent
cat > "$SUDOERS_FILE" <<'EOF'
tuxwall-agent ALL=(root) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl is-active *, /usr/bin/journalctl *, /usr/sbin/ufw status*, /usr/sbin/ip *, /usr/bin/ss *, /usr/bin/cat /var/log/*, /usr/bin/tail *, /usr/bin/head *, /usr/bin/grep *, /usr/bin/ls *, /usr/bin/df *, /usr/bin/free *, /usr/bin/uptime, /usr/sbin/unbound-control status, /usr/sbin/unbound-control stats_noreset, /usr/bin/cscli decisions list, /usr/bin/cscli alerts list, /usr/bin/wg show
EOF
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null || { echo "[!] sudoers syntax error — removing"; rm -f "$SUDOERS_FILE"; }

# ── 8. Go ───────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable tuxwall-agent.service >/dev/null 2>&1 || true
systemctl restart tuxwall-agent.service || echo "[!] agent failed to start — check: journalctl -u tuxwall-agent"
systemctl try-restart tuxwall.service >/dev/null 2>&1 || true

echo "[+] opencode agent ready (127.0.0.1:4096)"
echo "    token stored at $TOKEN_FILE (root-only)"
