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
    # Single rolling backup (not one per run — those litter /etc/tuxwall).
    [[ -f /etc/tuxwall/opencode.json ]] && cp -a /etc/tuxwall/opencode.json /etc/tuxwall/opencode.json.bak
    install -m 644 "$CFG_SRC" /etc/tuxwall/opencode.json
fi
# opencode's global config (per-user) wins for provider/model settings, so
# keep it in sync with the tuxwall-managed copy
install -d -m 700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config/opencode"
if [[ -f /etc/tuxwall/opencode.json ]]; then
    install -m 644 -o "$AGENT_USER" -g "$AGENT_USER" \
        /etc/tuxwall/opencode.json "$AGENT_HOME/.config/opencode/opencode.json"
else
    echo "[!] /etc/tuxwall/opencode.json missing and no config source given - skipping agent config sync"
fi

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
# NOTE: Ubuntu 26.04 ships sudo-rs, which rejects wildcards in sudoers
# command arguments — so every allowed invocation is enumerated exactly
# (no `*`). Mirrors the "allow" list in opencode.json permission.bash.
SUDOERS_FILE=/etc/sudoers.d/tuxwall-agent
cat > "$SUDOERS_FILE" <<'EOF'
Cmnd_Alias TUXWALL_SVC = /usr/bin/systemctl status tuxwall, /usr/bin/systemctl status tuxwall-agent, /usr/bin/systemctl status unbound, /usr/bin/systemctl status kea-dhcp4-server, /usr/bin/systemctl status nginx, /usr/bin/systemctl status suricata, /usr/bin/systemctl status crowdsec, /usr/bin/systemctl status crowdsec-firewall-bouncer, /usr/bin/systemctl status systemd-networkd, /usr/bin/systemctl status tuxwall-nat, /usr/bin/systemctl is-active tuxwall, /usr/bin/systemctl is-active tuxwall-agent, /usr/bin/systemctl is-active unbound, /usr/bin/systemctl is-active kea-dhcp4-server, /usr/bin/systemctl is-active nginx, /usr/bin/systemctl is-active suricata, /usr/bin/systemctl is-active crowdsec, /usr/bin/systemctl is-active systemd-networkd
Cmnd_Alias TUXWALL_LOGS = /usr/bin/journalctl -u tuxwall, /usr/bin/journalctl -u tuxwall-agent, /usr/bin/journalctl -u unbound, /usr/bin/journalctl -u kea-dhcp4-server, /usr/bin/journalctl -u nginx, /usr/bin/journalctl -u suricata, /usr/bin/journalctl -u crowdsec, /usr/bin/journalctl -u systemd-networkd, /usr/bin/journalctl --no-pager -u tuxwall, /usr/bin/journalctl --no-pager -u tuxwall-agent, /usr/bin/journalctl --no-pager -u unbound, /usr/bin/journalctl --no-pager -u kea-dhcp4-server, /usr/bin/journalctl --no-pager -u nginx, /usr/bin/journalctl --no-pager -u suricata, /usr/bin/journalctl --no-pager -u crowdsec, /usr/bin/journalctl --no-pager -u systemd-networkd
Cmnd_Alias TUXWALL_NET = /usr/sbin/ufw status, /usr/sbin/ufw status numbered, /usr/sbin/ufw status verbose, /usr/sbin/ip addr, /usr/sbin/ip route, /usr/sbin/ip -s link, /usr/sbin/ip -6 route, /usr/sbin/ip rule, /usr/sbin/ip neigh, /usr/bin/ss, /usr/bin/ss -tulpn, /usr/bin/df, /usr/bin/free, /usr/bin/uptime, /usr/bin/ls /var/log, /usr/bin/ls /var/log/suricata
Cmnd_Alias TUXWALL_SVC_CTL = /usr/sbin/unbound-control status, /usr/sbin/unbound-control stats_noreset, /usr/bin/cscli decisions list, /usr/bin/cscli alerts list, /usr/bin/wg show
# Bounded ops: what the agent may CHANGE (named services + shaping tools +
# tuxwall's own scripts only — no blanket admin). Keeps hand-editing
# sudoers unnecessary for routine gateway work.
Cmnd_Alias TUXWALL_OPS = /usr/bin/systemctl restart tuxwall, /usr/bin/systemctl restart unbound, /usr/bin/systemctl restart kea-dhcp4-server, /usr/bin/systemctl restart nginx, /usr/bin/systemctl restart suricata, /usr/bin/systemctl restart crowdsec, /usr/bin/systemctl restart crowdsec-firewall-bouncer, /usr/bin/systemctl restart systemd-networkd, /usr/bin/systemctl reload tuxwall, /usr/bin/systemctl reload unbound, /usr/bin/systemctl reload kea-dhcp4-server, /usr/bin/systemctl reload nginx, /usr/bin/systemctl reload suricata, /usr/bin/systemctl reload-or-restart kea-dhcp4-server, /usr/bin/systemctl reload-or-restart unbound, /usr/bin/systemctl reload-or-restart nginx, /usr/bin/systemctl daemon-reload, /usr/sbin/tc, /usr/local/bin/speedtest, /usr/local/sbin/tuxwall-sqm.sh, /usr/local/sbin/system-backup.sh
tuxwall-agent ALL=(root) NOPASSWD: TUXWALL_SVC, TUXWALL_LOGS, TUXWALL_NET, TUXWALL_SVC_CTL, TUXWALL_OPS
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
