#!/usr/bin/env bash
###############################################################################
#  TuxWall — opencode AI agent setup
#  ---------------------------------------------------------------------------
#  Provisions the opencode agent that powers the dashboard's AI assistant:
#    1. Dedicated 'tuxwall-agent' system user
#    2. opencode binary (pinned release, SHA-256 verified)
#    3. /etc/tuxwall/opencode.json (models + permission allowlist)
#    4. tuxwall-agent.service listening on 127.0.0.1:4096
#    5. Shared auth token between dashboard API and agent (root-only drop-ins)
#    6. Web root writable by the agent - only with TUXWALL_AGENT_EDIT_WEBROOT=1
#       (tuxwall-install.sh --agent-edit-webroot); by default it stays root's
#    7. Restricted sudo so the agent can run read-only gateway diagnostics
#
#  Shipped in the package (/usr/local/share/tuxwall/scripts/); the postinst
#  runs it when the opencode binary is missing (fresh installs).
#  Idempotent: safe to re-run (existing token/config/unit are preserved, an
#  installed opencode binary is not downloaded again).
#
#  Usage:
#    sudo bash setup-opencode-agent.sh [opencode.json] [tuxwall-agent.service]
#
#    opencode.json            installed as /etc/tuxwall/opencode.json only
#                             when that file does not exist yet
#    tuxwall-agent.service    installed only when the unit does not exist yet
#
#  Another opencode version (manual update; remove the old binary first):
#    sudo TUXWALL_OPENCODE_VERSION=x.y.z TUXWALL_OPENCODE_SHA256=<sha256 of
#      cli-<target>-x.y.z.tgz> bash setup-opencode-agent.sh
###############################################################################
set -euo pipefail

AGENT_USER="tuxwall-agent"
AGENT_HOME="/home/$AGENT_USER"
AGENT_BIN="$AGENT_HOME/.opencode/bin/opencode"
SELF_CMD="sudo bash /usr/local/share/tuxwall/scripts/setup-opencode-agent.sh"

# ── opencode release pin ────────────────────────────────────────────────────
# The npm registry tarball the official installer (opencode.ai/v2/install)
# downloads, pinned to one version. The SHA-256 of each .tgz is checked
# before anything is unpacked; npm never re-publishes a version, so the
# hashes are stable (they match the registry's sha512 "integrity" values).
OPENCODE_VERSION_PIN="2.1.4"
OPENCODE_REGISTRY="https://registry.npmjs.org"

opencode_pin_sha256() {   # opencode_pin_sha256 TARGET -> sha256 of cli-TARGET-<pin>.tgz
    case "$1" in
        linux-x64)          echo ce05abe2dce1041391c8ec8cdb8da066f640fd471e72ac846dcb089c441e11e1 ;;
        linux-x64-baseline) echo bfcb5c1931063e9835179ef4f1ee35eb3598d23ec77c31f0d5beedb45419fd25 ;;
        linux-arm64)        echo e9acb4e23a9ac432139693aa166455a6add8946533394cbe083459a48e788861 ;;
    esac
}

opencode_target() {   # opencode_target MACHINE [CPUINFO] -> npm target, empty = unsupported
    case "$1" in
        x86_64|amd64)
            # same rule as the official installer: no AVX2 -> baseline build
            if grep -qwi avx2 "${2:-/proc/cpuinfo}" 2>/dev/null; then echo linux-x64
            else echo linux-x64-baseline; fi ;;
        aarch64|arm64) echo linux-arm64 ;;
    esac
}

# opencode_fetch DEST OWNER -> 0 installed, 2 download failed, 3 refused
# (checksum / bad archive / version without hash), 4 unsupported machine
opencode_fetch() {
    local dest=$1 owner=$2 machine target ver sha url tmp got dir grp
    machine="$(uname -m)"
    target="$(opencode_target "$machine")"
    if [[ -z $target ]]; then
        echo "[!] opencode has no Linux build for this machine ($machine) - AI assistant not installed"
        return 4
    fi
    if [[ -n ${TUXWALL_OPENCODE_VERSION:-} ]]; then
        ver=${TUXWALL_OPENCODE_VERSION#v}
        sha=${TUXWALL_OPENCODE_SHA256:-}
        if [[ -z $sha ]]; then
            echo "[!] TUXWALL_OPENCODE_VERSION=$ver needs TUXWALL_OPENCODE_SHA256 (sha256 of cli-$target-$ver.tgz) - refused"
            return 3
        fi
    else
        ver=$OPENCODE_VERSION_PIN
        sha="$(opencode_pin_sha256 "$target")"
    fi
    sha=${sha,,}
    url="$OPENCODE_REGISTRY/@opencode/cli-$target/-/cli-$target-$ver.tgz"
    # (callers test the return code, so set -e is off in here: check each step)
    tmp="$(mktemp -d "${TMPDIR:-/var/tmp}/tuxwall-opencode.XXXXXX")" || return 2
    echo "[+] downloading opencode $ver ($target)..."
    if ! curl -fsSL --retry 2 --connect-timeout 20 -m 900 -o "$tmp/opencode.tgz" "$url"; then
        rm -rf "$tmp"
        echo "[!] could not download opencode $ver from $url (no internet?)"
        return 2
    fi
    got="$(sha256sum "$tmp/opencode.tgz" | awk '{print $1}')"
    if [[ $got != "$sha" ]]; then
        rm -rf "$tmp"
        echo "[!] opencode $ver ($target) checksum mismatch - download refused, nothing installed"
        echo "    expected sha256 $sha"
        echo "    got      sha256 $got"
        return 3
    fi
    if ! tar -xzf "$tmp/opencode.tgz" -C "$tmp" --no-same-owner --no-same-permissions package/bin/opencode \
            || [[ ! -f $tmp/package/bin/opencode || -L $tmp/package/bin/opencode ]]; then
        rm -rf "$tmp"
        echo "[!] opencode $ver archive has no package/bin/opencode - refused"
        return 3
    fi
    dir="$(dirname "$dest")"
    if ! { grp="$(id -gn "$owner")" \
            && { [[ -d $(dirname "$dir") ]] || install -d -m 0755 -o "$owner" -g "$grp" "$(dirname "$dir")"; } \
            && { [[ -d $dir ]] || install -d -m 0755 -o "$owner" -g "$grp" "$dir"; } \
            && install -m 0755 -o "$owner" -g "$grp" "$tmp/package/bin/opencode" "$dest.new" \
            && mv -f "$dest.new" "$dest"; }; then
        rm -rf "$tmp"
        rm -f "$dest.new"
        echo "[!] could not install opencode into $dir"
        return 2
    fi
    rm -rf "$tmp"
    echo "[+] installed opencode $ver at $dest (sha256 verified)"
    return 0
}

# ensure_opencode DEST OWNER -> 0 when the binary is there (never re-downloads)
ensure_opencode() {
    local dest=$1 owner=$2 rc=0
    if [[ -x $dest ]]; then
        echo "[+] opencode already installed at $dest"
        return 0
    fi
    opencode_fetch "$dest" "$owner" || rc=$?
    case $rc in
        0) ;;
        4) echo "[!] AI assistant not available here. The dashboard works without it." ;;
        3) echo "[!] AI assistant not installed (download refused). The dashboard works without it;"
           echo "    try again later with:"
           echo "      $SELF_CMD" ;;
        *) echo "[!] AI assistant not installed. The dashboard works without it; once this"
           echo "    machine is online, install it with:"
           echo "      $SELF_CMD" ;;
    esac
    return "$rc"
}

main() {
    [[ $EUID -eq 0 ]] || { echo "[!] Run as root: $SELF_CMD"; exit 1; }
    local cfg_src="${1:-}" unit_src="${2:-}" rc=0

    echo "[+] Setting up the TuxWall opencode agent..."

    # ── 1. Dedicated agent user ─────────────────────────────────────────────
    if ! id "$AGENT_USER" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$AGENT_USER"
        echo "[+] created user $AGENT_USER"
    fi

    # ── 2. opencode binary (pinned, verified) ───────────────────────────────
    ensure_opencode "$AGENT_BIN" "$AGENT_USER" || rc=$?
    (( rc == 0 )) || exit "$rc"

    # ── 3. Config (models + permission allowlist) ───────────────────────────
    # Never replaces an existing /etc/tuxwall/opencode.json (package conffile,
    # edited from the dashboard).
    mkdir -p /etc/tuxwall
    if [[ -n "$cfg_src" && -f "$cfg_src" && ! -e /etc/tuxwall/opencode.json ]]; then
        install -m 644 "$cfg_src" /etc/tuxwall/opencode.json
    fi
    # opencode's global config (per-user) wins for provider/model settings, so
    # keep it in sync with the tuxwall-managed copy
    [[ -d $AGENT_HOME/.config ]] || install -d -m 755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config"
    install -d -m 700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config/opencode"
    if [[ -f /etc/tuxwall/opencode.json ]]; then
        install -m 644 -o "$AGENT_USER" -g "$AGENT_USER" \
            /etc/tuxwall/opencode.json "$AGENT_HOME/.config/opencode/opencode.json"
    else
        echo "[!] /etc/tuxwall/opencode.json missing and no config source given - skipping agent config sync"
    fi

    # ── 4. systemd unit (installed only when absent) ────────────────────────
    if [[ -n "$unit_src" && -f "$unit_src" && ! -e /etc/systemd/system/tuxwall-agent.service ]]; then
        install -m 644 "$unit_src" /etc/systemd/system/tuxwall-agent.service
    fi
    [[ -f /etc/systemd/system/tuxwall-agent.service ]] || {
        echo "[!] tuxwall-agent.service is missing — pass it as the 2nd argument"
        exit 1
    }

    # ── 5. Shared auth token (dashboard API <-> agent server) ───────────────
    local token_file="/etc/tuxwall/agent-token" agent_pw
    if [[ ! -s "$token_file" ]]; then
        ( umask 077; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$token_file" )
    fi
    chmod 600 "$token_file"
    agent_pw="$(cat "$token_file")"

    install -d -m 755 /etc/systemd/system/tuxwall-agent.service.d /etc/systemd/system/tuxwall.service.d
    ( umask 077
      printf '[Service]\nEnvironment=OPENCODE_SERVER_PASSWORD=%s\n' "$agent_pw" \
          > /etc/systemd/system/tuxwall-agent.service.d/password.conf
      printf '[Service]\nEnvironment=TUXWALL_AGENT_PASSWORD=%s\n' "$agent_pw" \
          > /etc/systemd/system/tuxwall.service.d/agent-password.conf )
    chmod 600 /etc/systemd/system/tuxwall-agent.service.d/password.conf \
              /etc/systemd/system/tuxwall.service.d/agent-password.conf

    # ── 6. Web root: root-owned unless explicitly opted in ──────────────────
    # The installer's default (and every apt install) keeps the dashboard
    # code root-owned and read-only to the agent; --agent-edit-webroot passes
    # TUXWALL_AGENT_EDIT_WEBROOT=1 for the legacy agent-writable assets.
    if [[ ${TUXWALL_AGENT_EDIT_WEBROOT:-0} == 1 && -d /var/www/html ]]; then
        chown -R "$AGENT_USER":www-data /var/www/html
        # 2026-11-09 audit: api_server.py RUNS AS ROOT from this tree. Directory
        # write access = unlink-and-replace = root code execution on next
        # restart. The agent gets the dashboard ASSETS, never the code dirs.
        chown -R root:root /var/www/html/includes
        chmod 755 /var/www/html/includes
        chmod 644 /var/www/html/includes/*.py 2>/dev/null || true
        find /var/www/html -type d -exec chmod 775 {} +
        find /var/www/html -type f -exec chmod 664 {} +
        chmod 755 /var/www/html/includes/api_server.py /var/www/html/scripts/*.sh 2>/dev/null || true
    fi

    # ── 7. Restricted sudo for read-only gateway diagnostics ────────────────
    # NOTE: Ubuntu 26.04 ships sudo-rs, which rejects wildcards in sudoers
    # command arguments — so every allowed invocation is enumerated exactly
    # (no `*`). Mirrors the shell "allow" rules in opencode.json `permissions`.
    local sudoers_file=/etc/sudoers.d/tuxwall-agent
    cat > "$sudoers_file" <<'EOF'
Cmnd_Alias TUXWALL_SVC = /usr/bin/systemctl status tuxwall, /usr/bin/systemctl status tuxwall-agent, /usr/bin/systemctl status unbound, /usr/bin/systemctl status kea-dhcp4-server, /usr/bin/systemctl status nginx, /usr/bin/systemctl status suricata, /usr/bin/systemctl status crowdsec, /usr/bin/systemctl status crowdsec-firewall-bouncer, /usr/bin/systemctl status systemd-networkd, /usr/bin/systemctl status tuxwall-nat, /usr/bin/systemctl is-active tuxwall, /usr/bin/systemctl is-active tuxwall-agent, /usr/bin/systemctl is-active unbound, /usr/bin/systemctl is-active kea-dhcp4-server, /usr/bin/systemctl is-active nginx, /usr/bin/systemctl is-active suricata, /usr/bin/systemctl is-active crowdsec, /usr/bin/systemctl is-active systemd-networkd
Cmnd_Alias TUXWALL_LOGS = /usr/bin/journalctl -u tuxwall, /usr/bin/journalctl -u tuxwall-agent, /usr/bin/journalctl -u unbound, /usr/bin/journalctl -u kea-dhcp4-server, /usr/bin/journalctl -u nginx, /usr/bin/journalctl -u suricata, /usr/bin/journalctl -u crowdsec, /usr/bin/journalctl -u systemd-networkd, /usr/bin/journalctl --no-pager -u tuxwall, /usr/bin/journalctl --no-pager -u tuxwall-agent, /usr/bin/journalctl --no-pager -u unbound, /usr/bin/journalctl --no-pager -u kea-dhcp4-server, /usr/bin/journalctl --no-pager -u nginx, /usr/bin/journalctl --no-pager -u suricata, /usr/bin/journalctl --no-pager -u crowdsec, /usr/bin/journalctl --no-pager -u systemd-networkd
Cmnd_Alias TUXWALL_NET = /usr/sbin/ufw status, /usr/sbin/ufw status numbered, /usr/sbin/ufw status verbose, /usr/sbin/ip addr, /usr/sbin/ip route, /usr/sbin/ip -s link, /usr/sbin/ip -6 route, /usr/sbin/ip rule, /usr/sbin/ip neigh, /usr/bin/ss, /usr/bin/ss -tulpn, /usr/bin/df, /usr/bin/free, /usr/bin/uptime, /usr/bin/ls /var/log, /usr/bin/ls /var/log/suricata
Cmnd_Alias TUXWALL_SVC_CTL = /usr/sbin/unbound-control status, /usr/sbin/unbound-control stats_noreset, /usr/bin/cscli decisions list, /usr/bin/cscli alerts list, /usr/bin/wg show
# Bounded ops: what the agent may CHANGE (named services + shaping tools +
# tuxwall's own scripts only — no blanket admin). Keeps hand-editing
# sudoers unnecessary for routine gateway work.
Cmnd_Alias TUXWALL_OPS = /usr/bin/systemctl restart tuxwall, /usr/bin/systemctl restart unbound, /usr/bin/systemctl restart kea-dhcp4-server, /usr/bin/systemctl restart nginx, /usr/bin/systemctl restart suricata, /usr/bin/systemctl restart crowdsec, /usr/bin/systemctl restart crowdsec-firewall-bouncer, /usr/bin/systemctl restart systemd-networkd, /usr/bin/systemctl reload tuxwall, /usr/bin/systemctl reload unbound, /usr/bin/systemctl reload kea-dhcp4-server, /usr/bin/systemctl reload nginx, /usr/bin/systemctl reload suricata, /usr/bin/systemctl reload-or-restart kea-dhcp4-server, /usr/bin/systemctl reload-or-restart unbound, /usr/bin/systemctl reload-or-restart nginx, /usr/bin/systemctl daemon-reload, /usr/local/bin/speedtest, /usr/local/sbin/tuxwall-sqm.sh
tuxwall-agent ALL=(root) NOPASSWD: TUXWALL_SVC, TUXWALL_LOGS, TUXWALL_NET, TUXWALL_SVC_CTL, TUXWALL_OPS
EOF
    chmod 440 "$sudoers_file"
    visudo -cf "$sudoers_file" >/dev/null || { echo "[!] sudoers syntax error — removing"; rm -f "$sudoers_file"; }

    # ── 8. Go ───────────────────────────────────────────────────────────────
    systemctl daemon-reload
    systemctl enable tuxwall-agent.service >/dev/null 2>&1 || true
    systemctl restart tuxwall-agent.service || echo "[!] agent failed to start — check: journalctl -u tuxwall-agent"
    systemctl try-restart tuxwall.service >/dev/null 2>&1 || true

    echo "[+] opencode agent ready (127.0.0.1:4096)"
    echo "    token stored at $token_file (root-only)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
