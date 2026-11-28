#!/usr/bin/env bash
###############################################################################
#  TuxWall — opencode AI agent setup
#  ---------------------------------------------------------------------------
#  Provisions the opencode agent that powers the dashboard's AI assistant:
#    1. Dedicated 'tuxwall-agent' system user
#    2. opencode binary (pinned release, SHA-256 verified)
#    3. /etc/tuxwall/opencode.json (models + permission allowlist)
#    4. tuxwall-agent.service listening on 127.0.0.1:4096
#    5. Shared password between dashboard API and agent: root-only
#       /etc/tuxwall/agent-password.env, loaded by both units (EnvironmentFile=)
#    6. Web root writable by the agent - only with TUXWALL_AGENT_EDIT_WEBROOT=1
#       (tuxwall-install.sh --agent-edit-webroot); by default it stays root's
#    7. Restricted sudo so the agent can run read-only gateway diagnostics
#
#  Shipped in the package (/usr/local/share/tuxwall/scripts/); the postinst
#  runs it when the opencode binary is missing (fresh installs).
#  Idempotent: safe to re-run (existing password/config/unit are preserved, an
#  installed opencode binary is not downloaded again).
#
#  Usage:
#    sudo bash setup-opencode-agent.sh [opencode.json] [tuxwall-agent.service]
#    sudo bash setup-opencode-agent.sh --password-only
#                             only create / repair the shared password (the
#                             postinst moves 3.3.7's Environment= drop-ins)
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

# ── Shared password (dashboard API <-> agent server) ────────────────────────
# 3.3.8: ONE root-only env file (0600) that both units load with
# EnvironmentFile= - systemd reads it as root before the service starts and
# `systemctl show` only names the path. Until 3.3.7 the password sat in
# Environment= drop-ins, which systemd shows to every local user over D-Bus:
# an install that still has them gets a NEW password (the old one was
# readable), the drop-ins are rewritten without it and the old
# /etc/tuxwall/agent-token is removed. Never prints the password.
AGENT_PW_ENV=/etc/tuxwall/agent-password.env
AGENT_PW_DROPIN=/etc/systemd/system/tuxwall-agent.service.d/password.conf
DASH_PW_DROPIN=/etc/systemd/system/tuxwall.service.d/agent-password.conf
AGENT_PW_LEGACY_TOKEN=/etc/tuxwall/agent-token

agent_pw_new() {   # -> 48 random hex characters on stdout
    local pw
    pw="$(openssl rand -hex 24 2>/dev/null)" || pw=""
    [[ $pw =~ ^[0-9a-f]{48}$ ]] || pw="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    [[ $pw =~ ^[0-9a-f]{48}$ ]] || return 1
    printf '%s' "$pw"
}

# agent_pw_dropin_body agent|dashboard [ENV_FILE] -> drop-in text (no secret)
agent_pw_dropin_body() {
    local env=${2:-$AGENT_PW_ENV}
    printf '%s\n' "# TuxWall: the agent password is in $env (root:root 0600)." \
        "# systemd reads it as root before the service starts; \`systemctl show\`" \
        "# names only the file. Written by setup-opencode-agent.sh - never put" \
        "# the password into an Environment= line (readable by every local user)."
    if [[ $1 == agent ]]; then
        printf '%s\n' "# No \"-\": without the file the agent does not start (never unprotected)." \
            "[Service]" "EnvironmentFile=$env"
    else
        printf '%s\n' "# \"-\": the dashboard starts without it (the AI assistant then cannot log in)." \
            "[Service]" "EnvironmentFile=-$env"
    fi
}

agent_pw_write_dropin() {   # agent_pw_write_dropin FILE BODY -> 0 unchanged, 10 written, 1 failed
    local f=$1 body=$2 tmp
    if [[ -f $f && ! -L $f && "$(cat "$f")" == "$body" ]]; then
        chmod 644 "$f" 2>/dev/null || true
        return 0
    fi
    install -d -m 0755 "$(dirname "$f")" || return 1
    tmp="$(mktemp "$f.XXXXXX")" || return 1
    if ! { printf '%s\n' "$body" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$f"; }; then
        rm -f "$tmp"
        return 1
    fi
    return 10
}

# agent_password_setup [ROOT] -> 0 nothing changed, 10 written (restart
# tuxwall-agent + tuxwall), 1 failed. ROOT prefixes every path (tests).
agent_password_setup() {
    local root=${1:-} env drop_a drop_d pw="" a="" b="" legacy=0 changed=0 f tmp r
    env=$root$AGENT_PW_ENV
    drop_a=$root$AGENT_PW_DROPIN
    drop_d=$root$DASH_PW_DROPIN
    for f in "$drop_a" "$drop_d"; do
        if [[ -f $f ]] && grep -Eq '^[[:space:]]*Environment[[:space:]]*=.*(PASSWORD|SECRET|TOKEN|KEY)' "$f"; then
            legacy=1
        fi
    done
    if (( ! legacy )) && [[ -f $env && ! -L $env ]]; then
        a="$(sed -n 's/^OPENCODE_SERVER_PASSWORD=//p' "$env" | head -n 1)"
        b="$(sed -n 's/^TUXWALL_AGENT_PASSWORD=//p' "$env" | head -n 1)"
        [[ $a =~ ^[A-Za-z0-9]{32,}$ && $a == "$b" ]] && pw=$a
    fi
    if [[ -z $pw ]]; then
        pw="$(agent_pw_new)" || return 1
        install -d -m 0755 "$(dirname "$env")" || return 1
        tmp="$(mktemp "$env.XXXXXX")" || return 1
        if ! { chmod 600 "$tmp" \
                && { chown 0:0 "$tmp" 2>/dev/null || (( EUID != 0 )); } \
                && printf '# TuxWall AI agent password (root-only). Loaded by tuxwall-agent.service and\n# tuxwall.service (EnvironmentFile=); written by setup-opencode-agent.sh.\nOPENCODE_SERVER_PASSWORD=%s\nTUXWALL_AGENT_PASSWORD=%s\n' "$pw" "$pw" > "$tmp" \
                && mv -f "$tmp" "$env"; }; then
            rm -f "$tmp"
            return 1
        fi
        changed=1
    fi
    pw=""
    chmod 600 "$env" || return 1
    chown 0:0 "$env" 2>/dev/null || (( EUID != 0 )) || return 1

    r=0; agent_pw_write_dropin "$drop_a" "$(agent_pw_dropin_body agent)" || r=$?
    (( r == 10 )) && changed=1
    (( r == 0 || r == 10 )) || return 1
    r=0; agent_pw_write_dropin "$drop_d" "$(agent_pw_dropin_body dashboard)" || r=$?
    (( r == 10 )) && changed=1
    (( r == 0 || r == 10 )) || return 1

    # the old token file held the same (readable) value on most installs
    rm -f "$root$AGENT_PW_LEGACY_TOKEN"
    if (( changed )); then return 10; fi
    return 0
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

    # ── 5. Shared password (dashboard API <-> agent server) ─────────────────
    local pw_rc=0
    agent_password_setup || pw_rc=$?
    if (( pw_rc != 0 && pw_rc != 10 )); then
        echo "[!] could not write the agent password file $AGENT_PW_ENV"
        exit 1
    fi

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
    echo "    password stored in $AGENT_PW_ENV (root-only)"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ ${1:-} == --password-only ]]; then
        # postinst (3.3.8): move/repair the shared password only.
        # 2nd argument: a root prefix for sandboxed tests.
        [[ $EUID -eq 0 || -n ${2:-} ]] || { echo "[!] Run as root: $SELF_CMD --password-only"; exit 1; }
        pw_rc=0
        agent_password_setup "${2:-}" || pw_rc=$?
        exit "$pw_rc"
    fi
    main "$@"
fi
