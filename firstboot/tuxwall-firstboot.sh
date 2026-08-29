#!/usr/bin/env bash
###############################################################################
#  TuxWall First-Boot Wizard
#  -------------------------------------------------------------
#  Runs once on first boot of a TuxWall appliance. Detects interfaces,
#  prompts for WAN/LAN selection, writes the netplan / Kea / radvd / unbound /
#  suricata / crowdsec / ufw configs, sets up NAT+forwarding, installs the
#  TuxWall gateway stack, and enables all systemd services.
#
#  Written for Ubuntu 26.04 LTS (target base for the TuxWall appliance ISO).
#
#  Usage:
#    sudo bash tuxwall-firstboot.sh            # interactive wizard
#    sudo bash tuxwall-firstboot.sh --wan enp2s0 --lan enp3s0 [--dry-run]
#    sudo bash tuxwall-firstboot.sh --dry-run  # show actions, change nothing
###############################################################################
set -euo pipefail

STAGE_DIR="/opt/tuxwall-appliance"
STAGE_DEB="$STAGE_DIR/tuxwall.deb"
STAGE_REPO="$STAGE_DIR/repo"

DRY_RUN=0
WAN=""
LAN=""
LAN_SUBNET="192.168.1.0/24"
LAN_STATIC_IP="192.168.1.1"
LAN_GATEWAY_IP="192.168.1.1"
DOMAIN="localdomain"
INSTALLED_MARK="/etc/tuxwall/.appliance-configured"

# ── Colours ─────────────────────────────────────────────────────────────────
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'  C='\033[0;36m'
B='\033[1m'     DIM='\033[2m'   NC='\033[0m'
log()  { echo -e "${G}[+]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[x]${NC} $*" >&2; }
hr()   { echo -e "${DIM}$(printf '%.0s=' {1..60})${NC}"; }

# ── Run a command, respecting --dry-run ─────────────────────────────────────
run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "${DIM}  (dry-run) would run:${NC} $*"
    else
        "$@"
    fi
}

# ── Enumerate physical network interfaces ───────────────────────────────────
detect_interfaces() {
    # Returns only real (physical / usb / virtio) interfaces, excluding lo.
    ip -o link show 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | grep -Ev '^(lo)$' \
        | sort
}

# ── Interactive numbered selection prompt ───────────────────────────────────
pick_interface() {
    local PROMPT="$1" SKIP="$2"
    local ifaces=()
    local i name

    mapfile -t ifaces < <(detect_interfaces)

    # Filter out the interface already chosen for the other side
    local filtered=()
    for name in "${ifaces[@]}"; do
        [[ "$name" == "$SKIP" ]] && continue
        filtered+=("$name")
    done
    ifaces=("${filtered[@]}")

    if [[ ${#ifaces[@]} -eq 0 ]]; then
        err "No available interfaces (other than '$SKIP')."
        return 1
    fi

    echo -e "\n${B}${PROMPT}${NC}"
    echo "  Available interfaces:"
    for i in "${!ifaces[@]}"; do
        local idx=$(( i + 1 ))
        local mac state carrier
        mac=$(ip -o link show "${ifaces[$i]}" 2>/dev/null | awk '{print $NF}')
        state=$(ip -o link show "${ifaces[$i]}" 2>/dev/null | grep -o 'state [A-Z]*' | awk '{print $2}')
        carrier=$(cat "/sys/class/net/${ifaces[$i]}/carrier" 2>/dev/null && echo " (LINK/UP)" || echo "")
        printf "  ${C}%2d)${NC} %-12s ${DIM}%s  %s${carrier}${NC}\n" "$idx" "${ifaces[$i]}" "$mac" "$state"
    done
    echo -e "  ${C} 0)${NC} Exit setup (abort, keep current system as-is)"
    echo

    local choice
    while true; do
        read -rp "  Enter number (1-${#ifaces[@]}, 0 to exit): " choice
        # Allow 0, q, Q, or x to abort cleanly.
        if [[ "$choice" == "0" || "$choice" =~ ^[qQxX]$ ]]; then
            echo -e "\n${DIM}Exiting first-boot setup. No changes were applied.${NC}"
            echo -e "${DIM}Re-run later with: sudo /opt/tuxwall-appliance/tuxwall-firstboot.sh${NC}"
            echo -e "${DIM}(Autologin stays active until setup completes or a marker is set.)${NC}"
            ABORT=1
            return 1
        fi
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#ifaces[@]} )); then
            WAN_SEL="${ifaces[$(( choice - 1 ))]}"
            return 0
        fi
        warn "Invalid selection."
    done
}

# ── Convert a /24 subnet to a static IP in that subnet (host .1) ────────────
derive_ips() {
    # Given 192.168.5.0/24 -> static 192.168.5.1, prefix 24
    local base="${LAN_SUBNET%/*}"
    local prefix="${LAN_SUBNET#*/}"
    LAN_PREFIX="$prefix"
    # Replace the last octet of the base with .1
    LAN_STATIC_IP="$(echo "$base" | awk -F. '{print $1"."$2"."$3".1"}')"
    LAN_GATEWAY_IP="$LAN_STATIC_IP"
    # IPv6 ULA derived roughly from subnet for radvd, stable enough for a gateway
    LAN_PREFIX6="fd$(printf '%02x' $(( ${base//./} % 256 )))"
}

# ── Disable services that conflict with the TuxWall gateway stack ───────────
# Mirrors the known-good guidance in the tuxwall README:
#   - systemd-resolved binds port 53, conflicting with unbound
#   - standalone DHCPv6 clients fight systemd-networkd for UDP port 546
disable_conflicting_services() {
    log "Disabling conflicting services (resolved + DHCPv6 clients)"

    local RESOLVED_SVCS=(
        systemd-resolved
        systemd-resolved-varlink.socket
        systemd-resolved-monitor.socket
    )
    # Standalone DHCPv6 clients that conflict with systemd-networkd on :546
    local DHCPV6_SVCS=(
        wide-dhcpv6-client
        dibbler-client
        isc-dhcp6-client
        kea-dhcp6-server
    )

    for svc in "${RESOLVED_SVCS[@]}"; do
        [[ $DRY_RUN -eq 0 ]] && systemctl disable --now "$svc" 2>/dev/null || true
        [[ $DRY_RUN -eq 1 ]] && echo -e "${DIM}  (dry-run) systemctl disable --now $svc${NC}"
    done

    # Only disable a standalone DHCPv6 client if it is actually enabled AND
    # another process is bound to UDP port 546 (i.e. we keep systemd-networkd).
    check_dhcpv6_conflict() {
        [[ $DRY_RUN -eq 0 ]] || return 0
        ss -ulnp 2>/dev/null | grep -q ':546 ' && return 0 || return 1
    }
    if check_dhcpv6_conflict; then
        warn "UDP 546 (DHCPv6) conflict detected - disabling standalone DHCPv6 clients"
        for svc in "${DHCPV6_SVCS[@]}"; do
            [[ $DRY_RUN -eq 0 ]] && systemctl disable --now "$svc" 2>/dev/null || true
            [[ $DRY_RUN -eq 1 ]] && echo -e "${DIM}  (dry-run) systemctl disable --now $svc${NC}"
        done
    fi
}

# ── Replace /etc/resolv.conf with a static pointer to local unbound ────────
set_resolv_conf() {
    log "Replacing /etc/resolv.conf to point at local unbound"
    if [[ $DRY_RUN -eq 0 ]]; then
        rm -f /etc/resolv.conf
        printf 'nameserver 127.0.0.1\nnameserver ::1\nsearch %s\n' "$DOMAIN" > /etc/resolv.conf
    else
        echo -e "${DIM}  (dry-run) rewrite /etc/resolv.conf (nameserver 127.0.0.1 / ::1, search $DOMAIN)${NC}"
    fi
}

# ── Write netplan configuration ─────────────────────────────────────────────
config_netplan() {
    local NETPLAN="/etc/netplan/99-tuxwall.yaml"
    log "Writing netplan: $NETPLAN"
    log "  WAN=$WAN (DHCP)   LAN=$LAN (static $LAN_STATIC_IP/$LAN_PREFIX)"

    local TMP="$(mktemp)"
    cat > "$TMP" <<NETPLAN
# Generated by TuxWall first-boot wizard
network:
  version: 2
  ethernets:
    $WAN:
      dhcp4: true
      dhcp6: true
      # accept-ra handled by radvd; do not run a conflicting DHCPv6 client
      dhcp6-overrides:
        use-ntp: false
    $LAN:
      dhcp4: false
      addresses:
        - $LAN_STATIC_IP/$LAN_PREFIX
      # optional IPv6 ULA address
      # - $LAN_PREFIX6::1/64
      routes:
        - to: 0.0.0.0/0
          via: $(default_route_via)
          metric: 100
      nameservers:
        addresses: [127.0.0.1, ::1]
        search: [$DOMAIN]
NETPLAN

    install_file "$TMP" "$NETPLAN" 600
    rm -f "$TMP"
}

default_route_via() {
    ip route show default 2>/dev/null | awk '/default/ {print $3; exit}' || echo ""
}

install_file() {
    local SRC="$1" DST="$2" MODE="${3:-644}"
    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "${DIM}  (dry-run) would write:${NC} $DST"
        return 0
    fi
    install -m "$MODE" "$SRC" "$DST"
}

# ── Write Kea DHCP server config ────────────────────────────────────────────
config_kea() {
    local KEA="/etc/kea/kea-dhcp4.conf"
    local pool_base="${LAN_SUBNET%/*}"
    # pool host .100 - .199
    local pool_low="$(echo "$pool_base" | awk -F. '{print $1"."$2"."$3".100"}')"
    local pool_high="$(echo "$pool_base" | awk -F. '{print $1"."$2"."$3".199"}')"

    log "Writing Kea DHCP config: $KEA  (pool $pool_low - $pool_high)"

    local TMP="$(mktemp)"
    cat > "$TMP" <<KEA
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$LAN" ]
    },
    "valid-lifetime": 7200,
    "renew-timer": 3600,
    "rebind-timer": 6300,
    "lease-database": {
      "type": "memfile",
      "lfc-interval": 3600,
      "persist": true,
      "name": "/var/lib/kea/dhcp4.leases"
    },
    "subnet4": [
      {
        "subnet": "$LAN_SUBNET",
        "pools": [ { "pool": "$pool_low - $pool_high" } ],
        "option-data": [
          { "name": "domain-name-servers", "data": "$LAN_STATIC_IP, ::1" },
          { "name": "domain-name", "data": "$DOMAIN" },
          { "name": "routers", "data": "$LAN_GATEWAY_IP" },
          { "name": "subnet-mask", "data": "$(mask_from_prefix $LAN_PREFIX)" }
        ]
      }
    ],
    "loggers": [
      { "name": "kea-dhcp4", "output_options": [ { "output": "syslog" } ], "severity": "INFO" }
    ]
  }
}
KEA

    install_file "$TMP" "$KEA" 640
    rm -f "$TMP"
}

mask_from_prefix() {
    local p="$1" n=0 i
    for (( i=0; i<32; i++ )); do (( i < p )) && n=$(( n | (1 << (31 - i)) )); done
    echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))"
}

# ── Write radvd (IPv6 router advertisement) config ──────────────────────────
config_radvd() {
    local RADVD="/etc/radvd.conf"
    log "Writing radvd config: $RADVD"
    # Guard: radvd hard-fails to start if fields are empty or if RDNSS gets an
    # IPv4 address. We advertise a ULA derived from the LAN subnet and point
    # RDNSS at the gateway's ULA address (valid IPv6), not the LAN IPv4.
    if [[ -z "${LAN:-}" || -z "${LAN_PREFIX6:-}" ]]; then
        err "config_radvd: LAN or LAN_PREFIX6 is empty - aborting config write."
        return 1
    fi
    # AAAA record advertised in unbound uses ::1; use the ULA host address for
    # radvd's own advertisement so RDNSS is a real IPv6 address.
    local ULA_ADDR="${LAN_PREFIX6}::1"
    local TMP="$(mktemp)"
    cat > "$TMP" <<RADVD
interface $LAN
{
    AdvSendAdvert on;
    MinRtrAdvInterval 30;
    MaxRtrAdvInterval 100;
    AdvManagedFlag off;
    AdvOtherConfigFlag off;
    prefix $LAN_PREFIX6::/64
    {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };
    RDNSS $ULA_ADDR { };
};
RADVD
    install_file "$TMP" "$RADVD" 644
    rm -f "$TMP"
}

# ── Configure Unbound local zone for the gateway ────────────────────────────
config_unbound() {
    local UNBOUND_DOM="/etc/unbound/unbound.conf.d/98-tuxwall-domains.conf"
    local UNBOUND_LST="/etc/unbound/unbound.conf.d/99-tuxwall-listen.conf"
    log "Writing Unbound local domain: $UNBOUND_DOM"

    # Guard: never emit a broken config from empty variables (that produced
    # the real-world `local-data-ptr: " gateway.."` failure: unbound would not
    # start, and unbound-resolvconf would fail).
    if [[ -z "${LAN_STATIC_IP:-}" || -z "${DOMAIN:-}" ]]; then
        err "config_unbound: LAN_STATIC_IP or DOMAIN is empty - aborting config write."
        return 1
    fi

    local TMP="$(mktemp)"
    cat > "$TMP" <<UNB
server:
    local-zone: "$DOMAIN" static
    local-data: "gateway.$DOMAIN. IN A $LAN_STATIC_IP"
    local-data: "gateway.$DOMAIN. IN AAAA ::1"
    local-data-ptr: "$LAN_STATIC_IP gateway.$DOMAIN."
UNB
    install_file "$TMP" "$UNBOUND_DOM" 644
    rm -f "$TMP"

    # Listen on all interfaces for both IPv4 and IPv6 (README: unbound must
    # bind 0.0.0.0 and ::0 or DNS fails for IPv6 clients).
    local TMP2="$(mktemp)"
    cat > "$TMP2" <<UNB2
server:
    interface: 0.0.0.0
    interface: ::0
    interface-automatic: yes
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    access-control: $LAN_SUBNET allow
    do-ip6: yes
    prefer-ip6: yes
UNB2
    install_file "$TMP2" "$UNBOUND_LST" 644
    rm -f "$TMP2"
}

# ── Ensure unbound's DNSSEC root trust anchor exists ────────────────────────
# unbound's default config uses `auto-trust-anchor-file` pointing at
# /var/lib/unbound/root.key. On a fresh install that file is absent unless
# dns-root-data is present or unbound-anchor has fetched it, and unbound
# refuses to start ("root.key: No such file or directory"). Create it first.
setup_unbound_rootkey() {
    log "Ensuring unbound DNSSEC root trust anchor (root.key)..."
    mkdir -p /var/lib/unbound /etc/unbound

    if [[ -f /var/lib/unbound/root.key ]]; then
        log "  root.key already present."
        return 0
    fi

    # 1. Prefer Ubuntu's dns-root-data copy (offline, no network needed).
    if [[ -f /usr/share/dns/root.key ]]; then
        cp /usr/share/dns/root.key /var/lib/unbound/root.key
        log "  Installed root.key from dns-root-data."
    # 2. Otherwise fetch/refresh via unbound-anchor (needs network).
    elif command -v unbound-anchor >/dev/null 2>&1; then
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null \
            && log "  Generated root.key via unbound-anchor." \
            || warn "  unbound-anchor could not create root.key (network?)."
    else
        warn "  No way to obtain root.key (install dns-root-data). unbound may fail."
    fi

    if [[ -f /var/lib/unbound/root.key ]]; then
        chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
        chmod 640 /var/lib/unbound/root.key 2>/dev/null || true
    fi
}

# ── Configure Suricata to run on the WAN interface ──────────────────────────
config_suricata() {
    local SURICATA="/etc/suricata/suricata.yaml"
    # Suricata runs in IDS (monitor) mode on WAN by default.
    # The block below rewrites the HOME_NET to the LAN subnet.
    if [[ -f "$SURICATA" ]]; then
        log "Tuning Suricata HOME_NET for LAN subnet"
        if [[ $DRY_RUN -eq 0 ]]; then
            sed -i "s|HOME_NET: \"\[.*\]\"|HOME_NET: \"[$LAN_SUBNET]\"|" "$SURICATA" 2>/dev/null || true
        else
            echo -e "${DIM}  (dry-run) sed HOME_NET in $SURICATA${NC}"
        fi
    else
        warn "Suricata config not found at $SURICATA"
    fi
}

# ── Configure UFW: NAT + forwarding + allow services ────────────────────────
config_ufw() {
    log "Configuring UFW default forwarding policy + NAT"

    if [[ $DRY_RUN -eq 0 ]]; then
        sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
        # Enable UFW IPv6 support (README: required so the v6 firewall is active)
        sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
        # Enable IP forwarding inside ufw
        grep -q '^net/ipv4/ip_forward' /etc/ufw/sysctl.conf \
            || echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
        grep -q '^net/ipv6/conf/all/forwarding' /etc/ufw/sysctl.conf \
            || echo 'net/ipv6/conf/all/forwarding=1' >> /etc/ufw/sysctl.conf

        # NAT masquerade rule for WAN
        local NAT_RULE="/etc/ufw/before.rules"
        if ! grep -q '^\*nat' "$NAT_RULE"; then
            sed -i '1i\
*nat\
:POSTROUTING ACCEPT [0:0]\
-A POSTROUTING -o '"$WAN"' -j MASQUERADE\
COMMIT\
' "$NAT_RULE"
        fi

        ufw allow 80/tcp comment 'TuxWall dashboard' 2>/dev/null || true
        ufw allow 51820/udp comment 'WireGuard' 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
        ufw reload 2>/dev/null || true
    else
        echo -e "${DIM}  (dry-run) UFW: forwarding ACCEPT, NAT masquerade on $WAN, allow 80/51820, enable${NC}"
    fi
}

# ── Install the TuxWall stack (packages + deb + service layout) ─────────────
# Wait until we have a default route + a working resolver before apt, so a
# fresh install (no networking yet at wizard start) doesn't abort mid-setup.
# If a physical default route exists but DNS still fails (the classic
# systemd-resolved-not-up / stale-resolv.conf trap), repair the resolver so
# apt can actually reach the archives.
wait_for_network() {
    local i
    log "Waiting for network connectivity before installing packages..."
    for i in $(seq 1 15); do
        if ip route show default >/dev/null 2>&1 && \
           getent hosts archive.ubuntu.com >/dev/null 2>&1; then
            log "Network is up (default route + DNS resolved)."
            return 0
        fi
        sleep 2
    done

    # We have a link but resolution may still be broken. Try to repair DNS.
    if ip route show default >/dev/null 2>&1; then
        log "Default route present but DNS not resolving - attempting resolver repair..."
        # Point resolv.conf at a public resolver so apt can work regardless of
        # resolved/unbound state (the gateway will reconfigure DNS properly later).
        if [[ $(command -v systemctl >/dev/null 2>&1 && systemctl is-system-running 2>/dev/null || true) != "" ]] \
           && command -v systemd-resolve >/dev/null 2>&1; then
            systemctl enable --now systemd-resolved 2>/dev/null || true
            resolvectl flush-caches 2>/dev/null || true
        fi
        grep -qi "nameserver" /etc/resolv.conf 2>/dev/null || {
            printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
            log "  Set fallback resolvers in /etc/resolv.conf."
        }
        if getent hosts archive.ubuntu.com >/dev/null 2>&1; then
            log "DNS restored."
            return 0
        fi
    fi
    warn "Network not ready after 30s - continuing anyway (apt may fail)."
    return 0
}

install_tuxwall_stack() {
    # Package list from tuxwall setup.sh, adapted for 26.04.
    # NOTE: crowdsec + its firewall bouncer come from the CrowdSec packagecloud
    # repo (not the stock Ubuntu archive), so we add that repo first.
    local PKGS=(
        ufw iptables nftables iproute2
        kea-dhcp4-server kea-common
        unbound unbound-anchor dns-root-data
        radvd
        wireguard wireguard-tools
        suricata suricata-update
        crowdsec crowdsec-firewall-bouncer-nftables
        nginx
        python3 curl jq gzip ca-certificates ieee-data
    )

    if [[ $DRY_RUN -eq 1 ]]; then
        echo -e "${DIM}  (dry-run) add CrowdSec repo + apt-get install -y ${PKGS[*]}${NC}"
        return 0
    fi

    export DEBIAN_FRONTEND=noninteractive

    # Ensure curl + gpg are present (needed to add the CrowdSec repo below).
    # Both come from the stock archive, so this works before any extra repos.
    if ! command -v curl >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        log "Installing prerequisites (curl + gpg)..."
        apt-get update -qq 2>/dev/null || true
        apt-get install -y --no-install-recommends curl gnupg 2>/dev/null || true
    fi

    # ── CrowdSec repo (packagecloud) ──────────────────────────────────────
    # crowdsec* is not in the stock Ubuntu archive; setup.sh relies on the
    # CrowdSec packagecloud repo. Add it idempotently, RETRYING the GPG key
    # fetch (network/DNS may not be ready yet) and failing loudly if the key
    # never lands - otherwise apt rejects the repo as unsigned.
    if ! command -v crowdsec >/dev/null 2>&1; then
        KEYRING=/usr/share/keyrings/crowdsec-archive-keyring.gpg
        SOURCES=/etc/apt/sources.list.d/crowdsec.list
        log "Adding CrowdSec packagecloud repo..."
        if grep -rq "packagecloud.io/crowdsec" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
            log "  CrowdSec repo already present."
        else
            # Retry the key fetch (and ensure /etc/resolv.conf resolves) until
            # it works, up to ~2 minutes. A failing DNS at first-boot (resolver
            # not yet configured) is the #1 cause of an unsigned-repo failure.
            local key_ok=0 try
            for try in 1 2 3 4 5 6; do
                if curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey 2>/dev/null \
                    | gpg --dearmor > "$KEYRING" 2>/dev/null \
                    && [[ -s "$KEYRING" ]] \
                    && gpg --no-default-keyring --keyring "$KEYRING" --list-keys >/dev/null 2>&1; then
                    key_ok=1
                    break
                fi
                warn "  Retrying CrowdSec key fetch (attempt $try)..."
                sleep 10
            done

            if [[ $key_ok -eq 1 ]]; then
                printf 'deb [signed-by=%s] https://packagecloud.io/crowdsec/crowdsec/any any main\n' "$KEYRING" \
                    > "$SOURCES"
                log "  CrowdSec repo added + key verified."
            else
                err "Could not fetch/verify the CrowdSec GPG key after several tries."
                err "Check DNS/network, then re-run this wizard. crowdsec will be missing."
            fi
        fi
    else
        log "crowdsec already installed - skipping repo setup."
    fi

    log "Installing dependency packages..."
    if ! apt-get update -qq; then
        warn "apt-get update failed (network). Retrying once after a wait..."
        sleep 10
        apt-get update -qq || warn "apt-get update failed again - unknown packages will fail."
    fi
    if ! apt-get install -y --no-install-recommends "${PKGS[@]}"; then
        # Surface the real failure (log captures it) instead of hiding it.
        log "Package install reported an error. Attempting to recover missing pieces:"
        apt-get install -y "${PKGS[@]}" 2>&1 | tail -n 20
        warn "Some packages failed to install (see the output above for which)."
    fi
}

# ── Apply all the pieces (the "first boot" body) ────────────────────────────
run_firstboot() {
    hr
    log "TuxWall appliance first-boot configuration"
    hr

    # 1. Install packages if this is a fresh base (skip if already present)
    wait_for_network
    if [[ $(detect_interfaces) != "" ]] && ! command -v unbound >/dev/null 2>&1; then
        install_tuxwall_stack || warn "Package install failed - continuing with what's available."
    fi

    # 2. Disable conflicting services (resolved on :53, DHCPv6 clients on :546)
    disable_conflicting_services
    set_resolv_conf

    # 3. IP forwarding
    log "Enabling IPv4/IPv6 forwarding"
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /etc/sysctl.d
        printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' \
            > /etc/sysctl.d/99-tuxwall-forwarding.conf
        sysctl --system -q 2>/dev/null || true
    fi

    # 4. Write per-service configs
    config_netplan
    config_kea
    config_radvd
    config_unbound
    setup_unbound_rootkey
    config_suricata
    config_ufw

    # 5. Install the .deb if present in the stage dir
    if [[ -f "$STAGE_DEB" ]]; then
        log "Installing TuxWall package: $STAGE_DEB"
        if [[ $DRY_RUN -eq 0 ]]; then
            dpkg -i "$STAGE_DEB" 2>/dev/null || apt-get install -f -y 2>/dev/null || true
        else
            echo -e "${DIM}  (dry-run) dpkg -i $STAGE_DEB${NC}"
        fi
    else
        warn "No tuxwall .deb found at $STAGE_DEB — skipping package install."
    fi

    # 6. Apply repo configs (nginx, systemd, scripts) if a repo is staged
    if [[ -d "$STAGE_REPO" && $DRY_RUN -eq 0 ]]; then
        log "Applying repo configs from $STAGE_REPO"
        cp -f "$STAGE_REPO/nginx/tuxwall.conf" /etc/nginx/sites-available/tuxwall
        ln -sf /etc/nginx/sites-available/tuxwall /etc/nginx/sites-enabled/tuxwall
        rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

        for unit in tuxwall.service tuxwall-blocklist-update.service tuxwall-blocklist-update.timer; do
            [[ -f "$STAGE_REPO/systemd/$unit" ]] && cp -f "$STAGE_REPO/systemd/$unit" /etc/systemd/system/
        done
        cp -f "$STAGE_REPO/config/custom-blocklist.txt" /etc/tuxwall/ 2>/dev/null || true
        cp -f "$STAGE_REPO/config/llm.json.example"     /etc/tuxwall/ 2>/dev/null || true
        cp -f "$STAGE_REPO/config/ui.json"              /etc/tuxwall/ 2>/dev/null || true
        systemctl daemon-reload
    fi

    # 7. Enable all services
    log "Enabling systemd services"
    local svcs=(
        kea-dhcp4-server unbound radvd suricata crowdsec nginx tuxwall
        tuxwall-blocklist-update.timer
    )
    for svc in "${svcs[@]}"; do
        if [[ $DRY_RUN -eq 0 ]]; then
            systemctl enable "$svc" 2>/dev/null || warn "  could not enable $svc"
        else
            echo -e "${DIM}  (dry-run) systemctl enable $svc${NC}"
        fi
    done
    if [[ $DRY_RUN -eq 0 ]]; then
        systemctl daemon-reload
    fi

    # 8. Finalize netplan
    log "Applying netplan"
    if [[ $DRY_RUN -eq 0 ]]; then
        netplan apply 2>/dev/null || warn "  netplan apply failed — reboot to apply"
        log "  Rebooting recommended to fully apply networking + services."
    else
        echo -e "${DIM}  (dry-run) netplan apply + reboot${NC}"
    fi

    # 9. Mark configured
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p /etc/tuxwall
        touch "$INSTALLED_MARK"
        log "Marked configured: $INSTALLED_MARK"
    fi

    hr
    log "First-boot configuration complete."
    echo -e "  Dashboard : ${B}http://$LAN_STATIC_IP/${NC}"
    echo -e "  WAN       : $WAN  LAN: $LAN"
    hr
}

# ── Parse arguments ─────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --wan)      WAN="$2"; shift 2 ;;
            --lan)      LAN="$2"; shift 2 ;;
            --subnet)   LAN_SUBNET="$2"; shift 2 ;;
            --domain)   DOMAIN="$2"; shift 2 ;;
            --dry-run)  DRY_RUN=1; shift ;;
            *)          err "Unknown option: $1"; exit 1 ;;
        esac
    done
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    if [[ $EUID -ne 0 ]]; then
        err "Run as root: sudo bash $0"
        exit 1
    fi

    parse_args "$@"

    echo -e "${C}"
    cat << 'BANNER'
  ______          _       __      ____
 /_  __/_  ___  _| |     / /___ _/ / /
  / / / / / / |/_/ | /| / / __ `/ / /
 / / / /_/ />  < | |/ |/ / /_/ / / /
/_/  \__,_/_/|_| |__/|__/\__,_/_/_/

  Linux Network Firewall Appliance  (Ubuntu 26.04 LTS)

  Learn more: https://tuxwall.org
BANNER
    echo -e "${NC}"

    # Determine WAN/LAN interactively if not given
    if [[ -z "$WAN" && $DRY_RUN -eq 0 ]]; then
        ABORT=0
        pick_interface "Select the WAN (internet) interface:" "" || true
        [[ $ABORT -eq 1 ]] && exit 2
        WAN="$WAN_SEL"
        pick_interface "Select the LAN (internal) interface:" "$WAN" || true
        [[ $ABORT -eq 1 ]] && exit 2
        LAN="$WAN_SEL"
        echo
        read -rp "LAN subnet [default $LAN_SUBNET, 'x' to abort]: " -e input
        [[ "$input" =~ ^[qQxX]$ ]] && { log "Aborted."; exit 2; }
        [[ -n "$input" ]] && LAN_SUBNET="$input"
        read -rp "DNS domain [default $DOMAIN, 'x' to abort]: " -e input
        [[ "$input" =~ ^[qQxX]$ ]] && { log "Aborted."; exit 2; }
        [[ -n "$input" ]] && DOMAIN="$input"
    elif [[ -z "$WAN" || -z "$LAN" ]]; then
        err "--dry-run requires --wan and --lan to be specified."
        exit 1
    fi

    derive_ips

    echo -e "${DIM}  Configuration: WAN=$WAN LAN=$LAN subnet=$LAN_SUBNET ...${NC}"

    # Auto-skip if already configured (safety against re-running interactively)
    if [[ -f "$INSTALLED_MARK" && $DRY_RUN -eq 0 ]]; then
        warn "Appliance already configured ($INSTALLED_MARK). Re-run forced by removing it."
        read -rp "  Reconfigure anyway? [y/N] " ans
        [[ "$ans" =~ ^[yY]$ ]] || { log "Aborted."; exit 0; }
    fi

    run_firstboot
}

main "$@"
