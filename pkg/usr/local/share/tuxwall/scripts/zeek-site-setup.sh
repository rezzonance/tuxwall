#!/bin/bash
# TuxWall: Zeek site policy for device monitoring (3.3.7).
#
# Writes <site>/tuxwall-devicewatch.zeek and loads it from <site>/local.zeek:
#   @load policy/protocols/conn/mac-logging
#       conn.log gains orig_l2_addr / resp_l2_addr: device monitoring
#       attributes each flow to the MAC that carried it (reused IPv4
#       addresses, IPv6 privacy addresses the neighbour table forgot).
#   redef ignore_checksums = T;
#       only on a virtual machine (systemd-detect-virt --vm) or with
#       --ignore-checksums (kept on later runs): virtual NICs hand the capture
#       packets whose checksums the host offloads and never fills in; Zeek
#       drops them as bad and logs every completed connection as an
#       unanswered attempt. Chosen over turning NIC checksum offload off: it
#       changes nothing in the forwarding path, only what Zeek verifies.
# Then, when Zeek runs: `zeekctl check`, and `zeekctl deploy` (Zeek restarts
# for a few seconds). A failed check puts the previous files back.
#
#   zeek-site-setup.sh [--ignore-checksums] [--no-deploy] [SITE_DIR]
#
# Zeek is optional and not installed by TuxWall: no site directory -> exit 0.
# The postinst runs this on fresh installs; afterwards the dashboard
# (Settings > Threat) shows the command when Zeek logs no MAC addresses.
# Exit: 0 done / nothing to do, 1 zeekctl check failed (restored), 2 error.
set -u

IGNORE=0
DEPLOY=1
SITE=""
for a in "$@"; do
  case "$a" in
    --ignore-checksums) IGNORE=1 ;;
    --no-deploy) DEPLOY=0 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) SITE=$a ;;
  esac
done
if [[ -z $SITE ]]; then
  for d in "${ZEEK_SITE:-}" /opt/zeek/share/zeek/site /usr/local/zeek/share/zeek/site /usr/share/zeek/site; do
    [[ -n $d && -f $d/local.zeek ]] && { SITE=$d; break; }
  done
fi
if [[ -z $SITE || ! -f $SITE/local.zeek ]]; then
  echo "zeek: not installed (no site/local.zeek) - nothing to do"
  exit 0
fi
ZEEKCTL=${ZEEKCTL:-}
if [[ -z $ZEEKCTL ]]; then
  for z in "$SITE/../../../bin/zeekctl" /opt/zeek/bin/zeekctl "$(command -v zeekctl 2>/dev/null)"; do
    [[ -n $z && -x $z ]] && { ZEEKCTL=$z; break; }
  done
fi

POLICY=$SITE/tuxwall-devicewatch.zeek
LOCAL=$SITE/local.zeek
if (( ! IGNORE )); then
  if systemd-detect-virt --vm -q 2>/dev/null; then
    IGNORE=1
  elif [[ -f $POLICY ]] && grep -q '^redef ignore_checksums = T;' "$POLICY"; then
    IGNORE=1                     # chosen earlier (--ignore-checksums): keep it
  fi
fi

want=$(
  echo "## TuxWall device monitoring - managed by /usr/local/share/tuxwall/scripts/zeek-site-setup.sh"
  echo "## (rewritten by that script; keep your own settings in local.zeek)."
  echo ""
  echo "## conn.log: orig_l2_addr / resp_l2_addr - flows attributed to the MAC that carried them"
  echo "@load policy/protocols/conn/mac-logging"
  if (( IGNORE )); then
    echo ""
    echo "## virtual NIC: offloaded checksums are never filled in on capture; without"
    echo "## this every completed connection is logged as an unanswered attempt"
    echo "redef ignore_checksums = T;"
  fi
)

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
cp -p "$LOCAL" "$tmp/local.zeek" || exit 2
had_policy=0
[[ -f $POLICY ]] && { cp -p "$POLICY" "$tmp/policy.zeek" || exit 2; had_policy=1; }

changed=0
if [[ ! -f $POLICY ]] || [[ "$(cat "$POLICY")" != "$want" ]]; then
  printf '%s\n' "$want" > "$POLICY.tmp" || exit 2
  chmod 0644 "$POLICY.tmp"
  chgrp --reference="$SITE" "$POLICY.tmp" 2>/dev/null || true
  mv -f "$POLICY.tmp" "$POLICY" || exit 2
  changed=1
fi
if ! grep -Eq '^[[:space:]]*@load[[:space:]]+(\./)?tuxwall-devicewatch(\.zeek)?[[:space:]]*$' "$LOCAL"; then
  [[ -f $LOCAL.pre-tuxwall ]] || cp -p "$LOCAL" "$LOCAL.pre-tuxwall"
  printf '\n# TuxWall device monitoring (MAC addresses in conn.log; see the file)\n@load ./tuxwall-devicewatch.zeek\n' >> "$LOCAL" || exit 2
  changed=1
fi

restore() {
  cp -p "$tmp/local.zeek" "$LOCAL"
  if (( had_policy )); then cp -p "$tmp/policy.zeek" "$POLICY"; else rm -f "$POLICY"; fi
}

what="mac-logging$( (( IGNORE )) && echo ' + ignore_checksums')"
if (( ! changed )); then
  echo "zeek: site policy up to date ($what)"
  exit 0
fi
if (( ! DEPLOY )) || [[ -z $ZEEKCTL ]]; then
  echo "zeek: site policy written ($what) - takes effect on the next 'zeekctl deploy'"
  exit 0
fi
if ! "$ZEEKCTL" status 2>/dev/null | grep -qw running; then
  echo "zeek: site policy written ($what) - Zeek is not running; takes effect when it starts (zeekctl deploy)"
  exit 0
fi
if ! "$ZEEKCTL" check >"$tmp/check.log" 2>&1; then
  restore
  echo "zeek: 'zeekctl check' failed with the TuxWall policy - previous files restored:" >&2
  tail -n 5 "$tmp/check.log" >&2
  exit 1
fi
if "$ZEEKCTL" deploy >"$tmp/deploy.log" 2>&1; then
  echo "zeek: site policy deployed ($what)"
else
  echo "zeek: 'zeekctl deploy' reported a problem (see 'zeekctl status'):" >&2
  tail -n 5 "$tmp/deploy.log" >&2
  exit 2
fi
