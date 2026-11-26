#!/usr/bin/env bash
# github-release.sh - create or update the GitHub Release of TuxWall tags.
#
# Run by .github/workflows/apt.yml (job "release") after the apt repository
# is published; safe to re-run (idempotent).
#
#   tools/github-release.sh [--force] TAG...
#   tools/github-release.sh --assets DIR TAG    attach the install images
#
# For each tag vX.Y.Z:
#   - the .deb is the EXACT file the apt repository publishes: read from the
#     gh-pages branch ($PAGES_REF), else downloaded from $PAGES_URL;
#   - it is checked against the signed apt index that published it (the
#     newest gh-pages commit "apt: publish tuxwall X.Y.Z": InRelease
#     signature (apt-public.asc) -> Packages SHA256 -> the .deb); a mismatch
#     is refused. Without that index the checksum is computed from the served
#     file and the notes say so;
#   - SHA256SUMS + SHA256SUMS.asc (detached, armored, signed with the apt
#     repository key $GPG_FPR, then verified against apt-public.asc);
#   - notes = the annotated tag message + checksum/verification lines;
#   - the release is created, or updated: missing assets uploaded, title/
#     notes filled in when empty or written by this script (notes written by
#     hand are kept). Releases that already have all assets are skipped
#     unless --force. The newest vX.Y.Z tag is marked "latest";
#   - install images attached earlier (--assets) stay listed in SHA256SUMS
#     when it is re-signed.
#
# --assets DIR TAG (job "images", after the release exists): every
# tuxwall-netinstall-<ver>-amd64.iso / tuxwall-vm-<ver>-amd64.qcow2 in DIR,
# each checked against its .sha256 and GitHub's 2 GiB asset limit, is added
# to the release; SHA256SUMS = the release's signed SHA256SUMS (signature
# checked) + the images, re-signed; the notes (when written by this script)
# get an "Install images" list. Re-runs replace the same assets.
#
# Environment: GH_TOKEN + GH_REPO (gh), GPG_FPR (imported secret key),
# PAGES_REF (origin/gh-pages), PAGES_URL (https://rezzonance.github.io/tuxwall),
# APT_KEY (apt-public.asc), DRY_RUN=1 (print gh calls, sign nothing).
set -euo pipefail

PAGES_REF=${PAGES_REF:-origin/gh-pages}
PAGES_URL=${PAGES_URL:-https://rezzonance.github.io/tuxwall}
APT_KEY=${APT_KEY:-apt-public.asc}
EXPECT_FPR=${EXPECT_FPR:-5D79B9082DCAEB9CCB731382F5D8235716BDBDD1}
MARKER="<!-- tuxwall-release-assets -->"
DRY_RUN=${DRY_RUN:-0}

IMAGES_MARK="<!-- tuxwall-images -->"
IMAGES_END="<!-- /tuxwall-images -->"
# GitHub: each release asset must be under 2 GiB
MAX_ASSET_BYTES=$((2 * 1024 * 1024 * 1024 - 1))

FORCE=0
ASSETS_DIR=""
TAGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        --assets) ASSETS_DIR="${2:-}"; [[ -n $ASSETS_DIR ]] || { echo "--assets needs a directory" >&2; exit 2; }; shift 2 ;;
        *) TAGS+=("$1"); shift ;;
    esac
done
(( ${#TAGS[@]} )) || { echo "usage: $0 [--force] TAG... | $0 --assets DIR TAG" >&2; exit 2; }
[[ -z $ASSETS_DIR || ${#TAGS[@]} -eq 1 ]] || { echo "--assets takes exactly one TAG" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
GNUPG_VERIFY="$WORK/verify-keyring.gpg"
gpg --batch --yes --dearmor -o "$GNUPG_VERIFY" "$APT_KEY"
key_fpr="$(gpg --batch --show-keys --with-colons "$APT_KEY" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
[[ $key_fpr == "$EXPECT_FPR" ]] || { echo "::error::$APT_KEY fingerprint $key_fpr != $EXPECT_FPR" >&2; exit 1; }

gh_() {
    if [[ $DRY_RUN == 1 ]]; then echo "DRY-RUN gh $*"; else gh "$@"; fi
}

newest_tag() {   # newest annotated vX.Y.Z tag (releases are annotated)
    git for-each-ref --format='%(objecttype) %(refname:short)' 'refs/tags/v*' \
        | awk '$1 == "tag" {print $2}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1
}

# release_state TAG -> "exists=0|1 assets=<names,> body=empty|ours|owner title=empty|set draft=0|1"
release_state() {
    local json
    if ! json="$(gh release view "$1" --json name,body,assets,isDraft 2>/dev/null)"; then
        echo "exists=0"
        return 0
    fi
    MARKER="$MARKER" python3 -c '
import json, os, sys
d = json.loads(sys.stdin.read() or "{}")
body = (d.get("body") or "").strip()
kind = "empty" if not body else ("ours" if os.environ["MARKER"] in body else "owner")
names = ",".join(a.get("name", "") for a in d.get("assets") or [])
print("exists=1 assets=%s, body=%s title=%s draft=%d" % (names, kind, "set" if d.get("name") else "empty",
                                                         1 if d.get("isDraft") else 0))
' <<<"$json"
}

fetch_deb() {   # fetch_deb VER OUT -> "branch" | "https"
    local path="pool/main/t/tuxwall/tuxwall_$1_all.deb"
    if git cat-file -e "$PAGES_REF:$path" 2>/dev/null; then
        git cat-file blob "$PAGES_REF:$path" >"$2"
        echo branch
    elif curl -fsSL --retry 3 -m 300 -o "$2" "$PAGES_URL/$path"; then
        echo https
    else
        return 1
    fi
}

# index_sha VER -> "<sha256> <commit>" from the signed index that published VER, or nothing
index_sha() {
    local ver=$1 commit d sha pk
    commit="$(git log --format=%H -n1 --grep="^apt: publish tuxwall ${ver//./\\.}\$" "$PAGES_REF" 2>/dev/null || true)"
    [[ -n $commit ]] || return 0
    d="$WORK/index-$ver"
    mkdir -p "$d"
    git cat-file blob "$commit:dists/stable/InRelease" >"$d/InRelease" 2>/dev/null || return 0
    git cat-file blob "$commit:dists/stable/main/binary-amd64/Packages" >"$d/Packages" 2>/dev/null || return 0
    if ! gpgv --keyring "$GNUPG_VERIFY" "$d/InRelease" >/dev/null 2>&1; then
        echo "::error::InRelease at gh-pages $commit does not verify with $APT_KEY" >&2
        return 1
    fi
    pk="$(sha256sum "$d/Packages" | cut -d' ' -f1)"
    grep -Eq "^ $pk +[0-9]+ main/binary-amd64/Packages\$" "$d/InRelease" || {
        echo "::error::Packages at gh-pages $commit is not the one InRelease signs" >&2
        return 1
    }
    sha="$(awk -v f="pool/main/t/tuxwall/tuxwall_${ver}_all.deb" \
        '/^Filename:/{x=($2==f)} x&&/^SHA256:/{print $2; exit}' "$d/Packages")"
    [[ -n $sha ]] && echo "$sha $commit"
    return 0
}

# kept_sums TAG STATE DIR DEB -> DIR/kept.sums: the lines of the release's current
# SHA256SUMS for its other assets (install images), when that file's signature
# verifies with the apt key; nothing otherwise
kept_sums() {
    local tag=$1 state=$2 d=$3 deb=$4 name
    : >"$d/kept.sums"
    [[ $state == *"SHA256SUMS,"* && $state == *"SHA256SUMS.asc,"* ]] || return 0
    mkdir -p "$d/current"
    gh release download "$tag" -p SHA256SUMS -p SHA256SUMS.asc -D "$d/current" --clobber >/dev/null 2>&1 || return 0
    gpgv --keyring "$GNUPG_VERIFY" "$d/current/SHA256SUMS.asc" "$d/current/SHA256SUMS" >/dev/null 2>&1 || {
        echo "   current SHA256SUMS does not verify - not kept" >&2
        return 0
    }
    while read -r sum name; do
        name=${name#\*}
        [[ $sum =~ ^[0-9a-f]{64}$ && $name != "$deb" && $name =~ ^tuxwall-[A-Za-z0-9._-]+$ ]] || continue
        [[ $state == *"assets=$name,"* || $state == *",$name,"* ]] || continue
        printf '%s  %s\n' "$sum" "$name"
    done <"$d/current/SHA256SUMS" >"$d/kept.sums"
    return 0
}

# images_section SUMSFILE DEB -> the notes' "Install images" list (empty without images)
images_section() {
    local sum name what
    grep -qv -- "  $2\$" "$1" 2>/dev/null || return 0
    printf '%s\n**Install images** (README: "Install from USB (netinstaller)", "Run as a VM"):\n\n' "$IMAGES_MARK"
    # shellcheck disable=SC2016  # backticks are Markdown
    while read -r sum name; do
        [[ $name == "$2" ]] && continue
        case "$name" in
            *.iso) what="USB/CD netinstaller, BIOS + UEFI (Secure Boot)" ;;
            *.qcow2) what="VM image for Proxmox / KVM, cloud-init" ;;
            *) what="" ;;
        esac
        printf -- '- `%s`%s - SHA-256 `%s`\n' "$name" "${what:+ ($what)}" "$sum"
    done <"$1"
    printf '%s\n\n' "$IMAGES_END"
}

sign_sums() {   # sign_sums DIR -> DIR/SHA256SUMS.asc (verified)
    if [[ $DRY_RUN == 1 ]]; then
        echo "DRY-RUN gpg --detach-sign SHA256SUMS"
        : >"$1/SHA256SUMS.asc"
        return 0
    fi
    [[ ${GPG_FPR:-} == "$EXPECT_FPR" ]] || { echo "::error::signing key ${GPG_FPR:-none} != $EXPECT_FPR" >&2; return 1; }
    gpg --batch --yes --local-user "$GPG_FPR" --armor --detach-sign --output "$1/SHA256SUMS.asc" "$1/SHA256SUMS"
    gpgv --keyring "$GNUPG_VERIFY" "$1/SHA256SUMS.asc" "$1/SHA256SUMS" >/dev/null 2>&1 \
        || { echo "::error::SHA256SUMS.asc does not verify with $APT_KEY" >&2; return 1; }
}

release_one() {
    local tag=$1 ver deb state src sha idx want commit note latest=false d
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::not a release tag: $tag" >&2; return 1; }
    ver=${tag#v}
    deb="tuxwall_${ver}_all.deb"
    [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" == tag ]] \
        || { echo "::error::$tag is not an annotated tag (git fetch --force --tags?)" >&2; return 1; }
    [[ $tag == "$(newest_tag)" ]] && latest=true
    state="$(release_state "$tag")"
    echo "== $tag: $state latest=$latest"
    if [[ $state == exists=1* && $state == *"$deb,"* && $state == *"SHA256SUMS,"* \
          && $state == *"SHA256SUMS.asc,"* && $state != *body=empty* && $state != *title=empty* ]] && (( ! FORCE )); then
        echo "   complete - skipped"
        [[ $latest == true ]] && gh_ release edit "$tag" --latest >/dev/null
        return 0
    fi

    d="$WORK/$tag"
    mkdir -p "$d"
    src="$(fetch_deb "$ver" "$d/$deb")" || { echo "::error::$deb is not published (gh-pages or $PAGES_URL)" >&2; return 1; }
    sha="$(sha256sum "$d/$deb" | cut -d' ' -f1)"
    idx="$(index_sha "$ver")" || return 1
    if [[ -n $idx ]]; then
        want=${idx%% *}
        commit=${idx#* }
        if [[ $sha != "$want" ]]; then
            echo "::error::$deb ($src) sha256 $sha != $want in the signed apt index (gh-pages ${commit:0:7})" >&2
            return 1
        fi
        note="Verified against the signed apt index that published it (gh-pages ${commit:0:7}: InRelease signature -> Packages -> SHA256)."
    else
        note="Checksums computed at backfill ($(date -u +%F)) from the file the apt repository serves; the apt index no longer lists this version."
    fi
    echo "   $deb from $src, sha256 $sha"

    kept_sums "$tag" "$state" "$d" "$deb"
    { (cd "$d" && sha256sum "$deb"); cat "$d/kept.sums"; } >"$d/SHA256SUMS"
    [[ -s $d/kept.sums ]] && echo "   kept in SHA256SUMS: $(awk '{print $2}' "$d/kept.sums" | paste -sd' ' -)"
    sign_sums "$d" || return 1

    # shellcheck disable=SC2016  # backticks are Markdown
    {
        git for-each-ref --format='%(contents)' "refs/tags/$tag" | sed '/^-----BEGIN PGP SIGNATURE-----$/,$d'
        printf '\n---\n\n'
        printf '**Package:** `%s` (Architecture: all) - the same file the signed apt repository serves.\n\n' "$deb"
        printf '**SHA-256:** `%s`\n\n' "$sha"
        printf '%s\n\n' "$note"
        printf 'Verify a download: `sha256sum -c SHA256SUMS` and `gpg --verify SHA256SUMS.asc SHA256SUMS` '
        printf '(TuxWall APT signing key `%s`, published as `apt-public.asc`; see SECURITY.md).\n\n' "$EXPECT_FPR"
        images_section "$d/SHA256SUMS" "$deb"
        printf '%s\n' "$MARKER"
    } >"$d/notes.md"

    if [[ $state == exists=0 ]]; then
        gh_ release create "$tag" --verify-tag --title "TuxWall $ver" --notes-file "$d/notes.md" \
            --latest="$latest" "$d/$deb" "$d/SHA256SUMS" "$d/SHA256SUMS.asc"
        echo "   created"
    else
        local args=()
        [[ $state == *title=empty* ]] && args+=(--title "TuxWall $ver")
        [[ $state == *body=empty* || $state == *body=ours* ]] && args+=(--notes-file "$d/notes.md")
        [[ $state == *body=owner* ]] && echo "   notes written by hand - kept"
        [[ $latest == true ]] && args+=(--latest)
        (( ${#args[@]} )) && gh_ release edit "$tag" "${args[@]}" >/dev/null
        gh_ release upload "$tag" --clobber "$d/$deb" "$d/SHA256SUMS" "$d/SHA256SUMS.asc"
        echo "   updated"
    fi
}

assets_one() {
    local tag=$1 dir=$2 ver deb state d f n files=() bytes body
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::not a release tag: $tag" >&2; return 1; }
    ver=${tag#v}
    deb="tuxwall_${ver}_all.deb"
    [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" == tag ]] \
        || { echo "::error::$tag is not an annotated tag (git fetch --force --tags?)" >&2; return 1; }
    for f in "$dir"/tuxwall-netinstall-"$ver"-amd64.iso "$dir"/tuxwall-vm-"$ver"-amd64.qcow2; do
        [[ -f $f ]] && files+=("$f")
    done
    (( ${#files[@]} )) || { echo "::error::no tuxwall-netinstall-$ver-amd64.iso / tuxwall-vm-$ver-amd64.qcow2 in $dir" >&2; return 1; }
    for f in "${files[@]}"; do
        n=${f##*/}
        bytes="$(stat -c %s "$f")"
        (( bytes <= MAX_ASSET_BYTES )) || { echo "::error::$n is $bytes bytes - over GitHub's 2 GiB asset limit" >&2; return 1; }
        [[ -f $f.sha256 ]] || { echo "::error::$n.sha256 missing" >&2; return 1; }
        [[ "$(awk 'NR == 1 {sub(/^\*/, "", $2); print $2}' "$f.sha256")" == "$n" ]] \
            || { echo "::error::$n.sha256 is not about $n" >&2; return 1; }
        (cd "$dir" && sha256sum -c --quiet "$n.sha256") || { echo "::error::$n does not match $n.sha256" >&2; return 1; }
    done
    state="$(release_state "$tag")"
    echo "== $tag images: $state"
    [[ $state == exists=1* && $state == *"$deb,"* && $state == *"SHA256SUMS,"* && $state == *"SHA256SUMS.asc,"* ]] \
        || { echo "::error::release $tag lacks $deb / SHA256SUMS(.asc) - run the release job first" >&2; return 1; }
    d="$WORK/$tag-images"
    mkdir -p "$d/current"
    gh release download "$tag" -p SHA256SUMS -p SHA256SUMS.asc -D "$d/current" --clobber >/dev/null \
        || { echo "::error::cannot download SHA256SUMS of $tag" >&2; return 1; }
    gpgv --keyring "$GNUPG_VERIFY" "$d/current/SHA256SUMS.asc" "$d/current/SHA256SUMS" >/dev/null 2>&1 \
        || { echo "::error::the SHA256SUMS of release $tag does not verify with $APT_KEY" >&2; return 1; }
    {
        awk -v deb="$deb" '{sub(/^\*/, "", $2)} $2 == deb {print $1 "  " $2}' "$d/current/SHA256SUMS"
        awk -v deb="$deb" -v skip=" $(for f in "${files[@]}"; do printf '%s ' "${f##*/}"; done)" \
            '{sub(/^\*/, "", $2)} $2 != deb && index(skip, " " $2 " ") == 0 {print $1 "  " $2}' "$d/current/SHA256SUMS"
        for f in "${files[@]}"; do awk 'NR == 1 {sub(/^\*/, "", $2); print $1 "  " $2}' "$f.sha256"; done
    } >"$d/SHA256SUMS"
    grep -q "  $deb\$" "$d/SHA256SUMS" || { echo "::error::$deb missing from the release's SHA256SUMS" >&2; return 1; }
    sign_sums "$d" || return 1
    sed 's/^/   /' "$d/SHA256SUMS"

    body="$(gh release view "$tag" --json body 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("body") or "")')"
    if [[ $body == *"$MARKER"* ]]; then
        images_section "$d/SHA256SUMS" "$deb" >"$d/images.md"
        BODY="$body" python3 - "$d/images.md" "$IMAGES_MARK" "$IMAGES_END" "$MARKER" >"$d/notes.md" <<'PY'
import os, re, sys
body, sec = os.environ["BODY"], open(sys.argv[1]).read()
start, end, marker = sys.argv[2:]
body = re.sub(re.escape(start) + r".*?" + re.escape(end) + r"\n*", "", body, flags=re.S)
i = body.rfind(marker)
print(body[:i] + sec + body[i:], end="")
PY
        gh_ release edit "$tag" --notes-file "$d/notes.md" >/dev/null
    else
        echo "   notes written by hand - kept (images not listed there)"
    fi
    gh_ release upload "$tag" --clobber "${files[@]}"
    gh_ release upload "$tag" --clobber "$d/SHA256SUMS" "$d/SHA256SUMS.asc"
    echo "   images attached: $(for f in "${files[@]}"; do printf '%s ' "${f##*/}"; done)"
}

rc=0
if [[ -n $ASSETS_DIR ]]; then
    assets_one "${TAGS[0]}" "$ASSETS_DIR" || rc=1
    exit "$rc"
fi
for t in "${TAGS[@]}"; do
    release_one "$t" || rc=1
done
exit "$rc"
