#!/usr/bin/env bash
# Refresh the Warren DNS content-block RPZ zones from the upstream sources.
#
# For each category in rpz-sources.conf: fetch every source, normalize to
# bare domains (normalize-to-rpz.awk), dedupe, wrap into an RPZ zone, and
# atomically replace /var/lib/knot-resolver/rpz/<category>.rpz. kresd reloads
# each zone in place (policy.rpz watch=true), so no restart is needed.
#
# Run weekly-ish by warren-dns-refresh.timer (Mon-Thu, like Mullvad). Safe to
# run by hand. Best-effort per source: a single failed download is logged and
# skipped — the category keeps its other sources rather than going empty.
#
# No-log: this script handles only public blocklist data; it never touches
# user queries. It runs as the knot-resolver user where possible.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCES="${WARREN_DNS_SOURCES:-${HERE}/rpz-sources.conf}"
AWK_NORM="${WARREN_DNS_AWK:-${HERE}/normalize-to-rpz.awk}"
OUT_DIR="${WARREN_DNS_RPZ_DIR:-/var/lib/knot-resolver/rpz}"
CATEGORIES="ads trackers malware adult gambling social"
# Serial for the SOA: callers may pass a deterministic value; default to a
# fixed placeholder (kresd reloads on content change, not serial bump).
SERIAL="${WARREN_DNS_SERIAL:-1}"

log() { echo "warren-dns-refresh: $*" >&2; }

fetch() {
    # $1 = url (http(s):// or file://<relative-to-SOURCES-dir>)
    local url="$1"
    case "$url" in
        file://*)
            cat "${HERE}/${url#file://}"
            ;;
        *)
            curl -fsSL --max-time 60 --retry 2 "$url"
            ;;
    esac
}

# Emit a valid RPZ zone wrapping the deduped domain list on stdin.
# Each domain blocks the apex and all subdomains (CNAME . = NXDOMAIN).
wrap_rpz() {
    local zone="$1"
    printf '$TTL 1H\n'
    printf '@ SOA localhost. root.localhost. (%s 1H 15M 30D 2H)\n' "$SERIAL"
    printf '  NS localhost.\n'
    # apex + wildcard for every domain
    awk '{ printf "%s CNAME .\n*.%s CNAME .\n", $0, $0 }'
}

mkdir -p "$OUT_DIR"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

total=0
for cat in $CATEGORIES; do
    domains="${tmp_root}/${cat}.domains"
    : >"$domains"
    nsrc=0
    while read -r c url; do
        [ "$c" = "$cat" ] || continue
        if raw="$(fetch "$url" 2>/dev/null)"; then
            printf '%s\n' "$raw" | awk -f "$AWK_NORM" >>"$domains" || true
            nsrc=$((nsrc + 1))
        else
            log "WARN: fetch failed for $cat: $url (skipped)"
        fi
    done < <(grep -vE '^[[:space:]]*(#|$)' "$SOURCES")

    if [ ! -s "$domains" ]; then
        log "WARN: $cat produced 0 domains from $nsrc source(s); keeping existing zone"
        continue
    fi

    sort -u "$domains" -o "$domains"
    count="$(wc -l <"$domains")"
    out="${OUT_DIR}/${cat}.rpz"
    tmp_out="${tmp_root}/${cat}.rpz"
    wrap_rpz "$cat" <"$domains" >"$tmp_out"
    # Atomic replace so kresd never reads a half-written zone.
    mv -f "$tmp_out" "$out"
    log "$cat: $count domains from $nsrc source(s) -> $out"
    total=$((total + count))
done

log "done: $total total blocked domains across categories"

# Ask kresd to reload (no-op if watch=true already picked it up; harmless if
# kresd is down). Best-effort.
if command -v kresc >/dev/null 2>&1; then
    echo 'cache.clear()' | kresc 2>/dev/null || true
fi
