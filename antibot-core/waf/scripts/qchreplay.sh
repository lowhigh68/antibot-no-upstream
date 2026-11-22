#!/bin/bash
# Usage: qchreplay.sh FROM_EPOCH TO_EPOCH IP ACCESS_LOG [ACCESS_LOG...]
# Pass IP '-' to replay every source.  All logs must belong to one domain.
# Optional QCH_PATH_PREFIX narrows an incident family; it never affects runtime.

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}

die() {
    echo "QCHREPLAY_ERROR $*" >&2
    exit 2
}

[ "$#" -ge 4 ] || die "usage: qchreplay.sh FROM TO IP LOG [LOG...]"
FROM=$1
TO=$2
IP=$3
shift 3

case "$FROM:$TO" in
    *[!0-9:]*|:*|*:) die "FROM and TO must be epochs" ;;
esac
[ "$FROM" -le "$TO" ] || die "FROM is after TO"
[ -x "$RESTY" ] || die "resty not executable: $RESTY"
[ -r "$HERE/qchreplay.lua" ] || die "missing qchreplay.lua"

for file in "$@"; do
    [ -r "$file" ] || die "log not readable: $file"
done

emit_logs() {
    local file
    for file in "$@"; do
        case "$file" in
            *.gz) gzip -cd -- "$file" ;;
            *)    cat -- "$file" ;;
        esac
    done
}

OUT=$(mktemp "${TMPDIR:-/tmp}/qchreplay.XXXXXX")
trap 'rm -f -- "$OUT"' EXIT HUP INT TERM

emit_logs "$@" | "$RESTY" "$HERE/qchreplay.lua" "$FROM" "$TO" "$IP" \
    > "$OUT" 2>&1

cat "$OUT"
grep -q '^QCHREPLAY_OK$' "$OUT" || die "replay did not finish"
