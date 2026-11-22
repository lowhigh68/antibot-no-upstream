#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PLAIN="$TMP/access.log"
ROTATED="$TMP/access.log.1.gz"
FROM=$(date -d '2026-11-22 17:48:10 +0700' +%s)
TO=$(date -d '2026-11-22 17:48:30 +0700' +%s)
IP=108.206.38.169

cat > "$PLAIN" <<'EOF'
108.206.38.169 - - [22/Nov/2026:17:48:09 +0700] "GET /old?a=old HTTP/2.0" 200 1 "-" "ua"
108.206.38.169 - - [22/Nov/2026:17:48:10 +0700] "GET /audio?a=1 HTTP/2.0" 200 1 "-" "ua"
108.206.38.169 - - [22/Nov/2026:17:48:11 +0700] "GET /audio?a=2 HTTP/2.0" 200 1 "-" "ua"
108.206.38.169 - - [22/Nov/2026:17:48:12 +0700] "GET /audio HTTP/2.0" 200 1 "-" "ua"
203.0.113.9 - - [22/Nov/2026:17:48:12 +0700] "GET /audio?a=other HTTP/2.0" 200 1 "-" "ua"
not-an-access-line
EOF

cat > "$TMP/rotated" <<'EOF'
108.206.38.169 - - [22/Nov/2026:17:48:12 +0700] "HEAD /audio?a=3 HTTP/1.1" 200 1 "-" "ua"
108.206.38.169 - - [22/Nov/2026:17:48:13 +0700] "GET /audio?a=4 HTTP/1.1" 200 1 "-" "ua"
EOF
gzip -c "$TMP/rotated" > "$ROTATED"

OUT=$(bash "$HERE/qchreplay.sh" "$FROM" "$TO" "$IP" \
    "$PLAIN" "$ROTATED")
PASS=0

check() {
    local pattern=$1
    printf '%s\n' "$OUT" | grep -qE "$pattern"
    PASS=$((PASS + 1))
}

check '^window=10 shards=64$'
check '^path_prefix=-$'
check '^read=8 parsed=7 selected=5 path_skipped=0 bad=1 query_events=4 sources=1 buckets=1$'
check '^SET replay rows=4 qch\[p50=2 p95=4 p99=4 max=4\] qcd\[p50=2 p95=4 p99=4 max=4\]$'
check "^$FROM $IP 4 4$"
check '^QCHREPLAY_OK$'

PREFIX_OUT=$(QCH_PATH_PREFIX=/none/ bash "$HERE/qchreplay.sh" \
    "$FROM" "$TO" "$IP" "$PLAIN" "$ROTATED")
printf '%s\n' "$PREFIX_OUT" | grep -q '^QCHREPLAY_EMPTY$'
printf '%s\n' "$PREFIX_OUT" | grep -q '^path_prefix=/none/$'
PASS=$((PASS + 2))

set +e
bash "$HERE/qchreplay.sh" bad "$TO" "$IP" "$PLAIN" \
    > /dev/null 2>&1
RC=$?
set -e
[ "$RC" -eq 2 ]
PASS=$((PASS + 1))

echo "qchreplay_test: $PASS pass, 0 fail"
