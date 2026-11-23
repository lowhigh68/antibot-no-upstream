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
108.206.38.169 [22/Nov/2026:17:48:10 +0700] "GET /audio?a=1 HTTP/2.0" 200 score=- action=- fp=- tls13=- ja3_partial=- 0.231s
108.206.38.169 - - [22/Nov/2026:17:48:11 +0700] "GET /audio?a=2 HTTP/2.0" 200 1 "-" "ua"
108.206.38.169 - - [22/Nov/2026:17:48:12 +0700] "GET /audio HTTP/2.0" 200 1 "-" "ua"
203.0.113.9 - - [22/Nov/2026:17:48:12 +0700] "GET /audio?a=other HTTP/2.0" 200 1 "-" "ua"
not-an-access-line
EOF

cat > "$TMP/rotated" <<'EOF'
108.206.38.169 [22/Nov/2026:17:48:12 +0700] "HEAD /audio?a=3 HTTP/1.1" 200 score=- action=- fp=- tls13=- ja3_partial=- 0.112s
108.206.38.169 - - [22/Nov/2026:17:48:13 +0700] "GET /audio?a=4 HTTP/1.1" 200 1 "-" "ua"
EOF
gzip -c "$TMP/rotated" > "$ROTATED"

OUT=$(bash "$HERE/qchreplay.sh" "$FROM" "$TO" "$IP" \
    "$PLAIN" "$ROTATED")
PASS=0

check() {
    local pattern=$1
    grep -qE "$pattern" <<< "$OUT"
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
grep -q '^QCHREPLAY_EMPTY$' <<< "$PREFIX_OUT"
grep -q '^path_prefix=/none/$' <<< "$PREFIX_OUT"
PASS=$((PASS + 2))

# Bucket identity must include the source.  Without the IP component the
# second source below is folded into the first source's bucket, inflating qch
# and turning unrelated visitors into one apparent campaign.
ALL_OUT=$(bash "$HERE/qchreplay.sh" "$FROM" "$TO" - "$PLAIN" "$ROTATED")
grep -q '^read=8 parsed=7 selected=6 path_skipped=0 bad=1 query_events=5 sources=2 buckets=2$' \
    <<< "$ALL_OUT"
PASS=$((PASS + 1))

# These raw queries collide when a mutant uses only the first four MD5 hex
# characters modulo 64, but occupy different shards with the production eight
# characters.  Four ordinary queries cannot distinguish those algorithms.
HASHLOG="$TMP/hash.log"
cat > "$HASHLOG" <<'EOF'
108.206.38.169 [22/Nov/2026:17:48:20 +0700] "GET /audio?probe9 HTTP/2.0" 200 score=- action=- 0.100s
108.206.38.169 [22/Nov/2026:17:48:21 +0700] "GET /audio?probe10 HTTP/2.0" 200 score=- action=- 0.100s
EOF
HASH_OUT=$(bash "$HERE/qchreplay.sh" "$FROM" "$TO" "$IP" "$HASHLOG")
HASH_BUCKET=$((FROM + 10))
grep -q "^$HASH_BUCKET $IP 2 2$" <<< "$HASH_OUT"
PASS=$((PASS + 1))
HASH_DEBUG=$(QCH_DEBUG_SHARDS=1 bash "$HERE/qchreplay.sh" \
    "$FROM" "$TO" "$IP" "$HASHLOG")
grep -q '^DEBUG_SHARD probe9 37$' <<< "$HASH_DEBUG"
grep -q '^DEBUG_SHARD probe10 4$' <<< "$HASH_DEBUG"
PASS=$((PASS + 2))

# Repeated identical queries must increment qch but only one distinct shard.
# This guards the per-bucket `seen` bitmap; removing it makes qcd == qch.
DUPLOG="$TMP/duplicate.log"
cat > "$DUPLOG" <<EOF
108.206.38.169 [22/Nov/2026:17:48:20 +0700] "GET /audio?dup=1 HTTP/2.0" 200 score=- action=- 0.100s
108.206.38.169 [22/Nov/2026:17:48:21 +0700] "GET /audio?dup=1 HTTP/2.0" 200 score=- action=- 0.100s
108.206.38.169 [22/Nov/2026:17:48:22 +0700] "GET /audio?dup=2 HTTP/2.0" 200 score=- action=- 0.100s
EOF
DUP_OUT=$(bash "$HERE/qchreplay.sh" "$FROM" "$TO" "$IP" "$DUPLOG")
grep -qE '^[0-9]+ 108\.206\.38\.169 3 2$' <<< "$DUP_OUT"
PASS=$((PASS + 1))

# Shards are represented by a bounded per-bucket bitmap.  Removing the upper
# bound changes the memory contract, so exercise the rejection boundary rather
# than testing only the default value 64.
set +e
SHARD_OUT=$(QCH_SHARDS=129 bash "$HERE/qchreplay.sh" \
    "$FROM" "$TO" "$IP" "$PLAIN" 2>&1)
SHARD_RC=$?
set -e
[ "$SHARD_RC" -eq 2 ]
grep -q 'QCHREPLAY_ERROR invalid window/shards' <<< "$SHARD_OUT"
PASS=$((PASS + 1))

set +e
bash "$HERE/qchreplay.sh" bad "$TO" "$IP" "$PLAIN" \
    > /dev/null 2>&1
RC=$?
set -e
[ "$RC" -eq 2 ]
PASS=$((PASS + 1))

echo "qchreplay_test: $PASS pass, 0 fail"
