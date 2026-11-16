#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/log"
cat > "$TMP/resty" <<'EOF'
#!/bin/bash
if [ "${FAKE_SECRET_FAIL:-0}" = "1" ]; then
    echo "ACTOR_SECRET_ERROR fixture"
    exit 1
fi
echo "ACTOR_SECRET_OK current_bytes=32 previous=no"
EOF
chmod +x "$TMP/resty"

NOW=$(date +%s)
cat > "$TMP/log/antibot.log" <<EOF
[x] ts=$((NOW - 20)) domain=a.test class=unknown reason=score aid=a apresent=true avalid=true aissued=true ainvalid=- aissueerr=- bpersist=true bkind=actor bscope=host
[x] ts=$((NOW - 10)) domain=a.test class=unknown reason=actor_quarantine aid=a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=- bkind=actor bscope=host
[x] ts=$((NOW - 5)) domain=a.test class=unknown reason=actor_quarantine aid=a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=-
EOF

OUT=$(RESTY="$TMP/resty" bash "$HERE/actor_health.sh" 15 "$TMP/log")
printf '%s\n' "$OUT" | grep -q 'status=OK'
printf '%s\n' "$OUT" | grep -q '^actor_issue_error=0$'
printf '%s\n' "$OUT" | grep -q '^q2_total=2$'
printf '%s\n' "$OUT" | grep -q '^bad_q2_scope=0$'
printf '%s\n' "$OUT" | grep -q '^q2_scope_missing=1$'

cat >> "$TMP/log/antibot.log" <<EOF
[x] ts=$NOW domain=b.test class=unknown reason=score aid=- apresent=false avalid=false aissued=false ainvalid=- aissueerr=secret_unavailable bpersist=false bkind=- bscope=-
EOF

set +e
OUT=$(RESTY="$TMP/resty" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=DEGRADED'
printf '%s\n' "$OUT" | grep -q '^actor_secret_unavailable=1$'

cat >> "$TMP/log/antibot.log" <<EOF
[x] ts=$NOW domain=c.test class=unknown reason=actor_quarantine aid=c apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=- bkind=network bscope=global
EOF

set +e
OUT=$(RESTY="$TMP/resty" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=CRITICAL'
printf '%s\n' "$OUT" | grep -q '^bad_q2_scope=1$'

set +e
OUT=$(FAKE_SECRET_FAIL=1 RESTY="$TMP/resty" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=CRITICAL'

echo "actor_health_test: 14 pass, 0 fail"
