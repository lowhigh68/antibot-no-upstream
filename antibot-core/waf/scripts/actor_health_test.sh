#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/log"

# Never create an executable fixture below /tmp. Several production nodes
# intentionally mount /tmp with `noexec`; access(X_OK) then rejects a file even
# after chmod +x and makes this monitor-only test block an otherwise valid
# deploy. The production checker itself is covered by secrets_contract.lua.
# Here /bin/true and /bin/false model only its success/failure exit contract.
TRUE_BIN=/bin/true
FALSE_BIN=/bin/false
[ -x "$TRUE_BIN" ]
[ -x "$FALSE_BIN" ]

NOW=$(date +%s)
cat > "$TMP/log/antibot.log" <<EOF
[x] ts=$((NOW - 20)) domain=a.test class=unknown reason=score aid=a apresent=true avalid=true aissued=true ainvalid=- aissueerr=- bpersist=true bkind=actor bscope=host
[x] ts=$((NOW - 10)) domain=a.test class=unknown reason=actor_quarantine aid=a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=- bkind=actor bscope=host
[x] ts=$((NOW - 5)) domain=a.test class=unknown reason=actor_quarantine aid=a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=-
EOF

OUT=$(RESTY="$TRUE_BIN" bash "$HERE/actor_health.sh" 15 "$TMP/log")
printf '%s\n' "$OUT" | grep -q 'status=OK'
printf '%s\n' "$OUT" | grep -q '^actor_issue_error=0$'
printf '%s\n' "$OUT" | grep -q '^q2_total=2$'
printf '%s\n' "$OUT" | grep -q '^bad_q2_scope=0$'
printf '%s\n' "$OUT" | grep -q '^q2_scope_missing=1$'

cat >> "$TMP/log/antibot.log" <<EOF
[x] ts=$NOW domain=b.test class=unknown reason=score aid=- apresent=false avalid=false aissued=false ainvalid=- aissueerr=secret_unavailable bpersist=false bkind=- bscope=-
EOF

set +e
OUT=$(RESTY="$TRUE_BIN" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=DEGRADED'
printf '%s\n' "$OUT" | grep -q '^actor_secret_unavailable=1$'

cat >> "$TMP/log/antibot.log" <<EOF
[x] ts=$NOW domain=c.test class=unknown reason=actor_quarantine aid=c apresent=true avalid=true aissued=false ainvalid=- aissueerr=- bpersist=- bkind=network bscope=global
EOF

set +e
OUT=$(RESTY="$TRUE_BIN" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=CRITICAL'
printf '%s\n' "$OUT" | grep -q '^bad_q2_scope=1$'

set +e
OUT=$(RESTY="$FALSE_BIN" bash "$HERE/actor_health.sh" 15 "$TMP/log" 2>&1)
RC=$?
set -e
[ "$RC" -eq 1 ]
printf '%s\n' "$OUT" | grep -q 'status=CRITICAL'

echo "actor_health_test: 14 pass, 0 fail"
