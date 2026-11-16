#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

LOGDIR="$TMP/log"
OUTDIR="$TMP/out"
MARK="$TMP/actor.deploy_ts"
mkdir -p "$LOGDIR" "$OUTDIR"

NOW=$(date +%s)
SINCE=$((NOW - 90000))
echo "$SINCE" > "$MARK"

cat > "$LOGDIR/antibot.log" <<EOF
[x] ts=$((SINCE + 100)) domain=a.test class=navigation reason=score action=block aid=- apresent=false avalid=false aissued=true ainvalid=- aissueerr=- aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 rown=0.00 dev=desktop_chrome ipold=false ipmanual=false
[x] ts=$((SINCE + 200)) domain=a.test class=navigation reason=score action=block aid=actor-a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- aqclear=false bsup=- bpersist=true bkind=actor bscope=host ckn=true richness=0.60 rown=0.60 dev=desktop_chrome ipold=false ipmanual=false
[x] ts=$((SINCE + 300)) domain=a.test class=navigation reason=actor_quarantine_challenge action=challenge aid=actor-a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- aqclear=false bsup=- bpersist=- bkind=actor bscope=host ckn=true richness=0.60 rown=0.60 dev=desktop_chrome ipold=false ipmanual=false
[x] ts=$((SINCE + 500)) domain=b.test class=unknown reason=score action=block aid=- apresent=false avalid=false aissued=false ainvalid=- aissueerr=secret_unavailable aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 rown=0.00 dev=desktop_other ipold=false ipmanual=false
[x] ts=$((SINCE + 600)) domain=b.test class=unknown reason=actor_quarantine action=block aid=actor-b apresent=true avalid=true aissued=false ainvalid=- aissueerr=- aqclear=false bsup=- bpersist=- bkind=actor bscope=host ckn=false richness=0.10 rown=0.10 dev=desktop_other ipold=false ipmanual=false
[x] ts=$((SINCE + 650)) domain=c.test class=unknown reason=actor_quarantine action=block aid=actor-c apresent=true avalid=true aissued=false ainvalid=- aissueerr=- aqclear=false bsup=- bpersist=- ckn=false richness=0.10 rown=0.10 dev=desktop_other
[x] ts=$((SINCE + 700)) domain=a.test class=navigation reason=verify_success action=allow aid=actor-a apresent=true avalid=true aissued=false ainvalid=- aissueerr=- aqclear=true bsup=- bpersist=- bkind=- bscope=- ckn=true richness=0.60 rown=0.60 dev=desktop_chrome ipold=false ipmanual=false
EOF

cat > "$TMP/rotated" <<EOF
[x] ts=$((SINCE + 400)) domain=b.test class=unknown reason=score action=block aid=- apresent=false avalid=false aissued=false ainvalid=signature aissueerr=- aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 rown=0.00 dev=desktop_other ipold=true ipmanual=false
[x] ts=$((SINCE + 800)) domain=c.test class=unknown reason=score action=block aid=- apresent=false avalid=false aissued=false ainvalid=secret_unavailable aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 rown=0.00 dev=desktop_other ipold=false ipmanual=false
EOF
gzip -c "$TMP/rotated" > "$LOGDIR/antibot.log.1.gz"
touch "$LOGDIR/antibot.log" "$LOGDIR/antibot.log.1.gz"

if [ "${TRACE_ACTOR24:-0}" = "1" ]; then
    OUTPUT=$(bash -x "$HERE/actor24.sh" "$LOGDIR" "$MARK" "$OUTDIR")
else
    OUTPUT=$(bash "$HERE/actor24.sh" "$LOGDIR" "$MARK" "$OUTDIR")
fi
ARCHIVE=$(printf '%s\n' "$OUTPUT" | sed -n 's/^ACTOR24_READY file=//p')

[ -f "$ARCHIVE" ]
REPORT=$(gzip -cd "$ARCHIVE")

PASS=0
check() {
    local pattern=$1
    printf '%s\n' "$REPORT" | grep -qE "$pattern"
    PASS=$((PASS + 1))
}

check '^rows=9$'
check '^actor_issued=1$'
check '^actor_presented=5$'
check '^actor_valid_presented=5$'
check '^actor_unique_valid=3$'
check '^actor_invalid=3$'
check '^actor_cookie_invalid=1$'
check '^actor_issue_attempts=3$'
check '^actor_issue_error=2$'
check '^actor_secret_unavailable=2$'
check '^legacy_issue_error_rows=1$'
check '^q2_persisted=1$'
check '^q2_unique_persist_actor=1$'
check '^q2_total=3$'
check '^q2_unique_actor=3$'
check '^q2_block=2$'
check '^q2_challenge=1$'
check '^q2_cleared=1$'
check '^q2_unique_cleared_actor=1$'
check '^q2_known_cookie=1$'
check '^q2_rown_ge_050=1$'
check '^q2_human_class=1$'
check '^fp_candidate=1$'
check '^fp_candidate_v2=1$'
check '^fn_no_presented_actor=4$'
check '^bad_persist_scope=0$'
check '^bad_q2_scope=0$'
check '^q2_scope_missing=1$'
check '^old_ip_ignored=1$'
check '^1 signature$'
check '^2 secret_unavailable$'
check '^1 a.test$'
check '^1 b.test$'
check '^actor_health=DEGRADED$'
check '^=== SAMPLE ISSUE ERROR MAX 10 ===$'
check '^=== SAMPLE COOKIE INVALID MAX 10 ===$'
check '^=== SAMPLE PERSIST MAX 10 ===$'
check '^=== SAMPLE Q2 BLOCK MAX 10 ===$'
check '^=== SAMPLE Q2 CHALLENGE MAX 10 ===$'
check '^=== SAMPLE Q2 CLEAR MAX 10 ===$'
check '^=== SAMPLE Q2 BAD SCOPE MAX 10 ===$'
check '^=== SAMPLE Q2 SCOPE MISSING MAX 10 ===$'
check '^=== SAMPLE NO PRESENTED ACTOR MAX 10 ===$'

echo "actor24_test: $PASS pass, 0 fail"

