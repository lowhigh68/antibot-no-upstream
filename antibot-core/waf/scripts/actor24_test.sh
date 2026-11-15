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
[x] ts=$((SINCE + 100)) domain=a.test class=navigation reason=score action=block apresent=false avalid=false aissued=true ainvalid=- aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 ipold=false ipmanual=false
[x] ts=$((SINCE + 200)) domain=a.test class=navigation reason=score action=block apresent=true avalid=true aissued=false ainvalid=- aqclear=false bsup=- bpersist=true bkind=actor bscope=host ckn=true richness=0.60 ipold=false ipmanual=false
[x] ts=$((SINCE + 300)) domain=a.test class=navigation reason=actor_quarantine_challenge action=challenge apresent=true avalid=true aissued=false ainvalid=- aqclear=false bsup=- bpersist=- bkind=actor bscope=host ckn=true richness=0.60 ipold=false ipmanual=false
EOF

cat > "$TMP/rotated" <<EOF
[x] ts=$((SINCE + 400)) domain=b.test class=unknown reason=score action=block apresent=false avalid=false aissued=false ainvalid=signature aqclear=false bsup=no_presented_actor bpersist=false bkind=- bscope=- ckn=- richness=0.00 ipold=true ipmanual=false
EOF
gzip -c "$TMP/rotated" > "$LOGDIR/antibot.log.1.gz"
touch "$LOGDIR/antibot.log" "$LOGDIR/antibot.log.1.gz"

OUTPUT=$(bash "$HERE/actor24.sh" "$LOGDIR" "$MARK" "$OUTDIR")
ARCHIVE=$(printf '%s\n' "$OUTPUT" | sed -n 's/^ACTOR24_READY file=//p')

[ -f "$ARCHIVE" ]
REPORT=$(gzip -cd "$ARCHIVE")

check() {
    local pattern=$1
    printf '%s\n' "$REPORT" | grep -qE "$pattern"
}

check '^rows=4$'
check '^actor_issued=1$'
check '^actor_presented=2$'
check '^actor_valid_presented=2$'
check '^actor_invalid=1$'
check '^q2_persisted=1$'
check '^q2_total=1$'
check '^q2_challenge=1$'
check '^fp_candidate=1$'
check '^fn_no_presented_actor=2$'
check '^bad_persist_scope=0$'
check '^bad_q2_scope=0$'
check '^old_ip_ignored=1$'
check '^1 signature$'
check '^1 a.test$'
check '^1 b.test$'

echo "actor24_test: 16 pass, 0 fail"

