#!/bin/bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

LOGDIR="$TMP/log"
MARK="$TMP/qch.deploy_ts"
mkdir -p "$LOGDIR"

NOW=$(date +%s)
SINCE=$((NOW - 100))
echo "$SINCE" > "$MARK"

cat > "$LOGDIR/antibot.log" <<EOF
[x] ts=$((SINCE - 1)) domain=old.test class=navigation qch=99 qcd=64 ckn=true rown=1.00 apresent=true dgup=9.0 dgtn=9/10
[x] ts=$((SINCE + 1)) domain=a.test class=navigation action=allow
[x] ts=$((SINCE + 2)) domain=a.test class=navigation qch=- qcd=- ckn=- rown=- apresent=false dgup=0.1 dgtn=1/10
[x] ts=$((SINCE + 3)) domain=a.test class=navigation qch=1 qcd=1 ckn=false rown=0.00 apresent=false dgup=0.1 dgtn=1/10
[x] ts=$((SINCE + 4)) domain=a.test class=navigation qch=10 qcd=8 ckn=true rown=0.80 apresent=true dgup=2.5 dgtn=8/10 qcw=true qcb=3 qcx=true qcr=0.900
[x] ts=$((SINCE + 5)) domain=b.test class=interaction qch=3 qcd=2 ckn=false rown=0.10 apresent=true dgup=0.3 dgtn=2/10 qcw=false qcb=1 qcx=true qcr=1.000
EOF

cat > "$TMP/rotated" <<EOF
[x] ts=$((SINCE + 6)) domain=a.test class=unknown qch=5 qcd=4 ckn=true rown=0.60 apresent=false dgup=3.0 dgtn=5/10
EOF
gzip -c "$TMP/rotated" > "$LOGDIR/antibot.log.1.gz"
touch "$LOGDIR/antibot.log" "$LOGDIR/antibot.log.1.gz"

OUT=$(bash "$HERE/qchstat.sh" "$LOGDIR" "$MARK")
PASS=0

check() {
    local pattern=$1
    printf '%s\n' "$OUT" | grep -qE "$pattern"
    PASS=$((PASS + 1))
}

check '^rows=6 schema=5 numeric=4$'
check '^SET all rows=4 qch\[p50=3 p95=10 p99=10 max=10\] qcd\[p50=2 p95=8 p99=8 max=8\]$'
check '^SET page rows=3 '
check '^SET application rows=1 '
check '^SET actor_presented rows=2 '
check '^SET first_party_strong rows=2 '
check '^SET upstream_ge_2s rows=2 '
check '^would_qch=1$'
check '^exclusive=2$'
check '^exclusive_rate=0.500 \(2/4\)$'
check '^exclusive_ratio_mean=0.950 samples=2$'
check '^a\.test 3 10 8$'
check '^QCHSTAT_OK$'

echo bad > "$MARK"
set +e
bash "$HERE/qchstat.sh" "$LOGDIR" "$MARK" > /dev/null 2>&1
RC=$?
set -e
[ "$RC" -eq 2 ]
PASS=$((PASS + 1))

echo "qchstat_test: $PASS pass, 0 fail"
