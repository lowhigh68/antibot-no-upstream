#!/bin/bash
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d) || exit 2
trap 'rm -rf "$TMP"' EXIT
LOGF="$TMP/antibot.log"
pass=0
fail=0

ok() {
    if "$@"; then pass=$((pass+1)); else
        fail=$((fail+1)); echo "FAIL measure: $*" >&2
    fi
}

for i in 1 2 3 4 5; do
    printf '[2026-11-18 10:00:0%s] [antibot] ts=1 domain=old.test class=navigation id=o%s ip=172.64.1.1 ua=x action=allow reason=score=0 px=cloudflare pxv=true pxcv=false pxagg=true pxsrc=proxy_edge pxerr=proof_missing pxhops=- pxsp=- pxtls=proxy_edge pxpf=missing pxpz=-\n' "$i" "$i" >> "$LOGF"
    printf '[2026-11-18 11:00:0%s] [antibot] ts=2 domain=new.test class=navigation id=n%s ip=8.8.8.%s ua=y action=allow reason=score=0 px=cloudflare pxv=true pxcv=true pxagg=false pxsrc=cf-connecting-ip pxerr=- pxhops=1 pxsp=- pxtls=proxy_edge pxpf=signed_current pxpz=new.test\n' "$i" "$i" "$i" >> "$LOGF"
done

OUT=$(LOG="$LOGF" RCLI=/bin/true bash "$HERE/measure.sh" cf \
    "2026-11-18 10:30:00")
ok grep -q '^5$' <<<"$OUT"
ok grep -qE '^[[:space:]]*5 signed_current$' <<<"$OUT"
ok grep -q 'new.test' <<<"$OUT"
if grep -q 'old.test' <<<"$OUT"; then
    fail=$((fail+1)); echo "FAIL measure: row before marker leaked" >&2
else pass=$((pass+1)); fi

OUT2=$(LOG="$LOGF" RCLI=/bin/true bash "$HERE/measure.sh" cf \
    "[2026-11-18 10:30:00]")
ok grep -qE '^[[:space:]]*5 signed_current$' <<<"$OUT2"

LOG="$LOGF" RCLI=/bin/true bash "$HERE/measure.sh" cf bad-marker \
    >"$TMP/bad.out" 2>&1
rc=$?
if [ "$rc" -eq 2 ]; then pass=$((pass+1)); else
    fail=$((fail+1)); echo "FAIL measure: bad marker rc=$rc want=2" >&2
fi

echo "measure_test: $pass pass, $fail fail"
[ "$fail" -eq 0 ]
