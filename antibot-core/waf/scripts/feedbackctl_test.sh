#!/bin/bash
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
T=$(mktemp -d /tmp/feedbackctl-test.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
LOG="$T/antibot.log"
STATE="$T/state"
SAFE="$T/safe"
pass=0 fail=0

ok() {
    local name=$1; shift
    if "$@"; then pass=$((pass+1))
    else fail=$((fail+1)); echo "FAIL feedbackctl: $name" >&2; fi
}
has() {
    grep -qE "$2" "$1"
}
capture() {
    local state=$1; shift
    NOW=2000 FEEDBACKCTL_TEST_MODE=1 ANTIBOT_FEEDBACK_DIR="$state" \
      ANTIBOT_FEEDBACK_LOG="$LOG" RESTY="$RESTY" \
      bash "$HERE/feedbackctl.sh" capture "$@"
}

cat > "$LOG" <<'EOF'
[x] [antibot] ts=1950 domain=shop.test class=navigation id=h1 ip=1.1.1.1 action=allow pver=p1+aaaa dschema=1 dkind=policy dup=true autcwould=true epwould=false sgwould=false
[x] [antibot] ts=1960 domain=shop.test class=navigation id=b1 ip=2.2.2.2 action=challenge pver=p1+aaaa dschema=1 dkind=challenge dup=false autcwould=false epwould=true sgwould=false
[x] [antibot] ts=1970 domain=shop.test class=navigation id=c1 ip=3.3.3.3 action=throttled pver=p1+aaaa dschema=1 dkind=capacity dup=false autcwould=false epwould=false dgpswould=true
[x] [antibot] ts=1980 domain=other.test class=navigation id=x1 ip=4.4.4.4 action=allow pver=p1+aaaa dschema=1 dkind=policy dup=true autcwould=false epwould=false
EOF

capture "$STATE" human_fp 1900 1999 30 tester "known customer" \
  domain=shop.test id=h1 > "$T/c1"
rc=$?
ok "capture human_fp succeeds" test "$rc" -eq 0
ok "capture marker" has "$T/c1" '^FEEDBACK_CAPTURED .*label=human_fp rows=1 '

capture "$STATE" true_bot 1900 1999 30 tester "confirmed scanner" \
  domain=shop.test id=b1 > "$T/c2"
ok "capture true_bot succeeds" test "$?" -eq 0
ok "two immutable bundles" test "$(find "$STATE" -name manifest.json | wc -l)" -eq 2
ok "evidence private" test "$(stat -c %a "$(find "$STATE" -name evidence.log | head -1)")" = 600

NOW=2000 ANTIBOT_FEEDBACK_DIR="$STATE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" list > "$T/list"
ok "list summary" has "$T/list" 'feedback active=2 expired=0 true_bot=1 legit_automation=0 human_fp=1 capacity_only=0'

if NOW=2000 ANTIBOT_FEEDBACK_DIR="$STATE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" replay > "$T/replay" 2>&1; then
    replay_rc=0
else
    replay_rc=$?
fi
ok "human FP candidate blocks replay" test "$replay_rc" -eq 1
ok "block marker is explicit" has "$T/replay" '^REPLAY_BLOCK human_fp_candidate_rows=1$'
ok "axis is attributable" has "$T/replay" '^axis=automation_concurrency candidate_rows=1$'

capture "$SAFE" true_bot 1900 1999 1 tester "confirmed scanner" \
  domain=shop.test id=b1 > /dev/null
NOW=2000 ANTIBOT_FEEDBACK_DIR="$SAFE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" replay > "$T/safe-replay"
ok "safe replay completes" has "$T/safe-replay" '^REPLAY_OK active=1 expired=0 human_fp_candidate_rows=0$'
ok "absence of human FP is not called safe" has "$T/safe-replay" '^REPLAY_COVERAGE human_fp=0 note=no_false_positive_claim$'

NOW=88401 ANTIBOT_FEEDBACK_DIR="$SAFE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" status > "$T/expired"
ok "TTL removes label from active evidence" has "$T/expired" '^feedback active=0 expired=1 true_bot=0 legit_automation=0 human_fp=0 capacity_only=0$'

evidence=$(find "$SAFE" -name evidence.log | head -1)
printf 'tamper\n' >> "$evidence"
if NOW=2000 ANTIBOT_FEEDBACK_DIR="$SAFE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" replay > "$T/tamper" 2>&1; then
    tamper_rc=0
else
    tamper_rc=$?
fi
ok "tampered evidence rejected" test "$tamper_rc" -eq 2
ok "tamper reason visible" has "$T/tamper" 'evidence digest mismatch'

NOW=88401 FEEDBACKCTL_TEST_MODE=1 ANTIBOT_FEEDBACK_DIR="$SAFE" RESTY="$RESTY" \
  bash "$HERE/feedbackctl.sh" prune-expired > "$T/prune"
ok "expired evidence pruned explicitly" has "$T/prune" '^FEEDBACK_PRUNED expired=1$'
ok "prune leaves no incident directory" test "$(find "$SAFE" -name manifest.json | wc -l)" -eq 0

if capture "$T/none" human_fp 1900 1999 30 tester "no match" domain=missing.test \
  > "$T/none.out" 2>&1; then
    none_rc=0
else
    none_rc=$?
fi
ok "empty capture rejected" test "$none_rc" -eq 1
ok "empty capture explains why" has "$T/none.out" 'khong co dong nao khop'

echo "feedbackctl_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
