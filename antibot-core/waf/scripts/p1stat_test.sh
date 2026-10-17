#!/bin/bash
# Fixture tu kiem cho p1stat.sh. Khong doc log that, khong ghi Redis.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
P1STAT="$HERE/p1stat.sh"
T=$(mktemp -d /tmp/p1stat-test.XXXXXX)
trap 'rm -rf "$T"' EXIT

ok=0
bad=0

pass() { echo "  OK  $1"; ok=$((ok + 1)); }
fail() { echo "  LOI $1"; bad=$((bad + 1)); }

assert_has() {
    name=$1
    needle=$2
    file=$3
    if grep -Fq "$needle" "$file"; then pass "$name"; else
        fail "$name (thieu: $needle)"
        sed -n '/P1.3\/P1.4/,$p' "$file"
    fi
}

make_tree() {
    dir=$1
    gate=${2:-full}
    mkdir -p "$dir/live/async" "$dir/log"
    if [ "$gate" = "full" ]; then
        printf '%s\n' 'iptev ipku held_cookie ideg cbcand cblastn cblasth' > "$dir/live/async/logger.lua"
    else
        printf '%s\n' 'iptev ipku held_cookie ideg cbcand cblastn' > "$dir/live/async/logger.lua"
    fi
    printf '%s\n' "$D" > "$dir/stamp"
}

row() {
    # row <ts> <candidate> <lastn> <lasth> <transition>
    printf '[2026-10-17 00:00:00] [antibot] ts=%s domain=fixture.test action=allow cb=closed cbmode=shadow cbcause=- cbwould=false cbcand=%s cblastn=%s cblasth=%s cbtrans=%s cbdeg=false cbnosample=false\n' \
        "$1" "$2" "$3" "$4" "$5"
}

run_stat() {
    dir=$1
    set +e
    LIVE="$dir/live" STAMP="$dir/stamp" bash "$P1STAT" "$dir/log/antibot.log" > "$dir/out" 2>&1
    RC=$?
    set -e
}

set -e
D=$(( $(date +%s) - 120 ))

# Ca xanh: clear_recent nam trong file .gz, set/confirm nam trong file hien tai.
# Co tinh dat mtime file hien tai CU hon moc. Neu phep membership nham
# `antibot.log.1.gz` la `antibot.log`, hai dong nay se bien mat va rows chi con 1.
G="$T/good"
make_tree "$G"
row $((D + 10)) clear_recent 9 0 - | gzip -c > "$G/log/antibot.log.1.gz"
{
    row $((D + 20)) set 8 1 -
    row $((D + 21)) confirm 7 2 'closed>open'
} > "$G/log/antibot.log"
touch -d "@$((D - 10))" "$G/log/antibot.log"
run_stat "$G"
[ "$RC" -eq 0 ] && pass "fixture current + rotated tra rc=0" || fail "fixture xanh tra rc=$RC"
assert_has "doc ca file hien tai co mtime cu" "rows=3 schema=3 missing=0" "$G/out"
assert_has "dem du ba candidate" "set=1 confirm=1 clear_recent=1" "$G/out"
assert_has "freshness xanh" "bad_set=0 bad_confirm=0 degraded=0" "$G/out"

# set tren completed-second khong co hard la vi pham arm gate.
S="$T/bad-set"
make_tree "$S"
row $((D + 30)) set 9 0 - > "$S/log/antibot.log"
run_stat "$S"
[ "$RC" -eq 1 ] && pass "set stale lam p1stat fail" || fail "set stale can rc=1, nhan rc=$RC"
assert_has "set stale duoc dem" "bad_set=1 bad_confirm=0" "$S/out"

# confirm cung phai co bang chung tuoi rieng, khong duoc dung candidate cu.
C="$T/bad-confirm"
make_tree "$C"
row $((D + 40)) confirm 1 0 'closed>open' > "$C/log/antibot.log"
run_stat "$C"
[ "$RC" -eq 1 ] && pass "confirm stale lam p1stat fail" || fail "confirm stale can rc=1, nhan rc=$RC"
assert_has "confirm stale duoc dem" "bad_set=0 bad_confirm=1" "$C/out"

# Schema thieu khong duoc hien thanh so 0 hop le.
M="$T/missing-schema"
make_tree "$M"
printf '[antibot] ts=%s domain=fixture.test cb=closed cbcand=clear_recent cblastn=9 cbdeg=false cbnosample=false\n' \
    $((D + 50)) > "$M/log/antibot.log"
run_stat "$M"
[ "$RC" -eq 1 ] && pass "dong thieu schema lam p1stat fail" || fail "schema thieu can rc=1, nhan rc=$RC"
assert_has "schema thieu duoc dem" "rows=1 schema=0 missing=1" "$M/out"

# Cay runtime cu phai dung o cong kiem, truoc khi in cac so vo nghia.
V="$T/old-version"
make_tree "$V" old
row $((D + 60)) - - - - > "$V/log/antibot.log"
run_stat "$V"
[ "$RC" -eq 3 ] && pass "logger cu bi chan boi cong phien ban" || fail "logger cu can rc=3, nhan rc=$RC"
assert_has "cong chi ro cot thieu" "CONG KIEM SAI" "$V/out"
assert_has "cong phien ban co cblasth" "cblasth" "$V/out"

echo
echo "p1stat_test: $ok OK, $bad LOI"
[ "$bad" -eq 0 ]
