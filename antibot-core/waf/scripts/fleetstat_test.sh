#!/bin/bash
# fleetstat_test.sh — oracle cho `fleetstat.sh`.
#
# `fleetstat.sh` quyet dinh huong xu ly su co, nen chinh no phai co oracle.
# Fixture dung dinh dang `logger.lua:968-974` tung byte, va co du ba bay that:
# cot ket thuc bang "ts=", dong nhi phan, va file da xoay vong.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/fleetstat.sh"
W=$(mktemp -d) || exit 2

cleanup() {
    local rc=$?
    rm -rf "$W"
    exit $rc
}
trap cleanup EXIT

pass=0
fail=0
ck() {
    if [ "$2" = "$3" ]; then
        echo "  OK   $1"; pass=$((pass + 1))
    else
        echo "  LOI  $1: mong=[$2] thuc=[$3]"; fail=$((fail + 1))
    fi
}

mkdir -p "$W/log" "$W/live/l7"
AL="$W/log/antibot.log"

LINE() { # LINE <epoch> <domain> <phan con lai>
    printf '[%s] [antibot] ts=%s domain=%s class=navigation %s\n' \
        "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "$3"
}

N=$(date +%s)
T=$((N - 600))
OLD=$((N - 86400))

# TINH TAY, cua so 60 phut:
#   12 dong [antibot] trong cua so.
#   domain: a.test 6, b.test 3, c.test 2, d.test 1   -> 4 domain
#   autp=gptbot tren a/b/c = 3 domain, 7 luot
#   autp=other  tren a     = 1 domain, 1 luot
#   autwould=true 4 dong; trong do autthr=true 2 dong
#   autthr theo tang: operator 2 ; vuot-ma-khong-chan: unknown 2
#   autuptime: 0.5, 2.0, 15.0 -> mau 3, >1s = 2, >10s = 1
{
  LINE $T a.test 'autp=gptbot auttier=operator opnet=openai autwould=true autthr=true autbreach=principal:short autdeg=false autuptime=0.500 action=throttled'
  LINE $T a.test 'autp=gptbot auttier=operator opnet=openai autwould=true autthr=true autbreach=principal:short autdeg=false autuptime=2.000 action=throttled'
  LINE $T a.test 'autp=gptbot auttier=operator opnet=openai autwould=false autthr=false autdeg=false autuptime=15.000 action=monitor'
  LINE $T a.test 'autp=gptbot auttier=operator opnet=openai autwould=false autthr=false autdeg=false action=allow'
  LINE $T a.test 'autp=other auttier=unknown autwould=true autthr=false autdeg=false action=allow'
  LINE $T a.test 'action=allow'
  LINE $T b.test 'autp=gptbot auttier=operator opnet=openai autwould=false autthr=false autdeg=false action=allow'
  LINE $T b.test 'autp=gptbot auttier=operator opnet=openai autwould=false autthr=false autdeg=true action=allow'
  LINE $T b.test 'auttier=unknown autwould=true autthr=false autdeg=false action=allow'
  LINE $T c.test 'autp=gptbot auttier=operator opnet=openai autwould=false autthr=false autdeg=false action=allow'
  LINE $T c.test 'action=block'
  LINE $T d.test 'action=allow'
  # BAY 1a: cot KET THUC bang ten cot khac (`subdomain=`, `xautp=`). Khong co
  # guard `(^|[[:space:]])` thi `field domain` se bat ca `subdomain=...` va
  # dem no nhu mot domain that. Dong nay CO ts= hop le nen no THUC SU vao
  # cua so — do la dieu lam phep thu co nghia.
  LINE $T e.test 'subdomain=KHONG-PHAI-DOMAIN xautp=KHONG-PHAI-PRINCIPAL action=allow'
  # BAY 1: cot ket thuc bang "ts=", KHONG co ts= that -> khong duoc thanh dong nao
  echo '[x] [antibot] sclients=1 xf_hits=1 domain=rac.test'
  echo '[x] [waf] rid=r exists=1 parts=1 domain=rac.test'
  # BAY 2: dong nhi phan -> grep phai DOC duoc, khong bo ca file
  printf 'binary\x00junk [antibot] ts=%s domain=bin.test action=allow\n' "$T"
  # Ngoai cua so
  LINE $OLD z.test 'action=allow'
} > "$AL"

# BAY 3: file da xoay vong
LINE $T gz.test 'action=allow' | gzip -c > "$W/log/antibot.log.1.gz"

echo '-- khong co enforcement --' > "$W/live/l7/automation_guard.lua"

# `FS_KEEP=/duong/dan` giu lai output tho cua moi lan goi — de soi khi mot
# phep thu bao sai ma chua ro loi o script hay o chinh phep thu.
run() {
    local o
    o=$(AL="$AL" LIVE="$W/live" bash "$SCRIPT" "${1:-60}" 2>&1)
    if [ -n "${FS_KEEP:-}" ]; then
        printf '===== run %s =====\n%s\n' "${1:-60}" "$o" >> "$FS_KEEP"
    fi
    printf '%s\n' "$o"
}

out=$(run 60); rc=$?

echo "── 1. doc dung nguon ────────────────────────────────"
ck "rc=0" "0" "$rc"
ck "in ra file .gz da doc" "yes" \
   "$(printf '%s' "$out" | grep -q 'antibot.log.1.gz' && echo yes || echo no)"
ck "khong in 'binary file matches'" "0" \
   "$(printf '%s' "$out" | grep -c 'binary file matches')"
# 13 dong LINE + 1 dong nhi phan + 1 dong .gz = 15
ck "dem dung 15 dong trong cua so" "15" \
   "$(printf '%s' "$out" | sed -n 's/^dong    : //p')"

echo "── 2. bay 'cot ket thuc bang ts=' ───────────────────"
ck "domain rac.test KHONG duoc dem" "0" \
   "$(printf '%s' "$out" | grep -c 'rac.test')"
ck "cot KET THUC bang ten cot khac khong bi dem nham" "0" \
   "$(printf '%s' "$out" | grep -cE 'KHONG-PHAI-(DOMAIN|PRINCIPAL)')"
ck "fixture co that dong moi nhu vay" "1" \
   "$(grep -c 'subdomain=KHONG-PHAI-DOMAIN' "$AL")"
ck "fixture co that 2 dong bay" "2" \
   "$(grep -cE 'sclients=1 xf_hits=1|exists=1 parts=1' "$AL")"

echo "── 3. xep hang domain + do tap trung ────────────────"
ck "a.test dung dau voi 6 luot" "6" \
   "$(printf '%s' "$out" | awk '/ a.test$/{print $1; exit}')"
ck "b.test 3 luot" "3" \
   "$(printf '%s' "$out" | awk '/ b.test$/{print $1; exit}')"
# a,b,c,d,e + bin.test + gz.test = 7 domain
ck "dem dung 7 domain" "7" \
   "$(printf '%s' "$out" | sed -n 's/.*so domain co luu luong *: //p')"
ck "dong ngoai cua so bi loai" "0" \
   "$(printf '%s' "$out" | grep -cE '(^|[^a-z])z\.test')"

echo "── 4. principal tren BAO NHIEU domain ───────────────"
ck "gptbot 7 luot" "7" \
   "$(printf '%s' "$out" | awk '/gptbot$/{print $1; exit}')"
ck "gptbot tren 3 domain" "3" \
   "$(printf '%s' "$out" | awk '/gptbot$/{print $2; exit}')"
ck "other tren 1 domain" "1" \
   "$(printf '%s' "$out" | awk '/ other$/{print $2; exit}')"

echo "── 5. cong phien ban enforce ────────────────────────"
ck "bao CHUA DEPLOY" "yes" \
   "$(printf '%s' "$out" | grep -q 'CHUA DEPLOY' && echo yes || echo no)"
ck "khong in so autthr khi chua deploy" "0" \
   "$(printf '%s' "$out" | grep -c 'autthr=true   (CHAN THAT)')"

printf 'local x = ctx.automation_throttled\n' > "$W/live/l7/automation_guard.lua"
out2=$(run 60)
ck "bao DA DEPLOY" "yes" \
   "$(printf '%s' "$out2" | grep -q 'DA DEPLOY' && echo yes || echo no)"
ck "autthr=true dem 2" "2" \
   "$(printf '%s' "$out2" | awk '/autthr=true   \(CHAN THAT\)/{print $NF}')"
ck "autwould=true dem 4" "4" \
   "$(printf '%s' "$out2" | sed -n 's/.*autwould=true (vuot han muc) *: *\([0-9]*\).*/\1/p')"
ck "tang bi chan la operator" "2" \
   "$(printf '%s' "$out2" | awk '/auttier=operator/{print $1; exit}')"
# `VUOT NHUNG KHONG CHAN` chi in khi thr == 0. O fixture nay thr=2 nen KHONG
# duoc in — canh bao do danh cho truong hop vuot ma khong chan duoc luot nao.
ck "khong canh bao nham khi da chan duoc" "0" \
   "$(printf '%s' "$out2" | grep -c 'VUOT NHUNG KHONG CHAN')"

echo "── 5b. canh bao VUOT MA KHONG CHAN ──────────────────"
# Day la trang thai dang lo nhat tren production: han muc bi vuot nhung khong
# luot nao bi chan — tang khong nam trong `enforce_tiers`, hoac meter degraded.
# Phai co fixture rieng, vi fixture chinh co thr=2 nen khong kich hoat duoc.
# Luu bang `cp` chu khong `$(cat ...)`: fixture co byte NUL va command
# substitution bo byte do kem mot canh bao, tuc ban "khoi phuc" KHAC ban goc.
cp "$AL" "$W/al.saved"
{
  LINE $T a.test 'autp=gptbot auttier=unknown autwould=true autthr=false autdeg=false action=allow'
  LINE $T b.test 'autp=gptbot auttier=unknown autwould=true autthr=false autdeg=true action=allow'
} > "$AL"
out_warn=$(run 60)
ck "co canh bao khi vuot ma khong chan" "yes" \
   "$(printf '%s' "$out_warn" | grep -q 'VUOT NHUNG KHONG CHAN' && echo yes || echo no)"
ck "chi ro tang nao vuot ma thoat" "2" \
   "$(printf '%s' "$out_warn" | awk '/auttier=unknown/{print $1; exit}')"
ck "meter degraded duoc dem" "1" \
   "$(printf '%s' "$out_warn" | awk '/^ *[0-9]+ true$/{print $1; exit}')"
cp "$W/al.saved" "$AL"

echo "── 6. thoi gian upstream ────────────────────────────"
ck "mau upstream = 3" "3" \
   "$(printf '%s' "$out2" | sed -n 's/.*mau=\([0-9]*\) .*/\1/p')"
ck "cham nhat 15s" "15.000s" \
   "$(printf '%s' "$out2" | sed -n 's/.*cham nhat=\([0-9.]*s\).*/\1/p')"
ck ">10s dem 1" "1" \
   "$(printf '%s' "$out2" | sed -n 's/.*>10s=\([0-9]*\) .*/\1/p')"

echo "── 7. dau vao xau ───────────────────────────────────"
ck "so phut rac -> rc=2" "2" \
   "$(AL="$AL" LIVE="$W/live" bash "$SCRIPT" abc >/dev/null 2>&1; echo $?)"
ck "so phut 0 -> rc=2" "2" \
   "$(AL="$AL" LIVE="$W/live" bash "$SCRIPT" 0 >/dev/null 2>&1; echo $?)"
ck "khong co file -> rc=2" "2" \
   "$(AL="$W/khong-co" LIVE="$W/live" bash "$SCRIPT" 60 >/dev/null 2>&1; echo $?)"

echo "── 8. dan so 0 ──────────────────────────────────────"
: > "$AL"
rm -f "$W/log/antibot.log.1.gz"
out_empty=$(run 60); rc_empty=$?
ck "dan so 0 -> rc=0, khong vo" "0" "$rc_empty"
ck "noi ro khong co dong nao" "yes" \
   "$(printf '%s' "$out_empty" | grep -q 'khong co dong nao' && echo yes || echo no)"
ck "khong in ty le tren dan so 0" "0" \
   "$(printf '%s' "$out_empty" | grep -c '%  ')"

echo
echo "fleetstat_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
