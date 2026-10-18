#!/bin/bash
# epstat_test.sh — oracle cho `epstat.sh`.
#
# `epstat.sh` la cong quyet dinh production: no tra loi "co promote inflight
# sang enforce duoc chua". Mot lenh do hong tra ra so TRONG-CO-LY, nen chinh no
# phai co oracle: dung dau vao GIA phu kin tung nhanh, TINH TAY ket qua mong
# doi, so, roi DOT BIEN de chac phep do that su phan biet duoc.
#
# Bon bay cua `epstat.sh` deu co ca o day: cong phien ban, xoay vong log, loc
# theo epoch (ke ca mui gio), va mau so.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/epstat.sh"
W=$(mktemp -d) || exit 2

# Trap phai GIU LAI ma thoat. `trap 'rm -rf "$W"' EXIT` thi `rm` chay SAU lenh
# cuoi va ma thoat cua `rm` (thanh cong) de len ma thoat that cua suite: do
# duoc bang `bash -x`, thay `[ 2 -eq 0 ]` tra 1 roi `rm -rf` dua rc ve 0, nen
# `run.sh` bao xanh du co 2 phep thu hong. Dung ho loi voi `sh_suite` da ghim
# o `run.sh:44` (process substitution lam mat `$?`).
cleanup() {
    local rc=$?
    rm -rf "$W"
    exit $rc
}
trap cleanup EXIT

pass=0
fail=0
ck() { # ck <ten> <mong doi> <thuc te>
    if [ "$2" = "$3" ]; then
        echo "  OK   $1"
        pass=$((pass + 1))
    else
        echo "  LOI  $1: mong=[$2] thuc=[$3]"
        fail=$((fail + 1))
    fi
}

mkdir -p "$W/new/waf" "$W/new/l7" "$W/new/async" \
         "$W/old/waf" "$W/old/l7" "$W/old/async" "$W/log"

# ── Cay deploy GIA: ban MOI (gop scope theo docroot) ─────────────────
cat > "$W/new/waf/endpoint_policy.lua" <<'EOF'
local function scope_id(docroot)
    return ngx.md5(docroot):sub(1, 16)
end
ctx.endpoint_scope = scope_id(docroot)
EOF
echo '-- endpoint guard' > "$W/new/l7/endpoint_guard.lua"
echo 'epif= epwould= epcause= epshape= epsrc= epproof= epmode=' \
    > "$W/new/async/logger.lua"

# ── Cay deploy GIA: ban CU (con chia theo prefix) ────────────────────
cat > "$W/old/waf/endpoint_policy.lua" <<'EOF'
local function scope_id(docroot, prefix)
    return ngx.md5(docroot .. "|" .. prefix):sub(1, 16)
end
ctx.endpoint_scope = scope_id(docroot, prefix)
EOF
cp "$W/new/l7/endpoint_guard.lua" "$W/old/l7/"
cp "$W/new/async/logger.lua"      "$W/old/async/"

# ── Log gia ──────────────────────────────────────────────────────────
# Moc lay GAN hien tai, vi `find -newermt` loai file cu hon moc. Dong log sinh
# KEM OFFSET THAT cua may (`%z`) de bat bug mui gio: bo offset thi cua so lech
# dung bang offset do (7 tieng tren fleet nay).
#
# TINH TAY, tinh tu moc + SETTLE:
#   truoc moc : 3 dong ep=   -> phai BI LOAI het
#   sau moc   : 7 dong ep=   -> epif 1/3, 2/3, 3/3, 4/3, 5/3, 1/6, 7/3
#               would=true   -> 3 dong (4/3, 5/3, 7/3) = 42.9% cua 7
#               vuot tran    -> 4/3, 5/3, 7/3  (3/3 KHONG vuot)
#               epif=1/3     -> 1 luot (dong 1/6 la endpoint KHAC)
#   1 dong khong co ep=      -> khong duoc lam sai mau so
DEPLOY=$(( $(date +%s) - 4200 ))
SETTLE=0
MOC=$DEPLOY
# DINH DANG PHAI GIONG `logger.lua:968-974` TUNG BYTE:
#   "[%Y-%m-%d %H:%M:%S] [antibot] ts=<epoch> domain=... "
# Ban fixture dau dung `ts=a [18/Oct/2026:...]` theo kieu nginx access log —
# vua sai cot `ts=` (chu cai thay vi epoch) vua them dau thoi gian khong ton
# tai. Vi fixture va bo loc CUNG sai mot kieu nen 34 phep thu van xanh trong
# khi tren may that bo loc vut sach ca file. Fixture phai lay dinh dang tu NOI
# GHI, khong tu tri nho.
LINE() { # LINE <epoch> <phan con lai>
    printf '[%s] [antibot] ts=%s domain=inachau.net class=navigation %s\n' \
        "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}
T_BEFORE=$((MOC - 3600))
T_AFTER1=$((MOC + 600))
T_AFTER2=$((MOC + 1200))

L="$W/log/antibot.log"
E='epsrc=pretty epproof=wp epmode=shadow'
{
  LINE $T_BEFORE "ep=wp_oembed_embed epif=9/3 epwould=true epcause=inflight epshape=ok $E"
  LINE $T_BEFORE "ep=wp_oembed_embed epif=8/3 epwould=true epcause=inflight epshape=ok $E"
  LINE $T_BEFORE "ep=wp_oembed_embed epif=1/3 epwould=false epcause=- epshape=ok $E"
  LINE $T_AFTER1 "ep=wp_oembed_embed epif=1/3 epwould=false epcause=- epshape=ok $E"
  LINE $T_AFTER1 "ep=wp_oembed_embed epif=2/3 epwould=false epcause=- epshape=ok $E"
  LINE $T_AFTER1 "ep=wp_oembed_embed epif=3/3 epwould=false epcause=- epshape=ok $E"
  LINE $T_AFTER2 "ep=wp_oembed_embed epif=4/3 epwould=true epcause=inflight epshape=ok $E rown=0.00"
  LINE $T_AFTER2 "ep=wp_oembed_embed epif=5/3 epwould=true epcause=inflight epshape=bad_url $E rown=0.00"
  LINE $T_AFTER2 "ep=wp_users_collection epif=1/6 epwould=false epcause=- epshape=scan epsrc=rest_route epproof=wp epmode=shadow"
  LINE $T_AFTER2 "ep=wp_oembed_embed epif=7/3 epwould=true epcause=inflight epshape=ok $E rown=0.00"
  LINE $T_AFTER2 "reason=allow score=1.0 rown=0.80"
} > "$L"

echo "$DEPLOY" > "$W/log/.deploy_ts"

run() { # run <new|old> [moc]
    LIVE="$W/$1" STAMP="$W/log/.deploy_ts" SETTLE=0 \
        bash "$SCRIPT" "${2:-}" "$L" 2>&1
}

echo "── 1. cong phien ban ────────────────────────────────"
out_old=$(run old); rc_old=$?
ck "ban cu bi cong chan (rc=3)" "3" "$rc_old"
ck "cong neu ro ly do" "yes" \
   "$(printf '%s' "$out_old" | grep -q 'GATE FAIL' && echo yes || echo no)"
ck "ban cu KHONG in so epif nao" "0" \
   "$(printf '%s' "$out_old" | grep -c 'epif=')"
ck "cong giai thich so bi nhan len" "yes" \
   "$(printf '%s' "$out_old" | grep -q 'nhan len' && echo yes || echo no)"

out_new=$(run new); rc_new=$?
ck "ban moi qua cong (rc=0)" "0" "$rc_new"
ck "cong bao OK" "yes" \
   "$(printf '%s' "$out_new" | grep -q 'GATE OK' && echo yes || echo no)"

echo "── 2. loc theo cot ts= (epoch san trong log) ────────"
# Phep thu NAY la cai da thieu: bo loc doi dinh dang nginx
# (`[dd/Mon/yyyy:HH:MM:SS +0700]`) khong khop dong nao cua `antibot.log` nen
# vut sach ca file, ma fixture cu cung sai y het nen khong ai bat duoc.
ck "dong fixture dung dinh dang logger.lua" "yes" \
   "$(head -1 "$L" | grep -qE '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}\] \[antibot\] ts=[0-9]+ ' \
      && echo yes || echo no)"
ck "fixture KHONG chua dinh dang nginx" "0" \
   "$(grep -cE '\[[0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:' "$L")"
ck "dem dung 7 dong ep= sau moc" "7" \
   "$(printf '%s' "$out_new" | sed -n 's/^dong co ep= *: *//p')"
# Neu so sanh CHUOI, hoac bo offset, thi dong truoc moc lot vao -> thay 9/3, 8/3
ck "khong lot dong truoc moc" "yes" \
   "$(printf '%s' "$out_new" | grep -qE 'epif=9/3|epif=8/3' && echo no || echo yes)"
ck "moc doc tu .deploy_ts" "yes" \
   "$(printf '%s' "$out_new" | grep -q '.deploy_ts' && echo yes || echo no)"

echo "── 3. phan phoi epif + danh dau vuot tran ───────────"
ck "epif=1/3 dem 1 luot (1/6 la endpoint khac)" "1" \
   "$(printf '%s' "$out_new" | awk '/epif=1\/3/{print $1}' | head -1)"
ck "epif=4/3 duoc danh dau VUOT" "yes" \
   "$(printf '%s' "$out_new" | grep 'epif=4/3' | grep -q 'VUOT' && echo yes || echo no)"
ck "epif=3/3 KHONG bi danh dau vuot" "yes" \
   "$(printf '%s' "$out_new" | grep 'epif=3/3' | grep -q 'VUOT' && echo no || echo yes)"
ck "epif=1/6 KHONG bi danh dau vuot" "yes" \
   "$(printf '%s' "$out_new" | grep 'epif=1/6' | grep -q 'VUOT' && echo no || echo yes)"

echo "── 4. mau so: chi dong co ep= ───────────────────────"
ck "epwould=true dem 3" "3" \
   "$(printf '%s' "$out_new" | awk '/epwould=true: /{print $2}')"
ck "ti le tinh tren 7, khong tren 8" "42.9%" \
   "$(printf '%s' "$out_new" | grep -oE '= [0-9.]+%' | tr -d '= ')"

echo "── 5. shape / mode / proof tach rieng ───────────────"
ck "thay epshape=bad_url" "yes" \
   "$(printf '%s' "$out_new" | grep -q 'epshape=bad_url' && echo yes || echo no)"
ck "thay epshape=scan" "yes" \
   "$(printf '%s' "$out_new" | grep -q 'epshape=scan' && echo yes || echo no)"
ck "thay epsrc=rest_route" "yes" \
   "$(printf '%s' "$out_new" | grep -q 'epsrc=rest_route' && echo yes || echo no)"

echo "── 6. cong FP: khach that trong tap would ───────────"
# Ba dong would=true deu rown=0.00; dong rown=0.80 KHONG co ep= nen khong tinh.
ck "would=true dem 3" "3" \
   "$(printf '%s' "$out_new" | awk '/would=true  *: /{print $NF}')"
ck "khong co cookie that trong tap would" "0" \
   "$(printf '%s' "$out_new" | awk '/co cookie that: /{print $NF}')"
ck "neu ro khong co khach that" "yes" \
   "$(printf '%s' "$out_new" | grep -q 'KHONG co khach mang cookie that' \
      && echo yes || echo no)"

echo "── 7. settle: chua het thi khong doc ────────────────"
out_settle=$(LIVE="$W/new" STAMP="$W/log/.deploy_ts" SETTLE=999999 \
    bash "$SCRIPT" "" "$L" 2>&1)
ck "settle chua het -> bao CHUA TOI" "yes" \
   "$(printf '%s' "$out_settle" | grep -q 'CHUA TOI' && echo yes || echo no)"
ck "settle chua het -> khong in epif" "0" \
   "$(printf '%s' "$out_settle" | grep -c 'epif=')"

echo "── 8. xoay vong log ─────────────────────────────────"
gzip -c "$L" > "$W/log/antibot.log.1.gz"
: > "$L"                                    # file hien tai TRONG
touch -d "@$((MOC + 1500))" "$W/log/antibot.log.1.gz"
touch -d "@$((MOC - 7200))" "$L"            # file song CU HON moc
out_rot=$(run new)
ck "doc duoc du lieu trong .gz" "7" \
   "$(printf '%s' "$out_rot" | sed -n 's/^dong co ep= *: *//p')"
ck "in ra ten file da doc" "yes" \
   "$(printf '%s' "$out_rot" | grep -q 'antibot.log.1.gz' && echo yes || echo no)"
# Phep thu chuoi con (`case $F in *"$LOG"*`) se coi .gz la "da co file hien
# tai" va bo file song. O day file song trong nen khong doi ket qua, nhung phai
# thay no trong danh sach doc.
ck "file hien tai van nam trong danh sach doc" "yes" \
   "$(printf '%s' "$out_rot" | grep -qE "   $L\$" && echo yes || echo no)"

echo "── 9. dan so 0 ──────────────────────────────────────"
rm -f "$W/log/antibot.log.1.gz"
: > "$L"
touch -d "@$((MOC + 100))" "$L"
out_empty=$(run new); rc_empty=$?
ck "khong co row -> rc=0, khong vo" "0" "$rc_empty"
ck "noi ro chua co row nao" "yes" \
   "$(printf '%s' "$out_empty" | grep -q 'chua co row endpoint nao' \
      && echo yes || echo no)"
ck "khong in ti le tren dan so 0" "0" \
   "$(printf '%s' "$out_empty" | grep -c 'epwould=true:')"

echo "── 10. DOT BIEN: cong phai that su phan biet ────────"
cp "$W/new/waf/endpoint_policy.lua" "$W/keep.lua"
sed -i 's/local function scope_id(docroot)/local function scope_id(dr, pfx)/' \
    "$W/new/waf/endpoint_policy.lua"
rc_mut=$(run new >/dev/null 2>&1; echo $?)
ck "dot bien scope_id bi bat" "3" "$rc_mut"
cp "$W/keep.lua" "$W/new/waf/endpoint_policy.lua"

echo 'epif= epwould= epcause= epshape= epsrc= epproof=' \
    > "$W/new/async/logger.lua"
out_mut2=$(run new); rc_mut2=$?
ck "dot bien thieu cot epmode bi bat" "3" "$rc_mut2"
ck "cong chi ro cot thieu" "yes" \
   "$(printf '%s' "$out_mut2" | grep -q 'epmode' && echo yes || echo no)"
echo 'epif= epwould= epcause= epshape= epsrc= epproof= epmode=' \
    > "$W/new/async/logger.lua"

# Moc khong phai so -> phai tu choi, khong coi nhu 0 (= doc ca file)
out_bad=$(LIVE="$W/new" STAMP="$W/log/.deploy_ts" SETTLE=0 \
    bash "$SCRIPT" "khong-phai-so" "$L" 2>&1); rc_bad=$?
ck "moc rac bi tu choi (rc=2)" "2" "$rc_bad"
ck "moc rac khong bi coi nhu 0" "0" \
   "$(printf '%s' "$out_bad" | grep -c 'epif=')"

echo
echo "epstat_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
