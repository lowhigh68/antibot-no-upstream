#!/bin/bash
# autthr_test.sh — oracle cho autthr.sh.
#
# Phep thu quan trong nhat la BAY DA LAM HONG ket luan ngay 18-10: dong co
# autaxis=fleet nhung autthr=false. Neu script dem theo autaxis thi
# ahrefsbot/bingbot se hien ra nhu da bi chan, trong khi chung khong he bi.
#
# Dau vao gia phu tung nhanh, TINH TAY ket qua, so, roi dot bien.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$HERE/autthr.sh"
W=$(mktemp -d) || exit 2

# Trap phai GIU LAI ma thoat: "trap 'rm -rf' EXIT" thi rm chay sau lenh cuoi
# va ma thoat cua no de len ma thoat THAT cua suite (xem p1stat_test.sh).
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

mkdir -p "$W/log"
L="$W/log/antibot.log"

# Dinh dang PHAI giong logger.lua tung byte o cac cot script doc.
LINE() { # LINE <epoch> <principal> <tier> <would> <thr> <breach> <axis> <fs> <fl> <uptime>
    printf '[%s] [antibot] ts=%s domain=a.test class=navigation aut=1 autp=%s auttier=%s autfs=%s autfl=%s autwould=%s autuse=90 autaxis=%s autdeg=false autthr=%s autbreach=%s autuptime=%s\n' \
        "$(date -d "@$1" '+%Y-%m-%d %H:%M:%S')" "$1" "$2" "$3" "$8" "$9" "$4" "$7" "$5" "$6" "${10}"
}

N=$(date +%s)
T=$((N - 600))
OLD=$((N - 200 * 3600))

# TINH TAY:
#   gptbot       : 4 dong, 3 bi chan (autthr=true), breach dau = fleet:short
#                  autfs max 18.0, autfl max 62.0, uptime (5+6+7+8)/4 = 6.50
#   oai-searchbot: 1 dong, 1 bi chan, breach dau = fleet:long
#   ahrefsbot    : 1 dong, autaxis=fleet NHUNG autthr=false, autwould=false
#                  -> BAY: dem theo autaxis se ra 1, dem theo autthr ra 0
#   claudebot    : 1 dong, autwould=true nhung autthr=false (tang quan sat)
#   curl/unknown : 1 dong, autthr=false  -> muc 4 phai bao OK
#   tong autwould=true : gptbot 3 + oai 1 + claudebot 1 = 5
#   tong autthr=true   : gptbot 3 + oai 1               = 4
#   autbreach tach phay: fleet:short 3, server:short 1 (gptbot dong 3 co 2 truc)
#                        fleet:long 1
{
  LINE $T gptbot        operator true true  'fleet:short'              fleet 12.0 40.0 5.0
  LINE $T gptbot        operator true true  'fleet:short'              fleet 15.0 55.0 6.0
  LINE $T gptbot        operator true true  'fleet:short,server:short' fleet 18.0 62.0 7.0
  LINE $T gptbot        operator false false '-'                       principal 3.0 9.0 8.0
  LINE $T oai-searchbot operator true true  'fleet:long'               fleet 9.0 61.0 2.0
  # BAY: autaxis=fleet ma KHONG bi chan, va cung khong vuot han muc.
  LINE $T ahrefsbot     unknown  false false '-'                       fleet 1.0 2.0 0.5
  # Tang quan sat: vuot han muc nhung khong bi chan.
  LINE $T claudebot     operator true false 'fleet:short'              fleet 4.0 16.0 1.0
  LINE $T curl-client   unknown  false false '-'                       principal 1.0 1.0 0.3
  # Ngoai moc -> phai bi loai.
  LINE $OLD gptbot      operator true true  'fleet:short'              fleet 99.0 99.0 9.0
  # BAY: cot ket thuc bang "ts=" ma KHONG co ts= that. Phai bi loai boi neo.
  echo '[2026-10-18 09:00:00] [antibot] aut=1 autp=bay auttier=operator sclients=1 xf_hits=1 autthr=true autbreach=fleet:short'
  # BAY: byte nhi phan. Do duoc voi GNU grep 3.0, ca khi doc tu FILE lan tu
  # PIPE: thieu `-a` thi grep chi tra 1/3 dong khop. Khong co dong nay trong
  # fixture thi dot bien "bo -a" song sot va phep thu vo nghia.
  printf '[2026-10-18 09:00:00] [antibot] ts=%s domain=a.test aut=1 autp=nhiphan auttier=operator autfs=1.0 autfl=1.0 autwould=false autuse=1 autaxis=principal autdeg=false autthr=false autbreach=- autuptime=0.1 bin\000junk\n' "$T"
  # Dong khong co aut=1 -> khong phai automation, phai bi loai o grep.
  echo '[2026-10-18 09:00:00] [antibot] ts=1760000000 domain=b.test class=navigation action=allow'
} > "$L"

run() { LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/khong-co" bash "$SCRIPT" "${1:-60}" 2>&1; }

out=$(run 60); rc=$?

echo "-- 1. doc nguon + loc moc ---------------------------"
ck "rc=0" "0" "$rc"
# 8 dong trong moc. Dong OLD bi cutoff; dong bay "sclients=1" bi neo ts= loai;
# dong khong co aut=1 bi grep loai.
ck "dong = 9 (ke ca dong co byte nhi phan)" "9" "$(printf '%s' "$out" | sed -n 's/^dong *: *//p')"
ck "fixture co that 2 dong bay" "2" \
   "$(grep -acE 'autp=bay|domain=b.test' "$L")"

echo "-- 2. autthr vs autwould ----------------------------"
ck "autwould=true -> 5" "5" \
   "$(printf '%s' "$out" | awk '$1 == "autwould=true" {print $3}')"
ck "autthr=true -> 4" "4" \
   "$(printf '%s' "$out" | awk '$1 == "autthr=true" {print $3}')"
ck "autdeg=true -> 0" "0" \
   "$(printf '%s' "$out" | awk '$1 == "autdeg=true" {print $3}')"
ck "noi ro chenh 1 dong would-khong-thr" "yes" \
   "$(printf '%s' "$out" | grep -q 'chenh 1 dong' && echo yes || echo no)"

echo "-- 3. BAY: autaxis=fleet ma KHONG bi chan -----------"
# Day la phep thu quyet dinh. ahrefsbot co autaxis=fleet; neu script dem theo
# autaxis thi no se xuat hien o muc 3 (danh sach bi chan).
ck "ahrefsbot KHONG o muc 'ai bi chan'" "0" \
   "$(printf '%s' "$out" | sed -n '/^3\. AI BI CHAN/,/^4\./p' | grep -c 'ahrefsbot')"
ck "fixture co that dong autaxis=fleet autthr=false" "2" \
   "$(grep -ac 'autaxis=fleet autdeg=false autthr=false' "$L")"
ck "gptbot CO o muc 'ai bi chan'" "1" \
   "$(printf '%s' "$out" | sed -n '/^3\. AI BI CHAN/,/^4\./p' | grep -c 'gptbot')"

echo "-- 4. autbreach tach dau phay -----------------------"
ck "fleet:short dem 4 (3 gptbot + 1 claudebot vuot ma khong bi chan)" "4" \
   "$(printf '%s' "$out" | sed -n '/^2\. TRUC NAO VUOT/,/^3\./p' \
      | awk '$2 == "fleet:short" {print $1}')"
ck "server:short dem 1" "1" \
   "$(printf '%s' "$out" | sed -n '/^2\. TRUC NAO VUOT/,/^3\./p' \
      | awk '$2 == "server:short" {print $1}')"
ck "fleet:long dem 1" "1" \
   "$(printf '%s' "$out" | sed -n '/^2\. TRUC NAO VUOT/,/^3\./p' \
      | awk '$2 == "fleet:long" {print $1}')"

echo "-- 5. rao chan FP -----------------------------------"
ck "unknown bi chan = 0, bao OK" "yes" \
   "$(printf '%s' "$out" | grep -qE '^ +unknown +bi chan: 0 +OK' && echo yes || echo no)"
ck "khong co canh bao !!" "0" \
   "$(printf '%s' "$out" | sed -n '/^4\. RAO CHAN FP/,/^5\./p' | grep -c '!!')"

echo "-- 6. tai that theo principal -----------------------"
g=$(printf '%s' "$out" | sed -n '/^5\. TAI THAT/,$p' | awk '$1 == "gptbot"')
ck "gptbot 4 luot" "4" "$(printf '%s' "$g" | awk '{print $2}')"
ck "gptbot chan 3" "3" "$(printf '%s' "$g" | awk '{print $3}')"
ck "gptbot autfs max 18.0" "18.0" "$(printf '%s' "$g" | awk '{print $6}')"
ck "gptbot autfl max 62.0" "62.0" "$(printf '%s' "$g" | awk '{print $7}')"
ck "gptbot uptime TB 6.50s" "6.50s" "$(printf '%s' "$g" | awk '{print $8}')"
ck "perplexitybot khong co luot nao" "yes" \
   "$(printf '%s' "$out" | grep -q 'perplexitybot .*khong co luot nao' && echo yes || echo no)"

echo "-- 7. dau vao xau -----------------------------------"
ck "so phut rac -> rc=2" "2" \
   "$(LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" abc >/dev/null 2>&1; echo $?)"
ck "so phut 0 -> rc=2" "2" \
   "$(LOGDIR="$W/log" BASE=antibot.log bash "$SCRIPT" 0 >/dev/null 2>&1; echo $?)"
ck "thu muc khong ton tai -> rc=2" "2" \
   "$(LOGDIR="$W/khong-co" BASE=antibot.log bash "$SCRIPT" 60 >/dev/null 2>&1; echo $?)"
mkdir -p "$W/rong"
ck "thu muc rong -> rc=2" "2" \
   "$(LOGDIR="$W/rong" BASE=antibot.log bash "$SCRIPT" 60 >/dev/null 2>&1; echo $?)"

echo "-- 8. dan so 0 --------------------------------------"
mkdir -p "$W/cu"
LINE $OLD gptbot operator true true 'fleet:short' fleet 9.0 9.0 1.0 > "$W/cu/antibot.log"
out_old=$(LOGDIR="$W/cu" BASE=antibot.log DEPLOY_TS="$W/khong-co" bash "$SCRIPT" 60 2>&1)
rc_old=$?
ck "toan dong cu -> rc=0" "0" "$rc_old"
ck "noi ro khong co dong nao" "yes" \
   "$(printf '%s' "$out_old" | grep -q 'khong co dong automation nao' && echo yes || echo no)"
ck "khong in bang tren dan so 0" "0" \
   "$(printf '%s' "$out_old" | grep -c 'DA CHAN THAT')"

echo "-- 9. moc .deploy_ts --------------------------------"
# .deploy_ts chu KHONG mtime: rsync -a giu mtime cua nguon.
echo "$((N - 300))" > "$W/dts"
out_d=$(LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/dts" bash "$SCRIPT" 2>&1)
ck "doc duoc moc tu .deploy_ts" "yes" \
   "$(printf '%s' "$out_d" | grep -q 'tu moc deploy' && echo yes || echo no)"
# Moc N-300 tre hon moi dong fixture (T = N-600), nen KHONG con dong nao.
ck "moc N-300 loai het dong T=N-600" "0" \
   "$(printf '%s' "$out_d" | sed -n 's/^dong *: *//p')"
echo "khong-phai-so" > "$W/dts_bad"
ck ".deploy_ts khong phai so -> rc=2" "2" \
   "$(LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/dts_bad" bash "$SCRIPT" >/dev/null 2>&1; echo $?)"

echo "-- 10. log xoay vong --------------------------------"
gzip -c "$L" > "$W/log/antibot.log.1.gz"
: > "$L"
out_rot=$(run 60)
ck "doc duoc du lieu trong .gz" "9" \
   "$(printf '%s' "$out_rot" | sed -n 's/^dong *: *//p')"
ck "in ra ten file .gz" "yes" \
   "$(printf '%s' "$out_rot" | grep -q 'antibot.log.1.gz' && echo yes || echo no)"
rm -f "$W/log/antibot.log.1.gz"

echo "-- 11. DOT BIEN: dem theo autaxis thi phai SAI ------"
# Phep thu quyet dinh. Neu thay autthr bang autaxis o muc 3 ma ket qua KHONG
# doi, thi fixture khong chua bay that va ca bo kiem nay vo nghia.
#
# Dung awk voi chuoi CO DINH (index/substr) chu KHONG dung "sed s///": mau
# chua "=" va "!" va cac ky tu sed coi la dac biet, va trong buoi 18-10 mot
# ban dot bien dung sed da bi hong vi \0 trong phan thay the nghia la "toan bo
# phan khop" -- mutant khong he duoc tao ma phep thu van in ket qua.
{
  LINE $T gptbot    operator true true  'fleet:short' fleet 12.0 40.0 5.0
  LINE $T ahrefsbot unknown  false false '-'          fleet 1.0  2.0  0.5
} > "$L"

awk '
{
    old = "if (thr != \"true\") next"
    new = "if (ax != \"fleet\") next"
    i = index($0, old)
    if (i > 0) { $0 = substr($0, 1, i - 1) new substr($0, i + length(old)); c1++ }
    old2 = "else if (index(f[i], \"autbreach=\") == 1)  br = substr(f[i], 11)"
    new2 = "else if (index(f[i], \"autaxis=\") == 1)  ax = substr(f[i], 9)"
    j = index($0, old2)
    if (j > 0) { $0 = substr($0, 1, j - 1) new2 substr($0, j + length(old2)); c2++ }
    print
}
END { if (c1 == 0 || c2 == 0) exit 9 }' "$SCRIPT" > "$W/mut.sh"
mut_rc=$?
if [ "$mut_rc" -ne 0 ]; then
    echo "  LOI  khong tao duoc ban dot bien (khong tim thay moc trong script)"
    fail=$((fail + 1))
else
    mut_out=$(LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/khong-co" \
              bash "$W/mut.sh" 60 2>&1)
    clean_out=$(run 60)
    ck "ban DOT BIEN dem ahrefsbot thanh bi chan" "1" \
       "$(printf '%s' "$mut_out" | sed -n '/^3\. AI BI CHAN/,/^4\./p' | grep -c 'ahrefsbot')"
    ck "ban THAT khong dem ahrefsbot" "0" \
       "$(printf '%s' "$clean_out" | sed -n '/^3\. AI BI CHAN/,/^4\./p' | grep -c 'ahrefsbot')"
    ck "ban THAT van dem gptbot" "1" \
       "$(printf '%s' "$clean_out" | sed -n '/^3\. AI BI CHAN/,/^4\./p' | grep -c 'gptbot')"
fi

echo "-- 12. DOT BIEN: bo neo (^|space) o ts= ------------"
# Dong bay "sclients=1 xf_hits=1" khong co ts= that. Thieu neo thi
# `/ts=[0-9]+/` doc "sclients=1" thanh epoch 1 va dong rac duoc coi la hop le.
#
# Phai do bang cua so DU RONG: voi cua so 60 phut thi epoch 1 (nam 1970) bi
# chinh cutoff loai, nen ban dot bien va ban that TRONG GIONG NHAU. systime()
# khoang 1,79e9 giay nen can ~29.800.000 phut; dung 40000000 cho chac.
# Day la bay da lam mot phep thu trong ephours_test vo nghia truoc do.
HUGE=40000000
{
  LINE $T gptbot operator true true 'fleet:short' fleet 12.0 40.0 5.0
  echo '[2026-10-18 09:00:00] [antibot] aut=1 autp=bay auttier=operator sclients=1 xf_hits=1 autwould=true autthr=true autbreach=fleet:short'
} > "$L"

cat > "$W/mkmut.awk" <<'AWKEOF'
BEGIN {
    # Moc trong file la 18 ky tu: (^|[ \t])ts=[0-9]+
    # Mot backslash THAT phai viet "\\" trong awk string literal.
    o = "(^|[ \\t])ts=[0-9]+"
    n = "ts=[0-9]+"
}
{
    i = index($0, o)
    if (i > 0) { $0 = substr($0, 1, i - 1) n substr($0, i + length(o)); c++ }
    print
}
END { if (c == 0) exit 9 }
AWKEOF
awk -f "$W/mkmut.awk" "$SCRIPT" > "$W/mut2.sh"
if [ $? -ne 0 ] || cmp -s "$SCRIPT" "$W/mut2.sh"; then
    echo "  LOI  khong tao duoc ban dot bien bo neo ts="
    fail=$((fail + 1))
else
    m2=$(LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/khong-co" \
         bash "$W/mut2.sh" "$HUGE" 2>&1)
    c2=$(LOGDIR="$W/log" BASE=antibot.log DEPLOY_TS="$W/khong-co" \
         bash "$SCRIPT" "$HUGE" 2>&1)
    ck "ban KHONG neo dem dong bay (2 dong)" "2" \
       "$(printf '%s' "$m2" | sed -n 's/^dong *: *//p')"
    ck "ban CO neo loai dong bay (1 dong)" "1" \
       "$(printf '%s' "$c2" | sed -n 's/^dong *: *//p')"
    ck "ban KHONG neo dem them mot luot bi chan" "2" \
       "$(printf '%s' "$m2" | awk '$1 == "autthr=true" {print $3}')"
    ck "ban CO neo chi dem mot luot bi chan" "1" \
       "$(printf '%s' "$c2" | awk '$1 == "autthr=true" {print $3}')"
fi

echo
echo "autthr_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
