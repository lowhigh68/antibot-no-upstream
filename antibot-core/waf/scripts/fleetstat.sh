#!/bin/bash
# fleetstat.sh — nhin TOAN MAY, khong nhin mot domain.
#
# VI SAO CAN. `automation_guard` khoa han muc theo (host, principal) va
# (host, ip); chi truc `server` la toan may. Mot bot quet N domain vi vay co
# N NGAN SACH DOC LAP: han muc 8/10s tren 11 domain la 88/10s thuc te. Moi
# bang chi nhin mot domain deu bo sot dung cai do.
#
# Script tra loi bon cau, theo thu tu:
#   1. Tai dang do dau ra      — xep hang domain, va do TAP TRUNG
#   2. Ai dang keo             — principal nao, tren bao nhieu domain
#   3. Phanh da an chua        — autthr/autwould, tach theo tang
#   4. Dong nao dat tien       — class + thoi gian upstream
#
# BAY DA GHIM:
#   - Cot KET THUC bang "ts=" (`xf_hits=`, `sclients=`, `exists=`, `parts=`)
#     -> phai neo `(^|[[:space:]])ts=`, neu khong `sclients=1` thanh epoch 1.
#   - `grep` gap byte nhi phan thi in "binary file matches" va BO QUA ca file
#     -> dung `grep -a`.
#   - Ten file xoay vong khac nhau theo may -> `find`/glob + `zcat`, va IN RA
#     file da doc.
#   - Mot ty le phai co MAU SO. Mot `0` tren dan so 0 khong chung minh gi.
#
# Chay:  bash fleetstat.sh [so_phut_nhin_lai]      (mac dinh 60)

set -u
AL=${AL:-/var/log/antibot/antibot.log}
LIVE=${LIVE:-/usr/local/openresty/nginx/conf/antibot}
MINUTES=${1:-60}

case "$MINUTES" in
    ''|*[!0-9]*) echo "so phut phai la so nguyen: [$MINUTES]"; exit 2 ;;
esac
[ "$MINUTES" -gt 0 ] || { echo "so phut phai > 0"; exit 2; }

FOUND=0
echo "doc file:"
for f in "$AL"*; do
    [ -r "$f" ] || continue
    echo "   $f"
    FOUND=1
done
[ "$FOUND" -eq 1 ] || { echo "khong doc duoc $AL*"; exit 2; }
echo "cua so  : ${MINUTES} phut gan nhat"

# Ban enforce da len may chua. `autthr=` la cot MOI; `grep -c` tra 0 khong
# phan biet duoc "chua chan luot nao" voi "ma chua deploy".
if grep -q 'automation_throttled' "$LIVE/l7/automation_guard.lua" 2>/dev/null; then
    echo "enforce : DA DEPLOY (automation_guard co nhanh chan)"
    HAVE_ENFORCE=1
else
    echo "enforce : CHUA DEPLOY — moi so autthr= deu la 0 vi cot chua ton tai"
    HAVE_ENFORCE=0
fi

read_all() {
    for f in "$AL"*; do
        [ -r "$f" ] || continue
        case "$f" in *.gz) zcat "$f" ;; *) cat "$f" ;; esac
    done
}

W=$(mktemp) || exit 2
cleanup() { local rc=$?; rm -f "$W"; exit $rc; }
trap cleanup EXIT

read_all | grep -a '\[antibot\]' | awk -v mins="$MINUTES" '
BEGIN { cutoff = systime() - mins * 60 }
{
    if (!match($0, /(^|[[:space:]])ts=[0-9]+/)) next
    t = substr($0, RSTART, RLENGTH); sub(/^.*ts=/, "", t)
    if (t + 0 >= cutoff) print
}' > "$W"

TOTAL=$(wc -l < "$W")
echo "dong    : $TOTAL"
if [ "$TOTAL" -eq 0 ]; then
    echo
    echo "KET LUAN: khong co dong nao trong cua so. Kiem lai so phut / duong dan."
    exit 0
fi

# Moi cot cau truc chi duoc doc MOT LAN tren mot dong. `reason` co the chua
# lai `class=` (vi du "score=... class=navigation"), nen grep -o tat ca token
# se lam tong class/action lon hon tong so dong. Cot cau truc cua logger nam
# truoc reason; lay occurrence dau tien vua dung schema vua khong dem kep.
field() {
    awk -v wanted="$1" '
    {
        prefix = wanted "="
        for (i = 1; i <= NF; i++) {
            if (index($i, prefix) == 1) {
                print substr($i, length(prefix) + 1)
                break
            }
        }
    }' "$W"
}

echo
echo "=============================================================="
echo "1. TAI THEO DOMAIN — va do TAP TRUNG"
echo "=============================================================="
field domain | sort | uniq -c | sort -rn | head -20 \
  | awk -v tot="$TOTAL" '{printf "  %8d  %5.1f%%  %s\n", $1, $1*100/tot, $2}'
NDOM=$(field domain | sort -u | wc -l)
TOP5=$(field domain | sort | uniq -c | sort -rn | head -5 \
       | awk '{s+=$1} END{print s+0}')
awk -v n="$NDOM" -v t5="$TOP5" -v tot="$TOTAL" 'BEGIN{
    printf "\n  so domain co luu luong : %d\n", n
    printf "  5 domain dau chiem     : %d / %d = %.1f%%\n", t5, tot, t5*100/tot
    if (t5*100/tot < 60 && n > 5)
        print "  -> TAI TRAI DEU: mot bang chi nhin mot domain se bo sot phan lon"
    else
        print "  -> TAI TAP TRUNG: nhin domain dau la du dai dien"
}'

echo
echo "=============================================================="
echo "2. AI DANG KEO — principal, va tren BAO NHIEU domain"
echo "=============================================================="
echo "  (so domain la truc quan trong: han muc khoa theo (host,principal)"
echo "   nen N domain = N ngan sach doc lap)"
echo
printf "  %8s %7s  %s\n" "LUOT" "DOMAIN" "PRINCIPAL"
# Doc TUNG DONG, khong `paste - -`.
#
# `grep -o ... | paste - -` ghep hai lan khop lien tiep thanh mot cap, va no
# chi dung khi MOI dong deu co DU ca hai cot. Dong nao co `domain=` ma thieu
# `autp=` se lam lech toan bo chuoi ghep tu do tro di: do duoc tren fixture,
# ra nhung "principal" ten la `domain=b.test`. Mot phep ghep theo vi tri tren
# du lieu khong dong deu la mot phep ghep sai.
awk '{
    d = ""; p = ""
    for (i = 1; i <= NF; i++) {
        if ($i ~ /^domain=/) { d = substr($i, 8) }
        else if ($i ~ /^autp=/) { p = substr($i, 6) }
    }
    if (p == "" || p == "-") next
    if (d == "") d = "-"
    n[p]++
    if (!(p SUBSEP d in seen)) { seen[p SUBSEP d] = 1; dom[p]++ }
}
END { for (p in n) printf "  %8d %7d  %s\n", n[p], dom[p], p }' "$W" \
  | sort -rn | head -15

echo
echo "  --- tang bang chung ---"
field auttier | sort | uniq -c | sort -rn | sed 's/^/  /'
echo "  --- mang luoi cong bo ---"
field opnet | sort | uniq -c | sort -rn | sed 's/^/  /'

echo
echo "=============================================================="
echo "3. PHANH DA AN CHUA"
echo "=============================================================="
if [ "$HAVE_ENFORCE" -eq 1 ]; then
    THR=$(grep -ac 'autthr=true' "$W" || true)
    WOULD=$(grep -ac 'autwould=true' "$W" || true)
    awk -v thr="$THR" -v wd="$WOULD" -v tot="$TOTAL" 'BEGIN{
        printf "  autwould=true (vuot han muc) : %d (%.2f%% tong)\n", wd, wd*100/tot
        printf "  autthr=true   (CHAN THAT)    : %d\n", thr
        if (wd > 0 && thr == 0)
            print "  -> VUOT NHUNG KHONG CHAN: tang khong nam trong enforce_tiers,"
        if (wd > 0 && thr == 0)
            print "     hoac meter degraded. Xem hai bang duoi."
    }'
    echo "  --- tang nao bi chan ---"
    grep -a 'autthr=true' "$W" | grep -aoE 'auttier=[a-z]+' | sort | uniq -c \
      | sed 's/^/    /'
    echo "  --- tang nao VUOT ma khong bi chan ---"
    grep -a 'autwould=true' "$W" | grep -a -v 'autthr=true' \
      | grep -aoE 'auttier=[a-z]+' | sort | uniq -c | sed 's/^/    /'
    echo "  --- truc nao vuot ---"
    field autbreach | sort | uniq -c | sort -rn | head -8 | sed 's/^/    /'
    echo "  --- meter degraded ---"
    field autdeg | sort | uniq -c | sed 's/^/    /'
else
    echo "  BO QUA: ban enforce chua deploy."
fi

echo
echo "=============================================================="
echo "4. DONG NAO DAT TIEN"
echo "=============================================================="
echo "  --- phan loai request ---"
field class | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'
echo "  --- hanh dong cuoi ---"
field action | sort | uniq -c | sort -rn | sed 's/^/    /'
echo "  --- thoi gian upstream (giay) ---"
field autuptime | awk '
{
    v = $0 + 0
    if ($0 == "-" || $0 == "") { miss++; next }
    n++; sum += v
    if (v > max) max = v
    if (v > 1)  s1++
    if (v > 10) s10++
    if (v > 30) s30++
}
END {
    if (n == 0) { printf "    khong co mau (%d dong thieu cot)\n", miss + 0; exit }
    printf "    mau=%d  trung binh=%.3fs  cham nhat=%.3fs\n", n, sum/n, max
    printf "    >1s=%d (%.1f%%)  >10s=%d  >30s=%d\n",
        s1+0, s1*100/n, s10+0, s30+0
}'

cat <<'EOF'

=============================================================
CACH DOC
=============================================================
Muc 1 "TAI TRAI DEU" + muc 2 mot principal tren NHIEU domain
  -> han muc theo (host,principal) bi nhan len bang so domain.
     Truc `server` (toan may) la cong gom tai; sau khi ha nguong, xem
     `autbreach=server:short|server:long` de xac nhan cong nay dang shed.
Muc 3 autwould>0 nhung autthr=0
  -> tang do khong nam trong `enforce_tiers`, hoac meter degraded.
Muc 4 `autuptime` cao ma `class` phan lon la navigation
  -> backend cham, khong phai nhieu request. Siet toc do khong cuu duoc;
     phai tim cai gi lam backend cham.
EOF
