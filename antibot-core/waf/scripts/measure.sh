#!/bin/bash
# Doc so lieu tu /var/log/antibot/antibot.log va Redis. CHI DOC — khong sua
# file, khong ghi Redis, khong doi hanh vi gi. Chay bao nhieu lan cung duoc.
#
# DUNG:  measure.sh <nhom> [moc-thoi-gian]
#        measure.sh cf                             # doc ca file
#        measure.sh cf  /root/antibot_mark.txt      # chi doc tu moc trong file
#        measure.sh ban "2026-09-19 17:04:45"      # moc truyen truc tiep
#
# NHOM:  cf     luu luong qua reverse proxy (Cloudflare) + proxy_spoof
#        ban    phan bo TTL cua ban:<id> / ban:<ip>
#        fleet  lenh chan fleet theo dai
#        fp     ung vien false-positive (phien co cookie that bi chan)
#
# VI SAO CO FILE NAY. Moi vong do truoc day la 30-40 dong lenh dan qua chat, va
# BA LAN trong phien 19-09-2026 lenh SAI ma khong ai thay ngay:
#   1. grep -o 'ip=[0-9.]*'   tra chuoi rong vi mot so dong co ip= rong
#   2. grep 'ua="[^"]*"'      KHONG BAO GIO khop — logger khu dau nhay va
#                             khoang trang trong gia tri (thanh dau gach duoi)
#   3. awk -v t=""            khop MOI dong khi moc rong => doc ca file roi bao
#                             la "sau moc", cho ket luan sai
# Dat trong git thi lenh duoc review MOT lan, dung nhieu lan, sua mot cho.
#
# ═══ HAI DIEU PHAI NHO KHI DOC KET QUA ═══════════════════════════════════
#
#  1. COT TRANSPORT (ja3 ja3p ja3c j3m tls13 h2) GHI DAU GACH VI TANG CHUA
#     CHAY, khong phai "da do va rong". transport_layer la buoc CUOI cua
#     STEPS_COMMON, nen moi request thoat som (banned_ip buoc 6, banned_id,
#     fleet_dyn_block buoc 4, ip_whitelist, fast-path cookie) deu ghi dau gach.
#     DUNG dung cac cot nay de ket luan gi ve tap banned_*. Da doc sai 4 lan
#     trong mot phien. Xem khoi chu thich o dau async/logger.lua.
#
#  2. rown (session_richness) > 0 KHONG chung minh nguoi that. Gui 500 byte
#     cookie rac la dat richness cao (do 12-09-2026). Va rown HANG SO tren
#     nhieu IP khac nhau (vd 0.12 tren ba IP) la dau hieu BOT mang cookie co
#     dinh, khong phai khach quay lai. Phai doc them phan bo UA/identity.
#
# MOC THOI GIAN: truyen duong dan file (noi dung mot dong YYYY-MM-DD HH:MM:SS)
# hoac truyen truc tiep chuoi do. Bo trong thi doc CA FILE — va dong tieu de se
# noi ro dieu do, vi mot lan doc ca file ma tuong la "sau moc" da cho ket luan
# sai hom 19-09.

set -u
LOG=${LOG:-/var/log/antibot/antibot.log}
RCLI=${RCLI:-redis-cli}

usage() { sed -n '5,14p' "$0" | sed 's/^# \{0,1\}//'; }

GROUP=${1:-}
if [ -z "$GROUP" ]; then usage; exit 2; fi
shift || true

MARK=""
if [ $# -gt 0 ]; then
    if [ -r "$1" ]; then MARK=$(head -1 "$1"); else MARK="$*"; fi
fi

if [ ! -r "$LOG" ]; then echo "khong doc duoc $LOG"; exit 2; fi

if [ -n "$MARK" ]; then
    echo "### moc=$MARK   now=$(date '+%F %T')   log=$LOG"
else
    echo "### DOC CA FILE (khong co moc)   now=$(date '+%F %T')   log=$LOG"
fi
echo

# length(t)==0 la BAT BUOC: thieu no thi moc rong khop MOI dong va ket qua
# tuong la "sau moc" trong khi thuc ra la ca file.
since() { awk -v t="$MARK" 'length(t)==0 || $0 >= t' "$LOG"; }

# Dai IP reverse proxy cong cong — GIU DONG BO voi CF_V4_CIDRS trong
# core/proxy_origin.lua (day la dang regex cua cung danh sach do).
# KHONG dung tien to chuoi kieu 104.1[6-9]: khoi 104.16.0.0/13 trai dai
# 104.16..104.23 nen tien to vua bo sot 104.2x vua bat lam 104.160.*.
CF_LOG='ip=(172\.6[4-9]\.|172\.7[01]\.|162\.15[89]\.|141\.101\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|108\.162\.(19[2-9]|2[0-5][0-9])\.|104\.1[6-9]\.|104\.2[0-7]\.|103\.2[12]\.|103\.31\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.1[2-9]|131\.0\.7)'
CF_KEY='ban:(172\.(6[4-9]|7[01])\.|162\.15[89]\.|104\.1[6-9]\.|104\.2[0-7]\.|141\.101\.|108\.162\.|103\.2[12]\.|103\.31\.|190\.93\.|188\.114\.|197\.234\.|198\.41\.1[2-9]|131\.0\.7)'

# Tach truong an toan. Logger khu khoang trang trong gia tri nen moi truong la
# dung MOT tu => tr ' ' '\n' chinh xac. Con grep -o voi dau nhay thi khong bao
# gio khop, vi trong log khong co dau nhay nao.
field() { tr ' ' '\n' | grep "^$1=" | sed "s/^$1=//"; }

case "$GROUP" in

cf)
    echo "--- [1] tong luot qua reverse proxy (MAU SO — doc truoc moi thu khac):"
    since | grep -Ec " $CF_LOG" || true

    echo
    echo "--- [2] phan bo action:"
    since | grep -E " $CF_LOG" | field action | sort | uniq -c | sort -rn

    echo
    echo "--- [3] reason cua cac luot bi chan:"
    since | grep -E " $CF_LOG" | grep 'action=block' \
      | grep -oE 'reason=[a-z_0-9]+(:[0-9./]+)?' \
      | sed 's/reason=score=.*/reason=score=NN/' \
      | sort | uniq -c | sort -rn | head -10

    echo
    echo "--- [4] theo domain: luot / identity rieng biet / UA rieng biet / block:"
    T=$(mktemp)
    for d in $(since | grep -E " $CF_LOG" | field domain | sort -u); do
        since | grep -E " $CF_LOG" | grep " domain=$d " > "$T" || true
        n=$(wc -l < "$T")
        if [ "$n" -lt 5 ]; then continue; fi
        printf '  %-32s luot=%-6s id=%-5s ua=%-5s block=%s\n' "$d" "$n" \
          "$(field id < "$T" | sort -u | wc -l)" \
          "$(field ua < "$T" | sort -u | wc -l)" \
          "$(grep -c 'action=block' "$T" || true)"
    done
    rm -f "$T"

    echo
    echo "--- [5] khoa ban:<ip> la dia chi edge (PHAI = 0 sau ban va 112e27b):"
    $RCLI --scan --pattern 'ban:*' 2>/dev/null \
      | grep -v 'ban:hit:\|ban:age:\|ban_ctx' | grep -cE "$CF_KEY" || true

    echo
    echo "--- [6] proxy_spoof — header khai proxy ma IP ngoai moi dai da xac minh."
    echo "        Chi LAM TANG diem, khong bao gio mien tru (xem proxy_origin.lua)."
    echo "        Cao bat thuong => co proxy noi bo cua khach chua khai:"
    echo "        redis-cli SADD waf:proxyhosts <host>"
    printf '  tong: %s\n' "$(since | grep -c 'proxy_spoof' || true)"
    since | grep 'proxy_spoof' \
      | perl -ne '($i)=/ ip=(\S+)/; ($d)=/domain=(\S+)/;
                  print(($i // "-") . " | " . ($d // "-") . "\n")' \
      | sort | uniq -c | sort -rn | head -8
    ;;

ban)
    B=$(mktemp)
    $RCLI --scan --pattern 'ban:*' 2>/dev/null \
      | grep -v 'ban:hit:\|ban:age:\|ban_ctx' > "$B" || true

    echo "--- [1] tong so khoa:"
    printf '  ban:<id> = %s     ban:<ip> = %s\n' \
      "$(grep -vcE 'ban:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$B" || true)" \
      "$(grep -cE  'ban:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$B" || true)"

    echo
    echo "--- [2] phan bo TTL (mau 400 khoa dau):"
    head -400 "$B" | while read -r k; do $RCLI TTL "$k"; done | awk '
      $1==-1 {p++; next} $1==-2 {g++; next}
      $1<=300 {a++; next} $1<=3600 {b++; next} $1<=86400 {c++; next}
      $1<=604800 {d++; next} {e++}
      END {
        printf "  VINH VIEN (-1): %5d   <- ban va 2026-08-06 doi sang 30 ngay;\n", p+0
        printf "                              con lai la DI TICH, xoa tay duoc\n"
        printf "  da het han (-2):%5d\n", g+0
        printf "  <= 5 phut:      %5d\n", a+0
        printf "  5 phut - 1 gio: %5d\n", b+0
        printf "  1 gio - 1 ngay: %5d\n", c+0
        printf "  1 - 7 ngay:     %5d\n", d+0
        printf "  > 7 ngay:       %5d   <- ban_steps khong co bac giua 1 va 30 ngay\n", e+0
      }'

    echo
    echo "--- [3] khoa TTL ~30 ngay: viol con hay het."
    echo "        viol HET HAN + TTL con 30 ngay = khoa song lau hon bang chung"
    echo "        sinh ra no. Do 19-09 cho 0 => KHONG co vong tu nuoi."
    head -400 "$B" | while read -r k; do
        t=$($RCLI TTL "$k")
        v=$($RCLI GET "viol:${k#ban:}")
        echo "$t ${v:-none}"
    done | awk '
      $1>2500000 && $2=="none" {a++; next} $1>2500000 {b++; next} {c++}
      END {
        printf "  30 ngay + viol HET:  %5d\n", a+0
        printf "  30 ngay + viol con:  %5d\n", b+0
        printf "  con lai:             %5d\n", c+0
      }'
    rm -f "$B"
    ;;

fleet)
    echo "--- [1] lenh chan fleet theo dai (PHEP DO DUNG — dem dong log):"
    since | grep -oE 'reason=fleet_dyn_block_[0-9]+:[0-9./]+' \
      | sort | uniq -c | sort -rn | head -10

    echo
    echo "--- [2] co fl:dyn dang ton tai:"
    echo "        LUU Y: khoa ton tai KHONG phai dang chan. check_block tha"
    echo "        request xuong pipeline khi /24 da co dau crawler24; co van nam"
    echo "        do va van duoc ghi lai. Dem khoa la PHEP DO SAI — da mac 2 lan."
    $RCLI --scan --pattern 'fl:dyn:*' 2>/dev/null | head -12 || true

    echo
    echo "--- [3] dau crawler da cap:"
    printf '  crawler:<ip>   %s\n' "$($RCLI --scan --pattern 'crawler:*' 2>/dev/null | wc -l)"
    printf '  crawler24:<24> %s\n' "$($RCLI --scan --pattern 'crawler24:*' 2>/dev/null | wc -l)"
    ;;

fp)
    echo "--- [1] phien CO COOKIE THAT (rown>0) bi chan — ung vien FP theo reason:"
    echo "        Doc muc 2 o dau file truoc khi ket luan."
    since | grep -v 'rown=0.00' | grep -v 'rown=-' | grep 'action=block' \
      | grep -oE 'reason=[a-z_0-9]+' | sort | uniq -c | sort -rn | head -10

    echo
    echo "--- [2] so luot o rown >= 0.5 (phien dang nhap that) bi chan:"
    echo "        Day la FP NANG — auth_session_cap le ra phai gioi han o monitor."
    since | grep 'action=block' \
      | perl -ne '($r) = /rown=([0-9.]+)/; print if defined($r) && $r >= 0.5' \
      | wc -l

    echo
    echo "--- [3] UA cua nhom rown >= 0.5 bi chan:"
    since | grep 'action=block' \
      | perl -ne '($r) = /rown=([0-9.]+)/; print if defined($r) && $r >= 0.5' \
      | field ua | cut -c1-60 | sort | uniq -c | sort -rn | head -5

    echo
    echo "--- [4] UA/identity CHI trong tap co cookie that — thuoc do collapse:"
    echo "        =1 la moi client tach rieng (chan dung). >1 nhieu la identity"
    echo "        dang gop nhieu khach that. LOC COOKIE la BAT BUOC: thieu no thi"
    echo "        bot xoay UA cho so cao y nhu collapse that (da mac 19-09)."
    since | grep -v 'rown=0.00' | grep -v 'rown=-' \
      | perl -ne '($i) = / id=(\S+)/; ($u) = / ua=(\S+)/;
                  if (defined($i) && defined($u) && $i ne "-") { print "$i\t$u\n" }' \
      | sort -u | cut -f1 | uniq -c | sort -rn | head -5
    ;;

*)
    echo "nhom khong biet: $GROUP"
    echo
    usage
    exit 2
    ;;
esac
