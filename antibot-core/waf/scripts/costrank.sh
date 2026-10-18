#!/bin/bash
# costrank.sh — xep hang theo CHI PHI TICH LUY, khong theo so luot.
#
# VI SAO. Mot bot gui 1.498 request tra trong 50ms ton it hon nhieu so voi
# 195 request treo 60 giay. Moi bang xep hang theo SO LUOT deu tra loi sai
# cau hoi "cai gi dang chiem worker".
#
# Do duoc tren cloud28-246 18-10 (fleetstat):
#     autuptime trung binh 19,696s | >10s: 3.222 | >30s: 195 | max 60,007s
#     autwould=true chi 2/30.940 (0,01%)  -> KHONG ai cham han muc toc do
# Nen nut that khong phai SO LUONG request ma la THOI GIAN moi request.
#
# `60,007s` dang chu y rieng: mot request bi CPU starve ra so ngau nhien
# (37s, 52s, 71s), khong tu dung tai 60,007. Do la `max_execution_time=60`
# cat dung giay — tuc TREO, khong phai cham.
#
# Script doc NGINX access log (co URI + request_time), vi `antibot.log` CO Y
# khong ghi URI (`logger.lua:936`).
#
# BAY DA GHIM:
#   - DOC `*.log` (format `antibot_fmt`), KHONG doc `*.bytes`. Hai file do HAI
#     `log_format` khac nhau ghi ra, xem `nginx/nginx.conf:160-164`:
#         bytes       = ... "$http_referer" "$http_user_agent"      <- HET
#         antibot_fmt = ... ja3_partial=$sent_http_x_bot_ja3partial ${request_time}s
#     `$request_time` CHI co trong `antibot_fmt`. Ban dau script doc `*.bytes`
#     va in `co cot thoi gian: 0` tren 5.538 dong HOP LE — bo loc thoi gian
#     chay dung, chi la file khong he chua cot can do. Nen gio script tu noi ro
#     "dang doc gi / can doc gi" va tra rc=3, thay vi chi bao 0.
#   - Cot thoi gian KHONG phai `$NF`: trong format `bytes` $NF la User-Agent,
#     trong `antibot_fmt` moi la `${request_time}s`. Tim token dang
#     `<so>.<so>s` quet tu PHAI sang, nen khong phu thuoc vi tri cot.
#   - Cot status tim theo token SO TRAN 3 chu so: `fp=200` KHONG duoc nham la
#     status (no co tien to), va `/a?b=404` KHONG duoc nham vi query bi cat.
#   - `grep` gap byte nhi phan -> `grep -a`, neu khong no bo CA FILE.
#   - Moi bang phai co MAU SO va phai in tong chi phi, khong chi dem luot.
#
# Chay:  bash costrank.sh [so_phut]            (mac dinh 60)
#        LOGDIR=/duong/dan bash costrank.sh 30

set -u
LOGDIR=${LOGDIR:-/var/log/nginx/domains}
MINUTES=${1:-60}

case "$MINUTES" in
    ''|*[!0-9]*) echo "so phut phai la so nguyen: [$MINUTES]"; exit 2 ;;
esac
[ "$MINUTES" -gt 0 ] || { echo "so phut phai > 0"; exit 2; }

if [ ! -d "$LOGDIR" ]; then
    echo "khong thay thu muc log: $LOGDIR"
    echo "dat LOGDIR=/duong/dan neu khac"
    exit 2
fi

# `*.log` chu KHONG `*.bytes`: chi `antibot_fmt` co `$request_time`.
GLOB=${GLOB:-*.log}
NFILES=$(find "$LOGDIR" -maxdepth 1 -name "$GLOB" 2>/dev/null | wc -l)
if [ "$NFILES" -eq 0 ]; then
    echo "khong thay file $GLOB trong $LOGDIR"
    ls -la "$LOGDIR" 2>/dev/null | head -5
    exit 2
fi
echo "thu muc : $LOGDIR  ($NFILES file $GLOB)"
echo "cua so  : ${MINUTES} phut gan nhat"

W=$(mktemp) || exit 2
cleanup() { local rc=$?; rm -f "$W"; exit $rc; }
trap cleanup EXIT

# Doc moi file, gan ten domain vao tung dong, loc theo cua so thoi gian.
# Timestamp nginx la `dd/Mon/yyyy:HH:MM:SS +0700` -> phai doi sang epoch,
# KHONG so sanh chuoi (`30/Apr` > `17/Oct` vi `3` > `1`).
for f in "$LOGDIR"/$GLOB; do
    [ -r "$f" ] || continue
    d=$(basename "$f" | sed 's/\.[^.]*$//')
    grep -a '' "$f" | tail -200000 | sed "s|^|$d |"
done | awk -v mins="$MINUTES" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
    for (i = 1; i <= 12; i++) mon[m[i]] = i
    cutoff = systime() - mins * 60
    now = systime()
    local_off = now - mktime(strftime("%Y %m %d %H %M %S", now, 1))
}
{
    if (!match($0, /\[[0-9]{2}\/[A-Z][a-z]{2}\/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}/))
        next
    s = substr($0, RSTART + 1, RLENGTH - 1)
    split(s, p, /[\/:]/)
    t = mktime(sprintf("%s %s %s %s %s %s",
                       p[3], mon[p[2]], p[1], p[4], p[5], p[6]))
    t += local_off
    off = 0
    if (match($0, /[+-][0-9]{4}\]/)) {
        o = substr($0, RSTART, 5)
        sign = (substr(o, 1, 1) == "-") ? -1 : 1
        off = sign * (substr(o, 2, 2) * 3600 + substr(o, 4, 2) * 60)
    }
    t -= off
    if (t >= cutoff) print
}' > "$W"

TOTAL=$(wc -l < "$W")
echo "dong    : $TOTAL"
if [ "$TOTAL" -eq 0 ]; then
    echo
    echo "KET LUAN: khong co dong nao trong cua so."
    exit 0
fi

# Rut (domain, uri_rut_gon, status, request_time) tu moi dong.
# `uri` lay tu truong sau "GET/POST..., bo query string de gom nhom.
awk '{
    dom = $1
    rt = ""
    for (i = NF; i >= 2; i--) if ($i ~ /^[0-9]+\.[0-9]+s$/) { rt = $i; break }
    if (rt == "") next
    sub(/s$/, "", rt)

    uri = "-"
    for (i = 2; i <= NF; i++) {
        if ($i ~ /^"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)$/ && (i + 1) <= NF) {
            uri = $(i + 1); break
        }
    }
    sub(/\?.*$/, "", uri)

    st = "-"
    for (i = 2; i <= NF; i++) if ($i ~ /^(2|3|4|5)[0-9][0-9]$/) { st = $i; break }

    printf "%s\t%s\t%s\t%.3f\n", dom, uri, st, rt + 0
}' "$W" > "$W.p"

SAMPLES=$(wc -l < "$W.p")
echo "co cot thoi gian: $SAMPLES"
if [ "$SAMPLES" -eq 0 ]; then
    echo
    echo "KHONG tim thay cot thoi gian tren $TOTAL dong HOP LE."
    echo "Bo loc thoi gian da chay dung — file nay khong chua \$request_time."
    echo
    echo "  dang doc : $LOGDIR/$GLOB"
    echo "  can doc  : *.log    (format antibot_fmt, nginx.conf:162)"
    echo "  KHONG    : *.bytes  (format bytes, nginx.conf:164 — het o User-Agent)"
    echo
    echo "mot dong mau, TOAN BO truong:"
    head -1 "$W" | tr ' ' '\n' | nl -ba | sed 's/^/   /'
    exit 3
fi

echo
echo "=============================================================="
echo "1. TONG CHI PHI — giay-worker, khong phai so luot"
echo "=============================================================="
# `-v mins=` chu KHONG `MINUTES=... file`: dang sau la mot ASSIGNMENT ARGUMENT,
# no chi co hieu luc khi awk doc TOI vi tri do trong danh sach tep, va KHONG
# vao `ENVIRON`. Ket qua la `ENVIRON["MINUTES"]` rong -> chia cho 0 -> awk
# chet giua chung va muc 1 mat sach so lieu trong khi cac muc sau van in
# binh thuong. Oracle bat duoc dung vi no doi tung con so cu the.
awk -F'\t' -v mins="$MINUTES" '{
    n++; sum += $4
    if ($4 > 1)  s1++
    if ($4 > 10) s10++
    if ($4 > 30) s30++
    if ($4 >= 59 && $4 <= 61) near60++
    if ($4 > mx) mx = $4
}
END {
    if (n == 0) { print "  mau: 0"; exit }
    printf "  mau              : %d\n", n
    printf "  tong giay-worker : %.0fs", sum
    if (mins > 0) printf "  (= %.1f worker ban lien tuc)", sum / (mins * 60)
    printf "\n"
    printf "  trung binh       : %.2fs\n", sum / n
    printf "  cham nhat        : %.2fs\n", mx
    printf "  >1s  : %d (%.1f%%)\n", s1 + 0, s1 * 100 / n
    printf "  >10s : %d (%.1f%%)\n", s10 + 0, s10 * 100 / n
    printf "  >30s : %d (%.1f%%)\n", s30 + 0, s30 * 100 / n
    printf "  59-61s (TREO, bi max_execution_time cat): %d\n", near60 + 0
}' "$W.p"

echo
echo "=============================================================="
echo "2. DOMAIN theo CHI PHI (khong theo so luot)"
echo "=============================================================="
printf "  %12s %8s %9s %9s  %s\n" "GIAY-WORKER" "LUOT" "TB" "MAX" "DOMAIN"
awk -F'\t' '{ c[$1] += $4; n[$1]++; if ($4 > mx[$1]) mx[$1] = $4 }
END { for (d in c) printf "  %12.0f %8d %8.2fs %8.2fs  %s\n", c[d], n[d], c[d]/n[d], mx[d], d }' \
  "$W.p" | sort -rn | head -15

echo
echo "=============================================================="
echo "3. URI theo CHI PHI — day la cau tra loi 'cai gi chiem worker'"
echo "=============================================================="
printf "  %12s %8s %9s %9s  %s\n" "GIAY-WORKER" "LUOT" "TB" "MAX" "URI"
awk -F'\t' '{ c[$2] += $4; n[$2]++; if ($4 > mx[$2]) mx[$2] = $4 }
END { for (u in c) printf "  %12.0f %8d %8.2fs %8.2fs  %s\n", c[u], n[u], c[u]/n[u], mx[u], u }' \
  "$W.p" | sort -rn | head -20

echo
echo "=============================================================="
echo "4. TAP TREO (>30s) — URI nao, domain nao"
echo "=============================================================="
NSLOW=$(awk -F'\t' '$4 > 30' "$W.p" | wc -l)
echo "  so luot >30s: $NSLOW"
if [ "$NSLOW" -gt 0 ]; then
    echo "  --- theo URI ---"
    awk -F'\t' '$4 > 30 {print $2}' "$W.p" | sort | uniq -c | sort -rn | head -10 \
      | sed 's/^/    /'
    echo "  --- theo domain ---"
    awk -F'\t' '$4 > 30 {print $1}' "$W.p" | sort | uniq -c | sort -rn | head -10 \
      | sed 's/^/    /'
    echo "  --- theo ma HTTP ---"
    awk -F'\t' '$4 > 30 {print $3}' "$W.p" | sort | uniq -c | sort -rn | sed 's/^/    /'
fi

echo
echo "=============================================================="
echo "5. MA HTTP tren toan bo mau"
echo "=============================================================="
awk -F'\t' '{ n[$3]++; c[$3] += $4 }
END { for (s in n) printf "  %8d luot  %10.0f giay-worker  %s\n", n[s], c[s], s }' \
  "$W.p" | sort -k1 -rn

rm -f "$W.p"

cat <<'EOF'

=============================================================
CACH DOC
=============================================================
Muc 1 "59-61s" > 0
  -> co request chay HET max_execution_time roi bi giet. Do la TREO
     (cho mot thu khong bao gio den), khong phai cham do tai.
Muc 3 mot URI chiem phan lon giay-worker
  -> do la cho phai sua, bat ke no chiem bao nhieu % SO LUOT.
Muc 1 "worker ban lien tuc" >= tong max_children
  -> backend that su kin cho. Neu NHO hon nhieu ma van cham
     -> nut that o noi khac (DB, disk, mot khoa chung), khong o so worker.
EOF
