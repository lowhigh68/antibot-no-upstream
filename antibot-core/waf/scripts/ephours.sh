#!/bin/bash
# ephours.sh — luu luong theo GIO, tach rieng oembed va AI-operator.
#
# Cau hoi: cot nao VOT LEN TRUOC. Neu OPENAI vot truoc roi TONG moi vot thi
# lưu luong AI-bot la nguyen nhan va cho sua la tang `operator`; neu OEMBED
# vot doc lap thi do la mot nguon khac.
#
# Khong sua gi, khong ghi gi — chi doc. Khong co cong phien ban: script nay
# chi dem cot `ts=`/`ep=`/`opnet=` da ton tai tu lau, khong phu thuoc ban
# deploy nao. (Khac `epstat.sh`, vi script do doc `epif=`/`epwould=` la cot
# moi va con phu thuoc viec scope da gop theo docroot hay chua.)
#
# HAI BAY DA GHIM O DAY:
#
#   1. COT KET THUC BANG "ts=". Bon cot trong log ket thuc dung chuoi do:
#      `xf_hits=`, `sclients=` (antibot.log), `exists=`, `parts=` (waf.log).
#      Bo loc `/ts=[0-9]+/` KHONG co guard se doc `sclients=1` thanh epoch 1,
#      ra 01/01/1970 va cac gio rac kieu `20/07`, `21/07`. Do duoc that 18-10:
#      output co ca dong `ts=1`. Phai neo bang `(^|[[:space:]])`.
#
#   2. SAP XEP THEO CHUOI. `dd/Mon/yyyy` sap theo chuoi thi `30/Apr` > `17/Oct`
#      (vi `3` > `1`), nen `tail -48` tra ve thang 5 chu khong phai 48 gio gan
#      nhat — da lam hong mot lan do 18-10. O day khoa gio la
#      `%Y-%m-%d %H`, dinh dang MA thu tu chuoi TRUNG voi thu tu thoi gian,
#      nen so sanh chuoi an toan. Do la mot lua chon, khong phai tinh co.
#
# Chay:  bash ephours.sh [so_gio_nhin_lai]        (mac dinh 72)
#        LOGDIR=/duong/dan BASE=antibot.log bash ephours.sh 24

set -u
LOGDIR=${LOGDIR:-/var/log/antibot}
BASE=${BASE:-antibot.log}
HOURS=${1:-72}

case "$HOURS" in
    ''|*[!0-9]*) echo "so gio phai la so nguyen: [$HOURS]"; exit 2 ;;
esac
[ "$HOURS" -gt 0 ] || { echo "so gio phai > 0"; exit 2; }

FOUND=0
echo "doc file:"
for f in "$LOGDIR/$BASE"*; do
    [ -r "$f" ] || continue
    echo "   $f"
    FOUND=1
done
if [ "$FOUND" -eq 0 ]; then
    echo "khong doc duoc file nao khop $LOGDIR/$BASE*"
    exit 2
fi
echo "cua so   : ${HOURS}h gan nhat"

read_all() {
    for f in "$LOGDIR/$BASE"*; do
        [ -r "$f" ] || continue
        case "$f" in
            *.gz) zcat "$f" ;;
            *)    cat "$f"  ;;
        esac
    done
}

read_all | awk -v hours="$HOURS" '
BEGIN { cutoff = systime() - hours * 3600 }
{
    # Guard `(^|[[:space:]])`: xem bay 1 o dau file.
    if (!match($0, /(^|[[:space:]])ts=[0-9]+/)) next
    t = substr($0, RSTART, RLENGTH)
    sub(/^.*ts=/, "", t)
    t += 0
    if (t < cutoff) next

    key = strftime("%Y-%m-%d %H", t)
    seen[key] = 1
    total[key]++

    if (index($0, "oembed"))        oe[key]++
    if (index($0, "opnet=openai"))  oa[key]++
    if (index($0, "opnet=anthropic")) an[key]++
    if (index($0, "auttier=operator")) op[key]++
    if (index($0, "action=block"))  bl[key]++
}
END {
    n = 0
    for (k in seen) keys[++n] = k
    if (n == 0) {
        print "khong co dong nao trong cua so — kiem lai so gio hoac duong dan log"
        exit 0
    }
    # Khoa `%Y-%m-%d %H` co thu tu chuoi == thu tu thoi gian: xem bay 2.
    for (i = 1; i < n; i++)
        for (j = i + 1; j <= n; j++)
            if (keys[i] > keys[j]) { tmp = keys[i]; keys[i] = keys[j]; keys[j] = tmp }

    printf "\n%-14s %9s %9s %9s %9s %9s %9s\n",
        "GIO", "TONG", "OEMBED", "OPENAI", "ANTHROP", "OPERATOR", "BLOCK"
    for (i = 1; i <= n; i++) {
        k = keys[i]
        printf "%-14s %9d %9d %9d %9d %9d %9d\n",
            k, total[k], oe[k] + 0, oa[k] + 0, an[k] + 0, op[k] + 0, bl[k] + 0
    }

    printf "\n%-14s %9d %9d %9d %9d %9d %9d\n", "TONG CONG",
        sum(total, keys, n), sum(oe, keys, n), sum(oa, keys, n),
        sum(an, keys, n), sum(op, keys, n), sum(bl, keys, n)
}
function sum(arr, keys, n,   i, s) {
    s = 0
    for (i = 1; i <= n; i++) s += arr[keys[i]] + 0
    return s
}'

cat <<'EOF'

CACH DOC:
  OPENAI vot truoc, TONG vot sau   -> luu luong AI-bot la nguyen nhan;
                                      cho sua la gioi han toc do `operator`.
  OEMBED vot doc lap voi OPENAI    -> nguon khac, phai tim tiep.
  Ca hai phang, TONG van vot       -> nguyen nhan nam ngoai hai truc nay.
Cot OPERATOR gom ca ba nha cung cap; OPENAI/ANTHROP la tach rieng tu do.
EOF
