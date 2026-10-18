#!/bin/bash
# autthr.sh — GPTBot (va moi principal automation) bi throttle NHU THE NAO.
#
# VI SAO CAN SCRIPT RIENG. Cau hoi "da bi chan chua" KHONG doc duoc bang
# cot autaxis:
#   autaxis = automation_top_axis = truc co TI LE CAO NHAT trong bon truc, va
#   no duoc dat cho MOI dong aut=1 ke ca khi khong co gi vuot nguong
#   (automation_guard.lua:129). Nen "grep autaxis=fleet" dem "principal nao co
#   ti le fleet cao nhat", chu KHONG phai "principal nao bi chan". Mot bot 7
#   request van lot vao danh sach do neu ba truc kia con thap hon.
#   Do la ly do output 18-10 tren 28-246 co ca ahrefsbot/bingbot/applebot/
#   baiduspider trong "autaxis=fleet" — chung khong he bi chan.
#
# Hai cot tra loi DUNG cau hoi:
#   autthr=true   -> da THUC SU 429 (ctx.automation_throttled)
#   autbreach=    -> DANH SACH moi truc da vuot, ghep bang dau phay
#                    (automation_guard.lua:151 lay phan tu [1] lam reason)
# Mot dong "autwould=true autthr=false" la HOP LE va co nghia: tang dang quan
# sat (khong trong enforce_tiers), hoac meter degraded (fail-open co y).
#
# BAY DA GHIM:
#   - grep gap byte nhi phan thi bo CA FILE. Phai -a o MOI diem doc.
#   - Loc theo moc phai neo (^|space)ts=: bon cot KET THUC bang "ts="
#     (xf_hits=, sclients=, exists=, parts=), nen /ts=[0-9]+/ khong neo se doc
#     "sclients=1" thanh epoch 1 -> gio rac 1970.
#   - autbreach chua dau PHAY va co the rong ("-"): tach bang "," chu khong
#     dem bang grep -c tren ca dong.
#   - Doc moc tu .deploy_ts chu KHONG tu mtime: rsync -a giu mtime cua nguon,
#     nen file khong doi mang mtime cua lan pull TRUOC.
#
# Chay:  bash autthr.sh [so_phut]          (mac dinh: tu .deploy_ts)
#        LOGDIR=/duong/dan bash autthr.sh 30

set -u
LOGDIR=${LOGDIR:-/var/log/antibot}
BASE=${BASE:-antibot.log}
DEPLOY_TS=${DEPLOY_TS:-/usr/local/openresty/nginx/conf/antibot/.deploy_ts}

if [ ! -d "$LOGDIR" ]; then
    echo "khong thay thu muc log: $LOGDIR"
    exit 2
fi

NOW=$(date +%s)
if [ $# -ge 1 ]; then
    case "$1" in
        ''|*[!0-9]*) echo "so phut phai la so nguyen: [$1]"; exit 2 ;;
    esac
    [ "$1" -gt 0 ] || { echo "so phut phai > 0"; exit 2; }
    CUT=$((NOW - $1 * 60))
    MOC="$1 phut gan nhat"
elif [ -r "$DEPLOY_TS" ]; then
    CUT=$(tr -dc '0-9' < "$DEPLOY_TS")
    [ -n "$CUT" ] || { echo "deploy_ts khong chua so: $DEPLOY_TS"; exit 2; }
    MOC="tu moc deploy ($(date -d "@$CUT" '+%Y-%m-%d %H:%M:%S'), $(( (NOW - CUT) / 60 )) phut truoc)"
else
    CUT=$((NOW - 3600))
    MOC="60 phut gan nhat (khong doc duoc $DEPLOY_TS)"
fi

W=$(mktemp) || exit 2
cleanup() { local rc=$?; rm -f "$W"; exit $rc; }
trap cleanup EXIT

FILES=$(find "$LOGDIR" -maxdepth 1 -name "$BASE*" 2>/dev/null | sort)
[ -n "$FILES" ] || { echo "khong thay $BASE* trong $LOGDIR"; exit 2; }
echo "nguon   : $(printf '%s' "$FILES" | tr '\n' ' ')"
echo "moc     : $MOC"

for f in $FILES; do
    case "$f" in
        *.gz) zcat -f "$f" 2>/dev/null ;;
        *)    cat "$f" ;;
    esac
done | grep -a 'aut=1' | awk -v cut="$CUT" '
{
    if (!match($0, /(^|[ \t])ts=[0-9]+/)) next
    t = substr($0, RSTART, RLENGTH)
    sub(/^[ \t]/, "", t); sub(/^ts=/, "", t)
    if (t + 0 >= cut) print
}' > "$W"

TOTAL=$(wc -l < "$W")
echo "dong    : $TOTAL"
if [ "$TOTAL" -eq 0 ]; then
    echo
    echo "KET LUAN: khong co dong automation nao sau moc."
    exit 0
fi

col() { # col <ten_cot> -> in gia tri cot do tung dong
    awk -v k="$1" '{
        n = split($0, f, /[ \t]+/)
        v = "-"
        for (i = 1; i <= n; i++)
            if (index(f[i], k "=") == 1) { v = substr(f[i], length(k) + 2); break }
        print v
    }' "$W"
}

echo
echo "=============================================================="
echo "1. DA CHAN THAT CHUA -- doc autthr, KHONG doc autaxis"
echo "=============================================================="
NTHR=$(col autthr | grep -c '^true$')
NWOULD=$(col autwould | grep -c '^true$')
NDEG=$(col autdeg | grep -c '^true$')
printf "  autwould=true : %6d  (vuot han muc)\n" "$NWOULD"
printf "  autthr=true   : %6d  (THUC SU 429)\n" "$NTHR"
printf "  autdeg=true   : %6d  (meter hong -> fail-open co y)\n" "$NDEG"
if [ "$NWOULD" -gt 0 ]; then
    awk -v w="$NWOULD" -v t="$NTHR" 'BEGIN{
        printf "  ty le chan    : %.1f%% cua so vuot han muc\n", t * 100 / w }'
fi
GAP=$((NWOULD - NTHR))
if [ "$GAP" -gt 0 ]; then
    printf "  chenh %d dong autwould=true autthr=false -- HOP LE:\n" "$GAP"
    echo "    tang dang quan sat (khong trong enforce_tiers), hoac meter degraded."
fi

echo
echo "=============================================================="
echo "2. TRUC NAO VUOT -- tu autbreach, da tach dau phay"
echo "=============================================================="
col autbreach | grep -v '^-$' | tr ',' '\n' | grep -v '^$' \
  | sort | uniq -c | sort -rn | sed 's/^/  /'
echo "  (truc dau tien trong danh sach moi la truc di vao action_reason)"

echo
echo "=============================================================="
echo "3. AI BI CHAN -- principal x tang x truc, chi dong autthr=true"
echo "=============================================================="
printf "  %8s  %-22s %-14s %s\n" "LUOT" "PRINCIPAL" "TANG" "TRUC"
awk '{
    n = split($0, f, /[ \t]+/)
    p = "-"; thr = "false"; br = "-"; tier = "-"
    for (i = 1; i <= n; i++) {
        if (index(f[i], "autp=") == 1)            p = substr(f[i], 6)
        else if (index(f[i], "autthr=") == 1)     thr = substr(f[i], 8)
        else if (index(f[i], "autbreach=") == 1)  br = substr(f[i], 11)
        else if (index(f[i], "auttier=") == 1)    tier = substr(f[i], 9)
    }
    if (thr != "true") next
    split(br, b, ",")
    printf "%s\t%s\t%s\n", p, tier, (b[1] == "" ? "-" : b[1])
}' "$W" | sort | uniq -c | sort -rn | head -20 \
  | awk '{ printf "  %8d  %-22s %-14s %s\n", $1, $2, $3, $4 }'

echo
echo "=============================================================="
echo "4. RAO CHAN FP -- tang nao KHONG duoc phep bi chan"
echo "=============================================================="
# unknown la noi mot khach that bi phan loai nham roi vao; verified la
# Googlebot/Bingbot da qua DNS hai chieu. Ca hai KHONG trong enforce_tiers.
for tier in unknown verified attested; do
    n=$(awk -v t="$tier" '{
        n = split($0, f, /[ \t]+/); tt = "-"; thr = "false"
        for (i = 1; i <= n; i++) {
            if (index(f[i], "auttier=") == 1)     tt = substr(f[i], 9)
            else if (index(f[i], "autthr=") == 1) thr = substr(f[i], 8)
        }
        if (tt == t && thr == "true") c++
    } END { print c + 0 }' "$W")
    if [ "$n" -eq 0 ]; then
        printf "  %-12s bi chan: %-6d OK\n" "$tier" "$n"
    else
        printf "  %-12s bi chan: %-6d !! XEM LAI enforce_tiers\n" "$tier" "$n"
    fi
done

echo
echo "=============================================================="
echo "5. TAI THAT VA MUC BI SIET theo principal"
echo "=============================================================="
printf "  %-16s %6s %14s %10s %10s %s\n" \
    "PRINCIPAL" "LUOT" "CHAN" "autfs max" "autfl max" "uptime TB"
for p in gptbot oai-searchbot chatgpt-user claudebot perplexitybot; do
    awk -v p="$p" '{
        n = split($0, f, /[ \t]+/)
        pp = "-"; thr = "false"; fs = "-"; fl = "-"; up = "-"
        for (i = 1; i <= n; i++) {
            if (index(f[i], "autp=") == 1)           pp = substr(f[i], 6)
            else if (index(f[i], "autthr=") == 1)    thr = substr(f[i], 8)
            else if (index(f[i], "autfs=") == 1)     fs = substr(f[i], 7)
            else if (index(f[i], "autfl=") == 1)     fl = substr(f[i], 7)
            else if (index(f[i], "autuptime=") == 1) up = substr(f[i], 11)
        }
        if (pp != p) next
        tot++
        if (thr == "true") t++
        if (fs != "-" && fs + 0 > mxs) mxs = fs + 0
        if (fl != "-" && fl + 0 > mxl) mxl = fl + 0
        if (up != "-") { ups += up + 0; upn++ }
    }
    END {
        if (tot == 0) { printf "  %-16s %6s  khong co luot nao\n", p, "-"; exit }
        printf "  %-16s %6d %7d (%5.1f%%) %10.1f %10.1f", \
            p, tot, t + 0, t * 100 / tot, mxs + 0, mxl + 0
        if (upn > 0) printf " %9.2fs\n", ups / upn; else printf " %10s\n", "-"
    }' "$W"
done

cat <<'EOF'

=============================================================
CACH DOC
=============================================================
Muc 1 autthr nho hon nhieu autwould
  -> phan lon luot vuot han muc thuoc tang KHONG enforce. Day la thiet ke:
     chi operator va contradicted bi shed.
Muc 2 fleet:* dung dau
  -> truc principal-toan-may dang la rang buoc, tuc phep nhan mau so theo
     host da bi chan. Neu server:* dung dau thi tran toan may moi la rang
     buoc, va moi principal dang chia nhau no.
Muc 4 bat ky dong co "!!"
  -> mot tang le ra khong bi chan da bi chan. Doc enforce_tiers NGAY.
Muc 5 autfl max ma KHONG vuot han muc cau hinh
  -> principal do chua bao gio cham tran, nen KHONG THE bi truc fleet chan.
     Neu no van co "chan > 0" thi mot truc khac da chan no.
EOF
