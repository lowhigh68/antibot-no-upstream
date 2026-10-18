#!/bin/bash
# epstat.sh — doc phan phoi `endpoint_guard` tu moc deploy, tren MOT may.
#
# Cau hoi script nay tra loi: tran `inflight` da cau hinh co dung voi tai THAT
# cua pool PHP-FPM khong, va da du bang chung de promote `shadow -> enforce`
# chua. Khong sua gi, khong ghi gi — chi doc.
#
# BON BAY DA GHIM O DAY, ba cai dau giong `p1stat.sh`, cai thu tu la rieng:
#
#   1. MOC DEPLOY. Dung `.deploy_ts` do `deploy.sh` ghi SAU khi reload thanh
#      cong, KHONG dung mtime cua file trong cay da deploy: `rsync -a` BAO TOAN
#      mtime NGUON, nen mtime dich la luc `git pull` ghi file — va file khong
#      doi trong lan pull do con mang mtime cua lan pull TRUOC. Ban dau cua
#      script nay dung mtime va do chinh la cai bay `p1stat.sh` da ghi lai.
#
#   2. XOAY VONG LOG. `find -newermt` + `zcat`, va IN RA ten file da doc. Ten
#      file xoay khac nhau theo may nen hardcode `antibot.log.1` la sai. Phep
#      kiem "da co file hien tai chua" phai so TUNG PHAN TU: `case $F in
#      *"$LOG"*)` la phep thu CHUOI CON, nen `antibot.log.1.gz` khop
#      `antibot.log` va file song bi bo im lang.
#
#   3. MA CHUA LEN MAY. Cong phien ban chay TRUOC moi phep dem. `grep -c` tra 0
#      khong phan biet duoc "chua xay ra" voi "ma chua deploy". Cong sai thi
#      thoat rc=3 va KHONG in so nao.
#
#   4. MUI GIO. `awk mktime` doc theo gio DIA PHUONG cua may chay awk, nhung
#      dong log nginx mang san offset (`+0700`). Do duoc: mktime cho
#      `2025 10 9 7 53 20` tra 1759971200 trong khi epoch that la 1759996400 —
#      lech dung 25200s = 7 tieng, tuc ca cua so dich sang mot phia. Day la ho
#      lan thu hai cua bay timestamp: lan truoc la so sanh CHUOI tren
#      `dd/Mon/yyyy` (`30/Apr` > `17/Oct` vi `3` > `1`) nen gan nhu ca file loi
#      vao cua so va sinh ra con so "3.830 req/s" khong ton tai.
#
# Chay: bash epstat.sh [epoch_moc] [duong/dan/antibot.log]

set -u

MOC_ARG=${1:-}
LOG=${2:-/var/log/antibot/antibot.log}
LOGDIR=$(dirname "$LOG")
LOGBASE=$(basename "$LOG")
LIVE=${LIVE:-/usr/local/openresty/nginx/conf/antibot}
STAMP=${STAMP:-/var/log/antibot/.deploy_ts}

# Bo bao nhieu giay dau sau reload. Slot cu con song
# `slot_retention(180) + slot_bucket(30) + 1` = 211s: request da `admit` truoc
# reload van giu slot trong shared dict, nen giai doan do la trang thai pha
# tron. Lam tron len 300.
SETTLE=${SETTLE:-300}

# ── 0. CONG PHIEN BAN ────────────────────────────────────────────────
POL="$LIVE/waf/endpoint_policy.lua"
GUARD="$LIVE/l7/endpoint_guard.lua"
LOGGER="$LIVE/async/logger.lua"

for f in "$POL" "$GUARD" "$LOGGER"; do
    if [ ! -r "$f" ]; then
        echo "GATE FAIL: khong doc duoc $f"
        echo "  (dat LIVE=/duong/dan neu cay deploy o cho khac)"
        exit 3
    fi
done

# `scope_id` phai nhan MOT tham so. Ban dau khoa theo `docroot|prefix`, va do
# tren cloud28-246 18-10 thi WPML (`/vi/`, `/ja/`, `/zh/`, `/TH/` tren CUNG mot
# `public_html`) bi tach thanh bon budget, nen tran 3 thanh 3-moi-ngon-ngu va
# `epif` leo tới 15/3. Doc `epif` tren ban cu la doc mot con so da bi nhan len.
if ! grep -q 'local function scope_id(docroot)' "$POL"; then
    echo "GATE FAIL: scope_id chua gop theo docroot — ban dang chay con chia"
    echo "           budget theo prefix, nen moi so epif deu bi nhan len."
    grep -n 'scope_id' "$POL" | head -5 | sed 's/^/  /'
    exit 3
fi
if grep -q 'scope_id(docroot, prefix)' "$POL"; then
    echo "GATE FAIL: con cho goi scope_id(docroot, prefix)"
    grep -n 'scope_id(docroot, prefix)' "$POL" | head -3 | sed 's/^/  /'
    exit 3
fi

MISSING=""
for col in epif epwould epcause epshape epsrc epproof epmode; do
    grep -q "$col=" "$LOGGER" || MISSING="$MISSING $col"
done
if [ -n "$MISSING" ]; then
    echo "GATE FAIL: logger DANG CHAY thieu cot:$MISSING"
    echo "           (deploy chua len, hoac len ban cu)"
    exit 3
fi
echo "GATE OK: scope gop theo docroot, logger du cot"

# ── 1. MOC ───────────────────────────────────────────────────────────
if [ -n "$MOC_ARG" ]; then
    D=$MOC_ARG
    SRC="tham so"
else
    if [ ! -f "$STAMP" ]; then
        echo "khong thay $STAMP — deploy.sh chua ghi moc nao."
        echo "Dat STAMP=/duong/dan, hoac truyen epoch: bash epstat.sh <epoch>"
        exit 2
    fi
    D=$(tail -n1 "$STAMP")
    SRC="$STAMP"
fi

case "$D" in
    ''|*[!0-9]*) echo "moc khong phai epoch: [$D] (nguon: $SRC)"; exit 2 ;;
esac

MOC=$((D + SETTLE))
NOW=$(date +%s)
AGE=$((NOW - MOC))

echo "moc deploy : $D  ($(date -d "@$D" '+%F %T'))   nguon: $SRC"
echo "bo settle  : ${SETTLE}s  -> tinh tu $MOC ($(date -d "@$MOC" '+%F %T'))"
echo "hien tai   : $NOW ($(date -d "@$NOW" '+%F %T'))"

if [ "$AGE" -lt 0 ]; then
    echo "CHUA TOI: con $(( -AGE ))s nua moi het settle. Cho roi chay lai."
    exit 0
fi
echo "cua so     : ${AGE}s (~$((AGE / 60)) phut)"
if [ "$AGE" -lt 1800 ]; then
    echo "CANH BAO: chua du 30 phut sau settle — so lieu con mong, doc de tham khao."
fi

# ── 2. CHON FILE, KE CA FILE DA XOAY ─────────────────────────────────
FILES=$(find "$LOGDIR" -maxdepth 1 -name "$LOGBASE*" \
        -newermt "@$MOC" 2>/dev/null | sort)

# So TUNG PHAN TU, khong dung `case ... *"$LOG"*`: phep thu chuoi con lam
# `antibot.log.1.gz` khop `antibot.log`, va khi chi co file xoay moi hon moc
# thi file DANG GHI bi bo im lang.
HAVE_CURRENT=0
for f in $FILES; do
    [ "$f" = "$LOG" ] && HAVE_CURRENT=1
done
[ "$HAVE_CURRENT" -eq 1 ] || FILES="$FILES $LOG"

echo "doc file   :"
for f in $FILES; do
    [ -r "$f" ] && echo "   $f"
done

read_all() {
    for f in $FILES; do
        [ -r "$f" ] || continue
        case "$f" in
            *.gz) zcat "$f" ;;
            *)    cat "$f"  ;;
        esac
    done
}

WIN=$(mktemp) || exit 2
trap 'rm -f "$WIN"' EXIT

read_all | awk -v moc="$MOC" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
    for (i = 1; i <= 12; i++) mon[m[i]] = i
    # Chenh giua gio dia phuong cua may nay va UTC, do MOT lan.
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
    t += local_off              # coi nhu da doc ra gio UTC
    off = 0
    if (match($0, /[+-][0-9]{4}\]/)) {
        o = substr($0, RSTART, 5)
        sign = (substr(o, 1, 1) == "-") ? -1 : 1
        off = sign * (substr(o, 2, 2) * 3600 + substr(o, 4, 2) * 60)
    }
    t -= off                   # bu offset THAT cua dong log -> epoch
    if (t >= moc) print
}' > "$WIN"

TOTAL=$(wc -l < "$WIN")
EPROWS=$(grep -c ' ep=' "$WIN")

echo
echo "dong sau moc: $TOTAL"
echo "dong co ep= : $EPROWS"
if [ "$EPROWS" -eq 0 ]; then
    echo
    echo "KET LUAN: chua co row endpoint nao sau moc."
    echo "  Hoac chua co traffic oembed, hoac cong WP-root tu choi (doc epproof)."
    exit 0
fi

echo
echo "── endpoint ─────────────────────────────────────────"
grep -oE ' ep=[a-z_]+' "$WIN" | sort | uniq -c | sort -rn

echo
echo "── epif (in-flight / tran) ──────────────────────────"
grep -oE 'epif=[0-9]+/[0-9]+' "$WIN" \
  | awk -F'[=/]' '{print $2, $3}' | sort -n | uniq -c \
  | awk '{printf "  %6d  epif=%s/%s%s\n", $1, $2, $3,
          ($2 + 0 > $3 + 0 ? "   <-- VUOT TRAN" : "")}'

echo
echo "── would / cause ────────────────────────────────────"
grep -oE 'epwould=(true|false)' "$WIN" | sort | uniq -c
grep -oE 'epcause=[a-z_,]+' "$WIN" | sort | uniq -c | sort -rn

echo
echo "── shape (cong de promote shape_mode) ───────────────"
echo "  allowlist chi co url/format/maxwidth/_locale/rest_route; maxheight va"
echo "  callback la tham so CHUAN oEmbed nhung van se ra unknown_arg."
grep -oE 'epshape=[a-z_]+' "$WIN" | sort | uniq -c | sort -rn

echo
echo "── mode / proof / source ────────────────────────────"
grep -oE 'epmode=[a-z]+'   "$WIN" | sort | uniq -c | sort -rn
grep -oE 'epproof=[a-z_]+' "$WIN" | sort | uniq -c | sort -rn
grep -oE 'epsrc=[a-z_]+'   "$WIN" | sort | uniq -c | sort -rn

echo
echo "── ti le vuot tran (mau so = dong co ep=) ───────────"
OVER=$(grep -c 'epwould=true' "$WIN")
awk -v o="$OVER" -v t="$EPROWS" 'BEGIN {
    printf "  epwould=true: %d / %d = %.1f%%\n", o, t, (t ? o * 100 / t : 0)
}'

echo
echo "── khach THAT trong tap would (cong FP) ─────────────"
# Chi dem `rown>0`: UA trinh duyet KHONG phai bang chung nguoi that (da sai 4
# lan). Thuoc dung la dem trong tap CO cookie session that.
WOULD=$(grep 'epwould=true' "$WIN" | wc -l)
WOULD_COOKIE=$(grep 'epwould=true' "$WIN" \
  | grep -cE 'rown=[1-9]|rown=0\.[1-9]' || true)
echo "  would=true            : $WOULD"
echo "  trong do co cookie that: $WOULD_COOKIE"
if [ "$WOULD" -gt 0 ] && [ "$WOULD_COOKIE" -eq 0 ]; then
    echo "  -> KHONG co khach mang cookie that nao trong tap se bi chan"
fi

cat <<'EOF'

── DIEU KIEN promote inflight shadow -> enforce ─────
Viet truoc de khoi hop ly hoa sau:
  1. epif tu o 1..3, phan duoi tran chiem da so
  2. epwould=true TUT MANH so voi 41,9% do duoc tren ban chia scope (28-246,
     18-10). Van con cao sau khi gop = tai THAT cua pool, khi do enforce co
     co so; tut ve gan 0 = tran 3 dung nhung chua can enforce.
  3. epcause chi co `inflight`, khong lan shape_*/cross_host
  4. would=true KHONG chua khach mang cookie that
Chua dat ca bon thi giu shadow. Tat oembed bang mu-plugin van la duong re nhat.
EOF
