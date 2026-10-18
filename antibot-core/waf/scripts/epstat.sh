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
#   4. DINH DANG THOI GIAN lay tu NOI GHI, khong tu tri nho. `antibot.log`
#      ghi SAN epoch o cot `ts=` (`logger.lua:968-974`), nen bo loc chi can
#      doc cot do — khong phan tich ngay thang, khong bu mui gio.
#
#      Ban dau cua script nay doi dinh dang nginx access log
#      (`[dd/Mon/yyyy:HH:MM:SS +0700]`) va con bu mui gio cho no. Regex ay
#      KHONG KHOP DONG NAO cua `antibot.log`, nen bo loc vut sach ca file va
#      bao "dong sau moc: 0" tren mot may dang tai 132 — cua so 539 phut, may
#      chac chan co luu luong. Dung ho voi `uri=` (that ra la `matched=`) va
#      `autom=` (that ra la `aut=`).
#
#      BAY KEP: fixture cua oracle cung sai y het (dung `ts=a` + dau thoi
#      gian kieu nginx), nen 34 phep thu van xanh trong khi tren may that bo
#      loc hong hoan toan. Mot bo loc tra 0 tren may chac chan co luu luong
#      la dau hieu BO LOC HONG, khong phai "chua xay ra".
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
for col in epif epwould epcause epshape epsrc epproof epmode epq epck \
           epswarm epswh epswn epswmode epswscope epswuntil epswdeg \
           epsif epsifmode epsifgate epsifover epsifdeg; do
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

# `antibot.log` ghi SAN epoch trong cot `ts=` (`logger.lua:968-974`:
# `"[%s] [antibot] ts=%d ..."` voi `ngx.time()`), nen KHONG phai phan tich
# ngay thang gi het — doc thang cot do.
#
# Ban dau cua script nay doi `[dd/Mon/yyyy:HH:MM:SS +0700]` theo dinh dang
# nginx access log, roi bo cong suc bu mui gio cho no. Nhung `antibot.log`
# dung `[%Y-%m-%d %H:%M:%S]`, khong co thang chu va khong co offset, nen
# regex kia KHONG KHOP DONG NAO va bo loc im lang vut het ca file: do duoc
# 18-10, cua so 539 phut tren may dang tai nang ma bao `dong sau moc: 0`.
#
# Bai hoc giong ca `uri=` (that ra la `matched=`) va `autom=` (that ra la
# `aut=`): doc dinh dang tu NOI GHI, khong lay tu tri nho. Mot bo loc tra 0
# tren may chac chan co luu luong la dau hieu bo loc hong, khong phai dau
# hieu "chua xay ra".
read_all | awk -v moc="$MOC" '
{
    if (match($0, /(^|[[:space:]])ts=[0-9]+/)) {
        t = substr($0, RSTART, RLENGTH)
        sub(/^.*ts=/, "", t)
        if (t + 0 >= moc) print
    }
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
echo "-- epsif (whole-server live occupancy per endpoint family) --"
echo "  epsifover=true = raw occupancy only; epcause=server_inflight means"
echo "  every configured evidence gate (normally swarm) also passed."
awk '
function value(name,    i, p) {
    p = name "="
    for (i = 1; i <= NF; i++) if (index($i, p) == 1) return substr($i, length(p) + 1)
    return "-"
}
{
    ep = value("ep")
    split(value("epsif"), pair, "/")
    if (ep != "-" && pair[1] ~ /^[0-9]+$/ && pair[2] ~ /^[0-9]+$/) {
        key = ep " mode=" value("epsifmode") " gate=" value("epsifgate")
        rows[key]++
        if (value("epsifover") == "true") over[key]++
        if (value("epsifdeg") == "true") degraded[key]++
        if (pair[1] + 0 > maximum[key] + 0) maximum[key] = pair[1] + 0
        limit[key] = pair[2] + 0
        if (value("epcause") ~ /(^|,)server_inflight(,|$)/) candidate[key]++
    }
}
END {
    for (key in rows)
        printf "%s rows=%d raw_over=%d compound_candidate=%d degraded=%d max=%d/%d\n",
            key, rows[key], over[key] + 0, candidate[key] + 0,
            degraded[key] + 0, maximum[key] + 0, limit[key] + 0
}' "$WIN" | sort

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
echo "── route-shape swarm (gom IP theo /24, IPv6 theo /64) ───────"
echo "  Chi `epswarm=true` + epswmode=enforce moi la cong chan swarm."
echo "  Shape invalid/emergency co the van chan doc lap khi swarm shadow."
awk '
function value(name,    i, p) {
    p = name "="
    for (i = 1; i <= NF; i++) if (index($i, p) == 1) return substr($i, length(p) + 1)
    return "-"
}
{
    ep = value("ep")
    mode = value("epswmode")
    if (ep != "-" && mode != "-") {
        key = ep " mode=" mode " scope=" value("epswscope")
        rows[key]++
        if (value("epswarm") == "true") opened[key]++
        if (value("epswdeg") == "true") degraded[key]++
        split(value("epswh"), h, "/")
        split(value("epswn"), n, "/")
        if (h[1] ~ /^[0-9]+$/ && h[1] + 0 > maxh[key] + 0) maxh[key] = h[1] + 0
        if (n[1] ~ /^[0-9]+$/ && n[1] + 0 > maxn[key] + 0) maxn[key] = n[1] + 0
        if (h[2] ~ /^[0-9]+$/) hitlim[key] = h[2] + 0
        if (n[2] ~ /^[0-9]+$/) netlim[key] = n[2] + 0
    }
}
END {
    for (key in rows)
        printf "%s rows=%d open=%d degraded=%d max_hits=%d/%d max_networks=%d/%d\n",
            key, rows[key], opened[key] + 0, degraded[key] + 0,
            maxh[key] + 0, hitlim[key] + 0, maxn[key] + 0, netlim[key] + 0
}' "$WIN" | sort

echo
echo "── wp/v2 item: query × cookie × cost ────────────────────────"
echo "  epck chi la CO Cookie header, KHONG phai bang chung dang nhap."
echo "  rown>0 o muc FP ben duoi moi la cookie session da duoc xac nhan."
awk '
function value(name,    i, p) {
    p = name "="
    for (i = 1; i <= NF; i++) if (index($i, p) == 1) return substr($i, length(p) + 1)
    return "-"
}
{
    ep = value("ep")
    if (ep == "wp_rest_posts_item" || ep == "wp_rest_tags_read") {
        key = ep " query=" value("epq") " cookie=" value("epck")
        rows[key]++
        if (value("epwould") == "true") {
            would[key]++
            cause = value("epcause")
            if (cause ~ /(^|,)inflight(,|$)/) would_if[key]++
            if (cause ~ /(^|,)rate_short(,|$)/) would_rs[key]++
            if (cause ~ /(^|,)rate_long(,|$)/) would_rl[key]++
            if (cause ~ /(^|,)emergency(,|$)/) would_em[key]++
            if (cause ~ /(^|,)server_inflight(,|$)/) would_sif[key]++
        }
        if ((value("rown") + 0) > 0) trusted[key]++

        up = value("epuptime")
        if (up ~ /^[0-9]+([.][0-9]+)?$/) {
            upstream[key]++
            upsum[key] += up
            if (up + 0 > upmax[key] + 0) upmax[key] = up
        }

        inf = value("epif")
        split(inf, pair, "/")
        if (pair[1] ~ /^[0-9]+$/ && pair[1] + 0 > ifmax[key] + 0)
            ifmax[key] = pair[1] + 0
        sinf = value("epsif")
        split(sinf, spair, "/")
        if (spair[1] ~ /^[0-9]+$/ && spair[1] + 0 > sifmax[key] + 0)
            sifmax[key] = spair[1] + 0
    }
}
END {
    for (key in rows)
        printf "%s rows=%d would=%d em=%d if=%d sif=%d rs=%d rl=%d trusted=%d upstream=%d avg_up=%.3f max_up=%.3f max_if=%d max_sif=%d\n",
            key, rows[key], would[key] + 0, would_em[key] + 0,
            would_if[key] + 0, would_sif[key] + 0,
            would_rs[key] + 0, would_rl[key] + 0, trusted[key] + 0,
            upstream[key] + 0,
            upstream[key] ? upsum[key] / upstream[key] : 0,
            upmax[key] + 0, ifmax[key] + 0, sifmax[key] + 0
}' "$WIN" | sort

echo
echo "── ti le would (gom ca emergency; mau so = dong co ep=) ──"
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
Emergency oEmbed/tags dang chan local 429, nen khong dung cac dong `emergency`
de tune rate/inflight. Tat RIENG emergency cua endpoint can thu, roi moi thu
mot cua so shadow co kiem soat; khong tat ca hai endpoint cung luc.

Viet truoc de khoi hop ly hoa sau:
  1. epif tu o 1..3, phan duoi tran chiem da so
  2. epwould=true TUT MANH so voi 41,9% do duoc tren ban chia scope (28-246,
     18-10). Van con cao sau khi gop = tai THAT cua pool, khi do enforce co
     co so; tut ve gan 0 = tran 3 dung nhung chua can enforce.
  3. epcause chi co `inflight`, khong lan shape_*/cross_host
  4. would=true KHONG chua khach mang cookie that
Chua dat ca bon thi giu shadow. Tat oembed bang mu-plugin van la duong re nhat.
EOF
