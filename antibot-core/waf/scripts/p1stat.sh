#!/bin/bash
# p1stat.sh — theo doi cac thay doi P1 tren mot may, tu moc deploy.
#
# VI SAO LA SCRIPT CHU KHONG PHAI HAM DAN TAY. Ban truoc do la mot ham
# `since_deploy()` dinh nghia trong shell: no MAT khi doi shell hoac mo session
# moi (`bash: since_deploy: command not found`), va no chi doc `antibot.log` nen
# CAT IM LANG neu moc deploy nam truoc lan xoay vong nua dem.
#
# BA BAY DA GHIM O DAY, deu la bay da tung lam ra so sai:
#
#   1. XOAY VONG LOG. Dung `find -newermt` + `zcat` nhu `postdeploy.sh:48`, va
#      IN RA ten file da doc + cua so THAT. Ten file xoay khac nhau theo may,
#      nen hardcode `antibot.log.1` la sai.
#   2. MA CHUA LEN MAY. Moi phep do moi deu co CONG KIEM chuoi can do ton tai
#      trong cay DANG CHAY. `grep -c` tra 0 mo ho giua "chua xay ra" va "ma
#      chua co" — chi cong kiem phan biet duoc. Cong sai => thoat, khong in so.
#   3. DAN SO = 0. Moi bang deu in MAU SO. Mot ty le tren dan so 1 khong phai
#      ket luan, va mot `0` tren dan so 0 khong chung minh gi ca.
#
# Chay: bash p1stat.sh [duong/dan/antibot.log]
# Khong sua gi, khong ghi gi — chi doc.

set -u

LOG=${1:-/var/log/antibot/antibot.log}
LOGDIR=$(dirname "$LOG")
LOGBASE=$(basename "$LOG")
LIVE=${LIVE:-/usr/local/openresty/nginx/conf/antibot}
STAMP=${STAMP:-/var/log/antibot/.deploy_ts}

# ── 0. MOC DEPLOY ────────────────────────────────────────────────────
# `deploy.sh` ghi `date +%s` vao `.deploy_ts` SAU khi reload thanh cong, giu 50
# dong. Khong dung mtime cua file trong cay da deploy: `rsync -a` BAO TOAN mtime
# NGUON, nen mtime dich la luc `git pull` ghi file — con file KHONG doi trong lan
# pull do con mang mtime cua lan pull TRUOC.
if [ ! -f "$STAMP" ]; then
    echo "khong thay $STAMP — deploy.sh chua ghi moc nao. Dat STAMP=/duong/dan neu khac."
    exit 2
fi
D=$(tail -n1 "$STAMP")
case "$D" in
    ''|*[!0-9]*) echo "moc deploy khong phai epoch: '$D'"; exit 2;;
esac
NOW=$(date +%s)
AGE=$(( (NOW - D) / 60 ))

echo "=== 0. Cua so do ==="
echo "  moc deploy : $D ($(date -d "@$D" '+%Y-%m-%d %H:%M:%S')) -> $AGE phut truoc"

# ── 1. CONG KIEM: ma da len may chua ────────────────────────────────
# Moi cot duoi day thuoc mot commit cu the. Thieu cot nao thi phep do tuong ung
# tra 0 VO NGHIA chu khong phai "su kien chua xay ra".
LG="$LIVE/async/logger.lua"
if [ ! -f "$LG" ]; then
    echo "  KHONG thay $LG — dat LIVE=/duong/dan neu khac"; exit 2
fi
miss=""
for s in iptev ipku held_cookie ideg; do
    grep -q "$s" "$LG" 2>/dev/null || miss="$miss $s"
done
if [ -n "$miss" ]; then
    echo "  CONG KIEM SAI: $LG thieu:$miss"
    echo "  => ma chua len may. git pull && bash nginx/deploy.sh roi chay lai."
    echo "  KHONG in so: mot 0 o day khong phan biet duoc 'chua xay ra' voi 'chua co ma'."
    exit 3
fi
echo "  cong kiem  : OK (iptev ipku held_cookie ideg deu co trong logger.lua)"

# ── 2. CHON FILE, KE CA FILE DA XOAY ────────────────────────────────
TREF=$(date -d "@$D" '+%Y-%m-%d %H:%M:%S')
FILES=$(find "$LOGDIR" -maxdepth 1 -name "$LOGBASE*" -newermt "$TREF" \
        -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2)
# File DANG ghi luon phai co mat: neu no chua xoay thi mtime cua no moi hon moc,
# nhung neu may vua xoay xong thi file moi co the chua co dong nao.
case "$FILES" in *"$LOG"*) :;; *) FILES="$FILES $LOG";; esac

catf() { for f in $1; do [ -f "$f" ] || continue; case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; done; }

W=$(mktemp /tmp/p1stat.XXXXXX)
trap 'rm -f "$W"' EXIT
catf "$FILES" | awk -v d="$D" '
{ for (i = 1; i <= NF; i++) if ($i ~ /^ts=/) { split($i, a, "="); if (a[2] + 0 >= d) print; break } }
' > "$W"

N=$(wc -l < "$W")
printf '  file doc   :'; for f in $FILES; do [ -f "$f" ] && printf ' %s' "${f##*/}"; done; echo
echo "  dong sau moc: $N"
if [ "$N" -eq 0 ]; then
    echo "  KHONG co dong nao sau moc deploy — moi so duoi day VO NGHIA."
    exit 0
fi

# ── 3. P1.1 — mien tru ban IP Tier-2 ────────────────────────────────
# Cot chi in khi `ctx.ip_shared` (logger.lua), tuc chi IP da vuot nguong chia se
# nhe. Dan so thap la BINH THUONG, khong phai mat du lieu.
echo
echo "=== 1. P1.1 Tier-2 (chi IP da vuot shared_ua_min) ==="
awk '
{ e = ""; sv = ""; w = ""; ip = ""
  for (i = 1; i <= NF; i++) {
      split($i, x, "=")
      if (x[1] == "iptev")   e  = x[2]
      if (x[1] == "ipsv")    sv = x[2]
      if (x[1] == "iptwarm") w  = x[2]
      if (x[1] == "ip")      ip = x[2]
  }
}
e != "" {
    tot++; ev[e]++
    if (sv == "true")  imm++
    if (sv == "false") noimm++
    if (w  == "true") { warm++; if ($0 ~ /ts=([0-9]+)/) { match($0, /ts=[0-9]+/); lw = substr($0, RSTART + 3, RLENGTH - 3) + 0 } }
    # Thu P1.1 nham vao: IP gui cookie nhung cookie KHONG do host cap.
    if (sv == "false" && e == "rejected" && ip != "") rej_ip[ip] = 1
    # Doi chung: IP co bang chung first-party that.
    if (e == "known" && ip != "") known_ip[ip] = 1
}
END {
    if (tot == 0) { print "  dan so = 0 — chua IP nao vuot nguong chia se. Khong ket luan gi."; exit }
    printf "  dan so           : %d dong\n", tot
    printf "  bang chung cookie: known=%d legacy=%d rejected=%d none=%d\n",
           ev["known"]+0, ev["legacy"]+0, ev["rejected"]+0, ev["none"]+0
    printf "  mien tru Tier-2  : ipsv=true=%d  ipsv=false=%d\n", imm+0, noimm+0
    nr = 0; for (k in rej_ip) nr++
    nk = 0; for (k in known_ip) nk++
    printf "  IP co first-party: %d\n", nk
    printf "  IP cookie bi tu choi (distinct): %d\n", nr
    if (warm > 0)
        printf "  con trong grace   : %d dong (lan cuoi ts=%d)\n", warm, lw
    else
        print  "  con trong grace   : 0 — grace da tat, trang thai DA ON DINH"
    print ""
    if (nr > 0)
        printf "  >> XEM: %d IP bi tu choi cookie. Doi chieu chung co `known` o cua so truoc khong;\n     neu co thi dang thu hoi mien tru cua khach THAT -> rollback 63e52d2.\n", nr
    if (ev["rejected"]+0 == 0 && ev["none"]+0 > 0 && nk == 0)
        print  "  >> KHONG FP, nhung CUNG CHUA chung minh cong `known` bao ve dung ai:\n     gan nhu khong co khach that di qua cong nay. Can do tren may nhieu khach."
}' "$W"

# `rejected` tap trung mot domain = `cookie_registry` host do chua truong thanh,
# KHONG phai bot. Day la ca de doc sai nhat nen tach bang rieng.
if grep -q ' iptev=rejected ' "$W"; then
    echo
    # Dau nguoc trong chuoi nhay DOI bi shell THAY THE LENH: ban dau dong nay
    # viet `rejected` trong backtick va shell chay `rejected` nhu mot lenh
    # ("command not found") roi in tieu de MAT chu. Dung nhay don.
    echo '  --- rejected theo host (cao tap trung 1 host = registry chua hoc du) ---'
    awk '/ iptev=rejected /{
        h = ""
        for (i = 1; i <= NF; i++) { split($i, x, "="); if (x[1] == "host") h = x[2] }
        if (h != "") c[h]++; else nohost++
    }
    END { for (k in c) printf "    %-45s %d\n", k, c[k]
          if (nohost) printf "    (%d dong khong co cot host=)\n", nohost }' "$W" | sort -k2 -rn | head -10
fi

# ── 4. P1.0 — intelligence degraded ─────────────────────────────────
echo
echo "=== 2. P1.0 intelligence degraded (ky vong 0) ==="
IDEG=$(grep -c ' ideg=' "$W" || true)
printf '  dong co ideg= : %d / %d\n' "${IDEG:-0}" "$N"
[ "${IDEG:-0}" -gt 0 ] && awk '{for(i=1;i<=NF;i++){split($i,x,"=");if(x[1]=="ideg")c[x[2]]++}}
    END{for(k in c) printf "    %-24s %d\n", k, c[k]}' "$W" || :

# ── 5. P0.2/telemetry — goodbot verify + cookie crawler ─────────────
echo
echo "=== 3. P0.2 goodbot verify ==="
GB=$(grep -c ' gbv=' "$W" || true)
printf '  dong vao lane verify: %d\n' "${GB:-0}"
if [ "${GB:-0}" -gt 0 ]; then
    awk '{v="";for(i=1;i<=NF;i++){split($i,x,"=");if(x[1]=="gbv")v=x[2]}}
         v!=""{c[v]++} END{for(k in c) printf "    gbv=%-24s %d\n", k, c[k]}' "$W" | sort -k2 -rn
fi
# Su kien an ninh: UA crawler DANG GIU ve `verified:` con hieu luc (da qua PoW
# roi moi mang UA crawler). Ky vong 0. Cung ghi ngx.WARN nen co ca o error.log.
HELD=$(grep -c ' gbhuman=held_cookie' "$W" || true)
REJ=$(grep -c ' gbhuman=reject' "$W" || true)
printf '  gbhuman=held_cookie : %d   <- SU KIEN AN NINH, ky vong 0\n' "${HELD:-0}"
printf '  gbhuman=reject      : %d   (dan so crawler, chi de doi chieu)\n' "${REJ:-0}"

# Cap shared-ASN khi DNS degraded. `capped=0` nghia la CHUA GAP CA NAO — can
# resolver timeout trung luc crawler AS15169/8075 ghe, chuyen hiem. Nen 0 o day
# KHONG phai bang chung cap khong chay.
echo
echo "=== 4. P0.2 cap shared-ASN khi DNS degraded ==="
awk '/reason=good_bot_dns_degraded_cap/ {
    n++; if ($0 ~ / action=(block|challenge) /) bad++
}
END {
    printf "  capped=%d  violated=%d\n", n+0, bad+0
    if (n+0 == 0) print "  capped=0 = CHUA GAP CA NAO (can timeout trung luc crawler ghe), KHONG phai cap hong."
    if (bad+0 > 0) print "  >> BAT BIEN VI PHAM: co luot bi block/challenge du da duoc cap."
}' "$W"
