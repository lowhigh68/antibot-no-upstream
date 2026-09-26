#!/bin/bash
# postdeploy.sh — BAO CAO CHUAN sau moi lan deploy WAF. CHI DOC.
#
# Moi so lieu tinh tu moc `deployed=` trong VERSION cua cay da deploy, tren MOI
# file log co ghi sau moc do — ke ca file da xoay (.1 / -YYYYMMDD / .gz). Ten file
# xoay khac nhau theo may; doc cung `waf.log.1` la mat IM LANG phan truoc nua dem.
# Muc 0 in file da doc va cua so THAT.
#
# Nam trong repo, khong phai script dan tay: khi cot log doi thi bao cao doi CUNG
# commit. V7 doi `argrule`/`aorig` sang `nf`/`fl`/`fn`, va ban dan tay cu (w2h) se
# bao "khong co gi" trong im lang.
#
# DUNG (tren server, ~24 gio sau deploy):
#   bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/postdeploy.sh
export LC_ALL=C
A=${A:-/usr/local/openresty/nginx/conf/antibot}
L=${L:-/var/log/antibot}
E=${E:-/usr/local/openresty/nginx/logs/error.log}

T=$(sed -n 's/^deployed=//p' "$A/VERSION" 2>/dev/null)
S=$(sed -n 's/^sha=//p' "$A/VERSION" 2>/dev/null)
[ -n "$T" ] || { echo "khong doc duoc $A/VERSION"; exit 2; }

since() { find "$1" -maxdepth 1 -name "$2*" -newermt "$T" -printf '%T@ %p\n' 2>/dev/null | sort -n | cut -d' ' -f2; }
catf()  { for f in "$@"; do case "$f" in *.gz) zcat "$f";; *) cat "$f";; esac; done; }
names() { for f in "$@"; do printf ' %s' "${f##*/}"; done; }

W=$(mktemp /tmp/wafwin.XXXXXX); J=$(mktemp /tmp/wafpj.XXXXXX); K=$(mktemp /tmp/wafpk.XXXXXX)
trap 'rm -f "$W" "$J" "$K"' EXIT
WF=$(since "$L" waf.log)
catf $WF | awk -v T="$T" 'substr($0,2,19) >= T' > "$W"

MIN=$(( ( $(date +%s) - $(date -d "$T" +%s) ) / 60 ))
echo "=== 0. Cua so do ==="
echo "  ban $S  deploy $T  -> $MIN phut"
echo "  file doc   :$(names $WF)"
[ -n "$WF" ] || echo "  KHONG CO file waf.log nao ghi sau deploy - moi so duoi day VO NGHIA"
echo "  cua so THAT: $(head -n 1 "$W" | cut -c2-20) -> $(tail -n 1 "$W" | cut -c2-20)"
echo "  dong [waf] $(grep -cF '[waf]' "$W")   dong [waf-body] $(grep -cF '[waf-body]' "$W")"
echo "  rid dung chung >1 dong: $(grep -o " rid=[0-9a-f]*" "$W" | sort | uniq -d | wc -l)  (tu e4e5f43 phai > 0)"
[ "$MIN" -lt 1440 ] && echo "  CHUA DU 24 GIO - upload cua admin thua, muc 3-4 co the con rong"

echo "=== 1. Cong im lang (ca hai phai = 0) ==="
EF=$(since "$(dirname "$E")" "$(basename "$E")")
echo "  file doc:$(names $EF)"
[ -n "$EF" ] || echo "  KHONG doc duoc error log - hai so duoi KHONG do duoc"
catf $EF | awk -v T="$(printf '%s' "$T" | tr '-' '/')" '
/^[0-9][0-9][0-9][0-9]\// && substr($0,1,19) >= T {
    if (index($0, "[waf-v2] config")) c++
    if (index($0, "registry mismatch")) r++
}
END { printf "  cau hinh bi tu choi : %d\n  registry lech       : %d\n", c, r }'

echo "=== 2. Phan quyet (wafstat 0b/0c, CHI tren cua so) ==="
bash "$A/waf/scripts/wafstat.sh" "$W" 2>/dev/null \
| sed -n '/=== 0b/,/=== 1\./p' | sed '$d' | grep -v '^=== 0b\|^dong co cot'

P='{ delete f; for (i = 1; i <= NF; i++) { k = index($i, "="); if (k) f[substr($i, 1, k-1)] = substr($i, k+1) } }'

echo "=== 3. Luat tham so tren THAN theo VUNG (V7): vung / luat / pf ==="
grep -F '[waf-body]' "$W" | grep -F ' pf=' | awk "$P"'
{ s = (f["smp"] == "") ? 1 : f["smp"] + 0
  split(f["ip"], q, "."); net = q[1] "." q[2] "." q[3]
  split("nf fl fn", rg, " ")
  for (r = 1; r <= 3; r++) { v = f[rg[r]]
    if (v == "" || v == "-") continue
    m = split(v, ids, ",")
    for (j = 1; j <= m; j++) { key = rg[r] "  " ids[j] "  pf=" f["pf"]; c[key] += s; n++
      if (!((key SUBSEP net) in seen)) { seen[key, net] = 1; src[key]++ } } } }
END {
    if (!n) { print "  (khong co luat tham so nao tren than)"; exit }
    printf "  %-48s %6s %6s\n", "vung / luat / pf", "luot", "nguon"
    for (k in c) printf "  %-48s %6d %6d\n", k, c[k], src[k]
}'

echo "=== 4. Than multipart: chung minh duoc bao nhieu (uoc tinh, da nhan smp) ==="
grep -F '[waf-body]' "$W" | grep -F ' pf=' | awk "$P"'
f["ct"] == "multipart" {
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    c["pf=" f["pf"] "  fntr=" f["fntr"]] += s; tot += s; n++
}
END {
    if (!n) { print "  (khong co than multipart nao)"; exit }
    for (k in c) printf "  %-30s %8d\n", k, c[k]
    printf "  ---- tong multipart: %d\n", tot
}'

echo "=== 5. Than KHONG soi duoc (uoc tinh) ==="
grep -F '[waf-body]' "$W" | awk "$P"'
f["scan"] != "ok" && f["scan"] != "empty" && f["scan"] != "" {
    s = (f["smp"] == "") ? 1 : f["smp"] + 0; c[f["scan"]] += s; n++ }
END {
    if (!n) { print "  (khong co - tot)"; exit }
    for (k in c) printf "  scan=%-14s %8d\n", k, c[k]
}'

echo "=== 6. Phien co cookie WP dang nhap: engine quyet dinh gi ==="
grep -F '[waf]' "$W" | grep -F ' wpauth=1 ' | awk "$P"'
{ c[f["rule"] "  final=" f["final"]]++; n++
  if (f["final"] == "challenge" || f["final"] == "block") bad++ }
END {
    if (!n) { print "  (khong co)"; exit }
    for (k in c) printf "  %-52s %6d\n", k, c[k]
    if (bad) printf "  -> %d luot CHAN/THU THACH phien dang nhap: GUI NGAY\n", bad
    else print "  -> khong luot nao bi chan hay thu thach"
}'

echo "=== 7. Luat DUONG DAN tren file CO THAT bi chan / thu thach, va engine chan VI SAO ==="
grep -F '] [waf] ' "$W" \
| grep -E ' rule=(wp_plugin_direct|wp_theme_direct|wp_muplugin_direct|wp_root_unknown) ' | awk -v J="$J" "$P"'
{ n++ }
f["exists"] == "1" && (f["final"] == "challenge" || f["final"] == "block") {
    ph = (f["richness"] != "-" && f["richness"] + 0 > 0) ? "co-phien" : "-"
    c[f["rule"] "  " f["domain"] "  " f["matched"] "  " f["class"] "  " ph]++; m++
    print f["ts"] "|" f["ip"] "|" f["domain"] > J }
END {
    printf "  # %d luot luat duong dan, %d tren file co that bi chan/thu thach\n", n, m
    for (k in c) printf "  %5d  %s\n", c[k], k
}'
if [ -s "$J" ]; then
    sort -u "$J" | awk -F'|' '{ print "ts=" $1 " domain=" $3 " " }' | sort -u > "$K"
    AF=$(since "$L" antibot.log)
    echo "  antibot.log doc:$(names $AF)"
    catf $AF | grep -F -f "$K" | awk -v J="$J" '
    BEGIN { while ((getline line < J) > 0) want[line] = 1 }
    { delete f; for (i = 1; i <= NF; i++) { k = index($i, "="); if (k) f[substr($i, 1, k-1)] = substr($i, k+1) }
      if (!((f["ts"] "|" f["ip"] "|" f["domain"]) in want)) next
      n++; p = "-"; if (match(f["top"], /waf_wp_path=[0-9]+%/)) p = substr(f["top"], RSTART + 12, RLENGTH - 12)
      r = f["reason"]; sub(/=.*/, "", r)
      c[f["action"] "  reason=" r "  waf_wp_path=" p]++ }
    END { printf "  # antibot.log cung ts+ip+domain: %d dong\n", n; for (k in c) printf "  %-60s %6d\n", k, c[k] }'
fi
