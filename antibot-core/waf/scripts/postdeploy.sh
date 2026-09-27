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
# `rid` chi TRUNG khi MOT request sinh CA HAI dong — tuc mot POST vua co than vua
# khop luat. Con so 0 KHONG phai loi khi cua so chi co luat DUONG DAN (GET) va cac
# POST khong khop luat nao: do la hai dan so roi nhau.
#
# Chu thich cu o day ghi "tu e4e5f43 phai > 0" — SAI, va no la mot bao dong gia
# dung loai da ghi trong memory (`feedback_alert_reaches_nobody`): mot canh bao keu
# khi khong co gi sai lam nguoi ta ngung doc canh bao. Nen in CA mau so.
RID_SHARED=$(grep -o " rid=[0-9a-f]*" "$W" | sort | uniq -d | wc -l)
RID_BOTH=$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^rid=/) r = $i }
    /\[waf\]/    { law[r] = 1 }
    /\[waf-body\]/ { body[r] = 1 }
    END { n = 0; for (k in law) if (k in body) n++; print n }' "$W")
echo "  rid tren >1 dong: $RID_SHARED   request co CA dong luat lan dong than: $RID_BOTH"
echo "     (hai so nay chi khac 0 khi mot POST vua co than VUA khop luat — 0 la binh"
echo "      thuong khi cua so chi co luat duong dan tren GET)"
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

# Roadmap muc 2, GIAI DOAN DO (27-09): ghi lai phan mu / chua xac dinh, quyet sau
# tu chinh so lieu nay — chinh sach theo route (B2) va ngan sach hang doi (B3).
echo "=== 8. B1: than multipart KHONG soi het (body_multipart_incomplete), da nhan smp ==="
B1='{ why = "" }
f["ct"] == "multipart" {
    if (f["scan"] != "ok" && f["scan"] != "empty" && f["scan"] != "") why = f["scan"]
    else if (f["fntr"] ~ /^(n|hdr|bd|bval|bmax|nb)$/) why = "fntr_" f["fntr"]
    s = (f["smp"] == "") ? 1 : f["smp"] + 0 }'
grep -F '[waf-body]' "$W" | awk "$P$B1"'
why != "" { r[why] += s; t += s }
END { if (!t) { print "  (khong co)"; exit }
      for (k in r) printf "  %-16s %6d\n", k, r[k]
      printf "  ---- tong %d. 25 nhom lon nhat (luot / ly do / domain / route / lop):\n", t }'
grep -F '[waf-body]' "$W" | awk "$P$B1"'
why != "" { g[why "  " f["domain"] "  " f["method"] " " f["uri"] "  class=" f["class"] " vfy=" f["vfy"]] += s }
END { for (k in g) printf "%d\t%s\n", g[k], k }' | sort -t"$(printf '\t')" -k1,1nr | head -25 \
| awk -F'\t' '{ printf "  %6d  %s\n", $1, $2 }'

echo "=== 9. B3: hang doi soi file tam (than spill; moi luot deu ghi, smp=1) ==="
grep -F '[waf-body]' "$W" | grep -F ' qw=' | awk "$P"'
f["qw"] != "-" && f["qw"] != "" {
    n++; st[f["scan"]]++
    qw = f["qw"] + 0; qh = f["qh"] + 0; ms = (f["qms"] == "-") ? -1 : f["qms"] + 0
    if (qw > mw) mw = qw
    if (qh > mh) mh = qh
    if (ms > mm) mm = ms
    if (f["qwk"] + 0 > mk) mk = f["qwk"] + 0
    for (i = 0; i <= 4; i++) if (qh > 2 ^ i) over[i]++
    if (qw > 64) w64++
    if (qw > 128) w128++
    if (ms > 1000) s1++
    if (ms > 5000) s5++
    if (qh > hmax[f["domain"]]) hmax[f["domain"]] = qh
}
END {
    if (!n) { print "  (khong co luot nao qua pool)"; exit }
    printf "  %d luot qua pool:", n; for (k in st) printf "  scan=%s %d", k, st[k]; print ""
    printf "  qw (ca worker) lon nhat %d   >64: %d   >128 (sat tran hang doi): %d\n", mw, w64, w128
    printf "  qh (mot server block) lon nhat %d\n", mh
    printf "  neu moi server block chi duoc K luot dang bay, so luot SE VUOT:"
    for (i = 0; i <= 4; i++) printf "  K=%d:%d", 2 ^ i, over[i]; print ""
    printf "  qms lon nhat %d ms   >1s: %d   >5s: %d   KiB dang bay lon nhat (worker): %d\n", mm, s1, s5, mk
    for (d in hmax) if (hmax[d] > 1) printf "  qh lon nhat %3d  %s\n", hmax[d], d
}'

# V8 (buoc 1–2): the mo PHP theo VUNG, va gan ghep ten<->noi dung trong CUNG part.
# Muc nay tra loi cau quyet dinh cach BAT: hom nay `waf_body_php` trong so 50 ban
# theo mot co BOOLEAN toan than, nen mot `<?=` trong byte cua mot anh cho diem y
# nhu mot tep chua ma PHP that.
echo "=== 10. V8: the mo PHP nam o VUNG nao (multipart, da nhan smp) ==="
grep -F '[waf-body]' "$W" | grep -F ' pnf=' | awk "$P"'
f["ct"] == "multipart" && f["php"] != "-" && f["php"] != "" {
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    c["php=" f["php"] "  pnf=" f["pnf"] "  pfl=" f["pfl"] "  pf=" f["pf"]] += s; t += s
    if (f["php"] == "1" && f["pnf"] == "0" && f["pfl"] == "1") only_file += s
    if (f["php"] == "1" && f["pnf"] == "1") has_nonfile += s
}
END {
    if (!t) { print "  (khong co than multipart nao da soi)"; exit }
    for (k in c) printf "  %-44s %8d\n", k, c[k]
    printf "  ---- tong %d. CHI trong tep: %d.  Co ngoai tep: %d\n", t, only_file, has_nonfile
    print  "  (`php=1 pnf=1 pfl=0` = the mo o form field/header, KHONG trong tep)"
}'

echo "=== 11. V8: part record — ten nguy hiem VA noi dung nguy hiem CUNG mot tep? ==="
grep -F '[waf-body]' "$W" | grep -F ' parts=' | awk "$P"'
f["parts"] != "-" && f["parts"] != "" {
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    n = split(f["parts"], recs, ";")
    same = 0; namebad = 0; cfbad = 0
    for (i = 1; i <= n; i++) {
        split(recs[i], fld, ":")
        nf = fld[2]; cf = fld[3]
        if (nf != "0") namebad++
        if (cf != "0") cfbad++
        # CUNG part: ten co luat VA noi dung co co. `cf` co the mang ca `config_trunc`
        # o truong thu tu, nen chi lay truong 3 lam co noi dung.
        if (nf != "0" && cf != "0") { same++; sk[nf "  +  " cf] += s }
        if (fld[4] != "") trunc++
    }
    tot += s
    if (same) cung += s
    else if (namebad && cfbad) khac += s
    else if (namebad) chiten += s
    else if (cfbad) chinoidung += s
    else sach += s
}
END {
    if (!tot) { print "  (khong co than multipart nao chung minh duoc co part tep)"; exit }
    printf "  tong than co part tep: %d\n", tot
    printf "    CUNG part (ten nguy hiem + noi dung nguy hiem): %d\n", cung
    printf "    hai part KHAC nhau (correlation cu SE ban, V8 thi khong): %d\n", khac
    printf "    chi ten nguy hiem: %d    chi noi dung nguy hiem: %d    sach: %d\n",
           chiten, chinoidung, sach
    for (k in sk) printf "    cung part: %-44s %6d\n", k, sk[k]
    if (trunc) printf "    (tep cau hinh soi KHONG HET: %d part — doc `config_trunc`)\n", trunc
}'

echo "=== 12. Muc 7: DUOI hua mot dinh dang, BYTE DAU noi dang khac ==="
# Dem theo TUNG CO, khong theo "part co co gi khong": nhom quan trong nhat la TEN
# SACH + byte dau la MA (`shell.jpg` mang `MZ`/ELF) — muc 11 xep nhom do vao "chi
# noi dung nguy hiem" nen khong doc ra duoc tu do.
#
# Ca hai luat la `observe` diem 0. Con so quyet dinh co bat hay khong la ty le
# `magic_mismatch` MOT MINH (nghi ngo yeu, nhieu FP hop le: `.doc` cu vs `.docx`,
# cong cu ghi Exif khac nhau) so voi `magic_exec` (byte dau la ma da bien dich).
grep -F '[waf-body]' "$W" | grep -F ' parts=' | awk "$P"'
f["parts"] != "-" && f["parts"] != "" {
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    n = split(f["parts"], recs, ";")
    for (i = 1; i <= n; i++) {
        split(recs[i], fld, ":")
        nf = fld[2]; cf = fld[3]
        parts_tot += s
        if (cf == "0") { continue }
        ex = (cf ~ /magic_exec/);  mm = (cf ~ /magic_mismatch/)
        if (!ex && !mm) next
        if (ex) e_tot += s
        if (mm) m_tot += s
        # TEN SACH (`nf == "0"`) la nhom ca muc 7 ton tai vi no: kenh ten mu, va
        # `find_php_tag` cung mu neu khong co the mo PHP.
        if (nf == "0") {
            if (ex) e_clean += s
            if (mm) m_clean += s
        } else {
            if (ex) e_named += s
            if (mm) m_named += s
        }
        if (ex && mm) both += s
    }
}
END {
    if (!parts_tot) { print "  (khong co part tep nao)"; exit }
    printf "  tong part tep: %d\n", parts_tot
    printf "    magic_exec     (byte dau la MA):      %6d   ten sach: %6d   ten da nghi: %6d\n",
           e_tot, e_clean, e_named
    printf "    magic_mismatch (duoi khong khop):     %6d   ten sach: %6d   ten da nghi: %6d\n",
           m_tot, m_clean, m_named
    printf "    ca hai co tren cung mot part:         %6d\n", both
    if (!e_tot && !m_tot) print "  (khong co part nao lech — muc 7 chua co du lieu de quyet)"
    print  "  (`ten sach` + magic_exec = duong ca kenh TEN lan `find_php_tag` deu MU)"
}'

echo "=== 13. Muc 8: tep CAU HINH vua bi sua o thu muc cua tep dang bi goi ==="
# `fim_config_changed` tra `waf:fimchg:<docroot><thu muc>/<ten>` va chi hoi khi URI
# la mot tep PHP chay duoc. Luat `fim_config_changed` la `observe` diem 0.
#
# So sanh voi `fim=` (nhom `fimnew`) o cung cua so: hai nhom DOC LAP, va ty le giua
# chung la con so quyet dinh co nang diem nhom moi hay khong. `.htaccess` bi ghi lai
# HOP LE boi LiteSpeed Cache / Wordfence / doi permalink, nen mot so lon o day KHONG
# phai tin xau — no la ly do de KHONG bat.
grep -F '[waf]' "$W" | grep -F 'rule=fim_config_changed' | awk "$P"'
{
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    tot += s
    d[f["domain"]] += s
    m[f["matched"]] += s
    if (f["final"] != "" && f["final"] != "-") fin[f["final"]] += s
}
END {
    if (!tot) {
        print "  (khong co luot nao — hoac fim.sh chua bao `fimchg`, hoac khong co"
        print "   request nao goi tep PHP trong thu muc vua doi cau hinh)"
        exit
    }
    printf "  tong: %d luot\n", tot
    for (k in m)   printf "    tep cau hinh: %-16s %6d\n", k, m[k]
    for (k in d)   printf "    domain: %-32s %6d\n", k, d[k]
    for (k in fin) printf "    phan quyet THAT cua engine: %-12s %6d\n", k, fin[k]
    print  "  (diem 0 nen `final` o day la phan quyet do luat KHAC quyet — doi chieu"
    print  "   voi cot `fim=` de biet nhom `fimnew` co cung bao khong)"
}'

echo "=== 14. Muc 5: HOP DONG ENDPOINT (route policy) ==="
# Ba luat `observe` diem 0. Con so quyet dinh promote la ty le giua chung, KHONG
# phai tong: `route_upload` la ca HEP nhat (multipart tren route khong bao gio nhan
# tep — khong tang nao khac bat duoc) nen no duoc xet truoc; `route_ct` rong nhat
# (mot plugin gui JSON den `wp-comments-post.php` la chuyen co the xay ra).
#
# `matched=` mang TEN ROUTE (khoa cua bang CONTRACTS, mot hang so trong ma), nen
# doc duoc route nao dang sinh so ma khong lo URI tho.
#
# Cot `final=` la phan quyet THAT cua engine: diem 0 nen moi phan quyet o day do
# luat KHAC quyet. Mot `final=allow` ap dao nghia la ba luat nay dang thay thu ma
# khong ai khac thay — dung cai muc 5 sinh ra de tim.
grep -F '[waf]' "$W" | grep -E 'rule=route_(method|ct|upload|multipart)' | awk "$P"'
{
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    tot += s
    r[f["rule"]] += s
    rr[f["rule"] "  @  " f["matched"]] += s
    d[f["domain"]] += s
    if (f["final"] != "" && f["final"] != "-") fin[f["final"]] += s
}
END {
    if (!tot) {
        print "  (khong co luot nao — khong request nao vi pham hop dong cua bon"
        print "   route, hoac khong co luu luong den chung trong cua so nay)"
        exit
    }
    printf "  tong: %d luot\n", tot
    # In theo thu tu HEP -> RONG, khong theo thu tu bang: thu tu nay la thu tu xet
    # promote, nen no phai hien ra ngay trong bao cao.
    split("route_upload route_method route_ct route_multipart", ord, " ")
    for (i = 1; i <= 4; i++) if (r[ord[i]]) printf "    %-14s %6d\n", ord[i], r[ord[i]]
    print  "    ---- theo route:"
    for (k in rr) printf "    %-46s %6d\n", k, rr[k]
    for (k in d)  printf "    domain: %-32s %6d\n", k, d[k]
    for (k in fin) printf "    phan quyet THAT cua engine: %-12s %6d\n", k, fin[k]
    print  "  (thu tu in la thu tu XET PROMOTE: upload hep nhat, ct rong nhat)"
}'

echo "=== 15. Tep CAU HINH soi KHONG HET (duong bypass da dong) ==="
# `body_core` DA dat `scan_state = "config_trunc"` tu buoc 3, nhung TRUOC ad48546
# khong ai doc no — nen payload "<512 dong vo hai> + AddType ... .jpg" ne duoc
# composite, va `content_flags = false` doc thanh "da soi, sach".
#
# Con so quyet dinh: mot `.htaccess` HOP LE la cau hinh cho MOT thu muc (do 27-09
# tren fleet: lon nhat 4,1 KiB). Nen mot tep cau hinh cham tran 512 dong / 64 KiB
# gan nhu chac chan khong phai cau hinh that. Ty le nen RAT cao — neu no cao that
# thi day la nhom promote duoc SOM, va day la muc do chinh dieu do.
grep -F '[waf]' "$W" | grep -F 'rule=upload_config_scan_incomplete' | awk "$P"'
{
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    tot += s
    d[f["domain"]] += s
    # `matched` = "slot=N <ly do>" trong MA, nhung `scrub` o `waf_logger.lua:43`
    # doi MOI khoang trang thanh `_` truoc khi ghi — nen tren log that no la
    # `slot=1_config_trunc`. Tach bang `_`, khong bang khoang trang: mot phep tach
    # theo `" "` se chi thay `slot=1` va nhom moi ly do vao "-".
    #
    # Va KHONG tach theo `_` roi lay `p[2]`: `config_trunc` TU NO chua mot `_`, nen
    # phep tach cho `p[2] = "config"` — dung mot nua, tuc mot nhan SAI. Bo TIEN TO
    # `slot=<so>_` thay vi tach.
    ly = f["matched"]
    sub(/^slot=[0-9]+_/, "", ly)
    r[(ly == "" || ly == f["matched"]) ? "-" : ly] += s
}
END {
    if (!tot) {
        print "  (khong co luot nao — khong tep cau hinh nao cham tran)"
        exit
    }
    printf "  tong: %d luot\n", tot
    for (k in r) printf "    ly do: %-18s %6d\n", k, r[k]
    for (k in d) printf "    domain: %-32s %6d\n", k, d[k]
    print  "  (doi chieu muc 11: `cung part` DEM part co CA ten lan co noi dung;"
    print "   nhom o day la part co ten cau hinh ma noi dung CHUA soi het — tuc"
    print "   nhom muc 11 KHONG the ket luan gi ve)"
}'
