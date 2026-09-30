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
# Thu muc STATE cua `fim.sh` — muc 17 doc bo dem so lan doi tu day. Mac dinh khop
# `FIM_STATE` trong `fim.sh`; bo test tro no vao mot `mktemp -d`.
FS=${FS:-/var/lib/antibot/fim}

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



echo
echo "=== 16. VUNG MU: than co du lieu ma thieu Content-Type (BON NHOM) ==="
# DEM TRUOC, MO SAU. `body.probe` bo qua hoan toan cac request nay, nen mot raw
# POST/PUT/PATCH mang the PHP hay traversal khong duoc doc, va `init.lua` hieu la
# `has_body=false` nen hop dong endpoint cung khong thay.
#
# BON NHOM chu khong mot con so (nguoi dung bat 29-09). Ban truoc chi dem
# `Content-Length > 0`, nen con so bao cao la CAN DUOI ma khong noi ra minh la can
# duoi — ba nhom bi bo deu la than CO THAT:
#
#   cl_positive  Content-Length > 0     — nhom duy nhat ban truoc dem
#   cl_zero      Content-Length: 0      — khong TE, gan nhu chac la than rong
#   te_chunked   Transfer-Encoding      — than CO THAT, do dai chua biet truoc khi doc
#   cl_absent    khong CL, khong TE     — HTTP/2 DATA frame
#
# `te_chunked` va `cl_absent` la hai nhom QUAN TRONG NHAT cho quyet dinh mo duong:
# voi chung khong the gioi han byte bang header, phai gioi han trong luc doc.
#
# `Content-Length` CHI co nghia cho `cl_positive`; ba nhom kia khong mang do dai nen
# KHONG duoc dua vao phep tinh trung binh. Ban truoc lam `v = v + 0` tren ca `matched`
# nen mot `te_chunked` cong 0 vao tong va keo trung binh xuong — mot phep do sai im
# lang.
grep -F '[waf]' "$W" | grep -F 'rule=body_ct_missing' | awk "$P"'
{
    s = (f["smp"] == "") ? 1 : f["smp"] + 0
    n += s
    d[f["domain"]] += s
    ips[f["ip"]]++
    m = f["matched"]
    if (m ~ /^cl=[0-9]+$/) {
        g["cl_positive"] += s
        # `smp` phai nhan vao CA `n` LAN `tot`: mot dong mau dai dien nhieu request.
        v = m; sub(/^cl=/, "", v); v = v + 0
        np += s; tot += v * s
        if (v > mx) mx = v
    } else {
        g[m] += s
        gd[m "|" f["domain"]] += s
    }
}
END {
    if (!n) {
        print "  0 luot — khong request nao co than ma thieu Content-Type."
        print "  => tren may nay, mo duong doc than la MIEN PHI ve tai."
        exit
    }
    printf "  %d luot, %d domain, %d IP rieng biet\n", n, length(d), length(ips)
    print  "  -- theo NHOM --"
    order = "cl_positive cl_zero te_chunked cl_absent"
    nk = split(order, ok_, " ")
    for (i = 1; i <= nk; i++) if (g[ok_[i]] > 0)
        printf "    %-12s %6d\n", ok_[i], g[ok_[i]]
    for (k in g) {
        seen = 0
        for (i = 1; i <= nk; i++) if (k == ok_[i]) seen = 1
        if (!seen) printf "    %-12s %6d  (nhom LA — kiem lai body.lua)\n", k, g[k]
    }
    if (np > 0)
        printf "  cl_positive: Content-Length lon nhat %d B, trung binh %d B, tong %.2f MB\n", \
               mx, tot/np, tot/1048576
    print  "  -- theo domain --"
    for (k in d) printf "    domain: %-32s %6d\n", k, d[k]
    if (length(gd) > 0) {
        print "  -- nhom KHONG mang do dai, theo domain --"
        for (k in gd) { split(k, p, "|"); printf "    %-12s @ %-28s %6d\n", p[1], p[2], gd[k] }
    }
    print  "  -- CACH DOC --"
    print  "  chi co cl_positive         : gioi han byte bang header la DU"
    print  "  co te_chunked / cl_absent  : header KHONG noi do dai -> phai gioi han"
    print  "                               TRONG luc doc, khong truoc khi doc"
    print  "  n lon ma it IP             : gan nhu chac la mot cong cu/bot — xem IP truoc"
    print  "  tap trung mot domain       : co the la mot app that dung raw POST"
}'

echo
echo "=== 17. BO DEM SO LAN DOI (ha bac tep trang thai ngat quang) ==="
# Muc nay doc `$FS/chgcount.<tier>.txt`, KHONG doc log: bo dem la trang thai tren dia,
# va cau hoi no tra loi la "co ho tep trang thai nao dang lam loang canh bao".
#
# Vi sao can: do 30-09, `uploads/sucuri/*.php` (43 tep / 4 site) doi 8 lan/7 ngay va
# chiem 7/13 canh bao `fim.sh` trong hai thang. `$PREVCHG` khong bat duoc vi no nho
# DUNG MOT luot, con ho nay doi NGAT QUANG. Bo dem co cua so 21 ngay giai quyet, nhung
# no can THOI GIAN tich luy — nen muc nay la cach biet no da den dau.
#
# Cot `top` la cot dang doc nhat: no TU LO ra cac ho tep trang thai ma chua ai biet
# ten, dung muc dich cua co che thay vi mot danh sach ten.
for tier in full hot; do
    CC="$FS/chgcount.$tier.txt"
    [ -f "$CC" ] || { printf '  [%s] chua co bo dem (fim.sh --%s chua chay, hoac chua co CHG nao)\n' "$tier" "$tier"; continue; }
    n=$(wc -l < "$CC" 2>/dev/null); n=${n:-0}
    if [ "$n" -eq 0 ]; then
        printf '  [%s] bo dem RONG — khong duong dan nao doi trong cua so\n' "$tier"
        continue
    fi
    # `awk` mot pass: dem theo bac, va gio cua lan doi gan nhat.
    awk -F'|' -v tier="$tier" -v now="$(date +%s)" '
    {
        n = $1 + 0; ts = $2 + 0
        tot++
        if (n >= 2) reach++
        if (ts > newest) newest = ts
        if (oldest == 0 || ts < oldest) oldest = ts
        # Nhom theo THU MUC CHA, khong theo tep: mot ho tep trang thai lo ra o muc thu
        # muc (43 tep Sucuri nam trong 4 thu muc `uploads/sucuri/`), con liet ke tung
        # tep thi 43 dong che mat hinh dang.
        p = $3
        sub(/\/[^\/]*$/, "", p)
        d[p] += n
        dn[p]++
    }
    END {
        printf "  [%s] %d duong dan dang theo doi, %d da dat nguong (>=2 lan)\n", tier, tot, reach
        if (newest > 0)
            printf "        lan doi gan nhat: %d gio truoc; xa nhat: %d ngay truoc\n", \
                   int((now - newest) / 3600), int((now - oldest) / 86400)
        print  "  -- top 8 THU MUC theo tong so lan doi --"
        k = 0
        for (p in d) { arr[++k] = d[p] "|" dn[p] "|" p }
        # sap giam theo tong so lan: `asort` khong co o awk chuan nen chon tay.
        for (i = 1; i <= k && i <= 8; i++) {
            best = 0; bi = 0
            for (j = 1; j <= k; j++) {
                if (used[j]) continue
                split(arr[j], f, "|")
                if (f[1] + 0 > best) { best = f[1] + 0; bi = j }
            }
            if (bi == 0) break
            used[bi] = 1
            split(arr[bi], f, "|")
            printf "        %4d lan / %3d tep  %s\n", f[1], f[2], f[3]
        }
    }' "$CC"
done
echo "  -- CACH DOC --"
echo "  dat nguong = 0 sau >1 tuan : ho tep trang thai khong ton tai, hoac fim.sh khong chay"
echo "  mot thu muc chiem da so    : do la ho tep trang thai — xem no co plugin di kem khong"
echo "  nhieu tep 1 lan, khong tang: KHONG phai ho trang thai; neu chung o uploads/ thi"
echo "                               dang la CRITICAL that va can xem"
echo "  lan doi xa nhat > 21 ngay  : dong do dang cho bi rung o luot sau (dung thiet ke)"

# ══ 18. KHOA TRANG THAI: WAF co biet dang co gi khong ═══════════════════════
#
# Cau hoi muc nay tra loi, va truoc 01-10 KHONG ai tra loi duoc: tren may nay co
# bao nhieu thu muc MA NGAY BAY GIO dang cho PHP chay tu mot duoi khong phai `.php`,
# va WAF co nhan duoc dau cho tung cai khong.
#
# Co che cu chi bao khi mot tep cau hinh bi SUA, nen 11 tep doi handler tren fleet —
# lap tu 2014 den 2026, khong tep nao doi trong cua so quet — la vo hinh VINH VIEN.
# 620/620 lot fim.log deu `0 key bao WAF`.
echo
echo "── 18. khoa TRANG THAI cho WAF ───────────────────────────────"
RCLI="${POSTDEPLOY_REDIS_CLI:-redis-cli}"
RDB="${POSTDEPLOY_REDIS_DB:-0}"
if ! command -v "$RCLI" >/dev/null 2>&1; then
    echo "  thieu '$RCLI' — khong doc duoc khoa"
else
    nkey=$("$RCLI" -n "$RDB" --scan --pattern 'waf:fimchg:*' 2>/dev/null | wc -l)
    echo "  khoa waf:fimchg:* dang song : $nkey"
    if [ "$nkey" -eq 0 ]; then
        echo "  -- 0 khoa: hoac may nay khong co thu muc nao doi handler (hop le), hoac"
        echo "     tier full chua chay lan nao sau ban nay. Kiem bang muc duoi."
    else
        echo "  -- nhan tren tung khoa (do MANH giam dan) --"
        "$RCLI" -n "$RDB" --scan --pattern 'waf:fimchg:*' 2>/dev/null | sort | while read -r k; do
            [ -n "$k" ] || continue
            v=$("$RCLI" -n "$RDB" GET "$k" 2>/dev/null)
            t=$("$RCLI" -n "$RDB" TTL "$k" 2>/dev/null)
            printf '        %-28s TTL %5ss  %s\n' "$v" "$t" "${k#waf:fimchg:}"
        done
    fi
fi
# Doi chieu voi DIA: so thu muc that su doi handler. Lech giua hai so la loi duong ra.
A="${POSTDEPLOY_AWK_DIR:-/usr/local/openresty/nginx/conf/antibot/waf/scripts}"
if [ -f "$A/htaccess_parse.awk" ] && [ -f "$A/inifile_parse.awk" ]; then
    ndisk=0
    while read -r f; do
        [ -n "$f" ] || continue
        d=$(dirname "$f")
        case "$(basename "$f")" in
            .htaccess) awk -f "$A/htaccess_parse.awk" "$f" 2>/dev/null | grep -q . && ndisk=$((ndisk+1)) ;;
            *)         awk -f "$A/inifile_parse.awk" "$f" 2>/dev/null && ndisk=$((ndisk+1)) ;;
        esac
    done < <(find ${POSTDEPLOY_ROOTS:-/home/*/domains/*/public_html} \
                  \( -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' \) \
                  -type f 2>/dev/null)
    echo "  tren DIA, so tep doi handler: $ndisk"
    echo "  -- CACH DOC --"
    echo "  khoa == dia          : duong ra DUNG, WAF biet dung nhung gi dang co"
    echo "  khoa <  dia          : tier full chua chay lai, hoac Redis tu choi mot phan"
    echo "  khoa >  dia          : khoa cu chua het TTL 7 ngay (binh thuong sau khi khach sua)"
    echo "  ca hai == 0          : may nay khong co thu muc nao doi handler — ket qua HOP LE"
fi

# ══ 19. THU MUC MAY SINH TEP: tieng on NEW da giam chua ════════════════════
#
# Do 01-10 tren 171-96: 5.133/5.495 dong `HIGH NEW sc=0` trong fim.log la cache —
# 93,4% bao dong `NEW` la tieng on cua thu muc may sinh tep, va no lam loang canh bao
# Bo dem theo THU MUC (`newcount.<tier>.txt`) GOM NHOM chung — KHONG ha bac, vi
# `pscore == 0` khong chung minh tep lanh. Bac giu nguyen, `crit` van dem, mail van
# gui; chi la nhieu dong thanh mot dong. Muc nay doc tien do.
echo
echo "── 19. bo dem TEP MOI theo thu muc ─────────────────────────────"
for tier in hot full; do
    NC="$FS/newcount.$tier.txt"
    if [ ! -s "$NC" ]; then
        echo "  [$tier] chua co bo dem (chua chay lot nao, hoac khong co tep NEW)"
        continue
    fi
    awk -F'|' -v tier="$tier" -v now="$(date +%s)" -v nmin="${FIM_NEW_MIN_N:-30}" '
        { tot++; n = $1 + 0; ts = $2 + 0
          if (n >= nmin) reach++
          if (ts > newest) newest = ts
          if (oldest == 0 || ts < oldest) oldest = ts
          arr[++k] = n "|" $3
        }
        END {
            printf "  [%s] %d thu muc dang theo doi, %d da dat nguong (>=%d tep)\n", \
                   tier, tot, reach, nmin
            if (newest > 0)
                printf "        tep moi gan nhat: %d gio truoc; xa nhat: %d ngay truoc\n", \
                       int((now - newest) / 3600), int((now - oldest) / 86400)
            print  "  -- top 8 thu muc theo so tep moi --"
            for (i = 1; i <= k && i <= 8; i++) {
                best = -1; bi = 0
                for (j = 1; j <= k; j++) {
                    if (used[j]) continue
                    split(arr[j], f, "|")
                    if (f[1] + 0 > best) { best = f[1] + 0; bi = j }
                }
                if (bi == 0) break
                used[bi] = 1
                split(arr[bi], f, "|")
                printf "        %5d tep  %s%s\n", f[1], f[2], (f[1] + 0 >= nmin ? "  [da gom nhom]" : "")
            }
        }' "$NC"
done
echo "  -- DOI CHIEU voi fim.log: tieng on con lai --"
LOGF="${POSTDEPLOY_FIM_LOG:-/var/log/antibot/fim.log}"
if [ -f "$LOGF" ]; then
    nh=$(grep -c 'HIGH *NEW.*sc=0' "$LOGF" 2>/dev/null); nh=${nh:-0}
    nc=$(grep 'HIGH *NEW.*sc=0' "$LOGF" 2>/dev/null | grep -cE '/temp/|/cache|/caches/|vqcache'); nc=${nc:-0}
    echo "        tong dong 'HIGH NEW sc=0' trong lich su : $nh"
    echo "        trong do o thu muc cache                : $nc"
    echo "        (lich su khong hoi to — con so nay CHI giam voi dong MOI sau ban nay)"
fi
echo "  -- CACH DOC --"
echo "  dat nguong = 0 sau >1 ngay : khong co thu muc may sinh tep tren may nay (hop le)"
echo "  dat nguong > 0, dong HIGH NEW moi giam : co che dang lam viec"
echo "  dat nguong > 0 ma HIGH NEW khong giam  : thu muc dat nguong KHAC thu muc dang bao"
echo "  mot thu muc trong uploads/ dat nguong  : nguong gom KHONG ha o do (thiet ke) — xem no"
