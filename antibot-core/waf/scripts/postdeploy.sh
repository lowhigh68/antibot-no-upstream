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

# MOC CUA SO DO = `first_deployed=`, KHONG phai `deployed=`.
#
# `deployed=` bi ghi lai moi lan `deploy.sh` chay, nen moi deploy xoa cua so do
# ve 0 phut — ke ca khi ban moi khong cham module dang do. Nguoi dung bat 06-10:
# 05-10 deploy 5 lan trong mot ngay nen MOI phep do 24h deu bao "CHUA DU 24 GIO"
# vinh vien; `335f395` chi sua `fim.sh` ma van reset cua so cua `adm_use` thuoc
# `0570ea2`.
#
# `first_deployed=` chi doi khi `sha` doi (xem `deploy.sh`), nen deploy lai cung
# ban giu nguyen cua so.
#
# FALLBACK ve `deployed=`: mot may chay ban deploy.sh TRUOC thay doi nay se co
# VERSION khong co truong moi. Im lang roi xuong `deployed=` la dung — so lieu
# hep hon chu khong SAI. In ra moc dang dung de nguoi doc biet minh dang xem cai
# nao; khong in thi hai may cho hai cua so khac nhau ma trong y nhau.
T=$(sed -n 's/^first_deployed=//p' "$A/VERSION" 2>/dev/null)
TSRC="first_deployed"
if [ -z "$T" ]; then
    T=$(sed -n 's/^deployed=//p' "$A/VERSION" 2>/dev/null)
    TSRC="deployed (VERSION cu, chua co first_deployed)"
fi
TDEP=$(sed -n 's/^deployed=//p' "$A/VERSION" 2>/dev/null)
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
echo "  ban $S  moc do $T ($TSRC)  -> $MIN phut"
# In CA `deployed=` khi hai moc khac nhau: do la dau hieu da deploy lai cung
# ban, va nguoi doc can biet cua so KHONG bi xoa chu khong phai script doc sai.
[ "$TDEP" != "$T" ] && echo "  (deploy lan cuoi $TDEP — cung sha nen cua so GIU NGUYEN)" || :
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

# ── P1-2: TACH nhom "incomplete TAI endpoint upload" ────────────────
#
# Muc 8 o tren gop moi than multipart khong soi het. Nhung mot than khong soi duoc
# o `/wp-cron.php` va o `/wp-admin/async-upload.php` la hai su that khac han: o
# route khong bao gio nhan tep thi ban than multipart da bat thuong; o endpoint
# upload thi multipart la DUNG, va dieu dang lo la noi dung tep vao Media Library
# ma khong soi duoc.
#
# Day la so lieu de CHON chinh sach (Review 4 P1 muc 2: "khong can ap fail-closed
# cho moi POST"). Khong bake nguong vao code — doc cot nay roi quyet.
echo "=== 8b. P1-2: incomplete TAI endpoint upload (body_upload_ep_incomplete) ==="
grep -F '[waf-body]' "$W" | awk "$P$B1"'
why != "" && f["uri"] ~ /async-upload\.php/ {
    g[why "  " f["domain"] "  class=" f["class"] " vfy=" f["vfy"]] += s; t += s }
END {
    if (!t) { print "  (khong co luot nao o endpoint upload)"; exit }
    printf "  tong %d luot. Theo ly do / domain / lop:\n", t
    for (k in g) printf "  %6d  %s\n", g[k], k
}'
echo "  -- CACH DOC --"
echo "  0 luot                 : endpoint upload khong he co than khong soi duoc -> chua co co so doi policy"
echo "  tap trung 1-2 domain   : xem cau hinh site do (body lon? spill?) truoc khi doi policy toan fleet"
echo "  vfy=1 phan lon         : nguoi dung da dang nhap -> fail-closed se chan admin that, can than"
echo "  fntr_* phan lon        : kenh ten tep dung giua -> tang tran thay vi chan"

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
echo "=== 13. Muc 8: thu muc cua tep dang bi goi CO cau hinh doi handler ==="
# `fim_config_active` tra `waf:fimcfg:<docroot><thu muc>/` (DOI TEN tu
# `fim_config_changed` / `waf:fimchg:` ngay 02-10: khoa mang TRANG THAI DANG TON TAI
# chu khong phai su kien "vua doi"). Luat la `observe` diem 0.
#
# Doc CA HAI ten luat: `waf.log` trong cua so nay co the con dong `fim_config_changed`
# ghi TRUOC khi deploy. HAN CHOT 09-10-2026: bo ten cu.
#
# So sanh voi `fim=` (nhom `fimnew`) o cung cua so: hai nhom DOC LAP, va ty le giua
# chung la con so quyet dinh co nang diem nhom moi hay khong. `.htaccess` bi ghi lai
# HOP LE boi LiteSpeed Cache / Wordfence / doi permalink, nen mot so lon o day KHONG
# phai tin xau — no la ly do de KHONG bat.
grep -F '[waf]' "$W" | grep -E 'rule=fim_config_(active|changed)' | awk "$P"'
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
# Rong = khong gui AUTH. Phai khop `requirepass` cua Redis; lech thi muc 18 bao
# "0 khoa" tren mot Redis day khoa — tuc mot bao cao SAI, khong phai mot loi.
# Mat khau: bien moi truong TRUOC, roi TEP. Cron/root khong doc `/etc/environment`.
_RPW="${ANTIBOT_REDIS_PASS:-}"
if [ -z "$_RPW" ]; then
    _pwf="${ANTIBOT_REDIS_PASS_FILE:-/etc/antibot/redis.pass}"
    [ -r "$_pwf" ] && _RPW="$(head -1 "$_pwf" 2>/dev/null | tr -d '\r\n')"
fi
RAUTH=()
[ -n "$_RPW" ] && RAUTH=(--no-auth-warning -a "$_RPW")
if ! command -v "$RCLI" >/dev/null 2>&1; then
    echo "  thieu '$RCLI' — khong doc duoc khoa"
else
    # DEM CA HAI tien to: `fimcfg:` la dang moi (02-10), `fimchg:` la dang cu con
    # song het TTL. In RIENG hai so de thay phep di tru da xong chua — neu `fimchg:`
    # con > 0 sau mot lot `fim.sh check` thi reconcile KHONG don duoc chung, va do la
    # mot loi can biet. HAN CHOT 09-10-2026: bo dong `fimchg:`.
    nkey=$("$RCLI" "${RAUTH[@]}" -n "$RDB" --scan --pattern 'waf:fimcfg:*' 2>/dev/null | wc -l)
    nold=$("$RCLI" "${RAUTH[@]}" -n "$RDB" --scan --pattern 'waf:fimchg:*' 2>/dev/null | wc -l)
    echo "  khoa waf:fimcfg:* dang song : $nkey"
    echo "  khoa waf:fimchg:* (dang CU) : $nold  (mong 0 sau mot lot check)"
    if [ "${nold:-0}" -gt 0 ]; then
        echo "  !! $nold khoa dang CU van song — reconcile chua don duoc chung."
        echo "     Kiem \$STATE/statekeys.full.txt co dang \`waf:fimcfg:\` khong."
    fi
    if [ "$nkey" -eq 0 ]; then
        echo "  -- 0 khoa: hoac may nay khong co thu muc nao doi handler (hop le), hoac"
        echo "     tier full chua chay lan nao sau ban nay. Kiem bang muc duoi."
    else
        # DEM KHOA THEO PHIEN BAN GIA TRI. `c942edf` doi hop dong token va `v2` (03-10)
        # them moc de `init.lua` biet doc luat nao. Mot khoa KHONG moc la khoa ghi bang
        # ban TRUOC — hop le trong 7 ngay TTL, nhung so do phai ve 0 sau mot lot
        # `check`, va neu khong thi phep di tru dang tac.
        nv2=0; nold_val=0
        while read -r k; do
            [ -n "$k" ] || continue
            v=$("$RCLI" "${RAUTH[@]}" -n "$RDB" GET "$k" 2>/dev/null)
            case "$v" in
                v2|v2,*) nv2=$((nv2 + 1)) ;;
                *)       nold_val=$((nold_val + 1)) ;;
            esac
        done <<EOT
$("$RCLI" "${RAUTH[@]}" -n "$RDB" --scan --pattern 'waf:fimcfg:*' 2>/dev/null)
EOT
        echo "  gia tri CO moc v2       : $nv2"
        echo "  gia tri KHONG moc (cu)  : $nold_val  (mong 0 sau mot lot check full)"
        if [ "$nold_val" -gt 0 ]; then
            echo "     -> con khoa dang CU. Hop le trong 7 ngay TTL (FIM_MARK_TTL), vi"
            echo "        \`fim.sh\` chi ghi lai thu muc nao DOI. Neu con sau do thi"
            echo "        tier full chua chay, hoac \`dir_tokens\` khong dat moc."
        fi
        echo "  -- nhan tren tung khoa (do MANH giam dan) --"
        "$RCLI" "${RAUTH[@]}" -n "$RDB" --scan --pattern 'waf:fimcfg:*' 2>/dev/null | sort | while read -r k; do
            [ -n "$k" ] || continue
            v=$("$RCLI" "${RAUTH[@]}" -n "$RDB" GET "$k" 2>/dev/null)
            t=$("$RCLI" "${RAUTH[@]}" -n "$RDB" TTL "$k" 2>/dev/null)
            printf '        %-28s TTL %5ss  %s\n' "$v" "$t" "${k#waf:fimcfg:}"
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
            *)         awk -f "$A/inifile_parse.awk" "$f" >/dev/null 2>&1 && ndisk=$((ndisk+1)) ;;
        esac
    done < <(find ${POSTDEPLOY_ROOTS:-/home/*/domains/*/public_html} \
                  \( -name '.htaccess' -o -name '.user.ini' -o -name 'php.ini' \) \
                  -type f 2>/dev/null)
    echo "  tren DIA, so tep doi handler: $ndisk"
    echo "  -- CACH DOC --"
    echo "  khoa == dia          : duong ra DUNG. Mot khoa cho MOI thu muc co tep cau"
    echo "                         hinh — ke thua lam o BEN DOC (init.lua tra chuoi to"
    echo "                         tien bang mot MGET), nen KHONG co khoa cho thu muc con"
    echo "  khoa <  dia          : tier full chua chay lai, hoac Redis tu choi mot phan"
    echo "  khoa >  dia          : khoa cu chua bi reconcile — kiem statekeys.<tier>.txt"
    echo "  ca hai == 0          : may nay khong co thu muc nao doi handler — HOP LE"
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

echo
echo "── 20. CORRELATION dang SHADOW: so lieu de promote ─────────────"
# ── VI SAO CO MUC NAY ────────────────────────────────────────────────
#
# Review 4 giai doan P1 muc 1 noi: "Dung so lieu `postdeploy.sh` de promote lan
# luot cac correlation cung-part co confidence cao". Nhung dem lai 04-10:
# `postdeploy.sh` doc `uprule=` DUNG 0 LAN. `waf.log` CO ghi cot do, `registry.lua`
# CO ba rule `shadow` — nhung khong co duong ra so lieu, nen khong ai promote duoc
# gi ca. Dung lop "canh bao dung ma khong ai mo" (fim.sh bao 13 lan vao mail cron).
#
# Muc nay KHONG quyet dinh gi. No chi tra lo so de nguoi van hanh thay:
#   · bao nhieu lan moi luat ban trong cua so
#   · co bao nhieu DOMAIN va IP rieng biet -> mot domain chiem het = nghi FP cuc bo
#   · ban ket qua cuoi (`final=`) la gi -> neu da bi chan boi luat khac thi promote
#     khong doi gi, con `allow` het thi promote la mot thay doi THAT
#
# Promote khi nao la quyet dinh cua nguoi van hanh, khong phai cua script.
if [ -z "$WF" ]; then
    echo "  khong co waf.log sau moc deploy -> KHONG DO DUOC (khac 0 lan ban)"
else
    echo "  (doc: $(names $WF))"
    # ── DOC DUNG SCHEMA: `final=` KHONG co trong dong nay ─────────────
    #
    # `uprule=` nam o dong `[waf-body]` (`async/waf_logger.lua:188-191`), con
    # `final=` nam o dong log KHAC (`:501`, cac rule WAF). Ban dau toi viet cot
    # `final=` vao day va no se LUON RONG — dung lop loi "doc schema log truoc khi
    # viet lenh do" (toi tung dung `uri=` khi cot that la `matched=`).
    #
    # Cot THAT cung dong, va huu ich hon cho viec promote:
    #   `pf=`  bang chung than multipart co soi duoc khong (`ok` = da soi)
    #   `php=` co thay dau PHP trong noi dung khong
    # Mot luat ban nhieu ma `pf=` khong phai `ok` nghia la no ban khi CHUA SOI
    # duoc than — promote cai do la promote mot phong doan.
    catf $WF | awk '
        {
            ur = ""; dm = ""; ipa = ""; pf = ""
            for (i = 1; i <= NF; i++) {
                if      (substr($i, 1, 7) == "uprule=") ur  = substr($i, 8)
                else if (substr($i, 1, 7) == "domain=") dm  = substr($i, 8)
                else if (substr($i, 1, 3) == "ip=")     ipa = substr($i, 4)
                else if (substr($i, 1, 3) == "pf=")     pf  = substr($i, 4)
            }
            if (ur == "" || ur == "-") next
            n[ur]++
            if (dm  != "" && !(ur SUBSEP dm  in sd)) { sd[ur, dm]  = 1; nd[ur]++ }
            if (ipa != "" && !(ur SUBSEP ipa in si)) { si[ur, ipa] = 1; ni[ur]++ }
            if (pf == "ok") nok[ur]++
        }
        END {
            if (length(n) == 0) {
                print "  khong mot lan ban nao (uprule= trong cua so deu la -)"
                exit
            }
            printf "  %-26s %7s %7s %7s %9s\n", "uprule", "lan", "domain", "ip", "pf=ok"
            for (r in n) printf "  %-26s %7d %7d %7d %9d\n", r, n[r], nd[r], ni[r], nok[r] + 0
        }'
    echo "  -- CACH DOC --"
    echo "  domain=1 ma lan RAT cao      : nghi FP cuc bo o mot site, dung promote toan fleet"
    echo "  pf=ok THAP hon lan nhieu     : luat ban khi CHUA soi duoc than -> promote la phong doan"
    echo "  pf=ok == lan                 : moi lan ban deu co bang chung than -> co co so promote"
    echo "  0 lan ban sau >1 ngay        : luat chua gap luu luong thuc -> chua co co so promote"
fi

echo
echo "=== 21. Static MISS theo DOMAIN (admission: resource candidate vs thuc te) ==="
#
# VI SAO CO MUC NAY, va vi sao phai co cot DOMAIN.
#
# `admission.lua` dua static MISS vao ngan sach `dynamic` thay vi `resource`, vi
# `try_files` khong thay tep thi request di `@static_backend` -> Apache/PHP (voi
# WordPress thi `.htaccess` rewrite thanh `index.php`). Do la tai dynamic du duoi
# tep la `.jpg`.
#
# Ban dau phep do duoc de nghi la:
#     grep -o 'ractual=[^ ]*' antibot.log | sort | uniq -c
# Nguoi dung bat dung: lenh do chi tra hai dong TONG, khong biet domain nao —
# nen no KHONG tra loi duoc chinh cau hoi can tra loi ("tap trung o mot domain
# vua migrate thi do la FP"). Dung lop loi "lenh do hong tra so trong-co-ly".
#
# COT `ip-miss` LA COT QUYET DINH, khong phai cot `miss`:
#   · miss cao + ip-miss THAP (1-3 IP)   -> mot client/bot quet; dung noi ngung
#   · miss cao + ip-miss CAO (hang tram) -> KHACH THAT dang 404 anh hang loat.
#     Nghia la site vua migrate/doi theme va con link cu tro toi anh da xoa.
#     Day la FP ve capacity: ho khong tan cong, ho chi co nhieu 404 hop le.
#   · cot 429 > 0                        -> da co nguoi bi throttle that
#
# `ractual=-` (cot khong-do) la fail-open: `document_root` rong hoac dict loi ->
# admission coi nhu static that. So nay > 0 lien tuc nghia la phep do dang khong
# chay o dau do, va ngan sach `resource` 4000/s dang duoc ap cho ca static miss.
#
# Dong KHONG co cot `ractual=` la dong khong phai resource candidate -> bo qua,
# khong dem vao bat ky nhom nao. Bo phep loc nay thi dong `navigation` bi dem
# thanh "khong-do" (da thu dot bien, bao gia).
AF=$(since "$L" antibot.log)
if [ -z "$AF" ]; then
    echo "  khong co antibot.log nao moi hon $T — khong do duoc"
else
    echo "  antibot.log doc:$(names $AF)"
    catf $AF | awk '
        {
            dm = "-"; ra = ""; ipa = ""; ac = ""
            for (i = 1; i <= NF; i++) {
                if      (substr($i, 1, 7) == "domain=")  dm  = substr($i, 8)
                else if (substr($i, 1, 8) == "ractual=") ra  = substr($i, 9)
                else if (substr($i, 1, 3) == "ip=")      ipa = substr($i, 4)
                else if (substr($i, 1, 7) == "action=")  ac  = substr($i, 8)
            }
            if (ra == "") next
            if (ra == "false") {
                miss[dm]++
                if (!seen[dm "|" ipa]++) ipn[dm]++
                if (ac == "throttled") thr[dm]++
            } else if (ra == "true") hit[dm]++
            else                     unk[dm]++
            doms[dm] = 1
        }
        END {
            if (length(doms) == 0) {
                print "  khong mot dong nao co cot ractual= (chua deploy ban static-probe?)"
                exit
            }
            printf "  %-30s %7s %7s %9s %8s %6s\n", \
                   "domain", "miss", "hit", "khong-do", "ip-miss", "429"
            for (d in doms)
                printf "  %-30s %7d %7d %9d %8d %6d\n", d, \
                       miss[d]+0, hit[d]+0, unk[d]+0, ipn[d]+0, thr[d]+0
        }' | { IFS= read -r hdr; [ -n "$hdr" ] && echo "$hdr"; sort -k2 -rn | head -25; }
    echo "  -- CACH DOC (cot ip-miss quyet dinh, KHONG phai cot miss) --"
    echo "  miss cao + ip-miss 1-3       : mot bot quet duong dan — dung noi ngan sach"
    echo "  miss cao + ip-miss hang tram : KHACH THAT 404 anh hang loat (site vua"
    echo "                                 migrate/doi theme) -> FP capacity, nang"
    echo "                                 host_group.dynamic cho rieng host do"
    echo "  cot 429 > 0                  : da co nguoi bi throttle that, xem ngay"
    echo "  khong-do > 0 lien tuc        : fail-open dang chay — document_root rong"
    echo "                                 hoac dict loi; ngan sach resource 4000/s"
    echo "                                 dang ap cho ca static miss"
fi
echo
echo "=== 22. SHADOW h-:php: thu muc plugin/theme anh xa PHP sang text/plain ==="
# ── VI SAO CO MUC NAY ────────────────────────────────────────────────
#
# `fim.sh` bao vao `$CRITLOG` khi TAP doi (chong lap bang chu ky md5), nen mot
# thu muc bi cay tu truoc se KHONG xuat hien o luot sau. Muc nay doc TRANG THAI
# hien tai tu Redis chu khong doc log, nen no tra loi "dang co gi" thay vi "vua
# doi gi" — dung phan biet ma `feedback_alert_reaches_nobody` noi toi.
#
# SHADOW: n=2 tren toan fleet 05-10 (ca hai o mot site da xac nhan bi hack).
# Khong promote thanh luat truoc khi so nay co them mau tu site HOP LE hay khong.
if ! command -v "$RCLI" >/dev/null 2>&1; then
    echo "  thieu '$RCLI' — khong doc duoc khoa"
else
    nsus=0
    while read -r k; do
        [ -n "$k" ] || continue
        v=$("$RCLI" "${RAUTH[@]}" -n "$RDB" GET "$k" 2>/dev/null)
        d="${k#waf:fimcfg:}"
        case "$d" in
            */wp-content/plugins/*|*/wp-content/themes/*) ;;
            *) continue ;;
        esac
        # Cung bo token voi `suspect_cfg` trong fim.sh. `h0:` (reset) KHONG tinh.
        case ",$v," in
            *,@ft-,*|*,@sh-,*|*,h-:php,*|*,h-:phtml,*|*,t-:php,*|*,t-:phtml,*)
                nsus=$((nsus + 1))
                printf '  %s\n      %s\n' "$d" "$v" ;;
        esac
    done <<EOT
$("$RCLI" "${RAUTH[@]}" -n "$RDB" --scan --pattern 'waf:fimcfg:*' 2>/dev/null | sort)
EOT
    echo "  tong: $nsus thu muc"
    echo "  -- CACH DOC --"
    echo "  0                    : may nay khong co dau hieu nay (mong doi)"
    echo "  >0 tren MOT site     : nghi site do bi xam nhap — doi chieu mtime cua"
    echo "                         tep trong thu muc; cung mot moc = mot lan drop"
    echo "  >0 tren NHIEU site   : hoac co dot tan cong, hoac BAT BIEN SAI (mot"
    echo "                         plugin hop le lam vay) — kiem truoc khi promote"
    echo "  Go handler PHP = .php tai ve dang TEXT thay vi chay. Khong phai duong"
    echo "  chay ma, nen gia tri la DAU HIEU DA BI XAM NHAP."
fi
echo
echo "=== 23. lua_shared_dict: cau hinh tren DIA vs cai DANG CHAY ==="
# ── VI SAO CO MUC NAY ────────────────────────────────────────────────
#
# `nginx -s reload` KHONG cap phat lai `lua_shared_dict`: zone duoc cap luc
# MASTER khoi dong. Nen mot thay doi kich thuoc trong `nginx.conf` co the nam
# tren dia HAI THANG ma khong co hieu luc, va khong mot dong log nao bao.
#
# Do 06-10 tren hai may: `nginx.conf` ghi `antibot_cache 64m` nhung master khoi
# dong tu 24/07 va 10/08. Dict that van 5m, `adm=*dict_error` van xay ra, va hai
# phep do noi hai dieu trai nhau — endpoint bao `dicterr_total=0` (bo dem trong
# dict 1m cung chua duoc cap lai) trong khi log co dong moi.
#
# So MOC KHOI DONG cua master voi MOC SUA `nginx.conf`. Khong doc kich thuoc
# dang chay duoc (nginx khong phoi ra), nen day la phep do gian tiep DUY NHAT —
# va no du: conf moi hon master thi CHAC CHAN co thay doi chua nap.
NGX_CONF="${POSTDEPLOY_NGINX_CONF:-/usr/local/openresty/nginx/conf/nginx.conf}"
NGX_PID="${POSTDEPLOY_NGINX_PID:-/usr/local/openresty/nginx/logs/nginx.pid}"
if [ ! -r "$NGX_CONF" ]; then
    echo "  KHONG DOC DUOC $NGX_CONF -- khong do duoc"
elif [ ! -r "$NGX_PID" ]; then
    echo "  KHONG DOC DUOC $NGX_PID -- khong biet master khoi dong luc nao"
else
    _mpid=$(head -1 "$NGX_PID" 2>/dev/null | tr -d ' \r\n')
    _mstart=$(ps -o lstart= -p "${_mpid:-0}" 2>/dev/null | sed 's/^ *//')
    if [ -z "$_mstart" ]; then
        echo "  pid $_mpid KHONG CHAY -- pidfile cu, khong do duoc"
    else
        _mepoch=$(date -d "$_mstart" +%s 2>/dev/null || echo 0)
        _cepoch=$(date -r "$NGX_CONF" +%s 2>/dev/null || echo 0)
        printf '  master khoi dong : %s\n' "$_mstart"
        printf '  nginx.conf sua    : %s\n' "$(date -d "@$_cepoch" '+%a %b %e %T %Y' 2>/dev/null)"
        printf '  cac dict khai bao : %s\n' \
            "$(grep -c 'lua_shared_dict' "$NGX_CONF" 2>/dev/null)"
        if [ "${_cepoch:-0}" -gt "${_mepoch:-0}" ]; then
            _h=$(( (_cepoch - _mepoch) / 3600 ))
            echo "  *** nginx.conf MOI HON master ${_h}h — moi thay doi"
            echo "      \`lua_shared_dict\` CHUA CO HIEU LUC. Can \`restart\`,"
            echo "      \`reload\` KHONG cap phat lai zone. ***"
        else
            echo "  OK: master khoi dong SAU lan sua conf gan nhat"
        fi
    fi
fi
echo "  -- CACH DOC --"
echo "  conf moi hon master  : co thay doi chua nap. Neu thay doi do la KICH"
echo "                         THUOC dict thi phai \`restart\`, khong \`reload\`"
echo "  master moi hon conf  : moi khai bao dict dang co hieu luc"
echo "  (nginx khong phoi ra kich thuoc dang chay, nen day la phep do gian tiep)"

echo
echo "── 24. uploads/ CON dau cung hoa khong ────────────────────────"
# `.htaccess` do `uploads_harden.sh` ghi nam trong thu muc CUA KHACH, nen khach
# hoac mot plugin co the xoa no bat cu luc nao — va khi do lo mo lai trong im
# lang. Muc nay CHI DOC: no bao thu muc mat dau, khong tu va.
#
# `uploads_harden.sh` chay TAY mot lan moi may (cung ly le `fim.sh baseline`),
# nen "MAT" o day nghia la can chay lai TAY, khong phai mot loi tu dong.
#
# Vi sao khong dung `fim.sh`: rang buoc cung cua nguoi dung — `fim.sh` KHONG
# duoc xoa/chmod/di chuyen tep. Mot may do co quyen ghi vao thu muc khach thi
# moi bug cua no thanh mot su co du lieu.
# `POSTDEPLOY_HOME` ton tai de `postdeploy_test.sh` chay duoc muc 24/25 tren
# fixture. Khong co no thi bo kiem phai mo phong lai vong lap — va mo phong la
# thu da lam lot ba ban deploy hong (xem `feedback_contract_emulation`).
_uh_mark='# antibot-uploads-harden'
_uh_co=0; _uh_mat=0
while IFS= read -r _d; do
    [ -d "$_d" ] || continue
    if [ -f "$_d/.htaccess" ] && grep -qF "$_uh_mark" "$_d/.htaccess" 2>/dev/null; then
        _uh_co=$((_uh_co + 1))
    else
        _uh_mat=$((_uh_mat + 1))
        printf '  MAT  %s\n' "$_d"
    fi
done < <(find "${POSTDEPLOY_HOME:-/home}" -maxdepth 6 -type d -name uploads -path '*wp-content*' 2>/dev/null)
printf '  co dau: %s   mat dau: %s\n' "$_uh_co" "$_uh_mat"
if [ "$_uh_mat" -gt 0 ]; then
    echo "  -> chay TAY: \$ANTIBOT_DIR/waf/scripts/uploads_harden.sh         (xem truoc)"
    echo "               \$ANTIBOT_DIR/waf/scripts/uploads_harden.sh --apply (ghi that)"
fi
if [ "$_uh_co" = "0" ] && [ "$_uh_mat" = "0" ]; then
    echo "  (khong co thu muc wp-content/uploads nao tren may nay)"
fi

echo
echo "── 25. tep THUC THI DUOC trong uploads/ ───────────────────────"
# `uploads/` la noi plugin/theme ghi HOP PHAP, nen `fim.sh` co chu y KHONG soi
# tung tep o day (xem chu thich `fim.sh` quanh dong 1935): do 10-10 tren
# cloud168-123 co ~180 tep moi/ngay va 1.502 tep moi/7 ngay — toan la anh khach
# upload. Soi tung tep o day la on.
#
# Nhung dem theo DUOI THUC THI DUOC thi khac han: cung phep do, cung ngay, ket
# qua la **0**. Nen moi lan khac 0 la tin hieu THAT, khong phai nhieu. Day la
# phep do re nhat con lai sau khi `.htaccess` da chan duong HTTP — vi `.htaccess`
# KHONG chan `include()` lan LFI (PHP doc tep qua filesystem, Apache khong tham
# gia), nen mot tep `.php` xuat hien o day van la viec can biet.
_ex_n=0
while IFS= read -r _f; do
    _ex_n=$((_ex_n + 1))
    [ "$_ex_n" -le 20 ] && printf '  %s\n' "$_f"
done < <(find "${POSTDEPLOY_HOME:-/home}" -maxdepth 9 -path '*wp-content/uploads*' -type f \
             \( -name '*.php'   -o -name '*.php[0-9]' -o -name '*.phtml' \
                -o -name '*.phar' -o -name '*.inc'   -o -name '*.cgi' \) \
             2>/dev/null)
if [ "$_ex_n" = "0" ]; then
    echo "  0 tep — dung ky vong"
else
    printf '  *** %s tep thuc thi duoc trong uploads/ ***\n' "$_ex_n"
    [ "$_ex_n" -gt 20 ] && echo "      (chi in 20 dong dau)"
    echo '      .htaccess chan duong HTTP, nhung KHONG chan include()/LFI.'
    echo "      Soi tung tep: tep cua plugin hop phap hay webshell?"
fi
