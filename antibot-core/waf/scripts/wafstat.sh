#!/bin/bash
# Doc so lieu tu /var/log/antibot/waf.log. CHI DOC — khong sua file, khong cham
# Redis, khong doi hanh vi gi. Chay bao nhieu lan cung duoc.
#
# DUNG:  wafstat.sh [duong-dan-log]     (mac dinh /var/log/antibot/waf.log)
#
# HAI DIEU PHAI NHO KHI DOC KET QUA:
#
#   1. Dong `[waf-body]` DUOC LAY MAU. Dong khong dang chu y chi ghi 1/20. Moi
#      phep dem trong muc 6 va 7 da NHAN he so `smp=` roi, nen chung la UOC
#      TINH cho tong so that. Dong `[waf]` thi KHONG lay mau — dem that.
#
#   2. `richness >= 0.5` nghia la phien dang nhap that (`auth_session_cap` giu
#      o muc monitor). Mot luat tham so ban vao nhom AUTH gan nhu chac chan la
#      FP; ban vao nhom an-danh thi moi dang nghi. Do la CAU HOI QUYET DINH cho
#      viec co nang `waf_arg`/`waf_body_arg` len khoi trong so 0 hay khong.
#
# VI SAO BO PHAN TICH key=value DUOC VIET LAI TRONG TUNG LENH awk thay vi dat
# mot lan vao bien shell: dat vao bien roi nhung trong nhay KEP se lam bash nuot
# `$i` thanh chuoi rong, va moi con so deu sai ma khong co loi nao bao.
#
# `delete f` o DAU MOI DONG la bat buoc — thieu no thi gia tri dong truoc con
# sot sang dong sau. Dung loi da thoi phong `exists=1` tu 5 len 22 hom 02-09.

LOG=${1:-/var/log/antibot/waf.log}
[ -r "$LOG" ] || { echo "khong doc duoc $LOG"; exit 2; }

echo "=== 0. Pham vi du lieu ==="
printf 'dong [waf]      : %s\n' "$(grep -cF '[waf]' "$LOG")"
printf 'dong [waf-body] : %s\n' "$(grep -cF '[waf-body]' "$LOG")"
printf 'dau  : %s\n' "$(head -1 "$LOG" | cut -c1-20)"
printf 'cuoi : %s\n' "$(tail -1 "$LOG" | cut -c1-20)"
ls -l "$LOG"* 2>/dev/null

echo
echo "=== 1. Luat nao ban, theo target ==="
grep -F '[waf]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
{print f["target"], f["rule"]}' | sort | uniq -c | sort -rn

echo
echo "=== 2. Luat THAM SO chia theo richness  [CAU HOI QUYET DINH] ==="
echo "    AUTH = richness>=0.5 = phien dang nhap that => nhieu kha nang FP"
echo "    thoat-fastpath = client verified, thoat truoc classifier => THIEU du lieu,"
echo "                     dem RIENG chu khong gop vao khong-ro"
grep -F '[waf]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
f["target"]=="ARGS" || f["target"]=="BODY" {
    r=f["richness"]
    if (r=="-") tier = (f["vfy"]=="1") ? "thoat-fastpath" : "khong-ro"
    else tier = (r+0>=0.5) ? "AUTH" : "an-danh"
    print f["target"], f["rule"], tier
}' | sort | uniq -c | sort -rn

echo
echo "=== 3. Luat THAM SO: ten tham so bat duoc (KHONG kem gia tri) ==="
grep -F '[waf]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
f["target"]=="ARGS" || f["target"]=="BODY" {print f["rule"], f["matched"]}' \
| sort | uniq -c | sort -rn | head -40

echo
echo "=== 4. Luat THAM SO: domain nao ==="
grep -F '[waf]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
f["target"]=="ARGS" || f["target"]=="BODY" {print f["domain"]}' \
| sort | uniq -c | sort -rn | head -20

echo
echo "=== 5. Luat DUONG DAN: exists / fim / final ==="
grep -F '[waf]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
f["target"]=="URI" {print f["rule"], "exists="f["exists"], "fim="f["fim"], "final="f["final"]}' \
| sort | uniq -c | sort -rn | head -30

echo
echo "=== 6. [waf-body] phan bo do dai — DA NHAN he so smp ==="
grep -F '[waf-body]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
{
    s = (f["smp"]=="") ? 1 : f["smp"]+0
    b = f["blen"]+0
    if      (b <  0)     k="spill(-1)"
    else if (b == 0)     k="0(rong)"
    else if (b <  1024)  k="1..1K"
    else if (b <  8192)  k="1K..8K"
    else if (b <  16384) k="8K..16K"
    else if (b <  65536) k="16K..64K"
    else                 k=">64K"
    c[k]+=s; tot+=s; if(b>max) max=b
}
END{
    n=split("spill(-1) 0(rong) 1..1K 1K..8K 8K..16K 16K..64K >64K", ord, " ")
    for(j=1;j<=n;j++){ k=ord[j]; if(k in c) printf "  %-12s %8d  (%5.1f%%)\n", k, c[k], 100*c[k]/tot }
    printf "  ---- uoc tinh tong POST: %d | blen lon nhat doc duoc: %d\n", tot, max
}'

echo
echo "=== 7. [waf-body] family / php / spill / fnm — DA NHAN smp ==="
grep -F '[waf-body]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
{
    s = (f["smp"]=="") ? 1 : f["smp"]+0
    fam[f["ct"]]+=s
    if(f["php"]=="1")   php+=s
    if(f["spill"]=="1") sp+=s
    if(f["argrule"]!="-"){ ar[f["argrule"]]+=s
        if(f["fnm"]=="1") fn1+=s; else if(f["fnm"]=="0") fn0+=s }
    if(f["fnrule"]!="-" && f["fnrule"]!="") fr[f["fnrule"]]+=s
    if(f["fntr"]!="-" && f["fntr"]!="0" && f["fntr"]!="") ftr[f["fntr"]]+=s
    tot+=s
}
END{
    print "  -- content-type family --"
    for(k in fam) printf "  %-12s %8d\n", k, fam[k]
    printf "  the mo PHP trong body : %d\n", php+0
    printf "  spill ra file tam     : %d\n", sp+0
    print "  -- luat tham so trong THAN request --"
    for(k in ar) printf "  %-16s %8d\n", k, ar[k]
    printf "    trong do fnm=1 (lan khop duoc chon nam trong ten file): %d\n", fn1+0
    printf "    trong do fnm=0 (lan khop duoc chon nam ngoai ten file): %d\n", fn0+0
    print "  -- luat khop khi soi RIENG TEN FILE (fnrule) --"
    print "     Doc lap voi bang tren: chay luat len chinh gia tri ten file,"
    print "     khong le thuoc thu tu uu tien cua luat toan than. DAY moi la so"
    print "     dem duoc cho cau: co bao nhieu request tan cong o ten file."
    n=0; for(k in fr){ printf "  %-16s %8d\n", k, fr[k]; n++ }
    if(n==0) print "  (khong co)"
    print "  -- quet ten file khong hoan tat, theo LY DO --"
    print "     `stop` la binh thuong (dung lai vi da tim thay, di kem fnrule)."
    print "     Bon cai con lai deu la KHONG BIET, khong phai sach, va moi cai"
    print "     doi mot viec khac han — nen dem RIENG."
    tt=0
    if(ftr["rx"]>0){ printf "  rx    %8d  MAU KHONG BIEN DICH DUOC -> loi deploy, sua NGAY\n", ftr["rx"]; tt+=ftr["rx"] }
    if(ftr["len"]>0){ printf "  len   %8d  ten file > 512 byte -> hiem, tu no da dang ngo\n", ftr["len"]; tt+=ftr["len"] }
    if(ftr["n"]>0){ printf "  n     %8d  hon 32 phan -> thuong la upload that, cach xu ly la nang tran\n", ftr["n"]; tt+=ftr["n"] }
    if(ftr["spill"]>0){ printf "  spill %8d  multipart ra file tam -> KHONG soi gi ca\n", ftr["spill"]; tt+=ftr["spill"] }
    if(ftr["stop"]>0) printf "  stop  %8d  dung lai vi da tim thay (binh thuong)\n", ftr["stop"]
    for(k in ftr) if(k!="rx" && k!="len" && k!="n" && k!="spill" && k!="stop"){ printf "  %-5s %8d  (ngoai bang)\n", k, ftr[k]; tt+=ftr[k] }
    if(tt==0) print "  (khong co vung mu nao)"
    if(ftr["spill"]>0 && fam["multipart"]>0) printf "  => MULTIPART KHONG HE DUOC SOI: %.1f%% (%d/%d). Day la thien lech cua\n     moi ty le fnrule o tren, va no KHONG dong duoc bang client_body_buffer_size:\n     ke tan cong don them byte la vuot moi con so.\n", 100*ftr["spill"]/fam["multipart"], ftr["spill"], fam["multipart"]
    print ""
    print "  BA DIEU KIEN PHAI XU LY TRUOC KHI NANG fn_rule LEN TRONG SO > 0."
    print "  Doc so o tren xong la den luc de quen chung, nen chung in o day:"
    print "   1. Quet TOAN BO than, chua gioi han trong vung header cua tung"
    print "      part. Mot file van ban co NOI DUNG chua `; filename=\"../x.php\"`"
    print "      van dem. Nhieu telemetry thi chiu duoc; chan that thi la chan"
    print "      oan mot lan upload hop le. Phai tach part theo boundary lay tu"
    print "      Content-Type truoc da."
    print "   2. `rx`, `len`, `n` deu KHONG phai sach (`stop` thi binh thuong)."
    print "      Tai trong o ten file thu 33 hoac sau byte 512 khong duoc nhin"
    print "      thay. Enforcement doc chung nhu \"da soi, khong thay\" la bien"
    print "      vung mu thanh giay thong hanh."
    print "   3. fn_rule chi tinh tren multipart CON TRONG BO NHO. Upload lon"
    print "      spill nhieu hon, nen dung suy rong ty le nay ra toan bo upload."
    printf "  ---- uoc tinh tong POST: %d\n", tot
}'

echo
echo "=== 8. spill x cach nginx biet do dai body  [CAU HOI VE BUFFER] ==="
echo "    Cau hoi: nginx co BIET TRUOC do dai body khong. Biet thi no cap dung co"
echo "    va bo qua client_body_buffer_size; khong biet thi roi ve buffer va spill."
echo "    LUU Y: cl=- KHONG dong nghia chunked — header do con vang trong HTTP/2,"
echo "    HTTP/3, request khong body. Vi vay phai doc kem proto= va te=."
grep -F '[waf-body]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
{
    s = (f["smp"]=="") ? 1 : f["smp"]+0
    p  = f["proto"]; cl = f["cl"]; te = f["te"]
    has_cl = (cl != "-" && cl != "")
    chunk  = (te ~ /chunked/)
    if (p ~ /^1/)      mode = has_cl ? "h1 + Content-Length" : (chunk ? "h1 + chunked" : "h1 + khong ro")
    else if (p ~ /^2/) mode = has_cl ? "h2 + Content-Length" : "h2 + khong co CL"
    else if (p ~ /^3/) mode = has_cl ? "h3 + Content-Length" : "h3 + khong co CL"
    else               mode = "proto khac (" p ")"
    key = ((f["spill"]=="1") ? "spill=1  " : "spill=0  ") mode
    c[key] += s; tot += s
    if (f["spill"]=="1") spt += s
}
END{
    # THU TU CO DINH thay vi `asorti`: asorti la mo rong cua gawk, con mawk
    # (mac dinh tren Debian/Ubuntu) khong co — se bao loi tren dung may can doc.
    m = split("h1 + Content-Length|h1 + chunked|h1 + khong ro|" \
              "h2 + Content-Length|h2 + khong co CL|" \
              "h3 + Content-Length|h3 + khong co CL", md, "|")
    for (sp=1; sp>=0; sp--) {
        pre = (sp ? "spill=1  " : "spill=0  ")
        for (j=1;j<=m;j++) {
            k = pre md[j]
            if (k in c) { printf "  %-32s %8d  (%5.1f%%)\n", k, c[k], 100*c[k]/tot; seen[k]=1 }
        }
    }
    # Bat ky to hop nao khong nam trong bang tren — in ra chu khong nuot.
    for (k in c) if (!(k in seen)) printf "  %-32s %8d  (%5.1f%%)  <- ngoai bang\n", k, c[k], 100*c[k]/tot
    printf "  ---- uoc tinh tong POST: %d, trong do spill: %d (%.1f%%)\n",
           tot, spt+0, tot?100*(spt+0)/tot:0
}'
