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
    tot+=s
}
END{
    print "  -- content-type family --"
    for(k in fam) printf "  %-12s %8d\n", k, fam[k]
    printf "  the mo PHP trong body : %d\n", php+0
    printf "  spill ra file tam     : %d\n", sp+0
    print "  -- luat tham so trong THAN request --"
    for(k in ar) printf "  %-16s %8d\n", k, ar[k]
    printf "  trong do fnm=1 (TEN FILE, nhieu kha nang that): %d\n", fn1+0
    printf "  trong do fnm=0 (noi dung,  nhieu kha nang FP ): %d\n", fn0+0
    printf "  ---- uoc tinh tong POST: %d\n", tot
}'

echo
echo "=== 8. spill x Content-Length  [CAU HOI VE client_body_buffer_size] ==="
echo "    Gia thuyet: ngx.req.read_body() dat request_body_in_single_buf, nen"
echo "    request CO Content-Length duoc cap buffer vua co body va KHONG BAO GIO"
echo "    spill; chi CHUNKED (cl=-) moi roi ve client_body_buffer_size."
echo "    Dung => o 'spill=1 cl=co' phai gan bang 0."
grep -F '[waf-body]' "$LOG" | awk '
{delete f;for(i=1;i<=NF;i++){n=index($i,"=");if(n)f[substr($i,1,n-1)]=substr($i,n+1)}}
{
    s = (f["smp"]=="") ? 1 : f["smp"]+0
    sp = (f["spill"]=="1") ? "spill=1" : "spill=0"
    cl = (f["cl"]=="-" || f["cl"]=="") ? "cl=- (chunked)" : "cl=co"
    c[sp "  " cl] += s
    tot += s
}
END{
    n=split("spill=1  cl=- (chunked)|spill=1  cl=co|spill=0  cl=- (chunked)|spill=0  cl=co", ord, "|")
    for(j=1;j<=n;j++){ k=ord[j]
        printf "  %-26s %8d  (%5.1f%%)\n", k, (k in c)?c[k]:0, tot?100*((k in c)?c[k]:0)/tot:0 }
    printf "  ---- uoc tinh tong POST: %d\n", tot
}'
