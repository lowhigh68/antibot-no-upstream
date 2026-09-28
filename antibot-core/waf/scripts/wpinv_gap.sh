#!/bin/bash
# wpinv_gap.sh — DOI CHIEU cho `fim.sh wpinv`: WP root nao KHONG duoc mot host
# nao tro tới, tuc se KHONG co khoa, tuc ba luat HARD-BLOCK im lang o do.
#
# VI SAO CAN LA MOT LENH RIENG. `wpinv` in ba con so:
#     duong vao WP tren dia : N     (docroot, host) tu DA : M     khoa ghi : K
# Vong `awk` ghep trong `wpinv` BO IM LANG moi dong `roots` co docroot khong nam
# trong `inv`. Nen K < N la chuyen CO THAT XAY RA, va `wpinv` khong noi dong nao
# bi bo. Ho loi da giet `wp_paths.mark()` bon thang la dung ho nay: ghi mot noi,
# doc mot noi, khong ai bao loi.
#
# `K = N - (so root hut)` LA PHEP TRU SAI, dung no la ket luan sai. Mot docroot
# co alias sinh HAI khoa, nen hai chieu nguoc nhau tron vao mot hieu. Do tren
# chinh cay co dinh cua `wpinv_test.sh`: 6 root, 1 root hut, van ra 6 khoa. Phai
# LIET KE, khong tru.
#
# CHI DOC: khong Redis, khong manifest, khong $CRITLOG, khong sua gi. Chay duoc
# tren may that bat cu luc nao, ke ca khi `wpinv` da ghi roi.
#
# DUNG:  bash waf/scripts/wpinv_gap.sh
# Ma thoat: 0 = moi WP root deu co host   1 = co root hut   2 = khong do duoc.
set -u
export LC_ALL=C

ROOTS="${FIM_ROOTS:-/home/*/domains/*/public_html}"
DA_DATA="${FIM_DA_DATA:-/usr/local/directadmin/data/users}"
HOME_BASE="${FIM_HOME:-/home}"
WPMARK="wp-settings.php"

[ -d "$DA_DATA" ] || { echo "khong thay $DA_DATA" >&2; exit 2; }

inv=$(mktemp)   || exit 2
roots=$(mktemp) || exit 2
trap 'rm -f "$inv" "$roots"' EXIT

# ── (docroot, prefix) tu DIA — y HET nhanh wpinv ──────────────────────
for d in $ROOTS; do
    [ -d "$d" ] || continue
    [ -f "$d/$WPMARK" ] && printf '%s\t%s\n' "$d" "" >> "$roots"
    for sub in "$d"/*/; do
        [ -d "$sub" ] || continue
        if [ -f "$sub$WPMARK" ]; then
            name=$(basename "$sub")
            printf '%s\t/%s\n' "$d" "$name"    >> "$roots"
            printf '%s\t%s\n'  "${sub%/}" ""   >> "$roots"
        fi
    done
done

# ── (docroot, host) tu DirectAdmin — y HET nhanh wpinv ────────────────
for ulist in "$DA_DATA"/*/domains.list; do
    [ -f "$ulist" ] || continue
    duser=$(basename "$(dirname "$ulist")")
    while IFS= read -r dom || [ -n "$dom" ]; do
        dom="${dom%%#*}"; dom="${dom// /}"
        [ -z "$dom" ] && continue
        main="$HOME_BASE/$duser/domains/$dom/public_html"
        printf '%s\t%s\n' "$main" "$dom" >> "$inv"
        ptr="$DA_DATA/$duser/domains/$dom.pointers"
        if [ -f "$ptr" ]; then
            while IFS= read -r pline || [ -n "$pline" ]; do
                pline="${pline%%#*}"; pline="${pline// /}"
                [ -z "$pline" ] && continue
                printf '%s\t%s\n' "$main" "${pline%%=*}" >> "$inv"
            done < "$ptr"
        fi
        subf="$DA_DATA/$duser/domains/$dom.subdomains"
        if [ -f "$subf" ]; then
            while IFS= read -r s || [ -n "$s" ]; do
                s="${s%%#*}"; s="${s// /}"
                [ -z "$s" ] && continue
                sd="$HOME_BASE/$duser/domains/$s.$dom/public_html"
                if [ -d "$sd" ]; then printf '%s\t%s\n' "$sd" "$s.$dom" >> "$inv"
                else                  printf '%s\t%s\n' "$main/$s" "$s.$dom" >> "$inv"; fi
            done < "$subf"
        fi
    done < "$ulist"
done

echo "=== doi chieu wpinv ==="
echo "  duong vao WP tren dia : $(wc -l < "$roots")"
echo "  (docroot, host) tu DA : $(wc -l < "$inv")"
echo

echo "=== doi chieu wpinv $(date '+%Y-%m-%d %H:%M') ==="
echo "  duong vao WP tren dia : $(wc -l < "$roots")"
echo "  (docroot, host) tu DA : $(wc -l < "$inv")"
echo

# ── PHAN LOAI tung dong hut: hai loai, hai xu ly KHAC NHAU ────────────
#
# Khong in mot danh sach roi de nguoi doc phan loai bang mat: ket luan "mat bao
# ve" hay "binh thuong" phu thuoc mot dieu kien kiem duoc bang mot phep thu.
#
#   phu-boi-prefix  WP trong thu muc con ma DA khong khai `sub`. Duong
#                   `<host-cha>/<thu-muc>/` VAN co khoa `waf:wproot:...`, chi
#                   dong `<sub>.<host>` la khong dung duoc. KHONG mat bao ve.
#   KHONG-CO-HOST   docroot ma `domains.list` khong he nhac tới. Co WordPress
#                   chay duoc qua HTTP ma inventory khong sinh khoa nao. MAT
#                   BAO VE — day la dong phai xu ly truoc khi bat gate.
#
# Phan biet bang: thu muc cha (bo mot cap cuoi) co host trong `inv` khong, VA
# dong `(cha, /<ten>)` co that trong `roots` khong. Ca hai dung thi duong HTTP
# qua host cha van phu duoc WordPress nay.
#
# MOT awk, khong hai vong `while` trong pipeline: `while` trong pipeline chay o
# subshell nen bien dem KHONG ra duoc ngoai, va ket qua la 0 im lang -- dung ho
# loi "lenh do hong tra so trong-co-ly".
class=$(awk -F'\t' '
    FILENAME == inv_f          { have[$1] = 1; next }
    FILENAME == roots_f && p2  { seen[$1 FS $2] = 1; next }
    {
        if ($1 in have) next
        n = split($1, seg, "/")
        name = seg[n]
        parent = substr($1, 1, length($1) - length(name) - 1)
        if ((parent FS "/" name) in seen && (parent in have))
            printf "phu-boi-prefix\t%s\t%s\n", $1, name
        else
            printf "KHONG-CO-HOST\t%s\t%s\n", $1, $2
    }
' inv_f="$inv" roots_f="$roots" p2=1 "$inv" "$roots" p2= "$roots" | sort)

if [ -z "$class" ]; then
    echo "(khong co dong nao hut -- moi WP root tren dia deu co it nhat mot host)"
else
    printf '%s\n' "$class" | awk -F'\t' '
        $1 == "phu-boi-prefix" { printf "%-16s %s\n                 -> duong HTTP qua host cha + /%s van co khoa\n", $1, $2, $3; next }
        { printf "%-16s %s\tprefix=[%s]\n", $1, $2, $3 }'
fi
nmiss=$(printf '%s\n' "$class" | grep -c '^KHONG-CO-HOST' || true)
echo

# Dem theo LOAI KHOA, gom ca khong gian khoa MOI (`wpdir`, theo THU MUC). TONG
# ba so nay phai KHOP `khoa SE ghi` cua `wpinv --dry` — day la phep doi chieu
# chinh cua lenh nay, va no chi dung khi dem DU moi loai khoa ma `wpinv` ghi.
#
# `wpdir` IT hon `wphost` la DUNG, khong phai thieu: nhieu alias dung chung mot
# docroot sinh NHIEU khoa host nhung CHUNG MOT khoa thu muc. Chenh lech giua hai
# con so chinh la so alias duoc hop nhat — do tren 171-96: 243 host, 79 docroot.
#
# `wpdir` phat BEN TRONG vong host, khong o ngoai: mot docroot KHONG co host nao
# thi `wpinv` bo ca dong (vong ghep `awk` cua no chi chay khi `hmap` co host), nen
# no KHONG ghi khoa `wpdir` nao ca. Ban dau toi phat `wpdir` truoc vong host va
# dem ra 11 trong khi `wpinv` ghi 10 — hai ben khong dong y, va `wpinv` la ben
# dung: mot thu muc khong ai tro tới thi khong co khoa nao, ke ca khoa thu muc.
echo "── so khoa theo loai (TONG phai khop 'khoa SE ghi' cua wpinv --dry) ──"
awk -F'\t' '
    NR==FNR { hmap[$1] = hmap[$1] "\n" $2; next }
    {
        n=split(hmap[$1],hs,"\n")
        seen_dir = 0
        for (i=1;i<=n;i++) {
            h=hs[i]; if (h=="") continue
            if (!seen_dir) { printf "wpdir\t%s%s\n", $1, $2; seen_dir=1 }
            if ($2=="") printf "wphost\t%s\n", h; else printf "wproot\t%s:%s\n", h, $2
        }
    }
' "$inv" "$roots" | sort -u | awk '{c[$1]++; t++} END{
    for(k in c) printf "  %-8s %d\n", k, c[k]; printf "  %-8s %d\n", "TONG", t }'
echo
# Ma thoat doc SO DONG MAT BAO VE, khong doc tong so dong hut: `phu-boi-prefix`
# la trang thai BINH THUONG cua mot WP trong thu muc con, khong phai su co. Tra
# 1 cho no la day nguoi van hanh vao cho bo qua ca canh bao that.
if [ "$nmiss" -gt 0 ]; then
    echo "wpinv_gap: $nmiss WP root KHONG CO HOST nao -- xu ly truoc khi bat gate." >&2
    exit 1
fi
echo "wpinv_gap: moi WP root deu duoc phu."
exit 0
