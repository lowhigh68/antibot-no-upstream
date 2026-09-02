#!/bin/bash
# FIM — giam sat toan ven file tren hosting chia se.
#
# VI SAO CAN, khi da co WAF: luat theo URI chi thay thu di qua HTTP. Ba duong
# tan cong pho bien nhat KHONG di qua do:
#   - mu-plugins tu chay: WordPress `include` moi .php o day tren MOI request,
#     ke tan cong khong can gui request nao. Do 2026-09-02: quet dia tim ra file
#     tren 13 site, con WAF thi mu hoan toan.
#   - LFI: `/index.php?f=uploads/shell.php` — shell duoc `include`, khong bao gio
#     la mot HTTP request rieng.
#   - cron / CLI / vao thang Apache 127.0.0.1:8080: khong di qua OpenResty.
#
# METADATA CHU KHONG BAM NOI DUNG. `find -printf` gan nhu mien phi; sha256sum
# tren ~150k file PHP moi ngay la ganh I/O that tren may chia se. Danh doi:
#   BAT duoc  file moi (moi de doa chinh), file bi xoa, doi kich thuoc, doi mtime
#   BAT duoc  file bi LUI NGAY (`touch -t 2020...`) — thu ma `find -mtime -1` bo
#             lot hoan toan, vi duong dan do la MOI trong manifest du mtime ghi gi
#   BO SOT    sua noi dung roi `touch -r` tra lai mtime VA chen cho dung bang
#             kich thuoc cu. Can chan ca cai do thi doi sang sha256sum va chay
#             hang tuan thay vi hang ngay.
#
# DUNG:
#   fim.sh baseline        tao manifest dau tien, khong bao cao gi
#   fim.sh check           so sanh, bao cao, cap nhat manifest
#   fim.sh check --dry     so sanh, bao cao, KHONG cap nhat manifest
#
# Ma thoat: 0 = khong co gi dang chu y   1 = co phat hien CRITICAL/HIGH
#           2 = khong chay duoc
set -uo pipefail

ROOTS="/home/*/domains/*/public_html"
STATE="/var/lib/antibot/fim"
MANIFEST="$STATE/manifest.txt"
LOG="/var/log/antibot/fim.log"

# Nguong gom nhom. Mot ban cap nhat plugin hoac core cham hang tram file cung
# luc; mot webshell cham DUNG MOT. Nhom dong hon nguong nay gop thanh mot dong
# tom tat, nhom nho thi liet ke tung file. Day la toan bo co che chong nhieu cua
# script, va no du vi hai dan so do khac nhau ve BAC do lon.
GROUP_MAX=5

usage() { echo "dung: $0 {baseline|check} [--dry]" >&2; exit 2; }

# Be mat thuc thi + cau hinh. `.htaccess` va `.user.ini` co trong danh sach vi
# chung DOI DUOC handler: tha mot `.htaccess` vao uploads la bat lai PHP o do —
# loi vong ma khong luat URI nao nhin thay.
scan() {
    find $ROOTS \
        \( -name '*.php'  -o -name '*.php[0-9]' -o -name '*.phtml' \
        -o -name '*.phar' -o -name '*.pht'      -o -name '*.phps'  \
        -o -name '.htaccess' -o -name '.user.ini' \) \
        -type f -printf '%p|%s|%T@\n' 2>/dev/null | sort
}

mode="${1:-}"; [ -n "$mode" ] || usage
shift
dry=0; verbose=0
for a in "$@"; do
    case "$a" in
        --dry)        dry=1 ;;
        -v|--verbose) verbose=1 ;;
        *)            usage ;;
    esac
done

mkdir -p "$STATE" || { echo "khong tao duoc $STATE" >&2; exit 2; }

# KHOA CHONG CHAY CHONG. Bat buoc khi chay day (moi 15 phut): neu mot lan quet
# lau hon khoang cach giua hai lan, hai tien trinh se cung ghi $MANIFEST va ban
# ghi thang nao ket thuc sau thi thang. Hau qua khong phai bao dong sai ma la
# BO SOT: manifest bi ghi de bang anh chup cu hon, va thay doi giua hai moc do
# bien mat vinh vien.
#
# `-n` = khong doi. Lan chay bi trung se thoat im lang: no khong co gi de bao,
# lan dang chay se bao.
exec 9>"$STATE/.lock" || { echo "khong mo duoc lockfile" >&2; exit 2; }
if ! flock -n 9; then
    [ $verbose -eq 1 ] && echo "dang co lan chay khac, bo qua"
    exit 0
fi

if [ "$mode" = "baseline" ]; then
    scan > "$MANIFEST" || { echo "quet that bai" >&2; exit 2; }
    echo "baseline: $(wc -l < "$MANIFEST") file"
    exit 0
fi

[ "$mode" = "check" ] || usage
[ -s "$MANIFEST" ] || { echo "chua co manifest — chay '$0 baseline' truoc" >&2; exit 2; }

new_scan=$(mktemp) || exit 2
diff_out=$(mktemp) || exit 2
trap 'rm -f "$new_scan" "$diff_out"' EXIT

scan > "$new_scan" || { echo "quet that bai" >&2; exit 2; }

# Mot luot awk: NEW (duong dan chua tung thay), CHG (kich thuoc hoac mtime doi),
# DEL (bien mat). So sanh theo DUONG DAN chu khong theo dong, nen mot file doi
# noi dung ra dung mot dong CHG chu khong phai mot NEW cong mot DEL.
awk -F'|' '
    NR==FNR { old[$1] = $2 "|" $3; next }
    {
        if (!($1 in old))              print "NEW|" $1
        else if (old[$1] != $2 "|" $3) print "CHG|" $1
        seen[$1] = 1
    }
    END { for (p in old) if (!(p in seen)) print "DEL|" p }
' "$MANIFEST" "$new_scan" > "$diff_out"

total=$(wc -l < "$diff_out")
if [ "$total" -eq 0 ]; then
    [ $dry -eq 0 ] && cp "$new_scan" "$MANIFEST"
    # IM LANG khi khong co gi. cron gui mail theo BAT KY dong stdout nao, khong
    # phai theo ma thoat — in "khong co thay doi" moi 15 phut la 96 mail/ngay,
    # va hop thu bi nhan chim thi canh bao that cung chim theo.
    [ $verbose -eq 1 ] && echo "khong co thay doi nao"
    exit 0
fi

# Phan loai + gom nhom trong DUNG MOT luot awk.
#
# KHONG dung vong `while read` goi `classify`/`dirname` cho tung dong: mot ban
# cap nhat core 2.000 file se sinh 4.000 tien trinh con. Da tra gia cho dung sai
# lam do mot lan (script khao sat chay 11 phut 21 giay), khong lap lai.
#
# uploads/ va mu-plugins/: khong co ly do chinh dang nao de PHP MOI xuat hien.
# wp-includes/ va wp-admin/: thu vien core, chi doi khi cap nhat core — ma cap
# nhat core cham hang tram file nen roi vao nhanh gom nhom, khong gay nhieu.
# plugins/ va themes/: doi thuong xuyen va hop le nen ha xuong ROUTINE.
# Con lai (web root, wp-config.php, .htaccess ngoai cung) la HIGH.
#
# Sap xep theo chuoi muc do cho ra dung thu tu can doc: CRITICAL < HIGH < ROUTINE.
report=$(awk -F'|' -v max="$GROUP_MAX" '
    function sev(p) {
        if (p ~ /\/wp-content\/uploads\//)    return "CRITICAL"
        if (p ~ /\/wp-content\/mu-plugins\//) return "CRITICAL"
        if (p ~ /\/wp-includes\//)            return "CRITICAL"
        if (p ~ /\/wp-admin\//)               return "CRITICAL"
        if (p ~ /\/wp-content\/plugins\//)    return "ROUTINE"
        if (p ~ /\/wp-content\/themes\//)     return "ROUTINE"
        return "HIGH"
    }
    function dirn(p,   i) {
        i = length(p)
        while (i > 1 && substr(p, i, 1) != "/") i--
        return substr(p, 1, i - 1)
    }
    {
        key = sev($2) "\t" $1 "\t" dirn($2)
        n[key]++
        if (n[key] <= max) item[key] = item[key] $2 "\n"
    }
    END {
        for (k in n) {
            split(k, f, "\t")
            if (n[k] > max)
                printf "%-8s %-3s %4d file trong %s  (nhieu kha nang la cap nhat)\n", \
                       f[1], f[2], n[k], f[3]
            else {
                m = split(item[k], L, "\n")
                for (i = 1; i < m; i++) printf "%-8s %-3s %s\n", f[1], f[2], L[i]
            }
        }
    }' "$diff_out" | sort)

# Chi dem cac dong DUOC LIET KE TUNG FILE. Dong tom tat cua mot nhom dong la cap
# nhat phan mem — bao dong o do la bien script thanh thu khong ai doc nua.
crit=$(printf '%s\n' "$report" | grep -E '^(CRITICAL|HIGH) ' | grep -vc 'cap nhat')

header="=== FIM $(date '+%Y-%m-%d %H:%M') — $total thay doi, $crit dang chu y ==="

# LOG luon nhan day du, ke ca ROUTINE: khi dieu tra mot vu thi lich su cap nhat
# plugin lai la thu can doi chieu.
{ echo "$header"; printf '%s\n' "$report"; } >> "$LOG"

# stdout — tuc mail cua cron — CHI khi co gi dang chu y. Cap nhat plugin dinh ky
# ma cung gui mail thi vai tuan nua khong ai mo mail cua no nua.
if [ "$crit" -gt 0 ] || [ $verbose -eq 1 ]; then
    echo "$header"
    printf '%s\n' "$report"
fi

[ $dry -eq 0 ] && cp "$new_scan" "$MANIFEST"

[ "$crit" -gt 0 ] && exit 1
exit 0
