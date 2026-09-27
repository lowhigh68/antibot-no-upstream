#!/bin/bash
# fim_test.sh — kiem nhanh "TEP CAU HINH bi SUA" cua fim.sh (roadmap muc 8).
#
# VI SAO CAN, va vi sao bay gio: `fim.sh` quyet dinh cai gi DEN DUOC WAF, va truoc
# hom nay no khong co mot phep kiem nao. Muc 8 them mot nhom thu hai
# (`waf:fimchg:`) vao dung cho do. Mot loi o day KHONG bao gi — no chi lam mot
# nhom im lang mai mai, dung ho loi "canh bao dung ma khong ai mo".
#
# COO LAP HOAN TOAN: `FIM_ROOTS` tro vao mot `mktemp -d`, `FIM_STATE`/`FIM_LOG`
# cung vay, va `FIM_REDIS_CLI` la mot script GIA ghi lenh ra file. Khong cham
# `/home`, khong cham Redis, khong cham `/var/lib`. `baseline` la quyet dinh bao
# mat nen KHONG duoc chay tu dong tren may that — o day no chay tren cay thu muc
# gia do chinh bo nay dung ra, tuc khong phai cay nao cua ai.
#
# CHAY:  bash waf/scripts/fim_test.sh
# Ma thoat: 0 = moi con so khop, 1 = co lech, 2 = khong do duoc.
set -u
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)

R=$(mktemp -d /var/tmp/fimtest.XXXXXX) || exit 2
trap 'rm -rf "$R"' EXIT

WEB="$R/home/u1/domains/site.test/public_html"
mkdir -p "$WEB/wp-content/plugins/p1" "$R/state" "$R/bin"

export FIM_ROOTS="$R/home/*/domains/*/public_html"
export FIM_STATE="$R/state"
export FIM_LOG="$R/fim.log"
export FIM_CRITLOG="$R/fim_crit.log"
export FIM_REDIS_CLI="$R/bin/rcli"
export FIM_MARK_TTL=604800

# `redis-cli` GIA: doc lenh tu STDIN, ghi ra file de doi chieu. Tra ve dung gia tri
# cho `GET` de vong XAC MINH VONG TRON cua fim.sh di qua — neu khong, no bao
# "KHONG XAC MINH DUOC" va che mat cai dang kiem.
cat > "$R/bin/rcli" <<'RCLI'
#!/bin/bash
# `-n <db>` roi hoac `GET <key>` hoac doc lenh tu STDIN.
db=""
while [ $# -gt 0 ]; do
    case "$1" in
        -n) db="$2"; shift 2 ;;
        GET) key="$2"
             # Tra gia tri da ghi cho key do, lay tu file lenh.
             awk -v k="$key" '$1=="SETEX" && $2==k { print $4; found=1 }
                              END { if (!found) print "" }' "$RCLI_OUT" | tail -1
             exit 0 ;;
        *) shift ;;
    esac
done
cat >> "$RCLI_OUT"
RCLI
chmod +x "$R/bin/rcli"
export RCLI_OUT="$R/redis_cmds.txt"
: > "$RCLI_OUT"

pass=0; fail=0
want() {  # want <ten> <duoc> <mong>
    if [ "$2" = "$3" ]; then pass=$((pass+1))
    else fail=$((fail+1)); printf 'HONG  %s\n      duoc=%s  mong=%s\n' "$1" "$2" "$3"; fi
}
keys() { grep -c "^SETEX $1" "$RCLI_OUT" 2>/dev/null || true; }
haskey() {
    if grep -q "^SETEX $1 " "$RCLI_OUT" 2>/dev/null; then echo yes; else echo no; fi
}

echo "fim_test: tep cau hinh bi SUA -> waf:fimchg:"

# ══ 1. BASELINE tren mot cay SACH ═══════════════════════════════════════════
printf '<?php\n// plugin\n' > "$WEB/wp-content/plugins/p1/p1.php"
printf 'RewriteEngine On\n'  > "$WEB/.htaccess"
printf 'index.php\n'         > "$WEB/index.php"

if ! bash "$HERE/fim.sh" baseline >/dev/null 2>&1; then
    echo "fim_test: KHONG DO DUOC — baseline that bai"; exit 2
fi
want "1 baseline chua ghi key nao" "$(wc -l < "$RCLI_OUT")" "0"

# ══ 2. `.htaccess` bi SUA -> phai co `fimchg`, KHONG co `fimnew` ════════════
#
# Day la ca chinh cua muc 8: KHONG co file moi nao, nen `fimnew` phai im. Truoc
# ban nay ca lan chay nay khong bao gi sang WAF.
: > "$RCLI_OUT"
sleep 1
printf 'RewriteEngine On\nAddType application/x-httpd-lsphp .jpg\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true

want "2 fimchg co .htaccess" \
     "$(haskey "waf:fimchg:$WEB/.htaccess")" "yes"
want "2 KHONG co fimnew nao" "$(keys 'waf:fimnew:')" "0"
want "2 chi 1 key fimchg"    "$(keys 'waf:fimchg:')" "1"
# TTL va gia tri: gia tri la `1` (dau HIEN DIEN), khong phai muc tin cay cua boost.
want "2 gia tri la 1" \
     "$(awk "\$2==\"waf:fimchg:$WEB/.htaccess\" {print \$4}" "$RCLI_OUT")" "1"
want "2 TTL dung" \
     "$(awk "\$2==\"waf:fimchg:$WEB/.htaccess\" {print \$3}" "$RCLI_OUT")" "604800"

# ══ 3. File PHP MOI -> `fimnew`, KHONG lan sang `fimchg` ════════════════════
#
# Huong nguoc lai cua muc 2. Hai nhom phai DOC LAP; tron chung la bien mot lan
# plugin ghi `.htaccess` thanh "co file thuc thi moi".
: > "$RCLI_OUT"
sleep 1
printf '<?php eval($_GET[1]);\n' > "$WEB/shell.php"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true

want "3 fimnew co shell.php" "$(haskey "waf:fimnew:$WEB/shell.php")" "yes"
want "3 KHONG co fimchg nao" "$(keys 'waf:fimchg:')" "0"

# ══ 4. `.user.ini` bi sua -> fimchg ═════════════════════════════════════════
: > "$RCLI_OUT"
sleep 1
printf 'memory_limit=128M\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# Lan dau xuat hien la NEW, khong phai CHG — nen no di duong `fimnew`. Dung, va
# day la phep kiem ghim dieu do: mot `.user.ini` MOI la mot file moi.
want "4 .user.ini moi -> fimnew" "$(haskey "waf:fimnew:$WEB/.user.ini")" "yes"

: > "$RCLI_OUT"
sleep 1
printf 'memory_limit=128M\nauto_prepend_file=/tmp/x.php\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "4 .user.ini SUA -> fimchg" "$(haskey "waf:fimchg:$WEB/.user.ini")" "yes"
want "4 va KHONG fimnew"         "$(keys 'waf:fimnew:')" "0"

# ══ 5. File THUONG bi sua -> KHONG nhom nao ═════════════════════════════════
#
# Chong FP cua ca muc 8: `index.php` bi sua la mot `CHG` binh thuong (cap nhat
# phan mem), va no KHONG duoc vao `fimchg` — nhom do CHI danh cho tep cau hinh.
: > "$RCLI_OUT"
sleep 1
printf 'index.php\n// sua\n' > "$WEB/index.php"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "5 index.php sua: khong fimchg" "$(keys 'waf:fimchg:')" "0"

# ══ 6. `--dry` KHONG duoc ghi Redis ═════════════════════════════════════════
: > "$RCLI_OUT"
sleep 1
printf 'RewriteEngine On\nAddHandler x-httpd-lsphp .png\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check --dry >/dev/null 2>&1 || true
want "6 --dry khong ghi gi" "$(wc -l < "$RCLI_OUT")" "0"

# Va khong-dry ngay sau do THI ghi — de chac muc 6 xanh vi `--dry`, khong phai vi
# thay doi da bi tieu thu mat.
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "6 khong-dry thi ghi" "$(haskey "waf:fimchg:$WEB/.htaccess")" "yes"

printf '\nfim_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
