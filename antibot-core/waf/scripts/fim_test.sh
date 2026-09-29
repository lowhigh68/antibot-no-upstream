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
# cho `GET`/`EXISTS` de vong XAC MINH VONG TRON cua fim.sh di qua — neu khong, no
# bao "KHONG XAC MINH DUOC" va che mat cai dang kiem.
#
# BA che do, va do la diem cua ban nay: `RCLI_MODE=down` mo phong MAT KET NOI.
# Truoc ban nay ban gia luon `exit 0` va luon in mot dong, nen bo test KHONG DIEN DAT
# DUOC ca "Redis chet" — va do la ly do ba loi fail-silent trong `fim.sh` song duoc
# (nguoi dung bat 29-09). Cung ho loi voi stub `safe_get` khong tra duoc `(nil, err)`.
#
# `down` lam dung cai `redis-cli` that lam: khong in gi ra stdout, bao loi ra stderr,
# ma thoat khac 0. `fim.sh` PHAI phan biet duoc no voi "key khong ton tai".
cat > "$R/bin/rcli" <<'RCLI'
#!/bin/bash
# `-n <db>` roi hoac `GET/EXISTS/DEL <key>` hoac doc lenh tu STDIN.
if [ "${RCLI_MODE:-up}" = "down" ]; then
    cat >/dev/null 2>&1   # nuot STDIN neu co, y nhu mot binary that
    echo "Could not connect to Redis at 127.0.0.1:6379: Connection refused" >&2
    exit 1
fi
db=""
while [ $# -gt 0 ]; do
    case "$1" in
        -n) db="$2"; shift 2 ;;
        GET) key="$2"
             # Tra gia tri da ghi cho key do, lay tu file lenh. `DEL` sau do lam no
             # mat — nen phai xet CA hai theo THU TU xuat hien.
             awk -v k="$key" '
                 $1=="SETEX" && $2==k { v=$4; has=1 }
                 $1=="DEL"   && $2==k { v="";  has=0 }
                 END { if (has) print v; else print "" }' "$RCLI_OUT"
             exit 0 ;;
        EXISTS) key="$2"
             # `EX_STUCK=1` = khoa KHONG BAO GIO mat, tuc DEL that bai im lang. Do la
             # ca ma `-n "$(GET)"` cua ban truoc KHONG phan biet duoc voi "da xoa".
             if [ "${EX_STUCK:-0}" = 1 ]; then echo 1; exit 0; fi
             # 0/1, y nhu Redis that. Day la lenh phan biet duoc "khong con" voi
             # "khong ket luan duoc" — `GET` tra chuoi rong cho CA HAI.
             awk -v k="$key" '
                 $1=="SETEX" && $2==k { has=1 }
                 $1=="DEL"   && $2==k { has=0 }
                 END { print (has ? 1 : 0) }' "$RCLI_OUT"
             exit 0 ;;
        DEL) printf 'DEL %s\n' "$2" >> "$RCLI_OUT"; echo 1; exit 0 ;;
        *) shift ;;
    esac
done
cat >> "$RCLI_OUT"
RCLI
chmod +x "$R/bin/rcli"
export RCLI_OUT="$R/redis_cmds.txt"
: > "$RCLI_OUT"

# ── `sleep 0.02` chu khong `sleep 1` — DO DUOC, khong phong ─────────
#
# `deploy.sh` buoc [3b] TREO tren may that 30-09: bo nay vuot 300s va bi `timeout` cat,
# voi `user 1.7s` — tuc gan nhu khong CPU, toan bo la CHO. 32 lan `sleep 1` cong 32
# giay, roi moi lan goi `fim.sh` con mot `find` tren he thong tep that.
#
# `sleep` o day chi de mtime cua hai lan ghi lien tiep KHAC nhau. Do xem can bao lau:
#     find -printf '%T@'  ->  1790701796.4720924220   (10 chu so thap phan)
#     hai lan ghi cach 10ms ->  mtime DA khac
#     `sleep 0.02` x 20 lan  ->  0/20 lan mtime trung
# Va `fim.sh` con so CA kich thuoc (`%s`), nen hai lan ghi khac noi dung thi doi ca hai
# cot.
#
# Bo HET `sleep` cung cho 57/57 qua (do duoc), nhung giu 0.02 de phep kiem khong dua
# vao do phan giai nanosecond cua rieng ext4.
#
# Ket qua: 41s -> 7,7s trong WSL (giam 81%). Tren may that day la khac biet giua "treo
# deploy" va "chay xong".
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
sleep 0.02
printf 'RewriteEngine On\nAddType application/x-httpd-lsphp .jpg\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true

# ── KHOA LA THU MUC, GIA TRI LA DANH SACH DUOI (nguoi dung bat 27-09) ──
#
# Ban truoc khoa theo DUONG DAN TEP (`.../.htaccess`) va `waf/init.lua` chi tra
# khoa do khi URI co duoi trong `upload.PHP_EXT`. Nhung co che dang can bat la
# `AddType ... .jpg` roi goi `/shell.jpg` — `.jpg` khong trong `PHP_EXT`, nen WAF
# KHONG BAO GIO tra. Dieu kien loc BIT dung co che ma luat sinh ra de bat.
#
# Nay khoa la THU MUC va gia tri la cac DUOI bi anh xa, nen WAF tra duoc mot lan
# (khong ba round-trip) va biet `.jpg` la duoi dang nguy hiem trong thu muc do.
want "2 fimchg theo THU MUC" "$(haskey "waf:fimchg:$WEB/")" "yes"
want "2 KHONG con khoa theo TEP" "$(haskey "waf:fimchg:$WEB/.htaccess")" "no"
want "2 KHONG co fimnew nao" "$(keys 'waf:fimnew:')" "0"
want "2 chi 1 key fimchg"    "$(keys 'waf:fimchg:')" "1"
# GIA TRI la duoi bi anh xa — day la thong tin ma ban truoc khong co.
want "2 gia tri la duoi bi anh xa" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT")" "ext:jpg"
want "2 TTL dung" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$3}" "$RCLI_OUT")" "604800"

# Nhieu duoi, va CHI duoi cua directive ANH XA duoc tinh: `AddType text/plain .txt`
# khong duoc vao danh sach (do la FP loi 6 da sua o `upload_content.lua`).
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .jpg .png\nAddType text/plain .txt\n' \
    > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
got=$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT")
want "2b hai duoi duoc anh xa" "$got" "ext:jpg,ext:png"
case "$got" in *txt*) want "2b .txt KHONG duoc tinh" "co-txt" "khong-txt" ;;
               *)     want "2b .txt KHONG duoc tinh" "khong-txt" "khong-txt" ;; esac


# ══ 2c. TEN TEP khong duoc thanh CO — va cham khong gian ten ════════════════
#
# Nguoi dung tai hien 29-09: `AddHandler application/x-httpd-php .@all` sinh token
# `@all`, va `init.lua` doc thanh `handler_all` = "handler ap CA thu muc". Mot cai
# TEN TEP tro thanh mot phan quyet manh hon han su that.
#
# Ca nay di het duong THAT: `fim.sh check` -> `htaccess_parse.awk` -> gia tri Redis.
# Mot phep kiem chi o parser khong du — chinh cho noi gia tri duoc GHEP moi la cho
# hai khong gian ten gap nhau.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddHandler application/x-httpd-php .@all\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
got=$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT")
want "2c ten .@all -> ext:@all, KHONG phai @all" "$got" "ext:@all"
# Bien the: ten trung ca bon co.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddHandler application/x-httpd-php .@php .@phpini .@execcgi\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c ba ten trung co deu co tien to" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT")" \
     "ext:@execcgi,ext:@php,ext:@phpini"
# Huong NGUOC: `SetHandler` van phai ra `@all` THAT (phep sua khong lam mat nghia).
: > "$RCLI_OUT"
sleep 0.02
printf 'SetHandler application/x-httpd-php\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c SetHandler van la @all THAT" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT")" "@all"
# TRA lai trang thai cua ca 2b: ca 4 o duoi tinh tu `.htaccess` HIEN CO tren dia
# (thiet ke "tinh lai tu DIA"), nen mot ca chen vao giua PHAI don trang thai cua no.
# Thieu buoc nay thi ca 4 doc `@all` cua ca 2c va bao hong o mot cho khong lien quan.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .jpg .png\nAddType text/plain .txt\n' \
    > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# ══ 3. File PHP MOI -> `fimnew`, KHONG lan sang `fimchg` ════════════════════
#
# Huong nguoc lai cua muc 2. Hai nhom phai DOC LAP; tron chung la bien mot lan
# plugin ghi `.htaccess` thanh "co file thuc thi moi".
: > "$RCLI_OUT"
sleep 0.02
printf '<?php eval($_GET[1]);\n' > "$WEB/shell.php"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true

want "3 fimnew co shell.php" "$(haskey "waf:fimnew:$WEB/shell.php")" "yes"
want "3 KHONG co fimchg nao" "$(keys 'waf:fimchg:')" "0"

# ══ 4. `.user.ini` bi sua -> fimchg ═════════════════════════════════════════
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=128M\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# Lan dau xuat hien la NEW, khong phai CHG — nen no di duong `fimnew`. Dung, va
# day la phep kiem ghim dieu do: mot `.user.ini` MOI la mot file moi.
want "4 .user.ini moi -> fimnew" "$(haskey "waf:fimnew:$WEB/.user.ini")" "yes"

: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=128M\nauto_prepend_file=/tmp/x.php\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "4 .user.ini SUA -> fimchg" "$(haskey "waf:fimchg:$WEB/")" "yes"
want "4 va KHONG fimnew"         "$(keys 'waf:fimnew:')" "0"
# `auto_prepend_file` nap ma cho MOI script PHP trong thu muc, khong doi handler
# cua duoi nao -> gia tri `*`. Khac han nhom `.htaccess` (danh sach duoi cu the),
# va `waf/init.lua` giu dieu kien `PHP_EXT` RIENG cho nhom nay.
# `@php` chu KHONG `*`: ba nghia da duoc tach (nguoi dung bat 28-09). Dau `*` cu bi
# `init.lua` hieu la "autoload, chi duoi trong PHP_EXT", nen `SetHandler` — ap CA
# thu muc, moi duoi — bi hieu NHE HON su that.
#
# Va gia tri gio la TRANG THAI CA THU MUC, khong phai su kien cua tep vua doi:
# `.htaccess` tu buoc 2b van con tren dia nen `jpg,png` van co mat. Do la DUNG —
# khoa mo ta THU MUC, va day la chinh loi da duoc sua.
want "4 gia tri co @php (het dau * ba nghia)" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT" | tail -1)" "ext:jpg,ext:png,@php"

# Chong FP: mot `.user.ini` bi sua ma KHONG co autoload -> khong duoc bao.
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=256M\nupload_max_filesize=8M\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# KHONG con la "im": khoa mo ta CA THU MUC, va `.htaccess` tu buoc 2b van tren dia
# nen khoa van phai co `jpg,png`. Dieu phai kiem la KHONG co `@php` — tuc mot
# `.user.ini` khong autoload thi khong gop tin hieu autoload vao.
val4b=$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT" | tail -1)
want "4b khong autoload -> KHONG co @php" \
     "$(case "$val4b" in *@php*) echo co ;; *) echo khong ;; esac)" "khong"
want "4b nhung khoa VAN co (.htaccess con tren dia)" \
     "$(case "$val4b" in *jpg*) echo co ;; *) echo khong ;; esac)" "co"
# Va gia tri RONG / `none` cung khong duoc bao (hai dong CO THAT trong php.ini
# hop le de TAT tinh nang).
: > "$RCLI_OUT"
sleep 0.02
printf 'auto_prepend_file=\nauto_append_file=none\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
val4c=$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT" | tail -1)
want "4c autoload rong/none -> KHONG co @php" \
     "$(case "$val4c" in *@php*) echo co ;; *) echo khong ;; esac)" "khong"

# ══ 5. File THUONG bi sua -> KHONG nhom nao ═════════════════════════════════
#
# Chong FP cua ca muc 8: `index.php` bi sua la mot `CHG` binh thuong (cap nhat
# phan mem), va no KHONG duoc vao `fimchg` — nhom do CHI danh cho tep cau hinh.
: > "$RCLI_OUT"
sleep 0.02
printf 'index.php\n// sua\n' > "$WEB/index.php"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "5 index.php sua: khong fimchg" "$(keys 'waf:fimchg:')" "0"

# ══ 6. `--dry` KHONG duoc ghi Redis ═════════════════════════════════════════
: > "$RCLI_OUT"
sleep 0.02
printf 'RewriteEngine On\nAddHandler x-httpd-lsphp .png\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check --dry >/dev/null 2>&1 || true
want "6 --dry khong ghi gi" "$(wc -l < "$RCLI_OUT")" "0"

# Va khong-dry ngay sau do THI ghi — de chac muc 6 xanh vi `--dry`, khong phai vi
# thay doi da bi tieu thu mat.
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "6 khong-dry thi ghi" "$(haskey "waf:fimchg:$WEB/")" "yes"



# ══ 8. VONG DOI NEW -> CHG -> DEL cua tep cau hinh ══════════════════════
#
# Truoc ban nay dieu kien la `$1 == "CHG"`, nen:
#   · `.user.ini` MOI chua `auto_prepend_file` khong sinh `fimchg`. No di duong
#     `fimnew`, nhung `waf/init.lua` tra `fimnew` theo TEP DUOC REQUEST — request
#     la `/index.php`, khong phai `/.user.ini`. Tin hieu CO ma khong ai tieu thu.
#   · `.htaccess` MOI anh xa `.jpg` cung khong sinh `fimchg`, nen `/shell.jpg`
#     khong hoi khoa nao.
#   · Tep cau hinh BI XOA de lai khoa den 7 ngay -> telemetry duong tinh gia.
: > "$RCLI_OUT"
sleep 0.02
rm -f "$WEB/.htaccess" "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true

# `.htaccess` MOI (vua bi xoa o tren, nay tao lai) -> PHAI co fimchg.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddHandler application/x-httpd-lsphp .jpg\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "8 .htaccess MOI -> fimchg" "$(haskey "waf:fimchg:$WEB/")" "yes"
want "8 gia tri dung" \
     "$(awk "\$2==\"waf:fimchg:$WEB/\" {print \$4}" "$RCLI_OUT" | head -1)" "ext:jpg"

# `.user.ini` MOI co autoload -> PHAI co fimchg (gia tri `*`).
: > "$RCLI_OUT"
sleep 0.02
printf 'auto_prepend_file=/tmp/x.php\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "8 .user.ini MOI co autoload -> fimchg" "$(haskey "waf:fimchg:$WEB/")" "yes"

# BI XOA -> phai phat DEL, khong de khoa song het TTL.
: > "$RCLI_OUT"
sleep 0.02
rm -f "$WEB/.htaccess" "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "8 tep cau hinh bi XOA -> DEL khoa" \
     "$(grep -c "^DEL waf:fimchg:$WEB/\$" "$RCLI_OUT")" "1"
want "8 va KHONG dat lai SETEX fimchg" "$(keys 'waf:fimchg:')" "0"

# ══ 9. `.inc` — `upload.lua:PHP_EXT` coi la THUC THI DUOC ════════════════
#
# Hai ben truoc day lech: phia request coi `.inc` la executable, con `NAMES` cua
# FIM khong co `*.inc`. Nen webshell `.inc` moi khong vao manifest.
: > "$RCLI_OUT"
sleep 0.02
printf '<?php eval($_GET[1]);\n' > "$WEB/backdoor.inc"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "9 .inc moi -> fimnew" "$(haskey "waf:fimnew:$WEB/backdoor.inc")" "yes"

# `php.ini` — truoc ban nay nhanh xu ly no la MA CHET (khong co trong NAMES).
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=64M\n' > "$WEB/php.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "9 php.ini vao manifest (fimnew)" "$(haskey "waf:fimnew:$WEB/php.ini")" "yes"
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=64M\nauto_prepend_file=/tmp/y.php\n' > "$WEB/php.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "9 php.ini SUA co autoload -> fimchg" "$(haskey "waf:fimchg:$WEB/")" "yes"
# ══ 7. TANG NONG GENERIC (khong chi duong dan WordPress) ════════════════
#
# VI SAO: truoc ban nay 5/6 nhanh cua `scan_hot` la duong dan WordPress
# (`wp-content`, `mu-plugins`), chi nhanh dau la generic. Nen tren may code tay
# tang nong CHI thay web root do sau 1 — webshell tha vao `/includes/`,
# `/libraries/`, `/ajax/` chi duoc TANG DAY DU thay, tuc mot ngay mot lan.
#
# Tieu chi chon nhanh khong doi: "chay duoc ma khong can mot HTTP request nao" —
# do la bat bien GENERIC, `mu-plugins` chi la MOT hien thuc cua no.
HOT=$(mktemp -d /var/tmp/fimhot.XXXXXX) || exit 2
HW="$HOT/home/u1/domains/s.test/public_html"
mkdir -p "$HW/wp-includes/blocks" "$HW/wp-content/mu-plugins/deep/deeper" "$HW/vendor/pkg" \
         "$HW/sub1/wp-content/mu-plugins/x" \
         "$HW/libraries/joomla" "$HW/includes/sub" "$HW/ajax" "$HW/node_modules/m"
: > "$HW/index.php"                        # d1 generic          CO
: > "$HW/.htaccess"                        # d1 generic          CO
: > "$HW/wp-includes/load.php"             # d2 PRUNE            khong
: > "$HW/wp-includes/blocks/b.php"         # d3 PRUNE            khong
: > "$HW/vendor/autoload.php"              # d2 PRUNE            khong
: > "$HW/node_modules/m/x.php"             # d3 PRUNE            khong
: > "$HW/libraries/lib.php"                # d2 generic          CO
: > "$HW/libraries/joomla/j.php"           # d3 generic          CO
: > "$HW/includes/conf.php"                # d2 generic          CO
: > "$HW/includes/sub/deep.php"            # d3 generic          CO
: > "$HW/ajax/handler.php"                 # d2 generic          CO
: > "$HW/wp-content/mu-plugins/mu.php"     # d3                  CO
: > "$HW/wp-content/mu-plugins/deep/d.php" # d4
# d5 PHAN BIET hai nhanh: ca d4 o tren KHONG phan biet duoc, vi nhanh generic
# `-maxdepth 3` tinh tu `$ROOTS` cung voi tới `mu-plugins/deep` — dot bien "go
# nhanh mu-plugins" da XANH vi the. Tep nay o d5 nen CHI nhanh KHONG GIOI HAN
# thay duoc.
: > "$HW/wp-content/mu-plugins/deep/deeper/dd.php"
# NHANH SUBDOMAIN (`$ROOTS/*/wp-content/mu-plugins`): WordPress trong thu muc
# con — `da_to_openresty.sh:318` cho subdomain mot webroot dang
# <public_html>/<sub>. Tep nay o do sau 5 TU `$ROOTS` va duoi `sub1/`, nen
# nhanh generic (maxdepth 3) va nhanh `$ROOTS/wp-content/mu-plugins` deu
# KHONG thay — chi nhanh subdomain thay duoc.
: > "$HW/sub1/wp-content/mu-plugins/x/sub.php"
: > "$HW/anh.png"                          # khong khop NAMES    khong

HSTATE="$HOT/state"; mkdir -p "$HSTATE"
FIM_ROOTS="$HOT/home/*/domains/*/public_html" FIM_STATE="$HSTATE" \
FIM_LOG="$HOT/f.log" FIM_CRITLOG="$HOT/c.log" \
    bash "$HERE/fim.sh" baseline --hot >/dev/null 2>&1

hot_has() {
    if grep -q "^$HW/$1|" "$HSTATE/manifest.hot.txt" 2>/dev/null; then echo yes
    else echo no; fi
}
# DAP AN TINH TAY: 9 tep (dem tay tu bang tren, khong lay tu output).
want "7 tang nong: dung 11 tep" "$(wc -l < "$HSTATE/manifest.hot.txt")" "11"
# Thu muc GENERIC — day la phan ban nay them vao.
want "7 generic: libraries/ do sau 2" "$(hot_has 'libraries/lib.php')"      "yes"
want "7 generic: libraries/ do sau 3" "$(hot_has 'libraries/joomla/j.php')" "yes"
want "7 generic: includes/ do sau 3"  "$(hot_has 'includes/sub/deep.php')"  "yes"
want "7 generic: ajax/"               "$(hot_has 'ajax/handler.php')"       "yes"
# PRUNE — thu vien/core KHONG vao tang nong (tang day du van phu chung).
want "7 prune: wp-includes do sau 2"  "$(hot_has 'wp-includes/load.php')"      "no"
want "7 prune: wp-includes do sau 3"  "$(hot_has 'wp-includes/blocks/b.php')"  "no"
want "7 prune: vendor"                "$(hot_has 'vendor/autoload.php')"       "no"
want "7 prune: node_modules"          "$(hot_has 'node_modules/m/x.php')"      "no"
# `mu-plugins` PHAI giu nhanh KHONG GIOI HAN do sau: nhanh generic dung o 3, con
# WordPress `include` moi tep o do bat ke sau bao nhieu cap.
want "7 mu-plugins do sau 4 van bat" "$(hot_has 'wp-content/mu-plugins/deep/d.php')" "yes"
# PHEP KIEM PHAN BIET hai nhanh (xem chu thich o tep d5 tren).
want "7 mu-plugins do sau 5 (phan biet nhanh)" \
     "$(hot_has 'wp-content/mu-plugins/deep/deeper/dd.php')" "yes"
# PHAN BIET nhanh SUBDOMAIN: chi `$ROOTS/*/wp-content/mu-plugins` thay duoc.
want "7 mu-plugins cua thu muc con (nhanh subdomain)" \
     "$(hot_has 'sub1/wp-content/mu-plugins/x/sub.php')" "yes"
# Khong khop `NAMES` thi khong vao, du o do sau 1.
want "7 anh.png khong vao"           "$(hot_has 'anh.png')"                   "no"
rm -rf "$HOT"

# ══ 10. CHUYEN TRANG THAI: khoa mo ta THU MUC, khong mo ta SU KIEN ══════
#
# Nguoi dung bat 28-09, va da TAI HIEN duoc truoc khi sua. Chuoi that:
#   B1  `.htaccess` anh xa `.jpg`      -> SETEX ... jpg
#   B2  THEM `.user.ini` co autoload   -> SETEX jpg  ROI  SETEX *   (cai sau XOA
#                                         cai truoc: mat `.htaccess`)
#   B3  XOA `.user.ini`                -> SETEX *  ROI  DEL  (cung mot lan chay)
# Ket qua cuoi: MAT khoa, trong khi `.htaccess` nguy hiem VAN CON tren dia. Va vi
# `.htaccess` khong doi nua nen no KHONG bao gio xuat hien lai trong diff — khoa
# mat VO THOI HAN, khong phai tới het TTL.
#
# Bo test cu KHONG bat duoc vi no xoa `$RCLI_OUT` giua cac buoc va chi kiem HINH
# DANG lenh. Nhom nay GIU nguyen output qua ca ba buoc va kiem GIA TRI CUOI.
S=$(mktemp -d /var/tmp/fimstate.XXXXXX) || exit 2
SW="$S/home/u1/domains/st.test/public_html"
mkdir -p "$SW" "$S/state"
: > "$SW/index.php"
SOUT="$S/cmds.txt"; : > "$SOUT"
run_state() {
    RCLI_OUT="$SOUT" FIM_ROOTS="$S/home/*/domains/*/public_html" FIM_STATE="$S/state" \
    FIM_LOG="$S/f.log" FIM_CRITLOG="$S/c.log" FIM_REDIS_CLI="$R/bin/rcli" \
        bash "$HERE/fim.sh" "$@" >/dev/null 2>&1 || true
}
# Gia tri CUOI CUNG cua khoa thu muc: lenh cuoi cung tac dong len no quyet dinh.
final_val() {
    awk -v k="waf:fimchg:$SW/" '
        $1 == "SETEX" && $2 == k { v = $4 }
        $1 == "DEL"   && $2 == k { v = "(DA XOA)" }
        END { print (v == "" ? "(khong co)" : v) }' "$SOUT"
}
run_state baseline

sleep 0.02; printf 'AddHandler application/x-httpd-lsphp .jpg\n' > "$SW/.htaccess"
run_state check
want "10 B1 .htaccess -> ext:jpg" "$(final_val)" "ext:jpg"

# THEM `.user.ini`. `.htaccess` KHONG doi, nen ban cu mat dau vet cua no.
sleep 0.02; printf 'auto_prepend_file=/tmp/x.php\n' > "$SW/.user.ini"
run_state check
want "10 B2 hai tep -> GIU ca hai" "$(final_val)" "ext:jpg,@php"

# XOA `.user.ini`. `.htaccess` nguy hiem VAN CON -> phai SETEX lai, KHONG duoc DEL.
sleep 0.02; rm -f "$SW/.user.ini"
run_state check
want "10 B3 xoa .user.ini -> quay ve ext:jpg (KHONG xoa khoa)" "$(final_val)" "ext:jpg"

# XOA luon `.htaccess`: gio thu muc thuc su sach -> MOI duoc DEL.
sleep 0.02; rm -f "$SW/.htaccess"
run_state check
want "10 B4 xoa het -> DA XOA khoa" "$(final_val)" "(DA XOA)"

# Cau hinh doi tu NGUY HIEM thanh AN TOAN ma tep VAN TON TAI: ban cu khong sinh
# SETEX moi va cung khong DEL, nen khoa nguy hiem cu song tiep het TTL.
sleep 0.02; printf 'AddHandler application/x-httpd-lsphp .jpg\n' > "$SW/.htaccess"
run_state check
want "10 B5 dat lai -> ext:jpg" "$(final_val)" "ext:jpg"
sleep 0.02; printf 'RewriteEngine On\n' > "$SW/.htaccess"
run_state check
want "10 B6 sua thanh AN TOAN -> khoa bi xoa" "$(final_val)" "(DA XOA)"

# ══ 11. REDIS CHET: loi khac han vang mat ═══════════════════════════════════
#
# Nguoi dung bat 29-09. Ba loi cung mot ho trong `fim.sh`:
#   1. ma thoat cua lenh ghi bi bo qua
#   2. `[ -n "$(GET)" ]` coi stdout rong la "key khong con" — Redis chet cung cho
#      stdout rong
#   3. chi kiem `head -1`, key thu hai tro di khong ai kiem
#
# Nhom nay KHONG VIET DUOC truoc ban nay: `rcli` gia luon `exit 0`. Do la ly do ba
# loi tren song duoc trong khi bo test bao xanh — cung ho voi stub `safe_get` khong
# tra duoc `(nil, err)`.
#
# HUONG QUAN TRONG NHAT: Redis chet PHAI bao loi, KHONG duoc im lang thanh cong. Mot
# `fim.sh` im lang khi Redis chet nghia la WAF khong nhan duoc dau nao ma khong ai
# biet — dung ho loi "canh bao dung ma khong ai mo".
: > "$RCLI_OUT"
sleep 0.02
# Noi dung PHAI khac ca truoc: `check` tinh tu diff, va mot `.htaccess` khong doi thi
# khong co `chgcmds` nao — khi do khong nhanh Redis nao chay va ca nay do vi ly do
# KHONG lien quan den dieu no kiem. (Toi da mac dung loi do o ban dau.)
printf 'AddType application/x-httpd-lsphp .gif .bmp\n' > "$WEB/.htaccess"
out=$(RCLI_MODE=down bash "$HERE/fim.sh" check 2>&1)
case "$out" in
    *"KHONG GHI DUOC"*|*"KHONG XAC MINH DUOC"*|*"KHONG KET LUAN DUOC"*)
        want "11 Redis chet -> BAO LOI" "co-bao" "co-bao" ;;
    *)  want "11 Redis chet -> BAO LOI" "IM LANG" "co-bao"
        printf '      output THAT: %s\n' "$(printf '%s' "$out" | head -3 | tr '\n' '|')" ;;
esac
# Va ma thoat phai KHAC 0: mot `fim.sh` bao loi vao log roi `exit 0` la "canh bao
# dung ma khong ai mo" — cron khong bao, giam sat khong thay.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .tif\n' > "$WEB/.htaccess"
RCLI_MODE=down bash "$HERE/fim.sh" check >/dev/null 2>&1
rc11=$?
# Ma thoat phai DUNG BANG 2, khong chi "khac 0": `exit 1` la "co phat hien dang chu
# y" va `exit 3` la "ton dong mu-plugins" — ca hai nghia KHAC. Phep kiem "khac 0"
# cua ban dau KHONG phan biet duoc, va mot dot bien bo han `exit 2` van qua duoc no
# (toi do duoc dieu do). `exit 2` = KHONG DO DUOC, dung nghia da dung cho `mktemp`
# that bai.
want "11 Redis chet -> ma thoat DUNG 2" "$rc11" "2"
# THONG DIEP phai chi dung nguyen nhan. Ban cu chi noi "KHONG XAC MINH DUOC ... Kiem
# FIM_REDIS_DB co khop _M.redis.db" — dung khi lech db, nhung SAI HUONG khi Redis
# chet: no day nguoi van hanh di doc config trong khi viec can lam la khoi dong
# Redis. `redis_send` phan biet duoc hai truong hop do va day la gia tri THAT cua no
# (no khong them kha nang PHAT HIEN nao o nhanh SETEX — vong `GET` so gia tri da du;
# do duoc 29-09).
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .svg\n' > "$WEB/.htaccess"
out=$(RCLI_MODE=down bash "$HERE/fim.sh" check 2>&1)
case "$out" in
    *"KHONG GHI DUOC"*) want "11 Redis chet -> thong diep 'KHONG GHI DUOC'" "dung" "dung" ;;
    *"KHONG XAC MINH DUOC"*) want "11 Redis chet -> thong diep 'KHONG GHI DUOC'" "sai-huong-db" "dung" ;;
    *) want "11 Redis chet -> thong diep 'KHONG GHI DUOC'" "khong-co" "dung" ;;
esac
# Huong NGUOC: Redis SONG thi KHONG duoc bao loi. Thieu ca nay thi mot `fim.sh` luon
# bao loi cung "qua".
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .ico\n' > "$WEB/.htaccess"
out=$(bash "$HERE/fim.sh" check 2>&1)
case "$out" in
    *"KHONG GHI DUOC"*|*"KHONG XAC MINH DUOC"*|*"KHONG KET LUAN DUOC"*)
        want "11 Redis SONG -> KHONG bao loi" "co-bao" "khong-bao" ;;
    *)  want "11 Redis SONG -> KHONG bao loi" "khong-bao" "khong-bao" ;;
esac

# ══ 13. DEL THAT BAI phai bao — ca `-n "$(GET)"` khong the phan biet ════════
#
# Nguoi dung bat 29-09: `[ -n "$("$REDIS_CLI" ... GET "$dk")" ]` coi stdout RONG la
# "khoa khong con", ma Redis mat ket noi CUNG cho stdout rong. Hai ket luan NGUOC
# nhau tu cung mot dau hieu. `EXISTS` tra 0/1 nen phan biet duoc, va nhom nay do CA
# HAI HUONG.
#
# `EX_STUCK=1` lam `EXISTS` luon tra 1: khoa KHONG BAO GIO mat, tuc DEL that bai im
# lang. Ban truoc KHONG THE cho ket qua khac nhau giua hai huong.
#
# MOI buoc dung MOT thu muc RIENG va noi dung KHAC nhau: `check` tinh tu diff, nen
# hai buoc lien tiep cung noi dung thi buoc sau khong sinh lenh Redis nao va ca do vi
# ly do KHONG lien quan (toi da mac dung loi do o ban dau — `out` rong hoan toan).
mkdir -p "$WEB/x13a" "$WEB/x13b"
# A) DEL chay dung -> KHONG duoc bao. Thieu huong nay thi mot `fim.sh` luon bao loi
#    cung "qua", va mot canh bao luon sang la canh bao bi bo qua.
: > "$RCLI_OUT"; sleep 0.02
printf 'AddType application/x-httpd-lsphp .gif\n' > "$WEB/x13a/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
sleep 0.02
printf 'RewriteEngine On\n' > "$WEB/x13a/.htaccess"
out=$(bash "$HERE/fim.sh" check 2>&1)
case "$out" in
    *"(go fimchg)"*) want "13A DEL chay dung -> KHONG bao" "co-bao" "khong-bao" ;;
    *)               want "13A DEL chay dung -> KHONG bao" "khong-bao" "khong-bao" ;;
esac
# B) DEL that bai -> PHAI bao, va phai neu TEN KHOA con sot (khong chi "that bai"):
#    mot bao cao khong co ten khoa thi nguoi van hanh khong biet tim o dau.
: > "$RCLI_OUT"; sleep 0.02
printf 'AddType application/x-httpd-lsphp .bmp\n' > "$WEB/x13b/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
sleep 0.02
printf 'RewriteEngine On\n' > "$WEB/x13b/.htaccess"
out=$(EX_STUCK=1 bash "$HERE/fim.sh" check 2>&1)
case "$out" in
    *"VAN CON: waf:fimchg:"*)            want "13B DEL that bai -> bao ten khoa" "co-ten" "co-ten" ;;
    *"KHONG XAC MINH DUOC (go fimchg)"*) want "13B DEL that bai -> bao ten khoa" "bao-ma-khong-ten" "co-ten" ;;
    *) want "13B DEL that bai -> bao ten khoa" "IM LANG" "co-ten"
       printf '      [out] %s\n' "$(printf '%s' "$out" | tr '\n' '|' | cut -c1-160)" ;;
esac
rm -rf "$S"
printf '\nfim_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
