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
# `-n <db>` roi hoac `GET/EXISTS/DEL <key>`, hoac `--pipe` doc RESP tu STDIN.
#
# `$RCLI_OUT` dung TAB lam ranh gioi truong: `<lenh>\t<key>\t<ttl>\t<value>`. Ban truoc
# dung KHOANG TRANG va `awk '$2==k'`, nen mot key co khoang trang KHONG tra cuu lai
# duoc — stub mang dung gioi han ma `fim.sh` vua bo di, va se bao "qua" cho mot ca
# that ra hong.
if [ "${RCLI_MODE:-up}" = "down" ]; then
    cat >/dev/null 2>&1   # nuot STDIN neu co, y nhu mot binary that
    echo "Could not connect to Redis at 127.0.0.1:6379: Connection refused" >&2
    exit 1
fi
db=""
pipe=0
while [ $# -gt 0 ]; do
    case "$1" in
        -n) db="$2"; shift 2 ;;
        --pipe) pipe=1; shift ;;
        GET) key="$2"
             awk -F'\t' -v k="$key" '
                 $1=="SETEX" && $2==k { v=$4; has=1 }
                 $1=="DEL"   && $2==k { v="";  has=0 }
                 END { if (has) print v; else print "" }' "$RCLI_OUT"
             exit 0 ;;
        EXISTS) key="$2"
             # `EX_STUCK=1` = khoa KHONG BAO GIO mat, tuc DEL that bai im lang. Do la
             # ca ma `-n "$(GET)"` cua ban truoc KHONG phan biet duoc voi "da xoa".
             if [ "${EX_STUCK:-0}" = 1 ]; then echo 1; exit 0; fi
             awk -F'\t' -v k="$key" '
                 $1=="SETEX" && $2==k { has=1 }
                 $1=="DEL"   && $2==k { has=0 }
                 END { print (has ? 1 : 0) }' "$RCLI_OUT"
             exit 0 ;;
        DEL) printf 'DEL\t%s\n' "$2" >> "$RCLI_OUT"; echo 1; exit 0 ;;
        *) shift ;;
    esac
done

# ── GIAI MA RESP ────────────────────────────────────────────────────
# `*<n>\r\n` roi n lan `$<len>\r\n<arg>\r\n`. Doc bang DO DAI chu khong bang dong:
# mot doi so CO THE chua `\n`, va cat theo dong se lam lech moi thu sau no. Day la
# chinh tinh chat ma RESP dem lai, nen stub phai ton trong no hoac bo test se xanh
# cho mot hien thuc hong.
n_cmd=0
n_err=0
while IFS= read -r hdr; do
    hdr=${hdr%$'\r'}
    [ -n "$hdr" ] || continue
    case "$hdr" in
        \**) nargs=${hdr#\*} ;;
        *) n_err=$((n_err + 1)); continue ;;
    esac
    args=()
    i=0
    while [ "$i" -lt "$nargs" ]; do
        IFS= read -r lh || break
        lh=${lh%$'\r'}
        case "$lh" in
            \$*) alen=${lh#\$} ;;
            *) n_err=$((n_err + 1)); break ;;
        esac
        # `-N <len>` doc DUNG len byte; roi bo `\r\n` con lai.
        arg=""
        if [ "$alen" -gt 0 ]; then IFS= read -r -N "$alen" arg; fi
        IFS= read -r _crlf
        args+=("$arg")
        i=$((i + 1))
    done
    [ "${#args[@]}" -eq "$nargs" ] || { n_err=$((n_err + 1)); continue; }
    n_cmd=$((n_cmd + 1))
    # `RCLI_SKIP=<k>` = lenh thu k den duoc server, duoc DEM vao `replies`, nhung
    # KHONG duoc thuc thi va server KHONG bao loi. Do la ca `errors: 0` ma van MAT
    # mot khoa.
    #
    # KHONG giam `n_cmd`: do la diem toi lam sai o ban dau. Giam `n_cmd` lam canary
    # (lenh CUOI) truot xuong dung vi tri k o lan sau, nen chinh canary bi bo — va
    # canary bat duoc, tuc ca do do SAI thu can do. Do duoc: `rc=2`,
    # `doc=''`, `replies: 0`.
    #
    # `replies` van dem lenh nay, giong Redis that: do tren 171-96 (01-10) voi
    # `redis-cli 8.6.2`, mot lenh bi TU CHOI van vao `replies` (`errors: 1, replies: 3`).
    if [ -n "${RCLI_SKIP:-}" ] && [ "$n_cmd" = "$RCLI_SKIP" ]; then
        continue
    fi
    case "${args[0]}" in
        SETEX)
            if [ "${#args[@]}" -ne 4 ]; then n_err=$((n_err + 1)); continue; fi
            printf 'SETEX\t%s\t%s\t%s\n' "${args[1]}" "${args[2]}" "${args[3]}" >> "$RCLI_OUT" ;;
        DEL)
            printf 'DEL\t%s\n' "${args[1]}" >> "$RCLI_OUT" ;;
        EXISTS)
            # `EXISTS` NHIEU doi so tra MOT so = tong so khoa ton tai (Redis 3.0+).
            # `state_marks` dung no de dem lai CA tap vua ghi trong mot round-trip,
            # nen stub phai mo phong dung hanh vi cong don do.
            nex=0
            j=1
            while [ "$j" -lt "${#args[@]}" ]; do
                kk="${args[$j]}"
                if [ "${EX_STUCK:-0}" = 1 ]; then
                    nex=$((nex + 1))
                else
                    h=$(awk -F'\t' -v k="$kk" '
                        $1=="SETEX" && $2==k { has=1 }
                        $1=="DEL"   && $2==k { has=0 }
                        END { print (has ? 1 : 0) }' "$RCLI_OUT")
                    nex=$((nex + h))
                fi
                j=$((j + 1))
            done
            echo "(integer) $nex" ;;
        *) n_err=$((n_err + 1)) ;;
    esac
done

# `RCLI_ERRN=<k>` = Redis TU CHOI k lenh du ket noi song. Day la ca ma canary mot
# minh KHONG bat duoc, va la ly do `redis_send_resp` doc `errors:`.
if [ -n "${RCLI_ERRN:-}" ]; then n_err=$((n_err + RCLI_ERRN)); fi

if [ "$pipe" = 1 ]; then
    echo "All data transferred. Waiting for the last reply..."
    echo "Last reply received from server."
    echo "errors: $n_err, replies: $n_cmd"
fi
exit 0
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
# `$RCLI_OUT` dung TAB: `SETEX\t<key>\t<ttl>\t<value>`. Ba ham nay la DUY NHAT noi
# biet dinh dang do — truoc day moi ca tu viet mot `awk "\$2==..."` rieng, va khi
# stub doi sang tab thi phai sua hang chuc cho.
keys() { grep -cP "^SETEX\t\Q$1\E" "$RCLI_OUT" 2>/dev/null || true; }
haskey() {
    if grep -qP "^SETEX\t\Q$1\E\t" "$RCLI_OUT" 2>/dev/null; then echo yes; else echo no; fi
}
# `kval <key>` = gia tri cua LAN GHI CUOI; `kttl <key>` = TTL.
kval() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$RCLI_OUT"; }
kttl() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {v=$3} END{print v}' "$RCLI_OUT"; }
# Lan ghi DAU, cho cac ca xet thu tu.
kval1() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {print $4; exit}' "$RCLI_OUT"; }

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
# DOI KY VONG CO Y (01-10): truoc day ca nay doi DUNG MOT khoa, vi `fimchg` chi ghi
# cho thu muc CO tep cau hinh. KE THUA doi dieu do — `.htaccess` o webroot ap cho CA
# thu muc con, nen moi thu muc con co tep PHP cung phai co khoa. Day la phep sua mot
# FALSE NEGATIVE truc tiep: `/public_html/.htaccess` bat `.jpg` thi
# `/public_html/uploads/a.jpg` CHAY qua PHP, ma ban truoc khong co khoa nao o
# `uploads/`.
#
# Dieu ca nay THAT SU phai bao ve la "khoa theo THU MUC, khong theo TEP" — da kiem o
# hai ca tren. Nen o day chi kiem khoa khong BUNG NO: so khoa phai bang so thu muc co
# tep PHP duoi webroot, khong phai so TEP.
want "2 khoa theo thu muc, khong bung no theo tep" \
     "$([ "$(keys 'waf:fimchg:')" -le 3 ] && echo "trong tam" || echo "qua nhieu: $(keys 'waf:fimchg:')")" "trong tam"
# GIA TRI la duoi bi anh xa — day la thong tin ma ban truoc khong co.
want "2 gia tri la duoi bi anh xa" \
     "$(kval "waf:fimchg:$WEB/")" "ext:jpg"
want "2 TTL dung" \
     "$(kttl "waf:fimchg:$WEB/")" "604800"

# Nhieu duoi, va CHI duoi cua directive ANH XA duoc tinh: `AddType text/plain .txt`
# khong duoc vao danh sach (do la FP loi 6 da sua o `upload_content.lua`).
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .jpg .png\nAddType text/plain .txt\n' \
    > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
got=$(kval "waf:fimchg:$WEB/")
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
got=$(kval "waf:fimchg:$WEB/")
want "2c ten .@all -> ext:@all, KHONG phai @all" "$got" "ext:@all"
# Bien the: ten trung ca bon co.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddHandler application/x-httpd-php .@php .@phpini .@execcgi\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c ba ten trung co deu co tien to" \
     "$(kval "waf:fimchg:$WEB/")" \
     "ext:@execcgi,ext:@php,ext:@phpini"
# Huong NGUOC: `SetHandler` van phai ra `@all` THAT (phep sua khong lam mat nghia).
: > "$RCLI_OUT"
sleep 0.02
printf 'SetHandler application/x-httpd-php\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c SetHandler van la @all THAT" \
     "$(kval "waf:fimchg:$WEB/")" "@all"
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
# DOI KY VONG CO Y (30-09), va day la cho de doc nguoc nen noi ro: truoc day ca nay
# doi `fimchg` = 0, vi gia dinh "khong CHG -> khong khoa". Nguon TRANG THAI bac bo dung
# gia dinh do: `$WEB/.htaccess` tu muc 2 VAN con tren dia va VAN anh xa `.jpg` sang
# PHP, nen mot khoa cho thu muc do la DUNG — mot `.htaccess` nguy hiem khong tu het
# nguy chi vi lot nay khong ai sua no.
#
# Dieu ca nay THAT SU phai bao ve van nguyen: hai nhom DOC LAP. `shell.php` moi phai
# vao `fimnew`, va KHONG duoc lam token cua `fimchg` doi. Nen kiem dung do.
want "3 fimchg KHONG bi shell.php moi lam doi" \
     "$(kval "waf:fimchg:$WEB/")" "ext:jpg,ext:png"

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
     "$(kval "waf:fimchg:$WEB/")" "ext:jpg,ext:png,@php"

# Chong FP: mot `.user.ini` bi sua ma KHONG co autoload -> khong duoc bao.
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=256M\nupload_max_filesize=8M\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# KHONG con la "im": khoa mo ta CA THU MUC, va `.htaccess` tu buoc 2b van tren dia
# nen khoa van phai co `jpg,png`. Dieu phai kiem la KHONG co `@php` — tuc mot
# `.user.ini` khong autoload thi khong gop tin hieu autoload vao.
val4b=$(kval "waf:fimchg:$WEB/")
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
val4c=$(kval "waf:fimchg:$WEB/")
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
     "$(kval1 "waf:fimchg:$WEB/")" "ext:jpg"

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
     "$(grep -cP "^DEL\twaf:fimchg:\Q$WEB/\E$" "$RCLI_OUT")" "1"
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

# ══ 14. uploads/: tep TRANG THAI NGAT QUANG phai ha bac ══════════════════════
#
# Do tren may that 30-09: `uploads/sucuri/*.php` (43 tep / 4 site, plugin
# `sucuri-scanner` CO cai tren ca 4) doi 8 lan trong 7 ngay va CHIEM 7/13 canh bao
# `fim.sh` trong hai thang — FP nay lam loang duong bao that. Ngoai no, `uploads/` con
# 181 tep `.php` hop le khac (TCPDF font data + 90 `index.php`), nen danh sach TEN la
# cach sai.
#
# ── VI SAO PHAI CO LUOT IM GIUA CAC LAN DOI ─────────────────────────
#
# `$PREVCHG` da phu "doi HAI LAN LIEN TIEP". Ban DAU cua nhom nay doi tep ba lan lien
# tiep, va no bao XANH — nhung ba dot bien vao nhanh `chgn` deu KHONG bi bat, vi `prev`
# quyet dinh truoc va nhanh `chgn` chua bao gio chay. Xanh gia.
#
# Mot luot `check` KHONG doi gi giua cac lan doi lam `$PREVCHG` bi xoa (xem nhanh
# "khong co CHG nao"), tuc dung hinh dang NGAT QUANG cua Sucuri — va do la hinh dang
# duy nhat mot minh `chgn` tra loi duoc.
#
# DOC TU `$FIM_LOG` chu khong stdout: khi tep xuong `STATE` thi `crit=0` va `fim.sh` im
# lang o stdout (dung thiet ke — cron gui mail theo bat ky dong stdout nao).
mkdir -p "$WEB/wp-content/uploads/st"
bac14() { grep -E "CHG .*uploads/st/$1" "$FIM_LOG" 2>/dev/null | tail -1 | awk '{print $1}'; }
im14()  { bash "$HERE/fim.sh" check >/dev/null 2>&1 || true; }   # luot khong doi gi
doi14() { sleep 0.02; printf '<?php\n// v%s\nexit(0);\n' "$1" > "$WEB/wp-content/uploads/st/d.php"
          bash "$HERE/fim.sh" check >/dev/null 2>&1 || true; }

printf '<?php\n// v1\nexit(0);\n' > "$WEB/wp-content/uploads/st/d.php"
im14                                    # tep MOI, khong phai CHG
doi14 2; im14                           # CHG 1 -> chgn=1
want "14 CHG lan 1 (ngat quang) -> VAN CRITICAL" "$(bac14 d.php)" "CRITICAL"
doi14 3; im14                           # CHG 2 -> chgn=2
want "14 CHG lan 2 (ngat quang) -> VAN CRITICAL" "$(bac14 d.php)" "CRITICAL"
doi14 4                                 # CHG 3 -> bo dem doc duoc = 2 >= N
want "14 CHG lan 3 (ngat quang) -> ha bac STATE" "$(bac14 d.php)" "STATE"

# HUONG NGUOC — quan trong hon ca: mot tep doi DUNG MOT LAN phai GIU `CRITICAL`. Thieu
# ca nay thi mot phep sua "ha bac het" cung qua duoc, tuc mat toan bo kha nang bat
# webshell trong uploads/.
printf '<?php\n// moi\n' > "$WEB/wp-content/uploads/st/once.php"
im14
sleep 0.02; printf '<?php\n// doi mot lan\n' > "$WEB/wp-content/uploads/st/once.php"
im14
want "14 doi DUNG MOT lan -> VAN CRITICAL" "$(bac14 once.php)" "CRITICAL"

# CUA SO NGAY: bo dem KHONG phai danh sach vinh vien. Lui moc thoi gian 100 ngay ->
# moi dong phai rung, va tep quay ve CRITICAL.
CCF="$FIM_STATE/chgcount.full.txt"
want "14 bo dem co ton tai" "$([ -s "$CCF" ] && echo co || echo khong)" "co"
if [ -s "$CCF" ]; then
    OLD=$(( $(date +%s) - 100*86400 ))
    awk -v old="$OLD" '{ i=index($0,"|"); r=substr($0,i+1); j=index(r,"|")
                         print substr($0,1,i-1) "|" old "|" substr(r,j+1) }' "$CCF" > "$CCF.t" \
      && mv "$CCF.t" "$CCF"
    doi14 9
    want "14 dong QUA HAN bi rung -> lai CRITICAL" "$(bac14 d.php)" "CRITICAL"
fi

# ── NHOM 15: `wpinv` phai FAIL khi GHI that bai ───────────────────────
#
# `wpinv` truoc day goi `redis_send "$cmds" || true`, roi xac minh bang mot `GET`.
# Do la mot lo ho THAT (nguoi dung bat 30-09): neu batch nay loi TAM THOI nhung khoa
# tu lan chay TRUOC con song, `GET` van tra `1` -> wpinv bao "thanh cong" trong khi
# TTL KHONG duoc gia han. Khoa se het han im lang 30 ngay sau, va `is_wp_root` tat
# cam ma khong ai biet.
#
# Nhom nay dung mot rcli GIA co HAI hanh vi khac nhau cho GHI va cho DOC: ghi that
# bai, doc tra `1` (nhu mot khoa cu con song). Ban truoc SE XANH o day; ban nay phai
# do. Do la ca ma `RCLI_MODE=down` KHONG dien dat duoc — `down` lam ca hai that bai.

# ── NHOM 16: `detect_execcgi_ok` doc AllowOverride THAT ───────────────
#
# `ExecCGI` la quyen webserver phai cho, khong phai tinh chat cua tep. Ham nay DO no
# tu cau hinh Apache chu khong hardcode — vi `AllowOverride` khac nhau theo may.
#
# MAC DINH AN TOAN la `1`: khong do duoc thi giu tin hieu nhu cu. Nguoc lai se lam mot
# may khong co Apache o duong quen IM LANG toan bo tin hieu ExecCGI.
# ── NHOM 17: TRANG THAI, khong chi THAY DOI ───────────────────────────

#
# Ca ma co che CU KHONG THE bat: mot `.htaccess` doi handler DA co san TU LUC
# `baseline`. No khong bao gio sinh dong CHG, nen `$chgs` rong, va nhanh `total -eq 0`
# `exit 0` TRUC TIEP truoc khi den khoi `fimchg` — vo hinh VINH VIEN.
#
# DO duoc tren fleet 30-09: 11 tep doi handler, TAT CA trong manifest, `fimchg` = 0
# khoa, va 620/620 lot fim.log deu `0 key bao WAF`. Co che cu cho mot su kien chua
# tung xay ra.
#
# CAY THU PHAI DU LON DE PHAN BIET. Ban dau toi dung 1 thu muc co token va 1 khong,
# va BON dot bien (bo gate tier, ghi ca thu muc khong token, bo `.user.ini` khoi
# `config_dirs`, `DEL` ca nguon trang thai) deu KHONG bi bat — test xanh vi cay qua
# nho, khong vi ma dung. Nay: 1 thu muc `.htaccess`, 1 `.user.ini`, 1 `php.ini`,
# va BA thu muc sach — du de mot `DEL` hang loat lo ra.
printf '\n── trang thai: tep cau hinh co SAN tu baseline (muc 17) ──\n'
S17="$R/st17"
W17="$S17/home/u9/domains/s9.test/public_html"
mkdir -p "$W17/sub" "$W17/ini" "$W17/pini" "$W17/sach1" "$W17/sach2" "$W17/sach3" "$S17/state"
printf '<?php\n' > "$W17/index.php"
# BA thu muc co token, BA khong. Tat ca co SAN TRUOC baseline -> khong bao gio CHG.
printf 'AddHandler application/x-httpd-php .jpg\n'      > "$W17/sub/.htaccess"
printf 'auto_prepend_file = /tmp/x.php\n'               > "$W17/ini/.user.ini"
printf 'auto_append_file = /tmp/y.php\n'                > "$W17/pini/php.ini"
# Thu muc SACH: co tep cau hinh nhung KHONG doi handler -> khong duoc ghi khoa.
printf '# BEGIN WordPress\nRewriteEngine On\n'          > "$W17/sach1/.htaccess"
printf 'auto_prepend_file = none\n'                     > "$W17/sach2/.user.ini"
printf 'memory_limit = 256M\n'                          > "$W17/sach3/php.ini"
for d in sub ini pini sach1 sach2 sach3; do printf '<?php\n' > "$W17/$d/a.php"; done

r17() {  # r17 <mode...> — chay fim.sh tren cay rieng
    FIM_ROOTS="$S17/home/*/domains/*/public_html" FIM_STATE="$S17/state" \
    FIM_LOG="$S17/fim.log" FIM_CRITLOG="$S17/crit.log" \
    RCLI_OUT="$S17/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" \
      bash "$HERE/fim.sh" "$@" >/dev/null 2>&1 || true
}
# TAB, y nhu cac ham o tren.
k17()  { local n; n=$(grep -cP "^SETEX\twaf:fimchg:" "$S17/rcli.txt" 2>/dev/null); echo "${n:-0}"; }
v17()  { awk -F'\t' -v k="waf:fimchg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S17/rcli.txt" 2>/dev/null; }
nd17() { local n; n=$(grep -cP "^DEL\twaf:fimchg:" "$S17/rcli.txt" 2>/dev/null); echo "${n:-0}"; }

r17 baseline
: > "$S17/rcli.txt"
# Lot `check` day du: KHONG co gi doi, nhung trang thai phai duoc bao.
r17 check
want "17 khong doi gi ma VAN co khoa fimchg" "$([ "$(k17)" -ge 1 ] && echo co || echo khong)" "co"
# BA nguon token, moi nguon mot nhan RIENG. Bo mot nguon khoi `config_dirs` phai do.
want "17 .htaccess -> ext:jpg"   "$(v17 "$W17/sub/")"  "ext:jpg"
want "17 .user.ini -> @php"      "$(v17 "$W17/ini/")"  "@php"
want "17 php.ini -> @phpini"     "$(v17 "$W17/pini/")" "@phpini"
# DUNG BA khoa, khong hon: ba thu muc sach khong duoc ghi.
want "17 dung 3 khoa, khong ghi thu muc sach" "$(k17)" "3"
want "17 sach1 khong co khoa" "$(v17 "$W17/sach1/")" ""
want "17 sach2 khong co khoa" "$(v17 "$W17/sach2/")" ""
want "17 sach3 khong co khoa" "$(v17 "$W17/sach3/")" ""
# KHONG `DEL` hang loat: nguon TRANG THAI khong sinh `DEL` cho thu muc khong token.
want "17 KHONG DEL thu muc sach" "$(nd17)" "0"

# HUONG NGUOC: bo tep cau hinh di thi khoa phai HET. Thieu ca nay thi mot ban
# "luon ghi moi thu muc" cung qua.
rm -f "$W17/sub/.htaccess"
: > "$S17/rcli.txt"
r17 check
want "17 bo .htaccess -> khong con ghi khoa cho thu muc do" "$(v17 "$W17/sub/")" ""
want "17 bo mot nguon -> con 2 khoa" "$(k17)" "2"

# Redis chet trong luot KHONG CO THAY DOI NAO: `state_marks` phai bao loi va `check`
# phai tra 2. Day la mot DUONG RA rieng (`total -eq 0` -> `exit 0`), va truoc khi co
# doan nay no `exit 0` im lang — cron khong bao, giam sat khong thay. Dung ho loi
# fail-silent da bat ba lan o tep nay.
#
# PHAI `baseline` (tier full) NGAY TRUOC, khong phai `--hot`: mot manifest full cu se
# sinh THAY DOI, va luot do di vao nhanh CO thay doi chu khong vao `total -eq 0` —
# ca test se xanh vi `mark_err` duoc dat o duong KHAC. Ba dot bien khong bi bat vi
# dung ly do nay (do 01-10).
r17 baseline
: > "$S17/rcli.txt"
out17=$(FIM_ROOTS="$S17/home/*/domains/*/public_html" FIM_STATE="$S17/state" \
        FIM_LOG="$S17/fim.log" FIM_CRITLOG="$S17/crit.log" \
        RCLI_OUT="$S17/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" RCLI_MODE=down \
          bash "$HERE/fim.sh" check 2>&1)
rc17=$?
# Doi chieu: luot nay PHAI la luot khong co thay doi, khong thi ca nay do cho khac.
case "$out17" in
    *"thay doi"*) want "17 luot nay la luot KHONG doi" "co thay doi: $out17" "khong doi" ;;
    *) want "17 luot nay la luot KHONG doi" "khong doi" "khong doi" ;;
esac
case "$out17" in
    *"KHONG GHI DUOC"*) want "17 Redis chet o luot KHONG doi -> BAO LOI" "dung" "dung" ;;
    *) want "17 Redis chet o luot KHONG doi -> BAO LOI" "IM LANG: ${out17:-rong}" "dung" ;;
esac
want "17 Redis chet o luot KHONG doi -> ma thoat 2" "$rc17" "2"

# Tier NONG khong quet trang thai: no chay moi 5 phut. Dat tep cau hinh o WEB ROOT
# (tang nong CO quet cho nay) de ca nay phan biet duoc GATE chu khong phan biet
# "tang nong khong thay tep".
printf 'AddHandler application/x-httpd-php .gif\n' > "$W17/.htaccess"
r17 baseline --hot
: > "$S17/rcli.txt"
r17 check --hot
want "17 tier nong KHONG quet trang thai" "$(v17 "$W17/")" ""

# ── NHOM 18: THU MUC MAY SINH TEP -> GOM NHOM, khong ha bac ───────────
#
# `$CHGCOUNT` dem theo DUONG DAN nen no khong the bat mot ho tep sinh TEN MOI moi lan.
# Do 01-10 tren 171-96: `temp/caches/` cua mot web ECShop co 16 thu muc con, moi cai
# da sinh 311-355 tep qua lich su log; 489 tep song va CA 489 deu moi trong 24h.
# Ket qua: 5.133/5.495 dong `HIGH NEW sc=0` la cache — 93,4% bao dong `NEW` la tieng on.
#
# CACH GIAM la GOM NHOM, KHONG ha bac. Ban 3b93bcf ha `NEW` xuong `5STATE` khi
# `pscore == 0`, va do la mot sai lam: `pscore == 0` chi co nghia "khong khop TIN HIEU
# HIEN CO", khong chung minh tep lanh. Mot PHP toi gian duoc ma san co `include` van
# dat `sc=0`, khong co request truc tiep nao den no, va `5STATE` thi khong mail, khong
# `exit 1` — dung truong hop ma file-integrity sinh ra de phu.
#
# Nay `gmax()` ha nguong GOM NHOM cho rieng thu muc do: bac GIU NGUYEN, `crit` van
# dem, mail van gui, chi la 9 dong thanh MOT dong.
printf '\n── thu muc may sinh tep -> gom nhom (muc 18) ──\n'
S18="$R/st18"
W18="$S18/home/u8/domains/s8.test/public_html"
mkdir -p "$W18/temp/caches/7" "$W18/wp-content/uploads/u" "$S18/state"
printf '<?php\n' > "$W18/index.php"

r18() { FIM_ROOTS="$S18/home/*/domains/*/public_html" FIM_STATE="$S18/state" \
        FIM_LOG="$S18/fim.log" FIM_CRITLOG="$S18/crit.log" FIM_NEW_MIN_N=3 \
        RCLI_OUT="$S18/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" \
          bash "$HERE/fim.sh" "$@" >/dev/null 2>&1; echo $?; }
bac18() { grep -E "NEW .*$1" "$S18/fim.log" 2>/dev/null | tail -1 | awk '{print $1}'; }
gom18() { grep -cE "NEW +[0-9]+ file trong .*temp/caches/7" "$S18/fim.log" 2>/dev/null; }

r18 baseline >/dev/null
# Ba luot, moi luot MOT tep moi ten KHAC — thu muc chua dat nguong gom (gmax=5 mac dinh).
for i in 1 2 3; do
    sleep 0.02
    printf '<?php\n// cache %s\n' "$i" > "$W18/temp/caches/7/article_$i.php"
    r18 check >/dev/null
done
want "18 tep le luot 1 -> VAN HIGH (khong bi ha bac)" "$(bac18 'article_1\.php')" "HIGH"

# Luot 4: bo dem da ghi 3 tep -> `gmax` ha xuong 2. Tha BA tep mot luot -> GOM.
sleep 0.02
for i in 4 5 6; do printf '<?php\n// c %s\n' "$i" > "$W18/temp/caches/7/article_$i.php"; done
rc18=$(r18 check)
want "18 dot tep trong thu muc dat nguong -> MOT dong gom" \
     "$([ "$(gom18)" -ge 1 ] && echo co || echo khong)" "co"
# BAC GIU NGUYEN tren dong gom — day la diem phan biet voi ban ha bac.
got18=$(grep -E "NEW +[0-9]+ file trong .*temp/caches/7" "$S18/fim.log" | tail -1 | awk '{print $1}')
want "18 dong gom GIU bac HIGH (khong thanh STATE)" "$got18" "HIGH"
# Va `crit` van dem -> ma thoat 1, mail van gui. Ban ha bac cho `exit 0`.
want "18 dot tep VAN tra ma thoat 1 (crit dem)" "$rc18" "1"

# Mot tep LE trong thu muc da dat nguong VAN in rieng: `gmax` = 2, khong phai 1.
sleep 0.02
printf '<?php\n// le\n' > "$W18/temp/caches/7/article_le.php"
r18 check >/dev/null
want "18 mot tep LE van in RIENG" "$(bac18 'article_le\.php')" "HIGH"
# `gmax` = 2, khong phai 1: DUNG HAI tep mot luot van phai in RIENG, vi hai tep la
# hinh dang KHAC voi mot dot cache (cache sinh hang chuc tep moi lot — do 01-10:
# 89 tep/gio tren 171-96). Ca "mot tep le" o tren KHONG phan biet duoc `gmax` 1 hay 2
# (`1 > 1` va `1 > 2` deu false), nen phai co ca HAI tep.
sleep 0.02
printf '<?php\n// h1\n' > "$W18/temp/caches/7/hai_1.php"
printf '<?php\n// h2\n' > "$W18/temp/caches/7/hai_2.php"
r18 check >/dev/null
want "18 DUNG HAI tep van in RIENG (gmax=2, khong phai 1)" "$(bac18 'hai_2\.php')" "HIGH"

# `uploads/` KHONG bao gio duoc ha nguong gom, DU thu muc do da dat nguong: mot DOT
# tep vao do la NANG HON mot tep le, khong nhe hon (chinh hinh dang vu 20-09, 13 tep
# tren mot site). Phai cho `uploads/u` DAT nguong truoc — khong thi ca nay khong phan
# biet duoc (dot bien bo phep loai tru di qua, do 01-10).
for i in 1 2 3; do
    sleep 0.02
    printf '<?php\n// up %s\n' "$i" > "$W18/wp-content/uploads/u/p_$i.php"
    r18 check >/dev/null
done
# Gio `uploads/u` da co 3 tep trong bo dem = dat nguong `FIM_NEW_MIN_N=3`.
sleep 0.02
for i in 1 2 3 4 5; do printf '<?php\n// u %s\n' "$i" > "$W18/wp-content/uploads/u/f_$i.php"; done
r18 check >/dev/null
want "18 uploads/ giu bac CRITICAL" "$(bac18 'f_5\.php')" "CRITICAL"
# Va no KHONG bi gom, du bo dem da dat nguong.
nup=$(grep -cE "NEW +[0-9]+ file trong .*uploads/u" "$S18/fim.log" 2>/dev/null); nup=${nup:-0}
want "18 uploads/ KHONG bi gom thanh mot dong (du dat nguong)" "$nup" "0"
want "18 uploads/ in tung tep" \
     "$(grep -cE "NEW .*uploads/u/f_[0-9]+\.php" "$S18/fim.log" 2>/dev/null | tr -d '\n')" "5"

# NGUONG MAC DINH phai la 30. Bo test dung `FIM_NEW_MIN_N=3` cho nhanh, nen gia tri
# mac dinh KHONG duoc thu o dau — mot dot bien doi `30` thanh `1` khong bi bat.
ndef=$(grep -oE 'FIM_NEW_MIN_N:-[0-9]+' "$HERE/fim.sh" | head -1 | sed 's/.*-//')
want "18 nguong mac dinh la 30" "$ndef" "30"
want "18 nguong nam tren 5 (mot lan tha tep khong dat)" \
     "$([ "${ndef:-0}" -gt 5 ] && echo dung || echo "qua thap: $ndef")" "dung"
want "18 nguong nam duoi 311 (thu muc cache thap nhat van dat)" \
     "$([ "${ndef:-999}" -lt 311 ] && echo dung || echo "qua cao: $ndef")" "dung"
wdef=$(grep -oE 'FIM_CHG_WINDOW_DAYS:-[0-9]+' "$HERE/fim.sh" | head -1 | sed 's/.*-//')
want "18 dung chung cua so 21 ngay voi CHGCOUNT" "$wdef" "21"

# ── NHOM 22: khoa TRANG THAI — mot khoa moi thu muc CO tep cau hinh ───
#
# KE THUA KHONG o day nua. Ban 6e0a607 vat chat hoa khoa cho tung thu muc con, va so
# lieu tu 171-96 (01-10) bac bo no: 737/737 khoa cua mot site co gia tri Y HET NHAU,
# `check` 49s -> 5 phut 23, 5.490 khoa cho 11 thu muc cau hinh, va no VAN khong phu
# duoc `uploads/a.jpg` (manifest chi liet ke duoi PHP). Nay ke thua lam o BEN DOC —
# `init.lua` tra chuoi to tien bang mot `MGET`, va nhom do o `policy_test.lua`.
#
# Nhom nay kiem phan con lai cua `fim.sh`: DUNG mot khoa cho moi thu muc co tep cau
# hinh, va RECONCILE — khoa cua generation truoc phai bi `DEL` khi khong con.
printf '\n── khoa trang thai + reconcile (muc 22) ──\n'
S22="$R/st22"
W22="$S22/home/u7/domains/s7.test/public_html"
mkdir -p "$W22/con/chau" "$S22/state"
printf '<?php\n' > "$W22/index.php"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W22/.htaccess"
printf '<?php\n' > "$W22/con/a.php"
printf '<?php\n' > "$W22/con/chau/a.php"

r22() { FIM_ROOTS="$S22/home/*/domains/*/public_html" FIM_STATE="$S22/state" \
        FIM_LOG="$S22/fim.log" FIM_CRITLOG="$S22/crit.log" \
        RCLI_OUT="$S22/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" \
          bash "$HERE/fim.sh" "$@" >/dev/null 2>&1 || true; }
# TAB, y nhu `kval`/`keys` o tren — stub ghi `SETEX\t<key>\t<ttl>\t<value>`.
v22() { awk -F'\t' -v k="waf:fimchg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S22/rcli.txt" 2>/dev/null; }
k22() { local n; n=$(grep -cP "^SETEX\twaf:fimchg:" "$S22/rcli.txt" 2>/dev/null); echo "${n:-0}"; }
d22() { grep -cP "^DEL\twaf:fimchg:\Q$1\E$" "$S22/rcli.txt" 2>/dev/null | tr -d '\n'; }

r22 baseline
: > "$S22/rcli.txt"
r22 check
want "22 webroot co khoa"                "$(v22 "$W22/")"     "ext:jpg"
want "22 DUNG mot khoa, khong vat chat hoa thu muc con" "$(k22)" "1"
want "22 thu muc con KHONG co khoa rieng" "$(v22 "$W22/con/")" ""

# RECONCILE: bo `.htaccess` thi khoa cu phai bi `DEL`, khong de song het TTL 7 ngay.
# Ban truoc chi sinh `SETEX` nen khoa cu song mot tuan -> telemetry duong tinh GIA.
rm -f "$W22/.htaccess"
: > "$S22/rcli.txt"
r22 check
want "22 bo .htaccess -> khong ghi khoa moi" "$(v22 "$W22/")" ""
# `DEL` co the den tu HAI duong khi tep cau hinh bi XOA: nhanh `$dels` cu (no thay
# `.htaccess` mat) va reconcile moi (khoa khong con trong tap mong muon). Trung lap
# vo hai — `DEL` mot khoa hai lan cho cung ket qua — nen kiem ">= 1" chu khong "== 1".
#
# Ca THAT SU chi reconcile bat duoc la khi `.htaccess` VAN CON nhung khong con doi
# handler: nhanh `$dels` khong thay gi, con reconcile thi thay. Kiem ngay duoi.
want "22 bo .htaccess -> DEL khoa CU" \
     "$([ "$(d22 "$W22/")" -ge 1 ] && echo co || echo khong)" "co"
: > "$S22/rcli.txt"
r22 check
want "22 lot sau KHONG DEL lai" "$(d22 "$W22/")" "0"

# CA RIENG CUA RECONCILE: `.htaccess` VAN CON tren dia nhung khong con doi handler.
# Nhanh `$dels` khong thay gi (tep khong bi xoa), nhanh `$chgs` thay CHG nhung
# `dir_tokens` tra rong nen no `DEL` — va day la cho hai duong co the lech. Kiem rang
# khoa KHONG con, bang duong nao cung duoc.
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W22/.htaccess"
r22 baseline
: > "$S22/rcli.txt"; r22 check
want "22 dat lai .htaccess -> co khoa" "$(v22 "$W22/")" "ext:jpg"
sleep 0.02
printf '# BEGIN WordPress\nRewriteEngine On\n' > "$W22/.htaccess"
: > "$S22/rcli.txt"; r22 check
want "22 .htaccess CON nhung het token -> khoa bi go" \
     "$([ "$(d22 "$W22/")" -ge 1 ] && echo co || echo khong)" "co"
want "22 va KHONG ghi khoa moi" "$(v22 "$W22/")" ""

# BEN GHI chi ghi TRANG THAI CUC BO, KHONG merge to tien. Merge o CA HAI ben la trung
# lap, va do duoc 01-10 tren 171-96: `statekeys.full.txt` ra 526 dong thay vi 11 — moi
# thu muc cau hinh nam duoi mot webroot co `AddHandler` deu thua huong token roi duoc
# ghi khoa, va `check` van 1m25 thay vi ve 49s.
mkdir -p "$W22/duoi"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W22/.htaccess"
printf '# BEGIN WordPress\nRewriteEngine On\n' > "$W22/duoi/.htaccess"
printf '<?php\n' > "$W22/duoi/a.php"
r22 baseline
: > "$S22/rcli.txt"; r22 check
want "22 webroot co khoa (cuc bo)"        "$(v22 "$W22/")"      "ext:jpg"
want "22 thu muc duoi: .htaccess LANH -> KHONG khoa (khong merge)" "$(v22 "$W22/duoi/")" ""
want "22 DUNG mot khoa cho ca cay"        "$(k22)"              "1"
# Va `statekeys` phai co DUNG mot dong — day la cho 526-vs-11 lo ra.
want "22 statekeys co DUNG mot dong" \
     "$(wc -l < "$S22/state/statekeys.full.txt" 2>/dev/null | tr -d ' ')" "1"

# THU TU: chuyen generation CHI SAU khi ca hai batch xong. Neu chuyen TRUOC roi `DEL`
# that bai, ban ghi noi "da xoa" trong khi khoa VAN SONG — va lot sau khong con biet
# de thu lai. Kiem bang cach lam Redis chet DUNG luc co khoa can xoa.
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W22/.htaccess"
r22 baseline
: > "$S22/rcli.txt"; r22 check
sk_truoc=$(cat "$S22/state/statekeys.full.txt" 2>/dev/null)
rm -f "$W22/.htaccess"
# Redis CHET: `DEL` khong chay duoc.
FIM_ROOTS="$S22/home/*/domains/*/public_html" FIM_STATE="$S22/state" \
  FIM_LOG="$S22/fim.log" FIM_CRITLOG="$S22/crit.log" \
  RCLI_OUT="$S22/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" RCLI_MODE=down \
    bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
sk_sau=$(cat "$S22/state/statekeys.full.txt" 2>/dev/null)
want "22 Redis chet luc DEL -> generation KHONG chuyen" \
     "$([ "$sk_truoc" = "$sk_sau" ] && echo "giu" || echo "da chuyen OAN")" "giu"

# ══ 23. RESP + dem reply loi ════════════════════════════════════════
#
# BA bat bien, va chung la ly do `redis_send_resp` ton tai:
#
#   1. DUONG DAN CO KHOANG TRANG van danh dau duoc. Ban inline protocol dua khoa qua
#      STDIN noi khoang trang la RANH GIOI DOI SO, nen `SETEX waf:fimchg:/a b/ 604800
#      ext:php` thanh 5 doi so -> Redis tu choi. `gen_cmds` cu chon duong LOC, tuc BO
#      KHONG DANH DAU thu muc do (chi hien o stderr) — mot thu muc co that khong duoc
#      bao ve. Do tren 171-96 01-10: 0 thu muc cau hinh co khoang trang HOM NAY, nhung
#      khach tao duoc ten nhu vay bat ky luc nao.
#
#   2. MOT LENH BI TU CHOI phai lam `state_marks` bao loi. Canary o CUOI batch chi
#      chung minh KET NOI song va batch DA CHAY — no KHONG chung minh TUNG lenh thanh
#      cong. Day la ca ma dot bien BA (bo phep doc `errors:`) di qua duoc khi nhom nay
#      chua ton tai.
#
#   3. Generation KHONG duoc chuyen khi co lenh bi tu choi — khong thi `statekeys` noi
#      "da ghi" cho mot khoa khong ton tai, va lot sau khong con biet de thu lai.
printf '\n── RESP: khoang trang + reply loi (muc 23) ──\n'
S23="$R/s23"; mkdir -p "$S23/state"
W23="$S23/home/u1/domains/sp.test/public_html"
mkdir -p "$W23/co khoang trang"
r23() { FIM_ROOTS="$S23/home/*/domains/*/public_html" FIM_STATE="$S23/state" \
        FIM_LOG="$S23/fim.log" FIM_CRITLOG="$S23/crit.log" \
        RCLI_OUT="$S23/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" \
          bash "$HERE/fim.sh" "$@" >/dev/null 2>&1; }
v23() { awk -F'\t' -v k="waf:fimchg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S23/rcli.txt" 2>/dev/null; }

printf 'AddHandler application/x-httpd-php .jpg\n' > "$W23/co khoang trang/.htaccess"
r23 baseline
: > "$S23/rcli.txt"; r23 check
# Bat bien 1: duong dan co khoang trang DUOC danh dau, khong bi bo.
want "23 thu muc co KHOANG TRANG van co khoa" \
     "$(v23 "$W23/co khoang trang/")" "ext:jpg"
# Khoa phai den NGUYEN VEN, khong bi cat o khoang trang.
want "23 khoa khong bi cat o khoang trang" \
     "$(grep -cP "^SETEX\twaf:fimchg:\Q$W23/co khoang trang/\E\t" "$S23/rcli.txt")" "1"

# Bat bien 2: Redis TU CHOI mot lenh (canary VAN song) -> phai bao loi.
printf 'AddHandler application/x-httpd-php .png\n' > "$W23/co khoang trang/.htaccess"
: > "$S23/rcli.txt"
out23=$(FIM_ROOTS="$S23/home/*/domains/*/public_html" FIM_STATE="$S23/state" \
        FIM_LOG="$S23/fim.log" FIM_CRITLOG="$S23/crit.log" \
        RCLI_OUT="$S23/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" RCLI_ERRN=1 \
          bash "$HERE/fim.sh" check 2>&1); rc23=$?
want "23 mot lenh bi TU CHOI -> fim bao loi (khong im lang)" \
     "$(printf '%s' "$out23" | grep -ciE 'TU CHOI|KHONG GHI DUOC|KHONG GO DUOC' | tr -d '\n')" "1"
want "23 va ma thoat KHONG phai 0" \
     "$([ "$rc23" -ne 0 ] && echo khac0 || echo 0)" "khac0"

# Bat bien 3: generation KHONG chuyen khi co lenh bi tu choi.
: > "$S23/rcli.txt"; r23 check || true          # lot sach -> generation hop le
sk23_truoc=$(cat "$S23/state/statekeys.full.txt" 2>/dev/null)
printf 'AddHandler application/x-httpd-php .gif\n' > "$W23/co khoang trang/.htaccess"
: > "$S23/rcli.txt"
FIM_ROOTS="$S23/home/*/domains/*/public_html" FIM_STATE="$S23/state" \
  FIM_LOG="$S23/fim.log" FIM_CRITLOG="$S23/crit.log" \
  RCLI_OUT="$S23/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" RCLI_ERRN=1 \
    bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
sk23_sau=$(cat "$S23/state/statekeys.full.txt" 2>/dev/null)
want "23 lenh bi tu choi -> generation KHONG chuyen" \
     "$([ "$sk23_truoc" = "$sk23_sau" ] && echo giu || echo "da chuyen OAN")" "giu"

# ══ 24. MAT MOT KHOA GIUA batch — ba cua deu khong bat duoc ══════════
#
# Ca: mot lenh DEN DUOC server, duoc dem vao `replies`, nhung KHONG duoc thuc thi va
# server KHONG bao loi. Ba phep kiem hien co deu di qua:
#   · canary la lenh CUOI -> van song
#   · `errors: 0`
#   · `replies` = want+1 (Redis dem CA lenh bi tu choi; do tren 171-96 01-10:
#     `errors: 1, replies: 3` cho 3 lenh voi 1 lenh bi tu choi)
# Nen phai DEM lai tap vua ghi. `head -1` khong du: khoa bi mat la khoa thu 2.
#
# `RCLI_SKIP=<k>` mo phong dung ca do.
printf '\n── mat khoa giua batch (muc 24) ──\n'
S24="$R/s24"; mkdir -p "$S24/state"
W24="$S24/home/u1/domains/mk.test/public_html"
mkdir -p "$W24/a" "$W24/b" "$W24/c"
for dd in a b c; do printf 'AddHandler application/x-httpd-php .jpg\n' > "$W24/$dd/.htaccess"; done
r24() { FIM_ROOTS="$S24/home/*/domains/*/public_html" FIM_STATE="$S24/state" \
        FIM_LOG="$S24/fim.log" FIM_CRITLOG="$S24/crit.log" \
        RCLI_OUT="$S24/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" "$@"; }
r24 bash "$HERE/fim.sh" baseline >/dev/null 2>&1

# Doi chung: khong doi gi -> di qua `state_marks`, ba khoa trang thai, KHONG loi.
: > "$S24/rcli.txt"
o24=$(r24 bash "$HERE/fim.sh" check 2>&1); rc24=$?
want "24 doi chung: 3 khoa trang thai, khong loi" \
     "$(grep -cP '^SETEX\twaf:fimchg:' "$S24/rcli.txt")" "3"
want "24 doi chung: ma thoat 0" "$rc24" "0"

# Ca that: mat khoa thu 2.
: > "$S24/rcli.txt"
o24b=$(RCLI_SKIP=2 r24 bash "$HERE/fim.sh" check 2>&1); rc24b=$?
want "24 chi 2/3 khoa duoc ghi -> PHAI bao loi" \
     "$(printf '%s' "$o24b" | grep -c 'KHONG XAC MINH DUOC (fimchg trang thai)')" "1"
want "24 va ma thoat = 2 (khong do duoc)" "$rc24b" "2"
# Generation KHONG duoc chuyen: lot sau phai con biet de thu lai.
want "24 generation KHONG chuyen khi thieu khoa" \
     "$(wc -l < "$S24/state/statekeys.full.txt" 2>/dev/null | tr -d ' ')" "3"
# may khong co Apache o duong quen IM LANG toan bo tin hieu ExecCGI.
printf '\n── detect_execcgi_ok: doc AllowOverride (muc 16) ──\n'
AO="$R/ao"; mkdir -p "$AO/u1" "$AO/extra"
eok() {  # eok <ten> <mong>
    g=$(FIM_DA_HTTPD="$AO" FIM_APACHE_EXTRA="$AO/extra" \
        bash -c 'DA_HTTPD="$FIM_DA_HTTPD"; APACHE_EXTRA="$FIM_APACHE_EXTRA"
                 '"$(sed -n "/^detect_execcgi_ok() {/,/^}/p" "$HERE/fim.sh")"'
                 detect_execcgi_ok' 2>/dev/null)
    want "$1" "${g:-LOI}" "$2"
}
# Dang THAT cua DirectAdmin: whitelist KHONG co ExecCGI -> 0
printf 'AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,IncludesNOEXEC,MultiViews,SymLinksIfOwnerMatch,FollowSymLinks,None\n' \
  > "$AO/u1/httpd.conf"
eok "16 whitelist KHONG co ExecCGI -> 0" "0"
# Whitelist CO ExecCGI -> 1
printf 'AllowOverride FileInfo Options=Indexes,ExecCGI,MultiViews\n' > "$AO/u1/httpd.conf"
eok "16 whitelist CO ExecCGI -> 1" "1"
# `AllowOverride All` -> 1
printf 'AllowOverride All\n' > "$AO/u1/httpd.conf"
eok "16 AllowOverride All -> 1" "1"
# `Options` tran (khong dau `=`) = cho tat -> 1
printf 'AllowOverride FileInfo Options\n' > "$AO/u1/httpd.conf"
eok "16 Options tran -> 1" "1"
# KHONG co dong nao (khong do duoc) -> 1, MAC DINH AN TOAN
printf 'ServerName x.test\n' > "$AO/u1/httpd.conf"
eok "16 khong co AllowOverride -> 1 (mac dinh an toan)" "1"
# KHONG co tep nao -> 1
rm -f "$AO/u1/httpd.conf"
eok "16 khong co tep cau hinh -> 1 (mac dinh an toan)" "1"
# MOT dong cho, MOT dong khong -> 1 (co cho o dau do la du)
mkdir -p "$AO/u2"
printf 'AllowOverride FileInfo Options=Indexes,None\n' > "$AO/u1/httpd.conf"
printf 'AllowOverride All\n' > "$AO/u2/httpd.conf"
eok "16 mot dong cho, mot dong khong -> 1" "1"
# CA HAI khong cho -> 0
printf 'AllowOverride FileInfo Options=Indexes,None\n' > "$AO/u2/httpd.conf"
eok "16 ca hai KHONG cho -> 0" "0"
# `None` khong duoc doc thanh `All` chi vi chua chu... kiem chuoi khong khop nham
printf 'AllowOverride None\n' > "$AO/u1/httpd.conf"
printf 'AllowOverride None\n' > "$AO/u2/httpd.conf"
eok "16 AllowOverride None -> 0" "0"
printf '\n── wpinv: ghi that bai + khoa cu con song (muc 15) ──\n'
DA="$R/da"
mkdir -p "$DA/u1/domains" "$WEB/wp-content"
printf 'site.test\n' > "$DA/u1/domains.list"
# `wp-settings.php` la dau nhan WP cua `wpinv` (dong bo voi nhanh `check`).
printf '<?php\n' > "$WEB/wp-settings.php"

# rcli GIA: GHI (doc lenh tu STDIN) that bai; DOC (`GET` tren dong lenh) tra "1".
cat > "$R/bin/rcli_stale" <<'RC'
#!/bin/bash
for a in "$@"; do
    if [ "$a" = "GET" ]; then echo 1; exit 0; fi
done
cat >/dev/null 2>&1
echo "Could not connect to Redis" >&2
exit 1
RC
chmod +x "$R/bin/rcli_stale"

out15=$(FIM_REDIS_CLI="$R/bin/rcli_stale" FIM_DA_DATA="$DA" FIM_HOME="$R/home" \
        bash "$HERE/fim.sh" wpinv 2>&1)
rc15=$?
case "$out15" in
    *"KHONG GHI DUOC"*) want "15 ghi that bai -> BAO 'KHONG GHI DUOC'" "dung" "dung" ;;
    *"KHONG XAC MINH DUOC"*) want "15 ghi that bai -> BAO 'KHONG GHI DUOC'" "sai-huong-doc" "dung" ;;
    *) want "15 ghi that bai -> BAO 'KHONG GHI DUOC'" "IM LANG: $out15" "dung" ;;
esac
# `exit 2` = KHONG DO DUOC, khac `exit 1` (co phat hien) va `exit 3` (ton dong).
want "15 ghi that bai -> ma thoat DUNG BANG 2" "$rc15" "2"

# HUONG NGUOC: rcli that su chay duoc thi `wpinv` phai THANH CONG. Thieu ca nay thi
# mot ban "luon exit 2" cung qua.
out15b=$(FIM_DA_DATA="$DA" FIM_HOME="$R/home" bash "$HERE/fim.sh" wpinv 2>&1)
rc15b=$?
want "15 rcli chay duoc -> ma thoat 0" "$rc15b" "0"
case "$out15b" in
    *"khoa da ghi"*) want "15 rcli chay duoc -> co ghi khoa" "co" "co" ;;
    *) want "15 rcli chay duoc -> co ghi khoa" "khong: $out15b" "co" ;;
esac
rm -rf "$S"
printf '\nfim_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
