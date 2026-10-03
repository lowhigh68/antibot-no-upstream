#!/bin/bash

# fim_test.sh — kiem nhanh "TEP CAU HINH bi SUA" cua fim.sh (roadmap muc 8).
#
# VI SAO CAN, va vi sao bay gio: `fim.sh` quyet dinh cai gi DEN DUOC WAF, va truoc
# hom nay no khong co mot phep kiem nao. Muc 8 them mot nhom thu hai
# (`waf:fimcfg:`) vao dung cho do. Mot loi o day KHONG bao gi — no chi lam mot
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
        EXISTS)
             # `EXISTS` nhan NHIEU doi so va tra TONG so khoa ton tai (Redis 3.0+).
             # `count_live` dua ca lo qua DONG LENH — mot phan tu mang giu nguyen
             # khoang trang. Do tren Redis that: `EXISTS k1 'a b/' k2` tra `2`.
             shift
             nex=0
             for kk in "$@"; do
                 if [ "${EX_STUCK:-0}" = 1 ]; then
                     nex=$((nex + 1)); continue
                 fi
                 h=$(awk -F'\t' -v k="$kk" '
                     $1=="SETEX" && $2==k { has=1 }
                     $1=="DEL"   && $2==k { has=0 }
                     END { print (has ? 1 : 0) }' "$RCLI_OUT")
                 nex=$((nex + h))
             done
             echo "$nex"
             exit 0 ;;
        DEL) printf 'DEL\t%s\n' "$2" >> "$RCLI_OUT"; echo 1; exit 0 ;;
        *) shift ;;
    esac
done

# ── RESP CHI duoc giai ma khi co `--pipe` ───────────────────────────
#
# `redis-cli` THAT o che do THUONG doc stdin theo kieu INLINE, nen mot tep RESP cho
# `ERR unknown command '*4'`. Do tren Redis 6.0.16 that (02-10). Ban truoc cua stub
# nay giai ma RESP o MOI che do, nen `count_live` gui RESP qua stdin khong kem
# `--pipe` van CHAY TRONG TEST va chi hong tren production — stub NOI DOI.
#
# Mo phong dung: khong `--pipe` thi bao loi y nhu Redis that.
if [ "$pipe" != 1 ]; then
    nerr=0
    while IFS= read -r l; do
        l=${l%$'\r'}
        [ -n "$l" ] || continue
        echo "ERR unknown command \`${l%% *}\`, with args beginning with: " >&2
        nerr=$((nerr + 1))
    done
    [ "$nerr" -gt 0 ] && exit 1
    exit 0
fi

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
    # `RCLI_TRUNC=<k>` = chi THUC THI k lenh dau roi DUNG, va bao `replies: k` — dung nhu
    # `--pipe` khi tep RESP bi CAT GIUA LENH. Do tren Redis THAT (6.0.16, 02-10):
    #     tep 135 byte / 3 lenh, cat o 2/3  ->  errors: 0, replies: 2, rc=0, 2/3 khoa
    #     cat ngay sau lenh 1               ->  errors: 0, replies: 1,        1/3 khoa
    # Tuc `--pipe` tra rc=0 va `errors: 0` — KHONG dau hieu loi nao — ma mot phan batch
    # MAT. Chi phep so `replies` voi `want+1` bat duoc, va day la ca dot bien CC nham vao.
    #
    # Khac `RCLI_SKIP`: `SKIP` la "lenh den duoc server, VAO replies, nhung khong thuc
    # thi" (replies KHOP, `count_live` bat); `TRUNC` la "lenh KHONG den duoc server"
    # (replies LECH). Hai ca khac nhau, hai phep kiem khac nhau.
    if [ -n "${RCLI_TRUNC:-}" ] && [ "$n_cmd" -ge "$RCLI_TRUNC" ]; then
        # `n_cmd` DA tang cho lenh thu k truoc khi vao day, nen lui lai: tep bi cat
        # GIUA lenh k thi lenh do khong den duoc server, va `replies` = k-1.
        n_cmd=$((n_cmd - 1))
        break
    fi
    if [ -n "${RCLI_SKIP:-}" ] && [ "$n_cmd" = "$RCLI_SKIP" ]; then
        continue
    fi
    case "${args[0]}" in
        SETEX)
            if [ "${#args[@]}" -ne 4 ]; then n_err=$((n_err + 1)); continue; fi
            printf 'SETEX\t%s\t%s\t%s\n' "${args[1]}" "${args[2]}" "${args[3]}" >> "$RCLI_OUT" ;;
        DEL)
            printf 'DEL\t%s\n' "${args[1]}" >> "$RCLI_OUT" ;;
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
# `kval`/`kval1` CAT MOC `v2,` truoc khi tra: moc la chi tiet VAN CHUYEN (cho
# `init.lua` biet doc luat nao), khong phai noi dung ma cac ca nay do. Giu no trong
# moi ky vong se lam 21 ca nhieu chu hon ma khong them mot rang buoc nao.
#
# Moc duoc kiem RIENG o nhom "moc phien ban" ben duoi — mot cho, co chu dich.
strip_ver() { sed 's/^v2,//; s/^v2$//'; }
kval() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$RCLI_OUT" | strip_ver; }
kttl() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {v=$3} END{print v}' "$RCLI_OUT"; }
# Lan ghi DAU, cho cac ca xet thu tu.
kval1() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {print $4; exit}' "$RCLI_OUT" | strip_ver; }
# GIA TRI THO, co moc — cho cac ca kiem chinh moc.
kval_raw() { awk -F'\t' -v k="$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$RCLI_OUT"; }

echo "fim_test: tep cau hinh bi SUA -> waf:fimcfg:"

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
want "2 fimchg theo THU MUC" "$(haskey "waf:fimcfg:$WEB/")" "yes"
want "2 KHONG con khoa theo TEP" "$(haskey "waf:fimcfg:$WEB/.htaccess")" "no"
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
     "$([ "$(keys 'waf:fimcfg:')" -le 3 ] && echo "trong tam" || echo "qua nhieu: $(keys 'waf:fimcfg:')")" "trong tam"
# GIA TRI la duoi bi anh xa — day la thong tin ma ban truoc khong co.
want "2 gia tri la duoi bi anh xa" \
     "$(kval "waf:fimcfg:$WEB/")" "t+:jpg"
want "2 TTL dung" \
     "$(kttl "waf:fimcfg:$WEB/")" "604800"

# Nhieu duoi, va CHI duoi cua directive ANH XA duoc tinh: `AddType text/plain .txt`
# khong duoc vao danh sach (do la FP loi 6 da sua o `upload_content.lua`).
: > "$RCLI_OUT"
sleep 0.02
printf 'AddType application/x-httpd-lsphp .jpg .png\nAddType text/plain .txt\n' \
    > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
got=$(kval "waf:fimcfg:$WEB/")
want "2b hai duoi duoc anh xa" "$got" "t+:jpg,t+:png"
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
got=$(kval "waf:fimcfg:$WEB/")
want "2c ten .@all -> ext:@all, KHONG phai @all" "$got" "h+:@all"
# Bien the: ten trung ca bon co.
: > "$RCLI_OUT"
sleep 0.02
printf 'AddHandler application/x-httpd-php .@php .@phpini .@execcgi\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c ba ten trung co deu co tien to" \
     "$(kval "waf:fimcfg:$WEB/")" \
     "h+:@execcgi,h+:@php,h+:@phpini"
# Huong NGUOC: `SetHandler` van phai ra `@all` THAT (phep sua khong lam mat nghia).
: > "$RCLI_OUT"
sleep 0.02
printf 'SetHandler application/x-httpd-php\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "2c SetHandler van la @all THAT" \
     "$(kval "waf:fimcfg:$WEB/")" "@sh+"
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
     "$(kval "waf:fimcfg:$WEB/")" "t+:jpg,t+:png"

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
want "4 .user.ini SUA -> fimchg" "$(haskey "waf:fimcfg:$WEB/")" "yes"
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
     "$(kval "waf:fimcfg:$WEB/")" "t+:jpg,t+:png,@php"

# Chong FP: mot `.user.ini` bi sua ma KHONG co autoload -> khong duoc bao.
: > "$RCLI_OUT"
sleep 0.02
printf 'memory_limit=256M\nupload_max_filesize=8M\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
# KHONG con la "im": khoa mo ta CA THU MUC, va `.htaccess` tu buoc 2b van tren dia
# nen khoa van phai co `jpg,png`. Dieu phai kiem la KHONG co `@php` — tuc mot
# `.user.ini` khong autoload thi khong gop tin hieu autoload vao.
val4b=$(kval "waf:fimcfg:$WEB/")
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
val4c=$(kval "waf:fimcfg:$WEB/")
want "4c autoload rong/none -> PHU DINH tuong minh, khong phai im lang" \
     "$(case ",$val4c," in *,-@php,*) echo "phu-dinh" ;; *,@php,*) echo "BAT" ;; *) echo "im-lang" ;; esac)" \
     "phu-dinh"

# ══ 5. File THUONG bi sua -> KHONG nhom nao ═════════════════════════════════
#
# Chong FP cua ca muc 8: `index.php` bi sua la mot `CHG` binh thuong (cap nhat
# phan mem), va no KHONG duoc vao `fimchg` — nhom do CHI danh cho tep cau hinh.
: > "$RCLI_OUT"
sleep 0.02
printf 'index.php\n// sua\n' > "$WEB/index.php"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "5 index.php sua: khong fimchg" "$(keys 'waf:fimcfg:')" "0"

# ══ 6. `--dry` KHONG duoc ghi Redis ═════════════════════════════════════════
: > "$RCLI_OUT"
sleep 0.02
printf 'RewriteEngine On\nAddHandler x-httpd-lsphp .png\n' > "$WEB/.htaccess"
bash "$HERE/fim.sh" check --dry >/dev/null 2>&1 || true
want "6 --dry khong ghi gi" "$(wc -l < "$RCLI_OUT")" "0"

# Va khong-dry ngay sau do THI ghi — de chac muc 6 xanh vi `--dry`, khong phai vi
# thay doi da bi tieu thu mat.
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "6 khong-dry thi ghi" "$(haskey "waf:fimcfg:$WEB/")" "yes"



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
want "8 .htaccess MOI -> fimchg" "$(haskey "waf:fimcfg:$WEB/")" "yes"
want "8 gia tri dung" \
     "$(kval1 "waf:fimcfg:$WEB/")" "h+:jpg"

# `.user.ini` MOI co autoload -> PHAI co fimchg (gia tri `*`).
: > "$RCLI_OUT"
sleep 0.02
printf 'auto_prepend_file=/tmp/x.php\n' > "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "8 .user.ini MOI co autoload -> fimchg" "$(haskey "waf:fimcfg:$WEB/")" "yes"

# BI XOA -> phai phat DEL, khong de khoa song het TTL.
: > "$RCLI_OUT"
sleep 0.02
rm -f "$WEB/.htaccess" "$WEB/.user.ini"
bash "$HERE/fim.sh" check >/dev/null 2>&1 || true
want "8 tep cau hinh bi XOA -> DEL khoa" \
     "$(grep -cP "^DEL\twaf:fimcfg:\Q$WEB/\E$" "$RCLI_OUT")" "1"
want "8 va KHONG dat lai SETEX fimchg" "$(keys 'waf:fimcfg:')" "0"

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
want "9 php.ini SUA co autoload -> fimchg" "$(haskey "waf:fimcfg:$WEB/")" "yes"
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
    awk -v k="waf:fimcfg:$SW/" '
        $1 == "SETEX" && $2 == k { v = $4 }
        $1 == "DEL"   && $2 == k { v = "(DA XOA)" }
        END { print (v == "" ? "(khong co)" : v) }' "$SOUT" | strip_ver
}
run_state baseline

sleep 0.02; printf 'AddHandler application/x-httpd-lsphp .jpg\n' > "$SW/.htaccess"
run_state check
want "10 B1 .htaccess -> ext:jpg" "$(final_val)" "h+:jpg"

# THEM `.user.ini`. `.htaccess` KHONG doi, nen ban cu mat dau vet cua no.
sleep 0.02; printf 'auto_prepend_file=/tmp/x.php\n' > "$SW/.user.ini"
run_state check
want "10 B2 hai tep -> GIU ca hai" "$(final_val)" "h+:jpg,@php"

# XOA `.user.ini`. `.htaccess` nguy hiem VAN CON -> phai SETEX lai, KHONG duoc DEL.
sleep 0.02; rm -f "$SW/.user.ini"
run_state check
want "10 B3 xoa .user.ini -> quay ve ext:jpg (KHONG xoa khoa)" "$(final_val)" "h+:jpg"

# XOA luon `.htaccess`: gio thu muc thuc su sach -> MOI duoc DEL.
sleep 0.02; rm -f "$SW/.htaccess"
run_state check
want "10 B4 xoa het -> DA XOA khoa" "$(final_val)" "(DA XOA)"

# Cau hinh doi tu NGUY HIEM thanh AN TOAN ma tep VAN TON TAI: ban cu khong sinh
# SETEX moi va cung khong DEL, nen khoa nguy hiem cu song tiep het TTL.
sleep 0.02; printf 'AddHandler application/x-httpd-lsphp .jpg\n' > "$SW/.htaccess"
run_state check
want "10 B5 dat lai -> ext:jpg" "$(final_val)" "h+:jpg"
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
    *"VAN CON: waf:fimcfg:"*)            want "13B DEL that bai -> bao ten khoa" "co-ten" "co-ten" ;;
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
k17()  { local n; n=$(grep -cP "^SETEX\twaf:fimcfg:" "$S17/rcli.txt" 2>/dev/null); echo "${n:-0}"; }
v17()  { awk -F'\t' -v k="waf:fimcfg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S17/rcli.txt" 2>/dev/null | strip_ver; }
nd17() { local n; n=$(grep -cP "^DEL\twaf:fimcfg:" "$S17/rcli.txt" 2>/dev/null); echo "${n:-0}"; }

r17 baseline
: > "$S17/rcli.txt"
# Lot `check` day du: KHONG co gi doi, nhung trang thai phai duoc bao.
r17 check
want "17 khong doi gi ma VAN co khoa fimchg" "$([ "$(k17)" -ge 1 ] && echo co || echo khong)" "co"
# BA nguon token, moi nguon mot nhan RIENG. Bo mot nguon khoi `config_dirs` phai do.
want "17 .htaccess -> ext:jpg"   "$(v17 "$W17/sub/")"  "h+:jpg"
want "17 .user.ini -> @php"      "$(v17 "$W17/ini/")"  "@php"
want "17 php.ini -> @phpini"     "$(v17 "$W17/pini/")" "@phpini"
# BON khoa: ba nguon BAT + `sach2` mang PHU DINH tuong minh.
#
# `sach2` chua `auto_prepend_file = none`. Truoc 03-10 no khong sinh khoa, vi parser
# INI chi tra MA THOAT nen "tat tuong minh" va "khong nhac gi" khong phan biet duoc.
# Nhung `none` LA mot phat bieu, va no can thiet khi mot thu muc CHA bat autoload —
# khong co no thi `-@php` khong rut lai duoc `@php` ke thua. Doi lai la mot khoa Redis
# cho moi thu muc co dong `none`; do tren 171-96 (03-10) de biet con so that.
want "17 dung 4 khoa (3 BAT + 1 phu dinh)" "$(k17)" "4"
want "17 sach1 khong co khoa" "$(v17 "$W17/sach1/")" ""
want "17 sach2 mang PHU DINH -@php" "$(v17 "$W17/sach2/")" "-@php"
want "17 sach3 khong co khoa" "$(v17 "$W17/sach3/")" ""
# KHONG `DEL` hang loat: nguon TRANG THAI khong sinh `DEL` cho thu muc khong token.
want "17 KHONG DEL thu muc sach" "$(nd17)" "0"

# HUONG NGUOC: bo tep cau hinh di thi khoa phai HET. Thieu ca nay thi mot ban
# "luon ghi moi thu muc" cung qua.
rm -f "$W17/sub/.htaccess"
: > "$S17/rcli.txt"
r17 check
want "17 bo .htaccess -> khong con ghi khoa cho thu muc do" "$(v17 "$W17/sub/")" ""
want "17 bo mot nguon -> con 3 khoa" "$(k17)" "3"

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
v22() { awk -F'\t' -v k="waf:fimcfg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S22/rcli.txt" 2>/dev/null | strip_ver; }
k22() { local n; n=$(grep -cP "^SETEX\twaf:fimcfg:" "$S22/rcli.txt" 2>/dev/null); echo "${n:-0}"; }
d22() { grep -cP "^DEL\twaf:fimcfg:\Q$1\E$" "$S22/rcli.txt" 2>/dev/null | tr -d '\n'; }

r22 baseline
: > "$S22/rcli.txt"
r22 check
want "22 webroot co khoa"                "$(v22 "$W22/")"     "h+:jpg"
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
want "22 dat lai .htaccess -> co khoa" "$(v22 "$W22/")" "h+:jpg"
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
want "22 webroot co khoa (cuc bo)"        "$(v22 "$W22/")"      "h+:jpg"
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
#      STDIN noi khoang trang la RANH GIOI DOI SO, nen `SETEX waf:fimcfg:/a b/ 604800
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
v23() { awk -F'\t' -v k="waf:fimcfg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S23/rcli.txt" 2>/dev/null | strip_ver; }

printf 'AddHandler application/x-httpd-php .jpg\n' > "$W23/co khoang trang/.htaccess"
r23 baseline
: > "$S23/rcli.txt"; r23 check
# Bat bien 1: duong dan co khoang trang DUOC danh dau, khong bi bo.
want "23 thu muc co KHOANG TRANG van co khoa" \
     "$(v23 "$W23/co khoang trang/")" "h+:jpg"
# Khoa phai den NGUYEN VEN, khong bi cat o khoang trang.
want "23 khoa khong bi cat o khoang trang" \
     "$(grep -cP "^SETEX\twaf:fimcfg:\Q$W23/co khoang trang/\E\t" "$S23/rcli.txt")" "1"

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
     "$(grep -cP '^SETEX\twaf:fimcfg:' "$S24/rcli.txt")" "3"
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

# NHANH DIRTY cung phai dem. Hai duong THOAT khac nhau cua cung mot lot quet, va
# `9296010` chi khep duong `state_marks` — do duoc trong cung buoi: ba `.htaccess`
# VUA DOI di qua nhanh dirty, va o do phep xac minh con la `head -1`, nen mat khoa
# thu 2 trong 3 VAN LOT (`rc=1`, khong ai bao loi).
: > "$S24/rcli.txt"
for dd in a b c; do printf 'AddHandler application/x-httpd-php .png\n' > "$W24/$dd/.htaccess"; done
o24c=$(r24 bash "$HERE/fim.sh" check 2>&1); rc24c=$?
want "24 dirty doi chung: 3 khoa, khong loi xac minh" \
     "$(printf '%s' "$o24c" | grep -c 'KHONG XAC MINH')" "0"
want "24 dirty doi chung: 3 khoa duoc ghi" \
     "$(grep -cP '^SETEX\twaf:fimcfg:' "$S24/rcli.txt")" "3"

: > "$S24/rcli.txt"
for dd in a b c; do printf 'AddHandler application/x-httpd-php .gif\n' > "$W24/$dd/.htaccess"; done
o24d=$(RCLI_SKIP=2 r24 bash "$HERE/fim.sh" check 2>&1); rc24d=$?
want "24 dirty: mat khoa thu 2 -> PHAI bao loi" \
     "$(printf '%s' "$o24d" | grep -c 'KHONG XAC MINH DUOC (fimchg)')" "1"
want "24 dirty: ma thoat = 2" "$rc24d" "2"

# ══ 25. BATCH BI CAT NGAN — `replies` la phep duy nhat bat duoc ══════
#
# Do tren Redis THAT (6.0.16, 02-10) sau khi WSL co `redis-cli`:
#     tep RESP 135 byte / 3 lenh, cat o 2/3  ->  errors: 0, replies: 2, rc=0, 2/3 khoa
#     cat ngay sau lenh 1                    ->  errors: 0, replies: 1,        1/3 khoa
# `--pipe` tra `rc=0` va `errors: 0` — KHONG dau hieu loi nao — ma mot phan batch MAT.
#
# PHAN BIET voi muc 24: o do lenh DEN DUOC server va VAO `replies` (nen `replies`
# khop, va `count_live` moi bat duoc); o day lenh KHONG den duoc server (`replies`
# LECH, va `count_live` cung bat — nhung `replies` bat SOM hon, truoc mot round-trip).
#
# Ca nay truoc 02-10 KHONG co test: stub cu doc het stdin nen khong gia lap duoc "dut
# giua duong" ma khong dong thoi mat canary. Dot bien CC di qua duoc.
printf '\n── batch bi cat ngan (muc 25) ──\n'
S25="$R/s25"; mkdir -p "$S25/state"
W25="$S25/home/u1/domains/ct.test/public_html"
mkdir -p "$W25/a" "$W25/b" "$W25/c"
for dd in a b c; do printf 'AddHandler application/x-httpd-php .jpg\n' > "$W25/$dd/.htaccess"; done
r25() { FIM_ROOTS="$S25/home/*/domains/*/public_html" FIM_STATE="$S25/state" \
        FIM_LOG="$S25/fim.log" FIM_CRITLOG="$S25/crit.log" \
        RCLI_OUT="$S25/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" "$@"; }
r25 bash "$HERE/fim.sh" baseline >/dev/null 2>&1

: > "$S25/rcli.txt"
o25=$(r25 bash "$HERE/fim.sh" check 2>&1); rc25=$?
want "25 doi chung: khong loi, ma thoat 0" "$rc25" "0"

# Cat GIUA lenh thu 2: chi lenh 1 den duoc server.
#
# PHAT HIEN KHI DO (02-10): canary la lenh CUOI, nen bat ky phep cat nao cung cat
# LUON canary -> `canary khong doc nguoc duoc` bat TRUOC phep so `replies`. Tuc ca
# "batch bi cat ngan" DA duoc canary bao ve, va `replies` la lop THU HAI.
#
# Toi giu phep so `replies` lai chu khong go, vi no bat duoc ca ma canary khong:
# `--pipe` gui XONG het nhung server chi tra loi mot phan (vi du ngat ket noi SAU khi
# nhan du lieu, truoc khi tra het reply) — khi do canary CO THE da duoc ghi. Nhung
# toi KHONG dung duoc ca do bang stub lan Redis that, nen no van CHUA CO TEST, va toi
# ghi ro thay vi de mot phep kiem khong ai biet no bao ve gi.
: > "$S25/rcli.txt"
o25b=$(RCLI_TRUNC=2 r25 bash "$HERE/fim.sh" check 2>&1); rc25b=$?
want "25 batch cat ngan -> PHAI bao loi (canary bat truoc)" \
     "$(printf '%s' "$o25b" | grep -c 'KHONG GHI DUOC')" "1"
want "25 va ma thoat = 2" "$rc25b" "2"
want "25 generation KHONG chuyen" \
     "$(wc -l < "$S25/state/statekeys.full.txt" 2>/dev/null | tr -d ' ')" "3"
# ══ 26. TEP RESP THIEU LENH — ba cua deu qua, chi `replies` lech ════
#
# Toi GO phep so `replies` o `4cf7f15` voi lap luan "canary la lenh CUOI nen moi phep
# cat cung cat luon canary". Lap luan do CHI DUNG cho dut DUONG TRUYEN. Nguoi dung bat
# 02-10: neu TEP RESP thieu mot lenh thi canary VAN duoc noi vao stdin SAU `cat "$f"`,
# nen no luon toi.
#
# DO TREN REDIS THAT (6.0.16): preseed 3 khoa TTL 600, roi gui batch thieu lenh thu 2
#     errors: 0, replies: 3   (want+1 = 4)
#     canary = "ok"           -> canary KHONG bat
#     EXISTS k1 k2 k3 = 3     -> `count_live` KHONG bat (khoa cu con song)
#     k2 van "old2", TTL 600  -> KHONG duoc refresh
# `count_live` dem SU TON TAI, khong dem su REFRESH.
#
# Ca duoi PRESEED khoa bang mot lot `check` sach TRUOC, roi lot sau moi bo lenh —
# khong preseed thi `count_live` bat duoc va ca nay khong con do dung thu can do.
printf '\n── tep RESP thieu lenh (muc 26) ──\n'
S26="$R/s26"; mkdir -p "$S26/state"
W26="$S26/home/u1/domains/dr.test/public_html"
mkdir -p "$W26/a" "$W26/b" "$W26/c"
for dd in a b c; do printf 'AddHandler application/x-httpd-php .jpg\n' > "$W26/$dd/.htaccess"; done
r26() { FIM_ROOTS="$S26/home/*/domains/*/public_html" FIM_STATE="$S26/state" \
        FIM_LOG="$S26/fim.log" FIM_CRITLOG="$S26/crit.log" \
        RCLI_OUT="$S26/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" "$@"; }
r26 bash "$HERE/fim.sh" baseline >/dev/null 2>&1

# Lot 1: SACH -> ba khoa ton tai (preseed cho lot sau).
: > "$S26/rcli.txt"
o26=$(r26 bash "$HERE/fim.sh" check 2>&1); rc26=$?
want "26 lot preseed: ma thoat 0" "$rc26" "0"
want "26 lot preseed: 3 khoa" \
     "$(grep -cP '^SETEX\twaf:fimcfg:' "$S26/rcli.txt")" "3"

# Lot 2: BO lenh thu 2 khoi tep RESP. Khoa cu VAN CON tu lot 1, nen:
#   canary toi    -> qua
#   errors: 0     -> qua
#   EXISTS = 3    -> qua  (count_live mu truoc ca nay)
#   replies = 3   -> LECH want+1 = 4  -> PHAI bao loi
o26b=$(FIM_TEST_DROP_NTH=2 r26 bash "$HERE/fim.sh" check 2>&1); rc26b=$?
want "26 tep RESP thieu lenh -> PHAI bao loi" \
     "$(printf '%s' "$o26b" | grep -c 'THIEU lenh hoac batch bi cat')" "1"
want "26 va ma thoat = 2" "$rc26b" "2"
want "26 generation KHONG chuyen" \
     "$(wc -l < "$S26/state/statekeys.full.txt" 2>/dev/null | tr -d ' ')" "3"
# may khong co Apache o duong quen IM LANG toan bo tin hieu ExecCGI.


# ══ 29. CHA-CON THAT: hai tep .htaccess o hai tang ══════════════════
#
# Nhom 24 cua `htaccess_fixture_test.sh` dat HAI directive trong CUNG MOT TEP du chu
# thich mo ta cha-con. Nen no kiem "last-wins trong mot tep", KHONG kiem phep merge
# cha-con (review bat 02-10). Phep merge do nam o `init.lua`, va duong day du la:
#     hai `.htaccess` tren dia -> `fim.sh` ghi HAI khoa -> `init.lua` MGET + merge
#
# Nhom nay chay DUNG duong do: cay that, `fim.sh check` that, gia tri khoa lay tu
# stub Redis, roi nap vao `init.lua` qua `resty`. KHONG stub `safe_mget` bang chuoi
# go tay — chuoi phai la thu `fim.sh` THAT SU ghi ra.
printf '\n── cha-con THAT: hai tep hai tang (muc 29) ──\n'
RESTY_BIN="${RESTY:-/usr/local/openresty/bin/resty}"
if [ ! -x "$RESTY_BIN" ]; then
    echo "  BO QUA: khong co resty tai $RESTY_BIN (can de goi init.lua)."
    echo "          Dat RESTY=/duong/dan, hoac chay qua run.sh."
else
SRC29="$(cd "$HERE/../.." && pwd)/"

cat > "$R/cc.lua" <<'LUAEOF'
local SRC = os.getenv("ANTIBOT_SRC")
for _, name in ipairs({ "registry", "policy", "config", "telemetry",
                        "exposed", "args", "upload", "body", "routes" }) do
    package.preload["antibot.waf." .. name] = function()
        return dofile(SRC .. "waf/" .. name .. ".lua")
    end
end
for _, name in ipairs({ "wordpress.paths", "upload_content", "upload_magic",
                        "body_core", "body_worker" }) do
    package.preload["antibot.waf." .. name] = function()
        return dofile(SRC .. "waf/" .. name:gsub("%.", "/") .. ".lua")
    end
end
package.preload["antibot.core.redis_pool"] = function()
    return { safe_get = function() return nil end, safe_mget = function() return nil end }
end
local pool = require("antibot.core.redis_pool")
local waf  = dofile(SRC .. "waf/init.lua")

-- `CHAIN` = gia tri khoa tu CON len CHA, phan cach TAB. Phan tu rong = khong co khoa.
--
-- KHONG dung `gmatch("([^\t]*)")`: `*` khop CA chuoi rong, nen giua hai token no sinh
-- THEM mot phan tu rong. Voi `CHAIN="a\tb"` ket qua la `{"a", "", "b", ""}` chu khong
-- phai `{"a","b"}` — `chain[2]` thanh rong, gia tri cua CHA bi day xuong `chain[3]` va
-- bi `half` cat bo. Do duoc 02-10: ca "cha Options +ExecCGI + con AddHandler" tra
-- `nil` va toi suyt ket luan `init.lua` co FN ke thua, trong khi loi o chinh harness.
local chain = {}
do
    local s = os.getenv("CHAIN") or ""
    local i = 1
    while true do
        local j = s:find("\t", i, true)
        if not j then chain[#chain + 1] = s:sub(i); break end
        chain[#chain + 1] = s:sub(i, j - 1)
        i = j + 1
    end
end
-- `OLD` = nua SAU cua mang `MGET` (tien to `waf:fimchg:` cu), cung dang phan cach TAB.
-- Thieu bien nay thi khong ca nao dat duoc gia tri vao HAI namespace that, va dot bien
-- R-r1 (quay lai `for i = nk, 1, -1`) KHONG bi bat — do duoc 03-10.
local old = {}
do
    local s = os.getenv("OLD") or ""
    local i = 1
    while true do
        local j = s:find("\t", i, true)
        if not j then old[#old + 1] = s:sub(i); break end
        old[#old + 1] = s:sub(i, j - 1)
        i = j + 1
    end
end
pool.safe_mget = function(keys, n)
    local out, half = {}, n / 2
    -- `WANTKEY`/`WANTVAL`: tra gia tri cho khoa co TEN khop, thay vi theo CHI SO. Can
    -- cho cac ca ma dieu phai do la `init.lua` yeu cau khoa cua THU MUC NAO — vi du
    -- tran 12 tang: ban dung yeu cau `waf:fimcfg:<root>/` o phan tu cuoi, ban sai yeu
    -- cau mot thu muc giua. Do bang chi so thi hai ban cho CUNG ket qua va dot bien
    -- khong bi bat (do duoc 03-10).
    local wk, wv = os.getenv("WANTKEY"), os.getenv("WANTVAL")
    if wk and wk ~= "" then
        for i = 1, n do
            out[i] = (keys[i] == wk) and wv or ngx.null
        end
        return out
    end
    -- `init.lua` gui `ns` khoa tien to MOI roi `ns` khoa tien to CU.
    for i = 1, half do
        local v = chain[i]
        out[i] = (v and v ~= "") and v or ngx.null
    end
    for i = 1, half do
        local v = old[i]
        out[half + i] = (v and v ~= "") and v or ngx.null
    end
    return out
end
local ctx = {}
local rt = {
    var = { host = "a.test", uri = os.getenv("URI"), args = nil,
            remote_addr = "127.0.0.1", document_root = "/nonexistent",
            http_content_type = nil },
    req = { get_method = function() return "GET" end },
    log = function() end, exit = function() end, ERR = 4,
    waf_body_probe = function() end,
}
waf._run_pre_with_runtime(ctx, rt)
local got = "nil"
for i = 1, #(ctx.waf_hits or {}) do
    if ctx.waf_hits[i].rule == "fim_config_active" then got = ctx.waf_hits[i].matched end
end
io.write(got)
LUAEOF

n29_chua=0
n29_tong=0
# `cc <ten> <uri> <mong-APACHE> <mong-HIEN-TAI> <cha> <con> [execcgi_ok]`
#
# HAI ky vong, co y: `mong-APACHE` la hanh vi DUNG, `mong-HIEN-TAI` la thu code tra
# ve hom nay. Bon ca cua review co hai gia tri KHAC NHAU — do la BANG CHUNG loi, ghi
# vao bo test chu khong de trong mot tep rieng.
#
# `want` so voi `mong-HIEN-TAI` nen suite khong do thuong tru (`run.sh` tra 1 se chan
# moi commit ve sau, va mot suite do mai thi khong con la cong). Nhung cung KHONG im
# lang: moi ca lech in mot dong `CHUA SUA` kem CA HAI gia tri.
#
# Khi mot truc duoc sua: doi `mong-HIEN-TAI` thanh `mong-APACHE` cho ca do. Khi moi ca
# bang nhau thi bo tham so thu tu.
cc() {
    local nhan="$1" uri="$2" dung="$3" nay="$4" tcha="$5" tcon="$6" exok="${7:-}"
    local B="$R/cc_$(printf '%s' "$nhan" | tr -cd 'a-z0-9')"
    rm -rf "$B"; mkdir -p "$B/state"
    local W="$B/home/u1/domains/cc.test/public_html"
    mkdir -p "$W/con"
    printf '%b' "$tcha" > "$W/.htaccess"
    printf '%b' "$tcon" > "$W/con/.htaccess"
    local E=(FIM_ROOTS="$B/home/*/domains/*/public_html" FIM_STATE="$B/state"
             FIM_LOG="$B/l" FIM_CRITLOG="$B/c" RCLI_OUT="$B/rcli.txt"
             FIM_REDIS_CLI="$R/bin/rcli")
    # Tham so 7: CO DINH `EXECCGI_OK`. Khong dat thi `fim.sh` tu do, va trong WSL
    # `detect_execcgi_ok` doc duoc 0 dong -> tra `1`, con fleet tra `0` (do 02-10 tren
    # 171-96: hai `cgi-bin/.htaccess` that deu cho `@execcgi:noop`). Ca nao do CO CHE
    # `Options` phai ghim tri nay, neu khong no dang do `detect_execcgi_ok`.
    [ -n "$exok" ] && E+=(FIM_EXECCGI_OK="$exok")
    : > "$B/rcli.txt"
    env "${E[@]}" bash "$HERE/fim.sh" baseline >/dev/null 2>&1
    : > "$B/rcli.txt"
    env "${E[@]}" bash "$HERE/fim.sh" check >/dev/null 2>&1
    local vcon vcha got
    vcon=$(awk -F'\t' -v k="waf:fimcfg:$W/con/" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$B/rcli.txt")
    vcha=$(awk -F'\t' -v k="waf:fimcfg:$W/" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$B/rcli.txt")
    got=$(env ANTIBOT_SRC="$SRC29" CHAIN="$vcon	$vcha" URI="$uri" "$RESTY_BIN" "$R/cc.lua" 2>/dev/null)
    n29_tong=$((n29_tong + 1))
    want "29 $nhan" "$got" "$nay"
    if [ "$dung" != "$nay" ]; then
        printf '  CHUA SUA  29 %s\n            Apache=%s  hien tai=%s\n' "$nhan" "$dung" "$nay"
        n29_chua=$((n29_chua + 1))
    fi
    rm -rf "$B"
}

# ── BON CA cua review: DA SUA 02-10, `Apache=` == `hien tai=` ────────
#
# Truoc 02-10 bon ca nay lech, va do la ly do chung ton tai. Phep sua: parser bao cao
# BON TRUC rieng (`h±`/`t±`/`@sh±`/`@ft±`/`@exec±`) va `init.lua` ap PRECEDENCE
# (`SetHandler` -> `AddHandler` -> `ForceType` -> `AddType`) thay cho phep OR.
#
# Giu lai voi HAI ky vong BANG NHAU: chung la rang buoc chong tai pham. Mot ban sau gop
# lai hai truc hay doi lai thanh OR se lam chung do ngay.
cc "ca1 (DA SUA) con RemoveType .jpg KHONG xoa handler cua cha" \
   "/con/a.jpg" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .jpg\n' 'RemoveType .jpg\n'

cc "ca2 (DA SUA) con AddHandler default-handler GHI DE handler cua cha" \
   "/con/a.jpg" "nil" "nil" \
   'AddHandler application/x-httpd-php .jpg\n' 'AddHandler default-handler .jpg\n'

cc "ca3 (DA SUA) con ForceType text/plain KHONG huy SetHandler cua cha" \
   "/con/a.jpg" "handler_all" "handler_all" \
   'SetHandler application/x-httpd-php\n' 'ForceType text/plain\n'

cc "ca4 (DA SUA) con Options Includes (absolute) TAT ExecCGI cua cha" \
   "/con/a.cgi" "nil" "nil" \
   'Options +ExecCGI\n' 'Options Includes\n' 1

# ── PRECEDENCE phai la THANG, khong phai phep HOAC ───────────────────
#
# Bon ca tren khong bat duoc dot bien PR-A (cho truc TYPE duoc xet TIEP du truc HANDLER
# da noi TAT): suite van xanh 1995/0. Do la mot lo that — mot ban sau quay ve nua phan
# OR se khong bi chan. Ba ca duoi dong no, va moi ca co mot TANG noi mot trac KHAC NHAU
# nen chi mot thang precedence dung moi qua het.
#
# Dap an tinh TAY tu tai lieu Apache truoc khi chay:
#   cha `AddType php .jpg` (type BAT) + con `AddHandler default-handler .jpg`
#   -> handler uu tien CAO HON type, va handler noi "dung mac dinh" -> KHONG chay.
cc "prec: handler TAT o con DE BE type BAT o cha" \
   "/con/a.jpg" "nil" "nil" \
   'AddType application/x-httpd-php .jpg\n' 'AddHandler default-handler .jpg\n'

# Huong NGUOC cua cung cap truc: type lanh o con KHONG de be handler o cha, vi type
# nam DUOI handler. Thieu ca nay thi mot ban "luon uu tien tang GAN hon" cung qua.
cc "prec: type lanh o con KHONG de be handler o cha" \
   "/con/a.jpg" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .jpg\n' 'AddType image/jpeg .jpg\n'
# `SetHandler None` KHONG phai mot handler lanh — no la RESET.
#
# Tai lieu Apache (core, `SetHandler`): "Setting the value to None ... reverts to the
# normal handling". Nen `SetHandler none` o cha CHI bo forced handler; mot `AddHandler`
# o con VAN ap dung.
#
# Toi viet ky vong `nil` o ban truoc va KHANG DINH no bang mot dong chu thich tu suy
# luan ("SetHandler la muc CAO NHAT nen vuot ca khoang cach tang"). Review 2 diem 2 bat
# dung ca nay la oracle SAI, va tai lieu Apache xac nhan review dung. Ba trang thai
# (`@sh0` cho `None`, `@sh-` cho mot gia tri lanh) moi mo ta duoc phan biet nay.
cc "prec: SetHandler None o cha la RESET -> AddHandler o con VAN ap" \
   "/con/a.jpg" "handler_ext" "handler_ext" \
   'SetHandler none\n' 'AddHandler application/x-httpd-php .jpg\n'

# Huong NGUOC: mot gia tri LANH (khong phai `None`) thi DUNG lai.
cc "prec: SetHandler default-handler o cha CHAN AddHandler o con" \
   "/con/a.jpg" "nil" "nil" \
   'SetHandler default-handler\n' 'AddHandler application/x-httpd-php .jpg\n'

# ── `Options All`: DU LIEU BAC BO HAI GIA THUYET LIEN TIEP cua toi ───
#
# Do 02-10 tren 171-96: trong 47 dong `Options` toan-thu-muc o tang con, 46 la TUONG
# DOI (`-Indexes`, `-Indexes +ExecCGI`) va DUNG MOT la tuyet doi (`Options All
# -Indexes`).
#
# Gia thuyet 1 cua toi: "47 cho nay dang cho FP". SAI — 46/47 tuong doi, parser xu ly
# dung, con so that la 0.
#
# Gia thuyet 2: "vay dong `All` do la FN huong nguoc, con BAT ExecCGI ma parser bo
# sot". CUNG SAI. Do truc tiep bang parser:
#     Options All -Indexes   EXECCGI_OK=1 -> [@execcgi]   EXECCGI_OK=0 -> [@execcgi:noop]
# Parser BIET `All` bao gom ExecCGI. Hai ca duoi la DOI CHUNG, khong phai mon ton dong.
cc "dc: con Options All (absolute) -> BAT ExecCGI (parser DA dung)" \
   "/con/a.cgi" "execcgi_only" "execcgi_only" \
   '# khong gi\n' 'Options All -Indexes\n' 1

cc "dc: con Options All nhung server KHONG cho -> :noop" \
   "/con/a.cgi" "execcgi_noop" "execcgi_noop" \
   '# khong gi\n' 'Options All -Indexes\n' 0

# ── DOI CHUNG: hien tai DA DUNG, phai giu nguyen qua moi phep sua ────
cc "dc: con RemoveHandler .jpg -> TAT (cung truc)" \
   "/con/a.jpg" "nil" "nil" \
   'AddHandler application/x-httpd-php .jpg\n' 'RemoveHandler .jpg\n'

cc "dc: con im lang -> KE THUA cua cha" \
   "/con/a.jpg" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .jpg\n' '# khong gi\n'

cc "dc: cha im lang + con AddHandler -> con quyet dinh" \
   "/con/a.jpg" "handler_ext" "handler_ext" \
   '# khong gi\n' 'AddHandler application/x-httpd-php .jpg\n'

cc "dc: cha SetHandler php + con im lang -> KE THUA @all" \
   "/con/a.jpg" "handler_all" "handler_all" \
   'SetHandler application/x-httpd-php\n' '# khong gi\n'

cc "dc: cha SetHandler php + con SetHandler none -> TAT" \
   "/con/a.jpg" "nil" "nil" \
   'SetHandler application/x-httpd-php\n' 'SetHandler none\n'

# ── DOI CHUNG tu DU LIEU THAT tren fleet (do 02-10 tren 171-96) ──────
#
# Hai tep `cgi-bin/.htaccess` that, ca hai y nhau tung byte, va khoa Redis that cua ca
# hai thu muc cung y nhau:
#     AddHandler cgi-script .cgi .pl   ->  khoa = @execcgi:noop,ext:cgi,ext:pl
#
# NHUNG `@execcgi:noop` KHONG den tu dong `AddHandler` do. Do truc tiep:
#     AddHandler cgi-script .cgi .pl   EXECCGI_OK=0 -> [ext:cgi,ext:pl]
#     AddHandler cgi-script .cgi .pl   EXECCGI_OK=1 -> [ext:cgi,ext:pl]
# Y NHAU o ca hai tri — dong nay chi sinh `ext:`. Nen `@execcgi:noop` trong khoa that
# den tu mot directive `Options` o TANG KHAC cua chuoi to tien. Ban dau toi dung hai
# ca nay voi cha RONG va mong `execcgi_noop`, va chung HONG (`duoc=handler_ext`) —
# dung, vi hinh dang toi dung sai cho voi thuc te.
#
# Hai dau `.cgi` VA `.pl` deu vao `sufset`: `AddHandler` so doi so voi TUNG duoi mot,
# nen giu `sufset` la TAP la dung (muc 7 cua ke hoach). Day la bang chung THAT cho
# dieu do, khong phai tep dung tay.
#
# Chuoi to tien sau NHAT tren fleet la 4 tang duoi root, nen `ns >= 12` trong
# `init.lua` con thua rat nhieu. Ca `imsvietnam.ac.vn` co .htaccess o CA BA tang
# (`public_html` -> `bk` -> `cgi-bin`), dung hinh dang ma nhom nay do.
cc "dc THAT: cgi-bin cua fleet, chi AddHandler -> handler theo DUOI" \
   "/con/x.cgi" "handler_ext" "handler_ext" \
   '# khong gi\n' 'AddHandler cgi-script .cgi .pl\n' 0

cc "dc THAT: cung tep do, duoi .pl cung phai khop (sufset la TAP)" \
   "/con/x.pl" "handler_ext" "handler_ext" \
   '# khong gi\n' 'AddHandler cgi-script .cgi .pl\n' 0

# Hinh dang THAT: `Options` o CHA sinh `@execcgi`, `AddHandler` o CON sinh `ext:`, nen
# khoa cua con mang CA HAI nhan — dung nhu khoa that tren fleet.
#
# Ket qua la `handler_ext`, KHONG phai `execcgi_noop`: trong `init.lua` nhanh `hit_ext`
# nam TREN `hit_exec_noop`, co y — mot thu muc co ca hai thi nhan MANH HON thang, va
# `.cgi` khop `ext:cgi` nen `hit_ext` dung. Toi mong `execcgi_noop` va SAI; thu tu uu
# tien moi la cau tra loi, khong phai phep HOAC cua hai nhan.
cc "dc THAT: cha Options +ExecCGI + con AddHandler cgi -> ext THANG noop" \
   "/con/x.cgi" "handler_ext" "handler_ext" \
   'Options +ExecCGI\n' 'AddHandler cgi-script .cgi .pl\n' 0

# Cung hinh dang nhung duoi KHONG duoc anh xa: luc do `@execcgi:noop` moi hien ra.
cc "dc THAT: cung hinh dang, duoi .txt khong anh xa -> execcgi_noop" \
   "/con/x.txt" "execcgi_noop" "execcgi_noop" \
   'Options +ExecCGI\n' 'AddHandler cgi-script .cgi .pl\n' 0

cc "dc THAT: 46/47 dong Options o tang con la TUONG DOI -> giu cua cha" \
   "/con/a.cgi" "execcgi_only" "execcgi_only" \
   'Options +ExecCGI\n' 'Options -Indexes\n' 1

# ── `sufs` LA MOT TAP, khong phai "duoi cuoi cung" ───────────────────
#
# Mot review de nghi duyet duoi PHAI->TRAI va lay anh xa DAU TIEN gap, lap luan rang
# `shell.php.jpg` voi `AddHandler default-handler .jpg` thi `.jpg` thang. Khong lam, va
# day la bang chung THAY cho lap luan:
#
#   · Tai lieu Apache (mod_mime, `AddHandler`) noi mot tep co the co NHIEU duoi va
#     directive duoc so "against EACH of them" — khong phai chi duoi cuoi.
#   · `shell.php.jpg` CHAY qua PHP khi `.php` duoc anh xa. Day la lo hong upload co
#     dien, va `sufs` la TAP mo ta DUNG no.
#   · Hai `cgi-bin/.htaccess` THAT tren 171-96 (do 02-10) dung
#     `AddHandler cgi-script .cgi .pl` — mot dong anh xa HAI duoi, va khoa Redis that
#     mang CA `ext:cgi` va `ext:pl`. Apache khong chon mot.
#
# Doi sang phai->trai se tao mot FN THAT o ca duoi day. Ba ca nay chan phep doi do.
cc "muc7: shell.php.jpg CHAY khi .php duoc anh xa (sufs la TAP)" \
   "/con/shell.php.jpg" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .php\n' '# khong gi\n'

# Huong NGUOC: mot duoi KHONG duoc anh xa thi khong duoc tu BAT. Thieu ca nay thi mot
# ban "luon tra handler_ext khi co bat ky anh xa nao" cung qua.
cc "muc7: shell.txt.jpg KHONG chay khi chi .php duoc anh xa" \
   "/con/shell.txt.jpg" "nil" "nil" \
   'AddHandler application/x-httpd-php .php\n' '# khong gi\n'
# RIGHTMOST WINS trong CUNG mot truc — tai lieu Apache (mod_mime, "Files with Multiple
# Extensions"): "If more than one extension is given that maps onto the same type of
# metadata, then the one to the right will be used, except for languages and content
# encodings."
#
# Hai dong duoi deu la `AddHandler` — CUNG truc — nen `.jpg` o ben phai THANG, va
# `shell.php.jpg` KHONG chay. Toi ghim `handler_ext` o ban truoc va do la oracle SAI;
# review 2 diem 4 bat dung ca nay. Lan truoc toi con BAC BO diem nay bang mot lap luan
# ve `AddType`/`AddLanguage` — lap luan do khong ap cho hai `AddHandler`.
cc "muc7: hai AddHandler cung truc -> duoi BEN PHAI thang" \
   "/con/shell.php.jpg" "nil" "nil" \
   'AddHandler application/x-httpd-php .php\nAddHandler default-handler .jpg\n' '# khong gi\n'

# Dao thu tu duoi trong TEN TEP: `.php` o ben phai -> CHAY.
cc "muc7: shell.jpg.php -> .php ben phai thang -> CHAY" \
   "/con/shell.jpg.php" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .php\nAddHandler default-handler .jpg\n' '# khong gi\n'

# GIUA cac truc thi KHAC: handler thang media-type. Tai lieu Apache: "Care should be
# taken when a file with multiple extensions gets associated with both a media-type and
# a handler. This will usually result in the request being handled by the module
# associated with the handler."
#
# Nen lo hong upload co dien VAN bi bat: `.jpg` chi co `AddType`, khong canh tranh truc
# handler.
cc "muc7: handler .php + TYPE .jpg -> handler thang -> CHAY" \
   "/con/shell.php.jpg" "handler_ext" "handler_ext" \
   'AddHandler application/x-httpd-php .php\nAddType image/jpeg .jpg\n' '# khong gi\n'

printf '  => %s/%s ca CHUA SUA' "$n29_chua" "$n29_tong"
if [ "$n29_chua" -gt 0 ]; then
    printf ' -- xem cac dong "CHUA SUA" o tren'
fi
printf '\n'

# ══ 30. MOC `v2` — hai luat KHONG duoc cham nhau ════════════════════
#
# `c942edf` doi hop dong token ma khong doi tien to khoa, nen trong 7 ngay TTL mot
# khoa `waf:fimcfg:` co the mang dang CU (`ext:`/`@all`) hay dang MOI (`h+:`/`@sh+`).
# Moc `v2` o dau danh sach quyet dinh doc luat nao.
#
# Nhom nay nap chuoi khoa TRUC TIEP (khong qua `fim.sh`) vi chi o day moi dung duoc mot
# khoa dang CU — `fim.sh` khong con ghi dang do.
printf '\n── moc v2: hai luat khong cham nhau (muc 30) ──\n'
mv() {  # mv <ten> <uri> <mong> <khoa-con> [khoa-cha]
    local nhan="$1" uri="$2" mong="$3" kcon="$4" kcha="${5:-}"
    local got
    got=$(env ANTIBOT_SRC="$SRC29" CHAIN="$kcon	$kcha" URI="$uri" "$RESTY_BIN" "$R/cc.lua" 2>/dev/null)
    want "30 $nhan" "$got" "$mong"
}

# Dang CU khong moc: `ext:jpg` phai van doc duoc. Bo nhanh di tru ngay thi moi thu muc
# da danh dau MAT PHAT HIEN cho tới khi `fim.sh` chay lai — mot cua so mu tu tao ra.
mv "cu: ext:jpg (khong moc) -> handler_ext" "/a.jpg" "handler_ext" "ext:jpg"
mv "cu: @all (khong moc) -> handler_all"    "/a.jpg" "handler_all" "@all"
mv "cu: * (khong moc) -> autoload"          "/a.php" "autoload_userini" "*"

# MOI co moc.
mv "moi: v2,h+:jpg -> handler_ext"  "/a.jpg" "handler_ext" "v2,h+:jpg"
mv "moi: v2,@sh+ -> handler_all"    "/a.jpg" "handler_all" "v2,@sh+"
mv "moi: v2,@php -> autoload"       "/a.php" "autoload_userini" "v2,@php"

# HAI LUAT KHONG CHAM NHAU — day la ly do moc ton tai:
#   · mot khoa CU chua `h+:jpg` (vi du mot ten tep `.h+:jpg` sinh token do) KHONG duoc
#     doc theo luat moi;
#   · mot khoa MOI chua `ext:jpg` KHONG duoc doc theo luat cu.
# Ca nao cung phai roi vao nhanh "duoi THO" cua luat tuong ung.
mv "cach ly: khoa CU mang h+:jpg -> doc theo luat CU (duoi tho)" \
   "/a.h+:jpg" "handler_ext" "h+:jpg"
mv "cach ly: khoa MOI mang ext:jpg -> KHONG doc theo luat cu" \
   "/a.jpg" "nil" "v2,ext:jpg"

# KE THUA xuyen hai dang: cha dang CU, con dang MOI. Xay ra THAT trong 7 ngay sau
# deploy, vi `fim.sh` chi ghi lai thu muc nao DOI.
mv "tron: cha CU @all + con MOI im lang -> ke thua handler_all" \
   "/con/a.jpg" "handler_all" "" "@all"
mv "tron: cha CU @all + con MOI @sh- -> con TAT duoc" \
   "/con/a.jpg" "nil" "v2,@sh-" "@all"
mv "tron: cha MOI @sh+ + con CU rong -> ke thua" \
   "/con/a.jpg" "handler_all" "" "v2,@sh+"

# ── HAI NAMESPACE THAT: fallback theo TUNG TANG, khong cong hai snapshot ──
#
# Cac ca `mv` o tren chi dat gia tri vao nua `fimcfg` (MOI); chung tron GRAMMAR trong
# cung mot nua. Nen dot bien R-r1 (quay lai `for i = nk, 1, -1` tren CA mang) khong bi
# bat — do duoc 03-10, suite van xanh.
#
# `mv2 <ten> <uri> <mong> <moi-con> <moi-cha> <cu-con> <cu-cha>` dat CA HAI namespace.
#
# Ban truoc xep khoa `moi-con, moi-cha, cu-con, cu-cha` roi duyet tu CUOI ve DAU, nen
# thu tu ap thuc te la `cu-cha -> cu-con -> moi-cha -> moi-con` — KHONG phai thu tu
# Apache `cha -> con`. Do duoc:
#   FN: moi=[con rong, cha h-:jpg]  cu=[con ext:jpg, cha rong] -> `nil`, dung `handler_ext`
#   FP: cung thu muc, moi=[v2,@php] cu=[ext:jpg]               -> `handler_ext`, dung `nil`
mv2() {
    local nhan="$1" uri="$2" mong="$3" mcon="$4" mcha="$5" ccon="$6" ccha="$7"
    local got
    got=$(env ANTIBOT_SRC="$SRC29" CHAIN="$mcon	$mcha" OLD="$ccon	$ccha" \
              URI="$uri" "$RESTY_BIN" "$R/cc.lua" 2>/dev/null)
    want "30 $nhan" "$got" "$mong"
}

# THU TU TANG: con thang cha, bat ke khoa o namespace nao.
mv2 "ns: cha MOI an toan + con CU nguy -> CON thang" \
    "/con/a.jpg" "handler_ext" "" "v2,h-:jpg" "ext:jpg" ""
mv2 "ns: cha CU nguy + con MOI an toan -> CON thang" \
    "/con/a.jpg" "nil" "v2,h-:jpg" "" "" "ext:jpg"

# CUNG THU MUC co ca hai khoa: khoa MOI la snapshot THAY THE, khong phai bo sung.
# Snapshot moi khong con `.jpg` nghia la mapping do DA BI BO.
mv2 "ns: cung thu muc, MOI thieu truc cu -> truc cu KHONG song tiep" \
    "/con/a.jpg" "nil" "v2,@php" "" "ext:jpg" ""
mv2 "ns: cung thu muc, MOI co truc -> doc theo MOI" \
    "/con/a.jpg" "handler_ext" "v2,h+:jpg" "" "@all" ""

# CHI co khoa CU -> van doc duoc (di tru chua xong).
mv2 "ns: chi khoa CU o con" "/con/a.jpg" "handler_ext" "" "" "ext:jpg" ""
mv2 "ns: chi khoa CU o cha" "/con/a.jpg" "handler_all" "" "" "" "@all"

# ── RESET phai ROI XUONG, explicit-safe phai DUNG (review 2 diem 2) ──
#
# Dot bien R-r2 (coi `"reset"` nhu `false`) khong bi bat boi cac ca `mv` o tren. Ba ca
# duoi la ba ca FN ma review neu, do tren duong doc THAT.
mv "reset: cha t+:jpg + con h0:jpg -> type thanh synthetic handler" \
   "/con/a.jpg" "handler_ext" "v2,h0:jpg" "v2,t+:jpg"
mv "reset: cha h+:jpg + con @sh0 -> AddHandler cua cha VAN ap" \
   "/con/a.jpg" "handler_ext" "v2,@sh0" "v2,h+:jpg"
mv "reset: cha t+:jpg + con @ft0 -> MIME association khoi phuc" \
   "/con/a.jpg" "handler_ext" "v2,@ft0" "v2,t+:jpg"

# Huong NGUOC: explicit-safe DUNG lai, khong roi xuong. Thieu cap ca nay thi mot ban
# "coi moi phu dinh la reset" cung qua.
mv "safe: cha t+:jpg + con h-:jpg -> DUNG, khong roi xuong type" \
   "/con/a.jpg" "nil" "v2,h-:jpg" "v2,t+:jpg"
mv "safe: cha h+:jpg + con @sh- -> DUNG" \
   "/con/a.jpg" "nil" "v2,@sh-" "v2,h+:jpg"
mv "safe: cha t+:jpg + con @ft- -> DUNG" \
   "/con/a.jpg" "nil" "v2,@ft-" "v2,t+:jpg"

# ── PATH_INFO cho MOI duoi, khong chi duoi PHP ───────────────────────
#
# `script_path` cat PATH_INFO bang `RX_PHP_EXEC`, va bieu thuc do CHI liet ke duoi PHP.
# Do duoc 03-10 bang chinh `init.lua` TRUOC khi sua:
#     URI=/shell.jpg/x  CHAIN=[v2,h+:jpg]  ->  nil   (phai la handler_ext)
# `script_path` tra nguyen URI nen `dir` thanh `/shell.jpg/` (thu muc KHONG ton tai) va
# `sufs` lay tu `x` (khong duoi) — `MGET` tra khoa rac VA duoi that bi bo.
# `?pi` = ket luan den tu PHEP DOAN PATH_INFO. URI khong chung minh duoc `/shell.jpg/`
# la PATH_INFO hay mot thu muc THAT; neu la thu muc that thi `x` la tep that va nhan
# `handler_ext` se la FP (review 2 diem 5). Hau to cho policy dem duoc, va khong lan
# voi ket luan chac chan.
mv "pathinfo: /shell.jpg/x -> handler_ext?pi (DOAN, khong chac)" \
   "/shell.jpg/x" "handler_ext?pi" "v2,h+:jpg"
mv "pathinfo: /a.jpg khong PATH_INFO -> handler_ext" \
   "/a.jpg" "handler_ext" "v2,h+:jpg"

# KHONG cat khi phan sau CO dau `.`: `/a.jpg/b.css` la mot duong dan that co the ton
# tai (thu muc ten `a.jpg`), nen phai tra khoa cua thu muc DO chu khong cua `/`.
mv "pathinfo: /a.jpg/b.css la duong dan THAT -> khong cat" \
   "/a.jpg/b.css" "nil" "v2,h+:jpg"

# Huong NGUOC: duoi PHP van di qua `script_path` nhu cu.
mv "pathinfo: /a.php/x cat boi script_path, duoi la php" \
   "/a.php/x" "handler_ext" "v2,h+:php"

# GIOI HAN da biet, ghi ro chu khong che: mau chi khop MOT doan cuoi, nen
# `/shell.jpg/x/y` van khong cat duoc. Huong bo sot, khong bao oan.
mv "pathinfo: GIOI HAN /shell.jpg/x/y chua cat duoc (bo sot)" \
   "/shell.jpg/x/y" "nil" "v2,h+:jpg"

# Duoi co GACH: `[%w]` cu khong cat duoc `.x-y` du parser ho tro duoi do.
mv "pathinfo: duoi co gach, khong PATH_INFO" "/x.x-y" "handler_ext" "v2,h+:x-y"
mv "pathinfo: duoi co gach + PATH_INFO"      "/x.x-y/z" "handler_ext?pi" "v2,h+:x-y"

# ── TRAN 12 TANG phai GIU document root (review 2 diem 6) ───────────
#
# Vong tra chuoi to tien `break` khi du 12 phan tu, nen `/` KHONG vao `segs` va mot
# `AddHandler` o webroot bi bo HOAN TOAN. Do 03-10:
#     URI 13 tang, khoa @ webroot -> `nil`  (dung phai `handler_ext`)
# Do sau quan sat tren fleet la 4-7 tang, nhung URI do NGUOI GUI quyet dinh — khong
# phai rang buoc an toan.
#
# Do theo TEN KHOA, khong theo chi so: dieu phai do la `init.lua` yeu cau khoa cua THU
# MUC NAO. Ban dung yeu cau `waf:fimcfg:<root>/` o phan tu cuoi; ban bo webroot yeu cau
# mot thu muc GIUA (`<root>/a/b/`). Do bang chi so thi hai ban cho CUNG ket qua va dot
# bien khong bi bat — toi viet ca do truoc va no khong bat duoc gi.
mk() {  # mk <ten> <uri> <khoa> <gia-tri> <mong>
    local got
    got=$(env ANTIBOT_SRC="$SRC29" WANTKEY="$3" WANTVAL="$4" URI="$2" "$RESTY_BIN" "$R/cc.lua" 2>/dev/null)
    want "30 $1" "$got" "$5"
}
mk "tran: URI 13 tang VAN thay webroot" \
   "/a/b/c/d/e/f/g/h/i/j/k/l/m/x.jpg" "waf:fimcfg:/nonexistent/" "v2,h+:jpg" "handler_ext:cut"
# Huong NGUOC: URI ngan thi khoa webroot cung doc duoc va KHONG mang `:cut`.
mk "tran: URI 3 tang -> webroot doc duoc, khong :cut" \
   "/a/b/c/x.jpg" "waf:fimcfg:/nonexistent/" "v2,h+:jpg" "handler_ext"
# Thu muc GIUA cua URI sau: doc duoc binh thuong (khong bi cat mat).
mk "tran: URI 13 tang, khoa o thu muc cua request" \
   "/a/b/c/d/e/f/g/h/i/j/k/l/m/x.jpg" "waf:fimcfg:/nonexistent/a/b/c/d/e/f/g/h/i/j/k/l/m/" \
   "v2,h+:jpg" "handler_ext:cut"

# ── DAU PHAY trong TEN DUOI (review 2 diem 7) ───────────────────────
#
# Linux chi cam `NUL` va `/` trong ten tep, nen `AddHandler php .jpg,evil` la hop le.
# Parser tung phat `h+:jpg,evil` -> ben doc tach thanh `h+:jpg` va mot token la `evil`,
# nen request `x.jpg,evil` KHONG khop. FN, dau vao do khach kiem soat.
mv "phay: khoa h+:jpg%2Cevil khop /x.jpg,evil" \
   "/x.jpg,evil" "handler_ext" "v2,h+:jpg%2Cevil"
# Va KHONG khop `.jpg` tron — day la cho ban cu sai.
mv "phay: khoa h+:jpg%2Cevil KHONG khop /x.jpg" \
   "/x.jpg" "nil" "v2,h+:jpg%2Cevil"
# `%` THAT trong ten duoi: `%25` giai CUOI, nen `%252c` ve `%2c` chu khong ve `,`.
mv "phay: % that trong ten duoi (h+:p%252cq khop /x.p%2cq)" \
   "/x.p%2cq" "handler_ext" "v2,h+:p%252cq"
mv "phay: h+:jpg binh thuong van khop" "/x.jpg" "handler_ext" "v2,h+:jpg"
fi

# ══ 28. `DEL` BI BO QUA — xac minh phep GO ══════════════════════════
#
# `state_marks` gui `DEL` roi chuyen generation NGAY, khong doc nguoc. Nhanh dirty da
# kiem tung khoa bang `redis_absent` tu truoc, nhanh nay thi khong (nguoi dung bat
# 02-10).
#
# Theo dung failure model ma `RCLI_SKIP` dang phong: mot `DEL` bi bo qua lam khoa cu
# VAN SONG trong khi generation DA QUEN no — lot sau khong con biet de thu lai, va
# khoa do bao "dang nguy hiem" tới het TTL 7 ngay.
#
# `EX_STUCK=1` trong stub = khoa KHONG BAO GIO mat, tuc dung ca `DEL` that bai im
# lang.
printf '\n── DEL bi bo qua (muc 28) ──\n'
S28="$R/s28"; mkdir -p "$S28/state"
W28="$S28/home/u1/domains/dl.test/public_html"
# HAI thu muc: xoa `a/.htaccess` thi `statekeys` van con dong cua `b/`, nen generation
# KHONG bi ghi lai thanh rong — khong co `b/` thi tap mong muon rong va phep so
# generation mat y nghia (do duoc 02-10).
mkdir -p "$W28/a" "$W28/b"
printf 'AddHandler application/x-httpd-php .jpg\n' > "$W28/a/.htaccess"
printf 'AddHandler application/x-httpd-php .png\n' > "$W28/b/.htaccess"
r28() { env FIM_ROOTS="$S28/home/*/domains/*/public_html" FIM_STATE="$S28/state" \
            FIM_LOG="$S28/fim.log" FIM_CRITLOG="$S28/crit.log" \
            RCLI_OUT="$S28/rcli.txt" FIM_REDIS_CLI="$R/bin/rcli" "$@"; }
r28 bash "$HERE/fim.sh" baseline >/dev/null 2>&1
: > "$S28/rcli.txt"; r28 bash "$HERE/fim.sh" check >/dev/null 2>&1
want "28 lot 1: hai khoa" \
     "$(grep -cP '^SETEX\twaf:fimcfg:' "$S28/rcli.txt")" "2"
sk28=$(cat "$S28/state/statekeys.full.txt" 2>/dev/null)

# BO `.htaccess` -> lot sau phai `DEL` khoa cu. `EX_STUCK=1` lam `DEL` that bai im
# lang (khoa van ton tai khi doc nguoc).
# BO `.htaccess` roi chay BASELINE lai: lot sau khong con thay "thay doi" nen thu muc
# KHONG vao nhanh dirty, va `state_marks` moi la noi phat `DEL`. Khong lam vay thi ca
# nay do nhanh dirty (da co phep kiem tu truoc) chu khong do `state_marks` — do duoc
# 02-10: `DEL phat: 0` o duong state.
rm -f "$W28/a/.htaccess"
r28 bash "$HERE/fim.sh" baseline >/dev/null 2>&1
: > "$S28/rcli.txt"
o28=$(EX_STUCK=1 r28 bash "$HERE/fim.sh" check 2>&1); rc28=$?
want "28 DEL that bai im lang -> PHAI bao loi" \
     "$(printf '%s' "$o28" | grep -c 'KHONG XAC MINH DUOC phep GO')" "1"
want "28 va ma thoat = 2" "$rc28" "2"
want "28 generation KHONG chuyen (con biet de thu lai)" \
     "$(cat "$S28/state/statekeys.full.txt" 2>/dev/null)" "$sk28"

# ══ 27. LOCALE UTF-8 + ten thu muc tieng Viet ════════════════════════
#
# RESP khai do dai doi so bang BYTE, nhung `${#s}` (bash) dem KY TU khi locale la
# UTF-8. Do duoc (02-10): `waf:fimcfg:/home/u/thư mục/` cho `${#k} = 27` duoi UTF-8
# nhung 30 byte that.
#
# DO TREN REDIS THAT (6.0.16), locale `C.UTF-8`, mot thu muc ten `thư mục/`:
#     CO    `export LC_ALL=C` -> rc=0, 1 khoa, 0 loi
#     KHONG `export LC_ALL=C` -> rc=2, 0 khoa,
#                                "ERR Protocol error: expected '$', got '/'"
# Mot thu muc ten tieng Viet lam CA BATCH that bai, nen 12 khoa deu khong duoc ghi.
# Fail-visible (rc=2) chu khong im lang, nhung hau qua la mat toan bo phat hien.
#
# CA NAY CAN REDIS THAT: stub `rcli` doc doi so bang `read -r -N "$alen"` nen no
# KHONG tai hien duoc phep dem sai — `--pipe` that thi bao protocol error. Khong co
# Redis thi BAO QUA MAT chu khong im lang: mot ca khong chay phai noi ro.
#
# `fim_test.sh` dat `LC_ALL=C` o dau tep nen bo test KHONG BAO GIO thay loi nay neu
# khong ghi de TUONG MINH. Nguoi dung bat 02-10.
printf '\n── locale UTF-8 + ten tieng Viet (muc 27) ──\n'
RRCLI="${FIM_TEST_REAL_REDIS_CLI:-redis-cli}"
RRPORT="${FIM_TEST_REAL_REDIS_PORT:-6399}"
RRDB="${FIM_TEST_REAL_REDIS_DB:-9}"
if ! command -v "$RRCLI" >/dev/null 2>&1 \
   || [ "$("$RRCLI" -p "$RRPORT" ping 2>/dev/null)" != "PONG" ]; then
    echo "  BO QUA: khong co Redis that o port $RRPORT (can cho ca nay -- stub doc"
    echo "          theo byte nen khong tai hien duoc phep dem do dai sai)."
    echo "          Chay: redis-server --daemonize yes --port $RRPORT"
else
    S27="$R/s27"; mkdir -p "$S27/state"
    W27="$S27/home/u1/domains/vn.test/public_html"
    mkdir -p "$W27/thư mục"
    printf 'AddHandler application/x-httpd-php .jpg\n' > "$W27/thư mục/.htaccess"
    cat > "$R/bin/rrcli" <<RREOS
#!/bin/bash
exec "$RRCLI" -p "$RRPORT" "\$@"
RREOS
    chmod +x "$R/bin/rrcli"
    "$RRCLI" -p "$RRPORT" -n "$RRDB" FLUSHDB >/dev/null 2>&1
    r27() { env FIM_ROOTS="$S27/home/*/domains/*/public_html" FIM_STATE="$S27/state" \
                FIM_LOG="$S27/fim.log" FIM_CRITLOG="$S27/crit.log" \
                FIM_REDIS_CLI="$R/bin/rrcli" FIM_REDIS_DB="$RRDB" \
                LC_ALL=C.UTF-8 LANG=C.UTF-8 "$@"; }
    r27 bash "$HERE/fim.sh" baseline >/dev/null 2>&1
    o27=$(r27 bash "$HERE/fim.sh" check 2>&1); rc27=$?
    want "27 locale UTF-8 + ten tieng Viet: ma thoat 0" "$rc27" "0"
    want "27 KHONG co loi protocol" \
         "$(printf '%s' "$o27" | grep -ci 'protocol error')" "0"
    want "27 khoa duoc ghi vao Redis THAT" \
         "$("$RRCLI" -p "$RRPORT" -n "$RRDB" --scan --pattern 'waf:fimcfg:*' 2>/dev/null | wc -l)" "1"
    # GIA TRI THO tu Redis THAT, co MOC: ca nay la mot trong hai cho kiem moc that su
    # ton tai tren duong ghi. Cac ca khac cat moc qua `strip_ver` vi chung do NOI DUNG,
    # con ca nay do HOP DONG VAN CHUYEN — `init.lua` doc luat nao phu thuoc vao no.
    want "27 gia tri doc nguoc dung, CO moc v2" \
         "$("$RRCLI" -p "$RRPORT" -n "$RRDB" --raw GET "waf:fimcfg:$W27/thư mục/" 2>/dev/null)" "v2,h+:jpg"
    "$RRCLI" -p "$RRPORT" -n "$RRDB" FLUSHDB >/dev/null 2>&1
fi

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

# ── `execcgi_ok_for`: THEO USER, khong phai mot boolean toan may (muc 32) ──
#
# `detect_execcgi_ok` gop MOI user vao mot `yes`, nen ca "mot dong cho, mot dong khong
# -> 1" o tren la DUNG cho ham do nhung SAI cho cau hoi that: thu muc NAY co chay CGI
# duoc khong. Mot user cho `ExecCGI` khong lam user khac duoc cho.
#
# Do 03-10 tren 171-96: fleet DONG NHAT (66 dong `AllowOverride` giong nhau tung ky tu,
# 73/73 user CHAN), nen bug nay khong gay loi HOM NAY. Cac ca duoi do CO CHE, de mot
# user duoc doi `AllowOverride` khong keo ca may theo.
printf '\n── execcgi_ok_for: theo tung user (muc 32) ──\n'
AO32="$R/ao32"; mkdir -p "$AO32/u1" "$AO32/u2"
printf 'AllowOverride All\n' > "$AO32/u1/httpd.conf"
printf 'AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,None\n' > "$AO32/u2/httpd.conf"
eokf() {  # eokf <ten> <duong-dan> <mong> [EXECCGI_OK]
    local g
    # Ham DAT `$EXECCGI_R` chu khong in — xem ly do o `execcgi_ok_for` trong `fim.sh`
    # (command substitution chay trong subshell nen cache `UOK` se mat).
    g=$(FIM_AO32="$AO32" FIM_P="$2" FIM_DEF="${4:-1}" \
        bash -c 'set -uo pipefail
                 DA_HTTPD="$FIM_AO32"; EXECCGI_OK="$FIM_DEF"; EXECCGI_R=1; declare -A UOK
                 '"$(sed -n "/^execcgi_ok_for() {/,/^}/p" "$HERE/fim.sh")"'
                 execcgi_ok_for "$FIM_P"; printf "%s" "$EXECCGI_R"' 2>/dev/null)
    want "32 $1" "${g:-LOI}" "$3"
}
eokf "user CHO -> 1"  "/home/u1/domains/t.test/public_html" "1"
eokf "user CHAN -> 0" "/home/u2/domains/t.test/public_html" "0"
# HAI user tren CUNG mot may cho HAI ket qua: day la dieu `detect_execcgi_ok` khong
# lam duoc, va la toan bo ly do ham nay ton tai.
eokf "user KHONG co tep -> dung tri toan may (1)" "/home/u3/domains/t.test/public_html" "1"
eokf "user KHONG co tep, tri toan may 0 -> 0"     "/home/u3/domains/t.test/public_html" "0" "0"
# Duong dan NGOAI `/home` (vi du `FIM_ROOTS` tuy chinh trong bo test) -> tri toan may.
eokf "ngoai /home -> tri toan may (1)" "/srv/web/public_html" "1"
eokf "ngoai /home, tri toan may 0 -> 0" "/srv/web/public_html" "0" "0"
# `/home` nhung KHONG du hai doan -> tri toan may, khong duoc lay `home` lam user.
eokf "/home mot doan -> tri toan may" "/home/u1" "1"

# ── DAU-CUOI: `dir_tokens` phai THAT SU goi `execcgi_ok_for` ─────────
#
# Bay ca tren do CHINH HAM. Dot bien PR-F (doi lai thanh `execcgi_ok="$EXECCGI_OK"`)
# KHONG bi bat boi chung — suite van xanh cho mot ban da quay ve boolean toan may. Hai
# ca duoi dong lo do: hai user tren CUNG mot lan `check`, moi user mot `AllowOverride`,
# va khoa Redis cua ho phai KHAC nhau.
S32="$R/s32"; mkdir -p "$S32/state" "$S32/da/ua" "$S32/da/ub"
printf 'AllowOverride All\n' > "$S32/da/ua/httpd.conf"
printf 'AllowOverride AuthConfig FileInfo Indexes Limit Options=Indexes,None\n' \
  > "$S32/da/ub/httpd.conf"
for u in ua ub; do
    mkdir -p "$S32/home/$u/domains/t.test/public_html"
    printf 'Options +ExecCGI\n' > "$S32/home/$u/domains/t.test/public_html/.htaccess"
    printf '<?php\n' > "$S32/home/$u/domains/t.test/public_html/i.php"
done
r32() {
    FIM_ROOTS="$S32/home/*/domains/*/public_html" FIM_STATE="$S32/state" \
    FIM_LOG="$S32/f.log" FIM_CRITLOG="$S32/c.log" RCLI_OUT="$S32/rcli.txt" \
    FIM_REDIS_CLI="$R/bin/rcli" FIM_HOME="$S32/home" FIM_DA_HTTPD="$S32/da" \
    bash "$HERE/fim.sh" "$@" >/dev/null 2>&1
}
v32() { awk -F'\t' -v k="waf:fimcfg:$1" '$1=="SETEX" && $2==k {v=$4} END{print v}' "$S32/rcli.txt" 2>/dev/null | strip_ver; }
: > "$S32/rcli.txt"; r32 baseline
: > "$S32/rcli.txt"; r32 check
want "32 dau-cuoi: user CHO -> @exec+" \
     "$(v32 "$S32/home/ua/domains/t.test/public_html/")" "@exec+"
want "32 dau-cuoi: user CHAN -> @exec+:noop (CUNG lan check)" \
     "$(v32 "$S32/home/ub/domains/t.test/public_html/")" "@exec+:noop"

# ── CACHE phai THAT SU song qua nhieu lan goi (review 2 diem 8) ─────
#
# Ban truoc ham `printf` ket qua va cho goi qua `$(...)`. Command substitution chay ham
# trong SUBSHELL, nen moi phep gan `UOK[...]` mat khi subshell ket thuc. Do 03-10: sau
# 3 lan goi qua `$()`, `${#UOK[@]}` van la 0 — cache chi ton tai tren giay, va voi 1.075
# thu muc cau hinh tren fleet thi cung mot `httpd.conf` bi `grep` lai hang tram lan.
#
# Ca nay dem SO PHAN TU cua `UOK` sau nhieu lan goi; mot ban quay lai `printf` + `$()`
# se cho 0.
cache32=$(FIM_AO32="$AO32" bash -c 'set -uo pipefail
    DA_HTTPD="$FIM_AO32"; EXECCGI_OK=1; EXECCGI_R=1; declare -A UOK
    '"$(sed -n "/^execcgi_ok_for() {/,/^}/p" "$HERE/fim.sh")"'
    for i in 1 2 3 4 5; do execcgi_ok_for /home/u1/domains/t.test/public_html; done
    printf "%s" "${#UOK[@]}"' 2>/dev/null)
want "32 cache song qua 5 lan goi (1 phan tu)" "${cache32:-LOI}" "1"

# CACHE KEY LA `(user, domain)`: hai domain cua CUNG user phai la HAI phan tu. Khoa chi
# mang `<user>` se cho 1, va khi nao do duoc cau truc `<Directory>` that thi phan DOC
# moi phai doi — cache key da du cho.
cache32b=$(FIM_AO32="$AO32" bash -c 'set -uo pipefail
    DA_HTTPD="$FIM_AO32"; EXECCGI_OK=1; EXECCGI_R=1; declare -A UOK
    '"$(sed -n "/^execcgi_ok_for() {/,/^}/p" "$HERE/fim.sh")"'
    execcgi_ok_for /home/u1/domains/a.test/public_html
    execcgi_ok_for /home/u1/domains/b.test/public_html
    printf "%s" "${#UOK[@]}"' 2>/dev/null)
want "32 cache key la (user,domain) -> 2 phan tu" "${cache32b:-LOI}" "2"

# Huong NGUOC: CUNG domain goi hai lan -> van MOT phan tu.
cache32c=$(FIM_AO32="$AO32" bash -c 'set -uo pipefail
    DA_HTTPD="$FIM_AO32"; EXECCGI_OK=1; EXECCGI_R=1; declare -A UOK
    '"$(sed -n "/^execcgi_ok_for() {/,/^}/p" "$HERE/fim.sh")"'
    execcgi_ok_for /home/u1/domains/a.test/public_html
    execcgi_ok_for /home/u1/domains/a.test/public_html/sub
    printf "%s" "${#UOK[@]}"' 2>/dev/null)
want "32 cung domain, thu muc con -> 1 phan tu" "${cache32c:-LOI}" "1"
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
