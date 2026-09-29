#!/bin/bash
# htaccess_fixture_test.sh — HAI parser, MOT tap fixture, doi chung DONG Y.
#
# VI SAO CAN: mot ben la Lua (`upload_content.lua`), mot ben la awk trong
# `fim.sh`. Hai ben tra loi CUNG mot cau hoi bang hai hien thuc, va truoc ban nay
# chung lech — awk bo sot `addtype` viet thuong, `SetHandler`, `ForceType`, noi
# dong. Lech theo huong do la FALSE NEGATIVE: Lua bao nguy, FIM im lang.
#
# Chua hai danh sach directive o hai noi roi mong ai cung nho cap nhat ca hai la
# cach DA that bai. Bo nay la trong tai.
#
# CHAY:  bash waf/scripts/htaccess_fixture_test.sh
# Ma thoat: 0 = hai parser dong y tren moi dong, 1 = co lech, 2 = khong chay duoc.
set -u
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
FIX="$HERE/htaccess_fixture.txt"
RESTY=${RESTY:-/usr/local/openresty/bin/resty}

[ -s "$FIX" ] || { echo "thieu $FIX"; exit 2; }
[ -x "$RESTY" ] || { echo "thieu resty tai $RESTY"; exit 2; }

R=$(mktemp -d /var/tmp/hfix.XXXXXX) || exit 2
trap 'rm -rf "$R"' EXIT

pass=0; fail=0
want() {  # want <dong> <ben> <duoc> <mong>
    if [ "$3" = "$4" ]; then pass=$((pass+1))
    else fail=$((fail+1))
        printf 'HONG  [%s] %s\n      duoc=%s  mong=%s\n' "$2" "$1" "$3" "$4"; fi
}

echo "htaccess_fixture: hai parser tren cung mot tap"

# ── Ben LUA: goi `upload_content.scan_part` tren tung dong ────────────
cat > "$R/lua.lua" <<'LUAEOF'
local SRC = os.getenv("ANTIBOT_SRC")
local uc = dofile(SRC .. "waf/upload_content.lua")
local fix = os.getenv("FIXFILE")
for line in io.lines(fix) do
    if line ~= "" and line:sub(1, 1) ~= "#" then
        local want, rule = line:match("^(%u+)\t(.*)$")
        if want then
            -- `upload_apache_config` = ten `.htaccess` (xem `upload.lua`).
            local flags = uc.scan_part(rule, "upload_apache_config")
            local got = (flags and flags.handler) and "HANDLER" or "NONE"
            io.write(got, "\t", rule, "\n")
        end
    end
end
LUAEOF
ANTIBOT_SRC="$(cd "$HERE/../.." && pwd)/" FIXFILE="$FIX" \
    "$RESTY" "$R/lua.lua" > "$R/lua.out" 2>"$R/lua.err" || {
        echo "ben Lua chay that bai:"; sed 's/^/    /' "$R/lua.err"; exit 2; }

# ── Ben SHELL: trich dung khoi awk cua `fim.sh` ───────────────────────
#
# KHONG sao chep lai khoi awk vao day — mot ban sao la mot cho de lech tiep, dung
# cai benh bo nay sinh ra de chua. Trich TU `fim.sh` bang moc dong.
# Parser la TEP RIENG (`htaccess_parse.awk`), dung chung voi `fim.sh`. Truoc day
# bo nay TRICH khoi awk ra khoi `fim.sh` bang moc comment — mot phep trich la mot
# cho de lech, va no da hong mot lan (mat dong dau va dau dong cua khoi).
cp "$HERE/htaccess_parse.awk" "$R/shell.awk" 2>/dev/null
[ -s "$R/shell.awk" ] || { echo "khong trich duoc khoi awk tu fim.sh"; exit 2; }

while IFS=$'\t' read -r want rule; do
    case "$want" in ''|'#'*) continue ;; esac
    printf '%s\n' "$rule" > "$R/one.htaccess"
    out=$(awk -f "$R/shell.awk" "$R/one.htaccess" 2>/dev/null | sort -u | paste -sd, -)
    # ── SO TOKEN THAT cho nhanh duoi, khong con mot BIT ─────────────
    #
    # Ban truoc: `*) got=HANDLER` — MOI output khong phai `@all`/`@execcgi`/rong deu
    # thanh `HANDLER`, nen mot parser tra `ext:jpg` thay vi `ext:php` van BAO XANH
    # (nguoi dung bat 29-09). Nay duoi mong doi duoc SUY RA tu chinh dong fixture
    # (token cuoi, bo dau `.`) va so DUNG token.
    #
    # Khong them cot vao bang fixture: duoi nam san trong dong, va mot cot nua la mot
    # cho de lech giua cot va dong.
    case "$out" in
        "")         got=NONE ;;
        "@all")     got=ALL ;;
        "@execcgi") got=EXECCGI ;;
        *)          got=HANDLER ;;
    esac
    if [ "$want" = "HANDLER" ]; then
        # `AddType ... .php .phtml` cho HAI token; lay token cuoi cua DONG lam duoi
        # mong doi thi chi dung cho ca mot duoi. Ca nhieu duoi co nhom rieng o duoi.
        e=$(printf '%s\n' "$rule" | awk '{ print $NF }' | sed 's/^\.//' | tr 'A-Z' 'a-z')
        want "$rule" "token-duoi" "$out" "ext:$e"
    fi
    # ── HINH DANG TOKEN phai HOP LE ─────────────────────────────────
    #
    # Phep so ALL/HANDLER/NONE la mot BIT, va mot bit KHONG chung minh tuong
    # duong (nguoi dung bat 28-09). Ca that da lot: `AddHandler "application/
    # x-httpd-php extra" .php` cho ra `extra",php` — HAI token, mot cai la rac
    # mang dau nhay — nhung `got=HANDLER` van khop `want=HANDLER` nen fixture
    # BAO XANH. Fixture khi do che dung cai sai cua parser.
    #
    # Rang buoc nay doc lap voi phep so tren: MOI token phai la `@<chu>` hoac mot
    # duoi hop le (chu/so/gach). Mot token mang `"`, khoang trang, hay `/` la rac.
    bad=""
    for tk in $(printf '%s\n' "$out" | tr "," " "); do
        case "$tk" in
            @all|@php|@phpini|@execcgi) ;;
            ext:*) case "${tk#ext:}" in *[!a-z0-9_-]*|"") bad="$bad $tk" ;; esac ;;
            *[!a-z0-9_-]*) bad="$bad $tk" ;;
        esac
    done
    want "$rule" "token-hinh-dang" "${bad:-sach}" "sach"

    lua_got=$(awk -v r="$rule" -F'\t' '$2 == r { print $1; exit }' "$R/lua.out")
    # Lua tra mot BOOLEAN `handler`, nen no khong phan biet ALL voi HANDLER duoc.
    # Ghi ro GIOI HAN nay thay vi de nguoi doc tuong day la phep so token-doi-token:
    # de so den tan token, Lua phai phat ra chinh bo token do — mot thay doi cua
    # Lua de vua phep do, khong phai mot phep sua loi. Chua lam.
    # Lua tra mot BOOLEAN `handler` nen no khong phan biet ALL/EXECCGI/HANDLER.
    # `Options +ExecCGI`: Lua BAO (handler=true) con shell tra `@execcgi` — hai ben
    # dong y "co gi dang chu y" nhung KHAC ve do manh. Do la GIOI HAN da biet cua
    # phep so nay, ghi ro thay vi de nguoi doc tuong day la tuong duong token.
    exp_lua=$([ "$want" = "NONE" ] && echo NONE || echo HANDLER)
    want "$rule" "lua(bit)" "$lua_got" "$exp_lua"
    want "$rule" "shell"    "$got"     "$want"
done < "$FIX"

# ── Noi dong: mot ca RIENG vi no can HAI dong ────────────────────────
#
# Doi chung CA HAI ben: ban truoc chi chay ben shell, nen mot lech o Lua khong bi
# bat. Byte tren dia phai la gach nguoc + dong moi THAT — `printf '...\n'` sinh
# HAI KY TU `\` va `n`, va khi do phep noi dong CHUA BAO GIO duoc chay.
{ printf 'AddType application/x-httpd-php \\'; printf '\n    .php\n'; } > "$R/cont.htaccess"
out=$(awk -f "$R/shell.awk" "$R/cont.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "noi dong (2 dong)" "shell" "$out" "ext:php"

cat > "$R/cont.lua" <<'LUAEOF'
local uc = dofile(os.getenv("ANTIBOT_SRC") .. "waf/upload_content.lua")
local fh = assert(io.open(os.getenv("CONTFILE"), "r"))
local body = fh:read("*a"); fh:close()
local flags = uc.scan_part(body, "upload_apache_config")
io.write((flags and flags.handler) and "HANDLER" or "NONE")
LUAEOF
lua_cont=$(ANTIBOT_SRC="$(cd "$HERE/../.." && pwd)/" CONTFILE="$R/cont.htaccess"            "$RESTY" "$R/cont.lua" 2>/dev/null)
want "noi dong (2 dong)" "lua" "$lua_cont" "HANDLER"

# ── `<FilesMatch>`: SetHandler trong container KHONG ap ca thu muc ───
#
# Ca nay can NHIEU DONG nen khong vao duoc tap fixture mot-dong-mot-ca. Dot bien
# "bo kiem container" da KHONG bi bat truoc khi co nhom nay — dung lo hong nguoi
# dung neu ra 28-09.
#
# Apache: `SetHandler` trong `<FilesMatch>` chi ap cho tep KHOP mau do, khong phai
# ca thu muc. Parser chua doc duoc container context day du, nen ben trong
# container KHONG nang thanh `@all`. Huong sai la BO SOT, khong phai bao oan.
{ printf '<FilesMatch "x">\n'
  printf '    SetHandler application/x-httpd-php\n'
  printf '</FilesMatch>\n'; } > "$R/fm.htaccess"
out=$(awk -f "$R/shell.awk" "$R/fm.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "SetHandler trong <FilesMatch> -> KHONG @all" "shell" "${out:-NONE}" "NONE"

# Nhung NGOAI container thi van phai bao — de chac muc tren xanh vi container,
# khong phai vi parser bo han SetHandler.
{ printf '<FilesMatch "x">\n'
  printf '    Header set X-A b\n'
  printf '</FilesMatch>\n'
  printf 'SetHandler application/x-httpd-php\n'; } > "$R/fm2.htaccess"
out=$(awk -f "$R/shell.awk" "$R/fm2.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "SetHandler SAU khi dong container -> @all" "shell" "$out" "@all"

# `<IfModule>` KHONG gioi han pham vi theo tep: directive ben trong VAN ap ca thu muc.
{ printf '<IfModule mod_mime.c>\n'
  printf '    AddType application/x-httpd-php .php\n'
  printf '</IfModule>\n'; } > "$R/ifm.htaccess"
out=$(awk -f "$R/shell.awk" "$R/ifm.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "AddType trong <IfModule> -> VAN bao" "shell" "$out" "ext:php"

# ── PARSER INI: `#`/`;` TRONG DAU NHAY khong phai chu thich ──────────
#
# Nguoi dung tai hien 28-09: `auto_prepend_file="none#payload.php"` bi ban truoc
# cat thanh `auto_prepend_file="none` -> doc ra `none` -> ket luan "vo hieu hoa",
# tuc BO SOT mot autoload that. Lua (`upload_content.lua:strip`) xu ly dau nhay
# DUNG, nen day la mot lech giua hai parser theo huong FALSE NEGATIVE.
#
# Dot bien "bo xu ly dau nhay" KHONG bi bat truoc khi co nhom nay.
ini_t() {  # ini_t <mong: co|khong> <dong>
    printf '%s\n' "$2" > "$R/one.ini"
    if awk -f "$HERE/inifile_parse.awk" "$R/one.ini" 2>/dev/null; then g=co; else g=khong; fi
    want "$2" "ini" "$g" "$1"
}
ini_t co    'auto_prepend_file="none#payload.php"'
ini_t co    'auto_prepend_file="none;payload.php"'
ini_t co    'auto_prepend_file=/tmp/x.php'
ini_t co    'auto_prepend_file="/tmp/a b.php"'
ini_t co    'auto_append_file=/tmp/y.php'
ini_t khong 'auto_prepend_file=none'
ini_t khong 'auto_prepend_file='
ini_t khong '; auto_prepend_file=/tmp/x.php'
ini_t khong '# auto_prepend_file=/tmp/x.php'
ini_t khong 'memory_limit=128M'

# ── CRLF: tep sua tu Windows ─────────────────────────────────────────
#
# Nguoi dung tai hien 29-09. HAI HUONG SAI NGUOC NHAU tu cung mot nguyen nhan
# (`trim` va `gsub` khong bo `\r`):
#   · `Options +ExecCGI\r\n`        -> token `+execcgi\r` -> BO SOT (false negative)
#   · `auto_prepend_file=none\r\n`  -> `v = "none\r" != "none"` -> BAT NHAM (FP)
# Mot loi sinh CA hai loai.
#
# `ini_t` va bang fixture deu KHONG dien dat duoc CRLF (`printf '%s\n'` luon LF), nen
# nhom nay phai co ham rieng — day la ly do ba loi CRLF song duoc trong khi 108 ca
# bao xanh.
hta_raw() {  # hta_raw <ten> <mong> <printf-format>
    printf "$3" > "$R/raw.htaccess"
    want "$1" "shell" "$(awk -f "$HERE/htaccess_parse.awk" "$R/raw.htaccess")" "$2"
}
ini_raw() {  # ini_raw <ten> <mong: co|khong> <printf-format>
    printf "$3" > "$R/raw.ini"
    if awk -f "$HERE/inifile_parse.awk" "$R/raw.ini" 2>/dev/null; then g=co; else g=khong; fi
    want "$1" "ini" "$g" "$2"
}
hta_raw "CRLF: Options +ExecCGI"      "@execcgi" 'Options +ExecCGI\r\n'
hta_raw "CRLF: AddType"               "ext:php"      'AddType application/x-httpd-php .php\r\n'
hta_raw "CRLF: SetHandler"            "@all"     'SetHandler application/x-httpd-php\r\n'
ini_raw "CRLF: none = TAT"            "khong"    'auto_prepend_file=none\r\n'
ini_raw "CRLF: gia tri rong = TAT"    "khong"    'auto_prepend_file=\r\n'
ini_raw "CRLF: co gia tri = BAT"      "co"       'auto_prepend_file=/tmp/x.php\r\n'

# ── LAN CUOI THANG (last-directive-wins) ─────────────────────────────
#
# Nguoi dung tai hien 29-09. Apache/Zend doc TUAN TU va dong SAU ghi de dong TRUOC.
# Ban truoc hop moi lan xuat hien nen khong bao gio rut lai duoc — FP telemetry hom
# nay, va FP THAT neu luat duoc promote.
hta_raw "lan cuoi: +ExecCGI roi -ExecCGI" ""         'Options +ExecCGI\nOptions -ExecCGI\n'
hta_raw "lan cuoi: -ExecCGI roi +ExecCGI" "@execcgi" 'Options -ExecCGI\nOptions +ExecCGI\n'
hta_raw "lan cuoi: All roi None"          ""         'Options All\nOptions None\n'
hta_raw "lan cuoi: None roi All"          "@execcgi" 'Options None\nOptions All\n'
ini_raw "lan cuoi: x.php roi none"        "khong"    'auto_prepend_file=/tmp/x.php\nauto_prepend_file=none\n'
ini_raw "lan cuoi: none roi x.php"        "co"       'auto_prepend_file=none\nauto_prepend_file=/tmp/x.php\n'
# Huong NGUOC de phep sua khong thanh "luon tra khong": mot dong DUY NHAT co gia tri
# van phai BAT.
ini_raw "mot dong co gia tri van BAT"     "co"       'auto_prepend_file=/tmp/x.php\n'

# ── SO CHEO tren input NHIEU DONG ────────────────────────────────────
#
# Bang fixture o tren la MOT dong moi ca, va ben Lua doc no bang `io.lines` — nen
# `last-directive-wins` va noi dong KHONG the dien dat o do. Do la ly do loi
# last-wins song duoc o CA HAI parser trong khi 108 ca bao xanh: fixture khong co
# hinh dang de bat no.
#
# Nhom nay chay CA HAI ben tren cung mot input nhieu dong. `@execcgi` cua awk va
# `handler` cua Lua la HAI HINH DANH khac nhau cho cung mot cau tra loi ("dong nay
# co lam tep thanh chay duoc khong"), nen so o muc CO/KHONG — nhung KHAC voi
# `exp_lua` cu, day la input ma hai ben deu co the sai CUNG HUONG, nen ca nao cung
# ghi ro ky vong TUYET DOI chu khong chi "hai ben giong nhau".
cross() {  # cross <ten> <mong awk> <mong lua: co|khong> <printf-format>
    printf "$4" > "$R/x.htaccess"
    want "$1" "awk" "$(awk -f "$HERE/htaccess_parse.awk" "$R/x.htaccess")" "$2"
    cat > "$R/x.lua" <<'LX'
local SRC = os.getenv("ANTIBOT_SRC")
local uc = dofile(SRC .. "waf/upload_content.lua")
local fh = io.open(os.getenv("XFILE"), "rb")
local body = fh:read("*a"); fh:close()
local f = uc.scan_part(body, os.getenv("XFLAG"))
io.write((f and (f.handler or f.autoload)) and "co" or "khong")
LX
    g=$(ANTIBOT_SRC="$(cd "$HERE/../.." && pwd)/" XFILE="$R/x.htaccess" \
        XFLAG="${5:-upload_apache_config}" "$RESTY" "$R/x.lua" 2>/dev/null)
    want "$1" "lua" "${g:-LOI}" "$3"
}
cross "cheo: +ExecCGI roi -ExecCGI" ""         khong 'Options +ExecCGI\nOptions -ExecCGI\n'
cross "cheo: -ExecCGI roi +ExecCGI" "@execcgi" co    'Options -ExecCGI\nOptions +ExecCGI\n'
cross "cheo: All roi None"          ""         khong 'Options All\nOptions None\n'
cross "cheo: CRLF +ExecCGI"         "@execcgi" co    'Options +ExecCGI\r\n'
cross "cheo: ini x.php roi none"    ""         khong 'auto_prepend_file=/tmp/x.php\nauto_prepend_file=none\n' upload_user_ini
cross "cheo: ini none roi x.php"    ""         co    'auto_prepend_file=none\nauto_prepend_file=/tmp/x.php\n' upload_user_ini
cross "cheo: ini CRLF none"         ""         khong 'auto_prepend_file=none\r\n' upload_user_ini


# ── KHONG GIAN TEN: mot duoi khong bao gio duoc thanh mot co ─────────
#
# Nguoi dung tai hien 29-09: `AddHandler application/x-httpd-php .@all` sinh token
# `@all`, va `init.lua` doc thanh `handler_all` = "handler ap CA thu muc" — bao MANH
# HON su that tu mot cai TEN TEP. Tien to `ext:` lam hai khong gian khong the gap
# nhau.
#
# Ba ca duoi dung CHINH cac ten trung ten co: neu mai ai bo tien to, chung do ngay.
ns() {  # ns <ten> <mong> <printf-format>
    printf "$3" > "$R/ns.htaccess"
    want "$1" "ns" "$(awk -f "$HERE/htaccess_parse.awk" "$R/ns.htaccess" | paste -sd, -)" "$2"
}
ns "duoi .@all     -> ext:@all"     "ext:@all"     'AddHandler application/x-httpd-php .@all\n'
ns "duoi .@php     -> ext:@php"     "ext:@php"     'AddHandler application/x-httpd-php .@php\n'
ns "duoi .@execcgi -> ext:@execcgi" "ext:@execcgi" 'AddHandler application/x-httpd-php .@execcgi\n'
ns "SetHandler van la @all THAT"    "@all"         'SetHandler application/x-httpd-php\n'
ns "hai duoi deu co tien to"        "ext:php,ext:phtml" 'AddType application/x-httpd-php .php .phtml\n'
# HINH DANG: `ext:@all` PHAI bi bao la token rac (`@` khong phai ky tu duoi hop le),
# nhung no la RAC vo hai — `init.lua` khong co nhanh nao khop `ext:@all` tru khi duoi
# that cua request la `@all`, ma do khong phai duoi hop le.
printf '\nhtaccess_fixture: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
