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
    case "$out" in
        "")         got=NONE ;;
        "@all")     got=ALL ;;
        "@execcgi") got=EXECCGI ;;
        *)          got=HANDLER ;;
    esac

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
want "noi dong (2 dong)" "shell" "$out" "php"

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
want "AddType trong <IfModule> -> VAN bao" "shell" "$out" "php"

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

printf '\nhtaccess_fixture: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
