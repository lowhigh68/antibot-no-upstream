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
    # `OFFEXEC`/`OFFALL` = PHAT BIEU TAT, khac han `NONE` = khong noi gi. BA trang
    # thai, va fixture phai phan biet duoc chung — gop lai la pin dung cai nhap hai
    # thu do lam mot, tuc chinh lo da bo sot `SetHandler none` / `Options -ExecCGI`.
    #
    # Cap nhat 02-10: hop dong BON TRUC. `@all` cu tach thanh `@sh+` (`SetHandler`) va
    # `@ft+` (`ForceType`) — HAI truc, vi Apache cho `SetHandler` uu tien cao hon.
    # Fixture van gop chung vao mot lop `ALL` o day, vi cau hoi cua lop nay la "co ap
    # ca thu muc khong"; phep phan biet hai truc nam o nhom `cha-con` cua `fim_test.sh`
    # noi co ca chuoi to tien de do.
    case "$out" in
        "")                     got=NONE ;;
        "@sh+"|"@ft+"|"@all")   got=ALL ;;
        "@exec+"|"@execcgi")    got=EXECCGI ;;
        "@sh-"|"@ft-"|"-@all")  got=OFFALL ;;
        "@exec-"|"-@execcgi")   got=OFFEXEC ;;
        *)                      got=HANDLER ;;
    esac
    if [ "$want" = "HANDLER" ]; then
        # `AddType ... .php .phtml` cho HAI token; lay token cuoi cua DONG lam duoi
        # mong doi thi chi dung cho ca mot duoi. Ca nhieu duoi co nhom rieng o duoi.
        e=$(printf '%s\n' "$rule" | awk '{ print $NF }' | sed 's/^\.//' | tr 'A-Z' 'a-z')
        # TIEN TO THEO TRUC: `AddType`/`RemoveType` -> `t`, `AddHandler`/`RemoveHandler`
        # -> `h`. Day la chinh phep tach ma hop dong moi dua vao, nen fixture phai so
        # DUNG TRUC chu khong chi dung duoi — neu khong no lai che mot phep gop.
        #
        # CAT KHOANG TRANG DAU truoc khi so: mot ca trong bo nay thut le bon khoang
        # trang (`    AddType ...`, de do container), nen `addtype*` KHONG khop va ca
        # do bi gan sai truc. Do duoc 02-10: `duoc=t+:php mong=h+:php`.
        rule_lc=$(printf '%s' "$rule" | tr 'A-Z' 'a-z' | sed 's/^[[:space:]]*//')
        case "$rule_lc" in
            addtype*|removetype*) tr_pfx=t ;;
            *)                    tr_pfx=h ;;
        esac
        want "$rule" "token-duoi" "$out" "${tr_pfx}+:$e"
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
    # Rang buoc nay doc lap voi phep so tren: MOI token phai la mot nhan truc hop le
    # hoac mot duoi hop le (chu/so/gach). Mot token mang `"`, khoang trang, hay `/` la
    # rac. Danh sach cap nhat 02-10 cho hop dong BON TRUC (`h±`/`t±`/`@sh±`/`@ft±`/
    # `@exec±`); dang CU van hop le vi khoa dang song con mang no het TTL 7 ngay.
    bad=""
    for tk in $(printf '%s\n' "$out" | tr "," " "); do
        case "$tk" in
            @sh+|@sh-|@ft+|@ft-|@exec+|@exec-|@exec+:noop) ;;
            @php|@phpini) ;;
            @all|@execcgi|@execcgi:noop|-@all|-@execcgi) ;;
            h+:*|h-:*|t+:*|t-:*)
                case "${tk#??:}" in *[!a-z0-9_@-]*|"") bad="$bad $tk" ;; esac ;;
            ext:*) case "${tk#ext:}" in *[!a-z0-9_@-]*|"") bad="$bad $tk" ;; esac ;;
            *[!a-z0-9_-]*) bad="$bad $tk" ;;
        esac
    done
    want "$rule" "token-hinh-dang" "${bad:-sach}" "sach"

    lua_got=$(awk -v r="$rule" -F'\t' '$2 == r { print $1; exit }' "$R/lua.out")
    # ── VI SAO PHEP SO CHEO DUNG O MUC CO/KHONG ─────────────────────
    #
    # Nguoi dung neu 29-09 rang phep so nay la mot BIT. Dung, va toi DO lai xem co sua
    # duoc khong — cau tra loi la KHONG, vi hai ben CO Y khac nhau:
    #
    #   awk doc `.htaccess` DA NAM TREN DIA -> cau hoi la "THU MUC nay co nguy hiem
    #       khong" -> pham vi container QUAN TRONG (`SetHandler` trong `<FilesMatch>`
    #       KHONG ap ca thu muc)
    #   Lua doc part DANG UPLOAD -> cau hoi la "TEP nay co lam gi chay duoc khong" ->
    #       `SetHandler` trong `<FilesMatch>` VAN lam mot tep chay duoc, chi hep hon
    #
    # Do duoc: Lua tra `handler=co` cho CA BA — `SetHandler` ngoai container, trong
    # `<FilesMatch>`, va `AddType` trong `<FilesMatch>`. Bat hai ben khop token-doi-
    # token se lam MOT BEN SAI, khong phai lam ca hai dung.
    #
    # Nen phep so chéo giu o muc "ca hai co/khong thay gi dang chu y", va phep so
    # TOKEN CHINH XAC nam o ben shell (`token-duoi` o tren) noi no co nghia.
    #
    # DIEU DA SUA duoc: `exp_lua` cu khong phan biet "ca hai im" voi "Lua thay ma awk
    # khong" — huong FALSE NEGATIVE cua chinh awk, tuc dieu bo fixture nay sinh ra de
    # bat. Nay ca `NONE` duoc doi chung HAI CHIEU.
    # `OFFEXEC`/`OFFALL` o ben awk la "thu muc nay TAT tuong minh". Lua doc part dang
    # UPLOAD nen no khong thay gi dang chu y -> `NONE`. Gop chung vao nhanh `HANDLER`
    # se doi Lua bao `handler=co` cho mot dong TAT — nguoc han.
    case "$want" in
        NONE|OFFEXEC|OFFALL) exp_lua=NONE ;;
        *)                   exp_lua=HANDLER ;;
    esac
    want "$rule" "lua(co/khong)" "$lua_got" "$exp_lua"
    want "$rule" "shell"    "$got"     "$want"
done < "$FIX"

# ── Noi dong: mot ca RIENG vi no can HAI dong ────────────────────────
#
# Doi chung CA HAI ben: ban truoc chi chay ben shell, nen mot lech o Lua khong bi
# bat. Byte tren dia phai la gach nguoc + dong moi THAT — `printf '...\n'` sinh
# HAI KY TU `\` va `n`, va khi do phep noi dong CHUA BAO GIO duoc chay.
{ printf 'AddType application/x-httpd-php \\'; printf '\n    .php\n'; } > "$R/cont.htaccess"
out=$(awk -f "$R/shell.awk" "$R/cont.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "noi dong (2 dong)" "shell" "$out" "t+:php"

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
want "SetHandler SAU khi dong container -> @all" "shell" "$out" "@sh+"

# `<IfModule>` KHONG gioi han pham vi theo tep: directive ben trong VAN ap ca thu muc.
{ printf '<IfModule mod_mime.c>\n'
  printf '    AddType application/x-httpd-php .php\n'
  printf '</IfModule>\n'; } > "$R/ifm.htaccess"
out=$(awk -f "$R/shell.awk" "$R/ifm.htaccess" 2>/dev/null | sort -u | paste -sd, -)
want "AddType trong <IfModule> -> VAN bao" "shell" "$out" "t+:php"

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
hta_raw "CRLF: Options +ExecCGI"      "@exec+" 'Options +ExecCGI\r\n'
hta_raw "CRLF: AddType"               "t+:php"      'AddType application/x-httpd-php .php\r\n'
hta_raw "CRLF: SetHandler"            "@sh+"     'SetHandler application/x-httpd-php\r\n'

# ── NHOM 23: RemoveHandler / RemoveType -> token `rm:` ────────────────
#
# `Add*` TICH LUY theo duoi; `Remove*` RUT LAI mot duoi cu the. O thu muc CON, mot
# `Remove*` huy mapping KE THUA tu cha (mod_mime) — nen parser phai phat `rm:<duoi>`
# chu khong chi "khong in gi": ben doc can biet "duoi nay DA BI TAT o day" khac
# "khong co gi o day". Do la ly do khong the OR moi ancestor.
hta_raw "rm: chi RemoveHandler"           "h-:jpg"  'RemoveHandler .jpg\n'
hta_raw "rm: chi RemoveType"              "t-:php"  'RemoveType .php\n'
hta_raw "rm: Add roi Remove cung duoi"    "h-:jpg"  'AddHandler application/x-httpd-php .jpg\nRemoveHandler .jpg\n'
hta_raw "rm: Remove roi Add -> BAT lai"   "h+:jpg" 'RemoveHandler .jpg\nAddHandler application/x-httpd-php .jpg\n'
hta_raw "rm: Remove duoi KHAC khong anh huong" "h+:jpg
h-:png" 'AddHandler application/x-httpd-php .jpg\nRemoveHandler .png\n'
# `Remove*` KHONG loc theo handler: doi so cua no la danh sach DUOI tu token thu HAI,
# va no rut lai bat ke handler cu la gi.
hta_raw "rm: RemoveHandler nhieu duoi"    "h-:cgi
h-:pl" 'RemoveHandler .cgi .pl\n'
# Huong NGUOC: `Add*` khong-PHP van bi bo qua, va `Remove*` khong duoc lam no xuat hien.
hta_raw "rm: AddType text/plain roi Remove" "h-:jpg" 'AddType text/plain .jpg\nRemoveHandler .jpg\n'

# ── NHOM 24: HAI TRUC doc lap — handler vs media type ─────────────────
#
# `AddHandler`/`RemoveHandler` dat HANDLER, `AddType`/`RemoveType` dat MEDIA TYPE.
# mod_mime phan biet ro hai truc; gop chung vao mot bit sinh HAI loi NGUOC NHAU
# (nguoi dung bat 01-10):
#   FN: cha `AddHandler ... .jpg` + con `RemoveType .jpg` -> Apache VAN chay `.jpg`
#       nhung parser cu xoa ca `ext:jpg`.
#   FP: cha `AddHandler ... .jpg` + con `AddHandler default-handler .jpg` -> Apache
#       ghi de bang handler LANH, nhung parser cu bo qua dong khong chua `php|cgi`.
# HAI TOKEN, va do la BANG CHUNG hai truc tach THAT: `RemoveType .jpg` phat `t-:jpg`
# nhung KHONG cham `h+:jpg`. Truoc 02-10 ca nay cho MOT token `ext:jpg` vi hai truc bi
# OR trong parser, nen khong the phan biet "handler con song" voi "type bi go".
hta_raw "truc: RemoveType KHONG xoa handler" "h+:jpg
t-:jpg" 'AddHandler application/x-httpd-php .jpg\nRemoveType .jpg\n'
hta_raw "truc: RemoveHandler KHONG xoa type" "h-:jpg
t+:jpg" 'AddType application/x-httpd-php .jpg\nRemoveHandler .jpg\n'
hta_raw "truc: cung truc handler -> TAT"     "h-:jpg"  'AddHandler application/x-httpd-php .jpg\nRemoveHandler .jpg\n'
hta_raw "truc: cung truc type -> TAT"        "t-:jpg"  'AddType application/x-httpd-php .jpg\nRemoveType .jpg\n'
hta_raw "truc: ghi de bang handler LANH -> TAT" "h-:jpg" 'AddHandler application/x-httpd-php .jpg\nAddHandler default-handler .jpg\n'
hta_raw "truc: type lanh KHONG tat handler nguy" "h+:jpg" 'AddHandler application/x-httpd-php .jpg\nAddType image/jpeg .jpg\n'
# Huong NGUOC — quan trong nhat: mot `AddType` LANH don thuan KHONG phu dinh gi. In
# `rm:css` o day lam ben doc hieu "duoi nay bi TAT", mot cau sai (bo test bat 8 ca).
hta_raw "truc: AddType lanh KHONG sinh rm:"  ""        'AddType text/css .css\n'
hta_raw "truc: AddType lanh cho .jpg van im" ""        'AddType image/jpeg .jpg\n'
ini_raw "CRLF: none = TAT"            "khong"    'auto_prepend_file=none\r\n'
ini_raw "CRLF: gia tri rong = TAT"    "khong"    'auto_prepend_file=\r\n'
ini_raw "CRLF: co gia tri = BAT"      "co"       'auto_prepend_file=/tmp/x.php\r\n'

# ── LAN CUOI THANG (last-directive-wins) ─────────────────────────────
#
# Nguoi dung tai hien 29-09. Apache/Zend doc TUAN TU va dong SAU ghi de dong TRUOC.
# Ban truoc hop moi lan xuat hien nen khong bao gio rut lai duoc — FP telemetry hom
# nay, va FP THAT neu luat duoc promote.
hta_raw "lan cuoi: +ExecCGI roi -ExecCGI" "@exec-" 'Options +ExecCGI\nOptions -ExecCGI\n'
hta_raw "lan cuoi: -ExecCGI roi +ExecCGI" "@exec+" 'Options -ExecCGI\nOptions +ExecCGI\n'
hta_raw "lan cuoi: All roi None"          "@exec-" 'Options All\nOptions None\n'
hta_raw "lan cuoi: None roi All"          "@exec+" 'Options None\nOptions All\n'
ini_raw "lan cuoi: x.php roi none"        "khong"    'auto_prepend_file=/tmp/x.php\nauto_prepend_file=none\n'
ini_raw "lan cuoi: none roi x.php"        "co"       'auto_prepend_file=none\nauto_prepend_file=/tmp/x.php\n'
# Huong NGUOC de phep sua khong thanh "luon tra khong": mot dong DUY NHAT co gia tri
# van phai BAT.
ini_raw "mot dong co gia tri van BAT"     "co"       'auto_prepend_file=/tmp/x.php\n'

# ── NHOM 21: gia tri INI — TRIM hai dau, KHONG xoa khoang trang giua ──
#
# `gsub(/[ \t\r"']/, "", v)` xoa MOI khoang trang, nen `n o n e` thanh `none` va bi coi
# la TAT — trong khi Zend doc do la duong dan `n o n e` (nap that bai, KHAC nghia voi
# "tat tinh nang"). Lua giu nguyen nen hai parser LECH nhau theo huong FALSE NEGATIVE
# (nguoi dung bat 01-10; do duoc: awk rc=1, Lua autoload=true).
ini_raw "gia tri co khoang trang GIUA -> BAT"   "co"    'auto_prepend_file = /tmp/a b.php\n'
ini_raw "'n o n e' KHONG phai 'none'"           "co"    'auto_prepend_file = n o n e\n'
ini_raw "'none' that su -> TAT"                 "khong" 'auto_prepend_file = none\n'
ini_raw "'  none  ' (trim hai dau) -> TAT"      "khong" 'auto_prepend_file =   none  \n'
ini_raw "nhay bao quanh bi BO -> TAT"           "khong" 'auto_prepend_file = "none"\n'
ini_raw "nhay don bao quanh bi BO -> TAT"       "khong" "auto_prepend_file = 'none'\n"
ini_raw "nhay bao quanh gia tri THAT -> BAT"    "co"    'auto_prepend_file = "/tmp/a.php"\n'
ini_raw "nhay GIUA gia tri duoc GIU -> BAT"     "co"    'auto_prepend_file = /tmp/a"b.php\n'
ini_raw "CRLF + none van TAT"                   "khong" 'auto_prepend_file = none\r\n'

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
cross "cheo: +ExecCGI roi -ExecCGI" "@exec-" khong 'Options +ExecCGI\nOptions -ExecCGI\n'
cross "cheo: -ExecCGI roi +ExecCGI" "@exec+" co    'Options -ExecCGI\nOptions +ExecCGI\n'
cross "cheo: All roi None"          "@exec-" khong 'Options All\nOptions None\n'
cross "cheo: CRLF +ExecCGI"         "@exec+" co    'Options +ExecCGI\r\n'
cross "cheo: ini x.php roi none"    ""         khong 'auto_prepend_file=/tmp/x.php\nauto_prepend_file=none\n' upload_user_ini
cross "cheo: ini none roi x.php"    ""         co    'auto_prepend_file=none\nauto_prepend_file=/tmp/x.php\n' upload_user_ini
cross "cheo: ini CRLF none"         ""         khong 'auto_prepend_file=none\r\n' upload_user_ini
# Hai parser phai DONG Y tren `n o n e` va tren khoang trang GIUA duong dan — day la
# hai ca da LECH (awk rc=1 / Lua autoload=true). Dat o DAY chu khong o nhom 21: `cross`
# duoc dinh nghia ben duoi, va goi no TRUOC dinh nghia thi shell bao "command not
# found" roi di tiep — hai ca KHONG CHAY ma suite van xanh (nguoi dung bat 01-10).
cross "cheo: 'n o n e' hai ben deu BAT" "" co 'auto_prepend_file = n o n e\n' upload_user_ini
cross "cheo: khoang trang giua duong dan" "" co 'auto_prepend_file = /tmp/a b.php\n' upload_user_ini

# ── NHOM 15: prepend va append la HAI khoa DOC LAP ───────────────────
#
# Ban truoc dung MOT bien cho ca hai directive, nen
#     auto_prepend_file=/tmp/x.php
#     auto_append_file=none
# cho "khong nap ma" — BO SOT mot autoload dang bat (nguoi dung bat 30-09). Zend giu
# mot gia tri RIENG cho tung khoa: last-wins ap TRONG tung khoa, ket luan cuoi la HOAC.
#
# Bon ca dau la ma tran 2x2 cua hai khoa, vi mot ban sua chi doi mot khoa se lot.
ini_raw "doc lap: prepend BAT + append TAT" "co"    'auto_prepend_file=/tmp/x.php\nauto_append_file=none\n'
ini_raw "doc lap: prepend TAT + append BAT" "co"    'auto_prepend_file=none\nauto_append_file=/tmp/x.php\n'
ini_raw "doc lap: ca hai BAT"               "co"    'auto_prepend_file=/a.php\nauto_append_file=/b.php\n'
ini_raw "doc lap: ca hai TAT"               "khong" 'auto_prepend_file=none\nauto_append_file=none\n'
# last-wins van phai ap TRONG tung khoa — khong duoc bien thanh "mot lan bat la mai bat"
ini_raw "doc lap: append last-wins TAT"     "khong" 'auto_append_file=/a.php\nauto_append_file=none\n'
ini_raw "doc lap: prepend TAT, append cung TAT ve sau" "khong" 'auto_append_file=/a.php\nauto_prepend_file=/b.php\nauto_append_file=none\nauto_prepend_file=none\n'
cross "cheo: prepend BAT + append TAT" ""  co    'auto_prepend_file=/tmp/x.php\nauto_append_file=none\n' upload_user_ini
cross "cheo: prepend TAT + append BAT" ""  co    'auto_prepend_file=none\nauto_append_file=/tmp/x.php\n' upload_user_ini

# ── NHOM 16: Options theo PHAM VI, khong lan trang thai ──────────────
#
# `Options -ExecCGI` trong `<FilesMatch>` chi ap cho tap tep hep do; no KHONG rut lai
# quyen da cap cho ca thu muc. Ban truoc dung MOT cap (`execcgi_on`, `execcgi_depth`)
# nen dong trong container ghi de trang thai ngoai -> BO SOT (nguoi dung bat 30-09).
hta_raw "pham vi: ngoai BAT, trong FilesMatch TAT" "@exec+" 'Options +ExecCGI\n<FilesMatch "x">\nOptions -ExecCGI\n</FilesMatch>\n'

# ── `depth` AP DONG DEU cho MOI directive ────────────────────────────
#
# Do 03-10: bat doi xung THAT trong parser — `SetHandler`/`ForceType` kiem `depth == 0`
# con `Add*` KHONG kiem gi, nen
#     <Files *> AddHandler php .jpg </Files>   -> [h+:jpg]
#     <Files *> SetHandler php     </Files>    -> []
# Mot `AddHandler` trong `<Files>` chi ap cho TAP TEP KHOP, nen `h+:jpg` la bao MANH
# HON su that: moi `.jpg` trong thu muc bi tinh la chay duoc.
#
# Suite van XANH sau phep sua, nghia la truoc do khong ca nao do duong nay. Cac ca duoi
# dong lo do.
hta_raw "depth: AddHandler trong Files -> KHONG phai ca thu muc" "" \
    '<Files *>\nAddHandler application/x-httpd-php .jpg\n</Files>\n'
hta_raw "depth: AddType trong Files -> KHONG phai ca thu muc" "" \
    '<Files *>\nAddType application/x-httpd-php .jpg\n</Files>\n'
hta_raw "depth: SetHandler trong Files -> KHONG phai ca thu muc" "" \
    '<Files *>\nSetHandler application/x-httpd-php\n</Files>\n'
hta_raw "depth: ForceType trong Files -> KHONG phai ca thu muc" "" \
    '<Files *>\nForceType application/x-httpd-php\n</Files>\n'

# CHIEU TAT thi KHONG kiem `depth`, co chu dich: mot `Remove*` trong container rut lai
# kha nang thuc thi cho mot tap tep, va ghi nhan no o muc thu muc chi lam ket qua NHE
# hon — huong an toan.
hta_raw "depth: RemoveHandler trong FilesMatch VAN phat (huong an toan)" "h-:jpg" \
    '<FilesMatch "x">\nRemoveHandler .jpg\n</FilesMatch>\n'
hta_raw "depth: AddHandler LANH trong Files VAN phat h- (huong an toan)" "h-:jpg" \
    '<Files *>\nAddHandler default-handler .jpg\n</Files>\n'

# `<IfModule>` KHONG gioi han pham vi theo tep, nen directive ben trong VAN ap ca thu
# muc. Thieu ca nay thi mot ban "moi container deu chan" cung qua.
hta_raw "depth: AddHandler trong IfModule VAN la ca thu muc" "h+:jpg" \
    '<IfModule mod_php.c>\nAddHandler application/x-httpd-php .jpg\n</IfModule>\n'

# Huong NGUOC: NGOAI container thi van phat day du.
hta_raw "depth: AddHandler ngoai container -> h+:jpg" "h+:jpg" \
    'AddHandler application/x-httpd-php .jpg\n'
# Va mot `AddHandler` ngoai container SAU khi dong container van duoc tinh.
hta_raw "depth: AddHandler SAU khi dong Files -> h+:jpg" "h+:jpg" \
    '<Files *>\nRewriteEngine On\n</Files>\nAddHandler application/x-httpd-php .jpg\n'
hta_raw "pham vi: ngoai TAT, trong FilesMatch BAT" "@exec-" 'Options -ExecCGI\n<FilesMatch "x">\nOptions +ExecCGI\n</FilesMatch>\n'
hta_raw "pham vi: CHI trong FilesMatch"            ""         '<FilesMatch "x">\nOptions +ExecCGI\n</FilesMatch>\n'
hta_raw "pham vi: ngoai BAT, trong Directory None" "@exec+" 'Options +ExecCGI\n<Directory /x>\nOptions None\n</Directory>\n'
hta_raw "pham vi: IfModule KHONG gioi han"         "@exec+" '<IfModule mod_x.c>\nOptions +ExecCGI\n</IfModule>\n'
# Huong nguoc: last-wins CUNG pham vi van phai chay, khong duoc thanh "mot lan bat la mai bat"
hta_raw "pham vi: cung depth 0 last-wins TAT"      "@exec-" 'Options +ExecCGI\nOptions -ExecCGI\n'
# Long hai cap: TAT o depth 2 khong duoc leo ra depth 0
hta_raw "pham vi: long hai cap"                    "@exec+" 'Options +ExecCGI\n<Directory /x>\n<FilesMatch "y">\nOptions -ExecCGI\n</FilesMatch>\n</Directory>\n'

# ── NHOM 17: Lua theo PHAM VI — nhung tra loi CAU HOI KHAC awk ───────
#
# `cross` doi hai ben cung ket luan, nen KHONG dung duoc cho nhom nay: voi
#     Options +ExecCGI
#     <FilesMatch "x">
#       Options -ExecCGI
#     </FilesMatch>
# awk tra `@execcgi` ("ca thu muc chay CGI duoc") va Lua tra `co` ("co duong thuc
# thi") — TRUNG. Nhung voi `<FilesMatch>` CHI CO `+ExecCGI` ben trong thi awk tra
# RONG (khong phai quyen ca thu muc) con Lua phai tra `co` (noi dung nay MO mot duong
# thuc thi, du hep). Hai ky vong KHAC NHAU tren CUNG input, va do la dung — nen ky
# vong ghi RIENG tung ben.
lua_only() {  # lua_only <ten> <mong: co|khong> <printf-format> [flag]
    printf "$3" > "$R/x.htaccess"
    cat > "$R/x.lua" <<'LX'
local SRC = os.getenv("ANTIBOT_SRC")
local uc = dofile(SRC .. "waf/upload_content.lua")
local fh = io.open(os.getenv("XFILE"), "rb")
local body = fh:read("*a"); fh:close()
local f = uc.scan_part(body, os.getenv("XFLAG"))
io.write((f and (f.handler or f.autoload)) and "co" or "khong")
LX
    g=$(ANTIBOT_SRC="$(cd "$HERE/../.." && pwd)/" XFILE="$R/x.htaccess" \
        XFLAG="${4:-upload_apache_config}" "$RESTY" "$R/x.lua" 2>/dev/null)
    want "$1" "lua" "${g:-LOI}" "$2"
}
lua_only "lua pham vi: ngoai BAT, trong TAT"   "co"    'Options +ExecCGI\n<FilesMatch "x">\nOptions -ExecCGI\n</FilesMatch>\n'
lua_only "lua pham vi: CHI trong FilesMatch"   "co"    '<FilesMatch "x">\nOptions +ExecCGI\n</FilesMatch>\n'
lua_only "lua pham vi: ngoai TAT, trong BAT"   "co"    'Options -ExecCGI\n<FilesMatch "x">\nOptions +ExecCGI\n</FilesMatch>\n'
# Huong nguoc: TAT that su phai la TAT, khong duoc thanh "co container la co nguy"
lua_only "lua pham vi: cung depth last-wins TAT" "khong" 'Options +ExecCGI\nOptions -ExecCGI\n'
lua_only "lua pham vi: TAT o ca hai pham vi"     "khong" 'Options -ExecCGI\n<FilesMatch "x">\nOptions -ExecCGI\n</FilesMatch>\n'
lua_only "lua pham vi: khong co Options nao"     "khong" '<FilesMatch "x">\nRequire all granted\n</FilesMatch>\n'
# `<IfModule>` khong tang depth: trang thai ben trong VAN la pham vi ngoai
lua_only "lua pham vi: IfModule long, last-wins xuyen qua" "khong" 'Options +ExecCGI\n<IfModule mod_x.c>\nOptions -ExecCGI\n</IfModule>\n'

# ── NHOM 20: HAI container DONG CAP khong duoc xoa nhau ───────────────
#
# `depth` KHONG dung lam dinh danh pham vi: hai container dong cap cung co
# `depth == 1`, nen cai thu hai ghi de trang thai cai thu nhat (nguoi dung bat 01-10;
# bo test cu chi co MOT container moi tang nen khong bat duoc). Lua nay dung mot
# `scope` ID tang dan, cap moi cho tung container MO ra.
lua_only "lua dong cap: x:+ roi y:-" "co" '<FilesMatch "x">\nOptions +ExecCGI\n</FilesMatch>\n<FilesMatch "y">\nOptions -ExecCGI\n</FilesMatch>\n'
lua_only "lua dong cap: x:- roi y:+" "co" '<FilesMatch "x">\nOptions -ExecCGI\n</FilesMatch>\n<FilesMatch "y">\nOptions +ExecCGI\n</FilesMatch>\n'
lua_only "lua dong cap: ba container, giua BAT" "co" '<Files "a">\nOptions -ExecCGI\n</Files>\n<Files "b">\nOptions +ExecCGI\n</Files>\n<Files "c">\nOptions -ExecCGI\n</Files>\n'
# Huong NGUOC: ba container deu TAT thi phai TAT — `scope` khong duoc lam moi pham vi
# "nho mai" mot lan bat nao khong co.
lua_only "lua dong cap: ba container deu TAT" "khong" '<Files "a">\nOptions -ExecCGI\n</Files>\n<Files "b">\nOptions -ExecCGI\n</Files>\n<Files "c">\nOptions -ExecCGI\n</Files>\n'
# Long: pham vi trong TAT khong duoc xoa pham vi ngoai BAT (ca nay da co o nhom 17,
# giu lai de phep sua `scope` khong lam mat no).
lua_only "lua long: ngoai BAT, trong TAT" "co" 'Options +ExecCGI\n<FilesMatch "x">\nOptions -ExecCGI\n</FilesMatch>\n'
# Va last-wins TRONG CUNG mot container van phai chay.
lua_only "lua cung container: + roi -" "khong" '<FilesMatch "x">\nOptions +ExecCGI\nOptions -ExecCGI\n</FilesMatch>\n'

# ── NHOM 19: `@execcgi` chi co nghia khi AllowOverride CHO ───────────
#
# `ExecCGI` trong `.htaccess` la mot quyen ma WEBSERVER phai cho, khong phai mot tinh
# chat cua tep. Tren DirectAdmin `AllowOverride` la whitelist:
#   Options=Indexes,IncludesNOEXEC,MultiViews,SymLinksIfOwnerMatch,FollowSymLinks,None
# `ExecCGI` KHONG co trong do (do 30-09: 149 dong tren 73 tep httpd.conf), va
# `Options All` con lam Apache tra 500 — do duoc bang request THAT: thu muc co
# `Options All -Indexes` tra http=500 trong khi goc site tra 200.
#
# `execcgi_ok=1` la MAC DINH AN TOAN: khong do duoc thi giu tin hieu nhu cu.
hta_ok() {  # hta_ok <ten> <execcgi_ok> <mong> <printf-format>
    printf "$4" > "$R/x.htaccess"
    want "$1" "awk" "$(awk -v execcgi_ok="$2" -f "$HERE/htaccess_parse.awk" "$R/x.htaccess")" "$3"
}
hta_ok "execcgi_ok=1 -> @execcgi nhu cu"      1 "@exec+"      'Options +ExecCGI\n'
hta_ok "execcgi_ok=0 -> @execcgi:noop"        0 "@exec+:noop" 'Options +ExecCGI\n'
hta_ok "execcgi_ok=1 + All -> @execcgi"       1 "@exec+"      'Options All -Indexes\n'
hta_ok "execcgi_ok=0 + All -> noop"           0 "@exec+:noop" 'Options All -Indexes\n'
# `ext:` KHONG bi anh huong: `AddHandler` thuoc `FileInfo`, va `FileInfo` CO trong
# whitelist (do duoc: hai site co AddHandler o goc tra 200 va 301, khong 500).
hta_ok "execcgi_ok=0 KHONG anh huong ext:"    0 "h+:php"       'AddHandler application/x-httpd-php .php\n'
hta_ok "execcgi_ok=0 KHONG anh huong @all"    0 "@sh+"          'SetHandler application/x-httpd-php\n'
# TAT van la TAT o ca hai che do: co sua khong duoc thanh "luon in mot cai gi".
hta_ok "execcgi_ok=0 + TAT -> TAT tuong minh"  0 "@exec-"     'Options +ExecCGI\nOptions -ExecCGI\n'
hta_ok "execcgi_ok=1 + TAT -> TAT tuong minh"  1 "@exec-"     'Options +ExecCGI\nOptions -ExecCGI\n'
# KHONG truyen bien -> phai la 1 (mac dinh an toan), khong phai rong hay noop.
printf 'Options +ExecCGI\n' > "$R/x.htaccess"
want "execcgi_ok KHONG truyen -> mac dinh @execcgi" "awk" \
     "$(awk -f "$HERE/htaccess_parse.awk" "$R/x.htaccess")" "@exec+"
# Dang THAT tren fleet: cgi-bin co ca AddHandler lan ExecCGI. `ext:` giu, `@execcgi`
# thanh noop — hai tin hieu doc lap, khong keo nhau.
hta_ok "cgi-bin THAT, execcgi_ok=0" 0 "h+:cgi
h+:pl
@exec+:noop" 'Options -Indexes +ExecCGI\nAddHandler cgi-script .cgi .pl\n'

# ── HAI BEN DONG Y: sau dong DO DUOC, khong phai gia dinh ────────────
#
# Nhom nay ghi lai mot phep DO 29-09: toi tim cac dong co the lam hai parser lech
# theo huong FALSE NEGATIVE cua awk (awk im, Lua bao). Ket qua: ca sau dong hai ben
# DONG Y. Do la mot ket luan, nen no thanh ca test — neu mai mot ban sua lam lech,
# nhom nay do.
#
# `cross` doi hai ky vong TUYET DOI (khong phai "hai ben giong nhau"), vi mot phep so
# "hai ben dong y" khong phat hien duoc loi CHUNG.
cross "dong y: SetHandler cgi-script"   "@sh+"    co 'SetHandler cgi-script\n'
cross "dong y: AddHandler cgi-script"   "h+:sh"  co 'AddHandler cgi-script .sh\n'
cross "dong y: Action + AddHandler"     "h+:php" co 'Action php-script /cgi-bin/php\nAddHandler php-script .php\n'
cross "dong y: AddOutputFilter -> im"   ""        khong 'AddOutputFilter INCLUDES .shtml\n'
# ── `php_value`: DA DO, la duong CHET tren fleet nay ────────────────
#
# `php_value auto_prepend_file` trong `.htaccess` KHONG nap ma duoc o day, va ca hai
# parser bo qua no la DUNG chu khong phai mot vung mu.
#
# Do tren may that 29-09:
#     apachectl -M | grep -iE 'php|proxy_fcgi'   ->  proxy_fcgi_module (static)
#                                                    KHONG co php_module/php7_module
#     .htaccess dung php_value auto_prepend/append ->  0 tep tren ca fleet
#     .htaccess dung php_value bat ky              ->  4 tep
#
# `php_value` la directive cua mod_php. Voi FPM qua `proxy_fcgi`, Apache khong nhan
# no. `auto_prepend_file` chi co tac dung khi dat trong pool config cua php-fpm hoac
# trong `.user.ini`/`php.ini` — va HAI duong sau DA duoc `fim.sh` theo doi (`@php` va
# `@phpini`). Nen duong THAT da duoc phu; day la duong chet.
#
# Ca duoi GHIM dieu do: neu mai ai them luat `php_value`, no se do, va nguoi do phai
# doc lai khoi nay truoc khi quyet — mot luat nhu vay la FP tren mot dong vo hai.
cross "php_value: duong CHET voi FPM, ca hai IM la dung" "" khong 'php_value auto_prepend_file /tmp/x.php\n'


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
ns "duoi .@all     -> ext:@all"     "h+:@all"     'AddHandler application/x-httpd-php .@all\n'
ns "duoi .@php     -> ext:@php"     "h+:@php"     'AddHandler application/x-httpd-php .@php\n'
ns "duoi .@execcgi -> ext:@execcgi" "h+:@execcgi" 'AddHandler application/x-httpd-php .@execcgi\n'
ns "SetHandler van la @all THAT"    "@sh+"         'SetHandler application/x-httpd-php\n'
ns "hai duoi deu co tien to"        "t+:php,t+:phtml" 'AddType application/x-httpd-php .php .phtml\n'
# HINH DANG: `ext:@all` PHAI bi bao la token rac (`@` khong phai ky tu duoi hop le),
# nhung no la RAC vo hai — `init.lua` khong co nhanh nao khop `ext:@all` tru khi duoi
# that cua request la `@all`, ma do khong phai duoi hop le.
printf '\nhtaccess_fixture: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
