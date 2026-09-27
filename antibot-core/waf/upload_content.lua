local _M = {}

-- ── NOI DUNG mot tep dinh kem: ba nhom co do chinh xac cao ──────────────────
--
-- Lua THUAN, khong `ngx` — module nay chay trong worker thread qua
-- `ngx.run_worker_thread`, y nhu `body_core`. Khong `ngx.re`.
--
-- ── Cau hoi khac han `upload.lua` ───────────────────────────────────────────
--
-- `upload.lua` hoi "TEN nay, neu dap xuong dia, server co chay khong". File nay hoi
-- "NOI DUNG nay, trong mot tep co ten nhu vay, co phai mot duong chay ma khong".
-- Hai cau can nhau: mot `.htaccess` chua `AddType application/x-httpd-php .jpg`
-- KHONG chua the PHP nao — `php_tag` mu hoan toan — nhung no bien moi anh JPEG
-- trong thu muc thanh ma chay duoc. Va nguoc lai, mot `example.txt` chua `<?php`
-- chi la van ban.
--
-- Vi vay MOI co o day tra ve mot fact ve CHINH part do, va `body_core` gan no vao
-- `content_flags` cua part. Viec ghep "ten nguy hiem VA noi dung nguy hiem trong
-- CUNG mot part" la cua policy, khong phai cua file nay.
--
-- ── Vi sao CHI ba nhom ──────────────────────────────────────────────────────
--
-- Ba nhom nay co cung mot tinh chat: chung khong phai "dau hieu dang ngo" ma la
-- CO CHE chay ma da biet, doc duoc tu cau hinh THAT tren fleet (do 19-09). Mot mau
-- chung chung ("eval", "base64_decode") thi khac han — no khop ca ma hop le cua
-- khach — va do la loai luat ma `feedback_waf_strategy_not_cases` da loai.
--
-- KHONG bat short tag `<?` tran: `short_open_tag` mac dinh TAT tu PHP 5.4 nen `<?`
-- khong chay tren fleet nay, con bat no thi moi `<?xml` — SVG, RSS, SOAP, file
-- Office (OOXML la ZIP, nhung DOCX cu va nhieu dinh dang khac co XML tho) — thanh
-- duong tinh. Doi mot FP THAT lay mot duong chi ton tai neu khach tu bat lai cau
-- hinh do. Neu mai muon bat, dieu kien dung la DO `short_open_tag` tren dia tung
-- host, khong phai suy tu ten tep.

-- ── 1. Directive doi HANDLER (`.htaccess`) ──────────────────────────────────
--
-- Nam directive, va PHAI kiem GIA TRI co anh xa sang PHP/CGI — khong khop ten
-- directive dung rieng. Thieu dieu do thi moi `.htaccess` co
-- `AddType text/css .css` deu ban, tuc bien mot luat chinh xac cao thanh mot may FP.
--
-- Gia tri nhan dien duoc DOC TU CAU HINH THAT tren fleet (do 19-09, ba dong
-- `AddHandler`), khong phai tu tai lieu Apache:
--     application/x-httpd-lsphp                    (httpd-php-handlers.conf)
--     .../php74/sockets/webapps.sock               (httpd-hostname.conf, FPM)
-- Nen mot danh sach chuoi co dinh kieu `x-httpd-php` la KHONG DU. Ba dau hieu:
--   · `php` o bat ky dau trong gia tri  — phu `x-httpd-php`, `x-httpd-lsphp`,
--     `php-script`, `php74-fcgi`, duong socket `.../php74/...`
--   · `cgi`                            — `cgi-script`, `fcgid-script`
--   · `ExecCGI` (voi `Options`)        — bat thuc thi CGI cho thu muc
--
-- `proxy:unix:` va `proxy:fcgi://` cung vao nhom nay: do la cach FPM duoc goi, va
-- ca hai deu di kem mot duong co chua `php` tren fleet nay — nhung bat rieng chung
-- de mot cau hinh dat socket o duong khong co chu `php` van bi bat.
local HANDLER_DIRECTIVES = {
    addhandler  = true,
    addtype     = true,
    sethandler  = true,
    forcetype   = true,
    -- `AddOutputFilter`/`Action` cung doi duoc cach xu ly, nhung chung CHUA thay
    -- tren fleet va them chung vao la mo rong be mat FP ma khong co so do. Them khi
    -- co so lieu, khong them "cho chac".
}

-- Gia tri co anh xa sang mot bo thuc thi. `low` la MOT TOKEN da lower — khong
-- phai ca dong.
--
-- ── FP DA XAC MINH, va vi sao phai parse theo CU PHAP ───────────────
--
-- Ban truoc goi ham nay voi TOAN BO phan con lai cua directive, nen:
--     AddType text/plain .php      -> handler = true   (SAI)
--     AddType text/plain .cgi      -> handler = true   (SAI)
-- Chu `php` chi nam trong DUOI, con token anh xa la `text/plain` — tuc dong nay
-- lam `.php` thanh van ban thuan, NGUOC HAN y nghia bi gan cho no. Da chay module
-- de xac nhan ca hai dong tren tra `true`.
--
-- Cu phap Apache cua bon directive nay:
--     AddType    <mime-or-handler> <ext...>     -> token THU NHAT quyet dinh
--     AddHandler <handler>         <ext...>     -> token THU NHAT quyet dinh
--     SetHandler <handler>                      -> token THU NHAT (khong co ext)
--     ForceType  <mime>                         -> token THU NHAT
-- Nen ca bon deu chi xet ARGUMENT DAU TIEN. Khong co dang nao trong bon dang nay
-- dat handler o token thu hai.
local function maps_to_executor(low)
    return low:find("php", 1, true) ~= nil
        or low:find("cgi", 1, true) ~= nil
        or low:find("proxy:unix:", 1, true) ~= nil
        or low:find("proxy:fcgi:", 1, true) ~= nil
end

-- Token dau tien cua phan argument, da bo nhay. Apache cho nhay quanh gia tri co
-- khoang trang (duong socket FPM tren fleet CO nhay:
-- `AddHandler "proxy:unix:...|fcgi://..." .inc .php`), nen mot phep tach theo
-- khoang trang tran se cat DOI gia tri do.
local function first_arg(rest)
    local q = rest:sub(1, 1)
    if q == '"' or q == "'" then
        local close = rest:find(q, 2, true)
        if close then return rest:sub(2, close - 1) end
        -- Nhay khong dong: lay het phan con lai. Khong tra `nil` — mot dong hong
        -- cu phap khong duoc thanh mot duong LOT.
        return rest:sub(2)
    end
    return rest:match("^(%S+)") or rest
end

-- `Options` tach TOKEN chinh xac, khong tim chuoi tren ca dong.
--
-- Ban truoc dung `rest:find("execcgi", 1, true)` roi loai bang
-- `rest:find("%-execcgi")`. Hai cho sai: `Options +Includes -ExecCGI +FollowSymLinks`
-- co ca hai mau nen ket qua phu thuoc thu tu, va mot `Options All` (bat MOI thu,
-- gom ExecCGI) thi KHONG khop mau nao.
--
-- Apache: token co the co tien to `+`, `-`, hoac khong. `-X` la TAT. Token cuoi
-- cung noi ve ExecCGI la token quyet dinh, y nhu Apache xu ly tuan tu.
local function options_enables_exec(rest)
    local on = nil
    for tok in rest:gmatch("%S+") do
        local sign, name = tok:match("^([+-]?)(.+)$")
        name = (name or ""):lower()
        if name == "execcgi" then
            on = (sign ~= "-")
        elseif name == "all" and sign ~= "-" then
            -- `Options All` bat moi option TRU MultiViews — gom ExecCGI.
            on = true
        elseif name == "none" then
            on = false
        end
    end
    return on == true
end

-- ── 2. Directive cau hinh PHP nap ma (`.user.ini`, `php.ini`) ───────────────
--
-- `auto_prepend_file` / `auto_append_file` nap MOT TEP BAT KY truoc/sau moi script
-- PHP — ke ca mot tep `.jpg` da upload. Do la duong chay ma khong can `<?php` trong
-- chinh tep cau hinh.
--
-- CO DUNG CHUNG cho `.user.ini` va `php.ini` (nguoi dung chot 27-09): hai ten tach
-- o `name_flags` (`upload_php_config` cho ca hai, nhung composite policy xet rieng)
-- va o policy, KHONG tach o day — cung mot directive, cung mot co che.
--
-- Vi sao van tach o policy: `.user.ini` duoc PHP doc THEO THU MUC o che do
-- FPM/CGI — tuc mot tep upload vao webroot co tac dung THAT. `php.ini` thi KHONG
-- duoc doc theo thu muc o FPM hay mod_php, nen mot `php.ini` upload vao thu muc web
-- gan nhu khong lam gi. Gop hai ten vao mot phan quyet se lam con so cua
-- `.user.ini` phong len bang luu luong vo hai — cung loi da tach `web.config` khoi
-- `.htaccess`.
local AUTOLOAD_DIRECTIVES = {
    auto_prepend_file = true,
    auto_append_file  = true,
}

-- ── Doc theo DONG, va mot dong la mot don vi cu phap ────────────────────────
--
-- Ca `.htaccess` (Apache) lan `.ini` (PHP) deu doc theo dong, va ca hai deu bo dong
-- chu thich. Nen phep quet nay KHONG phai tim chuoi tren toan tep — mot bai viet
-- chua chu "AddHandler" trong mot doan van khong duoc ban.
--
-- Gioi han: so dong va do dai dong. Mot tep 50 MB co the la 50 trieu dong, va tang
-- nay chay TRONG worker thread nhung van la CPU cua may. Vuot tran thi tra
-- `incomplete = true` — KHONG tra "sach": "khong soi het" khac "khong co gi", cung
-- phan biet da lam o `fn_trunc` va `scan`.
local MAX_LINES    = 512    -- so dong soi toi da cua MOT tep cau hinh
local MAX_LINE_LEN = 1024   -- do dai dong toi da

-- ── TRAN BYTE, va vi sao MAX_LINES mot minh KHONG du ────────────────
--
-- `MAX_LINES = 512` gioi han PARSER, khong gioi han CHI PHI. Mot `.htaccess`
-- 50 MiB van bi: `body:sub` sao chep toan part, `gsub` noi tiep dong quet toan
-- part, roi `s .. "\n"` tao mot ban sao NUA — het thay TRUOC khi vong lap dung o
-- dong 512. Ba lan 50 MiB trong mot request, va ke gui chon duoc con so do.
--
-- Nen cat theo BYTE truoc moi phep sao chep. Con so 64 KiB lay tu dac ta chu
-- khong tu log: mot `.htaccess` hop le la cau hinh cho MOT thu muc; 512 dong
-- nhan 1.024 byte la 512 KiB da la tran tren khong tuong, va 64 KiB von da lon
-- hon moi `.htaccess` that tren fleet (do 27-09: lon nhat 4,1 KiB).
--
-- Vuot tran nay KHONG phai "sach" — no tra `incomplete = true` y nhu vuot
-- MAX_LINES, va `body_core` bien no thanh `scan_state = "config_trunc"`.
local MAX_CONFIG_BYTES = 65536
_M.MAX_CONFIG_BYTES = MAX_CONFIG_BYTES

-- `.htaccess` noi tiep dong bang gach nguoc cuoi dong. Khong go thi
-- `AddType \<newline> application/x-httpd-php .jpg` lot. Noi TRUOC khi tach dong.
local BACKSLASH = string.char(92)

-- Tra ve cac dong (da noi tiep neu `kind` cho phep), va `incomplete`.
--
-- ── NOI TIEP DONG CHI DUNG CHO APACHE ───────────────────────────────
--
-- Ban truoc noi tiep dong cho CA HAI dinh dang. Sai theo thiet ke: `.htaccess` la
-- cu phap Apache (gach nguoc cuoi dong = noi dong), con `.user.ini`/`php.ini` la
-- INI cua Zend, mot dinh dang KHAC khong co luat do. Ap cu phap cua dinh dang nay
-- cho dinh dang kia thi khong the dung — bat ke ket qua cu the ra sao.
--
-- Hau qua theo huong SAI AN (false negative), nen phai sua: neu PHP KHONG noi dong
-- thi `auto_prepend_file=<gach nguoc>` la mot gia tri KHONG RONG (chinh ky tu gach
-- nguoc), trong khi ta noi dong thanh `auto_prepend_file= none` roi doc thanh
-- "none" = vo hieu hoa, tuc BO QUA mot cau hinh co tac dung.
--
-- ── TOI KHONG DO DUOC CAI NAY BANG ORACLE ───────────────────────────
--
-- Da thu dung oracle `php-cgi` tren WSL: bon ca deu tra `string(0) ""`, KE CA ca
-- DOI CHUNG DUONG (`auto_prepend_file=/duong/dan/that.php`) va ca phep thu
-- prepend mot tep that. Nen `.user.ini` khong duoc doc trong moi truong do — phep
-- do HONG, khong phai "PHP im lang". Ghi lai o day thay vi de mot ket luan dua
-- tren mot oracle da that bai doi chung duong ([[feedback-read-log-schema-first]]).
--
-- Sua theo THIET KE (moi dinh dang mot cu phap), khong theo mot con so chua do
-- duoc. Neu mai do duoc tren fleet thi chi can doi phan `apache` o day.
local function config_lines(s, kind)
    local lines, n, truncated = {}, 0, false
    if kind == "apache" then
        -- Noi tiep dong: gach nguoc + xuong dong -> mot khoang trang.
        s = s:gsub(BACKSLASH .. "\r?\n[ \t]*", " ")
    end
    for line in (s .. "\n"):gmatch("([^\n]*)\n") do
        if line:sub(-1) == "\r" then line = line:sub(1, -2) end
        n = n + 1
        if n > MAX_LINES then truncated = true; break end
        if #line > MAX_LINE_LEN then
            -- Cat dong DAI, nhung van soi phan dau: mot directive that nam o dau
            -- dong. Danh dau `incomplete` vi phan bi cat co the mang thu khac.
            line = line:sub(1, MAX_LINE_LEN)
            truncated = true
        end
        lines[#lines + 1] = line
    end
    return lines, truncated
end

-- Bo chu thich va khoang trang hai dau. `#` cho `.ini`, `;` cho `.ini`, `#` cho
-- Apache. Apache KHONG co chu thich giua dong (mot `#` giua dong la ky tu thuong),
-- con `.ini` thi co — nen xu ly rieng theo `kind`.
local function strip(line, kind)
    if kind == "ini" then
        -- `.ini`: `;` va `#` bat dau chu thich o BAT KY dau ngoai nhay.
        local out, quote = {}, nil
        for i = 1, #line do
            local c = line:sub(i, i)
            if quote then
                if c == quote then quote = nil end
                out[#out + 1] = c
            elseif c == '"' or c == "'" then
                quote = c
                out[#out + 1] = c
            elseif c == ";" or c == "#" then
                break
            else
                out[#out + 1] = c
            end
        end
        line = table.concat(out)
    elseif line:find("^%s*#") then
        -- Apache: chi dong BAT DAU bang `#` la chu thich.
        --
        -- HOM NAY nhanh nay du thua, va ghi ra vi mot nhanh khong the kich hoat thi
        -- khong ai biet no con dung hay khong: mau tach directive la `^([%a_]+)%s`,
        -- doi CHU CAI o dau dong, nen mot dong `# AddType ...` khong khop du co nhanh
        -- nay hay khong (da do: dot bien bo nhanh nay khong lam test nao do). Giu lai
        -- vi mau kia co the doi — va luc do dong chu thich SE lot neu khong co day.
        return ""
    end
    return (line:gsub("^%s+", ""):gsub("%s+$", ""))
end

-- Bo nhay bao quanh mot gia tri, neu co.
local function unquote(v)
    local q = v:sub(1, 1)
    if (q == '"' or q == "'") and v:sub(-1) == q and #v >= 2 then
        return v:sub(2, -2)
    end
    return v
end

-- ── 3. The mo PHP ───────────────────────────────────────────────────────────
--
-- `body_core.find_php_tag` la nguon DUY NHAT cua phep tim nay (`<?php` va `<?=`).
-- KHONG cai lai o day: hai ban cai dat cua cung mot phep tim da lech that mot lan
-- trong file nay — ban `ngx.re` cho query string khong `lower()` lai sau moi vong
-- giai ma, nen `%50hp%3A%2F%2Finput` lot. `body_core` goi truc tiep, nen ham nay chi
-- ton tai cho duong khong-multipart va cho test.

-- ── Cong vao: NOI DUNG mot part + TEN cua chinh part do ─────────────────────
--
-- `name_flags` quyet dinh nhom nao chay, dung nhu nguoi dung yeu cau: chi soi
-- directive handler khi ten la `.htaccess`, chi soi autoload khi ten la
-- `.user.ini`/`php.ini`. Do KHONG phai toi uu toc do — do la DO CHINH XAC: mot bai
-- viet chua chu `AddHandler` khong duoc ban, va mot `.txt` chua `auto_prepend_file`
-- cung khong.
--
-- Tra ve `flags, incomplete`:
--   `flags`      bang co (`handler`, `autoload`), hoac `nil` khi khong co co nao
--   `incomplete` `true` khi tep cau hinh bi cat giua chung (vuot MAX_LINES hoac
--                dong qua dai) — CHUA SOI HET, khong phai sach
--
-- `php_tag` KHONG o day: `body_core` dat no theo khoang byte de khong sao chep noi
-- dung tep. File nay chi xu ly hai nhom can DOC THEO DONG.
--
-- ── NHAN KHOANG BYTE, KHONG NHAN CHUOI DA SAO CHEP ──────────────────
--
-- `from`/`to` la vi tri trong `body` (1-based, `to` bao gom). Goi voi mot chuoi
-- (khong `from`/`to`) van chay — bo test goi kieu do — nhung duong PRODUCTION
-- PHAI di qua khoang byte, vi day la noi duy nhat quyet dinh duoc "sao chep bao
-- nhieu". Truoc ban nay `body_core` lam `body:sub(rg[1], rg[2])` tuc sao chep TOAN
-- part roi moi vao day, nen `MAX_CONFIG_BYTES` o duoi khong cuu duoc gi.
function _M.scan_part(content, name_flags, from, to)
    if type(content) ~= "string" or content == "" then return nil, false end

    -- Cat theo byte NGAY TAI DAY, truoc moi phep sao chep hay quet nao. Ba viec
    -- nang nhat (`sub`, `gsub` noi tiep dong, `s .. "\n"`) deu dung sau dong nay
    -- nen ca ba chi con thay toi da `MAX_CONFIG_BYTES`.
    local over = false
    if from then
        to = to or #content
        if to - from + 1 > MAX_CONFIG_BYTES then
            to = from + MAX_CONFIG_BYTES - 1
            over = true
        end
        content = content:sub(from, to)
    elseif #content > MAX_CONFIG_BYTES then
        content = content:sub(1, MAX_CONFIG_BYTES)
        over = true
    end

    local kind
    if name_flags == "upload_apache_config" then kind = "apache"
    elseif name_flags == "upload_user_ini" or name_flags == "upload_php_ini" then
        -- CUNG parser cho ca hai ten: cung mot directive, cung mot co che. Tach o
        -- TEN (`name_flags`) va o policy (`SAME_PART`), khong tach o day.
        kind = "ini"
    else
        -- Ten khong phai tep cau hinh: khong nhom nao ap dung. `upload_config_case`
        -- (`.HTACCESS`) CO Y khong vao day — no la mot nhan rieng cho bien the hoa
        -- thuong, va neu mai so lieu cho thay no la tan cong that thi mo them o
        -- policy, khong mo o day.
        return nil, false
    end

    local lines, truncated = config_lines(content, kind)
    local flags = nil
    for i = 1, #lines do
        local line = strip(lines[i], kind)
        if line ~= "" then
            if kind == "apache" then
                -- `Directive gia_tri...` — tach tu dau tien.
                local d, rest = line:match("^([%a_]+)%s+(.+)$")
                if d then
                    local dl = d:lower()
                    if HANDLER_DIRECTIVES[dl] then
                        -- CHI argument DAU TIEN, khong phai ca dong: cu phap cua ca
                        -- bon directive dat handler/mime o token thu nhat, va duoi
                        -- tep di SAU. Quet ca dong lam `AddType text/plain .php`
                        -- thanh `handler` — nguoc han y nghia cua chinh dong do.
                        if maps_to_executor(first_arg(rest):lower()) then
                            flags = flags or {}
                            flags.handler = true
                        end
                    elseif dl == "options" and options_enables_exec(rest) then
                        flags = flags or {}
                        flags.handler = true
                    end
                end
            else
                -- `.ini`: `khoa = gia_tri`.
                local k, v = line:match("^([%w_.]+)%s*=%s*(.*)$")
                if k and AUTOLOAD_DIRECTIVES[k:lower()] then
                    v = unquote((v:gsub("%s+$", "")))
                    -- Gia tri RONG khong nap gi ca (`auto_prepend_file =`), nen no
                    -- khong phai mot duong chay ma. Bat no la nhan FP tu chinh cau
                    -- hinh hop le cua khach (dong nay co that trong nhieu php.ini de
                    -- TAT tinh nang do).
                    if v ~= "" and v:lower() ~= "none" then
                        flags = flags or {}
                        flags.autoload = true
                    end
                end
            end
        end
    end
    -- `over` (cat theo byte) hop voi `truncated` (cat theo dong/do dai dong): ca
    -- hai deu la "CHUA SOI HET", va ca hai phai den duoc `scan_state`.
    return flags, (truncated or over)
end

-- Chi de test va de hop dong doi chieu.
_M.HANDLER_DIRECTIVES  = HANDLER_DIRECTIVES
_M.AUTOLOAD_DIRECTIVES = AUTOLOAD_DIRECTIVES
_M.MAX_LINES           = MAX_LINES
_M.MAX_LINE_LEN        = MAX_LINE_LEN

return _M
