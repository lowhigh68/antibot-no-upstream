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

-- Gia tri co anh xa sang mot bo thuc thi. `low` la gia tri DA lower.
local function maps_to_executor(low)
    return low:find("php", 1, true) ~= nil
        or low:find("cgi", 1, true) ~= nil
        or low:find("proxy:unix:", 1, true) ~= nil
        or low:find("proxy:fcgi:", 1, true) ~= nil
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

-- `.htaccess` noi tiep dong bang gach nguoc cuoi dong. Khong go thi
-- `AddType \<newline> application/x-httpd-php .jpg` lot. Noi TRUOC khi tach dong.
local BACKSLASH = string.char(92)

-- Tra ve `iterator` cac dong da noi tiep, va `incomplete`.
local function config_lines(s)
    local lines, n, truncated = {}, 0, false
    -- Noi tiep dong: gach nguoc + xuong dong -> mot khoang trang.
    s = s:gsub(BACKSLASH .. "\r?\n[ \t]*", " ")
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
function _M.scan_part(content, name_flags)
    if type(content) ~= "string" or content == "" then return nil, false end

    local kind
    if name_flags == "upload_apache_config" then kind = "apache"
    elseif name_flags == "upload_php_config" then kind = "ini"
    else
        -- Ten khong phai tep cau hinh: khong nhom nao ap dung. `upload_config_case`
        -- (`.HTACCESS`) CO Y khong vao day — no la mot nhan rieng cho bien the hoa
        -- thuong, va neu mai so lieu cho thay no la tan cong that thi mo them o
        -- policy, khong mo o day.
        return nil, false
    end

    local lines, truncated = config_lines(content)
    local flags = nil
    for i = 1, #lines do
        local line = strip(lines[i], kind)
        if line ~= "" then
            if kind == "apache" then
                -- `Directive gia_tri...` — tach tu dau tien.
                local d, rest = line:match("^([%a_]+)%s+(.+)$")
                if d then
                    local dl = d:lower()
                    if HANDLER_DIRECTIVES[dl] and maps_to_executor(rest:lower()) then
                        flags = flags or {}
                        flags.handler = true
                    elseif dl == "options" and rest:lower():find("execcgi", 1, true) then
                        -- `Options +ExecCGI` / `Options ExecCGI`. `-ExecCGI` thi KHONG:
                        -- do la TAT thuc thi, nguoc han y nghia.
                        if not rest:lower():find("%-execcgi") then
                            flags = flags or {}
                            flags.handler = true
                        end
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
    return flags, truncated
end

-- Chi de test va de hop dong doi chieu.
_M.HANDLER_DIRECTIVES  = HANDLER_DIRECTIVES
_M.AUTOLOAD_DIRECTIVES = AUTOLOAD_DIRECTIVES
_M.MAX_LINES           = MAX_LINES

return _M
