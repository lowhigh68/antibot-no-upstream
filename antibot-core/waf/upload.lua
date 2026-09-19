-- upload.lua — P1: soi TEN FILE trong upload multipart.
--
-- ── VI SAO LA MOT FILE RIENG, KHONG NHET VAO `args.lua` ─────────────
--
-- `args.lua` tra loi "gia tri tham so nay co chua mau tan cong khong". Day tra
-- loi mot cau KHAC: "file nay, neu dap xuong dia va co ai goi URL cua no, thi
-- SERVER co chay nó khong". Cau thu hai khong nhin vao noi dung mau nao — no
-- nhin vao PHAN MO RONG va cach Apache/PHP-FPM anh xa duoi sang handler.
--
-- BAT BUOC LA LUA THUAN, khong `ngx.*`: `body_core` goi file nay, va
-- `body_core` chay trong `ngx.run_worker_thread` — mot VM KHONG co API `ngx`.
-- Cung ly do `args.lua` uy quyen `check` sang `body_core`. Mot goi `ngx.re.find`
-- o day khong hong luc bien dich; no hong luc co than request tran ra dia, tuc
-- dung nhom upload lon — nhom dang quan tam nhat.
--
-- ── VI SAO KHONG PHAI "QUET CHU KY WEBSHELL" ────────────────────────
--
-- `body_core.scan` DA co `php` = than chua `<?php` / `<?=`, va no DA la tin
-- hieu trong so 50 (`waf_body_php` trong `compute.lua`). Nen P1 KHONG phai di
-- tu 0 len co. Viec cua no la bit cac duong ma `<?php` KHONG xuat hien:
--
--   shell.php chua `<?php`        -> `waf_body_php` da bat (50d)
--   shell.phtml / .php5 / .phar   -> da bat, P1 cong them "duoi chay duoc"
--   x.php.jpg  (duoi kep)         -> tuy noi dung; P1 bat duoc ten
--   .htaccess  (AddType .jpg)     -> `waf_body_php` MU — khong co `<?php`
--   eval(base64_decode(...))      -> `waf_body_php` MU — khong co the mo
--
-- Hai dong cuoi la ly do P1 ton tai. Khong phai "them mau cho chac".
--
-- ── TRONG SO 0 ──────────────────────────────────────────────────────
--
-- Cung khuon da dung cho `waf_arg`/`waf_body_arg`, va la ly do
-- `arg_null_byte` khong pha 43 domain: luat chay, ghi log, KHONG cong diem cho
-- toi khi co so do. Tin hieu trong so 0 cung KHONG duoc co mat trong
-- `waf_signal()` — xem `waf/CLAUDE.md`, phan hop dong hai chieu do
-- `contract_test` gac.

local _M = {}

-- ── Duoi CHAY DUOC tren server ──────────────────────────────────────
--
-- Tieu chi vao bang nay HEP va kiem tra duoc: co cau hinh Apache/LiteSpeed nao
-- mac dinh anh xa duoi nay sang handler PHP khong. KHONG phai "duoi nghe nguy
-- hiem".
--
-- `.phar` co trong bang vi `php_value` mac dinh cho phep, va mot phar duoc
-- `include` la chay ma. `.inc` thi KHONG — no khong duoc anh xa sang PHP handler
-- theo mac dinh; no chi nguy hiem qua LFI, ma LFI la duong `args.lua` gac va
-- `fim.sh` phat hien. Dua `.inc` vao la bat oan moi file `.inc` cua theme that.
--
-- `.phtml` `.pht` `.php3..8` nam trong `AddHandler`/`AddType` mac dinh cua
-- nhieu ban Apache va cPanel/DA template.
--
-- CHUA KIEM TREN DAN MAY NAY. Bang nay dung tu tai lieu chung, khong tu
-- `/usr/local/apache2/conf` cua 5 may. Phai kiem truoc khi nang trong so khoi 0:
--     grep -rniE 'AddHandler|AddType' /usr/local/apache2/conf/ | grep -i php
-- Neu may nay anh xa duoi KHAC (vd `.php-single`) thi bang thieu; neu no KHONG
-- anh xa `.pht`/`.php3` thi bang rong hon thuc te — huong thu hai chi ton mot
-- dong log trong so 0, huong thu nhat la lo that. Do la ly do lenh kiem nam
-- day chu khong nam trong dau toi.
local EXEC_EXT = {
    php = true, php3 = true, php4 = true, php5 = true, php6 = true,
    php7 = true, php8 = true, phps = true, phtml = true, pht = true,
    phar = true, phtm = true,
}

-- Ten file CAU HINH — nguy hiem vi no doi cach server doi xu voi CAC file khac.
-- `.htaccess` chua `AddType application/x-httpd-php .jpg` bien moi anh JPEG
-- trong thu muc do thanh ma chay duoc, va KHONG chua `<?php` nen
-- `waf_body_php` mu hoan toan. Day la duong lot ma P1 sinh ra de bit.
local CONFIG_NAME = {
    [".htaccess"] = true, [".htpasswd"] = true, [".user.ini"] = true,
    ["php.ini"]    = true, ["web.config"] = true,
}

-- ── Chuan hoa ten file ─────────────────────────────────────────────
--
-- Chi lay THANH PHAN CUOI cua duong dan. Ke gui dieu khien chuoi nay, va
-- `filename="../../wp-config.php"` thi phan dang quan tam la `wp-config.php`.
-- Ca hai dau phan cach: Windows client gui `\` that, va PHP tren Linux cung
-- coi `\` la ky tu ten file binh thuong nen `a\b.php` la MOT ten file co duoi
-- `.php`.
local function basename(s)
    local last = 0
    for i = 1, #s do
        local c = s:sub(i, i)
        if c == "/" or c == "\\" then last = i end
    end
    return s:sub(last + 1)
end

-- Cat duoi TRAILING mà server bo qua khi anh xa handler.
--
-- Apache anh xa `shell.php.` (dau cham cuoi) va `shell.php ` (khoang trang
-- cuoi) sang PHP tren mot so cau hinh, va `shell.php::$DATA` la lo NTFS ADS.
-- Khong cat thi `duoi = ""` hoac `duoi = "php "` va luat truot.
local function strip_tail(s)
    local out = s
    -- NTFS alternate data stream
    local ads = out:find("::", 1, true)
    if ads then out = out:sub(1, ads - 1) end
    -- byte NUL cat chuoi: `shell.php\0.jpg` -> server thay `shell.php`
    local nul = out:find("\0", 1, true)
    if nul then out = out:sub(1, nul - 1) end
    -- khoang trang / dau cham / dau ngoac cuoi
    while #out > 0 do
        local c = out:sub(-1)
        if c == "." or c == " " or c == "\t" or c == "\r" or c == "\n" then
            out = out:sub(1, -2)
        else
            break
        end
    end
    return out
end

-- Tra ve DANH SACH duoi, tu phai sang trai. `x.php.jpg` -> {"jpg","php"}.
--
-- VI SAO DUYET HET CHU KHONG CHI LAY CAI CUOI. Apache voi `AddHandler` (khong
-- phai `SetHandler`) anh xa theo BAT KY duoi nao trong ten, khong chi duoi cuoi
-- — `x.php.jpg` chay nhu PHP tren cau hinh mac dinh cua nhieu ban. Day la mot
-- trong nhung duong upload webshell pho bien nhat va no KHONG doi hoi loi nao
-- khac. Gioi han 6 duoi: `a.b.c.d.e.f.g.php` la du sau roi, va tran de ke gui
-- khong bat ta duyet mot ten file 512 byte day dau cham.
local MAX_EXT = 6

local function extensions(name)
    local exts, n = {}, 0
    local tail = #name
    while n < MAX_EXT do
        local dot = 0
        for i = tail, 1, -1 do
            if name:sub(i, i) == "." then dot = i; break end
        end
        if dot == 0 then break end
        local e = name:sub(dot + 1, tail):lower()
        if e ~= "" then n = n + 1; exts[n] = e end
        tail = dot - 1
        if tail <= 0 then break end
    end
    return exts
end

-- ── Luat ────────────────────────────────────────────────────────────
--
-- Tra ve MOT rule_id, uu tien giam dan. Cung khuon `check_args`: mot lan khop
-- la du de ghi log, va thu tu co dinh nen so lieu doc duoc on dinh.
--
--   upload_exec_ext     duoi chay duoc o VI TRI CUOI — `shell.php`
--   upload_exec_double  duoi chay duoc KHONG o cuoi — `x.php.jpg`
--   upload_config       ten file cau hinh — `.htaccess`
--
-- KHONG co luat "khong co duoi" hay "duoi la la": khach upload file khong duoi
-- va duoi la that (`.dwg`, `.ai`, `.sketch`, `.psd`). Bat oan ca kho tai lieu
-- cua khach de doi lay mot vung phu ma `waf_body_php` da phu.
function _M.check_filename(raw)
    if type(raw) ~= "string" or raw == "" then return nil end

    local name = strip_tail(basename(raw))
    if name == "" then return nil end

    local lower = name:lower()
    if CONFIG_NAME[lower] then return "upload_config" end

    local exts = extensions(name)
    if #exts == 0 then return nil end

    if EXEC_EXT[exts[1]] then return "upload_exec_ext" end
    for i = 2, #exts do
        if EXEC_EXT[exts[i]] then return "upload_exec_double" end
    end
    return nil
end

_M.EXEC_EXT    = EXEC_EXT
_M.CONFIG_NAME = CONFIG_NAME
_M.basename    = basename
_M.strip_tail  = strip_tail
_M.extensions  = extensions

return _M
