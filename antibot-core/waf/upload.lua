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
-- TREN DAN MAY NAY anh xa duoi nay sang handler PHP khong. KHONG phai "duoi
-- nghe nguy hiem".
--
-- ── DA DO 19-09-2026, va so lieu BAC BO ban dau cua bang nay ────────
--
-- Ban dau toi viet 12 duoi tu tai lieu chung, va ghi trong chu thich rang
-- `.inc` "KHONG duoc anh xa sang PHP handler theo mac dinh". SAI, va con te hon
-- la toi da cai phong doan do vao `contract_test` [28] nhu mot BAT BIEN — tuc
-- khoa cung mot dieu sai, va nguoi sau sua dung se bi test bao do.
--
-- Do that tren fleet:
--     /etc/httpd/conf/extra/httpd-hostname.conf:4
--         AddHandler "proxy:unix:.../php74/sockets/webapps.sock|fcgi://..."
--                    .inc .php .phtml
--     /etc/httpd/conf/extra/httpd-php-handlers.conf:5,12
--         AddHandler application/x-httpd-lsphp  .inc .php .php5 .phtml
--
-- Hai ket luan, ca hai nguoc chieu nhau:
--
--   1. `.inc` LA MA CHAY DUOC tren dan may nay — dung ngay canh `.php` trong ca
--      ba dong. Bo no ra la mot lo THAT: webshell ten `x.inc` chay binh thuong.
--   2. `.php3 .php4 .php6 .php7 .php8 .pht .phtm .phps .phar` KHONG co trong
--      BAT KY dong nao. Bang cu rong gap ba lan thuc te.
--
-- Huong (2) chi ton mot dong log o trong so 0, nhung no lam BAN phep do: dem
-- `upload_exec_ext` ma khong biet bao nhieu lan la duoi that su chay duoc thi
-- khong the dung con so do quyet dinh trong so. Nen tach tang.
--
-- ── VONG DO THU HAI: DirectAdmin chon handler PER-DOMAIN ─────────────
--
-- Lenh `grep -i php` o vong mot KHONG du, vi DA sinh vhost theo BA nhanh loai
-- tru nhau, va ba nhanh do co tap duoi KHAC nhau:
--
--     HAVE_PHP1_FPM   ->  .php .inc .phtml       (AddHandler proxy:unix)
--     HAVE_PHP1_FCGI  ->  .php               chi (SetHandler fcgid-script)
--     HAVE_PHP1_CLI   ->  .php               chi (AddHandler x-httpd-php)
--
-- Do tren fleet: **74 / 0 / 0** — TOAN BO 74 domain dung nhanh FPM, khong domain
-- nao FCGI hay LiteSpeed. Nen `.inc` chay duoc tren MOI domain, khong phai chi
-- mot nhanh. Moi lo "`.inc` gay FP tren da so fleet" BI BAC BO bang so dem, va
-- y dinh tach `.inc` thanh nhan rieng da bo.
--
-- `FilesMatch` that trong `httpd-php-handlers.conf`:
--     <FilesMatch "\.(inc|php|php5|phtml)$">     (dong 4 va 11)
-- Khop CHINH XAC `PHP_EXT` duoi day. Khong thieu, khong thua.
--
-- ── MOT CHO TOI DOC SAI TRONG CHINH VONG DO NAY ─────────────────────
--
-- Template DA co `<FilesMatch "\.(php53|php54|...|php82)$">` o BA cho, va toi
-- da ket luan ngay "thieu 12 duoi, `shell.php74` chay duoc". SAI — than khoi do
-- la:
--     Order Allow,Deny
--     Deny from all
-- DA CHAN chung co chu y. Chung KHONG chay duoc, va them vao `PHP_EXT` la sai.
-- Toi doc CAU TRUC (`FilesMatch` co ten duoi) ma khong doc NOI DUNG khoi.
--
-- ── `.fcgi`: co trong `AddHandler` nhung phu thuoc CGI ──────────────
--
-- `grep -hoE 'AddHandler[^\n]*' | grep '^\.'` tra ve duy nhat `.fcgi` ngoai tap
-- PHP. Nhung trong `<Directory>` cua docroot, DA dat
--     Options -ExecCGI -Includes +IncludesNOEXEC
-- va dat no CHI KHI `CGI=""` (tuc CGI TAT). Domain BAT CGI thi co
-- `ScriptAlias /cgi-bin/` va KHONG co `-ExecCGI` => `.fcgi` `.cgi` `.pl` chay
-- duoc trong `/cgi-bin/`.
--
-- CHUA quyet dinh, vi con thieu mot so dem: bao nhieu domain co
-- `ScriptAlias /cgi-bin/`. Neu 0 thi khong them gi. May code tay la noi co kha
-- nang bat CGI nhat (site tu viet hay dung Perl CGI), nen phai do tren CA 5 MAY
-- chu khong chi may WordPress:
--     grep -c 'ScriptAlias /cgi-bin/' /usr/local/directadmin/data/users/*/httpd.conf \
--         | grep -v ':0$' | wc -l
--
-- ── Vi sao TACH TANG chu khong chi cat bang ─────────────────────────
--
-- Cat `.phar`/`.phps` ra khoi bang la mat kha nang phat hien; giu chung chung
-- mot rule_id voi `.php` la mat kha nang DO. Tach ra giai quyet ca hai: cung
-- ban, khac nhan, nen `waf.log` dem duoc rieng va ngay nang trong so thi nang
-- duoc TUNG TANG.
--
-- `PHP_EXT`    — DA XAC MINH tren fleet, HAI vong do doc lap: `AddHandler` va
--                `FilesMatch "\.(inc|php|php5|phtml)$"`. Ca hai cho cung mot
--                tap. `.inc` o day chu khong o tang duoi, va 74/74 domain dung
--                nhanh FPM nen no chay tren MOI domain.
-- `PHP_LEGACY` — KHONG thay trong bat ky `AddHandler`/`FilesMatch` nao tren
--                fleet. Voi `.php53..php82` thi con manh hon the: DA co
--                `Deny from all` tuong minh cho chung. Van soi vi mot may moi
--                cai hay mot `.htaccess` cua khach co the bat — nhung dem
--                RIENG, vi tron vao `PHP_EXT` lam con so kia mat nghia.
local PHP_EXT = {
    php = true, php5 = true, phtml = true, inc = true,
}

local PHP_LEGACY = {
    php3 = true, php4 = true, php6 = true, php7 = true, php8 = true,
    pht  = true, phtm = true, phps = true, phar = true,
}

-- Ten file CAU HINH — nguy hiem vi no doi cach server doi xu voi CAC file khac.
--
-- TACH BA NHOM, khong gop mot `upload_config`. Ly do: tren OpenResty + Apache
-- tren Linux, ba nhom nay co suc manh KHAC HAN nhau, va gop lai thi phep do
-- khong tra loi duoc cau hoi duy nhat dang quan tam — "tin hieu nay den tu
-- `.htaccess` hay tu `web.config`".
--
-- `APACHE_CONFIG` — doi HANDLER cua cac file khac. `.htaccess` chua
--   `AddType application/x-httpd-php .jpg` bien moi anh JPEG trong thu muc do
--   thanh ma chay duoc, va KHONG chua `<?php` nen `waf_body_php` mu hoan toan.
--   Day la nhom manh nhat va la duong lot ma P1 sinh ra de bit.
-- `PHP_CONFIG` — doi cau hinh PHP (`.user.ini` doc duoc o che do FPM/CGI:
--   `auto_prepend_file` la mot duong chay ma). Manh, nhung hep hon `.htaccess`.
-- `FOREIGN_CONFIG` — `web.config` la IIS, tren stack nay gan nhu KHONG co gia
--   tri thuc thi. Giu lai vi no la dau hieu scanner ro rang, nhung phai dem
--   RIENG: tron no vao `.htaccess` la lam con so `.htaccess` phong len bang
--   luu luong scanner vo hai.
--   `.htpasswd` cung o day — no khong doi handler, chi lo hash mat khau.
local APACHE_CONFIG = {
    [".htaccess"] = true,
}

local PHP_CONFIG = {
    [".user.ini"] = true, ["php.ini"] = true,
}

local FOREIGN_CONFIG = {
    ["web.config"] = true, [".htpasswd"] = true,
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
--   upload_apache_config   `.htaccess` — doi HANDLER cua file khac
--   upload_php_config      `.user.ini` / `php.ini` — `auto_prepend_file`
--   upload_foreign_config  `web.config` / `.htpasswd` — dau hieu scanner
--   upload_php_ext         duoi DA XAC MINH chay duoc, o vi tri cuoi
--   upload_php_double      duoi DA XAC MINH, KHONG o cuoi (`AddHandler`)
--   upload_php_legacy_ext  duoi phu thuoc cau hinh, bat ky vi tri
--
-- SAU nhan chu khong phai HAI, va day khong phai chia nho cho vui: gop lai thi
-- phep do khong tra loi duoc cau hoi quyet dinh trong so — "tin hieu nay den tu
-- `.htaccess` (doi handler cua moi file trong thu muc) hay tu `web.config`
-- (tren stack nay gan nhu vo hai)". Mot nhan gop la mot con so khong dung duoc.
--
-- KHONG co luat "khong co duoi" hay "duoi la la": khach upload file khong duoi
-- va duoi la that (`.dwg`, `.ai`, `.sketch`, `.psd`). Bat oan ca kho tai lieu
-- cua khach de doi lay mot vung phu ma `waf_body_php` da phu.

-- BON GOC NHIN, khong phai mot chuoi da normalize.
--
-- VI SAO. `basename` roi `strip_tail` la mot chuoi da PHA HUY THONG TIN, va voi
-- `shell.php\0/benign.jpg` no chon `benign.jpg`: `basename` thay dau `/` cuoi
-- cung nen lay phan sau NUL. Nhung mot thanh phan ha nguon dung chuoi kieu C
-- (hoac mot ham PHP cu) nhin thay `shell.php` — chuoi DUNG o chinh cho ta khong
-- nhin.
--
-- Chua chac la exploit tren stack hien tai: nginx va PHP hien dai tu choi NUL
-- trong ten file. Nhung phong ve KHONG duoc dua vao mot gia dinh ve tang khac,
-- va gia cua viec kiem bon goc nhin la ba lan `find` tren mot chuoi < 512 byte
-- — do duoc, va chi tra khi request THAT SU co `filename=`.
--
-- Thu tu trong bang la thu tu uu tien khi nhieu goc nhin cung khop: goc nhin
-- DAY DU nhat truoc.
local function canonical_views(raw)
    local views, seen, n = {}, {}, 0
    local function add(v)
        if v and v ~= "" and not seen[v] then
            seen[v] = true; n = n + 1; views[n] = v
        end
    end

    -- 1. Cat NUL/ADS TRUOC roi moi basename — goc nhin cua mot thanh phan dung
    --    chuoi kieu C. Day la goc nhin NGUY HIEM NHAT nen dung dau.
    add(strip_tail(basename(strip_tail(raw))))
    -- 2. basename truoc roi cat — goc nhin cua tang hien dai.
    add(strip_tail(basename(raw)))
    -- 3. Chuoi tho, chi cat duoi: bat ca truong hop khong co dau phan cach nao.
    add(strip_tail(raw))
    return views
end

local function classify_name(name)
    local lower = name:lower()
    if APACHE_CONFIG[lower]  then return "upload_apache_config"  end
    if PHP_CONFIG[lower]     then return "upload_php_config"     end
    if FOREIGN_CONFIG[lower] then return "upload_foreign_config" end

    local exts = extensions(name)
    if #exts == 0 then return nil end

    if PHP_EXT[exts[1]] then return "upload_php_ext" end
    for i = 2, #exts do
        if PHP_EXT[exts[i]] then return "upload_php_double" end
    end
    -- Tang legacy KHONG phan biet vi tri: no da la "phu thuoc cau hinh", nen
    -- tach them theo vi tri chi lam nho dan so ma khong them thong tin.
    for i = 1, #exts do
        if PHP_LEGACY[exts[i]] then return "upload_php_legacy_ext" end
    end
    return nil
end

function _M.check_filename(raw)
    if type(raw) ~= "string" or raw == "" then return nil end

    local views = canonical_views(raw)
    for i = 1, #views do
        local rule = classify_name(views[i])
        if rule then return rule end
    end
    return nil
end

_M.PHP_EXT        = PHP_EXT
_M.PHP_LEGACY     = PHP_LEGACY
_M.APACHE_CONFIG  = APACHE_CONFIG
_M.PHP_CONFIG     = PHP_CONFIG
_M.FOREIGN_CONFIG = FOREIGN_CONFIG
_M.basename       = basename
_M.strip_tail     = strip_tail
_M.extensions     = extensions
_M.canonical_views = canonical_views

return _M
