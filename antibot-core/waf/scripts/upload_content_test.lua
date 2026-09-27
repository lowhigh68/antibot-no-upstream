-- T — bo test cho waf/upload_content.lua (buoc 3) va bang chung CUNG MOT PART
-- (buoc 4). CHAY: ./run.sh
--
-- Cau hoi ma bo nay tra loi: "noi dung nay, TRONG mot tep co ten nhu vay, co phai
-- mot duong chay ma khong". Khac `upload_test.lua` (chi hoi ve TEN) va khac
-- `body_test.lua` (hoi ve vung cua than).
local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end
for _, m in ipairs({ "upload", "upload_content", "upload_magic", "body_core", "body_worker" }) do
    package.preload["antibot.waf." .. m] = function()
        return dofile(SRC .. "waf/" .. m .. ".lua")
    end
end
local uc       = require "antibot.waf.upload_content"
local core     = require "antibot.waf.body_core"
local registry = dofile(SRC .. "waf/registry.lua")

local pass, fail = 0, 0
local function check(name, got, want)
    if got == want then pass = pass + 1
    else
        fail = fail + 1
        io.write(string.format("HONG  %s\n      duoc=%s  mong=%s\n",
                 name, tostring(got), tostring(want)))
    end
end
local function flag_str(f, key)
    if type(f) ~= "table" then return "-" end
    return f[key] and key or "-"
end

-- ══ 1. `.htaccess`: GIA TRI phai anh xa sang PHP/CGI ════════════════════════
--
-- Yeu cau cua nguoi dung: "phai kiem gia tri co anh xa sang PHP/CGI, khong match
-- ten directive dung rieng". Thieu dieu do thi moi `.htaccess` co
-- `AddType text/css .css` deu ban — mot may FP tu mot luat le ra chinh xac cao.
io.write("upload_content: .htaccess — GIA TRI quyet dinh, khong phai ten directive\n")
local function ht(content) return flag_str(uc.scan_part(content, "upload_apache_config"), "handler") end

-- PHAI BAN — gia tri anh xa sang mot bo thuc thi.
check("AddType x-httpd-php", ht("AddType application/x-httpd-php .jpg"), "handler")
-- Gia tri THAT tren fleet (do 19-09): LiteSpeed PHP va socket FPM. Mot danh sach
-- chuoi co dinh kieu `x-httpd-php` se TRUOT ca hai.
check("AddHandler x-httpd-lsphp (gia tri that tren fleet)",
      ht("AddHandler application/x-httpd-lsphp .jpg"), "handler")
check("AddHandler socket FPM (gia tri that tren fleet)",
      ht("AddHandler \"proxy:unix:/usr/local/php74/sockets/webapps.sock|fcgi://localhost\" .jpg"),
      "handler")
check("SetHandler php-script", ht("SetHandler php-script"), "handler")
check("SetHandler proxy fcgi", ht("SetHandler proxy:fcgi://127.0.0.1:9000"), "handler")
check("ForceType x-httpd-php", ht("ForceType application/x-httpd-php"), "handler")
check("AddHandler cgi-script", ht("AddHandler cgi-script .jpg"), "handler")
check("Options +ExecCGI", ht("Options +ExecCGI"), "handler")
check("khong phan biet hoa thuong", ht("addtype APPLICATION/X-HTTPD-PHP .jpg"), "handler")

-- PHAI IM — `.htaccess` hop le cua khach. Day la nhom quyet dinh FP.
check("RewriteRule", ht("RewriteRule ^a$ b [L]"), "-")
check("AddType text/css", ht("AddType text/css .css"), "-")
check("AddType image/webp", ht("AddType image/webp .webp"), "-")
check("Options -Indexes", ht("Options -Indexes"), "-")
check("Options -ExecCGI (TAT thuc thi)", ht("Options -ExecCGI"), "-")
check("ten directive dung rieng", ht("AddHandler"), "-")
check("chu AddHandler trong mot cau van", ht("Toi doc ve AddHandler hom qua"), "-")
check("Deny from all", ht("Order Allow,Deny\nDeny from all"), "-")
check("tep rong", ht(""), "-")
-- `#` dau dong la chu thich cua Apache.
check("dong chu thich", ht("# AddType application/x-httpd-php .jpg"), "-")
check("chu thich roi dong THAT", ht("# ghi chu\nAddType application/x-httpd-php .jpg"),
      "handler")
-- Noi tiep dong bang gach nguoc: khong go thi directive that lot.
check("noi tiep dong bang gach nguoc",
      ht("AddType " .. string.char(92) .. "\n  application/x-httpd-php .jpg"), "handler")

-- ══ 2. `.user.ini` / `php.ini`: CO DUNG CHUNG, tach o name_flags ════════════
--
-- Nguoi dung chot 27-09: hai ten dung chung co `autoload`, tach o `name_flags` va o
-- composite policy. Cung mot directive, cung mot co che — nen mot co.
io.write("\nupload_content: .user.ini / php.ini — co autoload dung chung\n")
local function ini(content) return flag_str(uc.scan_part(content, "upload_php_config"), "autoload") end

check("auto_prepend_file", ini("auto_prepend_file=/tmp/shell.jpg"), "autoload")
check("auto_append_file", ini("auto_append_file = /tmp/x.jpg"), "autoload")
check("co nhay kep", ini('auto_prepend_file="/tmp/shell.jpg"'), "autoload")
check("co nhay don", ini("auto_prepend_file='/tmp/shell.jpg'"), "autoload")
check("khong phan biet hoa thuong", ini("AUTO_PREPEND_FILE=/tmp/x"), "autoload")
check("khoang trang quanh dau bang", ini("auto_prepend_file   =   /tmp/x"), "autoload")

-- PHAI IM — cau hinh hop le cua khach.
check("gia tri RONG (dong TAT tinh nang)", ini("auto_prepend_file="), "-")
check("gia tri none", ini("auto_prepend_file=none"), "-")
check("directive khac", ini("memory_limit=256M"), "-")
check("upload_max_filesize", ini("upload_max_filesize=64M"), "-")
check("chu thich dau cham phay", ini("; auto_prepend_file=/tmp/x"), "-")
check("chu thich thang", ini("# auto_prepend_file=/tmp/x"), "-")
check("chu thich SAU gia tri van ban", ini("memory_limit=256M ; auto_prepend_file"), "-")
-- Nhung mot gia tri THAT khong bi chu thich phia sau lam mat.
check("gia tri that + chu thich phia sau",
      ini("auto_prepend_file=/tmp/x.jpg ; ghi chu"), "autoload")

-- ══ 3. TEN quyet dinh nhom nao chay ═════════════════════════════════════════
--
-- Do KHONG phai toi uu toc do — do la DO CHINH XAC. Mot bai viet chua chu
-- `AddHandler`, hay mot `.txt` chua `auto_prepend_file`, khong duoc ban.
io.write("\nupload_content: TEN quyet dinh nhom nao chay\n")
check("noi dung .htaccess trong mot tep ten sach",
      flag_str(uc.scan_part("AddType application/x-httpd-php .jpg", false), "handler"), "-")
check("noi dung .user.ini trong mot tep ten sach",
      flag_str(uc.scan_part("auto_prepend_file=/tmp/x", false), "autoload"), "-")
check("noi dung .htaccess trong mot tep .php",
      flag_str(uc.scan_part("AddType application/x-httpd-php .jpg", "upload_php_ext"), "handler"), "-")
-- `.HTACCESS` (bien the hoa thuong) CO Y khong vao day: no la mot nhan rieng
-- (`upload_config_case`), va mo them la mo be mat FP ma chua co so do.
check("upload_config_case KHONG chay nhom handler",
      flag_str(uc.scan_part("AddType application/x-httpd-php .jpg", "upload_config_case"), "handler"), "-")
check("nil name_flags", uc.scan_part("AddType application/x-httpd-php .jpg", nil), nil)

-- ══ 4. Soi khong het KHAC sach ══════════════════════════════════════════════
io.write("\nupload_content: soi khong het khac sach\n")
do
    -- Hon MAX_LINES dong: `incomplete` phai true, va do KHONG phai "sach".
    local many = {}
    for i = 1, uc.MAX_LINES + 50 do many[i] = "memory_limit=" .. i .. "M" end
    local flags, partial = uc.scan_part(table.concat(many, "\n"), "upload_php_config")
    check("hon MAX_LINES -> incomplete", partial, true)
    check("hon MAX_LINES -> khong bia ra co", flag_str(flags, "autoload"), "-")
    -- Directive that o dong DAU van bat duoc du tep bi cat.
    local f2, p2 = uc.scan_part("auto_prepend_file=/tmp/x\n" .. table.concat(many, "\n"),
                                "upload_php_config")
    check("cat nhung van bat dong dau", flag_str(f2, "autoload"), "autoload")
    check("va van bao incomplete", p2, true)
end

-- ══ 5. BUOC 5 — bang chung CUNG MOT PART, tren THAN MULTIPART THAT ══════════
--
-- Day la phan quan trong nhat (nguoi dung 27-09). Cau hoi: `shell.php` RONG o part 1
-- cong `<?php` trong mot form field o part 2 co ban giong `shell.php` CHUA `<?php`
-- khong. Voi hai fact toan request thi CO — va do la ly do hai correlation cu khong
-- promote duoc.
io.write("\ncung part: tren than multipart that\n")
local B      = "----WebKitFormBoundaryAbC123"
local MULTI  = "multipart/form-data; boundary=" .. B
local function part(hdr, content)
    return "--" .. B .. "\r\n" .. hdr .. "\r\n\r\n" .. content .. "\r\n"
end
local function mp(parts) return table.concat(parts) .. "--" .. B .. "--\r\n" end
local function field(name, content)
    return part('Content-Disposition: form-data; name="' .. name .. '"', content)
end
local function filepart(fn, content)
    return part('Content-Disposition: form-data; name="f"; filename="' .. fn .. '"', content)
end

-- Tap luat cung-part ma mot than sinh ra, dang chuoi da sap xep.
local function same_part(data)
    local r = core.scan(data, MULTI)
    local out = {}
    for i = 1, #(r.parts or {}) do
        local p = r.parts[i]
        if p.name_flags and type(p.content_flags) == "table" then
            for flag in pairs(p.content_flags) do
                local id = registry.same_part_rule(p.name_flags, flag)
                if id then out[#out + 1] = p.slot .. ":" .. id end
            end
        end
    end
    table.sort(out)
    return #out > 0 and table.concat(out, ",") or "-"
end

-- ── BA ca PHAI KHONG tao composite (danh sach cua nguoi dung) ───────────────
check("(a) shell.php RONG + <?php trong FORM FIELD",
      same_part(mp({ filepart("shell.php", "khong co gi"),
                     field("a", "<?php echo 1;") })), "-")
check("(b) shell.php RONG + example.txt chua ma PHP",
      same_part(mp({ filepart("shell.php", "khong co gi"),
                     filepart("example.txt", "<?php echo 1;") })), "-")
check("(c) .htaccess chi co RewriteRule + tep khac chua PHP",
      same_part(mp({ filepart(".htaccess", "RewriteRule ^a$ b [L]"),
                     filepart("b.txt", "<?php echo 1;") })), "-")

-- ── BON ca PHAI tao composite (danh sach cua nguoi dung) ───────────────────
check("(d) shell.php CHUA <?php",
      same_part(mp({ filepart("shell.php", "<?php echo 1;") })),
      "1:upload_php_executable_content")
check("(e) x.php.jpg CHUA <?php",
      same_part(mp({ filepart("x.php.jpg", "<?php echo 1;") })),
      "1:upload_php_double_content")
check("(f) .htaccess chua AddType application/x-httpd-php .jpg",
      same_part(mp({ filepart(".htaccess", "AddType application/x-httpd-php .jpg") })),
      "1:upload_apache_handler_content")
check("(g) .user.ini chua auto_prepend_file=shell.jpg",
      same_part(mp({ filepart(".user.ini", "auto_prepend_file=shell.jpg") })),
      "1:upload_php_autoload_content")
-- `php.ini` dung CHUNG co va hom nay cung rule id — tach o `name_flags` (ca hai la
-- `upload_php_config`) se lam sau khi so lieu cho thay `php.ini` chiem bao nhieu.
check("(g2) php.ini cung co autoload",
      same_part(mp({ filepart("php.ini", "auto_prepend_file=shell.jpg") })),
      "1:upload_php_autoload_content")

-- ── Dao thu tu part, va them part vo hai ───────────────────────────────────
io.write("\ncung part: thu tu part va part vo hai\n")
check("part nguy hiem dung SAU part vo hai",
      same_part(mp({ field("a", "vo hai"), filepart("ok.jpg", "JFIF"),
                     filepart("shell.php", "<?php echo 1;") })),
      "3:upload_php_executable_content")
check("part nguy hiem dung TRUOC",
      same_part(mp({ filepart("shell.php", "<?php echo 1;"),
                     field("b", "vo hai"), filepart("ok.png", "PNG") })),
      "1:upload_php_executable_content")
-- HAI part nguy hiem: ca hai phai duoc bao, khong dung o part dau.
check("hai part nguy hiem — khong dung o part dau",
      same_part(mp({ filepart("shell.php", "<?php echo 1;"),
                     filepart(".htaccess", "SetHandler php-script") })),
      "1:upload_php_executable_content,2:upload_apache_handler_content")

-- ── Luat phai lay TU CHINH PART, khong tu `up_rule` toan request ────────────
--
-- `up_rule` la luat NGHIEM TRONG NHAT cua ca request, nen trong moi ca o tren no
-- TRUNG voi `name_flags` cua part nguy hiem — va mot ban cai dat lay `up_rule` thay
-- vi `name_flags` se bao XANH het. Ba ca duoi day tach hai gia tri do ra.
--
-- `UP_RANK`: apache_config 7 > php_ext 6 > php_double 5 > php_config 4.
io.write("\ncung part: luat lay tu CHINH part, khong tu up_rule\n")
do
    -- `.htaccess` SACH (chi RewriteRule) + `shell.php` CHUA `<?php`.
    -- `up_rule` = upload_apache_config (rank 7, tu part 1).
    -- Part 2 co `php_tag`, `name_flags` = upload_php_ext.
    -- Lay dung `name_flags` -> upload_php_executable_content.
    -- Lay `up_rule` -> tra cuu (apache_config, php_tag) = NIL, composite BIEN MAT.
    local data = mp({ filepart(".htaccess", "RewriteRule ^a$ b [L]"),
                      filepart("shell.php", "<?php echo 1;") })
    check("up_rule manh hon nam o part KHAC -> van phai bao dung luat",
          same_part(data), "2:upload_php_executable_content")
    check("va up_rule toan request dung la cai manh hon",
          core.scan(data, MULTI).up_rule, "upload_apache_config")

    -- Nguoc lai: `shell.php` SACH + `.user.ini` co autoload.
    -- `up_rule` = upload_php_ext (rank 6) tu part 1; part 2 la upload_php_config.
    -- Lay `up_rule` -> (php_ext, autoload) = NIL.
    local d2 = mp({ filepart("shell.php", "khong co gi"),
                    filepart(".user.ini", "auto_prepend_file=x.jpg") })
    check("up_rule tu part khac -> autoload van bao dung luat",
          same_part(d2), "2:upload_php_autoload_content")
    check("va up_rule dung la php_ext", core.scan(d2, MULTI).up_rule, "upload_php_ext")
end

-- ── Khong chung minh duoc -> KHONG co composite nao ────────────────────────
--
-- `binding = incomplete` cua nguoi dung: khong tao same-part correlation, nhung van
-- giu fact tho de khong fail-open.
io.write("\ncung part: khong chung minh duoc thi khong co composite\n")
do
    -- `filename*=` — PHP khong biet tham so nay, nen than khong chuan tac.
    local nc = mp({ part('Content-Disposition: form-data; name="f"; ' ..
                         "filename*=UTF-8''shell.php", "<?php echo 1;") })
    check("khong chuan tac -> khong composite", same_part(nc), "-")
    local r = core.scan(nc, MULTI)
    check("khong chuan tac -> parts nil", r.parts, nil)
    -- FACT THO van con: khong fail-open.
    check("khong chuan tac -> up_rule VAN bao", r.up_rule, "upload_php_ext")
    check("khong chuan tac -> co php VAN bao", r.php, true)

    -- Hon MAX_PARTS.
    local many = {}
    for i = 1, 70 do many[i] = filepart("shell" .. i .. ".php", "<?php") end
    local over = core.scan(mp(many), MULTI)
    check("hon MAX_PARTS -> parts nil", over.parts, nil)
    check("hon MAX_PARTS -> up_rule VAN bao", over.up_rule, "upload_php_ext")

    -- Tep cau hinh soi khong het: `scan_state` mang ly do, KHONG phai "ok".
    local lines = {}
    for i = 1, uc.MAX_LINES + 20 do lines[i] = "memory_limit=" .. i .. "M" end
    local big = core.scan(mp({ filepart(".user.ini", table.concat(lines, "\n")) }), MULTI)
    check("tep cau hinh bi cat -> scan_state mang ly do",
          big.parts and big.parts[1].scan_state, "config_trunc")
end

-- ── Memory == spill, va giao thuc V8 giu co noi dung ───────────────────────
io.write("\ncung part: memory == spill, V8 giu co noi dung\n")
do
    local tmp = os.tmpname()
    local worker = require "antibot.waf.body_worker"
    local data = mp({ filepart("ok.jpg", "JFIF"),
                      filepart(".htaccess", "AddType application/x-httpd-php .jpg"),
                      filepart("shell.php", "<?php echo 1;") })
    local mem = core.scan(data, MULTI)
    local fh = io.open(tmp, "wb"); fh:write(data); fh:close()
    local sp = core.unpack(worker.scan_file(tmp, MULTI))
    os.remove(tmp)
    local function sig(r)
        local out = {}
        for i = 1, #(r.parts or {}) do
            local p = r.parts[i]
            local names = {}
            if type(p.content_flags) == "table" then
                for k in pairs(p.content_flags) do names[#names + 1] = k end
                table.sort(names)
            end
            out[i] = p.slot .. ":" .. tostring(p.name_flags) .. ":" ..
                     (#names > 0 and table.concat(names, ",") or "-") .. ":" .. p.scan_state
        end
        return table.concat(out, ";")
    end
    check("spill giong memory tung record", sig(sp or {}), sig(mem))
    check("va co handler di qua duoc giao thuc",
          sig(mem):find("handler", 1, true) ~= nil, true)
    -- `scan_state` cung phai di qua: thieu no thi than SPILL luon bao `ok`.
    local lines = {}
    for i = 1, uc.MAX_LINES + 20 do lines[i] = "memory_limit=" .. i .. "M" end
    local d2 = mp({ filepart(".user.ini", table.concat(lines, "\n")) })
    local t2 = os.tmpname()
    fh = io.open(t2, "wb"); fh:write(d2); fh:close()
    local sp2 = core.unpack(worker.scan_file(t2, MULTI))
    os.remove(t2)
    check("spill: scan_state mang ly do, khong phai ok",
          sp2 and sp2.parts and sp2.parts[1].scan_state, "config_trunc")
end

io.write(string.format("\nupload_content: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
