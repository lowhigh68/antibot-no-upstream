-- T — bo test cho waf/upload.lua (P1: ten file upload)
--
-- CHAY: ./run.sh
--
-- KHONG can `resty`: `upload.lua` la Lua THUAN (no chay trong worker thread nen
-- khong duoc dung `ngx.*`). Chay duoc bang luajit tran — nhung `run.sh` van goi
-- qua `resty` cho dong nhat voi cac bo khac.
--
-- ── TRONG TAM: NHOM "PHAI IM" ───────────────────────────────────────
--
-- Cung ly do da ghi trong `args_test.lua`, nhung o day gay hon. Dan so chay qua
-- luat nay la KHO ANH VA TAI LIEU CUA KHACH — anh san pham, hoa don PDF, file
-- CAD. Mot mau qua rong khong lam sai mot phan tich; no chan khach hang dang
-- them anh san pham, va ho khong biet vi sao.
--
-- Nen so assertion "phai im" nhieu hon "phai ban" la CO Y.

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

local up = dofile(SRC .. "waf/upload.lua")

local pass, fail = 0, 0
local function eq(input, want, why)
    local ok, got = pcall(up.check_filename, input)
    if not ok then
        fail = fail + 1
        io.write(string.format("  LOI  %-46s %s\n", tostring(input), tostring(got)))
    elseif got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  %-46s cho=%-18s duoc=%-18s\n       %s\n",
                 tostring(input), tostring(want), tostring(got), why or ""))
    else
        pass = pass + 1
    end
end

io.write("\n[1] PHAI IM — file that cua khach hang\n")
-- Neu mot dong nao trong nhom nay do, KHONG duoc "sua test cho khop". Nhom nay
-- la dinh nghia cua dung/sai o tang nay.
eq("anh-san-pham.jpg",            nil, "anh thuong")
eq("IMG_20260919_103045.JPEG",    nil, "hoa thuong tu may anh")
eq("bao-gia-thang-9.pdf",         nil, "tai lieu")
eq("danh-muc.xlsx",               nil, "excel")
eq("logo.svg",                    nil, "SVG xu ly RIENG, khong o P1 — xem waf/CLAUDE.md")
eq("ban-ve.dwg",                  nil, "duoi la nhung that")
eq("thiet-ke.sketch",             nil, "duoi la nhung that")
eq("archive.tar.gz",              nil, "duoi kep hop le")
eq("khong-co-duoi",               nil, "khong duoi — KHONG bat")
eq("bang.gia.thang.9.2026.pdf",   nil, "nhieu dau cham hop le")
eq("Ảnh-sản-phẩm-mới.png",        nil, "UTF-8 tieng Viet")
eq("file name co khoang trang.jpg", nil, "khoang trang giua ten")
eq("styles.css",                  nil, "asset")
eq("script.js",                   nil, "asset")
eq("data.json",                   nil, "asset")
eq("index.html",                  nil, "HTML khong chay tren server")
eq("template.phpsomething.jpg",   nil, "`phpsomething` KHONG phai `php`")
eq("my-php-guide.pdf",            nil, "chu `php` trong TEN, khong phai duoi")
eq("php.jpg",                     nil, "duoi la `jpg`; `php` la ten goc")
eq("notes.txt",                   nil, "text")
-- `.inc` DA CHUYEN sang nhom "phai ban" (dong duoi muc [2]) — do tren fleet
-- 19-09 cho thay ca ba dong `AddHandler` liet ke `.inc` ngay canh `.php`.
--
-- GHI RO VI SAO LAN NAY SUA TEST LA DUNG, trong khi dau muc [1] noi "khong
-- duoc sua test cho khop": cai bi bac bo la GIA DINH cua toi ("`.inc` khong
-- duoc anh xa"), khong phai hanh vi dung cua code. Do luong tu may that thang
-- mot gia dinh chua kiem la ly do HOP LE duy nhat de doi ky vong; "test do nen
-- toi ha ky vong" thi khong.
eq("readme.md",                   nil, "markdown")

io.write("\n[2] PHAI BAN — duoi chay duoc o cuoi\n")
eq("shell.php",                   "upload_php_ext", "ca co ban")
eq("SHELL.PHP",                   "upload_php_ext", "khong phan biet hoa thuong")
eq("shell.phtml",                 "upload_php_ext", "phtml")
eq("shell.php5",                  "upload_php_ext", "php5")
eq("shell.php7",                  "upload_php_legacy_ext", "php7")
eq("shell.pht",                   "upload_php_legacy_ext", "pht")
eq("payload.phar",                "upload_php_legacy_ext", "phar include duoc")
eq("../../wp-config.php",         "upload_php_ext", "traversal — lay basename")
eq("..\..\shell.php",           "upload_php_ext", "dau phan cach Windows")
eq("/tmp/a/b/shell.php",          "upload_php_ext", "duong dan tuyet doi")
eq("shell.inc",                   "upload_php_ext", "DO TREN FLEET: AddHandler liet ke .inc canh .php")
eq("x.inc.jpg",                   "upload_php_double", ".inc o vi tri giua")

io.write("\n[3] PHAI BAN — duoi bi che o cuoi (cac duong ne that)\n")
eq("shell.php.",                  "upload_php_ext", "dau cham cuoi — Apache van anh xa")
eq("shell.php ",                  "upload_php_ext", "khoang trang cuoi")
eq("shell.php\t",                 "upload_php_ext", "tab cuoi")
eq("shell.php::$DATA",            "upload_php_ext", "NTFS ADS")
eq("shell.php\0.jpg",             "upload_php_ext", "byte NUL cat chuoi")
eq("shell.php...",                "upload_php_ext", "nhieu dau cham cuoi")

io.write("\n[4] PHAI BAN — duoi kep KHONG o cuoi (AddHandler)\n")
eq("x.php.jpg",                   "upload_php_double", "AddHandler khop duoi GIUA")
eq("avatar.phtml.png",            "upload_php_double", "phtml giua")
eq("a.php.b.c.jpg",               "upload_php_double", "sau nhieu lop")

io.write("\n[5] PHAI BAN — ten file cau hinh\n")
-- Nhom nay la ly do P1 ton tai: KHONG file nao o day chua `<?php`, nen
-- `waf_body_php` (trong so 50, da chay) mu hoan toan voi chung.
eq(".htaccess",                   "upload_apache_config", "AddType bien .jpg thanh PHP")
eq(".HTACCESS",                   "upload_apache_config", "khong phan biet hoa thuong")
eq(".user.ini",                   "upload_php_config", "PHP doc .user.ini")
eq("php.ini",                     "upload_php_config", "php.ini")
eq("web.config",                  "upload_foreign_config", "IIS")
eq("../.htaccess",                "upload_apache_config", "qua traversal")
eq(".htpasswd",                   "upload_foreign_config", "khong doi handler, chi lo hash")

-- Diem 3 cua ban gop y: NUL + dau phan cach. `basename` don thuan chon
-- `benign.jpg` (dau `/` cuoi cung nam SAU NUL), nhung mot thanh phan ha nguon
-- dung chuoi kieu C thay `shell.php`. `canonical_views` kiem ba goc nhin nen bat
-- duoc ca hai chieu. Thu pha: quay ve mot goc nhin => bon ca duoi do.
eq("shell.php\0/benign.jpg",      "upload_php_ext", "C-string thay shell.php")
eq("benign.jpg\0/shell.php",      "upload_php_ext", "basename thay shell.php")
eq("a/b/shell.php\0/x/y.jpg",     "upload_php_ext", "NUL + nhieu thu muc")
eq("shell.php\0",                 "upload_php_ext", "NUL o cuoi")

io.write("\n[6] MEP — dau vao xau khong duoc lam no no\n")
eq(nil,                           nil, "nil")
eq("",                            nil, "chuoi rong")
eq(".",                           nil, "mot dau cham")
eq("...",                         nil, "toan dau cham")
eq("/",                           nil, "chi dau phan cach")
eq("\\",                          nil, "chi dau phan cach Windows")
eq(".php",                        "upload_php_ext", "file an ten `.php` — duoi la php")
eq(string.rep("a", 500) .. ".php", "upload_php_ext", "ten dai van bat")
eq(string.rep("a.", 200) .. "jpg", nil, "200 dau cham, khong duoi chay duoc — KHONG treo")

io.write("\n[7] Ham phu — kiem rieng tung buoc chuan hoa\n")
local function eqf(fn, name, input, want, why)
    local got = fn(input)
    if got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  %s(%-28s) cho=%-16s duoc=%-16s %s\n",
                 name, '"'..tostring(input)..'"', tostring(want), tostring(got), why or ""))
    else
        pass = pass + 1
    end
end
eqf(up.basename,   "basename", "a/b/c.php",      "c.php",  "dau /")
eqf(up.basename,   "basename", "a\b\c.php",    "c.php",  "dau \\")
eqf(up.basename,   "basename", "c.php",          "c.php",  "khong dau phan cach")
eqf(up.strip_tail, "strip_tail", "a.php.",       "a.php",  "cat dau cham cuoi")
eqf(up.strip_tail, "strip_tail", "a.php::$DATA", "a.php",  "cat ADS")
eqf(up.strip_tail, "strip_tail", "a.jpg",        "a.jpg",  "khong cat gi khi khong can")

-- `extensions` tra ve bang — kiem tung phan tu.
local e = up.extensions("x.php.jpg")
if not (e[1] == "jpg" and e[2] == "php" and #e == 2) then
    fail = fail + 1
    io.write("  SAI  extensions('x.php.jpg') phai la {jpg,php}\n")
else
    pass = pass + 1
end
local e2 = up.extensions(string.rep("a.", 200) .. "jpg")
if #e2 > 6 then
    fail = fail + 1
    io.write(string.format("  SAI  extensions() khong ton trong MAX_EXT: %d\n", #e2))
else
    pass = pass + 1
end

io.write(string.format("\nupload_test: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
