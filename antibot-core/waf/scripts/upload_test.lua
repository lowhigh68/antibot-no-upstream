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
eq(".." .. string.char(92) .. ".." .. string.char(92) .. "shell.php",
                                  "upload_php_ext", "dau phan cach Windows")
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
-- `.HTACCESS` DA CHUYEN sang muc [8] voi nhan `upload_config_case`.
--
-- Dong cu o day khang dinh `.HTACCESS` -> `upload_apache_config`, va no da CHAN
-- MOT BAN DEPLOY: toi them nhan moi o muc [8] nhung de nguyen assertion cu o
-- day, nen hai muc trong CUNG MOT FILE noi nguoc nhau.
--
-- Khong phai loi logic — loi QUET SOT. Bai hoc cu the: khi doi gia tri tra ve
-- cua mot ham, phai `grep` TEN DAU VAO tren toan bo bo test, khong chi them ca
-- moi. Mot assertion cu con song la mot hop dong con song.
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
eq(string.char(92),              nil, "chi dau phan cach Windows")
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
eqf(up.basename,   "basename", "a" .. string.char(92) .. "b" .. string.char(92) .. "c.php",
                               "c.php",  "dau backslash")
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
-- ── ASSERTION DA GO: "`#extensions <= 6`" ────────────────────────────────
--
-- Ban truoc khang dinh `extensions()` KHONG duoc tra ve hon 6 duoi. Do la
-- assertion khoa cung CHINH GIOI HAN GAY BYPASS:
--
--     shell.php.a.b.c.d.e.f  ->  ban cu tra [f,e,d,c,b,a] va DUNG truoc `.php`
--
-- Da chung minh bang cach chay song song hai thuat toan: ban cu LOT, ban moi
-- BAT. Nen assertion cu bao XANH tren dung ca no phai chan — cung ho voi `.inc`
-- va voi ba lop kiem da go: mot phong doan duoc cai vao test roi tin.
--
-- Thay bang hai assertion NGUOC HUONG: quet HET (khong tran), va co bao khi
-- vuot muc bao cao.
do
    local e2, over = up.extensions(string.rep("a.", 200) .. "jpg")
    if #e2 ~= 200 then
        fail = fail + 1
        io.write(string.format(
            "  SAI  extensions() phai quet HET 200 duoi, duoc %d — tran la duong ne\n",
            #e2))
    else
        pass = pass + 1
    end
    if over ~= true then
        fail = fail + 1
        io.write("  SAI  extensions() phai BAO vuot muc bao cao (co thu hai)\n")
    else
        pass = pass + 1
    end
end

-- Duoi chay duoc nam SAU muc bao cao cu — dung ca phan bien neu.
eq("shell.php.a.b.c.d.e.f",       "upload_php_double",
   "8 duoi, .php o vi tri 7 — ban tran 6 LOT ca nay")
eq("shell.php.a.b.c.d.e.f.g.h",   "upload_php_double", "10 duoi")
eq("shell.inc.1.2.3.4.5.6.7",     "upload_php_double", ".inc sau 7 duoi rac")

io.write("\n[8] Bien the CASE sang nhan RIENG, khong lam ban nhom tin cay cao\n")
-- Giu `lower()` (fail-closed: mot so filesystem case-insensitive, mot so lop ghi
-- file normalize case, luc do `.HTACCESS` THANH `.htaccess` tren dia). Nhung
-- KHONG dem chung vao `upload_apache_config`, de con so nhom do giu nghia hep.
eq(".HTACCESS",   "upload_config_case", "khong lam ban apache_config")
eq(".HtAccess",   "upload_config_case", "mixed case")
eq("WEB.CONFIG",  "upload_config_case", "foreign + case")
eq(".USER.INI",   "upload_config_case", "php_config + case")
eq(".htaccess",   "upload_apache_config", "chuan — van la nhom manh nhat")
eq("web.config",  "upload_foreign_config", "chuan")

io.write("\n[9] worse_up — giu luat NGHIEM TRONG NHAT, khong phai luat DAU TIEN\n")
-- Ban truoc giu luat dau tien theo thu tu part, ma thu tu part la thu KE GUI
-- dieu khien: dat `web.config` o part 1 la lam so lieu bao `foreign_config` va
-- mat `php_ext` o part 2. Khong doi diem (tat ca ve `waf_upload = 1`, trong so
-- 0) nhung lam ban chinh con so dung de quyet dinh trong so.
local function eqw(a, b, want, why)
    local got = up.worse_up(a, b)
    if got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  worse_up(%s,%s) cho=%s duoc=%s  %s\n",
                 tostring(a), tostring(b), tostring(want), tostring(got), why or ""))
    else
        pass = pass + 1
    end
end
eqw("upload_foreign_config", "upload_php_ext", "upload_php_ext",
    "web.config part 1, shell.php part 2")
eqw("upload_php_ext", "upload_foreign_config", "upload_php_ext",
    "nguoc thu tu phai cho CUNG ket qua")
eqw("upload_php_ext", "upload_apache_config", "upload_apache_config",
    ".htaccess nang nhat")
eqw("upload_php_legacy_ext", "upload_php_double", "upload_php_double",
    "double > legacy")
eqw("upload_config_case", "upload_php_legacy_ext", "upload_config_case",
    "y dinh ro rang hon mot duoi la")
eqw(nil, "upload_php_ext", "upload_php_ext", "nil + X")
eqw("upload_php_ext", nil, "upload_php_ext", "X + nil")
eqw(nil, nil, nil, "nil + nil")

io.write(string.format("\nupload_test: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
