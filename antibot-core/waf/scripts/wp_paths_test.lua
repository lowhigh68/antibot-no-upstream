-- T — bo test cho waf/wp_paths.lua
--
-- CHAY: ./test/run.sh   (can OpenResty; dung `resty`, KHONG phai luajit tran)
--
-- Vi sao phai la resty: bon luat quyet dinh bang `ngx.re.find` voi PCRE
-- lookahead. Lua pattern khong dien dat duoc lookahead, nen mot stub thuan Lua
-- se kiem mot NGU NGHIA KHAC voi cai chay that. Test xanh ma sai ngu nghia con
-- te hon la khong co test.
--
-- PHAM VI v1 — chi `check()` va `needs_mark()`. Do la noi 100% quyet dinh luat
-- nam. KHONG phu hai cho, va ca hai phai doc bang waf.log tren luu luong that:
--   `waf.run_pre`   — glue mong, va no goi ngx.exit
--   `target_exists` — can `ngx.var.document_root` (khong ton tai ngoai request
--                     that) cong voi fixture tren dia
--
-- Bang case co hai loai dong. Dong ky vong DUNG (luat phai bat / phai im), va
-- dong danh dau GAP ghi lai HANH VI HIEN TAI cua mot lo hong da biet. Khi muc
-- 5-8 lam xong, dong GAP phai doi ky vong — do la cach chung minh thay doi lam
-- dung viec no hua, thay vi chi lam mot viec gi do.

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end
if not ngx.shared.antibot_cache then
    io.write("thieu shared dict: chay bang ./test/run.sh (no truyen --shdict)\n")
    os.exit(2)
end

-- Redis gia. Cong `is_wp_root` doc qua day, nen bang nay la thu quyet dinh (host,tien to)
-- nao duoc coi la WordPress trong test.
local REDIS = {}
package.preload["antibot.core.redis_pool"] = function()
    return {
        safe_get = function(k) return REDIS[k] end,
        safe_set = function(k, v) REDIS[k] = v return true end,
    }
end

local wp = dofile(SRC .. "waf/wp_paths.lua")
local ex = dofile(SRC .. "waf/exposed.lua")

local WP    = "wp.test"       -- host DA duoc danh dau la WordPress O GOC
local WPSUB = "wpsub.test"    -- WordPress cai trong THU MUC CON /en (khong o goc)
local PLAIN = "plain.test"    -- host code tu viet: luat 3 phai im
REDIS["waf:wphost:" .. WP] = "1"
-- Chu y: WPSUB KHONG co `waf:wphost:` — goc domain cua no khong phai WordPress.
-- Do la ca dang kiem nhat: hai cau hoi "host nay co WordPress o goc khong" va
-- "/en co phai mot goc WordPress khong" phai doc lap voi nhau.
REDIS["waf:wproot:" .. WPSUB .. ":/en"] = "1"

local CASES = {
-- wp_upload_exec — BLOCK
{"/wp-content/uploads/2024/01/shell.php", WP, "wp_upload_exec",
 "WordPress khong bao gio phuc vu PHP hop le tu uploads"},
{"/wp-content/uploads/shell.php.jpg", WP, "wp_upload_exec",
 "duoi kep: AddHandler khop .php o GIUA ten, khong chi duoi cuoi"},
{"/wp-content/uploads/shell.php.bak", WP, "wp_upload_exec",
 "duoi kep nguy hiem hon: .bak khong o fastpath tinh nen toi thang Apache"},
{"/wp-content/uploads/shell.pHp", WP, "wp_upload_exec",
 "khong phan biet hoa thuong"},
{"/wp-content/uploads/shell.phtml", WP, "wp_upload_exec", "duoi phtml"},
{"/wp-content/uploads/2024/01/anh.jpg", WP, nil,
 "DUONG DI NONG NHAT tren site WordPress that — mot FP o day la tham hoa"},
{"/wp-content/uploads/2024/tai-lieu.pdf", WP, nil, "file thuong"},

-- wp_content_exec — BLOCK
{"/wp-content/advanced-cache.php", WP, "wp_content_exec",
 "drop-in chi duoc PHP include, goi thang qua HTTP la dau hieu"},
{"/wp-content/index.php", WP, nil,
 "CA THAT 2026-09-02: file rong cua WordPress core (Silence is golden), co tren " ..
 "MOI cai dat. Chan no lam ban kenh canh bao exists=1"},
{"/wp-content/index.php/x", WP, "wp_content_exec",
 "PATH_INFO tren index.php khong hop le nen van phai bat"},
{"/wp-content/themes/index.php", WP, nil,
 "CA THAT 2026-09-02: 17/20 dong wp_theme_direct co exists=1 chinh la file nay, " ..
 "tren 9 domain. Chot chan liet ke thu muc cua WordPress core"},
{"/wp-content/plugins/index.php",    WP, nil, "cung chot chan do"},
{"/wp-content/mu-plugins/index.php", WP, nil, "cung chot chan do"},
{"/wp-content/uploads/index.php", WP, "wp_upload_exec",
 "KHONG mien tru o nhanh block: mien tru la mo mot loi vong CO SAN TEN GOI — " ..
 "ke tan cong chi can dat webshell ten index.php"},
{"/wp-content/themes/twentytwentyone/index.php", WP, "wp_theme_direct",
 "CHI mot cap: day la template cua theme, goi thang van la do tim"},
{"/wp-content/backup/db.php", WP, "wp_content_exec", "thu muc con la"},
{"/wp-content/updraft/x.php", WP, "wp_content_exec", "thu muc backup plugin"},

-- wp_plugin_direct — SIGNAL 0.25
{"/wp-content/plugins/us.php/", WP, "wp_plugin_direct",
 "CA THAT tu waf.log 2026-09-02 (alumicastore.com) — PATH_INFO duoi dau /"},
{"/wp-content/plugins/woocommerce/woocommerce.php", WP, "wp_plugin_direct",
 "file chinh plugin that van ban tin hieu, nhung 0.25 la duoi nguong"},
{"/wp-content/plugins/woocommerce/assets/js/x.js", WP, nil, "khong phai PHP"},

-- MUC 5 — themes va mu-plugins khong con la vung mu. Hai dong nay TRUOC DAY
-- danh dau GAP voi ky vong nil; viec doi ky vong o day chinh la bang chung muc
-- 5 lam dung viec no hua.
{"/wp-content/themes/x/timthumb.php", WP, "wp_theme_direct",
 "signal 0.25 chu khong block: timthumb cung ca mot the he theme cu THAT SU " ..
 "goi thang PHP cua chinh chung"},
{"/wp-content/mu-plugins/dev-ci-lint-woocommerce-job-update.php", WP,
 "wp_muplugin_direct",
 "CHINH file tim thay 2026-09-02 tren 13 site. 0.50 chu khong 0.25 vi mu-plugin " ..
 "HOP LE khong bao gio bi fetch qua HTTP. VAN khong cuu duoc truong hop no tu " ..
 "chay: WordPress include no moi request, khong co request nao de chan"},

-- MUC 6 — /wp-includes/ va /wp-admin/includes/
{"/wp-includes/js/tinymce/wp-tinymce.php", WP, nil,
 "ALLOWLIST: bo nap JS dong, trinh duyet fetch that"},
{"/wp-includes/ms-files.php", WP, nil, "ALLOWLIST: multisite phuc vu file"},
{"/wp-includes/functions.php", WP, "wp_includes_exec",
 "thu vien core, guard ABSPATH, chi duoc require tu trong PHP"},
{"/wp-includes/x/shell.php", WP, "wp_includes_exec",
 "cho tha webshell kinh dien, chinh vi hiem ai nhin vao"},
{"/wp-admin/includes/plugin.php", WP, "wp_admin_includes_exec", "thu vien thuan"},
{"/wp-admin/admin-post.php", WP, nil,
 "endpoint hop le — CHI chan includes/, KHONG chan ca /wp-admin/*.php"},

-- wp_root_unknown — SIGNAL 0.50, CAN host WordPress
{"/shell.php", WP, "wp_root_unknown", "PHP la o web root"},
-- WordPress cai trong thu muc con: `/en/shell.php`. Truoc `19fecf6` day tra nil
-- va do la lo hong nguoi van hanh chi ra — khong luat nao ban ⇒ init.lua khong
-- tra `waf:fimnew:` ⇒ FIM biet file moi ma WAF khong bao gio hoi.
{"/en/shell.php", WPSUB, "wp_root_unknown", "WordPress cai trong /en"},
{"/en/shell.php/x", WPSUB, "wp_root_unknown", "PATH_INFO trong thu muc con"},
{"/en/index.php", WPSUB, nil, "WP_ROOT_OK ap dung ca trong thu muc con"},
{"/en/wp-login.php", WPSUB, nil, ""},
-- Tien to CHUA duoc danh dau thi im. `WPSUB` chi co `/en`, khong co `/fr`.
{"/fr/shell.php", WPSUB, nil,
 "tien to chua hoc — im, khong doan"},
-- Host co goc WordPress nhung `/en` chua hoc: `/en/shell.php` phai im.
{"/en/shell.php", WP, nil,
 "host la WP o GOC, nhung /en chua duoc danh dau — hai cau hoi khac nhau"},
-- Sau hon mot cap: khong co nhanh nao, phai nil.
{"/a/b/shell.php", WPSUB, nil, "do sau 3: ngoai pham vi"},
{"/shell.php/x", WP, "wp_root_unknown",
 "MUC 2: PATH_INFO. Ban cu neo $ nen ra nil va lot sach"},
{"/shell.php/x.jpg", WP, "wp_root_unknown", "PATH_INFO co duoi gia"},
{"/wp-config.php.bak", WP, "wp_root_unknown",
 "CA THAT tu waf.log — chungkhoanplus.com"},
{"/shell.php", PLAIN, nil,
 "CONG CHONG FP: host khong phai WordPress thi root PHP tuy y la BINH THUONG"},
{"/shell.php/x", PLAIN, nil, "cong chong FP ap cho ca dang PATH_INFO"},
{"/index.php", WP, nil, "trong WP_ROOT_OK"},
{"/index.php/2020/01/bai-viet/", WP, nil,
 "permalink dang PATHINFO cua WordPress — bat cai nay la FP hang loat"},
{"/wp-login.php", WP, nil, "trong WP_ROOT_OK"},
{"/xmlrpc.php", WP, nil, "trong WP_ROOT_OK"},
{"/foo/bar.php", WP, nil, "khong o web root nen luat 3 khong ap"},
{"/wp-admin/admin-ajax.php", WP, nil,
 "endpoint hop le luu luong cao — khong o web root nen khong bi luat 3"},
{"/wp-includes/js/tinymce/wp-tinymce.php", WP, nil,
 "GAP: /wp-includes/ chua co luat (muc 6)"},

-- khong phai PHP: loi ra cua tuyet dai da so request
{"/", WP, nil, "trang chu"},
{"/style.css", WP, nil, "tinh"},
{"/wp-admin/", WP, nil, "thu muc, khong phai PHP"},
{"", WP, nil, "URI rong"},
}

-- needs_mark tra ve TIEN TO can danh dau (chuoi, CO THE RONG) hoac nil.
-- Chuoi rong = goc domain. Vi "" van truthy trong Lua, moi phep kiem o phia goi
-- phai so `~= nil`, KHONG duoc dung `if wp` roi tuong minh dang loai "" ra.
local MARK_CASES = {
{"/wp-content/themes/x/style.css", "m1.test", "",
 "anh va CSS duoi wp-content la bang chung WordPress manh nhat"},
{"/wp-admin/",           "m2.test", "",  ""},
{"/wp-includes/js/x.js", "m3.test", "",  ""},
{"/",                    "m4.test", nil, "khong phai duong dan WordPress"},
{"/about-us",            "m5.test", nil, ""},
{"/wp-content/x.jpg",    "",        nil, "host rong"},

-- WordPress cai trong THU MUC CON. Do duoc 5 ban tren cloud168-101 (2026-09-02):
-- `/en` tren 4 site, `/id` tren 1 — khong cai nao la subdomain.
{"/en/wp-admin/",        "m6.test", "/en", "ban cai trong thu muc con"},
{"/en/wp-content/themes/x/style.css", "m7.test", "/en", ""},
{"/id/wp-includes/js/x.js", "m8.test", "/id", ""},
-- Sau hon mot cap thi KHONG hoc. Tien to do NGUOI GUI dat, nen do sau tuy y
-- nghia la khong gian khoa tuy y — dung loai lo da phai va mot lan khi viec
-- danh dau con chay o access phase.
{"/a/b/wp-admin/",       "m9.test", nil, "sau hon 1 cap: khong hoc"},
{"/a/b/c/wp-content/x.jpg", "m10.test", nil, ""},
}

-- MUC 7 + 8 — waf/exposed.lua, khong phu thuoc WordPress, khong cong host.
local EXPOSED_CASES = {
{"/.env",       nil, "dotfile_exposed", "ro credential database + API key"},
{"/.git/config",nil, "dotfile_exposed", "tai ve toan bo ma nguon kem lich su"},
{"/.htaccess",  nil, "dotfile_exposed", ""},
{"/.user.ini",  nil, "dotfile_exposed", ""},
{"/sub/.env",   nil, "dotfile_exposed", "dotfile o thu muc con"},
{"/.well-known/acme-challenge/aBc123", nil, nil,
 "NGOAI LE BAT BUOC: chan nham day la MOI domain tren may khong gia han duoc " ..
 "chung chi, va no hong lang le toi tan ngay het han"},
{"/.well-known/security.txt", nil, nil, "moi thu duoi .well-known deu di qua"},
{"/style.css",  nil, nil, "dau cham khong dung sau dau /"},
{"/backup.sql", nil, "dump_exposed", "mot .sql ro ra la mat tron database"},
{"/db.sql.gz",  nil, "dump_exposed", ""},
{"/site.wpress",nil, "dump_exposed", "dinh dang All-in-One WP Migration"},
{"/wp-config.php.bak", nil, "dump_exposed", "CA THAT — chungkhoanplus.com"},
{"/tai-lieu.zip", nil, nil,
 "CO Y KHONG chan: .zip duoc phuc vu hop le (file tai ve trong uploads) va " ..
 "khong phan biet duoc voi ban sao luu chi bang duong dan"},
{"/anh.jpg",    nil, nil, ""},
{"/backup.sql/x", nil, nil, "neo $ — .sql phai o cuoi duong dan"},
}

-- Thu tu uu tien, sao lai dung dispatch trong waf/init.lua:run_pre.
local function dispatch(uri, host)
    return ex.check(uri) or wp.check(uri, host)
end

local PREC_CASES = {
{"/wp-config.php.bak", WP, "dump_exposed",
 "khop CA dump_exposed (block) lan wp_root_unknown (signal 0.50). exposed chay " ..
 "truoc nen nhan la cai chan — dung hon khi doc log"},
{"/shell.php", WP, "wp_root_unknown", "khong khop exposed nen roi xuong wp_paths"},
{"/.env", WP, "dotfile_exposed", "exposed thang, khong can cong host"},
{"/wp-content/uploads/shell.php", WP, "wp_upload_exec", "duong di WordPress binh thuong"},
}

local pass, fail = 0, 0
local function bad(fmt, ...)
    fail = fail + 1
    io.write(string.format(fmt, ...))
end

local function run(label, cases, fn)
    io.write(label, " - ", #cases, " case\n")
    for _, c in ipairs(cases) do
        local uri, host, want, why = c[1], c[2], c[3], c[4]
        local ok, got = pcall(fn, uri, host)
        if not ok then
            bad("  LOI  %-56s %s\n", uri, tostring(got))
        elseif got ~= want then
            bad("  SAI  %-56s cho=%s duoc=%s\n       %s\n",
                uri, tostring(want), tostring(got), why)
        else
            pass = pass + 1
        end
    end
end

io.write("\n")
run("check()", CASES, wp.check)
run("needs_mark()", MARK_CASES, wp.needs_mark)
run("exposed.check()", EXPOSED_CASES, ex.check)
run("thu tu uu tien", PREC_CASES, dispatch)

-- Ngat mach shdict: da danh dau roi thi khong duoc cham dia lan nua. Hong cho
-- nay la io.open chay cho MOI request cua host do trong suot 300s.
io.write("mark() ngat mach - 5 case\n")
wp.mark("marked.test", "")
if wp.needs_mark("/wp-content/x.jpg", "marked.test") ~= nil then
    bad("  SAI  sau mark(), needs_mark van tra tien to (mat ngat mach shdict)\n")
else
    pass = pass + 1
end
if REDIS["waf:wphost:marked.test"] ~= "1" then
    bad("  SAI  mark() khong ghi Redis (tien to rong phai giu ten khoa CU)\n")
else
    pass = pass + 1
end

-- Ngat mach phai theo TUNG TIEN TO, khong phai theo host. Danh dau goc roi thi
-- `/en` van phai duoc hoc — neu khong, host nao co WordPress o goc se vinh vien
-- khong bao gio hoc duoc ban cai trong thu muc con cua no, tuc lo hong van con
-- nguyen tren dung 5 domain vua do duoc.
if wp.needs_mark("/en/wp-admin/", "marked.test") ~= "/en" then
    bad("  SAI  danh dau goc lai chan luon viec hoc /en\n")
else
    pass = pass + 1
end

wp.mark("marked.test", "/en")
if wp.needs_mark("/en/wp-admin/", "marked.test") ~= nil then
    bad("  SAI  sau mark(host,'/en'), needs_mark van tra tien to\n")
else
    pass = pass + 1
end
if REDIS["waf:wproot:marked.test:/en"] ~= "1" then
    bad("  SAI  mark() khong ghi Redis cho tien to /en\n")
else
    pass = pass + 1
end

-- script_path(): cat PATH_INFO truoc khi ghep `document_root .. uri`.
--
-- Hong o day KHONG lam do bat ky luat nao — no lam hong hai thu KHAC va ca hai
-- deu hong trong IM LANG: khoa `waf:fimnew:` bi lech nen FIM danh dau ma WAF
-- khong nhan, va cot `exists=` bao 0 cho file dang nam tren dia. Dung cot dung
-- de phan biet "dang do tim" voi "da co san".
local SCRIPT_CASES = {
{"/shell.php/x",              nil, "/shell.php",       "PATH_INFO — ca lo do nay"},
{"/shell.php/a/b/c",          nil, "/shell.php",       "PATH_INFO nhieu tang"},
{"/wp-content/plugins/us.php/", nil, "/wp-content/plugins/us.php",
                                                       "da xuat hien trong waf.log THAT"},
{"/index.php/2020/01/bai/",   nil, "/index.php",       "permalink PATHINFO cua WordPress"},
{"/shell.php",                nil, "/shell.php",       "khong co PATH_INFO — giu nguyen"},
{"/blog/wp-config.php",       nil, "/blog/wp-config.php", "duong dan sau, giu nguyen"},
-- `/a.php/b.php`: script THAT SU chay la cai DAU, phan sau chi la PATH_INFO.
{"/a.php/b.php",              nil, "/a.php",           "cat o duoi PHP dau tien"},
{"/x.php5/y",                 nil, "/x.php5",          "php5 cung la duoi thuc thi"},
{"/x.phtml/y",                nil, "/x.phtml",         "phtml"},
-- Khong co duoi PHP thi tra NGUYEN URI. Hong cho nay se lam moi anh/css/js bi
-- tra khoa FIM sai, tuc lam nhieu chinh phep do.
{"/anh/logo.png",             nil, "/anh/logo.png",    "khong phai PHP — giu nguyen"},
{"/",                         nil, "/",                "web root"},
{"",                          nil, "",                 "chuoi rong khong duoc no"},
}
run("script_path()", SCRIPT_CASES, wp.script_path)

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
