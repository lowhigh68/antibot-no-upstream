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

-- Redis gia. Cong `is_wp_host` doc qua day, nen bang nay la thu quyet dinh host
-- nao duoc coi la WordPress trong test.
local REDIS = {}
package.preload["antibot.core.redis_pool"] = function()
    return {
        safe_get = function(k) return REDIS[k] end,
        safe_set = function(k, v) REDIS[k] = v return true end,
    }
end

local wp = dofile(SRC .. "waf/wp_paths.lua")

local WP    = "wp.test"       -- host DA duoc danh dau la WordPress
local PLAIN = "plain.test"    -- host code tu viet: luat 3 phai im
REDIS["waf:wphost:" .. WP] = "1"

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
{"/wp-content/backup/db.php", WP, "wp_content_exec", "thu muc con la"},
{"/wp-content/updraft/x.php", WP, "wp_content_exec", "thu muc backup plugin"},

-- wp_plugin_direct — SIGNAL 0.25
{"/wp-content/plugins/us.php/", WP, "wp_plugin_direct",
 "CA THAT tu waf.log 2026-09-02 (alumicastore.com) — PATH_INFO duoi dau /"},
{"/wp-content/plugins/woocommerce/woocommerce.php", WP, "wp_plugin_direct",
 "file chinh plugin that van ban tin hieu, nhung 0.25 la duoi nguong"},
{"/wp-content/plugins/woocommerce/assets/js/x.js", WP, nil, "khong phai PHP"},

-- GAP da biet: themes va mu-plugins. Hai dong nay ghi HANH VI HIEN TAI.
-- Muc 5 se doi ky vong sang tin hieu.
{"/wp-content/themes/x/timthumb.php", WP, nil,
 "GAP: themes/ nam trong WP_CONTENT_OK nen khong luat nao ap"},
{"/wp-content/mu-plugins/dev-ci-lint-woocommerce-job-update.php", WP, nil,
 "GAP: CHINH file tim thay 2026-09-02 tren 13 site. mu-plugins tu chay moi " ..
 "request nen ke tan cong khong can gui request nao — luat URI mu vinh vien"},

-- wp_root_unknown — SIGNAL 0.50, CAN host WordPress
{"/shell.php", WP, "wp_root_unknown", "PHP la o web root"},
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

local MARK_CASES = {
{"/wp-content/themes/x/style.css", "m1.test", true,
 "anh va CSS duoi wp-content la bang chung WordPress manh nhat"},
{"/wp-admin/",           "m2.test", true,  ""},
{"/wp-includes/js/x.js", "m3.test", true,  ""},
{"/",                    "m4.test", false, "khong phai duong dan WordPress"},
{"/about-us",            "m5.test", false, ""},
{"/wp-content/x.jpg",    "",        false, "host rong"},
}

local pass, fail = 0, 0
local function bad(fmt, ...)
    fail = fail + 1
    io.write(string.format(fmt, ...))
end

local function run(label, cases, fn)
    io.write(label, " — ", #cases, " case\n")
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

-- Ngat mach shdict: da danh dau roi thi khong duoc cham dia lan nua. Hong cho
-- nay la io.open chay cho MOI request cua host do trong suot 300s.
io.write("mark() ngat mach — 2 case\n")
wp.mark("marked.test")
if wp.needs_mark("/wp-content/x.jpg", "marked.test") ~= false then
    bad("  SAI  sau mark(), needs_mark van tra true (mat ngat mach shdict)\n")
else
    pass = pass + 1
end
if REDIS["waf:wphost:marked.test"] ~= "1" then
    bad("  SAI  mark() khong ghi Redis\n")
else
    pass = pass + 1
end

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
