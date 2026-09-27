-- T — bo test cho waf/routes.lua (roadmap muc 5: hop dong endpoint).
-- CHAY: ./run.sh
--
-- Cau hoi ma bo nay tra loi: "HINH DANG cua request co dung hop dong cua route
-- khong" — method, content-type, co tep khong. Khac `wp_hardening` (ai gui) va
-- khac `args`/`body_core` (trong than co gi).
--
-- ── PHAN QUAN TRONG NHAT CUA BO NAY LA MUC 1, KHONG PHAI MUC 2 ──────
--
-- Positive security la mot phep dao nguoc nguy hiem: moi thu khong khai bao thanh
-- dang nghi. Nen phep kiem co gia tri nhat o day KHONG phai "co bat duoc tan cong
-- khong" ma la "co IM LANG dung nhung luu luong that khong". Muc 1 dai nhat vi
-- the.
local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end
package.preload["antibot.waf.routes"] = function()
    return dofile(SRC .. "waf/routes.lua")
end
local routes   = require "antibot.waf.routes"
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

-- `r()` tra ten vi pham, hoac "-" khi khong co gi de noi.
local function r(uri, method, ct)
    local bad = routes.check(uri, method, ct)
    return bad or "-"
end

local URLENC = "application/x-www-form-urlencoded"
local MULTI  = "multipart/form-data; boundary=----x"
local XML    = "text/xml"
local JSON   = "application/json"

-- ══ 1. KHONG DUOC BAO GI: luu luong THAT tren bon route ═════════════════════
--
-- Moi dong duoi day la mot dang request that su xay ra tren mot site WordPress
-- binh thuong. Mot dong nao do o day bao vi pham la mot FP tren 43 domain.
io.write("routes: luu luong THAT phai IM LANG\n")

-- wp-login.php: GET render form, POST urlencoded dang nhap.
check("login GET",            r("/wp-login.php", "GET", nil),          "-")
check("login GET co ct",      r("/wp-login.php", "GET", URLENC),       "-")
check("login POST urlenc",    r("/wp-login.php", "POST", URLENC),      "-")
-- Query string: `?action=logout&_wpnonce=...`, `?loggedout=true`, `?redirect_to=`
check("login POST co query",  r("/wp-login.php?action=postpass", "POST", URLENC), "-")
check("login GET logout",     r("/wp-login.php?action=logout&_wpnonce=ab12", "GET", nil), "-")
-- `charset` trong content-type: phai bi cat truoc khi so.
check("login ct co charset",
      r("/wp-login.php", "POST", URLENC .. "; charset=UTF-8"), "-")
-- Hoa thuong trong content-type: HTTP khong phan biet.
check("login ct HOA",
      r("/wp-login.php", "POST", "APPLICATION/X-WWW-FORM-URLENCODED"), "-")
-- HEAD: bo kiem uptime va mot so proxy dung HEAD.
check("login HEAD",           r("/wp-login.php", "HEAD", nil),         "-")

-- xmlrpc.php: Jetpack va WP Core gui XML. GET tra mot dong text.
check("xmlrpc POST xml",      r("/xmlrpc.php", "POST", XML),           "-")
check("xmlrpc POST app/xml",  r("/xmlrpc.php", "POST", "application/xml"), "-")
check("xmlrpc xml co charset",
      r("/xmlrpc.php", "POST", "text/xml; charset=utf-8"),             "-")
check("xmlrpc GET",           r("/xmlrpc.php", "GET", nil),            "-")
-- `?for=jetpack` la query that cua Jetpack.
check("xmlrpc jetpack query", r("/xmlrpc.php?for=jetpack", "POST", XML), "-")

-- wp-cron.php: WordPress tu goi. `spawn_cron` gui body RONG.
check("cron GET",             r("/wp-cron.php", "GET", nil),           "-")
check("cron POST khong ct",   r("/wp-cron.php", "POST", nil),          "-")
check("cron POST body rong",  r("/wp-cron.php", "POST", URLENC),       "-")
check("cron co doing_wp_cron",
      r("/wp-cron.php?doing_wp_cron=1727000000.1", "GET", nil),        "-")

-- wp-comments-post.php: form comment.
check("comment POST urlenc",  r("/wp-comments-post.php", "POST", URLENC), "-")
check("comment GET",          r("/wp-comments-post.php", "GET", nil),  "-")

-- ── Route KHONG co hop dong: phai im lang TUYET DOI ──
--
-- Day la nua con lai cua chong-FP. Bang hop dong CO Y hep; moi thu khac khong
-- duoc noi gi, ke ca khi trong nhu tan cong.
io.write("routes: route KHONG khai bao -> im lang tuyet doi\n")
check("admin-ajax multipart", r("/wp-admin/admin-ajax.php", "POST", MULTI), "-")
check("admin-ajax PUT",       r("/wp-admin/admin-ajax.php", "PUT", JSON),   "-")
check("async-upload",         r("/wp-admin/async-upload.php", "POST", MULTI), "-")
check("wp-json PUT json",     r("/wp-json/wp/v2/posts/1", "PUT", JSON),     "-")
check("wp-json DELETE",       r("/wp-json/wp/v2/posts/1", "DELETE", nil),   "-")
check("goc GET",              r("/", "GET", nil),                           "-")
check("index.php POST",       r("/index.php", "POST", MULTI),               "-")
check("route la PATCH",       r("/api/x", "PATCH", JSON),                   "-")
-- Mot file TEN GIONG nhung o thu muc khac: hop dong khoa theo path CHINH XAC,
-- nen `/sub/wp-login.php` KHONG bi rang buoc. Dung — WordPress cai trong thu muc
-- con thi `document_root` khac, va URI cua no khong phai `/wp-login.php`.
check("wp-login trong subdir", r("/blog/wp-login.php", "POST", MULTI),      "-")
check("xmlrpc trong subdir",   r("/sub/xmlrpc.php", "POST", MULTI),         "-")

-- ══ 2. PHAI BAO: vi pham hop dong ═══════════════════════════════════════════
io.write("routes: vi pham hop dong\n")

-- `route_upload` — HEP nhat, va la ca dong luc cua ca muc 5: mot multipart tren
-- route khong bao gio nhan tep. Khong tang nao khac bat duoc ca nay.
check("cron multipart",       r("/wp-cron.php", "POST", MULTI),       "route_upload")
check("login multipart",      r("/wp-login.php", "POST", MULTI),      "route_upload")
check("xmlrpc multipart",     r("/xmlrpc.php", "POST", MULTI),        "route_upload")
check("comment multipart",    r("/wp-comments-post.php", "POST", MULTI), "route_upload")
-- multipart KHONG co boundary van la multipart.
check("multipart khong bound", r("/wp-cron.php", "POST", "multipart/form-data"), "route_upload")

-- `route_ct` — rong hon, nen se duoc xet promote SAU.
check("login json",           r("/wp-login.php", "POST", JSON),       "route_ct")
check("login xml",            r("/wp-login.php", "POST", XML),        "route_ct")
check("xmlrpc urlencoded",    r("/xmlrpc.php", "POST", URLENC),       "route_ct")
check("xmlrpc json",          r("/xmlrpc.php", "POST", JSON),         "route_ct")
check("cron json",            r("/wp-cron.php", "POST", JSON),        "route_ct")
check("comment json",         r("/wp-comments-post.php", "POST", JSON), "route_ct")
-- Content-type la dang KHONG nhan ra: `other`, khong nam trong tap cho phep.
check("login ct la la",       r("/wp-login.php", "POST", "x/y"),      "route_ct")

-- `route_method`
check("login PUT",            r("/wp-login.php", "PUT", URLENC),      "route_method")
check("login DELETE",         r("/wp-login.php", "DELETE", nil),      "route_method")
check("xmlrpc PATCH",         r("/xmlrpc.php", "PATCH", XML),         "route_method")
check("cron TRACE",           r("/wp-cron.php", "TRACE", nil),        "route_method")
-- method chu thuong: phai chuan hoa.
check("method chu thuong ok",  r("/wp-login.php", "post", URLENC),    "-")
check("method thuong vi pham", r("/wp-login.php", "put", URLENC),     "route_method")

-- ══ 3. THU TU uu tien: `route_upload` manh hon `route_ct` ═══════════════════
--
-- Mot multipart tren `/xmlrpc.php` vi pham CA HAI (khong phai xml, VA la upload
-- tren route khong nhan tep). Phai bao cai MANH hon — nguoc lai thi mot upload
-- vao xmlrpc chi duoc bao la "content-type sai", dung nhung nhe hon han su that.
io.write("routes: multipart vi pham ca hai -> bao cai MANH hon\n")
check("xmlrpc multipart uu tien upload", r("/xmlrpc.php", "POST", MULTI), "route_upload")
check("cron multipart uu tien upload",   r("/wp-cron.php", "POST", MULTI), "route_upload")
-- Nhung `route_method` uu tien CAO NHAT: mot `PUT` multipart la sai method truoc
-- da, va do la cau tra loi dung nhat ve cai request do.
check("method sai uu tien nhat", r("/wp-cron.php", "PUT", MULTI),      "route_method")

-- ══ 4. `nil` (khong body) KHAC `other` (body dang la) ═══════════════════════
--
-- Hai thu nay khong duoc gop: mot `POST` khong `Content-Type` la request khong
-- khai bao than — no khong vi pham `ct` (khong co gi de so). Gop lai thi moi
-- `POST /wp-cron.php` cua WordPress (body rong, co the khong co ct) bi bao.
io.write("routes: khong co content-type KHAC content-type la la\n")
check("ct nil",               r("/wp-login.php", "POST", nil),        "-")
check("ct chuoi rong",        r("/wp-login.php", "POST", ""),         "-")
check("ct chi khoang trang",  r("/wp-login.php", "POST", "  "),       "route_ct")
check("ct la la",             r("/wp-login.php", "POST", "zzz"),      "route_ct")

-- ══ 5. `ct_family` — phep phan loai ═════════════════════════════════════════
io.write("routes: ct_family\n")
check("fam nil",       routes.ct_family(nil),        nil)
check("fam rong",      routes.ct_family(""),         nil)
check("fam urlenc",    routes.ct_family(URLENC),     "urlencoded")
check("fam multi",     routes.ct_family(MULTI),      "multipart")
check("fam text/xml",  routes.ct_family(XML),        "xml")
check("fam app/xml",   routes.ct_family("application/xml"), "xml")
check("fam json",      routes.ct_family(JSON),       "json")
check("fam khac",      routes.ct_family("image/png"), "other")
-- Khoang trang dau/cuoi va tham so.
check("fam co space",  routes.ct_family("  application/json  "), "json")
check("fam co param",  routes.ct_family("application/json; charset=utf-8"), "json")

-- ══ 6. `path_of` — tach path khoi query ═════════════════════════════════════
io.write("routes: path_of\n")
check("path thuong",   routes.path_of("/wp-login.php"),        "/wp-login.php")
check("path co query", routes.path_of("/wp-login.php?a=1"),    "/wp-login.php")
check("path co frag",  routes.path_of("/wp-login.php#x"),      "/wp-login.php")
check("path ca hai",   routes.path_of("/x.php?a=1#y"),         "/x.php")
check("path nil",      routes.path_of(nil),                     "/")
check("path rong",     routes.path_of(""),                      "/")
check("path chi query", routes.path_of("?a=1"),                 "/")

-- ══ 7. Hop dong phai co MOT luat trong registry ════════════════════════════
--
-- Mot ten vi pham ma `registry` khong biet thi `policy.emit` bo qua trong IM
-- LANG — luat khong bao gio chay, va khong ai bao loi. Dung ho loi `canvas_change`
-- (trong so 50, ghi theo identity doc theo ip, vinh vien bang 0).
io.write("routes: moi ten vi pham phai co luat trong registry\n")
for _, id in ipairs({ "route_method", "route_ct", "route_upload" }) do
    local rule = registry.get(id)
    check("registry co " .. id, rule ~= nil, true)
    if rule then
        -- Giai doan DO: diem 0 va `observe`. Doi cho nay phai la mot quyet dinh
        -- CO Y, khong phai mot lan sua tay lot qua.
        check(id .. " diem 0",       rule.score,  0)
        check(id .. " la observe",   rule.action, "observe")
        check(id .. " ho protocol",  rule.family, "protocol")
    end
end

-- Va nguoc lai: moi luat `route_*` trong registry phai duoc `routes.check` tra ve
-- o mot ca nao do. Mot luat khai bao ma khong ai phat thi vinh vien bang 0.
io.write("routes: moi luat route_* phai duoc phat o mot ca nao do\n")
do
    local emitted = {}
    -- Ba ca dai dien, lay tu chinh muc 2 o tren.
    emitted[routes.check("/wp-login.php", "PUT", URLENC)] = true
    emitted[routes.check("/wp-login.php", "POST", JSON)]  = true
    emitted[routes.check("/wp-cron.php", "POST", MULTI)]  = true
    for id in pairs(registry.all()) do
        if id:sub(1, 6) == "route_" then
            check("luat " .. id .. " co duong phat", emitted[id] == true, true)
        end
    end
end

-- ══ 8. Bang hop dong: moi dong phai co `why` ════════════════════════════════
--
-- `why` la cho ghi BAT BIEN dan ra dong do. Mot hop dong khong co ly do la mot
-- hop dong lay tu log — dung thu ma muc 5 khong duoc phep lam.
io.write("routes: moi hop dong phai co `why`\n")
do
    local n = 0
    for path, c in pairs(routes.CONTRACTS) do
        n = n + 1
        check("hop dong " .. path .. " co why",
              type(c.why) == "string" and #c.why > 10, true)
        -- Bon route deu cho GET: chan GET khong bat duoc gi ma pha ca bon.
        check("hop dong " .. path .. " cho GET", c.methods.GET, true)
    end
    check("co du bon hop dong", n, 4)
end

io.write(string.format("\nroutes: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
