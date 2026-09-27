-- T — bo test cho waf/routes.lua (roadmap muc 5: hop dong endpoint).
-- CHAY: ./run.sh
--
-- Cau hoi ma bo nay tra loi: "HINH DANG cua request co dung hop dong cua route
-- khong" — method, content-type, co tep dinh kem khong. Khac `wp_hardening` (ai
-- gui) va khac `args`/`body_core` (trong than co gi).
--
-- ── BAN TRUOC CUA BO NAY KHOA DUNG CAI SAI ──────────────────────────
--
-- Nguoi dung bat 27-09: ban truoc cua `routes_test` "chu dong coi moi multipart la
-- route_upload" — tuc no ghi nhan mot premise SAI nhu the la dung. `route_upload`
-- phai doi PARSER chung minh co part tep; mot form multipart chi co field, hay mot
-- than RONG khai bao multipart, khong phai upload.
--
-- Nen bo nay kiem CA BA truc:
--   1. luu luong THAT phai im lang (chong FP — phan dai nhat)
--   2. `route_upload` chi ban khi CO part tep da chung minh
--   3. hop dong chi ap khi host DA duoc chung minh la WordPress
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

-- Cong nhan CMS: `true` = host da duoc chung minh la WordPress. Mot ham, vi
-- `is_wp_root` that khoa theo `(host, tien to)`.
local WP    = function() return true end
local NOTWP = function() return false end

local URLENC = "application/x-www-form-urlencoded"
local MULTI  = "multipart/form-data; boundary=----x"
local XML    = "text/xml"
local JSON   = "application/json"

-- Than co MOT part tep da chung minh.
local WITH_FILE = {
    family = "multipart", proof = "ok", scan = "ok",
    parts = { { slot = 1, name_flags = false, content_flags = false,
                scan_state = "ok", bytes = 9 } },
}
-- Than multipart KHONG co part tep (chi field), da soi tron.
local NO_FILE = { family = "multipart", proof = "ok", scan = "ok", parts = nil }
-- Than KHONG chung minh duoc: `parts = nil` vi khong soi noi, khong phai vi sach.
local UNPROVEN = { family = "multipart", proof = "hdr", scan = "ok", parts = nil }
-- Than urlencoded thuong.
local FORM = { family = "urlencoded", proof = "ok", scan = "ok" }

-- `pre()` = pha 1 (chi method). `post()` = pha 2. `mp()` = do multipart rieng.
local function pre(uri, method, wp)
    return routes.check_pre(uri, method, wp or WP, "a.test") or "-"
end
local function post(uri, ct, has_body, body, wp)
    return routes.check_post(uri, ct, has_body, body, wp or WP, "a.test") or "-"
end
local function mp(uri, ct, has_body, wp)
    return routes.check_multipart(uri, ct, has_body, wp or WP, "a.test") or "-"
end

-- ══ 1. KHONG DUOC BAO GI: luu luong THAT tren bon route ═════════════════════
--
-- Moi dong duoi day la mot dang request that su xay ra tren mot site WordPress
-- binh thuong. Mot dong nao do o day bao vi pham la mot FP tren 43 domain.
io.write("routes: luu luong THAT phai IM LANG\n")

-- wp-login.php: GET render form, POST urlencoded dang nhap.
check("login GET",            pre("/wp-login.php", "GET"),            "-")
check("login GET ph2",        post("/wp-login.php", nil, false, nil), "-")
check("login POST urlenc",    post("/wp-login.php", URLENC, true, FORM), "-")
-- Query string: `?action=logout&_wpnonce=...`, `?loggedout=true`, `?redirect_to=`
check("login POST co query",
      post("/wp-login.php?action=postpass", URLENC, true, FORM),      "-")
check("login GET logout",
      pre("/wp-login.php?action=logout&_wpnonce=ab12", "GET"),        "-")
-- `charset` trong content-type: phai bi cat truoc khi so.
check("login ct co charset",
      post("/wp-login.php", URLENC .. "; charset=UTF-8", true, FORM), "-")
-- Hoa thuong trong content-type: HTTP khong phan biet.
check("login ct HOA",
      post("/wp-login.php", "APPLICATION/X-WWW-FORM-URLENCODED", true, FORM), "-")
check("login HEAD",           pre("/wp-login.php", "HEAD"),           "-")

-- xmlrpc.php: Jetpack va WP Core gui XML. GET tra mot dong text.
check("xmlrpc POST xml",      post("/xmlrpc.php", XML, true, FORM),   "-")
check("xmlrpc POST app/xml",  post("/xmlrpc.php", "application/xml", true, FORM), "-")
check("xmlrpc xml co charset",
      post("/xmlrpc.php", "text/xml; charset=utf-8", true, FORM),     "-")
check("xmlrpc GET",           pre("/xmlrpc.php", "GET"),              "-")
check("xmlrpc jetpack query",
      post("/xmlrpc.php?for=jetpack", XML, true, FORM),               "-")

-- wp-cron.php: WordPress tu goi. `spawn_cron` gui body RONG.
check("cron GET",             pre("/wp-cron.php", "GET"),             "-")
check("cron POST khong ct",   post("/wp-cron.php", nil, true, nil),   "-")
check("cron POST body rong",  post("/wp-cron.php", URLENC, true, FORM), "-")
check("cron doing_wp_cron",
      pre("/wp-cron.php?doing_wp_cron=1727000000.1", "GET"),          "-")

-- wp-comments-post.php
check("comment POST urlenc",  post("/wp-comments-post.php", URLENC, true, FORM), "-")
check("comment GET",          pre("/wp-comments-post.php", "GET"),    "-")

-- ── Route KHONG co hop dong: im lang TUYET DOI ──
io.write("routes: route KHONG khai bao -> im lang tuyet doi\n")
check("admin-ajax multipart",
      post("/wp-admin/admin-ajax.php", MULTI, true, WITH_FILE),       "-")
check("admin-ajax mp do",
      mp("/wp-admin/admin-ajax.php", MULTI, true),                    "-")
check("admin-ajax PUT",       pre("/wp-admin/admin-ajax.php", "PUT"), "-")
check("async-upload",
      post("/wp-admin/async-upload.php", MULTI, true, WITH_FILE),     "-")
check("wp-json PUT",          pre("/wp-json/wp/v2/posts/1", "PUT"),   "-")
check("goc GET",              pre("/", "GET"),                        "-")
check("index.php multipart",  post("/index.php", MULTI, true, WITH_FILE), "-")
check("route la PATCH",       pre("/api/x", "PATCH"),                 "-")
-- Sau HAI cap thi khong rang buoc: cung cap do `wp_prefix` cho phep hoc.
check("sau hai cap",          pre("/a/b/wp-login.php", "PUT"),        "-")

-- ══ 2. `route_upload` doi PARSER chung minh co tep ══════════════════════════
--
-- Day la loi 3 nguoi dung bat, va la truc ma ban truoc cua bo nay khoa SAI.
io.write("routes: route_upload chi ban khi CO part tep da chung minh\n")
check("cron + part tep",      post("/wp-cron.php", MULTI, true, WITH_FILE), "route_upload")
check("login + part tep",     post("/wp-login.php", MULTI, true, WITH_FILE), "route_upload")
check("xmlrpc + part tep",    post("/xmlrpc.php", MULTI, true, WITH_FILE), "route_upload")
check("comment + part tep",
      post("/wp-comments-post.php", MULTI, true, WITH_FILE),          "route_upload")

-- CHI CO FIELD: khong phai upload. `route_ct` van ban (multipart khong duoc phep).
check("chi co field -> KHONG upload", post("/wp-cron.php", MULTI, true, NO_FILE), "route_ct")
-- KHONG chung minh duoc: khong duoc bia ra "co tep".
check("khong chung minh -> KHONG upload",
      post("/wp-cron.php", MULTI, true, UNPROVEN),                    "route_ct")
-- `body = nil` (khong soi gi ca): cung khong duoc ket luan co tep.
check("body nil -> KHONG upload", post("/wp-cron.php", MULTI, true, nil), "route_ct")
-- `parts` RONG (bang rong, khong phai nil): cung khong co tep.
check("parts rong -> KHONG upload",
      post("/wp-cron.php", MULTI, true,
           { family = "multipart", proof = "ok", scan = "ok", parts = {} }), "route_ct")

-- `route_multipart` do RIENG: no ban cho MOI multipart, bat ke co tep. Do la cach
-- biet `route_upload` bo qua bao nhieu.
io.write("routes: route_multipart do RIENG, bat ke co tep\n")
check("mp co tep",            mp("/wp-cron.php", MULTI, true),        "route_multipart")
check("mp chi field",         mp("/wp-cron.php", MULTI, true),        "route_multipart")
check("mp khong than",        mp("/wp-cron.php", MULTI, false),       "-")
check("mp khong phai multipart", mp("/wp-cron.php", URLENC, true),    "-")
-- Route KHONG cam upload thi khong do (bang hop dong hom nay: khong co route nao
-- nhu vay, nen day la phep kiem ve CO CHE).
check("mp tren route khong khai bao", mp("/index.php", MULTI, true),  "-")

-- ══ 3. `route_ct` va `has_body` ═════════════════════════════════════════════
--
-- Loi 3 phan hai: mot `GET` mang `Content-Type` la la KHONG duoc sinh fact.
io.write("routes: khong co THAN -> content-type khong rang buoc gi\n")
check("GET + ct json",        post("/wp-login.php", JSON, false, nil), "-")
check("GET + ct la la",       post("/wp-login.php", "x/y", false, nil), "-")
check("POST co than + json",  post("/wp-login.php", JSON, true, FORM), "route_ct")
check("POST co than + xml",   post("/wp-login.php", XML, true, FORM),  "route_ct")
check("xmlrpc + urlencoded",  post("/xmlrpc.php", URLENC, true, FORM), "route_ct")
check("cron + json",          post("/wp-cron.php", JSON, true, FORM),  "route_ct")
check("ct la la",             post("/wp-login.php", "x/y", true, FORM), "route_ct")
-- `nil` (khong content-type) KHAC `other`: khong co gi de so.
check("co than nhung ct nil", post("/wp-login.php", nil, true, FORM),  "-")
check("co than nhung ct rong", post("/wp-login.php", "", true, FORM),  "-")

-- ══ 4. `route_method` la PHA 1 — khong can than ═════════════════════════════
io.write("routes: route_method o pha 1\n")
check("login PUT",            pre("/wp-login.php", "PUT"),            "route_method")
check("login DELETE",         pre("/wp-login.php", "DELETE"),         "route_method")
check("xmlrpc PATCH",         pre("/xmlrpc.php", "PATCH"),            "route_method")
check("cron TRACE",           pre("/wp-cron.php", "TRACE"),           "route_method")
check("method chu thuong ok", pre("/wp-login.php", "post"),           "-")
check("method thuong vi pham", pre("/wp-login.php", "put"),           "route_method")

-- ══ 5. Hop dong la OVERLAY WordPress ═══════════════════════════════════════
--
-- Loi 4 nguoi dung bat. Site khong phai WordPress co quyen dung `/wp-login.php`.
io.write("routes: chi ap khi host DA duoc chung minh la WordPress\n")
check("khong WP: PUT im",     pre("/wp-login.php", "PUT", NOTWP),     "-")
check("khong WP: json im",    post("/wp-login.php", JSON, true, FORM, NOTWP), "-")
check("khong WP: upload im",
      post("/wp-cron.php", MULTI, true, WITH_FILE, NOTWP),            "-")
check("khong WP: mp im",      mp("/wp-cron.php", MULTI, true, NOTWP), "-")
-- Cong nhan CMS thieu hoan toan (khong truyen ham): cung im.
check("khong co ham cong nhan",
      routes.check_pre("/wp-login.php", "PUT", nil, "a.test") == nil, true)

-- ══ 6. TIEN TO: WordPress cai trong thu muc con ════════════════════════════
--
-- Ban truoc khoa theo path CHINH XAC nen `/blog/wp-login.php` bi bo qua hoan toan
-- — mot lo FN ma nguoi dung chi ra.
io.write("routes: tien to (WordPress trong thu muc con)\n")
check("blog PUT",             pre("/blog/wp-login.php", "PUT"),       "route_method")
check("blog upload",
      post("/blog/wp-cron.php", MULTI, true, WITH_FILE),              "route_upload")
check("blog luu luong that im", post("/blog/wp-login.php", URLENC, true, FORM), "-")
-- `split_route` tra CA tien to: kiem truc tiep.
do
    local p1, r1 = routes.split_route("/wp-login.php")
    check("split goc: tien to rong", p1, "")
    check("split goc: route",        r1, "/wp-login.php")
    local p2, r2 = routes.split_route("/blog/wp-login.php")
    check("split blog: tien to",     p2, "/blog")
    check("split blog: route",       r2, "/wp-login.php")
    check("split sau hai cap",       routes.split_route("/a/b/wp-login.php"), nil)
    check("split route khong biet",  routes.split_route("/index.php"), nil)
end
-- Tien to di vao `is_wp_root`: mot `/blog` co WordPress KHONG lam `/shop` bi rang
-- buoc. Kiem bang mot ham cong nhan CHI dung cho `/blog`.
do
    local only_blog = function(_, prefix) return prefix == "/blog" end
    check("chi /blog duoc cong nhan",
          routes.check_pre("/blog/wp-login.php", "PUT", only_blog, "a.test"),
          "route_method")
    check("/shop khong duoc cong nhan",
          routes.check_pre("/shop/wp-login.php", "PUT", only_blog, "a.test") == nil,
          true)
end

-- ══ 7. `ct_family` va `path_of` ════════════════════════════════════════════
io.write("routes: ct_family va path_of\n")
check("fam nil",       routes.ct_family(nil),        nil)
check("fam rong",      routes.ct_family(""),         nil)
check("fam urlenc",    routes.ct_family(URLENC),     "urlencoded")
check("fam multi",     routes.ct_family(MULTI),      "multipart")
check("fam text/xml",  routes.ct_family(XML),        "xml")
check("fam app/xml",   routes.ct_family("application/xml"), "xml")
check("fam json",      routes.ct_family(JSON),       "json")
check("fam khac",      routes.ct_family("image/png"), "other")
check("fam co space",  routes.ct_family("  application/json  "), "json")
check("fam co param",  routes.ct_family("application/json; charset=utf-8"), "json")
check("path thuong",   routes.path_of("/wp-login.php"),        "/wp-login.php")
check("path co query", routes.path_of("/wp-login.php?a=1"),    "/wp-login.php")
check("path co frag",  routes.path_of("/wp-login.php#x"),      "/wp-login.php")
check("path ca hai",   routes.path_of("/x.php?a=1#y"),         "/x.php")
check("path nil",      routes.path_of(nil),                     "/")
check("path rong",     routes.path_of(""),                      "/")
check("path chi query", routes.path_of("?a=1"),                 "/")

-- ══ 8. Moi ten vi pham phai co MOT luat trong registry ═════════════════════
--
-- Mot ten ma `registry` khong biet thi `policy.emit` bo qua trong IM LANG — luat
-- khong bao gio chay, va khong ai bao loi.
io.write("routes: moi ten vi pham phai co luat trong registry\n")
for _, id in ipairs({ "route_method", "route_ct", "route_upload", "route_multipart" }) do
    local rule = registry.get(id)
    check("registry co " .. id, rule ~= nil, true)
    if rule then
        check(id .. " diem 0",       rule.score,   0)
        check(id .. " la observe",   rule.action,  "observe")
        check(id .. " ho protocol",  rule.family,  "protocol")
        -- Loi 4: PHAI la overlay wordpress, khong phai generic.
        check(id .. " profile wordpress", rule.profile, "wordpress")
    end
end

-- Nguoc lai: moi luat `route_*` phai duoc tra ve o mot ca nao do.
io.write("routes: moi luat route_* phai duoc phat o mot ca nao do\n")
do
    local emitted = {}
    emitted[routes.check_pre("/wp-login.php", "PUT", WP, "a.test")] = true
    emitted[routes.check_post("/wp-login.php", JSON, true, FORM, WP, "a.test")] = true
    emitted[routes.check_post("/wp-cron.php", MULTI, true, WITH_FILE, WP, "a.test")] = true
    emitted[routes.check_multipart("/wp-cron.php", MULTI, true, WP, "a.test")] = true
    for id in pairs(registry.all()) do
        if id:sub(1, 6) == "route_" then
            check("luat " .. id .. " co duong phat", emitted[id] == true, true)
        end
    end
end

-- ══ 9. Bang hop dong: moi dong phai co `why` ═══════════════════════════════
io.write("routes: moi hop dong phai co `why`\n")
do
    local n = 0
    for path, c in pairs(routes.CONTRACTS) do
        n = n + 1
        check("hop dong " .. path .. " co why",
              type(c.why) == "string" and #c.why > 10, true)
        check("hop dong " .. path .. " cho GET", c.methods.GET, true)
        -- Bon route deu KHONG nhan tep — do la bat bien chung cua bang hom nay.
        check("hop dong " .. path .. " cam tep", c.upload, false)
    end
    check("co du bon hop dong", n, 4)
end

io.write(string.format("\nroutes: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
