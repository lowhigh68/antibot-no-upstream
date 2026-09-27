-- routes.lua — roadmap muc 5: HOP DONG ENDPOINT.
--
-- ── CAU HOI MA FILE NAY TRA LOI ─────────────────────────────────────
--
-- Khong phai "ai gui" (do la viec cua antibot: UA, cookie, toc do — xem
-- `detection/wp_hardening.lua`, no DA lam viec do tren dung cac route duoi day).
-- Khong phai "trong than co mau tan cong khong" (do la `args.lua`/`body_core`).
--
-- Cau o day la: **HINH DANG cua request nay co dung hop dong cua route do khong?**
--     method, content-type, co body khong, co upload khong.
--
-- Mot `POST /wp-cron.php` voi `multipart/form-data` chua mot tep `.php` khong vi
-- pham luat NAO o hai tang tren: UA co the la `WordPress/6.4`, than co the khong
-- co `<?php`, ten tep co the sach. Nhung `wp-cron.php` KHONG BAO GIO nhan upload.
-- Do la thu ma chi mot hop dong noi duoc.
--
-- ── VI SAO HEP, va vi sao KHONG "hoc tu log" ────────────────────────
--
-- Positive security (chi cho phep cai da khai bao) la mot phep dao nguoc nguy
-- hiem: moi thu khong khai bao thanh dang nghi. Tren 43 domain khach ma KHONG AI
-- khai bao route cua site ho, mot hop dong rong la mot may FP.
--
-- Nen bang duoi day CO Y chi chua route co BAT BIEN GIAO THUC — thu dung voi moi
-- ban WordPress tren moi may, doc ra duoc tu chinh ma WordPress, khong phai tu
-- "toi thay log no thuong nhu vay":
--
--   /wp-cron.php        WordPress goi bang `wp_remote_post` KHONG co body va
--                       khong co file; no la mot cron trigger. `spawn_cron()`
--                       gui `blocking => false, body => array()`.
--   /xmlrpc.php         Giao thuc XML-RPC: than PHAI la XML. Khong co dinh nghia
--                       nao cua XML-RPC dung multipart.
--   /wp-login.php       Form dang nhap: `<form method="post">` khong co
--                       `enctype`, tuc urlencoded theo HTML. Khong co truong file.
--   /wp-comments-post.php  Cung vay — form comment cua WordPress khong co file.
--
-- KHONG co `/wp-admin/`, KHONG co `/wp-json/`: hai cho do plugin cam duoc tay
-- vao va upload that su xay ra o `admin-ajax.php`. Dat hop dong o do la dat FP.
-- Do cung la ly do `wp_hardening` khong cover `wp-admin` (chu thich cua no).
--
-- ── DIEM 0, SHADOW ──────────────────────────────────────────────────
--
-- Cung khuon B1/B3 va muc 7/8: chua co MOT con so nao tren dan may nay ve bao
-- nhieu request THAT vi pham cac hop dong tren. `postdeploy.sh` muc 14 la cho
-- quyet. Khong bat truoc khi co so.
--
-- BAT BUOC LA LUA THUAN, khong `ngx.*`: de bo test nap duoc doc lap, va de cung
-- khuon voi `upload.lua`/`upload_content.lua`/`upload_magic.lua`.

local _M = {}

-- ── Ho content-type ─────────────────────────────────────────────────
--
-- Chi phan loai tho, va do la co y. `body_core.ct_family` da co mot phep phan
-- loai rieng cho viec soi than; o day can mot cau khac: "ho content-type nay co
-- nam trong danh sach route cho phep khong".
--
-- `nil` nghia la KHONG CO content-type (GET, hoac POST khong khai bao) — khac
-- `"other"` (co khai bao, khong nhan ra). Hai thu nay khong duoc gop: mot hop
-- dong co the cho phep "khong co body" ma khong cho phep "body la dang la".
local function ct_family(ct)
    if not ct or ct == "" then return nil end
    local low = ct:lower()
    -- Cat tham so (`; charset=`, `; boundary=`) truoc khi so.
    local base = low:match("^([^;]+)") or low
    base = base:gsub("^%s+", ""):gsub("%s+$", "")
    if base == "application/x-www-form-urlencoded" then return "urlencoded" end
    if base == "multipart/form-data"                then return "multipart" end
    if base == "text/xml" or base == "application/xml" then return "xml" end
    if base == "application/json"                   then return "json" end
    return "other"
end
_M.ct_family = ct_family

-- ── Bang hop dong ───────────────────────────────────────────────────
--
-- Moi dong phai dan duoc ve mot BAT BIEN doc tu ma WordPress, khong phai tu log.
-- Khoa la URI CHINH XAC (khong phai tien to): ba trong bon route nay la mot file
-- cu the, va `/wp-cron.php` co the mang query string nen so sanh o
-- `_M.check` dung phan path da tach.
--
--   methods   tap method duoc phep. Thieu khoa = khong rang buoc.
--   ct        tap ho content-type duoc phep khi CO body. Thieu = khong rang buoc.
--   upload    `false` = route nay KHONG BAO GIO nhan tep. `nil` = khong noi gi.
--
-- `GET` duoc phep o ca bon: WordPress tu goi `/wp-login.php` bang GET de render
-- form, `/xmlrpc.php` GET tra ve mot dong text, va mot cron trigger co the la GET.
-- Chan GET o day khong bat duoc gi ma pha ca bon route.
local CONTRACTS = {
    ["/wp-cron.php"] = {
        -- `spawn_cron()` trong `wp-includes/cron.php` goi `wp_remote_post` voi
        -- `body => array()` — tuc than RONG. Khong co duong nao trong WordPress
        -- gui tep tin den day.
        methods = { GET = true, POST = true, HEAD = true },
        ct      = { urlencoded = true },
        upload  = false,
        why     = "cron trigger: than rong, khong bao gio co tep",
    },
    ["/xmlrpc.php"] = {
        -- Giao thuc XML-RPC (`class-IXR-server.php`): than la XML. Jetpack cung
        -- dung dung giao thuc do.
        methods = { GET = true, POST = true, HEAD = true },
        ct      = { xml = true },
        upload  = false,
        why     = "XML-RPC: than PHAI la XML theo giao thuc",
    },
    ["/wp-login.php"] = {
        -- `wp-login.php` in mot `<form name="loginform" method="post">` khong co
        -- `enctype`, nen theo HTML la `application/x-www-form-urlencoded`. Khong
        -- co `<input type="file">` nao trong form do.
        methods = { GET = true, POST = true, HEAD = true },
        ct      = { urlencoded = true },
        upload  = false,
        why     = "form dang nhap: urlencoded, khong co truong tep",
    },
    ["/wp-comments-post.php"] = {
        -- `comment_form()` cung in mot form khong `enctype`. Anh trong comment la
        -- viec cua plugin, va plugin nao lam vay thi gui qua `admin-ajax.php`
        -- chu khong qua day.
        methods = { GET = true, POST = true, HEAD = true },
        ct      = { urlencoded = true },
        upload  = false,
        why     = "form comment: urlencoded, khong co truong tep",
    },
}
_M.CONTRACTS = CONTRACTS

-- Tach phan path khoi URI. `ngx.var.uri` da bo query string, nhung ham nay la Lua
-- thuan va duoc goi ca tu test voi chuoi tho — nen tu cat, va cat CA `?` lan `#`.
local function path_of(uri)
    if not uri or uri == "" then return "/" end
    local p = uri:match("^([^?#]*)") or uri
    if p == "" then return "/" end
    return p
end
_M.path_of = path_of

-- ── Phep kiem ───────────────────────────────────────────────────────
--
-- Tra `nil` khi khong co gi de noi (route khong co hop dong, hoac request dung
-- hop dong). Khi vi pham, tra TEN VI PHAM — mot chuoi tu tap co dinh duoi day,
-- KHONG chua gi do ke gui dat:
--
--   route_method     method khong nam trong tap cho phep
--   route_ct         co body voi ho content-type khong duoc phep
--   route_upload     route khong bao gio nhan tep, ma day la multipart
--
-- `has_body` tach khoi `ct`: mot `POST` khong co `Content-Type` la mot cau khac
-- voi mot `POST` co `Content-Type: application/json`. Cai dau khong vi pham `ct`
-- (khong co gi de so), cai sau thi co.
-- Tra ve HAI gia tri: ten vi pham, va ten route (khoa cua bang `CONTRACTS`).
-- Ten route la mot HANG SO trong ma nay, khong phai chuoi ke gui dat — nen no vao
-- duoc `matched=` cua log, con URI tho thi khong.
function _M.check(uri, method, content_type)
    local path = path_of(uri)
    local c = CONTRACTS[path]
    if not c then return nil end

    if c.methods and method and not c.methods[method:upper()] then
        return "route_method", path
    end

    local fam = ct_family(content_type)
    if not fam then return nil end      -- khong co body khai bao -> het cau hoi

    -- `upload = false` kiem TRUOC `ct`: mot multipart tren route khong nhan tep la
    -- ket luan MANH hon "content-type khong duoc phep", va hai luat cung khop thi
    -- phai bao cai manh hon. Nguoc lai thi mot upload vao `/wp-cron.php` chi duoc
    -- bao la `route_ct` — dung nhung nhe hon han su that.
    if c.upload == false and fam == "multipart" then
        return "route_upload", path
    end
    if c.ct and not c.ct[fam] then
        return "route_ct", path
    end
    return nil
end

return _M
