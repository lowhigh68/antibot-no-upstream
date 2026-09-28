-- routes.lua — roadmap muc 5: HOP DONG ENDPOINT.
--
-- ── CAU HOI MA FILE NAY TRA LOI ─────────────────────────────────────
--
-- Khong phai "ai gui" (do la viec cua antibot: UA, cookie, toc do — xem
-- `detection/wp_hardening.lua`, no DA lam viec do tren dung cac route duoi day).
-- Khong phai "trong than co mau tan cong khong" (do la `args.lua`/`body_core`).
--
-- Cau o day la: **HINH DANG cua request nay co dung hop dong cua route do khong?**
--     method, content-type, co tep dinh kem khong.
--
-- Mot `POST /wp-cron.php` voi mot tep `.php` dinh kem khong vi pham luat NAO o hai
-- tang tren: UA co the la `WordPress/6.4`, than co the khong co `<?php`, ten tep co
-- the sach. Nhung `wp-cron.php` KHONG BAO GIO nhan upload. Do la thu ma chi mot hop
-- dong noi duoc.
--
-- ── HAI PHA, va vi sao BAT BUOC ─────────────────────────────────────
--
-- Ban dau ca ba phep kiem chay MOT lan, truoc khi doc than. Sai o hai cho:
--
--   1. `route_upload` chi thay `Content-Type: multipart/form-data` — no KHONG
--      chung minh co tep nao. Mot form multipart chi co field, hay mot than RONG
--      khai bao multipart, deu bi goi la "upload bi cam". Telemetry mang mot ten
--      noi dieu no khong do.
--   2. `route_ct` doc content-type ma chua biet co THAN hay khong, nen mot `GET`
--      mang `Content-Type` la la cung sinh fact.
--
-- Nen tach:
--   `check_pre`   truoc khi doc than — CHI method. Khong can than de biet method.
--   `check_post`  sau `body.probe` — content-type khi THAT SU co than, va upload
--                 khi parser DA CHUNG MINH co part tep (`parts`).
--
-- ── HOP DONG NAY LA OVERLAY WORDPRESS, khong phai generic ───────────
--
-- Bon route duoi day la route cua WordPress. Ap chung cho moi host la sai kien
-- truc, va se thanh FP that khi promote: mot site tu viet co quyen dung
-- `/wp-login.php` cho muc dich rieng. Nen:
--   · ba luat khai bao `profile = "wordpress"` (policy tu gate),
--   · VA `check_*` doi mot cong nhan CMS bang BANG CHUNG TREN DIA
--     (`wp_paths.is_wp_root`) — cung cong ma `wp_root_unknown` dung, khong viet
--     lai phep kiem thu hai.
--
-- `split_route` suy TIEN TO tu chinh ten route, nen `/blog/wp-login.php` duoc phu
-- khi WordPress cai trong thu muc con — ban truoc khoa theo path CHINH XAC nen no
-- bi bo qua hoan toan. Va vi `is_wp_root` khoa theo `(host, tien to)`, cong nhan
-- CMS o tien to do la cong RIENG: mot `/blog` co WordPress khong lam
-- `/shop/wp-login.php` bi rang buoc.
--
-- BAT BUOC LA LUA THUAN, khong `ngx.*`: de bo test nap duoc doc lap, va cung khuon
-- voi `upload.lua`/`upload_content.lua`/`upload_magic.lua`. Cong nhan WordPress di
-- vao bang MOT HAM (`is_wp_fn`), khong bang mot `require` — nen file nay khong keo
-- theo Redis lan shared dict.

local _M = {}

-- ── Ho content-type ─────────────────────────────────────────────────
--
-- `nil` nghia la KHONG CO content-type — khac `"other"` (co khai bao, khong nhan
-- ra). Hai thu nay khong duoc gop: mot hop dong co the cho phep "khong co than" ma
-- khong cho phep "than la dang la".
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
--
--   methods   tap method duoc phep. Thieu khoa = khong rang buoc.
--   ct        tap ho content-type duoc phep khi CO than. Thieu = khong rang buoc.
--   upload    `false` = route nay KHONG BAO GIO nhan tep.
--
-- `GET`/`HEAD` duoc phep o ca bon: WordPress tu goi `/wp-login.php` bang GET de
-- render form, `/xmlrpc.php` GET tra ve mot dong text, va mot cron trigger co the
-- la GET. Chan GET khong bat duoc gi ma pha ca bon route.
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

-- Tach mot URI thanh (tien to, path con) sao cho path con la khoa cua `CONTRACTS`.
-- Tra `nil` khi URI khong tro tới route nao trong bang.
--
-- `wp_prefix` cua `paths.lua` KHONG dung duoc o day: no chi hoc tien to tu
-- `/wp-content/`, `/wp-admin/`, `/wp-includes/` — ba marker khong xuat hien trong
-- bon route nay. Nen suy tien to tu CHINH ten route, va chi MOT cap sau (cung cap
-- do `wp_prefix` cho phep hoc): `/blog/wp-login.php` -> ("/blog", "/wp-login.php").
local function split_route(uri)
    local p = path_of(uri)
    if CONTRACTS[p] then return "", p end
    local seg, rest = p:match("^(/[^/]+)(/[^/]+)$")
    if seg and CONTRACTS[rest] then return seg, rest end
    return nil
end
_M.split_route = split_route

-- Hop dong cua mot URI, hoac `nil`.
--
-- `is_wp_fn`  ham `(host, prefix, docroot) -> boolean`: thu muc nay DA duoc
--             chung minh la
--             WordPress tai tien to do (bang chung tren dia). Thieu no thi KHONG
--             hop dong nao ap — day la cong overlay. Truyen ham chu khong boolean
--             vi tien to chi biet SAU khi tach URI, va `is_wp_root` khoa theo
--             (host, tien to).
-- `host`      de truyen cho `is_wp_fn`.
local function contract_of(uri, is_wp_fn, host, docroot)
    local prefix, p = split_route(uri)
    if not prefix then return nil end
    if not is_wp_fn or not is_wp_fn(host, prefix, docroot) then return nil end
    return CONTRACTS[p], p
end
_M.contract_of = contract_of

-- ── PHA 1: truoc khi doc than — CHI method ──────────────────────────
--
-- Tra `"route_method", <path>` hoac `nil`. Khong doc content-type o day: mot
-- content-type khong noi duoc gi cho tới khi biet co THAN hay khong.
function _M.check_pre(uri, method, is_wp_fn, host, docroot)
    local c, p = contract_of(uri, is_wp_fn, host, docroot)
    if not c then return nil end
    if c.methods and method and not c.methods[method:upper()] then
        return "route_method", p
    end
    return nil
end

-- ── PHA 2: sau `body.probe` — content-type va tep dinh kem ──────────
--
-- `body`  ket qua cua `body.probe` (bang tu `body_core.scan`, hoac `nil` khi khong
--         co than). Hai truong duoc dung:
--           `body.parts`  danh sach part TEP da CHUNG MINH (V8). Khong rong =>
--                         that su co tep dinh kem.
--           `body.scan`   trang thai soi; `nil`/khong ok nghia la KHONG chung
--                         minh duoc, va khi do khong duoc ket luan "co tep".
-- `has_body`  than co ton tai khong. Mot `GET` mang `Content-Type` la la KHONG
--             sinh fact — khong co than thi content-type khong rang buoc gi.
--
-- Tra `"route_upload"` hoac `"route_ct"` kem path, hoac `nil`.
--
-- `route_upload` uu tien tren `route_ct`: mot multipart CO TEP tren route khong
-- bao gio nhan tep vi pham ca hai, va bao cai nhe hon la noi nhe hon han su that.
function _M.check_post(uri, content_type, has_body, body, is_wp_fn, host, docroot)
    local c, p = contract_of(uri, is_wp_fn, host, docroot)
    if not c then return nil end
    if not has_body then return nil end

    local fam = ct_family(content_type)
    if not fam then return nil end

    -- `upload == false` + CO TEP DA CHUNG MINH. Khong dung `fam == "multipart"`:
    -- do chi la mot LOI KHAI BAO cua ke gui, khong phai bang chung co tep. Mot
    -- form multipart chi co field la chuyen binh thuong tren mot form dang nhap
    -- co `enctype` do plugin doi.
    if c.upload == false and body and body.parts and #body.parts > 0 then
        return "route_upload", p
    end
    if c.ct and not c.ct[fam] then
        return "route_ct", p
    end
    return nil
end

-- `route_multipart` — DO RIENG, khong tron vao `route_upload`.
--
-- Cau hoi khac: "route nay co nhan mot than multipart khong", bat ke co tep. Con
-- so nay can de biet nhom `route_upload` bo qua bao nhieu (multipart chi co field,
-- va multipart KHONG soi duoc). Neu khong do thi khong biet `route_upload` im lang
-- vi sach hay vi khong chung minh duoc.
function _M.check_multipart(uri, content_type, has_body, is_wp_fn, host, docroot)
    local c, p = contract_of(uri, is_wp_fn, host, docroot)
    if not c or c.upload ~= false then return nil end
    if not has_body then return nil end
    if ct_family(content_type) ~= "multipart" then return nil end
    return "route_multipart", p
end

return _M
