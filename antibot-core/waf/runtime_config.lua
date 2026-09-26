-- Cau hinh runtime cua WAF V2. NGUOI VAN HANH SUA FILE NAY.
--
-- `waf/config.lua` giu bang MAC DINH va khong duoc sua de doi chinh sach. File
-- nay la cho de doi: `antibot/init.lua:init_worker()` nap no roi goi
-- `waf.configure(...)`. Thieu buoc do thi toan bo co che per-domain, exception va
-- profile chi TON TAI trong ma nguon chu khong co hieu luc — do la trang thai
-- truoc 25-09, va no la mot lop cau hinh trong nhu da chay.
--
-- BA DIEU PHAI BIET TRUOC KHI SUA:
--
--   1. Cu phap sai thi `configure()` TRA LOI va cau hinh CU duoc giu. Khong co
--      nua vai: khong bao gio ap mot phan. Loi ra `error.log` voi tien to
--      `[waf-v2] config`.
--   2. Khoa la = LOI. `mod`, `mdoe`, `wordpres`, `uri_prefx` — bon ca go sai that
--      da tung vuot qua validator va lam cau hinh trong nhu da ap (ca thu tu thi
--      te hon: no NOI RONG mot exception ra toan bo luat). Gio chung bi tu choi.
--      Nen mot cau hinh duoc nhan la mot cau hinh duoc hieu dung.
--   3. `exceptions` PHAI co it nhat mot selector ngoai `id`. `id` chi la ten de
--      truy nguoc trong `waf.log` (cot `exc=`), no khong loc gi ca — mot
--      exception chi co `id` khop MOI luat tren MOI host.
--
-- DOI MOT GIA TRI O DAY LA MOT QUYET DINH AN NINH. Doc `waf/CLAUDE.md` truoc.
--
-- ─── Doc so lieu truoc khi doi bat cu gi ────────────────────────────────────
--
--   wafstat.sh muc 0b/0c   luat nao SE chan, va bao nhieu luot ban vao phien
--                          dang nhap that (cot `auth`). Cot do phai bang 0 VA
--                          dan so phai >= 30 truoc khi bat `enforce` cho mot
--                          correlation.
--   /antibot-admin/waf     bo dem telemetry, gom `write_errors` (phai bang 0;
--                          khac 0 nghia la `antibot_cache` day va moi con so
--                          khac khong tin duoc).

return {
    -- `enforce` = luat nao co `mode = "enforce"` thi duoc chan.
    -- `shadow`  = tinh du phan quyet nhung KHONG chan gi (cot `would=` van ghi).
    -- `observe` = chi thu thap su kien.
    --
    -- GIU `enforce`: cac bat bien cung (`dotfile_exposed`, `dump_exposed`,
    -- `wellknown_exec`, bon luat `*_exec` cua WordPress) dang chan that va do
    -- 25-09 tren nam may cho 0/1.700 luot ban vao phien dang nhap. Ha xuong
    -- `shadow` la MO cac duong do ra.
    mode = "enforce",

    -- Cham diem tong: TAT, co y. Cac luat mo ho va correlation phai co dan so
    -- do duoc truoc khi mot nguong diem duoc phep chan. Bat cai nay khi chua co
    -- so lieu la dung dung thu ma ca khung V2 duoc dung len de tranh.
    score_enforcement = false,

    -- Khong co override nao. De rong chu khong xoa: cho de them khi co so lieu,
    -- va de `policy_test.lua` co duong di qua nhanh nay.
    --
    -- Vi du (DUNG bo comment ma khong do truoc):
    --   rules = { arg_traversal = { mode = "shadow" } },
    --   domains = { ["shop.example.com"] = { profiles = { wordpress = false } } },
    --   exceptions = {
    --       { id = "magento-upload", rule = "arg_traversal",
    --         host = "shop.example.com", target = "BODY",
    --         uri_prefix = "/index.php/admin/catalog_product_gallery/upload/" },
    --   },
    --   `target` khop CHINH XAC. Tu V7 than request co ba target: `BODY` (moi byte
    --   chua chung minh la noi dung tep), `BODY_FILE` (noi dung tep) va
    --   `MULTIPART_FILENAME` (ten tep); query string la `ARGS`. Bo `target` thi
    --   exception ap cho moi target. (Vi du tren da loi thoi tu V7: `../` trong
    --   noi dung tep nay la `body_file_traversal`, observe.)
    rules        = {},
    families     = {},
    correlations = {},
    exceptions   = {},
    domains      = {},

    telemetry = {
        enabled = true,
        -- `per_host = false`: bat no lam sinh mot khoa moi cho MOI Host header,
        -- va Host la thu ke gui dat. `config.lua` da chan bang `host_limit`
        -- nhung nhom do la nhom DUY NHAT con phai quet trong `snapshot()`, nen
        -- bat no doi lai mot lan khoa dict moi lan doc so lieu.
        per_host = false,
    },
}
