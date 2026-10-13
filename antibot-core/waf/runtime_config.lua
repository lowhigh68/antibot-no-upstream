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
    --
    -- ── DAY LA MOT LUA CHON, KHONG PHAI MA NGU (ghi 13-10-2026) ─────────────
    --
    -- Co nay nhan override o moi scope (`config.lua` SCOPE_KEYS), duoc validate
    -- kieu boolean, va `policy_test.lua` co ca chay voi `true`. Doi mot boolean
    -- la no chay. Dung doc dong `= false` thanh "chuc nang chua lam xong".
    --
    -- TEN CO GAY HIEU SAI, va chinh toi da doc sai mot lan: `score_enforcement`
    -- KHONG phai "bat chan theo diem" ma la "bat SINH candidate theo diem".
    -- Viec chan do `threshold_mode` quyet. Hai co LONG NHAU:
    --
    --   Trang thai          | tinh state.score | ghi wscore | sinh score_threshold | chan boi TONG diem
    --   A. false + shadow   | CO               | CO         | khong                | khong   <- DANG O DAY
    --   B. true  + shadow   | CO               | CO         | co, vao `would_*`    | khong
    --   C. true  + enforce  | CO               | CO         | co                   | CO
    --
    -- Ca BA trang thai deu tinh va ghi diem: `policy.lua` cong vao `state.score`
    -- khong dieu kien, va `waf_logger.lua:481` ghi `wscore=` tu `dec.score`.
    -- `false` CHI vo hieu `score_candidate()` (`policy.lua:211` tra `nil`), nen
    -- tong diem khong sinh `score_threshold`, khong vao `would=`, va khong bao
    -- gio doi phan quyet.
    --
    -- Va o CA BA trang thai, TAM luat hard-block (`dotfile_exposed`,
    -- `dump_exposed`, `inc_exposed`, `wellknown_exec`, bon `wp_*_exec`) VAN chan
    -- binh thuong: `enforce_candidate` nhan chung o `policy.lua:183-184`, doc
    -- lap hoan toan voi co nay. "Khong chan boi tong diem" KHAC "khong chan".
    --
    -- NGUONG 100 danh gia TO HOP NHIEU SIGNAL YEU, khong phai mot luat manh:
    --   * 15 luat mang 100 diem deu DA co `action = "block"` (8 enforce, 7
    --     shadow) — chung chan bang chinh action, khong nho nguong tong;
    --   * va 7 correlation shadow KHONG cong vao `state.score` ca
    --     (`policy.lua:177` loai `family == "correlation"`, de mot correlation
    --     dang shadow khong the day tong qua nguong roi chan GIAN TIEP — vong
    --     qua chinh che do shadow cua no);
    --   * nen diem cong chi tu luat khac: cao nhat la 50 (`fim_new_executable`,
    --     `body_php_code`, `arg_php_wrapper`, `arg_null_byte`), roi 45, 40, 35.
    --     Dat 100 can it nhat HAI luat 50 diem cung ban.
    --
    -- ── VI SAO GIU `false` KHI DANG PAUSE S2.5 ─────────────────────────────
    --
    -- Nguoi dung chot: S2.5 PAUSED, dung bat `score_enforcement`. Trang thai B
    -- VAN la bat co nay du khong chan ai, nen khong lach quyet dinh do bang ly
    -- le "cai nay khac".
    --
    -- He qua da biet va CHAP NHAN: khong co du lieu would-block theo tong diem,
    -- nen C khong mo duoc bang so lieu — mot vong tron (cho so lieu, ma cong
    -- tat thi khong sinh so). Doi lai, moi luat `enforce` van chan day du.
    --
    -- NEU sau nay mo lai giai doan do, bat B truoc va bat buoc co BA thu, khong
    -- thi `would=block` khong truy duoc nguon:
    --   1. them `wreason=` (hoac tuong duong) de phan biet `would=block` den tu
    --      NGUONG TONG voi den tu mot trong 7 correlation shadow — hien hai thu
    --      do ghi cung mot gia tri;
    --   2. dat moc/version telemetry (`pver=`) tai thoi diem bat;
    --   3. tach du lieu TRUOC/SAU moc khi dem — cot `would=` doi nghia tai do,
    --      nen so hai ben khong so sanh duoc.
    -- Thu tu: bat B -> do 7 ngay -> doc `would=block` do `score_threshold` ->
    -- kiem `wpauth=1` (co admin that nao bi khop khong) -> roi moi quyet C.
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
