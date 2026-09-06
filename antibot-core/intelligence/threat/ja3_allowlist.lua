local _M   = {}
local pool = require "antibot.core.redis_pool"

-- MOT vong Redis cho ca hai danh sach, khong phai hai.
--
-- Ban truoc goi `safe_get` hai lan, va moi `safe_get` tu MO connection tu pool,
-- gui mot lenh, roi tra connection. Voi mot hash binh thuong — khong nam trong
-- ca allowlist lan blocklist, tuc gan nhu MOI request — do la hai vong tron
-- ven. Hom nay chua ai tra gia vi `ctx.ja3_partial` luon true nen ham `run`
-- thoat truoc do; nhung nac `cfg.tls.ja3_cipher = "on"` mo dung cho nay ra cho
-- toan bo traffic.
--
-- Thu tu trong pipeline giu nguyen y nghia cu: blocklist truoc, allowlist sau,
-- va block THANG khi ca hai cung co.
--
-- Van la HAI khoa chu khong gop thanh `ja3:status:<hash>`: admin/init.lua ghi,
-- xoa va `scan_keys` theo dung hai tien to nay (`ja3:allow:*`, `ja3:block:*`).
-- Gop khoa se pha giao dien quan tri va lam mo mat moi ban ghi dang co.
local function check_lists(ja3_hash)
    local res = pool.pipeline(function(red)
        red:get("ja3:block:" .. ja3_hash)
        red:get("ja3:allow:" .. ja3_hash)
    end)
    if type(res) ~= "table" then
        -- Redis hong => khong ket luan gi, roi ve phan tich cau truc ben duoi.
        return false, false
    end
    return res[1] == "1", res[2] == "1"
end

-- Tach chuoi ID phan cach bang dau `-` thanh TAP HOP de so khop CHINH XAC.
--
-- Ban truoc dung `ext_s:find("51")` tren ca chuoi. `find` khong biet ranh gioi
-- phan tu, nen mot client gui extension 17513 (ALPS — Chrome co gui) lam
-- `find("51")` khop ngay giua "17513" va he thong tuong client CO key_share.
-- Cung the: `curve_s:find("29")` khop trong bat ky ID nao chua "29".
--
-- HUONG SAI LA FAIL-OPEN, khong phai fail-closed: khop nham lam client trong
-- GIONG trinh duyet hon, tuc diem `miss` THAP hon. Nen day khong phai lo hong
-- gay chan nham dang chay; sua no la SIET LAI. Trinh duyet that khong bi anh
-- huong — chung gui du that extension 0/35/43/51 nen van dat >= 2 nhu cu.
local function id_set(s)
    local t, n = {}, 0
    if s and s ~= "" then
        for id in s:gmatch("[^%-]+") do
            t[id] = true
            n = n + 1
        end
    end
    return t, n
end

-- Analyse TLS structure from raw JA3 string to estimate browser-likeness.
-- JA3 format: tls_version,ciphers,extensions,curves,point_formats
-- Only runs when cipher list is available (ja3_partial = false).
-- This function returns a miss score (0.0 = browser-like, 1.0 = not browser).
local function score_from_tls_structure(ctx)
    local raw = ctx.ja3_raw
    if not raw or raw == "" then return 0.6 end

    local ver_s, cipher_s, ext_s, curve_s = raw:match("^(%d+),([^,]*),([^,]*),([^,]*)")
    if not ver_s then return 0.6 end

    local ver = tonumber(ver_s) or 0

    local ver_score = 0.0
    if ver ~= 0x0303 then ver_score = 0.2 end

    -- `cipher_count < 5` la nguong duoc GHIM tu phia con lai: `transport/tls/
    -- ja3.lua` chi bo co `partial` khi bat duoc >= MIN_PLAUSIBLE_CIPHERS cipher,
    -- va `contract_test` muc 10b kiem hai con so do khong lech nhau. Doi so 5 o
    -- day thi phai doi ca ben kia.
    local _, cipher_count = id_set(cipher_s)
    local cipher_score = 0.0
    if cipher_count < 5 then
        cipher_score = 0.6
    elseif cipher_count > 30 then
        cipher_score = 0.3
    end

    local ext = id_set(ext_s)
    local ext_score = 0.0
    local browser_ext_count = (ext["0"]  and 1 or 0)   -- server_name
                            + (ext["35"] and 1 or 0)   -- session_ticket
                            + (ext["43"] and 1 or 0)   -- supported_versions
                            + (ext["51"] and 1 or 0)   -- key_share
    if browser_ext_count < 2 then
        ext_score = 0.4
    end

    local curve = id_set(curve_s)
    local curve_score = 0.0
    if not curve["29"] and not curve["23"] then        -- x25519 / secp256r1
        curve_score = 0.3
    end

    local miss = math.max(ver_score, cipher_score, ext_score, curve_score)

    ngx.log(ngx.DEBUG,
        "[ja3_allow] structure_analysis",
        " ver_score=", ver_score,
        " cipher_score=", cipher_score,
        " ext_score=", ext_score,
        " curve_score=", curve_score,
        " miss=", miss)

    return miss
end

function _M.run(ctx)
    local ja3 = ctx.ja3
    -- `ctx.ja3_known_browser` DA BI GO (2026-09-06): ghi 4 lan, doc 0 lan.
    ctx.ja3_allowlist_miss = 0.0

    if not ja3 or ja3 == "" then
        return
    end

    -- Partial JA3: cipher list missing (no stream preread in this architecture).
    -- Hash is computed without ciphers → not meaningful for allowlist/blocklist.
    -- Skip scoring entirely to avoid false penalties on legitimate browsers.
    if ctx.ja3_partial then
        ctx.ja3_allowlist_miss = 0.0
        ngx.log(ngx.DEBUG, "[ja3_allow] partial → skip scoring")
        return
    end

    local blocked, allowed = check_lists(ja3)

    if blocked then
        ctx.ja3_allowlist_miss = 1.0
        ngx.log(ngx.INFO, "[ja3_allow] blocklist ja3=", ja3:sub(1,8))
        return
    end

    if allowed then
        ctx.ja3_allowlist_miss = 0.0
        ngx.log(ngx.DEBUG, "[ja3_allow] allowlist ja3=", ja3:sub(1,8))
        return
    end

    local miss = score_from_tls_structure(ctx)
    ctx.ja3_allowlist_miss = miss

    ngx.log(ngx.INFO,
        "[ja3_allow] structure ja3=", ja3,
        " miss=", miss,
        " ip=", ctx.ip or "?")
end

return _M
