local _M   = {}
local pool = require "antibot.core.redis_pool"

local function check_redis_allowlist(ja3_hash)
    local val = pool.safe_get("ja3:allow:" .. ja3_hash)
    return val == "1"
end

local function check_redis_blocklist(ja3_hash)
    local val = pool.safe_get("ja3:block:" .. ja3_hash)
    return val == "1"
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

    local cipher_count = 0
    for _ in cipher_s:gmatch("[^%-]+") do cipher_count = cipher_count + 1 end
    local cipher_score = 0.0
    if cipher_count < 5 then
        cipher_score = 0.6
    elseif cipher_count > 30 then
        cipher_score = 0.3
    end

    local ext_score = 0.0
    local has_sni      = ext_s:find("^0%-") or ext_s:find("%-0%-") or ext_s:find("%-0$") or ext_s == "0"
    local has_sess     = ext_s:find("35")
    local has_versions = ext_s:find("43")
    local has_keyshare = ext_s:find("51")
    local browser_ext_count = (has_sni and 1 or 0) + (has_sess and 1 or 0)
                            + (has_versions and 1 or 0) + (has_keyshare and 1 or 0)
    if browser_ext_count < 2 then
        ext_score = 0.4
    end

    local curve_score = 0.0
    local has_x25519 = curve_s:find("29")
    local has_p256   = curve_s:find("23")
    if not has_x25519 and not has_p256 then
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
    ctx.ja3_known_browser  = false
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

    if check_redis_blocklist(ja3) then
        ctx.ja3_known_browser  = false
        ctx.ja3_allowlist_miss = 1.0
        ngx.log(ngx.INFO, "[ja3_allow] blocklist ja3=", ja3:sub(1,8))
        return
    end

    if check_redis_allowlist(ja3) then
        ctx.ja3_known_browser  = true
        ctx.ja3_allowlist_miss = 0.0
        ngx.log(ngx.DEBUG, "[ja3_allow] allowlist ja3=", ja3:sub(1,8))
        return
    end

    local miss = score_from_tls_structure(ctx)
    ctx.ja3_known_browser  = (miss < 0.3)
    ctx.ja3_allowlist_miss = miss

    ngx.log(ngx.INFO,
        "[ja3_allow] structure ja3=", ja3,
        " miss=", miss,
        " ip=", ctx.ip or "?")
end

return _M
