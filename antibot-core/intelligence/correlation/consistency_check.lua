local _M = {}

-- Attack 2 — HTTP/1.1 downgrade:
-- Bot force HTTP/1.1 để tránh H2 fingerprinting.
-- Thêm compound rule: Chrome UA + no H2 + no Sec-Fetch → penalty mạnh hơn.
-- api_callback class được loại trừ (server callback hợp lệ không có H2).

local function ua_is_chrome(ua)
    return ua and ua:find("Chrome/", 1, true) ~= nil
              and ua:find("Edg/",    1, true) == nil
end
local function ua_is_firefox(ua)
    return ua and ua:find("Firefox/", 1, true) ~= nil
end
local function ua_is_modern_browser(ua)
    return ua_is_chrome(ua) or ua_is_firefox(ua)
        or (ua and ua:find("Safari/", 1, true) ~= nil
                and ua:find("Chrome/", 1, true) == nil)
end

function _M.run(ctx)
    local score = 0.0
    local ua    = ctx.ua or ""
    local class = ctx.req_class or "navigation"
    local req   = ctx.req or {}

    -- Attack 2: skip H2 downgrade penalty cho api_callback
    -- (payment IPN, webhook, server callback hợp lệ không dùng H2)
    local skip_h2_check = (class == "api_callback")

    -- Chrome UA + không có H2 (nguyên bản: +0.25)
    if not skip_h2_check and ua_is_chrome(ua)
       and ctx.h2_is_h2 == false and ctx.ja3 ~= nil then
        score = score + 0.25
        ngx.log(ngx.DEBUG, "[consistency] chrome_ua+no_h2 ip=", ctx.ip)
    end

    -- Attack 2 — compound rule: Chrome/Firefox UA + no H2 + no Sec-Fetch
    -- Real browser trên HTTPS luôn có cả H2 lẫn Sec-Fetch.
    -- Thiếu cả hai = HTTP library giả mạo UA.
    if not skip_h2_check and ua_is_modern_browser(ua)
       and ctx.h2_is_h2 == false
       and (req.sec_fetch_mode == nil or req.sec_fetch_mode == "")
       and (req.sec_fetch_site == nil or req.sec_fetch_site == "") then
        score = score + 0.35
        ngx.log(ngx.DEBUG,
            "[consistency] browser_ua+no_h2+no_sec_fetch ip=", ctx.ip)
    end

    -- Chrome UA + TLS 1.2 (Chrome 100+ luôn dùng TLS 1.3)
    if ua_is_chrome(ua) and ctx.tls13 == false then
        score = score + 0.35
        ngx.log(ngx.DEBUG, "[consistency] chrome_ua+tls12 ip=", ctx.ip)
    end

    -- Browser UA + entropy thấp (headless không che hoàn toàn)
    local ent = ctx.entropy
    if ent and ent < 0.2 and ua_is_modern_browser(ua) then
        score = score + 0.45
        ngx.log(ngx.DEBUG, "[consistency] browser_ua+headless ip=", ctx.ip)
    end

    if ctx.h2_tls_mismatch then
        score = score + 0.25
    end

    if ctx.h2_header_profile then
        local ch = ctx.h2_header_profile.client_hints
        if ch and ch.has_ch_ua and not ua_is_chrome(ua) then
            score = score + 0.3
        end
    end

    if ctx.h2_bot_pattern then
        score = score + 0.3
    end

    ctx.mismatch = math.min(1.0, score)
end

return _M
