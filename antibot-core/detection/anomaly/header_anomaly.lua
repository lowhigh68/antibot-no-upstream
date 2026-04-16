local _M = {}

-- Header anomaly detection — device-aware structural analysis.
--
-- Nguyên tắc:
--   1. Penalty signal mobile KHÔNG HỖ TRỢ → giảm/bỏ
--   2. Penalty signal mobile PHẢI CÓ nhưng thiếu → giữ hoặc tăng
--   3. Signal MỚI phân biệt mobile thật vs bot giả mobile UA

local function ua_lacks_browser_structure(ua)
    if ua == "" then return false end
    local has_platform = ua:find("(", 1, true) ~= nil
    local has_engine   = ua:find("AppleWebKit/", 1, true)
                      or ua:find("Gecko/",        1, true)
                      or ua:find("Trident/",      1, true)
    return not has_platform or not has_engine
end

local function ua_is_versioned_tool(ua)
    if #ua > 80 then return false end
    return ua:match("^[%w%.%-%_]+/%d") ~= nil
       and not ua:find("(", 1, true)
end

-- Sec-Fetch penalty dựa trên device type
-- Trả về penalty score (0.0 - 0.4)
local function sec_fetch_penalty(device_type, sec_fetch_expected)
    -- Nếu device classifier đã xác định không expected → 0
    if not sec_fetch_expected then
        -- inapp: hoàn toàn không penalize
        if device_type == "inapp" then return 0.0 end
        -- iOS cũ, custom_tab: penalty nhẹ (bot vẫn có thể giả)
        if device_type == "mobile_safari_ios_old"
        or device_type == "tablet_ipad"  -- sẽ được set expected=false nếu old
        or device_type == "custom_tab" then
            return 0.05
        end
        return 0.05  -- unknown device cũng nhẹ
    end

    -- Device expected Sec-Fetch nhưng không có:
    if device_type == "desktop_chrome"
    or device_type == "desktop_firefox" then
        return 0.40  -- desktop modern browser phải có
    end
    if device_type == "desktop_safari" then
        return 0.30  -- Safari desktop có từ 16.1
    end
    if device_type == "mobile_chrome_android" then
        return 0.30  -- Chrome Android có từ v76
    end
    if device_type == "mobile_safari_ios" then
        return 0.25  -- Safari iOS >= 16.4
    end
    if device_type == "tablet_ipad" then
        return 0.25
    end
    if device_type == "tablet_android" then
        return 0.25
    end
    -- fallback
    return 0.30
end

function _M.run(ctx)
    local score = 0.0
    local req   = ctx.req or {}
    local ua    = ctx.ua  or ""

    local device_type     = ctx.device_type or "unknown"
    local sec_fetch_exp   = ctx.device_sec_fetch_expected
    local ch_mobile_exp   = ctx.device_ch_ua_mobile_expected
    local is_mobile       = ctx.device_is_mobile or false

    -- ── UA structure check ───────────────────────────────────
    if ua == "" then
        score = score + 0.5
        ngx.log(ngx.DEBUG, "[anomaly] empty UA ip=", ctx.ip)
    elseif ua_is_versioned_tool(ua) then
        score = score + 0.35
        ngx.log(ngx.DEBUG, "[anomaly] versioned_tool UA ip=", ctx.ip)
    elseif ua_lacks_browser_structure(ua) then
        score = score + 0.25
        ngx.log(ngx.DEBUG, "[anomaly] no_browser_structure UA ip=", ctx.ip)
    end

    -- ── Accept header ────────────────────────────────────────
    if not req.accept or req.accept == "" then
        score = score + 0.2
    end

    -- ── Accept-Language ──────────────────────────────────────
    local lang = req.accept_lang or req.lang or ""
    if lang == "" then
        -- Mobile thật LUÔN có Accept-Language từ OS locale
        -- → không có = suspect MẠNH HƠN với mobile
        if is_mobile then
            score = score + 0.20
        else
            score = score + 0.15
        end
    end

    -- ── Accept-Encoding / brotli ─────────────────────────────
    local accept_enc = req.accept_enc or ""
    if accept_enc == "" then
        score = score + 0.10
    elseif not accept_enc:find("br", 1, true) then
        -- Chrome (desktop + Android) và Firefox luôn support brotli
        if device_type == "desktop_chrome"
        or device_type == "desktop_firefox"
        or device_type == "mobile_chrome_android" then
            score = score + 0.10
        end
    end

    -- ── Sec-Fetch headers (device-aware) ────────────────────
    local scheme   = ngx.var.scheme or ""
    if scheme == "https" then
        local sf_mode = req.sec_fetch_mode or ""
        local sf_site = req.sec_fetch_site or ""
        local sf_dest = req.sec_fetch_dest or ""

        local has_sec_fetch = sf_mode ~= "" or sf_site ~= "" or sf_dest ~= ""

        if not has_sec_fetch then
            local penalty = sec_fetch_penalty(device_type, sec_fetch_exp)
            if penalty > 0 then
                score = score + penalty
                ngx.log(ngx.DEBUG,
                    "[anomaly] no_sec_fetch device=", device_type,
                    " penalty=", penalty,
                    " ip=", ctx.ip)
            end

            -- Compound: thiếu Sec-Fetch + thiếu Accept-Language
            -- Chỉ penalize compound khi device phải có cả hai
            if lang == "" and sec_fetch_exp then
                score = score + 0.10
                ngx.log(ngx.DEBUG,
                    "[anomaly] compound missing headers ip=", ctx.ip)
            end
        elseif sf_mode == "" then
            score = score + 0.15
        end
    end

    -- ── Mobile protocol check (signal cứng, không gộp) ────────
    -- Mobile browser thật LUÔN dùng HTTP/2 trên HTTPS.
    -- HTTP/1.1 + mobile UA là signal cứng riêng biệt — không phải
    -- UA identity issue mà là protocol impossibility.
    local proto  = ctx.req and ctx.req.proto or ngx.var.server_protocol or ""
    local is_http1 = proto == "HTTP/1.1" or proto == "HTTP/1.0"
    if is_mobile and is_http1 and scheme == "https" then
        score = score + 0.50
        ngx.log(ngx.DEBUG,
            "[anomaly] mobile_ua_http1_on_https device=", device_type,
            " ip=", ctx.ip)
    end

    -- ── UA identity uncertainty (group) ──────────────────────
    -- Gộp tất cả các trường hợp UA claim một browser identity
    -- nhưng headers không khớp hoàn toàn.
    --
    -- Nguyên nhân hợp lệ (không phải bot):
    --   - Chrome DevTools device emulation (Safari UA + CH-UA Chrome)
    --   - Firefox/Safari bug gửi header lạ
    --   - Browser extension đổi UA string
    --   - VPN/proxy app thay đổi UA
    --   - Chrome Android + extension không đổi CH-UA-Mobile
    --
    -- Xử lý: đếm số inconsistency, map thành penalty nhỏ duy nhất.
    -- Không penalize từng check riêng — signal quá dễ bypass và
    -- quá nhiều false positive từ legitimate tools.
    do
        local inconsistency_count = 0

        -- Safari UA nhưng có Sec-CH-UA (Chrome Client Hints)
        -- Safari không bao giờ gửi CH-UA theo spec
        local is_safari_ua = (device_type == "mobile_safari_ios"
                           or device_type == "mobile_safari_ios_old"
                           or device_type == "desktop_safari"
                           or device_type == "tablet_ipad")
        if is_safari_ua and (ngx.var.http_sec_ch_ua or "") ~= "" then
            inconsistency_count = inconsistency_count + 1
        end

        -- Chrome Android UA nhưng thiếu Sec-CH-UA-Mobile: ?1
        -- Chrome Android 89+ luôn gửi, trừ khi extension can thiệp
        if ch_mobile_exp and (ngx.var.http_sec_ch_ua_mobile or "") == "" then
            inconsistency_count = inconsistency_count + 1
        end

        -- Mobile UA nhưng Sec-CH-UA-Platform claim desktop OS
        -- (ví dụ UA = Android nhưng Platform = "Windows")
        local ch_platform = ngx.var.http_sec_ch_ua_platform or ""
        if is_mobile and ch_platform ~= "" then
            local platform_lower = ch_platform:lower()
            local desktop_platform = platform_lower:find("windows") or
                                     platform_lower:find("macos")   or
                                     platform_lower:find("linux")
            if desktop_platform then
                inconsistency_count = inconsistency_count + 1
            end
        end

        -- 1 inconsistency: có thể là tool/extension → penalty rất nhỏ
        -- 2+ inconsistency: khó giải thích bằng legitimate tool → penalty lớn hơn
        if inconsistency_count == 1 then
            score = score + 0.10
            ctx.ua_identity_uncertain = true
            ngx.log(ngx.DEBUG,
                "[anomaly] ua_identity_uncertain=1 device=", device_type,
                " ip=", ctx.ip)
        elseif inconsistency_count >= 2 then
            score = score + 0.20
            ctx.ua_identity_uncertain = true
            ngx.log(ngx.DEBUG,
                "[anomaly] ua_identity_uncertain=", inconsistency_count,
                " device=", device_type,
                " ip=", ctx.ip)
        end
    end

    -- ── Referer chain (Attack 4 — slow crawl) ────────────────
    local class    = ctx.req_class or "unknown"
    if class == "navigation" or class == "unknown" then
        local referer  = ngx.var.http_referer or ""
        local sess_len = ctx.sess_len or 0
        local host     = ngx.var.host or ""

        if sess_len > 2 and referer == "" then
            score = score + 0.15
            ngx.log(ngx.DEBUG, "[anomaly] no_referer_returning ip=", ctx.ip)
        end

        if referer ~= "" and host ~= "" then
            local ref_host = referer:match("https?://([^/]+)")
            if ref_host and ref_host ~= host then
                local known_referrer =
                    ref_host:find("google",   1, true) or
                    ref_host:find("bing",     1, true) or
                    ref_host:find("yahoo",    1, true) or
                    ref_host:find("facebook", 1, true) or
                    ref_host:find("zalo",     1, true)
                if not known_referrer and sess_len > 5 then
                    score = score + 0.10
                    ngx.log(ngx.DEBUG,
                        "[anomaly] external_referer ip=", ctx.ip,
                        " ref=", ref_host)
                end
            end
        end
    end

    ctx.header_flag = math.min(1.0, score)
end

return _M
