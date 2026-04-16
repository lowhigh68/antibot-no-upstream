local _M = {}

-- ============================================================
-- Device classifier — phân loại thiết bị từ UA + HTTP signals
--
-- ctx.device_type values:
--   mobile_chrome_android  — Chrome trên Android
--   mobile_safari_ios      — Safari trên iPhone/iPod
--   mobile_safari_ios_old  — Safari iOS < 16.4 (không có Sec-Fetch)
--   tablet_ipad            — Safari/Chrome trên iPad
--   tablet_android         — Chrome trên Android tablet (không có "Mobile/")
--   desktop_chrome         — Chrome trên Windows/Mac/Linux
--   desktop_safari         — Safari trên macOS
--   desktop_firefox        — Firefox trên bất kỳ desktop OS
--   desktop_other          — Desktop browser khác
--   custom_tab             — Chrome Custom Tab / WebView không phải inapp
--   inapp                  — WebView trong app đã biết (Zalo, FB, ...)
--   unknown                — không xác định
--
-- ctx.device_sec_fetch_expected: boolean
--   true  = device này phải gửi Sec-Fetch headers
--   false = device này không gửi / không đảm bảo gửi Sec-Fetch
--
-- ctx.device_ch_ua_mobile_expected: boolean
--   true  = Chrome Android: phải gửi Sec-CH-UA-Mobile: ?1
--
-- ctx.device_is_mobile: boolean (mobile + tablet)
-- ctx.device_ios_version: number | nil (iOS version từ UA)
-- ============================================================

local SEC_FETCH_THRESHOLD_IOS = 16  -- iOS 16.4+ có Sec-Fetch

-- Parse iOS version từ UA string
-- UA format: "... CPU iPhone OS 17_0 ..." hoặc "CPU OS 16_4 ..."
local function parse_ios_version(ua)
    local v = ua:match("CPU%s+iPhone%s+OS%s+(%d+)[_%.]")
           or ua:match("CPU%s+OS%s+(%d+)[_%.]")
    return v and tonumber(v) or nil
end

-- Detect Android tablet: có Android nhưng KHÔNG có "Mobile/"
-- Android phone: "Mozilla/5.0 (Linux; Android 13; Pixel 7) ... Mobile Safari"
-- Android tablet: "Mozilla/5.0 (Linux; Android 13; SM-T870) ... Safari" (no Mobile)
local function is_android_tablet(ua)
    return ua:find("Android", 1, true) ~= nil
       and ua:find("Mobile", 1, true) == nil
       and ua:find("iPad", 1, true) == nil
end

-- Detect Chrome Custom Tab / embedded WebView không phải inapp app đã biết
-- Chrome Custom Tab UA: thêm "wv" trong parentheses
-- Ví dụ: "Mozilla/5.0 (Linux; Android 12; SM-G998B wv) AppleWebKit/... Chrome/..."
local function is_custom_tab(ua)
    if not ua then return false end
    -- "wv" token trong platform section
    if ua:find("%(%S* wv[%)%s]") or ua:find("%(.*; wv%)") then
        return true
    end
    -- Version/x.0 pattern với mobile context (generic WebView pattern)
    -- Loại trừ:
    --   Safari iOS thật: có "CPU iPhone OS" trong UA
    --   Android tablet dùng Samsung Browser: Android + Version/x.0 nhưng KHÔNG có "Mobile"
    --   (Samsung Browser trên tablet không append "Mobile", phone thì có)
    if (ua:find("Android", 1, true) or ua:find("iPhone", 1, true))
    and ua:find("Version/%d", 1, false)
    and not ua:find("Chrome/", 1, true)
    and not ua:find("Firefox/", 1, true)
    and not ua:find("CPU iPhone OS", 1, true)
    and ua:find("Mobile", 1, true) ~= nil then
        return true
    end
    return false
end

-- Known inapp app tokens (từ req_classifier.lua, sync ở đây)
local INAPP_TOKENS = {
    "Zalo", "FBAN", "FBAV", "FBIOS", "Instagram",
    "Line/", "Twitter", "TikTok", "Snapchat", "Pinterest",
    "LinkedIn", "MicroMessenger", "Viber",
    "Shopee", "Lazada", "TikiApp",
}

local function is_inapp(ua)
    if not ua or ua == "" then return false end
    local is_mobile = ua:find("Mobile/", 1, true)
                   or ua:find("Android", 1, true)
    if not is_mobile then return false end
    for _, token in ipairs(INAPP_TOKENS) do
        if ua:find(token, 1, true) then return true end
    end
    return false
end

function _M.classify(ua, proto)
    if not ua or ua == "" then
        return {
            device_type                   = "unknown",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

    local is_h2 = proto and proto:find("HTTP/2", 1, true) ~= nil

    -- ── inapp browser ─────────────────────────────────────────
    if is_inapp(ua) then
        return {
            device_type                   = "inapp",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = true,
            device_ios_version            = parse_ios_version(ua),
        }
    end

    -- ── Chrome Custom Tab / WebView ───────────────────────────
    if is_custom_tab(ua) then
        return {
            device_type                   = "custom_tab",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = true,
            device_ios_version            = nil,
        }
    end

    -- ── iPad ──────────────────────────────────────────────────
    if ua:find("iPad", 1, true) then
        local ios_ver = parse_ios_version(ua)
        return {
            device_type                   = "tablet_ipad",
            device_sec_fetch_expected     = ios_ver and ios_ver >= SEC_FETCH_THRESHOLD_IOS or false,
            device_ch_ua_mobile_expected  = false,  -- iPad gửi ?0
            device_is_mobile              = true,
            device_ios_version            = ios_ver,
        }
    end

    -- ── iPhone / iPod ─────────────────────────────────────────
    if ua:find("iPhone", 1, true) or ua:find("iPod", 1, true) then
        local ios_ver = parse_ios_version(ua)
        local is_old  = ios_ver and ios_ver < SEC_FETCH_THRESHOLD_IOS
        return {
            device_type                   = is_old and "mobile_safari_ios_old"
                                                    or "mobile_safari_ios",
            device_sec_fetch_expected     = not is_old,
            device_ch_ua_mobile_expected  = false,  -- Safari không gửi CH-UA
            device_is_mobile              = true,
            device_ios_version            = ios_ver,
        }
    end

    -- ── Android tablet (không có "Mobile/") ───────────────────
    if is_android_tablet(ua) then
        return {
            device_type                   = "tablet_android",
            device_sec_fetch_expected     = ua:find("Chrome/", 1, true) ~= nil,
            device_ch_ua_mobile_expected  = false,  -- tablet gửi ?0
            device_is_mobile              = true,
            device_ios_version            = nil,
        }
    end

    -- ── Android phone ─────────────────────────────────────────
    if ua:find("Android", 1, true) and ua:find("Mobile", 1, true) then
        local is_chrome = ua:find("Chrome/", 1, true) ~= nil
        return {
            device_type                   = "mobile_chrome_android",
            device_sec_fetch_expected     = is_chrome,
            -- Chrome Android 89+ gửi Sec-CH-UA-Mobile: ?1
            device_ch_ua_mobile_expected  = is_chrome,
            device_is_mobile              = true,
            device_ios_version            = nil,
        }
    end

    -- ── Desktop: Firefox ──────────────────────────────────────
    if ua:find("Firefox/", 1, true) and not ua:find("Mobile", 1, true) then
        return {
            device_type                   = "desktop_firefox",
            device_sec_fetch_expected     = true,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

    -- ── Desktop: Safari (macOS) ───────────────────────────────
    if ua:find("Safari/", 1, true)
    and ua:find("Macintosh", 1, true)
    and not ua:find("Chrome/", 1, true) then
        return {
            device_type                   = "desktop_safari",
            -- Safari desktop có Sec-Fetch từ 16.1 (phổ biến rồi)
            device_sec_fetch_expected     = true,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

    -- ── Desktop: Chrome / Chromium ────────────────────────────
    if ua:find("Chrome/", 1, true)
    and not ua:find("Mobile", 1, true)
    and not ua:find("Android", 1, true) then
        return {
            device_type                   = "desktop_chrome",
            device_sec_fetch_expected     = true,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

    -- ── Desktop: other ────────────────────────────────────────
    local has_desktop_platform = ua:find("Windows", 1, true)
                               or ua:find("Macintosh", 1, true)
                               or ua:find("Linux", 1, true)
    if has_desktop_platform then
        return {
            device_type                   = "desktop_other",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

    return {
        device_type                   = "unknown",
        device_sec_fetch_expected     = false,
        device_ch_ua_mobile_expected  = false,
        device_is_mobile              = false,
        device_ios_version            = nil,
    }
end

function _M.run(ctx)
    local ua    = ctx.ua or ""
    local proto = ctx.req and ctx.req.proto or ngx.var.server_protocol or ""

    local info = _M.classify(ua, proto)

    ctx.device_type                  = info.device_type
    ctx.device_sec_fetch_expected    = info.device_sec_fetch_expected
    ctx.device_ch_ua_mobile_expected = info.device_ch_ua_mobile_expected
    ctx.device_is_mobile             = info.device_is_mobile
    ctx.device_ios_version           = info.device_ios_version

    ngx.log(ngx.DEBUG,
        "[device] type=", info.device_type,
        " sec_fetch_exp=", tostring(info.device_sec_fetch_expected),
        " ch_mobile_exp=", tostring(info.device_ch_ua_mobile_expected),
        " is_mobile=",     tostring(info.device_is_mobile),
        " ios_ver=",       tostring(info.device_ios_version))

    return true, false
end

return _M
