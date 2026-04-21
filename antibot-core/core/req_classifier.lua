local _M = {}

_M.CLASS_CONFIG = {
    resource = {
        score_multiplier = 0.2,
        rate_weight      = 0.1,
        skip_layers      = { graph=true, cluster=true, anomaly=true,
                             behavior=true, session=true, browser=true },
        is_static        = true,
    },
    navigation = {
        score_multiplier = 1.0,
        rate_weight      = 1.0,
        skip_layers      = {},
        is_static        = false,
    },
    interaction = {
        score_multiplier = 0.6,
        rate_weight      = 0.3,
        skip_layers      = { graph=true, cluster=true, browser=true },
        is_static        = false,
    },
    -- Server-to-server POST callbacks: payment gateways, webhooks, IPN.
    api_callback = {
        score_multiplier = 0.5,
        rate_weight      = 0.5,
        skip_layers      = { graph=true, cluster=true, browser=true,
                             anomaly=true, behavior=true, session=true },
        is_static        = false,
    },
    -- In-app browser: Zalo, Facebook, Instagram, Line, TikTok, v.v.
    -- Người dùng thật mở link được share qua app chat.
    -- Đặc điểm: thiếu Sec-Fetch-* headers (WebView không gửi),
    -- JA3 khác Chrome/Safari → score cao sai → cần giảm multiplier.
    -- Vẫn chạy threat intelligence (ip_rep, asn_rep) để block bot
    -- giả UA in-app. Skip browser/anomaly vì WebView không có
    -- navigator.plugins, canvas khác, v.v. — những signal này
    -- không có ý nghĩa với in-app browser.
    inapp_browser = {
        score_multiplier = 0.4,
        rate_weight      = 0.3,
        skip_layers      = { graph=true, cluster=true, browser=true,
                             anomaly=true, behavior=true },
        is_static        = false,
    },
    unknown = {
        score_multiplier = 1.0,
        rate_weight      = 1.0,
        skip_layers      = {},
        is_static        = false,
    },
}

local RESOURCE_EXT = {
    png=1, jpg=1, jpeg=1, gif=1, webp=1,
    ico=1, svg=1,
    woff=1, woff2=1, ttf=1, eot=1,
}

-- Nhận dạng in-app browser bằng pattern chung trong UA.
-- Nguyên tắc: KHÔNG hardcode từng app — dùng đặc điểm cấu trúc UA:
--   1. Phải có dấu hiệu mobile thật (Mobile/ hoặc Android)
--      → loại bot dùng desktop UA hoặc UA rỗng
--   2. Có app token đặc trưng của in-app WebView
--      → phân biệt với Safari/Chrome thật trên mobile
--
-- App tokens: các app chat/social phổ biến đều nhúng tên vào UA
-- khi mở WebView. Pattern này ổn định qua các version vì là
-- identifier của app, không phải version string.
local INAPP_UA_TOKENS = {
    -- Vietnamese apps
    "Zalo",           -- Zalo iOS/Android
    -- Meta platforms
    "FBAN",           -- Facebook App
    "FBAV",           -- Facebook App variant
    "FBIOS",          -- Facebook iOS
    "Instagram",      -- Instagram
    -- International chat/social
    "Line/",          -- Line messenger
    "Twitter",        -- Twitter/X
    "TikTok",         -- TikTok
    "Snapchat",       -- Snapchat
    "Pinterest",      -- Pinterest
    "LinkedIn",       -- LinkedIn
    "MicroMessenger", -- WeChat
    "Viber",          -- Viber
    -- Telegram WebView gửi UA bình thường, không cần token riêng
    -- Shopee, Lazada, Tiki in-app browser
    "Shopee",
    "Lazada",
    "TikiApp",
}

local function is_inapp_browser(ua)
    if not ua or ua == "" then return false end

    -- Điều kiện 1: phải có dấu hiệu mobile thật
    -- Bot thường không có "Mobile/" hoặc dùng UA không có Android/iOS context
    local is_mobile = ua:find("Mobile/", 1, true) or
                      ua:find("Android", 1, true)
    if not is_mobile then return false end

    -- Điều kiện 2: UA phải chứa app token
    for _, token in ipairs(INAPP_UA_TOKENS) do
        if ua:find(token, 1, true) then
            return true
        end
    end

    return false
end

local function classify(ctx)
    local uri    = ngx.var.uri                or ""
    local method = ngx.var.request_method     or "GET"
    local accept = ngx.var.http_accept        or ""
    local ct     = ngx.var.http_content_type  or ""
    local xrw    = ngx.var.http_x_requested_with or ""
    local sec_fetch_dest = ngx.var.http_sec_fetch_dest or ""
    local sec_fetch_mode = ngx.var.http_sec_fetch_mode or ""
    local sec_fetch_site = ngx.var.http_sec_fetch_site or ""
    local ua     = ngx.var.http_user_agent    or ""

    -- Resource: static files by extension
    local ext = uri:match("%.([%a%d]+)$")
    if ext and RESOURCE_EXT[ext:lower()] then
        return "resource"
    end

    -- Resource: browser-declared sub-resource fetch
    if sec_fetch_dest == "image"  or
       sec_fetch_dest == "script" or
       sec_fetch_dest == "style"  or
       sec_fetch_dest == "font"   then
        return "resource"
    end

    -- Interaction: explicit API/data requests
    if ct:find("application/json", 1, true) or
       accept:find("application/json", 1, true) then
        return "interaction"
    end

    if xrw == "XMLHttpRequest" then
        return "interaction"
    end

    if sec_fetch_mode == "cors" or sec_fetch_mode == "no-cors" then
        return "interaction"
    end

    if sec_fetch_dest == "empty" then
        return "interaction"
    end

    -- Navigation: browser form POST with Sec-Fetch context
    if method == "POST" and
       (ct:find("application/x-www-form-urlencoded", 1, true) or
        ct:find("multipart/form-data", 1, true)) and
       (sec_fetch_mode ~= "" or sec_fetch_site ~= "") then
        return "navigation"
    end

    -- api_callback: server-to-server POST without browser Sec-Fetch context.
    if method == "POST" and
       (ct:find("application/x-www-form-urlencoded", 1, true) or
        ct:find("multipart/form-data", 1, true) or
        ct == "") and
       sec_fetch_mode == "" and sec_fetch_site == "" then
        return "api_callback"
    end

    -- Interaction: non-form POST without JSON
    if method == "POST" and
       not ct:find("application/x-www-form-urlencoded", 1, true) and
       not ct:find("multipart/form-data", 1, true) then
        return "interaction"
    end

    -- In-app browser: có app token (FBAN, Zalo, Instagram, …) + mobile context.
    -- Đặt TRƯỚC text/html check vì in-app WebView cũng gửi Accept: text/html —
    -- nếu để sau, branch này là dead code và mọi in-app rơi vào "navigation"
    -- với multiplier 1.0 → bị challenge oan.
    -- Real browser không có app token nên vẫn fallback xuống navigation.
    if is_inapp_browser(ua) then
        return "inapp_browser"
    end

    -- Navigation: explicit browser navigation
    if accept:find("text/html", 1, true) then
        return "navigation"
    end

    if sec_fetch_mode == "navigate" then
        return "navigation"
    end

    return "unknown"
end

function _M.run(ctx)
    local class  = classify(ctx)
    local config = _M.CLASS_CONFIG[class]

    ctx.req_class        = class
    ctx.score_multiplier = config.score_multiplier
    ctx.rate_weight      = config.rate_weight
    ctx.skip_layers      = config.skip_layers
    ctx.is_static        = config.is_static

    ngx.log(ngx.DEBUG,
        "[classifier] class=", class,
        " mult=", config.score_multiplier,
        " rate_w=", config.rate_weight,
        " uri=", ngx.var.uri or "?")

    return true, false
end

return _M
