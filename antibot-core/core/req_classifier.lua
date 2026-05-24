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
    -- Auth/sensitive endpoints: wp-login, xmlrpc, admin-ajax, wp-json users.
    -- Bruteforce target → multiplier cao hơn navigation để bắt sớm.
    auth_endpoint = {
        score_multiplier = 1.5,
        rate_weight      = 1.5,
        skip_layers      = {},
        is_static        = false,
    },
    -- Feed / sitemap / robots: crawler legit (Googlebot, Bingbot, RSS readers)
    -- hit thường xuyên → multiplier thấp tránh FP. Vẫn chạy threat layer
    -- để chặn bot scraping content qua feed.
    feed_or_meta = {
        score_multiplier = 0.4,
        rate_weight      = 0.3,
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
    -- Path/method không match rule nào → không classify được.
    -- Nguyên tắc bayesian: uncertainty GIẢM penalty, không tăng.
    -- Bot thật hiếm khi tạo edge-case URL — chúng thường imitate
    -- navigation/interaction pattern → đã rơi vào class cụ thể.
    -- Path lạ thường là CMS admin panel (Joomla /administrator,
    -- Drupal /?q=admin, Magento /admin/dashboard, custom apps).
    -- Mult 0.5 vẫn cho phép signal khác (anomaly/h2_bot/cluster)
    -- escalate nếu thực sự bot.
    unknown = {
        score_multiplier = 0.5,
        rate_weight      = 0.5,
        skip_layers      = {},
        is_static        = false,
    },
}

local RESOURCE_EXT = {
    png=1, jpg=1, jpeg=1, gif=1, webp=1,
    ico=1, svg=1,
    woff=1, woff2=1, ttf=1, eot=1,
}

-- Auth endpoint detection — generic semantic vocabulary, KHÔNG framework
-- enumeration.
--
-- Nguyên lý (cùng nguyên lý session_richness):
--   Đo BẢN CHẤT (semantic), không đo BRAND (framework). Một auth endpoint
--   có gì chung bất kể CMS? — Path component (giữa các /) chứa keyword
--   thuộc semantic auth vocabulary. Endpoint nào dùng tên `/login`,
--   `/auth/*`, `/register` CỐ Ý signal "đây là auth-related" — semantic
--   intent rõ ràng, ngôn ngữ vocabulary stable theo thời gian.
--
-- Vd cùng được catch bởi single keyword "login":
--   /wp-login.php             (WP)
--   /user/login               (Drupal)
--   /customer/account/login   (Magento)
--   /api/v1/auth/login        (REST custom)
--   /login                    (any custom CMS)
--   /strapi/admin/auth/login  (CMS tương lai chưa có hiện tại)
--
-- Trade-off vs enumeration:
--   + Pro: zero maintenance khi CMS mới ra; cover custom apps; consistent
--          với principle "không hardcode brand list" áp dụng cho cookies,
--          inapp_browser, ASN, etc.
--   − Con: CMS đặt tên unconventional (Magento `loginpost` component)
--          có thể miss. Chấp nhận trade-off vì 95%+ frameworks dùng
--          semantic naming.
--
-- Chỉ match POST: GET tới /login là user mở trang đăng nhập (legitimate
-- navigation), không phải bruteforce attempt.

-- Semantic auth vocabulary — KHÔNG phải framework list.
-- Mỗi keyword là một concept auth chuẩn. Anyone naming an endpoint
-- với các từ này CỐ Ý chỉ ra intent "auth-related".
local AUTH_KEYWORDS = {
    "login", "signin", "signup", "register", "logon",
    "auth", "oauth", "oauth2", "sso",
    "password", "passwd",
    "token",
    "session", "sessions",
    "2fa", "mfa",
    "credentials",
}

-- Legacy exception list — paths bị abuse bruteforce nhưng KHÔNG chứa
-- semantic keyword nào trong URI VÀ body cũng không chứa marker chuẩn
-- (body semantic detection miss). Mỗi entry phải justify rõ ràng.
local AUTH_LEGACY_PATHS = {
    -- WordPress xmlrpc.php — XML-RPC dispatcher dùng XML body format.
    -- Bruteforce qua system.multicall với password được wrap trong
    -- <value><string>password</string></value> — KHÔNG có literal
    -- "password=" trong body → body detection miss. URI cũng không có
    -- semantic auth keyword → cần explicit exception.
    "^/xmlrpc%.php$",
    -- Lưu ý: /wp-admin/admin-ajax.php KHÔNG có ở đây nữa.
    -- Body detection (commit này) catch nó qua body có pwd= hoặc password=
    -- khi bruteforce action=login. Nếu admin-ajax không có credential
    -- field trong body, không phải auth attempt → không cần amplify.
}

-- Body markers — semantic invariants của credential transmission.
-- Match bằng substring (literal find, không regex) → fast + ZERO false
-- positive vì các marker này là chuỗi rất cụ thể.
--
-- KHÔNG bao gồm CAPTCHA-only fields (g-recaptcha-response, h-captcha...)
-- vì CAPTCHA xuất hiện trong contact form, comment form, register form,
-- không chỉ login → quá broad, FP risk cho non-auth form spam protection
-- (mà spam protection thuộc concern khác).
local AUTH_BODY_MARKERS = {
    -- Password field (smoking gun, primary signal)
    -- Form-urlencoded
    "password=", "passwd=", "pwd=", "passphrase=",
    -- JSON (quoted key)
    '"password"', '"passwd"', '"pwd"', '"passphrase"',
    -- Multipart form-data
    'name="password"', 'name="pwd"', 'name="passwd"',
    -- OAuth client credentials
    "client_secret=", '"client_secret"',
    -- OAuth Resource Owner Password Credentials grant
    "grant_type=password",
    '"grant_type":"password"',
    -- OTP/2FA fields (bruteforce target trong stage 2 attack)
    "otp=", "totp=",
    "mfa_code=", "mfa_token=",
    "verification_code=",
    '"otp"', '"totp"', '"mfa_code"', '"verification_code"',
}

-- Word-boundary match: keyword phải LÀ component hoặc bounded bởi
-- separator path-safe (- _ .). Tránh FP như "author" matching "auth"
-- (không separator giữa "auth" và "or" → không match).
local function path_component_matches_kw(component, kw)
    return component == kw                          -- /login
        or component:find("^" .. kw .. "[-_.]")     -- /login-form, /login.do
        or component:find("[-_.]" .. kw .. "$")     -- /wp-login, /user_login
        or component:find("[-_.]" .. kw .. "[-_.]") -- /wp-login.php
end

local function has_auth_keyword_in_path(lower_uri)
    for component in lower_uri:gmatch("[^/]+") do
        for i = 1, #AUTH_KEYWORDS do
            if path_component_matches_kw(component, AUTH_KEYWORDS[i]) then
                return true
            end
        end
    end
    return false
end

local function matches_legacy_path(lower_uri)
    for i = 1, #AUTH_LEGACY_PATHS do
        if lower_uri:find(AUTH_LEGACY_PATHS[i]) then return true end
    end
    return false
end

-- Query string keyword detection — Joomla/OpenCart routing patterns
-- (?option=com_users&task=user.login, ?route=account/login). Boundary
-- thêm "/" vì query value có thể chứa nested path.
local function has_auth_keyword_in_args(lower_args)
    for param in lower_args:gmatch("[^&]+") do
        local _, val = param:match("([^=]+)=(.+)")
        if val then
            for i = 1, #AUTH_KEYWORDS do
                local kw = AUTH_KEYWORDS[i]
                if val == kw
                    or val:find("^" .. kw .. "[-_./]")
                    or val:find("[-_./]" .. kw .. "$")
                    or val:find("[-_./]" .. kw .. "[-_./]") then
                    return true
                end
            end
        end
    end
    return false
end

-- Body inspection (slow path) — chỉ chạy khi keyword/legacy/qs đều miss.
-- Cap body size 8KB: auth body luôn nhỏ (<1KB typical). Body lớn hơn
-- là file upload / GraphQL query / etc — không phải auth.
--
-- Performance note: ngx.req.read_body() đọc body từ connection vào memory
-- (cap by client_body_buffer_size, default 16KB). Cost ~10-50µs per POST.
-- Chỉ POST mới đến nhánh này, GET zero overhead.
local function body_contains_auth_marker()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body or body == "" or #body > 8192 then return false end

    local lower = body:lower()
    for i = 1, #AUTH_BODY_MARKERS do
        if lower:find(AUTH_BODY_MARKERS[i], 1, true) then return true end
    end
    return false
end

-- v3-hybrid: keyword fast path + body semantic fallback.
-- Fast path catches 95% standard CMS frameworks (zero body read).
-- Body fallback catches obfuscated paths (/portal/enter, /api/v9/handshake,
-- Magento `loginpost` không có separator) khi body chứa credential field.
-- Hai layer độc lập → defense-in-depth, attacker phải bypass cả hai.
local function is_auth_endpoint(method, uri, args)
    if method ~= "POST" then return false end

    local lower_uri = uri:lower()

    -- FAST PATH 1: URI path semantic keyword
    if has_auth_keyword_in_path(lower_uri) then return true end

    -- FAST PATH 2: Legacy non-semantic paths (xmlrpc.php only)
    if matches_legacy_path(lower_uri) then return true end

    -- FAST PATH 3: Query string semantic (Joomla, OpenCart, custom routing)
    if args and args ~= "" then
        if has_auth_keyword_in_args(args:lower()) then return true end
    end

    -- SLOW PATH: body semantic — credential field literal in POST body.
    -- Catches paths không có semantic keyword nhưng transmit credentials.
    return body_contains_auth_marker()
end

-- In-app browser detection — generic structural signals, KHÔNG app brand
-- enumeration.
--
-- Nguyên lý (cùng pattern session_richness, auth_endpoint v3):
--   Đo BẢN CHẤT của WebView request thay vì list app brands. WebView có
--   structural signatures khác standalone browser:
--     - Android: X-Requested-With = app bundle ID (com.X.Y reverse-domain)
--     - UA tail: append brand token sau Safari version (non-canonical)
--     - Missing client hints despite Chrome UA (WebView không expose)
--
-- Output: ctx.inapp_likeness ∈ [0,1] — continuous modifier (cùng pattern
-- session_richness). Threshold 0.4 swap class → inapp_browser (apply
-- existing skip_layers + mult 0.4 config). Class+modifiers hybrid.
--
-- Generic catches MỌI app hiện tại và tương lai:
--   Android: Facebook (com.facebook.katana), Zalo (com.zing.zalo),
--            Instagram, TikTok, WeChat, Alipay, DingTalk, Douyin, ...
--   iOS:     Facebook, Instagram, Zalo, Line, ... (UA tail token)
--   Tương lai: Threads, BeReal, Lemon8 — auto-covered, zero code change.

-- OS-level engine markers — safety net cho platforms KHÔNG có
-- Android/iOS WebView signals (Signal 1+2 miss).
--
-- Quy tắc IN LIST: chỉ OS-level identifier hoặc WebView engine, KHÔNG
-- app brand. App brand caught bởi Signal 1+2. Standalone browser brand
-- caught bởi Signal 2 (non-canonical Safari ending).
--
-- Event launch: 1-2 lần / decade. Maintain simple — add 1 string với
-- inline comment khi OS mới launch.
local OS_ENGINE_MARKERS = {
    "OpenHarmony",   -- HarmonyOS NEXT pure runtime (2024+, post-Android)
    "HarmonyOS",     -- HarmonyOS legacy (≤4.x, Android-compatible)
    "HMSCore",       -- Huawei Mobile Services (any Huawei device)
    "ArkWeb",        -- HarmonyOS NEXT WebView engine
    "TBS/",          -- Tencent X5 WebView (WeChat/QQ embedded browser)
    "KAIOS",         -- KaiOS feature phones (India/Africa market)
}

local INAPP_CLASS_THRESHOLD = 0.4   -- threshold swap class

local function compute_inapp_likeness(ua, xrw, sec_ch_ua)
    if not ua or ua == "" then return 0.0 end

    -- RFC 9309 bot self-identification: "(compatible; BotName/X.Y; +http://...)"
    -- Real WebView apps NEVER use this format. Googlebot/Bingbot/any compliant
    -- crawler declares itself this way — zero false positives for app traffic.
    -- Structural pattern, not brand list: no specific bot names hardcoded.
    if ua:find("%(compatible;", 1, true) then return 0.0 end

    -- Prerequisite: mobile context (extended cho non-Android/iOS OS)
    local is_mobile = ua:find("Mobile/", 1, true)
                   or ua:find("Android", 1, true)
                   or ua:find("OpenHarmony", 1, true)
                   or ua:find("HarmonyOS", 1, true)
                   or ua:find("KAIOS", 1, true)
    if not is_mobile then return 0.0 end

    local score = 0.0

    -- SIGNAL 1 (strong, 0.6): Android WebView X-Requested-With reverse-domain.
    -- Pattern com.X.Y / vn.X.Y / io.X.Y / app.X.Y (any TLD-style prefix).
    -- Android tự động set header này = app bundle ID. Standalone browser
    -- không có. Strongest signal vì khó fake mà không break UX.
    if xrw and xrw ~= "" and
       xrw:find("^%l[%l%d]*%.[%l%d][%w%-%.]+") then
        score = score + 0.6
    end

    -- SIGNAL 2 (medium, 0.3): UA không kết thúc canonical Safari/X.Y.
    -- Standard browser: "... Safari/537.36" hoặc "... Safari/604.1"
    -- WebView/non-standard: append tokens SAU Safari version, hoặc bỏ
    -- Safari hẳn (iOS WKWebView Facebook: "... Mobile/15E148 [FBAN/...]")
    if not ua:match("Safari/[%d%.]+%s*$") then
        score = score + 0.3
    end

    -- SIGNAL 3 (weak, 0.15): Chrome 90+ UA thiếu Sec-Ch-Ua client hints.
    -- Standalone Chrome 90+ luôn gửi. WebView thường thiếu (not exposed
    -- through WebView API).
    local chrome_ver = ua:match("Chrome/(%d+)")
    if chrome_ver and tonumber(chrome_ver) >= 90
       and (not sec_ch_ua or sec_ch_ua == "") then
        score = score + 0.15
    end

    -- SIGNAL 4 (safety net, 0.3): OS-level engine marker (HarmonyOS NEXT,
    -- Tencent X5, KaiOS — edge case khi UA canonical ending + xrw không set).
    for i = 1, #OS_ENGINE_MARKERS do
        if ua:find(OS_ENGINE_MARKERS[i], 1, true) then
            score = score + 0.3
            break   -- no double-count nếu UA chứa multiple markers
        end
    end

    if score > 1.0 then score = 1.0 end
    return score
end

-- Detect inapp + return (is_inapp, likeness) cho caller mutate ctx.
local function detect_inapp(ua)
    local xrw       = ngx.var.http_x_requested_with or ""
    local sec_ch_ua = ngx.var.http_sec_ch_ua or ""
    local likeness  = compute_inapp_likeness(ua, xrw, sec_ch_ua)
    return likeness >= INAPP_CLASS_THRESHOLD, likeness
end

local function classify(ctx)
    local uri    = ngx.var.uri                or ""
    local args   = ngx.var.args               or ""
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

    -- Feed / sitemap / robots — crawler-friendly endpoints, hit nhiều bởi
    -- Googlebot/Bingbot/RSS readers. Đặt SỚM (trước branch resource ext
    -- không match cho /feed/) để tránh rơi vào navigation mult 1.0 và bị
    -- FP với crawler legit.
    if uri == "/robots.txt" or
       uri:find("^/feed/?$") or
       uri:find("^/feed/") or
       uri:find("^/sitemap[^/]*%.xml$") or
       uri:find("^/sitemap%-") then
        return "feed_or_meta"
    end

    -- Resource: browser-declared sub-resource fetch
    if sec_fetch_dest == "image"  or
       sec_fetch_dest == "script" or
       sec_fetch_dest == "style"  or
       sec_fetch_dest == "font"   then
        return "resource"
    end

    -- Auth endpoint — PHẢI check TRƯỚC interaction JSON.
    -- POST tới /wp-json/wp/v2/users với Content-Type: application/json
    -- (REST API modern) sẽ match interaction nếu để sau → bypass auth
    -- amplified mult 1.5. Đặt sớm để mọi auth POST đi đúng class
    -- bất kể content-type. Generic patterns cover WP/Joomla/Drupal/
    -- Magento/OAuth/2FA — xem AUTH_PATH_PATTERNS ở đầu file.
    if is_auth_endpoint(method, uri, args) then
        return "auth_endpoint"
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

    -- In-app browser: structural WebView signals (X-Requested-With bundle ID,
    -- non-canonical Safari tail, missing client hints). Đặt TRƯỚC text/html
    -- check vì in-app WebView cũng gửi Accept: text/html — nếu để sau,
    -- branch này là dead code và mọi in-app rơi vào "navigation" mult 1.0.
    local is_inapp, inapp_likeness = detect_inapp(ua)
    ctx.inapp_likeness = inapp_likeness
    if is_inapp then
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
        " inapp=", string.format("%.2f", ctx.inapp_likeness or 0),
        " uri=", ngx.var.uri or "?")

    return true, false
end

return _M
