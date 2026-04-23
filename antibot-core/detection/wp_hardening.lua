local _M   = {}
local pool = require "antibot.core.redis_pool"

-- WP attack surface — POST tới wp-login.php và xmlrpc.php.
-- Thay vì rate limit hoặc challenge (lockout tools/CI/app), contribute
-- signals vào score. Bruteforce bằng HTTP client thô (requests/curl/Go)
-- thiếu nhiều marker protocol mà browser thật tự nhiên có.
--
-- wp-admin không được cover ở đây vì /wp-admin/admin-ajax.php là endpoint
-- public được plugin frontend dùng (contact form, comment, v.v.) — check
-- logged_in cookie sẽ false positive diện rộng.

local ZONE_LOGIN  = "login"
local ZONE_XMLRPC = "xmlrpc"

local function detect_zone(uri, method)
    if method ~= "POST" then return nil end
    if uri == "/wp-login.php" then return ZONE_LOGIN end
    if uri == "/xmlrpc.php"   then return ZONE_XMLRPC end
    return nil
end

-- POST /wp-login.php — real browser submit flow:
--   GET wp-login.php → server Set-Cookie: wordpress_test_cookie
--   → browser echo cookie back trong POST + gửi Referer cùng host + Sec-Fetch-Mode=navigate
-- Bruteforce tool POST thẳng → thiếu hầu hết marker này.
local function score_login(ctx)
    local score   = 0
    local reasons = {}

    -- 1. Missing wordpress_test_cookie (strong signal, near-zero FP)
    if not ngx.var.cookie_wordpress_test_cookie then
        score = score + 0.25
        reasons[#reasons+1] = "no_testcookie"
    end

    -- 2. Session pre-history: real user đã browse trước khi login
    local fp = ctx.fp_light
    if fp then
        local nav = tonumber(pool.safe_get("sess_nav:" .. fp)) or 0
        if nav < 2 then
            score = score + 0.20
            reasons[#reasons+1] = "no_prior_nav"
        end
    end

    -- 3. Referer: form submit có Referer cùng host
    local referer = ngx.var.http_referer or ""
    local host    = ngx.var.host or ""
    if referer == "" then
        score = score + 0.15
        reasons[#reasons+1] = "no_referer"
    elseif host ~= "" and not referer:find(host, 1, true) then
        score = score + 0.15
        reasons[#reasons+1] = "bad_referer"
    end

    -- 4. fp_quality thấp: bot không chạy JS beacon
    local fpq = ctx.fp_quality or 1.0
    if fpq < 0.3 then
        score = score + 0.15
        reasons[#reasons+1] = "low_fpq"
    end

    -- 5. Body nhỏ: real form có log, pwd, wp-submit, redirect_to, testcookie
    --    ~150-400 bytes. Bruteforce minimal (log+pwd) < 100 bytes.
    local cl = tonumber(ngx.var.http_content_length) or 0
    if cl > 0 and cl < 100 then
        score = score + 0.20
        reasons[#reasons+1] = "small_body"
    end

    -- 6. Sec-Fetch-Mode: browser submit form = "navigate".
    --    Tool HTTP client đời cũ không gửi, bot cao cấp có thể fake.
    local sfm = ngx.var.http_sec_fetch_mode or ""
    if sfm == "" then
        score = score + 0.10
        reasons[#reasons+1] = "no_sec_fetch"
    elseif sfm ~= "navigate" then
        score = score + 0.05
        reasons[#reasons+1] = "bad_sec_fetch"
    end

    return score, reasons
end

-- POST /xmlrpc.php — phân biệt legit Jetpack vs bruteforce multicall.
-- Legit single call: body < 1KB, single method.
-- Bruteforce system.multicall: body thường > 2KB (gói 50-500 login trong 1 request).
local function score_xmlrpc(ctx)
    local score   = 0
    local reasons = {}

    -- 1. Body lớn = near-certain multicall. Legit single call không đạt ngưỡng này.
    local cl = tonumber(ngx.var.http_content_length) or 0
    if cl > 2048 then
        score = score + 0.40
        reasons[#reasons+1] = "body_large"
    elseif cl > 1024 then
        score = score + 0.20
        reasons[#reasons+1] = "body_med"
    end

    -- 2. No cookie: bot ít khi giữ cookie.
    local cookies = ngx.var.http_cookie or ""
    if cookies == "" then
        score = score + 0.10
        reasons[#reasons+1] = "no_cookie"
    end

    -- 3. No session history: fresh IP+UA chưa từng request gì khác.
    --    Jetpack legit cũng không có session nav vì server-to-server → dùng
    --    chung với no_cookie không phải signal mạnh, để cân bằng false positive.
    local fp = ctx.fp_light
    if fp then
        local nav = tonumber(pool.safe_get("sess_nav:" .. fp)) or 0
        if nav == 0 then
            score = score + 0.15
            reasons[#reasons+1] = "no_session"
        end
    end

    -- 4. UA không phải WP/Jetpack — signal mạnh nhất cho xmlrpc.
    --    Legit Jetpack/WP luôn có token rõ trong UA. Python/Go/curl khác hoàn toàn.
    --    Không dùng fp_quality vì Jetpack server-to-server cũng có fp_q thấp.
    local ua = ctx.ua or ""
    local ua_lower = ua:lower()
    if not ua_lower:find("jetpack", 1, true) and
       not ua_lower:find("wordpress", 1, true) then
        score = score + 0.35
        reasons[#reasons+1] = "non_wp_ua"
    end

    return score, reasons
end

function _M.run(ctx)
    local uri    = ngx.var.uri or ""
    local method = ngx.var.request_method or "GET"

    local zone = detect_zone(uri, method)
    if not zone then return true, false end

    local score, reasons
    if zone == ZONE_LOGIN then
        score, reasons = score_login(ctx)
    else
        score, reasons = score_xmlrpc(ctx)
    end

    if score > 1.0 then score = 1.0 end

    ctx.wp_attack_score = score
    ctx.wp_zone         = zone
    ctx.wp_reasons      = reasons

    if score > 0.3 then
        ngx.log(ngx.INFO,
            "[wp_hardening] zone=", zone,
            " score=", string.format("%.2f", score),
            " reasons=", table.concat(reasons, ","),
            " ip=", ctx.ip or "?")
    end

    return true, false
end

return _M
