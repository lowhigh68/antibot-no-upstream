local _M   = {}
local pool = require "antibot.core.redis_pool"

-- WP attack surface — POST tới wp-login.php, xmlrpc.php, wp-comments-post.php.
-- Thay vì rate limit hoặc challenge (lockout tools/CI/app), contribute
-- signals vào score. Bruteforce bằng HTTP client thô (requests/curl/Go)
-- thiếu nhiều marker protocol mà browser thật tự nhiên có.
--
-- Fast-path hard exits (trước scoring) cho 2 case near-zero FP:
--   xmlrpc  — non-WP/Jetpack UA: Jetpack/WP Core/CLI luôn self-identify.
--   wp-login — missing testcookie 2 lần / 30s: tool post thẳng không GET-first,
--              VÀ `session_richness < 0.5`. Cửa thoát richness thêm 18-09-2026:
--              bộ đếm khoá theo `ip` nên nó GỘP MỌI NGƯỜI trên cùng địa chỉ —
--              khi botnet đang nện wp-login, bộ đếm của IP đó đã vượt 2 từ lâu
--              và một quản trị viên thật đi ra từ cùng IP ăn chặn ngay lần POST
--              đầu. Đo được 240/139/113/103 lượt chặn client MANG cookie do
--              chính host cấp trên comchaydacsan/achauled/chungkhoanplus/
--              alumicastore. Ngưỡng 0.5 đồng bộ `SHARED_ID_RICHNESS` ở
--              `l7/ban/ban_store.lua` — cùng một lớp vấn đề, cùng một cửa thoát.
--
-- wp-admin không được cover ở đây vì /wp-admin/admin-ajax.php là endpoint
-- public được plugin frontend dùng (contact form, comment, v.v.) — check
-- logged_in cookie sẽ false positive diện rộng.

local ZONE_LOGIN   = "login"
local ZONE_XMLRPC  = "xmlrpc"
local ZONE_COMMENT = "comment"

-- Leo thang CHỈ CHO ZONE XMLRPC. Cố tình KHÔNG dùng chung với zone login:
-- ngưỡng dưới đây suy ra từ tốc độ tấn công xmlrpc đo được, và `wp-login.php`
-- có bề mặt FP rộng hơn hẳn (người dùng thật xoá cookie, trình duyệt chặn
-- cookie bên thứ ba). Muốn áp cho login thì phải đo riêng trước.
--
-- Vấn đề đã đo (2026-08-01 và 08-02, hai ngày liên tiếp, mỗi ngày IP khác):
-- một nguồn bắn 800-2400 POST /xmlrpc.php. Mọi lượt ĐỀU bị chặn 444 — code
-- không hề bỏ sót — nhưng nó không có TRÍ NHỚ, nên kẻ tấn công lặp vô hạn và
-- mỗi lượt vẫn ngốn ~15 module trước khi bị chặn (23.007 lượt/ngày).
--
-- Vì sao ba cơ chế sẵn có đều không khép được vòng:
--   * `ngx.exit(444)` ở tầng detection ⇒ `enforcement/ban/ban_store_write`
--     KHÔNG BAO GIỜ chạy ⇒ không ghi ban, không tăng `viol:`.
--   * `risk_update` (log phase) có thể nâng `ip_risk:<ip>`, nhưng nơi ĐỌC nó là
--     `engine.lua` — cũng không chạy vì đã exit. Attacker chỉ đánh xmlrpc nên
--     mọi request đều thoát sớm, vòng phản hồi không bao giờ khép.
--   * Rate limit không chạm: đo được 7,2 lượt/phút mỗi IP — cố tình chậm.
--
-- Ngưỡng chọn theo tốc độ THẬT đó: cửa sổ 300s chỉ tích được ~36 lượt nên
-- không đủ tin cậy; cửa sổ 1 giờ + 20 strike ⇒ khoá sau chưa tới 3 phút.
-- Sau khi ban, request kế tiếp thoát ở `l7/ban/ip_ban_check` (module thứ 6)
-- thay vì đi hết pipeline.
--
-- MỞ RỘNG PHẠM VI CHẶN, phải ý thức: 444 chỉ chặn riêng endpoint, còn ban khoá
-- IP trên MỌI domain. Chấp nhận được vì luật xmlrpc đã là "near-zero FP" (client
-- hợp lệ luôn có `wordpress`/`jetpack` trong UA nên không bao giờ vào tới đây),
-- và còn phải lặp 20 lần. Giữ miễn trừ IP dùng chung đã chứng minh (Tier-2).
local HARD_EXIT_WINDOW  = 3600
local HARD_EXIT_STRIKES = 20
local HARD_EXIT_BAN_TTL = 86400

local function escalate_xmlrpc(ctx)
    local ip = ctx.ip or ""
    if ip == "" or ip == "127.0.0.1" or ip == "::1" then return end
    -- Tier-2: IP dùng chung đã chứng minh có nhiều user cookie thật
    -- (CGNAT/văn phòng) — một thiết bị hỏng không được khoá cả nhà.
    if ctx.ip_shared_verified then return end
    -- Dia chi edge cua reverse proxy: cung ly le, va dai do con dong nguoi that
    -- hon CGNAT. Xem `enforcement/ban/ban_store_write.lua` (72 khoa edge CF do
    -- 19-09). Identity van bi chan binh thuong.
    if ctx.behind_proxy then return end

    local n = pool.safe_incr("hardexit:xmlrpc:" .. ip, HARD_EXIT_WINDOW) or 0
    if n < HARD_EXIT_STRIKES then return end

    pool.safe_set("ban:" .. ip, "1", HARD_EXIT_BAN_TTL)
    pool.safe_set("ban:hit:" .. ip, tostring(ngx.time()), 300)
    -- ngx.ERR: access phase, per-domain error_log ép mức `error` nên WARN bị lọc.
    ngx.log(ngx.ERR, "[wp_hardening] BAN ip=", ip,
            " reason=xmlrpc strikes=", n,
            " ttl=", HARD_EXIT_BAN_TTL,
            " ua=", (ctx.ua or "-"):sub(1, 40))
end

local function detect_zone(uri, method)
    if method ~= "POST" then return nil end
    if uri == "/wp-login.php"         then return ZONE_LOGIN   end
    if uri == "/xmlrpc.php"           then return ZONE_XMLRPC  end
    if uri == "/wp-comments-post.php" then return ZONE_COMMENT end
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

-- POST /wp-comments-post.php — phân biệt legit comment submission vs spam bot.
-- Real browser flow: GET post page → receive testcookie → submit form với
-- Referer = post URL, Sec-Fetch-Mode = navigate, body có đủ fields.
-- Spam bot POST thẳng → thiếu hầu hết marker này.
local function score_comment(ctx)
    local score   = 0
    local reasons = {}

    -- 1. Missing wordpress_test_cookie (near-zero FP)
    --    Browser thật đã GET post page trước → nhận cookie → POST comment.
    if not ngx.var.cookie_wordpress_test_cookie then
        score = score + 0.25
        reasons[#reasons+1] = "no_testcookie"
    end

    -- 2. No prior navigation: user phải đọc bài viết trước khi comment.
    local fp = ctx.fp_light
    if fp then
        local nav = tonumber(pool.safe_get("sess_nav:" .. fp)) or 0
        if nav < 2 then
            score = score + 0.15
            reasons[#reasons+1] = "no_prior_nav"
        end
    end

    -- 3. Referer: form submit có Referer là URL bài viết (cùng host).
    local referer = ngx.var.http_referer or ""
    local host    = ngx.var.host or ""
    if referer == "" then
        score = score + 0.15
        reasons[#reasons+1] = "no_referer"
    elseif host ~= "" and not referer:find(host, 1, true) then
        score = score + 0.15
        reasons[#reasons+1] = "bad_referer"
    end

    -- 4. Sec-Fetch-Mode: browser form submit = "navigate".
    local sfm = ngx.var.http_sec_fetch_mode or ""
    if sfm == "" then
        score = score + 0.15
        reasons[#reasons+1] = "no_sec_fetch"
    elseif sfm ~= "navigate" then
        score = score + 0.10
        reasons[#reasons+1] = "bad_sec_fetch"
    end

    -- 5. fp_quality thấp: bot không chạy JS beacon.
    local fpq = ctx.fp_quality or 1.0
    if fpq < 0.3 then
        score = score + 0.10
        reasons[#reasons+1] = "low_fpq"
    end

    -- 6. Body rất nhỏ: real comment form có comment text + author + email +
    --    comment_post_ID + _wpnonce ≥ ~80 bytes. Spam bot gửi minimal fields.
    local cl = tonumber(ngx.var.http_content_length) or 0
    if cl > 0 and cl < 80 then
        score = score + 0.30
        reasons[#reasons+1] = "small_body"
    end

    return score, reasons
end

function _M.run(ctx)
    local uri    = ngx.var.uri or ""
    local method = ngx.var.request_method or "GET"

    local zone = detect_zone(uri, method)
    if not zone then return true, false end

    -- Fast-path hard exits — fire trước scoring, không cần history.

    -- xmlrpc: legitimate callers (Jetpack, WP Core, WP-CLI) LUÔN include
    -- "wordpress" hoặc "jetpack" trong UA. UA khác = near-certain attack.
    if zone == ZONE_XMLRPC then
        local ua_lower = (ctx.ua or ""):lower()
        if not ua_lower:find("jetpack", 1, true) and
           not ua_lower:find("wordpress", 1, true) then
            ctx.action        = "block"
            ctx.action_reason = "xmlrpc_ua_reject"
            escalate_xmlrpc(ctx)
            ngx.exit(444)
        end
    end

    -- wp-login: missing testcookie = tool posting thẳng không qua GET-first flow.
    -- 1 miss tolerated (browser privacy-clear / race condition).
    -- 2 misses trong 30s → attack confirmed.
    if zone == ZONE_LOGIN then
        if not ngx.var.cookie_wordpress_test_cookie then
            -- CUA THOAT: phien da co trang thai that voi CHINH site nay.
            --
            -- Bo dem duoi day khoa theo `ip`, tuc GOP MOI NGUOI tren cung mot
            -- dia chi. Khi mot botnet dang nen `wp-login.php`, bo dem cua IP do
            -- da vuot 2 tu lau; mot quan tri vien THAT di ra tu cung IP (hoac
            -- tu mot IP ma botnet cung dung) an 444 ngay o lan POST dau tien.
            --
            -- Do 18-09-2026, so luot bi chan ma client MANG COOKIE do chinh
            -- host cap (`rown > 0`): comchaydacsan.com 240, achauled.com 139,
            -- chungkhoanplus.com 113, alumicastore.com 103.
            --
            -- Nguong 0.5 dong bo voi `SHARED_ID_RICHNESS` o
            -- `l7/ban/ban_store.lua:102` — cung mot lop van de (bo dem/hash gop
            -- nhieu nguoi lam mot), nen cung mot cua thoat. Dung `richness`
            -- (max qua cua so) chu KHONG phai `rown`: o day ta dang MO cua chu
            -- khong phai CAP dac quyen, va admin chuyen domain thi `rown` tut
            -- xuong trong khi ho van la chinh ho.
            --
            -- KHONG noi long cho ke tan cong: toan bo dan IP do duoc 18-09 deu
            -- co richness = 0 (POST thang, khong cookie). Ke muon qua cua nay
            -- phai GET truoc de nhan cookie that cua site — ma lam vay thi no
            -- co luon `wordpress_test_cookie` va khong con di vao nhanh nay.
            local richness = ctx.session_richness or 0
            if richness < 0.5 then
                local cnt = pool.safe_incr("wp_login_notc:" .. (ctx.ip or ""), 30)
                if (cnt or 0) >= 2 then
                    ctx.action        = "block"
                    ctx.action_reason = "wp_login_notc_repeat"
                    -- 403 CO THAN, khong phai 444.
                    --
                    -- 444 dong ket noi ma khong tra gi, nen trinh duyet hien
                    -- LOI MANG — nguoi dung thay "site chet" chu khong thay mot
                    -- trang tu choi. Voi botnet thi hai ma nhu nhau (chung
                    -- khong doc than tra ve); voi nguoi that thi khac han, va
                    -- no cung lam cho ca ho lan nguoi van hanh chan doan duoc.
                    ngx.status = 403
                    ngx.header["Content-Type"] = "text/plain"
                    ngx.say("Access denied.")
                    ngx.exit(403)
                end
            end
        end
    end

    local score, reasons
    if zone == ZONE_LOGIN then
        score, reasons = score_login(ctx)
    elseif zone == ZONE_XMLRPC then
        score, reasons = score_xmlrpc(ctx)
    else
        score, reasons = score_comment(ctx)
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
