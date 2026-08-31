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

-- Self-declared crawler — bot/spider/crawler token or RFC contact URL.
-- Structural (no brand list). Uses bot-SUFFIX patterns (bot/ ; ) space) so
-- device brands like "CUBOT" (cubot_x) are not mislabelled as crawlers.
local function is_crawler(ua)
    local ul = ua:lower()
    return ul:find("spider", 1, true) ~= nil
        or ul:find("crawler", 1, true) ~= nil
        or ul:find("bot/", 1, true) ~= nil
        or ul:find("bot;", 1, true) ~= nil
        or ul:find("bot)", 1, true) ~= nil
        or ul:find("bot ", 1, true) ~= nil
        -- URL liên hệ kiểu RFC. Mẫu cũ `%(%+https?://` đòi dấu `+` phải NGAY
        -- SAU dấu mở ngoặc — chỉ đúng với dạng `meta-externalagent/1.1
        -- (+https://…)` mà nó được viết ra để bắt. Dạng phổ biến hơn nhiều là
        -- `(compatible; Tên/1.0; +http://…)`, ở đó `+http` đứng sau `; `.
        -- Hai ca bắt được từ bảng UA Samples ngày 2026-08-17, cả hai đều
        -- KHÔNG có token bot/spider/crawler nào để các nhánh trên tóm:
        --   Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)
        --   Mozilla/5.0 (compatible; coccocbot-image/1.0; +http://help.coccoc.com/…)
        -- ("bots)" ≠ "bot)", và "coccocbot-image/" ≠ "bot/".)
        --
        -- 2026-08-20 — ĐÃ NỚI TIẾP, và lý do đáng ghi lại: hôm 17/8 tôi viết
        -- "KHÔNG nới thành `%+https?://` trần vì như vậy là bỏ hẳn ngữ cảnh",
        -- chọn `[%(;]%s*%+https?://`. Số liệu bác bỏ ngay chính ràng buộc đó —
        -- đọc 282.619 dòng antibot.log, ô `unknown` chứa:
        --   104x  Mozilla/5.0 (compatible; heritrix/3.14.2-…T06:21:22Z +https://www.image-meta.com)
        --   124x  Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; Claude-User/1.0; +mailto:support@anthropic.com
        -- heritrix trượt vì `+https` đứng sau **`Z `** chứ không sau `(`/`;`;
        -- Claude-User trượt vì URL liên hệ là **`mailto:`**, không phải http.
        --
        -- Bản thân dấu `+` ĐÃ LÀ ngữ cảnh: nó là quy ước khai báo liên hệ của
        -- bot, không trình duyệt nào sinh ra `+http://` hay `+mailto:`. Ràng
        -- buộc thêm về ký tự đứng trước chỉ tạo ra chỗ lọt, không thêm an toàn.
        --
        -- Vẫn KHÔNG thêm "bot-" vào danh sách token phía trên: hãng điện thoại
        -- CUBOT có model đặt tên `CUBOT-…`, sẽ thành crawler oan — mà nhãn này
        -- đã ảnh hưởng tới ý định (crawler ⇒ không bao giờ là `human`) nên FP ở
        -- đó không còn vô hại. Rủi ro của `+scheme:` thì khác hẳn: bằng 0.
        --
        -- Còn lọt có chủ đích: `MistralAI-User/1.0` (63 lượt) không token, không
        -- URL liên hệ — không có gì để bắt. KHÔNG thêm danh sách tên riêng.
        or ua:find("%+https?://") ~= nil
        or ua:find("%+mailto:")  ~= nil
end

-- Non-browser HTTP client — real browsers always send "Mozilla/" AND an engine
-- token; libraries (curl, python-requests, Go-http, Java, okhttp, wget) send
-- neither. Structural signal, zero maintenance.
--
-- 2026-08-31 — ĐỪNG BỎ DÒNG `if ua:find("Mozilla/") ... return false` phía dưới.
-- Chú thích trên mô tả đúng thực tế (browser có CẢ `Mozilla/` LẪN token engine;
-- thư viện KHÔNG có gì), nhưng code chỉ hiện thực được vế "không có gì". Dải
-- giữa — **có `Mozilla/`, không có engine** — không thuộc nhánh nào, rơi xuống
-- `unknown` ở cuối hàm. Nhìn từ bảng "Unknown Client — UA Samples" thì đó trông
-- hệt như lỗ hổng: thấy `zgrab/0.x`, `WP-VerProbe/1.0`, `CT-WP-Probe/1.2` và
-- `Mozilla/5.0` trần nằm chình ình trong ô `unknown`. Đo rồi thì CẢ BA hướng
-- sửa đều tệ hơn hiện trạng.
--
-- Đo 1 ngày antibot.log, lọc `Mozilla` + KHÔNG `AppleWebKit|Gecko|Trident|Presto`
-- ⇒ dải giữa rộng 23.340 req, nhưng phân bố ngược hẳn trực giác:
--   22.743  crawler         ← `is_crawler` chạy TRƯỚC hàm này, đã hứng 97,4%
--      254  unknown         ← phần hở THẬT, chỉ có bấy nhiêu
--      177  gate_exit       ← thoát trước bước 10, `device_type` còn nil
--      127  desktop_chrome  ← xem (2) và (3)
--       36  desktop_other   ← MSIE 6/7 dị dạng, đã ăn 0,05 y như http_client
--        2  http_client
--        1  desktop_firefox
--
-- (1) Đổi nhãn 254 `unknown` → `http_client`: THUẦN THẨM MỸ. Cả hai đều
--     `sec_fetch_expected=false` ⇒ `sec_fetch_penalty()` trả 0,05 y hệt
--     (header_anomaly.lua:27) ⇒ không xê dịch một điểm nào. Lại còn làm mù
--     bảng UA Samples: `logger.lua:261` CHỈ lấy mẫu ô `unknown`, đó là cửa sổ
--     duy nhất nhìn thấy chuỗi UA thô của đám đang dò.
--
-- (2) Đẩy kiểm engine lên đầu hàm (`return not has_engine`): LÀM YẾU HỆ.
--     128 dòng `desktop_chrome`/`desktop_firefox` kia đang mang
--     `sec_fetch_expected=true` ⇒ thiếu Sec-Fetch là ăn 0,40. Biến thành
--     `http_client` tức tụt còn 0,05: −0,35 × 0,45 × 35 = **−5,5 điểm raw**,
--     đúng vào nhóm đáng ngờ nhất của cả dải. Sửa cho sạch nhãn hoá ra là tự
--     tháo một mũi phạt.
--
-- (3) Thêm tín hiệu "khai `Chrome/`|`Firefox/` mà không engine": KHÔNG LẬT
--     ĐƯỢC GÌ. 128 dòng đó là UA giả viết tay — 123 lượt cùng MỘT chuỗi:
--         Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0
--     = chuỗi Chrome 120 thật trừ đi hai mệnh đề engine ở giữa. KHÔNG phải
--     hiện vật cắt chuỗi: logger cắt ở ký tự 120, mà `AppleWebKit` nằm ở ký
--     tự 42 và chuỗi thật chỉ dài 111 — một nhát cắt sẽ GIỮ AppleWebKit rồi
--     mất đuôi, chứ không moi được khúc giữa. Client thật không sinh ra hình
--     dạng này ⇒ FP = 0. NHƯNG: 112 lượt đã `block` + 1 `challenge` bằng
--     đường khác, và 15 lượt `allow` còn lại nằm ở **eff 10-19, class
--     `api_callback`** (`score_multiplier = 0,5` ⇒ raw 20-38). Nâng
--     `ua_lacks_browser_structure` từ 0,25 lên tận 1,00 — trọng số tối đa
--     tuyệt đối của cả module — chỉ được 19 + 0,75×15,75×0,5 = **24,9**, vẫn
--     dưới `MONITOR = 25`. Nhân 0,5 của lớp `api_callback` nuốt hết. Và
--     `ip_risk_lowered` bị vô hiệu đúng cho lớp này (engine.lua:513) nên
--     không có ngưỡng 40 nào để mượn. Lợi bằng đúng KHÔNG.
--
-- Tóm: ô `unknown` ở đây KHÔNG phải chỗ bot lọt. Chúng đã ăn +0,35
-- (`ua_is_versioned_tool`) hoặc +0,25 (`ua_lacks_browser_structure`) từ trước
-- đó. Nhãn xấu, phán quyết đúng — để nguyên.
local function is_http_tool(ua)
    if ua:find("Mozilla/", 1, true) then return false end
    if ua:find("AppleWebKit", 1, true)
       or ua:find("Gecko", 1, true)
       or ua:find("Trident", 1, true)
       or ua:find("Presto", 1, true) then
        return false
    end
    return true
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

    -- ── Non-browser agents (drain the old catch-all "unknown") ─
    -- crawler: self-declared bot. http_client: HTTP library (no Mozilla+engine).
    -- Enforcement-neutral (device_type isn't scored) — makes the admin Client
    -- panel meaningful instead of dumping every bot/tool into "unknown".
    if is_crawler(ua) then
        return {
            device_type                   = "crawler",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end
    if is_http_tool(ua) then
        return {
            device_type                   = "http_client",
            device_sec_fetch_expected     = false,
            device_ch_ua_mobile_expected  = false,
            device_is_mobile              = false,
            device_ios_version            = nil,
        }
    end

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
        -- `is_custom_tab` gộp HAI dân số khác hẳn nhau, và trước 2026-08-21 cả
        -- hai cùng được miễn kiểm Sec-Fetch:
        --   • WebView Chromium hiện đại (`wv` + `Chrome/`) — CÓ gửi Sec-Fetch
        --   • trình duyệt AOSP đời cũ (`Version/N`, không Chrome) — KHÔNG gửi
        -- Sự miễn trừ được viết cho nhóm sau, mà đo 2026-08-20 nhóm sau chỉ có
        -- **8 request** (Android 2.2 / 2.3.7 / 4.4.2) trên 27.669.
        --
        -- BẰNG CHỨNG (không suy từ kiến trúc — đo trên antibot.log):
        --   custom_tab, action=allow : sf=1 456 / sf=0 55 = **89,2% CÓ gửi**
        --                              (Chrome Android thật chỉ 81,3%)
        --   custom_tab, action=block : sf=1   0 / sf=0 353 = **0%**
        -- Gradient tuyệt đối theo phán quyết ⇒ `sf=0` là chữ ký bot, không phải
        -- hiện vật giao thức.
        --
        -- FP = 0 THEO CẤU TRÚC, đã đo chứ không phải hy vọng: 165 lượt
        -- `custom_tab sf=0 allow` phân bố 0-9:48, 10-19:45, 20-29:72 — KHÔNG
        -- có gì từ 30 trở lên. Phạt tăng thêm tối đa
        -- (0,30−0,05 +0,10) × 0,45 × 35 = **+5,51 điểm thô**, đẩy đỉnh lên ~35,
        -- còn cách ngưỡng challenge 55 hai chục điểm, và dưới cả ngưỡng 40 của
        -- nhánh `ip_risk_lowered` (dải 34-40 đếm được **0**).
        --
        -- `ch_ua_mobile` thì NGƯỢC LẠI, và đó là lý do hai trường không đi cùng
        -- nhau: chỉ **26/970 = 2,7%** WebView gửi `Sec-CH-UA-Mobile`. Bật nó sẽ
        -- bắn oan 97% WebView thật. Giữ `false`.
        local is_chromium_wv = ua:find("Chrome/", 1, true) ~= nil
        return {
            device_type                   = "custom_tab",
            device_sec_fetch_expected     = is_chromium_wv,
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
