-- session_richness — generic proxy cho "client đã có state với server chưa",
-- không phụ thuộc CMS cookie schema.
--
-- Lý do tồn tại:
--   Mỗi CMS issue cookie/header riêng (WP: wp_logged_in_*, Joomla:
--   joomla_user_state, Magento: admin/frontend, Drupal: SESS<hash>, SPA:
--   JWT trong Authorization header). Hardcode list dẫn đến maintain
--   không bao giờ đủ. Thay vì check TÊN cookie, đo BẰNG CHỨNG VẬT LÝ
--   rằng client đã có state: cookie payload size, count, auth headers.
--
-- Output: ctx.session_richness ∈ [0, 1]
--   0.0 = no state (first-time visitor, dumb bot, curl)
--   0.3 = light state (analytics cookies, returning anonymous)
--   0.6 = moderate state (multiple cookies, partial auth)
--   0.9 = full state (logged-in admin, multi-cookie session)
--   1.0 = saturated (Authorization + CSRF + nhiều cookie)
--
-- Continuous (không binary) để graceful degradation. Dùng làm:
--   1. Threshold multiplier ở l7/rate + l7/burst (lift threshold cho user
--      có state, không lift cho first-visit/bot)
--   2. Negative signal trong intelligence/scoring/compute (weight -30):
--      richness 1.0 trừ 30 pts khỏi score → trust-based lowering
--
-- Cross-domain persistence (richness:max:<identity> TTL 3600s):
--   Cookie là per-domain — admin có richness=0.80 ở domain A nhưng khi
--   truy cập domain B lần đầu richness=0.10 (chưa có cookie domain B).
--   cluster_score vẫn fire cross-domain → không đủ offset → ban oan.
--   Fix: persist max richness per identity trong Redis → domain B đọc
--   được giá trị domain A đã prove → negative signal đủ lớn → allow.
--   Redis shared toàn server chính xác là cơ sở để implement điều này.
--
-- Generic: thêm CMS mới ZERO config change. Cookie tên gì cũng được —
-- chỉ cần có payload thật là tính.

local _M  = {}
local pool = require "antibot.core.redis_pool"

-- Calibration từ observation thực tế:
--   - Anonymous first visit:                bytes 0,    n 0,    r=0.0
--   - Returning anon (1 _ga cookie):         bytes 30,   n 1,    r~0.1
--   - Returning anon + cart:                 bytes 150,  n 3,    r~0.4
--   - WP logged-in:                          bytes 350,  n 4-5,  r~0.7
--   - Magento admin:                         bytes 600,  n 6,    r~0.9
--   - SPA + JWT Bearer:                      bytes 100,  n 2,    r~0.5 (auth bonus)
--   - WP admin + CSRF (POST):                bytes 400,  n 5,    r~1.0
local SIZE_SATURATION  = 500    -- byte tại đó size_score = 1.0
local COUNT_SATURATION = 4      -- cookie count tại đó count_score = 1.0
local SIZE_WEIGHT      = 0.5    -- 50% sức nặng dành cho payload bytes
local COUNT_WEIGHT     = 0.3    -- 30% cho count (chống bot 1 cookie giả lớn)
local AUTH_BONUS       = 0.3    -- Authorization header (Bearer/Basic)
local CSRF_BONUS       = 0.2    -- X-CSRF-Token / X-XSRF-TOKEN

-- Cross-domain persistence thresholds.
-- PERSIST_MIN: chỉ lưu Redis khi richness đủ meaningful — tránh write
-- storm từ casual visitor với 1 analytics cookie (r~0.1). 0.4 tương
-- ứng returning user với vài cookie, đủ phân biệt với first-visit bot.
local RICHNESS_PERSIST_MIN = 0.4
local RICHNESS_TTL         = 3600  -- 1 giờ, cover 1 work session

local function count_cookies(s)
    if not s or s == "" then return 0 end
    local n = 0
    for _ in s:gmatch("[^;]+") do n = n + 1 end
    return n
end

function _M.compute(ctx)
    local cookie = ngx.var.http_cookie or ""
    local auth   = ngx.var.http_authorization or ""
    local csrf   = ngx.var.http_x_csrf_token  or
                   ngx.var.http_x_xsrf_token  or ""

    local bytes = #cookie
    local n_ck  = count_cookies(cookie)

    local size_score  = math.min(bytes / SIZE_SATURATION, 1.0)
    local count_score = math.min(n_ck / COUNT_SATURATION, 1.0)
    local has_auth    = (auth ~= "")
    local has_csrf    = (csrf ~= "")

    local r = SIZE_WEIGHT  * size_score
            + COUNT_WEIGHT * count_score
            + (has_auth and AUTH_BONUS or 0)
            + (has_csrf and CSRF_BONUS or 0)

    if r > 1.0 then r = 1.0 end

    -- Cross-domain richness persistence.
    -- Admin prove richness=0.80 ở domain A → stored in Redis per identity.
    -- Khi truy cập domain B (ít cookie hơn → r thấp hơn), đọc stored max
    -- → dùng giá trị cao hơn → cluster_score được offset đúng mức.
    -- Write chỉ khi r >= RICHNESS_PERSIST_MIN để tránh pollute bằng casual
    -- visit. Write cũng refresh TTL khi dùng stored value (admin active).
    local id = ctx.identity or ctx.ip or ""
    if id ~= "" then
        local key    = "richness:max:" .. id
        local stored = tonumber(pool.safe_get(key)) or 0
        if stored > r then r = stored end
        if r >= RICHNESS_PERSIST_MIN then
            pool.safe_set(key, string.format("%.2f", r), RICHNESS_TTL)
        end
    end

    ctx.session_richness = r

    ngx.log(ngx.DEBUG,
        "[session_richness] r=", string.format("%.2f", r),
        " bytes=", bytes,
        " n_ck=", n_ck,
        " auth=", has_auth and "1" or "0",
        " csrf=", has_csrf and "1" or "0")
end

function _M.run(ctx)
    _M.compute(ctx)
    return true, false
end

return _M
