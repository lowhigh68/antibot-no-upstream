local _M  = {}
local cfg = require "antibot.core.config"

-- burst_decision — fire ctx.burst_flag dựa trên 2 dimension orthogonal:
--
--   1. Class nature (cfg.rate.class_burst_factor[req_class])
--      Loại request này tự nhiên burst nhiều hay ít? Nav class human-realistic
--      max ~20/s; interaction class SPA frontend có thể 45/s legitimately.
--
--   2. First-party state cua CHINH request
--      Chi `session_richness_own` khi `session_cookie_known == true` moi duoc
--      lift. Cookie rac hoac richness ke thua khong co quyen noi threshold.
--
-- effective_threshold = base × class_factor × (1 + richness × 2)
--
-- Ví dụ effective_threshold (base=30):
--   WP admin AJAX (richness 0.8, interaction):  30 × 1.5 × 2.6  = 117/s
--   Anonymous SPA (richness 0.15, interaction): 30 × 1.5 × 1.3  = 58/s
--   Bot scrape (richness 0, interaction):       30 × 1.5 × 1.0  = 45/s
--   Multi-tab user (richness 0, navigation):    30 × 0.67 × 1.0 = 20/s
--   Login bot (richness 0, auth_endpoint):      30 × 0.8 × 1.0  = 24/s

function _M.run(ctx)
    local base   = cfg.rate.burst_threshold
    local class  = ctx.req_class or "unknown"
    local factor = (cfg.rate.class_burst_factor or {})[class] or 1.0
    -- Chi first-party state cua CHINH request moi duoc lift threshold.
    local r = 0
    if ctx.session_cookie_known == true then
        r = ctx.session_richness_own or 0
    end
    local lift   = 1.0 + r * 2.0

    local effective = base * factor * lift
    ctx.burst_flag = (ctx.burst or 0) > effective

    if ctx.burst_flag then
        ngx.log(ngx.INFO,
            "[burst] violation count=", ctx.burst,
            " thresh=", string.format("%.0f", effective),
            " base=", base,
            " class=", class, " (factor=", factor, ")",
            " richness=", string.format("%.2f", r),
            " ip=", ctx.ip)
    end
end

return _M
