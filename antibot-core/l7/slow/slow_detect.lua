local _M = {}
local cfg = require "antibot.core.config"

-- Network instability tolerance:
-- Mobile 3G/4G typical RTT 200-800ms + packet loss → request_time cao tự nhiên.
-- Trusted session (đã prove human qua nhiều request thành công) → tolerance cao hơn.
-- Bot thật trên mạng tốt vẫn rt thấp → ngưỡng device-aware không che giấu được.
local MOBILE_MULT  = 2.5
local TRUSTED_MULT = 1.5

function _M.run(ctx)
    local rt = tonumber(ngx.var.request_time) or 0
    local base = cfg.rate.slow_threshold_s

    local effective = base
    if ctx.device_is_mobile then
        effective = effective * MOBILE_MULT
    end
    local trust = cfg.trust or {}
    if (ctx.sess_len or 0) >= (trust.session_min or 5)
       and (ctx.session_flag or 0) < (trust.session_flag_max or 0.4) then
        effective = effective * TRUSTED_MULT
    end

    ctx.slow = rt > effective
    if ctx.slow then
        ngx.log(ngx.INFO,
            "[slow] attack request_time=", rt,
            " effective_threshold=", effective,
            " device=", ctx.device_type or "?",
            " ip=", ctx.ip)
    end
end

return _M
