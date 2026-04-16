local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local id = ctx.identity or ctx.fp_light
    if not id then ctx.burst = 0; return end

    local sess_len  = ctx.sess_len  or 0
    local sess_flag = ctx.session_flag or 0.0
    local trust_min = cfg.trust and cfg.trust.session_min or 5
    local flag_max  = cfg.trust and cfg.trust.session_flag_max or 0.4

    if sess_len >= trust_min and sess_flag < flag_max then
        ctx.burst = 0
        ngx.log(ngx.DEBUG,
            "[burst] grace applied sess_len=", sess_len,
            " sess_flag=", string.format("%.2f", sess_flag),
            " id=", id:sub(1, 8), "...")
        return
    end

    local count = pool.safe_incr("burst:" .. id, cfg.ttl.burst)
    ctx.burst = count or 0
end

return _M
