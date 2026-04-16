local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local base   = cfg.rate.base_threshold
    local risk   = ctx.ip_score or 0
    local thresh = math.floor(base * (1.0 - risk * cfg.rate.risk_factor))

    local id_rate = ctx.rate    or 0
    local ip_rate = ctx.ip_rate or 0

    ctx.rate_flag = id_rate > thresh

    local ip_surge_thresh = cfg.rate.ip_surge_threshold or (base * 5)
    ctx.ip_surge = ip_rate > ip_surge_thresh

    if ctx.rate_flag then
        ngx.log(ngx.INFO,
            "[rate] id violation id_rate=", id_rate,
            " thresh=", thresh,
            " ip=", ctx.ip)
        local id = ctx.identity or ctx.fp_light
        if id then
            ngx.timer.at(0, function()
                local r = pool.get()
                if r then
                    r:incr("viol:" .. id)
                    r:expire("viol:" .. id, cfg.ttl.violation)
                    pool.put(r)
                end
            end)
        end
    end

    if ctx.ip_surge and not ctx.rate_flag then
        ngx.log(ngx.INFO,
            "[rate] ip surge ip_rate=", ip_rate,
            " thresh=", ip_surge_thresh,
            " ip=", ctx.ip,
            " (shared IP, identity rate ok)")
    end
end

return _M
