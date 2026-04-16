local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local id  = ctx.identity or ctx.fp_light
    local ip  = ctx.ip
    local ttl = ctx.ban_ttl

    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end
        local payload = string.format(
            '{"ip":"%s","identity":"%s","ttl":%s}',
            ip or "", id or "", tostring(ttl or 0))
        red:publish("channel:ban", payload)
        pool.put(red)
    end)
end

return _M
