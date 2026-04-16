local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local id  = ctx.identity or ctx.fp_light
    local now = ngx.now()
    ctx.timing = { delta = nil, stddev = nil }

    if not id then return end

    local key    = "timing:" .. id
    local red, e = pool.get()
    if not red then return end

    red:init_pipeline()
    red:getset(key, string.format("%.3f", now))
    red:expire(key, 300)
    local res = red:commit_pipeline()
    pool.put(red)

    local prev = res and tonumber(res[1])
    if prev then
        ctx.timing.delta = now - prev
    end
end

return _M
