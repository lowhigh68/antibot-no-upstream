local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local id = ctx.identity or ctx.fp_light
    if not id then ctx.risk = 0.0; return end
    local val = pool.safe_get("risk:" .. id)
    ctx.risk = tonumber(val) or 0.0
end

return _M
