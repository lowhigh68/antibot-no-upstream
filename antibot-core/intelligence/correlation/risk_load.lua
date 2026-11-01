local _M   = {}
local pool = require "antibot.core.redis_pool"
local state_scope = require "antibot.core.state_scope"

function _M.run(ctx)
    local id = ctx.identity or ctx.fp_light
    if not id then ctx.risk = 0.0; return end
    local val = pool.safe_get(state_scope.risk_key(ctx, id))
    ctx.risk = tonumber(val) or 0.0
end

return _M
