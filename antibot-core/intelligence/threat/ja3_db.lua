local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    -- No ja3 or partial ja3 (cipher list missing) → hash is not meaningful
    -- for reputation lookup. Skip to avoid false hits on wrong hash.
    if not ctx.ja3 or ctx.ja3_partial then
        ctx.ja3_rep = 0.0
        return true, false
    end
    local val = pool.safe_get("rep:ja3:" .. ctx.ja3)
    ctx.ja3_rep = tonumber(val) or 0.0
    return true, false
end

return _M
