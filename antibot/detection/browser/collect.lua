local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local fp = ctx.fp_light
    if not fp then ctx.browser = nil; return end

    local val = pool.safe_get("beacon_data:" .. fp)
    if not val then ctx.browser = nil; return end

    local ok, data = pcall(require("cjson").decode, val)
    if ok and data then
        ctx.browser = data
        ctx.beacon_received = true
    else
        ctx.browser = nil
    end
end

return _M
