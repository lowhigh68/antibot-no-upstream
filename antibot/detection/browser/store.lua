local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local fp = ctx.fp_light
    if not fp or not ctx.browser then return end

    local ok, json = pcall(require("cjson").encode, ctx.browser)
    if not ok then return end

    pool.safe_set("beacon_data:" .. fp, json, 600)
    pool.safe_set("beacon:" .. fp, "1", 600)
    ctx.beacon_received = true
end

return _M
