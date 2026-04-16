local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local fp = ctx.fp_light
    if not fp then ctx.session = {}; return end

    local limit = cfg.ttl.session_max_len - 1

    local red, err = pool.get()
    if not red then
        ctx.session = {}
        return
    end

    local data, rerr = red:lrange("sess:" .. fp, 0, limit)
    pool.put(red)

    if data and type(data) == "table" then
        ctx.session  = data
        ctx.sess_len = #data
    else
        ctx.session  = {}
        ctx.sess_len = 0
    end
end

return _M
