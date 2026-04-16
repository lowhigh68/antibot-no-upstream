local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx, nonce)
    local id = ctx.identity or ctx.fp_light
    if not id or not nonce then return false end

    local red, err = pool.get()
    if not red then return false end

    local ok = red:setnx("nonce:" .. id, nonce)
    if ok == 1 then
        red:expire("nonce:" .. id, cfg.ttl.nonce)
    end
    pool.put(red)

    if ok ~= 1 then
        ngx.log(ngx.WARN, "[nonce] replay attempt or collision id=", id)
        return false
    end
    return true
end

return _M
