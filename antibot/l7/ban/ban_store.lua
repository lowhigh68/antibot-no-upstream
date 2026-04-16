local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local id = ctx.fp_light or ctx.identity
    if not id or id == "" then
        ctx.banned = false
        return false, false
    end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_store] redis unavailable: ", err)
        ctx.banned = false
        return false, false
    end

    local val, rerr = red:get("ban:" .. id)
    pool.put(red)

    if val == "1" then
        ctx.banned = true
        ngx.log(ngx.INFO, "[ban_store] blocked id=", id:sub(1, 8), "...")
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true
    end

    ctx.banned = false
    return false, false
end

return _M
