local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    local banned = pool.safe_get("ban:" .. ip)
    if banned == "1" then
        ctx.banned = true
        ngx.log(ngx.INFO, "[ip_ban] blocked ip=", ip)
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true
    end

    return true, false
end

return _M
