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
        -- Ghi nhận L7 thực sự enforce ban này. Dashboard dùng để phân biệt
        -- ban đang active (có hit gần đây) vs idle (entry còn TTL nhưng không
        -- còn traffic — có thể L3 đã chặn upstream, hoặc bot đã ngừng).
        -- TTL 300s: sau 5 phút không có hit → coi là idle.
        pool.safe_set("ban:hit:" .. ip, tostring(ngx.time()), 300)
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
