local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    -- Only the request that atomically created a new sentence may publish it.
    -- Concurrent engine blocks still receive 403, but publishing each loser
    -- would make downstream consumers recreate/refresh one incident many times.
    if ctx.ban_created ~= true or ctx.ban_persisted ~= true then return end

    local id  = ctx.actor_id
    local ttl = ctx.ban_ttl
    local scope = "actor_host"
    local host = ctx.ban_host or ""
    if not id or ctx.actor_presented ~= true then return end

    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end
        local payload = string.format(
            '{"schema":2,"actor_id":"%s","scope":"%s",' ..
            '"host":"%s","ttl":%s}',
            id, scope, host,
            tostring(ttl or 0))
        red:publish("channel:ban", payload)
        pool.put(red)
    end)
end

return _M
