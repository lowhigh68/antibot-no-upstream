local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    local id  = ctx.ban_id or ctx.network_id or ctx.identity or ctx.fp_light
    local ip  = ctx.ip
    local ttl = ctx.ban_ttl
    local scope = ctx.ban_scope or "host"
    local host = ctx.ban_host or ""
    -- Legacy subscribers understand `identity` only as a fleet-wide subject.
    -- Never put a host quarantine id there or an old consumer may recreate
    -- ban:<id> globally. V2-aware consumers use network_id+scope+host; IP stays
    -- present so existing IP synchronization behavior is preserved.
    local legacy_identity = scope == "global" and id or ""

    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end
        local payload = string.format(
            '{"ip":"%s","identity":"%s","network_id":"%s",' ..
            '"scope":"%s","host":"%s","ttl":%s}',
            ip or "", legacy_identity or "", id or "", scope, host,
            tostring(ttl or 0))
        red:publish("channel:ban", payload)
        pool.put(red)
    end)
end

return _M
