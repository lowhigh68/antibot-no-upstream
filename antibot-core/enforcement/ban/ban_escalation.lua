local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local steps = cfg.ttl.ban_steps
    local class = ctx.req_class or "unknown"

    if class == "resource" or class == "interaction" then
        ctx.ban_ttl = steps[1]
        ngx.log(ngx.WARN,
            "[ban_escalation] unexpected call for class=", class,
            " ip=", ctx.ip or "?",
            " — engine should have prevented this")
        return true, false
    end

    local id = ctx.identity or ctx.fp_light
    if not id then
        ctx.ban_ttl = steps[1]
        ngx.log(ngx.WARN, "[ban_escalation] no identity, ttl=", ctx.ban_ttl)
        return true, false
    end

    local red, err = pool.get()
    local viol = 1
    if red then
        local v = red:get("viol:" .. id)
        viol = tonumber(v) or 1
        pool.put(red)
    else
        ngx.log(ngx.WARN,
            "[ban_escalation] redis unavailable: ", tostring(err),
            " — using step 1")
    end

    local idx   = math.min(viol, #steps)
    ctx.ban_ttl = steps[idx]

    ngx.log(ngx.INFO,
        "[ban_escalation]",
        " class=", class,
        " id=", id:sub(1, 8), "...",
        " viol=", viol,
        " step=", idx,
        " ttl=", ctx.ban_ttl == 0 and "permanent" or tostring(ctx.ban_ttl) .. "s")

    return true, false
end

return _M
