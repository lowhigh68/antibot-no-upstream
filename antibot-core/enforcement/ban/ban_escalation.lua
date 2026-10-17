local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local quarantine = require "antibot.core.network_quarantine"

local function choose_scope(ctx)
    local c = cfg.network_quarantine or {}
    local reasons = c.global_reasons or {}
    if reasons[ctx.action_reason or ""] == true then return "global" end
    return "host"
end

function _M.run(ctx)
    local qcfg  = cfg.network_quarantine or {}
    local scope = choose_scope(ctx)
    local steps = scope == "global" and cfg.ttl.ban_steps
        or qcfg.steps or {300, 3600, 86400}
    local class = ctx.req_class or "unknown"
    local keys  = quarantine.keys(ctx, scope)
    local id    = keys and keys.id

    ctx.ban_scope   = scope
    ctx.ban_id_kind = "network_ua"
    ctx.ban_id      = id
    ctx.ban_host    = keys and keys.host or nil
    ctx.ban_key     = keys and keys.ban or nil

    if class == "resource" or class == "interaction" then
        ctx.ban_ttl = steps[1]
        ctx.ban_previous_viol = 0
        ctx.ban_violation = 1
        ngx.log(ngx.WARN,
            "[ban_escalation] unexpected call for class=", class,
            " ip=", ctx.ip or "?",
            " -- engine should have prevented this")
        return true, false
    end

    if not id then
        ctx.ban_ttl = steps[1]
        ctx.ban_previous_viol = 0
        ctx.ban_violation = 1
        ngx.log(ngx.WARN, "[ban_escalation] no network identity, ttl=",
            ctx.ban_ttl)
        return true, false
    end

    -- Only a fresh engine block reaches this function. A request that merely
    -- hits an existing seal exits from l7/ban/ban_store.lua and never changes
    -- the violation counter or the remaining sentence.
    local previous = tonumber(pool.safe_get(keys.viol)) or 0
    local viol = previous + 1
    local idx  = math.min(viol, #steps)
    ctx.ban_ttl = steps[idx]
    ctx.ban_previous_viol = previous
    ctx.ban_violation = viol

    ngx.log(ngx.INFO,
        "[ban_escalation]",
        " class=", class,
        " id=", id:sub(1, 8), "...",
        " scope=", scope,
        " host=", keys.host,
        " viol=", viol,
        " step=", idx,
        " ttl=", tostring(ctx.ban_ttl) .. "s")

    return true, false
end

return _M
