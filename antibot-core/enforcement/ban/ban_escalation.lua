local _M   = {}
local cfg  = require "antibot.core.config"
local quarantine = require "antibot.core.network_quarantine"

function _M.run(ctx)
    local qcfg  = cfg.network_quarantine or {}
    local steps = qcfg.steps or {300, 3600, 86400}
    local keys  = quarantine.keys(ctx, "host")

    -- A live score/WAF decision still blocks this request.  Persistence is a
    -- separate privilege and requires a valid host-bound actor that arrived
    -- with the request; a SID minted on this response is intentionally absent.
    ctx.ban_scope   = keys and "host" or nil
    ctx.ban_id_kind = keys and "actor" or nil
    ctx.ban_id      = keys and keys.id or nil
    ctx.ban_host    = keys and keys.host or nil
    ctx.ban_key     = keys and keys.ban or nil
    ctx.ban_ttl     = keys and steps[1] or nil
    ctx.ban_previous_viol = keys and 0 or nil
    ctx.ban_violation = keys and 1 or nil
    ctx.ban_created = nil
    ctx.ban_persisted = false

    if not keys then
        ctx.ban_suppressed = "no_presented_actor"
        return true, false
    end

    ngx.log(ngx.INFO,
        "[ban_escalation] pending_actor_claim",
        " class=", ctx.req_class or "unknown",
        " actor=", keys.id:sub(1, 8), "...",
        " host=", keys.host,
        " provisional_ttl=", tostring(ctx.ban_ttl), "s")
    return true, false
end

return _M
