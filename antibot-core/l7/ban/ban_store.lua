local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local quarantine = require "antibot.core.network_quarantine"
local decision = require "antibot.core.decision"

function _M.run(ctx)
    local qcfg = cfg.network_quarantine or {}
    if qcfg.enabled == false then
        ctx.banned = false
        return false, false
    end

    -- No valid cookie means no durable subject and therefore no lookup.  Live
    -- WAF/L7/scoring still runs and may block this request normally.
    local keys = quarantine.keys(ctx, "host")
    if not keys then
        ctx.banned = false
        return false, false
    end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_store] redis unavailable: ", tostring(err))
        ctx.banned = false
        return false, false
    end
    local sealed = red:get(keys.ban)
    pool.put(red)
    if sealed ~= "1" then
        ctx.banned = false
        return false, false
    end

    ctx.ban_id        = keys.id
    ctx.ban_id_kind   = "actor"
    ctx.ban_scope     = "host"
    ctx.ban_host      = keys.host
    ctx.ban_key       = keys.ban
    ctx.ban_legacy    = false

    local accept = (ctx.req and ctx.req.accept) or ngx.var.http_accept or ""
    local html_navigation = accept:find("text/html", 1, true) ~= nil
    if html_navigation then
        pool.safe_set(keys.hit, tostring(ngx.time()), 300)
        ctx.action        = "challenge"
        ctx.action_reason = "actor_quarantine_challenge"
        decision.set(ctx, {
            kind = "challenge", source = "quarantine",
            rule = ctx.action_reason, mode = "enforce",
            scope = "actor_host", subject = keys.id, upstream = false,
        })
        ctx.banned = false
        ngx.log(ngx.INFO,
            "[ban_store] actor recovery challenge actor=",
            keys.id:sub(1, 8), "... host=", keys.host)
        require("antibot.enforcement.challenge").run(ctx)
        return true, true
    end

    -- A seal hit is activity, not new evidence: never refresh the sentence or
    -- advance the violation ladder here.
    pool.safe_set(keys.hit, tostring(ngx.time()), 300)
    ctx.banned        = true
    ctx.action        = "block"
    ctx.action_reason = "actor_quarantine"
    decision.set(ctx, {
        kind = "security", source = "quarantine",
        rule = ctx.action_reason, mode = "enforce",
        scope = "actor_host", subject = keys.id, upstream = false,
    })
    ngx.log(ngx.INFO,
        "[ban_store] actor blocked actor=", keys.id:sub(1, 8),
        "... host=", keys.host)
    ngx.status = 403
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Access denied.")
    ngx.exit(403)
    return true, true
end

return _M
