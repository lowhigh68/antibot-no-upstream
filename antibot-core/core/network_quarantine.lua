-- Durable quarantine key contract.
--
-- Historical qban/gban subjects were `network_id = md5(IP | ua_norm)`.  That
-- value is useful for short correlation but is never a person/device: CGNAT,
-- cloned office browsers and proxy edges collide.  Version 2 accepts only a
-- signed actor cookie that the client PRESENTED, and every key is host scoped.
-- Old namespaces are intentionally not read or migrated; they expire by TTL.

local _M = {}

local identity   = require "antibot.core.fingerprint.identity"
local site_scope = require "antibot.core.site_scope"

-- Retained for short-lived analytics/rate callers.  It must never be used by
-- keys() or any other durable-sentence path.
function _M.network_id(ctx)
    if ctx and ctx.ip_is_aggregate == true then return nil end
    if ctx and ctx.network_id and ctx.network_id ~= "" then
        return ctx.network_id
    end
    if not ctx or not ctx.ip or ctx.ip == "" then return nil end
    local id = identity.build_from(ctx.ip, ctx.ua or "")
    ctx.network_id = id
    return id
end

function _M.actor_id(ctx)
    if not ctx or ctx.actor_presented ~= true or ctx.actor_valid ~= true then
        return nil
    end
    local id = ctx.actor_id
    if type(id) ~= "string" or not id:match("^[0-9a-f]+$") or #id ~= 32 then
        return nil
    end
    return id
end

function _M.host(ctx)
    return site_scope.host(ctx)
end

function _M.keys(ctx, _scope)
    local id = _M.actor_id(ctx)
    if not id then return nil end
    local host = site_scope.host(ctx)
    local suffix = host .. ":" .. id
    return {
        id      = id,
        host    = host,
        scope   = "host",
        kind    = "actor",
        ban     = "q2:"    .. suffix,
        hit     = "q2hit:" .. suffix,
        viol    = "q2v:"   .. suffix,
        context = "q2ctx:" .. suffix,
    }
end

-- Explicit tombstone: no caller may silently re-enable the collective legacy
-- read path by toggling a config flag.
function _M.legacy_keys(_ctx)
    return nil
end

return _M
