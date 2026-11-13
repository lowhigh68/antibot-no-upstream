-- Shared key contract for the network-UA quarantine layer.
--
-- `network_id` is intentionally coarse: md5(version | IP | normalized-UA).
-- It is not a device identifier.  The collision is handled by host scope,
-- short finite TTLs and challenge-first recovery, not by adding unstable
-- request headers to the hash.

local _M = {}

local identity = require "antibot.core.fingerprint.identity"
local site_scope = require "antibot.core.site_scope"

function _M.network_id(ctx)
    -- With no verified end-client address, identity.build_from(edge, ua)
    -- represents every user sharing one proxy edge and browser family.  It is
    -- not a device/network identity and must never address a persistent seal.
    if ctx and ctx.ip_is_aggregate == true then return nil end
    if ctx and ctx.network_id and ctx.network_id ~= "" then
        return ctx.network_id
    end
    if not ctx then return nil end
    local ip = ctx.ip or ""
    if ip == "" then return nil end
    local id = identity.build_from(ip, ctx.ua or "")
    ctx.network_id = id
    return id
end

function _M.host(ctx)
    return site_scope.host(ctx)
end

function _M.keys(ctx, scope)
    local id = _M.network_id(ctx)
    if not id or id == "" then return nil end

    if scope == "global" then
        return {
            id      = id,
            host    = site_scope.host(ctx),
            scope   = "global",
            ban     = "gban:"  .. id,
            hit     = "ghit:"  .. id,
            viol    = "gviol:" .. id,
            context = "gctx:"  .. id,
        }
    end

    local host = site_scope.host(ctx)
    local suffix = host .. ":" .. id
    return {
        id      = id,
        host    = host,
        scope   = "host",
        ban     = "qban:"  .. suffix,
        hit     = "qhit:"  .. suffix,
        viol    = "qviol:" .. suffix,
        context = "qctx:"  .. suffix,
    }
end

function _M.legacy_keys(ctx)
    local id = _M.network_id(ctx)
    if not id or id == "" then return nil end
    return {
        id      = id,
        host    = site_scope.host(ctx),
        scope   = "legacy",
        ban     = "ban:" .. id,
        hit     = "ban:hit:" .. id,
        viol    = "viol:" .. id,
        context = "ban_ctx:" .. id,
    }
end

return _M
