-- Key contract for behavioral state which must not bleed between tenants.
--
-- External clients retain the historical keys byte-for-byte.  Only trusted
-- self traffic (the unspoofable TCP peer matches this server) receives a
-- canonical site/vhost component.  It is still scored normally; this module
-- isolates state, it does not whitelist the server IP or HTTP clients.

local _M = {}

local ip_scope   = require "antibot.core.ip_scope"
local site_scope = require "antibot.core.site_scope"

function _M.is_self(ctx)
    if ctx and ctx.self_request ~= nil then
        return ctx.self_request == true
    end

    local value = ip_scope.is_self(ctx) == true
    if ctx then ctx.self_request = value end
    return value
end

function _M.site(ctx)
    return site_scope.host(ctx)
end

function _M.risk_key(ctx, id)
    if _M.is_self(ctx) then
        return "risk:self:" .. _M.site(ctx) .. ":" .. id
    end
    return "risk:" .. id
end

function _M.ip_risk_key(ctx, ip)
    if _M.is_self(ctx) then
        return "ip_risk:self:" .. _M.site(ctx) .. ":" .. ip
    end
    return "ip_risk:" .. ip
end

function _M.fingerprint_seed(ctx, base)
    if _M.is_self(ctx) then
        return base .. "|self|" .. _M.site(ctx)
    end
    return base
end

return _M
