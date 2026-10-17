-- Shared key contract for the network-UA quarantine layer.
--
-- `network_id` is intentionally coarse: md5(version | IP | normalized-UA).
-- It is not a device identifier.  The collision is handled by host scope,
-- short finite TTLs and challenge-first recovery, not by adding unstable
-- request headers to the hash.

local _M = {}

local identity = require "antibot.core.fingerprint.identity"

local function safe_host(ctx)
    -- Intentional SITE/VHOST scope, not the literal Host header.  In nginx,
    -- `$server_name` is the first name declared by the matched server block;
    -- aliases that share one vhost/docroot therefore share one quarantine
    -- bucket.  That avoids escaping a quarantine by switching www/apex/alias,
    -- at the accepted cost that one alias can affect its sibling aliases.
    local host = ngx.var.server_name
    if not host or host == "" then
        host = (ctx and ctx.req and ctx.req.host) or ngx.var.host or "unknown"
    end
    host = tostring(host):lower():gsub("%.$", "")
    host = host:gsub("[^%w%.%-_]", "_")
    if host == "" then host = "unknown" end
    if #host > 96 then
        host = ngx.md5 and ngx.md5(host):sub(1, 32) or host:sub(1, 96)
    end
    return host
end

function _M.network_id(ctx)
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
    return safe_host(ctx)
end

function _M.keys(ctx, scope)
    local id = _M.network_id(ctx)
    if not id or id == "" then return nil end

    if scope == "global" then
        return {
            id      = id,
            host    = safe_host(ctx),
            scope   = "global",
            ban     = "gban:"  .. id,
            hit     = "ghit:"  .. id,
            viol    = "gviol:" .. id,
            context = "gctx:"  .. id,
        }
    end

    local host = safe_host(ctx)
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
        host    = safe_host(ctx),
        scope   = "legacy",
        ban     = "ban:" .. id,
        hit     = "ban:hit:" .. id,
        viol    = "viol:" .. id,
        context = "ban_ctx:" .. id,
    }
end

return _M
