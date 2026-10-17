-- Generic automation traffic meter.
--
-- Claim recognition is structural (bot/spider/crawler or RFC contact marker),
-- not a list of AI brands. This module runs before every early exit so banned,
-- WAF-blocked and admission-limited automation still appears in telemetry.
-- It uses the existing shared dict only: no Redis RTT and no nginx.conf change.
--
-- Current rollout is shadow-only by contract. `autwould=true` is a calibration
-- result; this module never sets ctx.action, headers or ngx.exit.

local _M = {}

local cfg = require "antibot.core.config"
local operator_network = require "antibot.core.operator_network"

local function conf()
    return cfg.automation or {}
end

local function digest(value)
    value = tostring(value or "-")
    if ngx.md5 then return ngx.md5(value) end
    -- Test/fallback only. OpenResty always provides ngx.md5.
    return value:gsub("[^%w_.-]", "_"):sub(1, 64)
end

local function bump(dict, key, delta, ttl)
    local added, err = dict:add(key, delta, ttl)
    if added then return delta end
    if err ~= "exists" then return nil, err end
    return dict:incr(key, delta)
end

local function key(axis, identity, window, now)
    return "auto:" .. axis .. ":" .. digest(identity)
        .. ":" .. window .. ":" .. math.floor(now / window)
end

local function pair(dict, axis, identity, windows, cost, now)
    local short = tonumber(windows.short) or 10
    local long  = tonumber(windows.long) or 60
    local sv, se = bump(dict, key(axis, identity, short, now), cost, short * 2 + 2)
    local lv, le = bump(dict, key(axis, identity, long, now), cost, long * 2 + 2)
    return sv, lv, se or le
end

local function consider(ctx, axis, short_value, long_value, limits, top)
    if not limits then return top end
    local sr = limits.short and short_value and short_value / limits.short or 0
    local lr = limits.long  and long_value  and long_value  / limits.long  or 0
    local ratio, window = sr, "short"
    if lr > ratio then ratio, window = lr, "long" end
    if ratio > (top.ratio or 0) then
        top = { ratio = ratio, axis = axis .. ":" .. window }
    end
    if sr >= 1 or lr >= 1 then ctx.automation_would_throttle = true end
    return top
end

function _M.evaluate(ctx)
    if not ctx.automation_observed then return true, false end
    local c = conf()
    local limits = c.provisional_limits or {}
    local tiers = limits.tiers or {}
    local tier = ctx.automation_tier or "unknown"
    local top = { ratio = 0, axis = "-" }

    ctx.automation_would_throttle = false
    top = consider(ctx, "principal", ctx.automation_principal_short,
        ctx.automation_principal_long, tiers[tier] or tiers.unknown, top)
    top = consider(ctx, "ip", ctx.automation_ip_short,
        ctx.automation_ip_long, limits.ip, top)
    top = consider(ctx, "host", ctx.automation_host_short,
        ctx.automation_host_long, limits.host, top)
    top = consider(ctx, "server", ctx.automation_server_short,
        ctx.automation_server_long, limits.server, top)

    ctx.automation_tier = tier
    ctx.automation_top_axis = top.axis
    ctx.automation_top_use = math.floor((top.ratio or 0) * 100 + 0.5)
    return true, false
end

function _M.run(ctx)
    local c = conf()
    if c.enabled == false or c.mode == "off" then return true, false end
    if not ctx.automation_meter_claimed and not ctx.automation_claimed then
        return true, false
    end
    if ngx.is_subrequest then return true, false end

    -- One cached Redis lookup only for machine-shaped/claimed automation, not
    -- for ordinary traffic.  Positive evidence changes the meter tier but does
    -- not bypass any detector or access rule.
    operator_network.resolve(ctx)

    ctx.automation_mode = c.mode or "shadow"
    ctx.automation_tier = ctx.automation_tier or "unknown"
    ctx.automation_principal = ctx.automation_principal or "automation-client"

    local dict = ngx.shared and ngx.shared.antibot_cache
    if not dict then
        ctx.automation_observed = true
        ctx.automation_degraded = true
        return _M.evaluate(ctx)
    end

    local class = ctx.req_class or "unknown"
    local cost = tonumber((c.costs or {})[class]) or 1
    local host = ((ctx.req and ctx.req.host) or ngx.var.host or "-"):lower()
    local ip = tostring(ctx.ip or "-")
    local principal = tostring(ctx.automation_principal)
    local now = ngx.time()
    local windows = c.windows or { short = 10, long = 60 }

    local ps, pl, pe = pair(dict, "p", host .. "\0" .. principal,
        windows, cost, now)
    local is, il, ie = pair(dict, "i", host .. "\0" .. ip,
        windows, cost, now)
    local hs, hl, he = pair(dict, "h", host, windows, cost, now)
    local ss, sl, se = pair(dict, "s", "server", windows, cost, now)

    ctx.automation_observed = true
    ctx.automation_cost = cost
    ctx.automation_principal_short = ps
    ctx.automation_principal_long  = pl
    ctx.automation_ip_short = is
    ctx.automation_ip_long  = il
    ctx.automation_host_short = hs
    ctx.automation_host_long  = hl
    ctx.automation_server_short = ss
    ctx.automation_server_long  = sl
    if pe or ie or he or se then ctx.automation_degraded = true end

    return _M.evaluate(ctx)
end

return _M
