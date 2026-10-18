-- Generic per-tenant endpoint-cost guard.
--
-- Endpoint policy supplies a bounded `ctx.endpoint_id` and scope.  This module
-- meters two fixed rate windows plus in-flight work using the existing local
-- shared dict.  It deliberately does not update bot score, reputation or ban
-- state: exhausting an expensive route is a capacity fact, not proof that a
-- particular IP/identity is malicious.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.endpoint_guard or {}
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function dictionary()
    return ngx.shared and ngx.shared.antibot_cache
end

local function log_dict_error(where, err)
    local stats = ngx.shared and ngx.shared.antibot_stats
    if stats then
        if not stats:incr("endpoint:dicterr", 1) then
            stats:add("endpoint:dicterr", 1, 86400)
        end
    end
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[endpoint_guard] shared-dict error at ", where,
            ": ", tostring(err or "unknown"), " (fail-open)")
    end
end

local function delete_key(dict, key)
    if dict.delete then return dict:delete(key) end
    return dict:set(key, nil)
end

local function increment(dict, key, ttl)
    local value, err = dict:incr(key, 1)
    if not value then
        if err ~= "not found" then return nil, err end
        local added, add_err = dict:add(key, 1, ttl)
        if added then
            value = 1
        elseif add_err == "exists" then
            value, err = dict:incr(key, 1)
            if not value then return nil, err end
        else
            return nil, add_err
        end
    end
    if dict.expire then
        local ok, expire_err = dict:expire(key, ttl)
        if not ok then return value, expire_err or "expire failed" end
    end
    return value
end

local function decrement(dict, key, ttl)
    local value, err = dict:incr(key, -1)
    if not value then
        if err == "not found" then return 0, "not found" end
        return nil, err
    end
    if value <= 0 then
        delete_key(dict, key)
        return 0
    end
    if dict.expire then dict:expire(key, ttl) end
    return value
end

local function endpoint_spec(ctx)
    local c = conf()
    if not c.enabled or not ctx or not ctx.endpoint_id then return nil, c end
    local specs = type(c.endpoints) == "table" and c.endpoints or {}
    local spec = specs[ctx.endpoint_id]
    if type(spec) ~= "table" then return nil, c end
    return spec, c
end

local function safe_scope(ctx)
    local scope = tostring(ctx.endpoint_scope or "unknown")
    if not scope:match("^[%w_-]+$") then
        scope = ngx.md5 and ngx.md5(scope):sub(1, 16)
            or scope:gsub("[^%w_-]", "_"):sub(1, 64)
    end
    return scope ~= "" and scope or "unknown"
end

local function base_key(ctx)
    return "ep:" .. safe_scope(ctx) .. ":" .. tostring(ctx.endpoint_id)
end

local function window_settings(c)
    local windows = type(c.windows) == "table" and c.windows or {}
    return math.max(math.floor(tonumber(windows.short) or 10), 1),
           math.max(math.floor(tonumber(windows.long) or 60), 1)
end

local function rate_key(base, name, seconds, t)
    return base .. ":r:" .. name .. ":" .. tostring(math.floor(t / seconds))
end

local function slot_settings(c)
    local seconds = math.max(math.floor(tonumber(c.slot_bucket_seconds) or 30), 1)
    local retention = math.max(
        math.floor(tonumber(c.slot_retention_seconds) or 180), seconds)
    return seconds, math.ceil(retention / seconds) + 1,
           retention + seconds + 1, retention
end

local function slot_key(base, bucket)
    return base .. ":slot:" .. tostring(bucket)
end

local function total_inflight(dict, base, c, t, current_value)
    local seconds, span = slot_settings(c)
    local current = math.floor(t / seconds)
    local total = 0
    for bucket = current - span + 1, current do
        if bucket == current and current_value ~= nil then
            total = total + current_value
        else
            total = total + (tonumber(dict:get(slot_key(base, bucket))) or 0)
        end
    end
    return total
end

local function modes(spec)
    local rate = type(spec.rate) == "table" and spec.rate or {}
    local inflight = type(spec.inflight) == "table" and spec.inflight or {}
    return tostring(rate.mode or "off"),
           tostring(inflight.mode or "off"),
           tostring(spec.shape_mode or "off"),
           tostring(spec.cross_host_mode or "off")
end

local function cause_state(ctx, spec, short_n, long_n, inflight_n)
    local rate_mode, inflight_mode, shape_mode, cross_mode = modes(spec)
    local causes, enforced = {}, {}
    local function add(name, mode)
        if mode == "off" then return end
        causes[#causes + 1] = name
        if mode == "enforce" then enforced[#enforced + 1] = name end
    end

    local shape = tostring(ctx.endpoint_shape or "ok")
    if shape ~= "ok" and shape ~= "scan" then add("shape_" .. shape, shape_mode) end
    if ctx.endpoint_url_relation == "cross" then add("cross_host", cross_mode) end

    local inflight = type(spec.inflight) == "table" and spec.inflight or {}
    local limit = tonumber(inflight.limit)
    if limit and limit > 0 and inflight_n > limit then add("inflight", inflight_mode) end

    local rate = type(spec.rate) == "table" and spec.rate or {}
    local short_limit, long_limit = tonumber(rate.short), tonumber(rate.long)
    if short_limit and short_limit > 0 and short_n > short_limit then
        add("rate_short", rate_mode)
    end
    if long_limit and long_limit > 0 and long_n > long_limit then
        add("rate_long", rate_mode)
    end

    return causes, #enforced > 0, enforced
end

local function observed_mode(spec, causes)
    if #causes == 0 then
        local rate, inflight, shape, cross = modes(spec)
        if rate == "enforce" or inflight == "enforce"
           or shape == "enforce" or cross == "enforce" then return "enforce" end
        if rate == "shadow" or inflight == "shadow"
           or shape == "shadow" or cross == "shadow" then return "shadow" end
        return "off"
    end
    local rate, inflight, shape, cross = modes(spec)
    for i = 1, #causes do
        local cause = causes[i]
        if (cause == "inflight" and inflight == "enforce")
           or (cause:find("^rate_") and rate == "enforce")
           or (cause:find("^shape_") and shape == "enforce")
           or (cause == "cross_host" and cross == "enforce") then
            return "enforce"
        end
    end
    return "shadow"
end

local function reject(ctx, c, enforced_causes)
    local joined = table.concat(enforced_causes, ",")
    local status = tonumber(c.rate_status) or 429
    for i = 1, #enforced_causes do
        if enforced_causes[i] == "inflight" then
            status = tonumber(c.inflight_status) or 503
            break
        elseif enforced_causes[i]:find("^shape_") then
            status = tonumber(c.shape_status) or 400
        end
    end

    ctx.endpoint_rejected = true
    ctx.action = "throttled"
    ctx.action_reason = "endpoint_guard:" .. tostring(ctx.endpoint_id)
        .. ":" .. joined
    ngx.header["Retry-After"] = tostring(c.retry_after or 2)
    ngx.status = status
    ngx.say(status == 503 and "Service temporarily unavailable."
        or (status == 400 and "Bad request." or "Too many requests."))
    ngx.exit(status)
    return false, true
end

-- Early read-only gate.  It only acts after a rule is explicitly promoted to
-- enforce.  The late atomic gate in admit() remains authoritative for races.
function _M.before(ctx)
    local spec, c = endpoint_spec(ctx)
    if not spec or ngx.is_subrequest then return true, false end

    local dict = dictionary()
    if not dict then
        ctx.endpoint_degraded = true
        return true, false
    end
    local t, base = now(), base_key(ctx)
    local short_s, long_s = window_settings(c)
    local short_n = tonumber(dict:get(rate_key(base, "s", short_s, t))) or 0
    local long_n = tonumber(dict:get(rate_key(base, "l", long_s, t))) or 0
    local inflight_n = total_inflight(dict, base, c, t)

    local rate = type(spec.rate) == "table" and spec.rate or {}
    local inflight = type(spec.inflight) == "table" and spec.inflight or {}
    ctx.endpoint_short_count = short_n + 1
    ctx.endpoint_long_count = long_n + 1
    ctx.endpoint_short_limit = tonumber(rate.short) or 0
    ctx.endpoint_long_limit = tonumber(rate.long) or 0
    ctx.endpoint_inflight = inflight_n + 1
    ctx.endpoint_inflight_limit = tonumber(inflight.limit) or 0

    -- cause_state uses `>` because this request is not counted yet.  Supply
    -- +1 to ask whether admitting it would cross the configured boundary.
    local causes, enforce, enforced_causes = cause_state(
        ctx, spec, short_n + 1, long_n + 1, inflight_n + 1)
    if enforce then
        ctx.endpoint_would_reject = true
        ctx.endpoint_cause = table.concat(causes, ",")
        ctx.endpoint_mode = observed_mode(spec, causes)
        return reject(ctx, c, enforced_causes)
    end
    return true, false
end

-- Count only a request that survived WAF/antibot and is about to reach the
-- backend.  Local blocks therefore cannot consume a tenant endpoint budget.
function _M.admit(ctx)
    local spec, c = endpoint_spec(ctx)
    if not spec or ngx.is_subrequest then return true, false end
    if ctx.endpoint_admitted and not ctx.endpoint_released then return true, false end

    local dict = dictionary()
    if not dict then
        ctx.endpoint_degraded = true
        return true, false
    end

    local t, base = now(), base_key(ctx)
    local short_s, long_s = window_settings(c)
    local rate = type(spec.rate) == "table" and spec.rate or {}
    local short_key = rate_key(base, "s", short_s, t)
    local long_key = rate_key(base, "l", long_s, t)
    local short_n, short_err = increment(dict, short_key, short_s + 2)
    local long_n, long_err = increment(dict, long_key, long_s + 2)
    if not short_n or not long_n then
        ctx.endpoint_degraded = true
        log_dict_error("rate", short_err or long_err)
        return true, false
    end
    if short_err or long_err then
        ctx.endpoint_degraded = true
        log_dict_error("rate_ttl", short_err or long_err)
    end

    local bucket_s, _, slot_ttl = slot_settings(c)
    local bucket = math.floor(t / bucket_s)
    local request_slot_key = slot_key(base, bucket)
    local bucket_n, slot_err = increment(dict, request_slot_key, slot_ttl)
    if not bucket_n then
        ctx.endpoint_degraded = true
        log_dict_error("slot", slot_err)
        return true, false
    end
    if slot_err then
        ctx.endpoint_degraded = true
        log_dict_error("slot_ttl", slot_err)
    end

    local inflight_n = total_inflight(dict, base, c, t, bucket_n)
    local short_limit = tonumber(rate.short) or 0
    local long_limit = tonumber(rate.long) or 0
    local inflight_cfg = type(spec.inflight) == "table" and spec.inflight or {}
    local inflight_limit = tonumber(inflight_cfg.limit) or 0

    ctx.endpoint_admitted = true
    ctx.endpoint_released = false
    ctx.endpoint_admit_at = t
    ctx.endpoint_slot_key = request_slot_key
    ctx.endpoint_base_key = base
    ctx.endpoint_short_count = short_n
    ctx.endpoint_long_count = long_n
    ctx.endpoint_short_limit = short_limit
    ctx.endpoint_long_limit = long_limit
    ctx.endpoint_inflight = inflight_n
    ctx.endpoint_inflight_limit = inflight_limit

    local causes, enforce, enforced_causes = cause_state(
        ctx, spec, short_n, long_n, inflight_n)
    ctx.endpoint_mode = observed_mode(spec, causes)
    if #causes > 0 then
        ctx.endpoint_would_reject = true
        ctx.endpoint_cause = table.concat(causes, ",")
    end

    if enforce then
        decrement(dict, request_slot_key, slot_ttl)
        ctx.endpoint_released = true
        ctx.endpoint_admitted = false
        return reject(ctx, c, enforced_causes)
    end
    return true, false
end

local function max_upstream_time(raw)
    if not raw or raw == "" or raw == "-" then return nil end
    local maximum
    for token in tostring(raw):gmatch("%d+%.?%d*") do
        local value = tonumber(token)
        if value and (not maximum or value > maximum) then maximum = value end
    end
    return maximum
end

function _M.after(ctx)
    if not ctx or not ctx.endpoint_id then return end
    ctx.endpoint_actual_status = ngx.status
    ctx.endpoint_actual_upstream_status = ngx.var.upstream_status
    ctx.endpoint_upstream_time = max_upstream_time(ngx.var.upstream_response_time)

    if not ctx.endpoint_admitted or ctx.endpoint_released then return end
    ctx.endpoint_released = true

    local _, c = endpoint_spec(ctx)
    local dict = dictionary()
    if not dict then
        ctx.endpoint_degraded = true
        return
    end
    local _, _, ttl, retention = slot_settings(c)
    local t = now()
    ctx.endpoint_duration = math.max(t - (tonumber(ctx.endpoint_admit_at) or t), 0)
    if ctx.endpoint_duration > retention then ctx.endpoint_slot_expired = true end

    local _, err = decrement(dict, ctx.endpoint_slot_key or "", ttl)
    if err == "not found" then
        ctx.endpoint_slot_expired = true
    elseif err then
        ctx.endpoint_degraded = true
        log_dict_error("release", err)
    end
end

return _M
