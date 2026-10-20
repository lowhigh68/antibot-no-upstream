-- Generic dynamic-backend guard.
--
-- This module deliberately knows nothing about WordPress, plugins, endpoint
-- names or attack strings.  It protects four bounded behavioural axes:
--
--   1. live dynamic requests from one (docroot, source IP);
--   2. live dynamic requests from one source IP across the whole server;
--   3. many distinct dynamic paths from one (docroot, source IP), reinforced
--      by completed expensive responses;
--   4. completed upstream work per docroot and wall-clock window.
--
-- Slots are acquired only at the last common point before content/upstream and
-- released in log phase.  Static hits, subrequests and local WAF/ban/challenge
-- exits therefore never become backend occupancy.  All uncertain decisions
-- fail open.  Capacity is not reputation: this module never writes a ban or a
-- score.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.dynamic_guard or {}
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function dictionary()
    return ngx.shared and ngx.shared.antibot_cache
end

local function stat(name)
    local stats = ngx.shared and ngx.shared.antibot_stats
    if not stats then return end
    local key = "dynamic_guard:" .. name
    if not stats:incr(key, 1) then stats:add(key, 1, 86400) end
end

local function log_dict_error(where, err)
    stat("dicterr")
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[dynamic_guard] shared-dict error at ", where,
            ": ", tostring(err or "unknown"), " (fail-open)")
    end
end

local function digest(value)
    value = tostring(value or "")
    if ngx.md5 then return ngx.md5(value):sub(1, 16) end
    return value:gsub("[^%w_.-]", "_"):sub(1, 64)
end

local function dynamic_request(ctx)
    if not ctx or ngx.is_subrequest then return false end
    if ctx.admission_group ~= nil then
        return ctx.admission_group == "dynamic"
    end
    -- Admission normally owns the static-hit/static-miss distinction.  If it
    -- is disabled, never guess an unknown resource into a capacity verdict.
    return ctx.req_class ~= nil and ctx.req_class ~= "resource"
end

local function scope_id()
    local root = tostring(ngx.var.document_root or "")
    root = root:gsub("\\", "/"):gsub("/+$", ""):lower()
    if root ~= "" then return digest("root:" .. root) end
    -- server_name is selected by Nginx and has bounded fleet cardinality.  Raw
    -- Host is intentionally not used as a shared-dict key source.
    local host = tostring(ngx.var.server_name or "unknown"):lower()
    return digest("vhost:" .. host)
end

local function source_id(ctx)
    local ip = tostring((ctx and ctx.ip) or ngx.var.remote_addr or "")
    if ip == "" or ip == "-" then return nil end
    return digest(ip)
end

local function delete_key(dict, key)
    if dict.delete then return dict:delete(key) end
    return dict:set(key, nil)
end

local function increment(dict, key, delta, ttl)
    delta = delta or 1
    local value, err = dict:incr(key, delta)
    if not value then
        if err ~= "not found" then return nil, err end
        local added, add_err = dict:add(key, delta, ttl)
        if added then
            value = delta
        elseif add_err == "exists" then
            value, err = dict:incr(key, delta)
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

local function slot_settings(c)
    local seconds = math.max(math.floor(
        tonumber(c.slot_bucket_seconds) or 30), 1)
    local retention = math.max(math.floor(
        tonumber(c.slot_retention_seconds) or 180), seconds)
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

local function acquire(dict, base, axis, limit, c, t)
    local seconds, _, ttl = slot_settings(c)
    local key = slot_key(base, math.floor(t / seconds))
    local bucket_n, err = increment(dict, key, 1, ttl)
    if not bucket_n then return nil, err end
    return {
        axis = axis, key = key, base = base, limit = limit,
        count = total_inflight(dict, base, c, t, bucket_n),
    }, err
end

local function axis_config(c, name, default_limit)
    local spec = type(c[name]) == "table" and c[name] or {}
    local mode = tostring(spec.mode or c.mode or "shadow")
    local limit = math.max(math.floor(
        tonumber(spec.limit) or default_limit), 0)
    return spec, mode, limit
end

local function path_shard(uri, shards)
    local hex = digest(uri)
    local n = tonumber(hex:sub(1, 8), 16)
    if not n and ngx.crc32_short then n = ngx.crc32_short(uri) end
    n = tonumber(n) or 0
    return n % shards
end

local function observe_paths(dict, ctx, c, scope, source, t)
    local spec = type(c.path_spray) == "table" and c.path_spray or {}
    local mode = tostring(spec.mode or "off")
    ctx.dynamic_path_mode = mode
    if mode == "off" then return false end

    local window = math.max(math.floor(tonumber(spec.window) or 10), 1)
    local bucket = math.floor(t / window)
    local ttl = window * 2 + 2
    local base = "dg:path:" .. scope .. ":" .. source .. ":"
        .. tostring(bucket)
    local hits, hit_err = increment(dict, base .. ":hits", 1, ttl)
    if not hits then
        ctx.dynamic_guard_degraded = true
        log_dict_error("path_hits", hit_err)
        return false
    end

    local shards = math.max(math.min(math.floor(
        tonumber(spec.shards) or 32), 64), 8)
    local uri = tostring(ngx.var.uri or (ctx.req and ctx.req.uri) or "/")
    local shard = path_shard(uri, shards)
    local distinct_key = base .. ":distinct"
    local distinct = tonumber(dict:get(distinct_key)) or 0
    if distinct < shards then
        local added, add_err = dict:add(
            base .. ":seen:" .. tostring(shard), 1, ttl)
        if added then
            local n, nerr = increment(dict, distinct_key, 1, ttl)
            if n then
                distinct = n
            else
                ctx.dynamic_guard_degraded = true
                log_dict_error("path_distinct", nerr)
            end
        elseif add_err ~= "exists" then
            ctx.dynamic_guard_degraded = true
            log_dict_error("path_seen", add_err)
        end
    end

    -- Cost is source/docroot scoped with an idle TTL rather than tied to the
    -- request-start bucket.  A request that takes longer than `window` seconds
    -- must still reinforce the next path; binding cost to its completion
    -- bucket would separate the two halves precisely for the expensive cases.
    local costly_key = "dg:path:" .. scope .. ":" .. source
        .. ":costly_recent"
    local costly = tonumber(dict:get(costly_key)) or 0
    local min_hits = math.max(math.floor(tonumber(spec.min_hits) or 12), 2)
    local min_paths = math.max(math.floor(tonumber(spec.min_paths) or 8), 2)
    local min_costly = math.max(math.floor(tonumber(spec.min_costly) or 2), 1)
    ctx.dynamic_path_hits = hits
    ctx.dynamic_path_distinct = distinct
    ctx.dynamic_path_costly = costly
    ctx.dynamic_path_hit_limit = min_hits
    ctx.dynamic_path_distinct_limit = min_paths
    ctx.dynamic_path_costly_limit = min_costly
    ctx.dynamic_path_cost_key = costly_key
    local candidate = hits >= min_hits and distinct >= min_paths
        and costly >= min_costly
    ctx.dynamic_path_candidate = candidate
    return candidate
end

-- A request-target is one URI.  A second absolute HTTP target serialized into
-- its path after whitespace/comma is a protocol-shape anomaly independent of
-- CMS, extension, locale or today's attack token.  Decode only structural
-- bytes, at most twice; never perform a general URI decode or retain the value.
local function observe_uri_integrity(ctx, c)
    local spec = type(c.uri_integrity) == "table" and c.uri_integrity or {}
    local mode = tostring(spec.mode or "off")
    ctx.dynamic_uri_mode = mode
    if mode == "off" then return false, mode end

    local raw = tostring(ngx.var.request_uri
        or ngx.var.uri or (ctx.req and ctx.req.uri) or "/")
    raw = raw:match("^([^?]*)") or raw
    local value = raw:lower()
    local function structural_decode(s)
        return (s:gsub("%%(%x%x)", function(hex)
            local n = tonumber(hex, 16)
            if n == 0x09 or n == 0x0a or n == 0x0d or n == 0x20
               or n == 0x2c or n == 0x2f or n == 0x3a
               or n == 0x25 then
                return string.char(n)
            end
            return "%" .. hex
        end))
    end
    value = structural_decode(structural_decode(value))
    local invalid = value:find("[%s,]https?://") ~= nil
    if invalid then
        ctx.dynamic_uri_shape = "second_absolute_target"
    else
        ctx.dynamic_uri_shape = "ok"
    end
    return invalid, mode
end

local function pressure_config(c)
    local spec = type(c.pressure) == "table" and c.pressure or {}
    return spec, tostring(spec.mode or "off")
end

local function pressure_keys(scope)
    return "dg:pressure:" .. scope
end

local function read_pressure(dict, ctx, c, scope, t, acquire_probe)
    local spec, mode = pressure_config(c)
    ctx.dynamic_pressure_mode = mode
    ctx.dynamic_pressure_policy = tostring(spec.policy or "blanket")
    if mode == "off" then return false end
    local base = pressure_keys(scope)
    local until_at = tonumber(dict:get(base .. ":open_until"))
    if not until_at then return false end

    if t < until_at then
        ctx.dynamic_pressure_open = true
        ctx.dynamic_pressure_until = until_at
        ctx.dynamic_pressure_would_reject = true
        return true
    end

    -- Do not elect the half-open probe in the early hook: that request may
    -- still be terminated by WAF/ban/challenge and would then hold the only
    -- probe lease without ever touching upstream.  Late-admit is the atomic
    -- authority; early access merely marks the state as half-open.
    if not acquire_probe then
        ctx.dynamic_pressure_open = true
        ctx.dynamic_pressure_until = until_at
        ctx.dynamic_pressure_half_open = true
        return false
    end

    -- Exactly one late-admitted request probes after the hold interval. Others
    -- remain candidates until that request completes or the lease expires.
    local probe_ttl = math.max(tonumber(spec.probe_timeout) or 10, 1)
    local acquired, err = dict:add(base .. ":probe", 1, probe_ttl)
    if acquired then
        ctx.dynamic_pressure_probe = true
        ctx.dynamic_pressure_half_open = false
        ctx.dynamic_pressure_open = true
        ctx.dynamic_pressure_until = until_at
        return false
    end
    if err ~= "exists" then
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_probe", err)
        return false
    end
    ctx.dynamic_pressure_open = true
    ctx.dynamic_pressure_until = until_at
    ctx.dynamic_pressure_would_reject = true
    return true
end

local function pressure_automation(ctx)
    return ctx.automation_observed == true
        or ctx.automation_claimed == true
        or ctx.automation_meter_claimed == true
        or ctx.good_bot_claimed == true
        or ctx.good_bot_verified == true
end

-- Pressure is a capacity verdict, not a reputation verdict.  Once a docroot
-- is open, shed the traffic least likely to represent an active human first;
-- never turn a Cookie header by itself into trust.  Human/stateful traffic is
-- bounded by a small live reserve, so it can make progress without defeating
-- the breaker.  The reserve uses the same crash-bounded slot primitive as the
-- other concurrency axes and is released in log phase.
local function pressure_select(dict, ctx, c, scope, t, slots)
    if not ctx.dynamic_pressure_would_reject then
        if ctx.dynamic_pressure_probe then
            ctx.dynamic_pressure_disposition = "probe"
        end
        return false
    end

    local spec = type(c.pressure) == "table" and c.pressure or {}
    local policy = tostring(spec.policy or "blanket")
    ctx.dynamic_pressure_policy = policy

    if policy ~= "selective" then
        ctx.dynamic_pressure_disposition = "shed_all"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    -- Explicit operator policy (including internal callbacks) wins over the
    -- overload ranker.  This is deliberately narrower than any Cookie claim.
    if ctx.whitelisted == true then
        ctx.dynamic_pressure_disposition = "keep_whitelist"
        return false
    end

    -- Verified crawlers are legitimate identities, but they are still
    -- automation and must yield while a tenant is consuming extreme backend
    -- work.  No vendor/principal name is needed here.
    if pressure_automation(ctx) then
        ctx.dynamic_pressure_disposition = "shed_automation"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    local verified = ctx.verified == true
    local richness = tonumber(ctx.session_richness_own) or 0
    local first_party = ctx.session_cookie_known == true
        and richness >= (tonumber(spec.first_party_richness) or 0.5)
    if not verified and not first_party then
        ctx.dynamic_pressure_disposition = "shed_untrusted"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    local reserve = math.max(math.floor(
        tonumber(spec.first_party_reserve) or 4), 0)
    ctx.dynamic_pressure_reserve_limit = reserve
    if reserve <= 0 then
        ctx.dynamic_pressure_disposition = "shed_reserve"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    local slot, err = acquire(dict, pressure_keys(scope) .. ":priority",
        "pressure_reserve", reserve, c, t)
    if not slot then
        -- An uncertain capacity read must not lock out an authenticated user.
        ctx.dynamic_guard_degraded = true
        ctx.dynamic_pressure_degraded = true
        ctx.dynamic_pressure_disposition = "keep_degraded"
        log_dict_error("pressure_reserve", err)
        return false
    end
    slots[#slots + 1] = slot
    ctx.dynamic_pressure_reserve_inflight = slot.count
    if err then
        ctx.dynamic_guard_degraded = true
        ctx.dynamic_pressure_degraded = true
        ctx.dynamic_pressure_disposition = "keep_degraded"
        log_dict_error("pressure_reserve_ttl", err)
        return false
    end
    if slot.count > reserve then
        ctx.dynamic_pressure_disposition = "shed_reserve"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    ctx.dynamic_pressure_disposition = verified
        and "keep_verified" or "keep_first_party"
    return false
end

local function reject(ctx, c, cause, status)
    status = tonumber(status) or tonumber(c.status) or 429
    ctx.dynamic_guard_rejected = true
    ctx.action = "throttled"
    ctx.action_reason = "dynamic_guard:" .. tostring(cause)
    if status == 429 or status == 503 then
        ngx.header["Retry-After"] = tostring(c.retry_after or 3)
    end
    ngx.header["Cache-Control"] = "no-store"
    ngx.status = status
    ngx.say(status == 503 and "Service temporarily unavailable."
        or (status == 400 and "Bad request."
        or "Too many dynamic requests. Please retry later."))
    ngx.exit(status)
    return false, true
end

function _M.before(ctx)
    local c = conf()
    if not c.enabled or tostring(c.mode or "off") == "off"
       or not dynamic_request(ctx) then return true, false end

    local dict = dictionary()
    if not dict then
        ctx.dynamic_guard_degraded = true
        return true, false
    end
    local scope = scope_id()
    ctx.dynamic_guard_scope = scope
    -- Detection has not run yet, so this hook cannot distinguish automation,
    -- a verified human or a first-party session.  It only exposes breaker
    -- state; late-admit is the sole authority for selective shedding.
    read_pressure(dict, ctx, c, scope, now(), false)
    return true, false
end

function _M.admit(ctx)
    local c = conf()
    if not c.enabled or tostring(c.mode or "off") == "off"
       or not dynamic_request(ctx) then return true, false end
    if ctx.dynamic_guard_admitted and not ctx.dynamic_guard_released then
        return true, false
    end

    local source = source_id(ctx)
    if not source then return true, false end
    local dict = dictionary()
    if not dict then
        ctx.dynamic_guard_degraded = true
        return true, false
    end

    local t = now()
    local scope = ctx.dynamic_guard_scope or scope_id()
    ctx.dynamic_guard_scope = scope
    local _, tenant_mode, tenant_limit =
        axis_config(c, "tenant_client", 8)
    local _, server_mode, server_limit =
        axis_config(c, "server_client", 16)
    ctx.dynamic_guard_mode = tostring(c.mode or "shadow")
    ctx.dynamic_tenant_mode = tenant_mode
    ctx.dynamic_server_mode = server_mode
    ctx.dynamic_tenant_limit = tenant_limit
    ctx.dynamic_server_limit = server_limit

    local slots = {}
    local degraded = false
    local tenant_slot, server_slot, err
    if tenant_mode ~= "off" and tenant_limit > 0 then
        tenant_slot, err = acquire(dict,
            "dg:tenant:" .. scope .. ":" .. source,
            "tenant", tenant_limit, c, t)
        if not tenant_slot then
            ctx.dynamic_guard_degraded = true
            log_dict_error("tenant_admit", err)
            return true, false
        end
        slots[#slots + 1] = tenant_slot
        if err then degraded = true; log_dict_error("tenant_ttl", err) end
    end

    if server_mode ~= "off" and server_limit > 0 then
        server_slot, err = acquire(dict,
            "dg:server:" .. source, "server", server_limit, c, t)
        if not server_slot then
            -- A broken second axis must not leave a live first-axis slot.
            local _, _, ttl = slot_settings(c)
            for i = #slots, 1, -1 do decrement(dict, slots[i].key, ttl) end
            ctx.dynamic_guard_degraded = true
            log_dict_error("server_admit", err)
            return true, false
        end
        slots[#slots + 1] = server_slot
        if err then degraded = true; log_dict_error("server_ttl", err) end
    end

    ctx.dynamic_guard_admitted = true
    ctx.dynamic_guard_released = false
    ctx.dynamic_guard_admit_at = t
    ctx.dynamic_guard_slots = slots
    ctx.dynamic_guard_source = source
    ctx.dynamic_tenant_inflight = tenant_slot and tenant_slot.count or nil
    ctx.dynamic_server_inflight = server_slot and server_slot.count or nil
    if degraded then ctx.dynamic_guard_degraded = true end

    local causes, enforced = {}, {}
    local function add(name, mode)
        causes[#causes + 1] = name
        if mode == "enforce" then enforced[#enforced + 1] = name end
    end
    if tenant_slot and tenant_slot.count > tenant_limit then
        add("tenant_concurrency", tenant_mode)
    end
    if server_slot and server_slot.count > server_limit then
        add("server_concurrency", server_mode)
    end

    local spray = observe_paths(dict, ctx, c, scope, source, t)
    local spray_spec = type(c.path_spray) == "table" and c.path_spray or {}
    local spray_mode = tostring(spray_spec.mode or "off")
    if spray then add("path_spray", spray_mode) end

    local uri_invalid, uri_mode = observe_uri_integrity(ctx, c)
    if uri_invalid then add("uri_integrity", uri_mode) end

    -- before() normally populated this.  Keep admit independently correct for
    -- verified/whitelist/test call sites that invoke only the late hook.
    if ctx.dynamic_pressure_open == nil or ctx.dynamic_pressure_half_open then
        read_pressure(dict, ctx, c, scope, t, true)
    end
    local _, pressure_mode = pressure_config(c)
    local pressure_shed = pressure_select(
        dict, ctx, c, scope, t, slots)
    if pressure_shed then
        add("pressure", pressure_mode)
    end

    if #causes > 0 then
        ctx.dynamic_guard_would_reject = true
        ctx.dynamic_guard_cause = table.concat(causes, ",")
    end

    if #enforced > 0 and not ctx.dynamic_guard_degraded then
        local _, _, ttl = slot_settings(c)
        for i = #slots, 1, -1 do decrement(dict, slots[i].key, ttl) end
        ctx.dynamic_guard_released = true
        ctx.dynamic_guard_admitted = false
        local cause = enforced[1]
        if cause == "pressure" then
            ctx.dynamic_pressure_selective_rejected = true
        end
        local status = cause == "pressure"
            and ((type(c.pressure) == "table" and c.pressure.status) or 503)
            or (cause == "path_spray" and spray_spec.status or nil)
        if cause == "uri_integrity" then
            local uri_spec = type(c.uri_integrity) == "table"
                and c.uri_integrity or {}
            status = tonumber(uri_spec.status) or 400
        end
        return reject(ctx, c, cause, status)
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

local function record_path_cost(dict, ctx, c, up, t)
    if not ctx.dynamic_guard_source or not ctx.dynamic_guard_scope then return end
    local spec = type(c.path_spray) == "table" and c.path_spray or {}
    if tostring(spec.mode or "off") == "off" then return end
    local costly_seconds = tonumber(spec.costly_seconds) or 2.0
    if not up or up < costly_seconds then return end
    local window = math.max(math.floor(tonumber(spec.window) or 10), 1)
    local ttl = window + 2
    local key = ctx.dynamic_path_cost_key or ("dg:path:"
        .. ctx.dynamic_guard_scope .. ":" .. ctx.dynamic_guard_source
        .. ":costly_recent")
    local _, err = increment(dict, key, 1, ttl)
    if err then
        ctx.dynamic_guard_degraded = true
        log_dict_error("path_cost", err)
    end
end

local function pressure_bucket(base, second, suffix)
    return base .. ":b:" .. tostring(second) .. ":" .. suffix
end

local function open_pressure(dict, ctx, spec, base, t, work, samples, slow)
    local hold = math.max(tonumber(spec.hold_seconds) or 20, 1)
    local probe = math.max(tonumber(spec.probe_timeout) or 10, 1)
    local until_at = t + hold
    local ok, err = dict:set(base .. ":open_until", until_at,
        hold + probe + 5)
    if not ok then
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_open", err)
        return
    end
    delete_key(dict, base .. ":probe")
    ctx.dynamic_pressure_open = true
    ctx.dynamic_pressure_until = until_at
    ctx.dynamic_pressure_transition = "open"
    ctx.dynamic_pressure_work = work
    ctx.dynamic_pressure_samples = samples
    ctx.dynamic_pressure_slow = slow
    stat("pressure_open")
end

local function record_pressure(dict, ctx, c, up, t)
    local spec, mode = pressure_config(c)
    if mode == "off" or not up then return end
    local scope = ctx.dynamic_guard_scope
    if not scope then return end
    local base = pressure_keys(scope)
    local second = math.floor(t)
    local window = math.max(math.floor(tonumber(spec.window) or 10), 2)
    local ttl = window * 3 + 5
    local slow_seconds = tonumber(spec.slow_seconds) or 2.5

    local _, nerr = increment(dict,
        pressure_bucket(base, second, "n"), 1, ttl)
    local _, werr = increment(dict,
        pressure_bucket(base, second, "work"), up, ttl)
    local serr
    if up >= slow_seconds then
        _, serr = increment(dict,
            pressure_bucket(base, second, "slow"), 1, ttl)
    end
    if nerr or werr or serr then
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_record", nerr or werr or serr)
        return
    end

    -- Probe result is direct evidence and must be handled before aggregate
    -- window evaluation.  A fast completion closes; a slow completion reopens.
    if ctx.dynamic_pressure_probe then
        delete_key(dict, base .. ":probe")
        if up < slow_seconds then
            delete_key(dict, base .. ":open_until")
            local recovery = math.max(tonumber(spec.recovery_seconds) or 5, 1)
            dict:set(base .. ":recovery", 1, recovery)
            ctx.dynamic_pressure_open = false
            ctx.dynamic_pressure_transition = "close"
            stat("pressure_close")
            return
        end
    end

    if dict:get(base .. ":recovery") then return end
    local interval = math.max(tonumber(spec.eval_interval) or 1, 0.1)
    local elected, elect_err = dict:add(base .. ":eval:"
        .. tostring(math.floor(t / interval)), 1, interval + 1)
    if not elected then
        if elect_err ~= "exists" then
            ctx.dynamic_guard_degraded = true
            log_dict_error("pressure_elect", elect_err)
        end
        return
    end

    local samples, work, slow = 0, 0, 0
    for s = second - window + 1, second do
        samples = samples + (tonumber(dict:get(
            pressure_bucket(base, s, "n"))) or 0)
        work = work + (tonumber(dict:get(
            pressure_bucket(base, s, "work"))) or 0)
        slow = slow + (tonumber(dict:get(
            pressure_bucket(base, s, "slow"))) or 0)
    end
    ctx.dynamic_pressure_samples = samples
    ctx.dynamic_pressure_work = work
    ctx.dynamic_pressure_slow = slow
    ctx.dynamic_pressure_evaluated = true

    local min_samples = math.max(math.floor(
        tonumber(spec.min_samples) or 5), 1)
    local work_limit = math.max(tonumber(spec.work_seconds) or 15, 0.1)
    -- Freshness is non-negotiable: the response completing this evaluation
    -- must itself be slow.  Old expensive work left in the rolling window may
    -- support a decision but can never open a recovered docroot by itself.
    local candidate = samples >= min_samples and work >= work_limit
        and up >= slow_seconds
    ctx.dynamic_pressure_candidate = candidate
    if candidate then
        open_pressure(dict, ctx, spec, base, t, work, samples, slow)
    end
end

function _M.after(ctx)
    if not ctx or not ctx.dynamic_guard_scope then return end
    local c = conf()
    local dict = dictionary()
    if not dict then
        ctx.dynamic_guard_degraded = true
        return
    end

    local t = now()
    local up = max_upstream_time(ngx.var.upstream_response_time)
    local upstream = ngx.var.upstream_status
    ctx.dynamic_guard_actual_status = ngx.status
    ctx.dynamic_guard_upstream_status = upstream
    ctx.dynamic_guard_upstream_time = up

    if ctx.dynamic_guard_admitted and not ctx.dynamic_guard_released then
        ctx.dynamic_guard_released = true
        local _, _, ttl, retention = slot_settings(c)
        ctx.dynamic_guard_duration = math.max(
            t - (tonumber(ctx.dynamic_guard_admit_at) or t), 0)
        if ctx.dynamic_guard_duration > retention then
            ctx.dynamic_guard_slot_expired = true
        end
        local slots = ctx.dynamic_guard_slots or {}
        for i = #slots, 1, -1 do
            local slot = slots[i]
            local remaining, err = decrement(dict, slot.key or "", ttl)
            if err == "not found" then
                ctx.dynamic_guard_slot_expired = true
            elseif err then
                ctx.dynamic_guard_degraded = true
                log_dict_error("release_" .. tostring(slot.axis), err)
            elseif slot.axis == "tenant" then
                ctx.dynamic_tenant_remaining = remaining
            elseif slot.axis == "server" then
                ctx.dynamic_server_remaining = remaining
            elseif slot.axis == "pressure_reserve" then
                ctx.dynamic_pressure_reserve_remaining = remaining
            end
        end
    end

    -- Only completed upstream work teaches cost.  Local 4xx/429/503 responses
    -- never poison the pressure or expensive-path evidence.
    if not ctx.dynamic_guard_outcome_recorded
       and upstream and upstream ~= "" and upstream ~= "-" and up then
        ctx.dynamic_guard_outcome_recorded = true
        record_path_cost(dict, ctx, c, up, t)
        record_pressure(dict, ctx, c, up, t)
    end
end

return _M
