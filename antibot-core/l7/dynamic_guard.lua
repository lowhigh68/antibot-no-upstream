-- Generic dynamic-backend guard.
--
-- This module deliberately knows nothing about WordPress, plugins, endpoint
-- names or attack strings.  It protects four bounded behavioural axes:
--
--   1. live dynamic requests from one (docroot, source IP);
--   2. live dynamic requests from one source IP across the whole server;
--   3. many distinct dynamic paths from one (docroot, source IP), reinforced
--      by completed expensive responses;
--   4. completed upstream work per docroot and wall-clock window;
--   5. whole-node completed work with evidence-bound selective shedding;
--   6. client-aborted upstream work as telemetry only.
--
-- Slots are acquired only at the last common point before content/upstream and
-- released in log phase.  Static hits, subrequests and local WAF/ban/challenge
-- exits therefore never become backend occupancy.  All uncertain decisions
-- fail open.  Capacity is not reputation: this module never writes a ban or a
-- score.

local _M  = {}
local cfg = require "antibot.core.config"
local policy = require "antibot.core.policy"
local decision = require "antibot.core.decision"

local last_dict_error = 0

local function conf(ctx)
    return policy.section(ctx, "dynamic_guard", cfg.dynamic_guard or {})
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

local function server_pressure_config(c)
    local spec = type(c.server_pressure) == "table"
        and c.server_pressure or {}
    return spec, tostring(spec.mode or "off")
end

local function aborted_pressure_config(c)
    local spec = type(c.aborted_pressure) == "table"
        and c.aborted_pressure or {}
    return spec, spec.enabled == true
end

local function pressure_keys(scope)
    return "dg:pressure:" .. scope
end

local function server_pressure_keys()
    return "dg:server_pressure"
end

local function aborted_pressure_keys(scope)
    return "dg:aborted:" .. scope
end

local function read_pressure(dict, ctx, c, scope, t, _acquire_probe)
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

    -- Cohort identity does not exist in the early hook.  Late-admit elects a
    -- probe per contributing cohort; a global probe would let one unrelated
    -- request decide recovery for every traffic family on the docroot.
    ctx.dynamic_pressure_open = true
    ctx.dynamic_pressure_until = until_at
    ctx.dynamic_pressure_half_open = true
    return false
end

local function read_server_pressure(dict, ctx, c, t)
    local spec, mode = server_pressure_config(c)
    ctx.dynamic_server_pressure_mode = mode
    ctx.dynamic_server_pressure_policy = tostring(spec.policy or "cohort")
    if mode == "off" then return false end
    local until_at = tonumber(dict:get(
        server_pressure_keys() .. ":open_until"))
    if not until_at or t >= until_at then
        ctx.dynamic_server_pressure_open = false
        return false
    end
    ctx.dynamic_server_pressure_open = true
    ctx.dynamic_server_pressure_until = until_at
    return true
end

local function pressure_automation(ctx)
    return ctx.automation_observed == true
        or ctx.automation_claimed == true
        or ctx.automation_meter_claimed == true
        or ctx.good_bot_claimed == true
        or ctx.good_bot_verified == true
end

local function length_bucket(n)
    if n <= 3 then return "s" end
    if n <= 8 then return "m" end
    if n <= 16 then return "l" end
    return "x"
end

local function segment_shape(segment)
    local value = tostring(segment or ""):lower()
    local ext = value:match("%.([%w]+)$")
    if ext and #ext > 8 then ext = "long" end
    local core = ext and value:sub(1, #value - #ext - 1) or value
    local kind
    if core:match("^%d+$") then
        kind = "n"
    elseif core:match("^%x+$") and core:match("%d") then
        kind = "h"
    elseif core:match("^[a-z]+$") then
        kind = "a"
    elseif core:match("^[a-z0-9_-]+$") then
        kind = "w"
    else
        kind = "m"
    end
    return kind .. length_bucket(#core) .. "." .. tostring(ext or "-")
end

local function query_shape(ctx)
    local args = ngx.var.args
    if args == nil then
        args = tostring((ctx.req and ctx.req.uri) or ""):match("%?(.*)$")
    end
    if not args or args == "" then return "-" end
    local keys, overflow = {}, false
    for field in tostring(args):gmatch("[^&;]+") do
        local key = (field:match("^([^=]+)") or ""):lower()
        key = key:gsub("%%[%x][%x]", "_"):gsub("[^%w_.-]", "_")
        if key ~= "" then
            if #keys < 8 then
                keys[#keys + 1] = key:sub(1, 32)
            else
                overflow = true
                break
            end
        end
    end
    table.sort(keys)
    return digest(table.concat(keys, ",") .. (overflow and ",+" or ""))
end

local function request_shape(ctx)
    local uri = tostring(ngx.var.uri
        or (ctx.req and ctx.req.uri) or "/")
    uri = (uri:match("^([^?]*)") or uri):lower()
    local parts, count = {}, 0
    for segment in uri:gmatch("[^/]+") do
        count = count + 1
        if #parts < 6 then parts[#parts + 1] = segment_shape(segment) end
    end
    if count > #parts then parts[#parts + 1] = "+" end
    if #parts == 0 then parts[1] = "root" end
    local method = tostring(ngx.var.request_method
        or (ctx.req and ctx.req.method) or "GET"):upper()
    return table.concat({
        method,
        tostring(ctx.req_class or "unknown"),
        tostring(ctx.admission_group or "dynamic"),
        table.concat(parts, "/"),
        query_shape(ctx),
    }, "|")
end

local function client_shape(ctx)
    local ja3 = tostring(ctx.ja3 or "")
    local transport
    if ja3 ~= "" and ja3 ~= "-" then
        transport = "j:" .. ja3
    else
        local ua = tostring(ctx.ua or ngx.var.http_user_agent or ""):lower()
        -- Browser patch/minor versions are churn, not new clients.  Keep the
        -- product grammar but erase numeric runs before hashing.
        ua = ua:gsub("%d+", "#"):sub(1, 192)
        transport = "u:" .. digest(ua)
    end
    return table.concat({
        tostring(ctx.device_type or "unknown"),
        transport,
        tostring((ctx.req and ctx.req.proto) or ngx.var.server_protocol or "-"),
    }, "|")
end

local function pressure_cohort(ctx)
    if ctx.dynamic_pressure_cohort_id then
        return ctx.dynamic_pressure_cohort_id,
               ctx.dynamic_pressure_cohort_kind
    end
    local kind, signature
    if pressure_automation(ctx) then
        -- Multiple crawler principals can jointly exhaust a tenant without
        -- any one principal crossing a rate limit.  They share the automation
        -- capacity lane, but only while that lane itself has measured work.
        kind, signature = "automation", "automation"
    else
        kind = "shape"
        signature = request_shape(ctx) .. "|" .. client_shape(ctx)
    end
    local id = digest("cohort:" .. kind .. ":" .. signature)
    ctx.dynamic_pressure_cohort_kind = kind
    ctx.dynamic_pressure_cohort_id = id
    return id, kind
end

local function pressure_cohort_base(base, id)
    return base .. ":c:" .. tostring(id)
end

-- Server-wide automation attribution must remain principal-specific.  The old
-- fixed-window server axis demonstrated why: one aggressive vendor made quiet
-- Claude/Perplexity traffic inherit its overload.  Weak self-claims share one
-- unverified lane; evidence-backed identities get independent lanes.
local function server_pressure_cohort(ctx)
    if ctx.dynamic_server_pressure_cohort_id then
        return ctx.dynamic_server_pressure_cohort_id,
               ctx.dynamic_server_pressure_cohort_kind
    end

    local kind, signature
    if pressure_automation(ctx) then
        kind = "automation"
        local principal = tostring(ctx.automation_principal
            or ctx.good_bot_name or ""):lower()
        local evidence_bound = ctx.good_bot_verified == true
            or (ctx.automation_tier == "operator"
                and ctx.operator_network_verified == true)
            or (ctx.automation_tier == "cloud_automation"
                and ctx.automation_proof == "contact_cloud_ptr")
        if evidence_bound and principal ~= "" and principal ~= "-" then
            signature = "principal:" .. principal
        else
            signature = "unverified_automation"
        end
    else
        kind = "shape"
        signature = request_shape(ctx) .. "|" .. client_shape(ctx)
    end

    local id = digest("server-cohort:" .. kind .. ":" .. signature)
    ctx.dynamic_server_pressure_cohort_kind = kind
    ctx.dynamic_server_pressure_cohort_id = id
    return id, kind
end

local function server_pressure_select(dict, ctx, c)
    local spec, mode = server_pressure_config(c)
    ctx.dynamic_server_pressure_mode = mode
    ctx.dynamic_server_pressure_policy = tostring(spec.policy or "cohort")
    if mode == "off" or not ctx.dynamic_server_pressure_open then return false end

    local id, kind = server_pressure_cohort(ctx)
    local base = server_pressure_keys()
    local cohort_base = pressure_cohort_base(base, id)
    local hot_work = tonumber(dict:get(cohort_base .. ":hot"))
    local hot_n = tonumber(dict:get(cohort_base .. ":hot_n"))
    local open_work = tonumber(dict:get(base .. ":open_work"))
    local min_share = math.max(math.min(
        tonumber(spec.cohort_min_share) or 0.15, 1), 0)
    local share = hot_work and open_work and open_work > 0
        and hot_work / open_work or 0
    local match = hot_work ~= nil and hot_n ~= nil
        and open_work ~= nil and share >= min_share

    ctx.dynamic_server_pressure_cohort_hot_work = hot_work
    ctx.dynamic_server_pressure_cohort_samples = hot_n
    ctx.dynamic_server_pressure_cohort_share = share
    ctx.dynamic_server_pressure_cohort_match = match
    ctx.dynamic_server_pressure_attributed = match

    if not match then
        ctx.dynamic_server_pressure_disposition = "keep_normal"
        return false
    end

    -- Server pressure can never spend a finite reserve belonging to an
    -- unrelated tenant.  Explicit policy and strong first-party state are
    -- unconditional keep paths on this cross-site axis.
    local richness = tonumber(ctx.session_richness_own) or 0
    local first_party = ctx.verified == true
        or (ctx.session_cookie_known == true
            and richness >= (tonumber(spec.first_party_richness) or 0.5))
    if ctx.whitelisted == true then
        ctx.dynamic_server_pressure_disposition = "keep_whitelist"
        return false
    end
    if first_party then
        ctx.dynamic_server_pressure_disposition = "keep_first_party"
        return false
    end

    ctx.dynamic_server_pressure_would_reject = true
    ctx.dynamic_server_pressure_selective_candidate = true
    ctx.dynamic_server_pressure_disposition = kind == "automation"
        and "shed_incident_automation" or "shed_incident_cohort"
    return true
end

-- Pressure detects an incident; measured cohort contribution decides who is
-- shed.  A docroot-wide overload is never authority to reject an unrelated
-- first visitor.  Cohorts contain no IP, raw URI, query value or CMS token.
local function pressure_select(dict, ctx, c, scope, t, slots)
    local spec = type(c.pressure) == "table" and c.pressure or {}
    local policy = tostring(spec.policy or "blanket")
    ctx.dynamic_pressure_policy = policy

    if not ctx.dynamic_pressure_open then return false end
    if policy == "blanket" and ctx.dynamic_pressure_would_reject then
        ctx.dynamic_pressure_disposition = "shed_all"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end
    if policy ~= "cohort" then
        ctx.dynamic_pressure_disposition = "keep_policy"
        return false
    end

    local id, kind = pressure_cohort(ctx)
    local base = pressure_keys(scope)
    local cohort_base = pressure_cohort_base(base, id)
    local hot_work = tonumber(dict:get(cohort_base .. ":hot"))
    local hot_n = tonumber(dict:get(cohort_base .. ":hot_n"))
    local open_work = tonumber(dict:get(base .. ":open_work"))
    local min_share = math.max(math.min(
        tonumber(spec.cohort_min_share) or 0.15, 1), 0)
    local share = hot_work and open_work and open_work > 0
        and (hot_work / open_work) or 0
    local cohort_candidate = hot_work ~= nil and hot_n ~= nil
    local match = cohort_candidate
        and open_work ~= nil and share >= min_share
    ctx.dynamic_pressure_cohort_hot_work = hot_work
    ctx.dynamic_pressure_cohort_samples = hot_n
    ctx.dynamic_pressure_cohort_share = share
    ctx.dynamic_pressure_cohort_candidate = cohort_candidate
    ctx.dynamic_pressure_cohort_match = match
    ctx.dynamic_pressure_attributed = match

    if not match then
        ctx.dynamic_pressure_disposition = "keep_normal"
        return false
    end

    -- After the global hold, each contributing cohort owns its probe lease.
    -- Unrelated traffic never consumes it and never decides recovery for it.
    if ctx.dynamic_pressure_half_open then
        local probe_ttl = math.max(tonumber(spec.probe_timeout) or 10, 1)
        local acquired, err = dict:add(cohort_base .. ":probe", 1, probe_ttl)
        if acquired then
            ctx.dynamic_pressure_probe = true
            ctx.dynamic_pressure_probe_cohort = id
            ctx.dynamic_pressure_half_open = false
            ctx.dynamic_pressure_disposition = "probe"
            return false
        end
        if err ~= "exists" then
            ctx.dynamic_guard_degraded = true
            ctx.dynamic_pressure_degraded = true
            ctx.dynamic_pressure_disposition = "keep_degraded"
            log_dict_error("pressure_cohort_probe", err)
            return false
        end
        ctx.dynamic_pressure_disposition = "shed_incident_wait"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    if not ctx.dynamic_pressure_would_reject then
        ctx.dynamic_pressure_disposition = "keep_normal"
        return false
    end

    -- Explicit operator policy (including internal callbacks) wins over the
    -- incident scheduler.  This is deliberately narrower than any Cookie.
    if ctx.whitelisted == true then
        ctx.dynamic_pressure_disposition = "keep_whitelist"
        return false
    end

    -- Verified crawlers are legitimate identities, but they are still
    -- automation and must yield while a tenant is consuming extreme backend
    -- work.  No vendor/principal name is needed here.
    if pressure_automation(ctx) then
        ctx.dynamic_pressure_disposition = "shed_incident_automation"
        ctx.dynamic_pressure_selective_candidate = true
        return true
    end

    local verified = ctx.verified == true
    local richness = tonumber(ctx.session_richness_own) or 0
    local first_party = ctx.session_cookie_known == true
        and richness >= (tonumber(spec.first_party_richness) or 0.5)
    if not verified and not first_party then
        ctx.dynamic_pressure_disposition = "shed_incident"
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
    local security = cause == "uri_integrity" or cause == "path_spray"
    local scope = cause == "server_pressure" and "server"
        or (cause == "server_client" and "server_ip"
        or (cause == "tenant_client" and "docroot_ip" or "docroot"))
    decision.set(ctx, {
        kind = security and "security" or "capacity",
        source = "dynamic_guard", rule = cause,
        mode = "enforce", scope = scope,
        subject = ctx.dynamic_server_pressure_cohort_id
            or ctx.endpoint_scope or ctx.ip,
        upstream = false,
    })
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
    local c = conf(ctx)
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
    read_server_pressure(dict, ctx, c, now())
    return true, false
end

function _M.admit(ctx)
    local c = conf(ctx)
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
    -- Compute the cohort on every admitted request so log phase can attribute
    -- completed work even before any aggregate pressure state exists.
    pressure_cohort(ctx)
    server_pressure_cohort(ctx)
    if ctx.dynamic_pressure_open == nil or ctx.dynamic_pressure_half_open then
        read_pressure(dict, ctx, c, scope, t, true)
    end
    local _, pressure_mode = pressure_config(c)
    local pressure_shed = pressure_select(
        dict, ctx, c, scope, t, slots)
    if pressure_shed then
        add("pressure", pressure_mode)
    end

    if ctx.dynamic_server_pressure_open == nil then
        read_server_pressure(dict, ctx, c, t)
    end
    local _, server_pressure_mode = server_pressure_config(c)
    local server_pressure_shed = server_pressure_select(dict, ctx, c)
    if server_pressure_shed then
        add("server_pressure", server_pressure_mode)
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
        elseif cause == "server_pressure" then
            ctx.dynamic_server_pressure_rejected = true
        end
        local status = cause == "pressure"
            and ((type(c.pressure) == "table" and c.pressure.status) or 503)
            or (cause == "path_spray" and spray_spec.status or nil)
        if cause == "server_pressure" then
            local server_spec = type(c.server_pressure) == "table"
                and c.server_pressure or {}
            status = tonumber(server_spec.status) or 503
        end
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

local function sum_pressure_buckets(dict, base, second, window)
    local samples, work, slow = 0, 0, 0
    for s = second - window + 1, second do
        samples = samples + (tonumber(dict:get(
            pressure_bucket(base, s, "n"))) or 0)
        work = work + (tonumber(dict:get(
            pressure_bucket(base, s, "work"))) or 0)
        slow = slow + (tonumber(dict:get(
            pressure_bucket(base, s, "slow"))) or 0)
    end
    return samples, work, slow
end

local function open_pressure(dict, ctx, spec, base, t, work, samples, slow)
    local hold = math.max(tonumber(spec.hold_seconds) or 20, 1)
    local probe = math.max(tonumber(spec.probe_timeout) or 10, 1)
    local until_at = t + hold
    local state_ttl = hold + probe + 5
    local ok, err = dict:set(base .. ":open_until", until_at, state_ttl)
    if not ok then
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_open", err)
        return
    end
    local work_ok, work_err = dict:set(base .. ":open_work", work, state_ttl)
    local n_ok, n_err = dict:set(base .. ":open_n", samples, state_ttl)
    if not work_ok or not n_ok then
        -- Without the denominator no cohort share can be proven.  Leave the
        -- aggregate state visible, but cohort matching will fail open.
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_open_evidence", work_err or n_err)
    end
    ctx.dynamic_pressure_open = true
    ctx.dynamic_pressure_until = until_at
    ctx.dynamic_pressure_transition = "open"
    ctx.dynamic_pressure_work = work
    ctx.dynamic_pressure_samples = samples
    ctx.dynamic_pressure_slow = slow
    stat("pressure_open")
end

local function reopen_pressure_cohort(dict, ctx, spec, base, cohort_base, t, up)
    local hold = math.max(tonumber(spec.hold_seconds) or 20, 1)
    local probe = math.max(tonumber(spec.probe_timeout) or 10, 1)
    local window = math.max(math.floor(tonumber(spec.window) or 10), 2)
    local state_ttl = hold + probe + 5
    local cohort_ttl = window + state_ttl
    local until_at = t + hold
    local hot_work = math.max(tonumber(dict:get(cohort_base .. ":hot")) or 0,
        tonumber(up) or 0)
    local hot_n = math.max(tonumber(dict:get(cohort_base .. ":hot_n")) or 0, 1)
    local ok1, err1 = dict:set(base .. ":open_until", until_at, state_ttl)
    local ok2, err2 = dict:set(base .. ":open_work", hot_work, state_ttl)
    local ok3, err3 = dict:set(base .. ":open_n", hot_n, state_ttl)
    local ok4, err4 = dict:set(cohort_base .. ":hot", hot_work, cohort_ttl)
    local ok5, err5 = dict:set(cohort_base .. ":hot_n", hot_n, cohort_ttl)
    if not ok1 or not ok2 or not ok3 or not ok4 or not ok5 then
        ctx.dynamic_guard_degraded = true
        log_dict_error("pressure_cohort_reopen",
            err1 or err2 or err3 or err4 or err5)
        return
    end
    ctx.dynamic_pressure_open = true
    ctx.dynamic_pressure_until = until_at
    ctx.dynamic_pressure_transition = "cohort_reopen"
    ctx.dynamic_pressure_cohort_hot_work = hot_work
    ctx.dynamic_pressure_cohort_samples = hot_n
    ctx.dynamic_pressure_cohort_match = true
    stat("pressure_reopen")
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
    local cohort_id = ctx.dynamic_pressure_cohort_id
        or select(1, pressure_cohort(ctx))
    local cohort_base = pressure_cohort_base(base, cohort_id)

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

    -- Cohort cardinality is bounded by completed *slow* work, not arrivals.
    -- An attacker cannot fill shared memory with cheap unique URI/UA shapes.
    local cohort_samples, cohort_work, cohort_slow = 0, 0, 0
    if up >= slow_seconds then
        local _, cnerr = increment(dict,
            pressure_bucket(cohort_base, second, "n"), 1, ttl)
        local _, cwerr = increment(dict,
            pressure_bucket(cohort_base, second, "work"), up, ttl)
        local _, cserr = increment(dict,
            pressure_bucket(cohort_base, second, "slow"), 1, ttl)
        if cnerr or cwerr or cserr then
            ctx.dynamic_guard_degraded = true
            log_dict_error("pressure_cohort_record", cnerr or cwerr or cserr)
            return
        end
        cohort_samples, cohort_work, cohort_slow =
            sum_pressure_buckets(dict, cohort_base, second, window)
        ctx.dynamic_pressure_cohort_samples = cohort_samples
        ctx.dynamic_pressure_cohort_work = cohort_work
        ctx.dynamic_pressure_cohort_slow = cohort_slow

        local cohort_min_samples = math.max(math.floor(
            tonumber(spec.cohort_min_samples) or 3), 1)
        local cohort_work_limit = math.max(
            tonumber(spec.cohort_work_seconds) or 30, 0.1)
        local cohort_candidate = cohort_samples >= cohort_min_samples
            and cohort_work >= cohort_work_limit
        ctx.dynamic_pressure_cohort_candidate = cohort_candidate
        if cohort_candidate
           and not dict:get(cohort_base .. ":recovery") then
            local hot_ttl = window
                + math.max(tonumber(spec.hold_seconds) or 20, 1)
                + math.max(tonumber(spec.probe_timeout) or 10, 1) + 5
            local hok, herr = dict:set(
                cohort_base .. ":hot", cohort_work, hot_ttl)
            local nok, nseterr = dict:set(
                cohort_base .. ":hot_n", cohort_samples, hot_ttl)
            if not hok or not nok then
                ctx.dynamic_guard_degraded = true
                log_dict_error("pressure_cohort_hot", herr or nseterr)
                return
            end
        end
    end

    -- Probe result is direct evidence and must be handled before aggregate
    -- window evaluation.  A fast completion closes only its cohort; a slow
    -- completion directly renews that cohort and the aggregate hold.  It must
    -- not depend on rebuilding 180/12 after the breaker just shed arrivals.
    if ctx.dynamic_pressure_probe then
        local probe_id = ctx.dynamic_pressure_probe_cohort or cohort_id
        local probe_base = pressure_cohort_base(base, probe_id)
        delete_key(dict, probe_base .. ":probe")
        if up < slow_seconds then
            delete_key(dict, probe_base .. ":hot")
            delete_key(dict, probe_base .. ":hot_n")
            local recovery = math.max(tonumber(spec.recovery_seconds) or 5, 1)
            dict:set(probe_base .. ":recovery", 1, recovery)
            ctx.dynamic_pressure_open = false
            ctx.dynamic_pressure_cohort_match = false
            ctx.dynamic_pressure_transition = "cohort_close"
            stat("pressure_close")
            return
        end
        reopen_pressure_cohort(
            dict, ctx, spec, base, probe_base, t, up)
        return
    end

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

    local samples, work, slow =
        sum_pressure_buckets(dict, base, second, window)
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
    ctx.dynamic_pressure_cohort_share = work > 0 and cohort_work / work or 0
    local min_share = math.max(math.min(
        tonumber(spec.cohort_min_share) or 0.15, 1), 0)
    ctx.dynamic_pressure_attributed =
        ctx.dynamic_pressure_cohort_candidate == true
        and ctx.dynamic_pressure_cohort_share >= min_share
    if candidate then
        open_pressure(dict, ctx, spec, base, t, work, samples, slow)
    end
end

local function record_server_pressure(dict, ctx, c, up, t)
    local spec, mode = server_pressure_config(c)
    if mode == "off" or not up then return end
    local base = server_pressure_keys()
    local second = math.floor(t)
    local window = math.max(math.floor(tonumber(spec.window) or 10), 2)
    local hold = math.max(tonumber(spec.hold_seconds) or 20, 1)
    local ttl = window * 3 + hold + 5
    local slow_seconds = tonumber(spec.slow_seconds) or 2.5
    local cohort_id = ctx.dynamic_server_pressure_cohort_id
        or select(1, server_pressure_cohort(ctx))
    local cohort_base = pressure_cohort_base(base, cohort_id)

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
        ctx.dynamic_server_pressure_degraded = true
        log_dict_error("server_pressure_record", nerr or werr or serr)
        return
    end

    local cohort_samples, cohort_work, cohort_slow = 0, 0, 0
    if up >= slow_seconds then
        local _, cnerr = increment(dict,
            pressure_bucket(cohort_base, second, "n"), 1, ttl)
        local _, cwerr = increment(dict,
            pressure_bucket(cohort_base, second, "work"), up, ttl)
        local _, cserr = increment(dict,
            pressure_bucket(cohort_base, second, "slow"), 1, ttl)
        if cnerr or cwerr or cserr then
            ctx.dynamic_server_pressure_degraded = true
            log_dict_error("server_pressure_cohort_record",
                cnerr or cwerr or cserr)
            return
        end
        cohort_samples, cohort_work, cohort_slow =
            sum_pressure_buckets(dict, cohort_base, second, window)
        ctx.dynamic_server_pressure_cohort_samples = cohort_samples
        ctx.dynamic_server_pressure_cohort_work = cohort_work
        ctx.dynamic_server_pressure_cohort_slow = cohort_slow

        local cohort_min_samples = math.max(math.floor(
            tonumber(spec.cohort_min_samples) or 3), 1)
        local cohort_work_limit = math.max(
            tonumber(spec.cohort_work_seconds) or 30, 0.1)
        local cohort_candidate = cohort_samples >= cohort_min_samples
            and cohort_work >= cohort_work_limit
        ctx.dynamic_server_pressure_cohort_candidate = cohort_candidate
        if cohort_candidate then
            local hot_ttl = window + hold + 5
            local hok, herr = dict:set(
                cohort_base .. ":hot", cohort_work, hot_ttl)
            local nok, nseterr = dict:set(
                cohort_base .. ":hot_n", cohort_samples, hot_ttl)
            if not hok or not nok then
                ctx.dynamic_server_pressure_degraded = true
                log_dict_error("server_pressure_cohort_hot",
                    herr or nseterr)
                return
            end
        end
    end

    local interval = math.max(tonumber(spec.eval_interval) or 1, 0.1)
    local elected, elect_err = dict:add(base .. ":eval:"
        .. tostring(math.floor(t / interval)), 1, interval + 1)
    if not elected then
        if elect_err ~= "exists" then
            ctx.dynamic_server_pressure_degraded = true
            log_dict_error("server_pressure_elect", elect_err)
        end
        return
    end

    local samples, work, slow =
        sum_pressure_buckets(dict, base, second, window)
    ctx.dynamic_server_pressure_samples = samples
    ctx.dynamic_server_pressure_work = work
    ctx.dynamic_server_pressure_slow = slow
    ctx.dynamic_server_pressure_evaluated = true
    local min_samples = math.max(math.floor(
        tonumber(spec.min_samples) or 12), 1)
    local work_limit = math.max(tonumber(spec.work_seconds) or 180, 0.1)
    local candidate = samples >= min_samples and work >= work_limit
        and up >= slow_seconds
    ctx.dynamic_server_pressure_candidate = candidate
    ctx.dynamic_server_pressure_cohort_share = work > 0
        and cohort_work / work or 0
    local min_share = math.max(math.min(
        tonumber(spec.cohort_min_share) or 0.15, 1), 0)
    ctx.dynamic_server_pressure_attributed =
        ctx.dynamic_server_pressure_cohort_candidate == true
        and ctx.dynamic_server_pressure_cohort_share >= min_share
    if not candidate then return end

    local until_at = t + hold
    local state_ttl = hold + window + 5
    local ok1, err1 = dict:set(base .. ":open_until", until_at, state_ttl)
    local ok2, err2 = dict:set(base .. ":open_work", work, state_ttl)
    local ok3, err3 = dict:set(base .. ":open_n", samples, state_ttl)
    if not ok1 or not ok2 or not ok3 then
        ctx.dynamic_server_pressure_degraded = true
        log_dict_error("server_pressure_open", err1 or err2 or err3)
        return
    end
    ctx.dynamic_server_pressure_open = true
    ctx.dynamic_server_pressure_until = until_at
    ctx.dynamic_server_pressure_transition = "open"
    stat("server_pressure_open")
end

local function record_aborted_pressure(dict, ctx, c, up, t)
    local spec, enabled = aborted_pressure_config(c)
    if not enabled or not up then return end
    local window = math.max(math.floor(tonumber(spec.window) or 10), 2)
    local ttl = window * 3 + 5
    local second = math.floor(t)
    local slow_seconds = tonumber(spec.slow_seconds) or 2.5

    local function record_one(base, label)
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
            ctx.dynamic_aborted_degraded = true
            log_dict_error("aborted_" .. label, nerr or werr or serr)
            return nil
        end
        return { sum_pressure_buckets(dict, base, second, window) }
    end

    local doc = record_one(
        aborted_pressure_keys(ctx.dynamic_guard_scope), "docroot")
    local server = record_one(aborted_pressure_keys("server"), "server")
    ctx.dynamic_aborted_sample = true
    ctx.dynamic_aborted_upstream_time = up
    if doc then
        ctx.dynamic_aborted_doc_samples = doc[1]
        ctx.dynamic_aborted_doc_work = doc[2]
        ctx.dynamic_aborted_doc_slow = doc[3]
    end
    if server then
        ctx.dynamic_aborted_server_samples = server[1]
        ctx.dynamic_aborted_server_work = server[2]
        ctx.dynamic_aborted_server_slow = server[3]
    end
end

function _M.after(ctx)
    if not ctx or not ctx.dynamic_guard_scope then return end
    local c = conf(ctx)
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

    -- A 499 carried real occupancy but not a completed upstream verdict.  It is
    -- recorded on an isolated telemetry plane and can never teach path cost,
    -- cohort guilt or breaker state.  This distinction prevents an overloaded
    -- server's client aborts from becoming self-amplifying enforcement proof.
    local aborted = tonumber(ngx.status) == 499 and up ~= nil
    if aborted and not ctx.dynamic_guard_aborted_recorded then
        ctx.dynamic_guard_aborted_recorded = true
        record_aborted_pressure(dict, ctx, c, up, t)
    end

    -- Only completed, non-aborted upstream work teaches cost.  Local
    -- 4xx/429/503 responses never poison pressure or expensive-path evidence.
    if not aborted and not ctx.dynamic_guard_outcome_recorded
       and upstream and upstream ~= "" and upstream ~= "-" and up then
        ctx.dynamic_guard_outcome_recorded = true
        record_path_cost(dict, ctx, c, up, t)
        record_pressure(dict, ctx, c, up, t)
        record_server_pressure(dict, ctx, c, up, t)
    end
end

return _M
