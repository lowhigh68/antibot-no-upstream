-- Whole-server concurrency gate for evidence-backed automation.
--
-- Rate windows answer how quickly a crawler arrives.  This gate answers the
-- different capacity question: how many requests from the same canonical
-- operator are still alive after the last local verdict and immediately before
-- content/upstream.  The key intentionally contains no host, URI or IP, so an
-- operator cannot multiply its backend budget by spreading work across tenant
-- domains or published source ranges. Weaker cloud-only evidence also gets a
-- source-IP axis because one production IP alternated multiple vendor claims.
-- Verified crawlers enter only when the existing good-bot policy has placed
-- them in the generic `aggressive` class.  This is deliberately class-based:
-- Amazonbot supplied the production evidence, but no vendor name belongs in
-- this capacity primitive and polite/moderate search crawlers remain outside.
--
-- The slot primitive mirrors endpoint_guard: acquire in late access, release in
-- log phase, and age counters in bounded time buckets.  A slow request therefore
-- holds one slot for longer without a guessed req_class cost.  Slot duration is
-- request lifetime, not exact PHP-FPM busy time; `autcdur` and `autcup` expose
-- the buffering/slow-client gap before any principal is promoted from shadow.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.automation_concurrency or {}
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
        if not stats:incr("automation:concurrency:dicterr", 1) then
            stats:add("automation:concurrency:dicterr", 1, 86400)
        end
    end
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[operator_concurrency] shared-dict error at ",
            where, ": ", tostring(err or "unknown"), " (fail-open)")
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

local function canonical_principal(ctx)
    local principal = tostring(ctx and ctx.automation_principal or ""):lower()
    if principal == "" or principal == "-" then return nil end
    return principal
end

-- Do not let a self-selected UA allocate shared-dict keys or consume another
-- operator's slots. Published operators require their network binding. Cloud
-- automation requires the exact proof emitted by bot/init.lua after PTR lookup;
-- a claim-only UA cannot manufacture either eligibility path.
local function eligible(ctx, c)
    if not c.enabled or tostring(c.mode or "off") == "off" then return nil end
    if not ctx or ngx.is_subrequest then return nil end
    local principal = canonical_principal(ctx)
    if not principal then return nil end

    if ctx.automation_tier == "operator"
       and ctx.operator_network_verified == true then
        return { principal = principal, tier = "operator" }
    end

    if ctx.automation_tier == "cloud_automation"
       and ctx.automation_proof == "contact_cloud_ptr"
       and ctx.automation_cloud_claimed == true then
        local source = tostring(ctx.ip or "")
        if source ~= "" and source ~= "-" then
            return {
                principal = principal,
                tier = "cloud_automation",
                source = source,
            }
        end
    end

    if ctx.automation_tier == "verified"
       and ctx.good_bot_verified == true
       and ctx.good_bot_class == "aggressive" then
        return { principal = principal, tier = "verified_aggressive" }
    end
    return nil
end

local function principal_policy(c, principal, tier)
    local spec = type(c.principals) == "table" and c.principals[principal] or nil
    if type(spec) ~= "table" then spec = {} end
    local tier_spec = type(c.tiers) == "table" and c.tiers[tier] or nil
    if type(tier_spec) ~= "table" then tier_spec = {} end
    local mode = tostring(spec.mode or tier_spec.mode or c.mode or "shadow")
    local limit = tonumber(spec.limit) or tonumber(tier_spec.limit)
        or tonumber(c.limit) or 0
    local source_limit = tonumber(spec.source_limit)
        or tonumber(tier_spec.source_limit) or 0
    return mode, math.max(math.floor(limit), 0),
           math.max(math.floor(source_limit), 0)
end

local function digest(value)
    if ngx.md5 then return ngx.md5(value) end
    return value:gsub("[^%w_.-]", "_"):sub(1, 64)
end

local function base_key(principal)
    return "aut:conc:" .. digest(principal)
end

local function source_base_key(source)
    return "aut:conc:src:" .. digest(source)
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

local function acquire_slot(dict, base, axis, limit, c, t)
    local bucket_s, _, ttl = slot_settings(c)
    local bucket = math.floor(t / bucket_s)
    local key = slot_key(base, bucket)
    local bucket_n, err = increment(dict, key, ttl)
    if not bucket_n then return nil, err end
    return {
        axis = axis,
        base = base,
        key = key,
        count = total_inflight(dict, base, c, t, bucket_n),
        limit = limit,
    }, err
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

local function reject(ctx, c, principal, tier, axis)
    local status = tonumber(c.status) or 429
    ctx.automation_concurrency_rejected = true
    ctx.action = "throttled"
    ctx.action_reason = "automation_concurrency:" .. tostring(tier)
        .. ":" .. tostring(axis) .. ":" .. principal
    ngx.header["Retry-After"] = tostring(c.retry_after or 10)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["X-Bot-Action"] = "throttled"
    ngx.status = status
    ngx.say("Too many concurrent crawler requests. Please retry later.")
    ngx.exit(status)
    return false, true
end

-- Atomic authority at the last common point before content/upstream.  There is
-- deliberately no early `before()` gate: local WAF/ban/challenge exits must not
-- look like backend occupancy, and the post-increment count closes worker races.
function _M.admit(ctx)
    local c = conf()
    local evidence = eligible(ctx, c)
    if not evidence then return true, false end
    if ctx.automation_concurrency_admitted
       and not ctx.automation_concurrency_released then return true, false end

    local principal, tier = evidence.principal, evidence.tier
    local mode, limit, source_limit = principal_policy(c, principal, tier)
    ctx.automation_concurrency_mode = mode
    ctx.automation_concurrency_limit = limit
    ctx.automation_concurrency_principal = principal
    ctx.automation_concurrency_tier = tier
    ctx.automation_concurrency_source_limit = source_limit > 0
        and source_limit or nil
    if mode == "off" or limit <= 0 then return true, false end

    local dict = dictionary()
    if not dict then
        ctx.automation_concurrency_degraded = true
        return true, false
    end

    local t = now()
    local base = base_key(principal)
    local _, _, ttl = slot_settings(c)
    local principal_slot, err = acquire_slot(
        dict, base, "principal", limit, c, t)
    if not principal_slot then
        ctx.automation_concurrency_degraded = true
        log_dict_error("admit", err)
        return true, false
    end
    if err then
        ctx.automation_concurrency_degraded = true
        log_dict_error("admit_ttl", err)
    end

    local slots = { principal_slot }
    local source_slot
    if evidence.source and source_limit > 0 then
        source_slot, err = acquire_slot(dict,
            source_base_key(evidence.source), "source", source_limit, c, t)
        if source_slot then
            slots[#slots + 1] = source_slot
            if err then
                ctx.automation_concurrency_degraded = true
                log_dict_error("admit_source_ttl", err)
            end
        else
            -- Keep the principal slot for accurate telemetry/release, but a
            -- broken second axis makes the whole decision fail-open.
            ctx.automation_concurrency_degraded = true
            log_dict_error("admit_source", err)
        end
    end

    ctx.automation_concurrency_admitted = true
    ctx.automation_concurrency_released = false
    ctx.automation_concurrency_admit_at = t
    ctx.automation_concurrency_slots = slots
    ctx.automation_concurrency_slot_key = principal_slot.key
    ctx.automation_concurrency_base_key = base
    ctx.automation_concurrency_inflight = principal_slot.count
    ctx.automation_concurrency_source_inflight = source_slot
        and source_slot.count or nil

    local principal_over = principal_slot.count > limit
    local source_over = source_slot and source_slot.count > source_limit or false
    ctx.automation_concurrency_would_reject = principal_over or source_over
    if source_over then
        ctx.automation_concurrency_axis = "source"
    elseif principal_over then
        ctx.automation_concurrency_axis = "principal"
    elseif source_slot
       and source_slot.count / source_limit > principal_slot.count / limit then
        ctx.automation_concurrency_axis = "source"
    else
        ctx.automation_concurrency_axis = "principal"
    end

    -- A counter whose TTL could not be installed is not trustworthy enough to
    -- deny traffic: it may retain stale slots after their requests finish.
    -- Keep the would-reject telemetry, but fail open until the meter is healthy.
    if ctx.automation_concurrency_would_reject
       and mode == "enforce"
       and not ctx.automation_concurrency_degraded then
        local principal_remaining, source_remaining
        local release_err
        for i = #slots, 1, -1 do
            local slot = slots[i]
            local remaining, one_err = decrement(dict, slot.key, ttl)
            if slot.axis == "source" then
                source_remaining = remaining
            else
                principal_remaining = remaining
            end
            if one_err and one_err ~= "not found" then release_err = one_err end
        end
        ctx.automation_concurrency_released = true
        ctx.automation_concurrency_admitted = false
        ctx.automation_concurrency_remaining = principal_remaining
        ctx.automation_concurrency_source_remaining = source_remaining
        if release_err then
            ctx.automation_concurrency_degraded = true
            log_dict_error("rollback", release_err)
        end
        return reject(ctx, c, principal, tier,
            ctx.automation_concurrency_axis)
    end
    return true, false
end

-- Log phase release.  Shared-dict operations are legal here and do not require
-- a timer.  Mark-before-decrement makes repeated hooks idempotent.
function _M.after(ctx)
    if not ctx or not ctx.automation_concurrency_principal then return end
    ctx.automation_concurrency_actual_status = ngx.status
    ctx.automation_concurrency_upstream_status = ngx.var.upstream_status
    ctx.automation_concurrency_upstream_time =
        max_upstream_time(ngx.var.upstream_response_time)

    if not ctx.automation_concurrency_admitted
       or ctx.automation_concurrency_released then return end
    ctx.automation_concurrency_released = true

    local c = conf()
    local dict = dictionary()
    if not dict then
        ctx.automation_concurrency_degraded = true
        return
    end

    local _, _, ttl, retention = slot_settings(c)
    local t = now()
    ctx.automation_concurrency_duration = math.max(
        t - (tonumber(ctx.automation_concurrency_admit_at) or t), 0)
    if ctx.automation_concurrency_duration > retention then
        ctx.automation_concurrency_slot_expired = true
    end

    local slots = ctx.automation_concurrency_slots or {
        { axis = "principal", key = ctx.automation_concurrency_slot_key,
          base = ctx.automation_concurrency_base_key },
    }
    for i = #slots, 1, -1 do
        local slot = slots[i]
        local _, err = decrement(dict, slot.key or "", ttl)
        if err == "not found" then
            ctx.automation_concurrency_slot_expired = true
        elseif err then
            ctx.automation_concurrency_degraded = true
            log_dict_error("release_" .. tostring(slot.axis), err)
        else
            local remaining = total_inflight(dict, slot.base or "", c, t)
            if slot.axis == "source" then
                ctx.automation_concurrency_source_remaining = remaining
            else
                ctx.automation_concurrency_remaining = remaining
            end
        end
    end
end

return _M
