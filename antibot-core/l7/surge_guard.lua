-- Per-host dynamic in-flight surge guard.
--
-- This module is deliberately Lua-only.  It reuses `antibot_cache`, never
-- touches Redis, and never treats capacity pressure as bot evidence.
--
-- There are two access-phase calls:
--   * before(): cheap early gate using the number of already admitted dynamic
--     requests.  In enforce mode a full host is rejected before WAF/Redis work.
--   * admit(): atomic slot acquisition, called only after WAF/antibot has
--     decided that the request may continue to content/upstream.
--
-- after() releases exactly one acquired slot in log phase.  Therefore static
-- hits, subrequests, WAF blocks, challenges and local 429/503 responses never
-- consume a slot.  A slot measures dynamic Nginx request lifetime from the end
-- of access phase to log phase.  It is a useful Lua-only proxy for concurrent
-- backend pressure, but not an exact PHP-FPM busy-worker count: buffered output
-- and a slow client can keep the slot after the upstream has completed.  The
-- sampled `surge_duration` and `surge_upstream_time` fields expose that gap.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.l7_surge_guard or {}
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function set_ctx(ctx, fields)
    if not ctx then return end
    for k, v in pairs(fields) do ctx[k] = v end
end

local function log_dict_error(where, err)
    local stats = ngx.shared and ngx.shared.antibot_stats
    if stats then
        local skey = "l7surge:dicterr"
        if not stats:incr(skey, 1) then stats:add(skey, 1, 86400) end
    end

    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[l7_surge] shared-dict error at ", where,
            ": ", tostring(err or "unknown"), " (fail-open)")
    end
end

local function dictionary()
    local dict = ngx.shared and ngx.shared.antibot_cache
    if not dict then log_dict_error("dictionary", "antibot_cache missing") end
    return dict
end

local function safe_host()
    -- Never key capacity state by the raw Host header.  server_name is the
    -- virtual host selected by Nginx and has bounded fleet cardinality.
    local host = ngx.var.server_name
    if not host or host == "" then host = "unknown" end
    host = tostring(host):lower():gsub("[^%w%.%-_:]", "_")
    if #host > 96 then
        host = (ngx.md5 and ngx.md5(host):sub(1, 16)) or host:sub(1, 96)
    end
    return host ~= "" and host or "unknown"
end

local function key(host, suffix)
    return "sg:" .. host .. ":" .. suffix
end

-- Slots are split by their start-time bucket instead of one eternal aggregate
-- key.  A worker crash can skip log phase; with one aggregate counter, any later
-- traffic would refresh that leaked count forever.  Closed time buckets stop
-- receiving TTL refreshes, so a leaked slot ages out even on a permanently busy
-- host.  The trade-off is explicit: a request older than the retention horizon
-- is no longer counted by this Lua proxy.
local function slot_settings(c)
    local seconds = math.max(
        math.floor(tonumber(c.slot_bucket_seconds) or 60), 1)
    local retention = math.max(
        math.floor(tonumber(c.slot_retention_seconds) or 300), seconds)
    local span = math.ceil(retention / seconds) + 1
    local ttl = retention + seconds + 1
    return seconds, span, ttl, retention
end

local function slot_key(host, bucket)
    return key(host, "slot:" .. tostring(bucket))
end

local function total_inflight(dict, host, c, t, current_value)
    local seconds, span = slot_settings(c)
    local current = math.floor(t / seconds)
    local total = 0
    for bucket = current - span + 1, current do
        if bucket == current and current_value ~= nil then
            total = total + current_value
        else
            total = total + (tonumber(dict:get(slot_key(host, bucket))) or 0)
        end
    end
    return total
end

local function dynamic_request(ctx)
    if not ctx then return false end
    if ngx.is_subrequest then return false end
    if ctx.admission_group ~= nil then
        return ctx.admission_group == "dynamic"
    end
    -- Admission normally supplies the authoritative static-hit/static-miss
    -- split.  If it is disabled, do not guess an unknown/resource request into
    -- a capacity verdict: uncertainty must fail open for real static assets.
    local class = ctx.req_class
    return class ~= nil and class ~= "resource"
end

local function thresholds(c)
    local limit = math.max(math.floor(tonumber(c.max_inflight) or 20), 1)
    local surge_ratio = tonumber(c.surge_ratio) or 0.75
    if surge_ratio < 0 then surge_ratio = 0 end
    if surge_ratio > 1 then surge_ratio = 1 end
    local recover_ratio = tonumber(c.recover_ratio) or 0.50
    if recover_ratio < 0 then recover_ratio = 0 end
    if recover_ratio > surge_ratio then recover_ratio = surge_ratio end

    local surge_at = math.max(math.ceil(limit * surge_ratio), 1)
    local recover_at = math.max(math.floor(limit * recover_ratio), 0)
    return limit, surge_at, recover_at
end

local function delete_key(dict, k)
    if dict.delete then return dict:delete(k) end
    return dict:set(k, nil)
end

-- Compatible add+incr path for OpenResty builds where incr(init, ttl) is not
-- available.  Refreshing the TTL is safe because expire() does not overwrite
-- the atomically incremented value.
local function increment(dict, k, ttl)
    local value, err = dict:incr(k, 1)
    if not value then
        if err ~= "not found" then return nil, err end
        local added, add_err = dict:add(k, 1, ttl)
        if added then
            value = 1
        elseif add_err == "exists" then
            value, err = dict:incr(k, 1)
            if not value then return nil, err end
        else
            return nil, add_err
        end
    end

    if dict.expire then
        local ok, expire_err = dict:expire(k, ttl)
        if not ok then return value, expire_err or "expire failed" end
    end
    return value
end

local function decrement(dict, k, ttl)
    local value, err = dict:incr(k, -1)
    if not value then
        if err == "not found" then return 0, "not found" end
        return nil, err
    end
    if value <= 0 then
        delete_key(dict, k)
        return 0
    end
    if dict.expire then
        local ok, expire_err = dict:expire(k, ttl)
        if not ok then return value, expire_err or "expire failed" end
    end
    return value
end

local function transition(dict, ctx, c, host, old_state, new_state, count,
                          limit, t)
    if old_state == new_state then return end

    local state_key = key(host, "state")
    local recovery_key = key(host, "recovery_until")
    local state_ttl = math.max(tonumber(c.state_ttl) or 300, 10)
    if new_state == "normal" then
        delete_key(dict, state_key)
        delete_key(dict, recovery_key)
    else
        local ok, err = dict:set(state_key, new_state, state_ttl)
        if not ok then
            log_dict_error("state", err)
            if ctx then ctx.surge_degraded = true end
            return
        end
        if new_state == "recovery" then
            local until_at = t + math.max(tonumber(c.recovery_seconds) or 2, 0)
            ok, err = dict:set(recovery_key, until_at, state_ttl)
            if not ok then
                log_dict_error("recovery_until", err)
                if ctx then ctx.surge_degraded = true end
            end
        elseif new_state == "surge" or new_state == "shed" then
            delete_key(dict, recovery_key)
        end
    end

    -- State writes may race at a boundary.  Elect one observable transition
    -- per host/state/second; the counter and enforcement remain atomic even if
    -- another worker wins this low-volume logging lease.
    local event = old_state .. ">" .. new_state
    local event_key = key(host,
        "transition:" .. event .. ":" .. tostring(math.floor(t)))
    local elected, elect_err = dict:add(event_key, 1, 2)
    if elected then
        if ctx then
            ctx.surge_transition = ctx.surge_transition
                and (ctx.surge_transition .. "," .. event) or event
        end
        ngx.log(ngx.WARN, "[l7_surge] transition host=", host,
            " state=", event,
            " inflight=", tostring(count),
            " limit=", tostring(limit),
            " mode=", tostring(c.mode))
    elseif elect_err ~= "exists" then
        log_dict_error("transition", elect_err)
        if ctx then ctx.surge_degraded = true end
    end
end

local function reconcile_state(dict, ctx, c, host, count, t)
    local limit, surge_at, recover_at = thresholds(c)
    local old_state = tostring(dict:get(key(host, "state")) or "normal")
    local new_state = old_state

    if count >= limit then
        new_state = "shed"
    elseif count >= surge_at then
        new_state = "surge"
    elseif old_state == "shed" or old_state == "surge" then
        if count <= recover_at then new_state = "recovery" end
    elseif old_state == "recovery" then
        local until_at = tonumber(dict:get(key(host, "recovery_until"))) or 0
        if count >= surge_at then
            new_state = "surge"
        elseif count <= recover_at and t >= until_at then
            new_state = "normal"
        end
    else
        new_state = "normal"
    end

    transition(dict, ctx, c, host, old_state, new_state, count, limit, t)
    set_ctx(ctx, {
        surge_state    = new_state,
        surge_mode     = c.mode,
        surge_limit    = limit,
        surge_inflight = count,
        surge_use      = math.floor((count / limit) * 100),
    })
    return new_state, limit
end

local function reject(ctx, c, state, count, limit)
    set_ctx(ctx, {
        surge_state        = state,
        surge_mode         = c.mode,
        surge_inflight     = count,
        surge_limit        = limit,
        surge_use          = math.floor((count / limit) * 100),
        surge_would_reject = true,
        action             = "throttled",
        action_reason      = "l7_surge:capacity",
    })

    ngx.header["Retry-After"]  = tostring(c.retry_after or 2)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["X-Bot-Action"] = "throttled"
    ngx.header["X-L7-Surge"]   = state
    ngx.status = tonumber(c.status) or 503
    ngx.say("Service temporarily unavailable.")
    ngx.exit(tonumber(c.status) or 503)
    return true, true
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

-- Early access gate.  It cannot acquire a slot here because WAF/challenge may
-- still terminate the request; doing so would count blocked work as backend
-- concurrency.  It only rejects a host that is already at capacity in enforce
-- mode.  admit() remains the atomic authority for races between workers.
function _M.before(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" or not dynamic_request(ctx) then
        return true, false
    end
    -- Shadow cannot reject here, and the request may still be blocked by WAF.
    -- Defer all measurement to admit() to avoid a duplicate six-key read on
    -- every production request during rollout.
    if c.mode ~= "enforce" then return true, false end

    local dict = dictionary()
    if not dict then
        if ctx then ctx.surge_degraded = true end
        return true, false
    end

    local host = safe_host()
    local t = now()
    local count = total_inflight(dict, host, c, t)
    local state, limit = reconcile_state(dict, ctx, c, host, count, t)
    if c.mode == "enforce" and count >= limit then
        return reject(ctx, c, state, count, limit)
    end
    return true, false
end

-- Acquire one slot immediately before the request is allowed to continue to
-- content/upstream.  The (limit + 1) request is the first rejected request;
-- at exactly `limit` all configured slots are occupied but none is revoked.
--
-- `admit()` kiem `count > limit` con `before()` kiem `count >= limit`, va hai
-- toan tu khac nhau do la DUNG: chung doc `count` o hai thoi diem khac nhau.
-- `before()` doc TRUOC khi co incr nao, nen `count == limit` nghia la "day";
-- `admit()` doc SAU incr cua chinh request nay, nen "day" la `count == limit+1`.
-- Hai bieu thuc mo ta CUNG mot trang thai vat ly. Dung sua mot ben cho
-- "khop" ben kia — doi `before()` sang `>` lam cong som gan nhu khong bao gio
-- ban (chi ban khi co slot ro), tuc bo han muc dich "tu choi truoc WAF/Redis",
-- va bo kiem `full host bi shed som` se bat ngay.
function _M.admit(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" or not dynamic_request(ctx) then
        return true, false
    end
    if ctx.surge_admitted and not ctx.surge_released then return true, false end

    local dict = dictionary()
    if not dict then
        if ctx then ctx.surge_degraded = true end
        return true, false
    end

    local host = safe_host()
    local t = now()
    local bucket_seconds, _, ttl = slot_settings(c)
    local bucket = math.floor(t / bucket_seconds)
    local request_slot_key = slot_key(host, bucket)
    local bucket_count, err = increment(dict, request_slot_key, ttl)
    if not bucket_count then
        log_dict_error("admit", err)
        if ctx then ctx.surge_degraded = true end
        return true, false
    end
    if err then
        log_dict_error("admit_ttl", err)
        if ctx then ctx.surge_degraded = true end
    end

    set_ctx(ctx, {
        surge_admitted = true,
        surge_released = false,
        surge_host     = host,
        surge_admit_at = t,
        surge_slot_key = request_slot_key,
    })
    -- Use this request's atomic increment return for the current bucket instead
    -- of re-reading it.  Concurrent later increments must not make several
    -- workers all believe they were the unique (limit + 1) request and roll
    -- back valid slots together.
    local count = total_inflight(dict, host, c, t, bucket_count)
    local state, limit = reconcile_state(dict, ctx, c, host, count, t)

    if count > limit then
        if ctx then ctx.surge_would_reject = true end
        if c.mode == "enforce" then
            -- This request did not get a slot.  Roll its atomic increment back
            -- now; log phase must not decrement it a second time.
            local remaining, rollback_err = decrement(
                dict, request_slot_key, ttl)
            if remaining == nil or rollback_err then
                log_dict_error("rollback", rollback_err)
                if ctx then ctx.surge_degraded = true end
            end
            local total_remaining = total_inflight(dict, host, c, t)
            if ctx then
                ctx.surge_admitted = false
                ctx.surge_released = true
                ctx.surge_remaining = total_remaining
            end
            reconcile_state(dict, ctx, c, host, total_remaining, t)
            return reject(ctx, c, "shed", count, limit)
        end
    end
    return true, false
end

-- Log phase: release exactly one admitted slot and elect one telemetry sample
-- per host/second.  No Redis/cosocket call is made here.
function _M.after(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" or not ctx
       or not ctx.surge_admitted or ctx.surge_released then return end

    -- Mark first: even if shared-dict maintenance fails, a repeated call from a
    -- test/hook cannot decrement another request's slot.
    ctx.surge_released = true

    local dict = dictionary()
    if not dict then
        ctx.surge_degraded = true
        return
    end

    local host = ctx.surge_host or safe_host()
    local t = now()
    local _, _, ttl, retention = slot_settings(c)

    ctx.surge_duration = math.max(t - (tonumber(ctx.surge_admit_at) or t), 0)
    ctx.surge_upstream_time = max_upstream_time(ngx.var.upstream_response_time)
    local within_horizon = ctx.surge_duration <= retention
    if not within_horizon then ctx.surge_slot_expired = true end

    local slot_remaining, err = decrement(
        dict, ctx.surge_slot_key or "", ttl)
    if slot_remaining == nil then
        ctx.surge_degraded = true
        log_dict_error("release", err)
        return
    end
    if err == "not found" then
        -- The request outlived the configured retention horizon.  Its slot is
        -- already absent from total_inflight, so this is expected fail-open
        -- aging rather than a shared-dict failure.
        ctx.surge_slot_expired = true
    elseif err then
        ctx.surge_degraded = true
        log_dict_error("release_ttl", err)
    end
    -- One sum after the decrement is enough.  A second full-window read before
    -- it would add six shared-dict gets to every request only to derive a
    -- telemetry value.  If this slot was still inside the counted horizon and
    -- existed, the immediately-before-release observation is remaining + 1.
    local remaining = total_inflight(dict, host, c, t)
    local current = remaining
    if within_horizon and err ~= "not found" then current = current + 1 end
    ctx.surge_observed = current
    ctx.surge_remaining = remaining
    reconcile_state(dict, ctx, c, host, remaining, t)

    local interval = math.max(tonumber(c.sample_interval) or 1, 0.1)
    local bucket = math.floor(t / interval)
    local sampled, sample_err = dict:add(
        key(host, "sample:" .. tostring(bucket)), 1, interval + 1)
    if sampled then
        ctx.surge_sampled = true
        -- Report the larger of the value observed at admission and immediately
        -- before release.  It is exact for this request, though intentionally
        -- not advertised as a per-second global peak.
        ctx.surge_sample_count = math.max(
            tonumber(ctx.surge_inflight) or 0, current)
        local limit = tonumber(ctx.surge_limit) or thresholds(c)
        ctx.surge_use = math.floor((ctx.surge_sample_count / limit) * 100)
    elseif sample_err ~= "exists" then
        ctx.surge_degraded = true
        log_dict_error("sample", sample_err)
    end
end

return _M
