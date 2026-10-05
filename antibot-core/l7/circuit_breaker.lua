-- Per-host backend circuit breaker.
--
-- This is a capacity control, not a bot verdict.  It learns only from dynamic
-- requests that actually reached an upstream and protects only the affected
-- virtual host.  Static hits keep being served while an unhealthy PHP/Apache
-- path is open.
--
-- Only hard upstream failures (502/503/504) may open the state machine.  Slow
-- 200 responses are measured as `circuit_slow_candidate` but never create an
-- OPEN state: replacing a valid, slow page with 503 needs fleet evidence and a
-- separate policy, not the hard-failure switch.
--
-- All state lives in the existing `antibot_cache` shared dictionary.  Access
-- phase performs one state lookup; log phase updates short fixed buckets and
-- elects at most one evaluator per host/second.  Evaluation reads only fully
-- completed one-second buckets.  This makes a configured 3 req/s equal a real
-- 30 samples/10 seconds, at the deliberate cost of about one second detection
-- latency.  Same-second bursts belong to admission.lua.  No Redis/cosocket is
-- used.
--
-- SAN LUU LUONG, do tren harness voi backend chet 100% trong 60 giay:
--   1-2 req/s  -> KHONG BAO GIO mo (duoi min_dynamic_rps)
--   3 req/s    -> mo o giay 10
--   4 req/s    -> giay 8
--   10 req/s   -> giay 3
--   30 req/s   -> giay 1
-- Day la y dinh: mot host 1 req/s khong lam can PHP pool, nen 503 cho no la FP
-- thuan. Nhung tren dan may nay phan lon host nam duoi san do (do 171-96 04-10:
-- `phuson.vn` 752 hit/24h ~ 0,009 req/s), nen breaker thuc te chi bao ve vai
-- host lon nhat. Dung ky vong no cuu moi tenant.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.l7_circuit_breaker or {}
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function log_dict_error(where, err)
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[l7_circuit] shared-dict error at ", where,
            ": ", tostring(err or "unknown"), " (fail-open)")
    end
end

local function dictionary()
    local dict = ngx.shared and ngx.shared.antibot_cache
    if not dict then log_dict_error("dictionary", "antibot_cache missing") end
    return dict
end

local function clamp(v, lo, hi)
    v = tonumber(v) or lo
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

local function safe_host(ctx)
    -- `server_name` is selected by nginx config and cannot create arbitrary
    -- cardinality from an attacker-controlled Host header.
    local host = ngx.var.server_name
    if not host or host == "" then
        -- Never fall back to the raw Host header: an attacker could otherwise
        -- create unbounded shared-dict keys on the default virtual server.
        host = "unknown"
    end
    host = tostring(host):lower():gsub("[^%w%.%-_:]", "_")
    if #host > 96 then
        host = (ngx.md5 and ngx.md5(host):sub(1, 16)) or host:sub(1, 96)
    end
    return host ~= "" and host or "unknown"
end

local function key(host, suffix)
    return "cb:" .. host .. ":" .. suffix
end

local function dynamic_request(ctx)
    if not ctx then return false end
    if ctx.admission_group ~= nil then
        return ctx.admission_group == "dynamic"
    end
    -- Admission normally fills `admission_group`.  If it is disabled, a known
    -- non-resource class is still dynamic; an unknown/resource request is not
    -- guessed into the breaker because that could turn measurement failure
    -- into a false 503 for a real static asset.
    local class = ctx.req_class
    return class ~= nil and class ~= "resource"
end

local function set_ctx(ctx, fields)
    if not ctx then return end
    for k, v in pairs(fields) do ctx[k] = v end
end

local function incr_with_ttl(dict, k, delta, ttl)
    local value, err = dict:incr(k, delta)
    if value then return value end
    if err ~= "not found" then return nil, err end

    local ok, add_err = dict:add(k, delta, ttl)
    if ok then return delta end
    if add_err == "exists" then return dict:incr(k, delta) end
    return nil, add_err
end

local function delete_key(dict, k)
    if dict.delete then dict:delete(k) else dict:set(k, nil) end
end

local function reject(ctx, c, state, open_until, cause)
    set_ctx(ctx, {
        circuit_state        = state,
        circuit_mode         = c.mode,
        circuit_cause        = cause,
        circuit_would_reject = true,
        circuit_open_until   = open_until,
        action               = "throttled",
        action_reason        = "l7_circuit:" .. state,
    })

    ngx.header["Retry-After"]   = tostring(c.retry_after or c.open_seconds or 5)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"]  = "text/plain"
    ngx.header["X-Bot-Action"]  = "throttled"
    ngx.header["X-L7-Circuit"]  = state
    ngx.status = tonumber(c.status) or 503

    -- Do not mirror every shed request into nginx error.log: the structured
    -- antibot logger records it, while transition() is the low-volume alert.
    ngx.say("Service temporarily unavailable.")
    ngx.exit(tonumber(c.status) or 503)
    return true, true
end

local function shadow_allow(ctx, c, state, open_until, cause)
    set_ctx(ctx, {
        circuit_state         = state,
        circuit_mode          = c.mode,
        circuit_cause         = cause,
        circuit_would_reject  = true,
        circuit_shadow_reject = true,
        circuit_open_until    = open_until,
    })
    return true, false
end

-- Access phase.  CLOSED costs one shared-dict get.  OPEN rejects only dynamic
-- work.  Once the cooldown expires, one request/host/second receives a probe
-- lease; every other dynamic request remains rejected until recovery is proven.
function _M.before(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" or not dynamic_request(ctx) then
        return true, false
    end

    local dict = dictionary()
    if not dict then
        if ctx then ctx.circuit_degraded = true end
        return true, false
    end

    local host = safe_host(ctx)
    local t = now()
    local open_until = tonumber(dict:get(key(host, "open_until")))
    if not open_until then
        if ctx then
            ctx.circuit_state = "closed"
            ctx.circuit_mode  = c.mode
        end
        return true, false
    end
    -- Current implementation opens only for hard upstream failures.  The key
    -- also makes the reason explicit in telemetry and leaves room for a future
    -- independent slow-policy state machine.  Missing means a short-lived
    -- state written by the pre-cause version, which was also a hard/slow mix;
    -- treating it as hard is conservative and it expires naturally in shadow.
    local cause = tostring(dict:get(key(host, "cause")) or "hard")

    if t < open_until then
        if c.mode == "enforce" then
            return reject(ctx, c, "open", open_until, cause)
        end
        return shadow_allow(ctx, c, "open", open_until, cause)
    end

    -- HALF-OPEN.  A time-bucketed add is atomic across workers.
    local probe_seconds = math.max(tonumber(c.probe_interval) or 1, 0.1)
    local probe_bucket = math.floor(t / probe_seconds)
    local probe_key = key(host, "probe:" .. tostring(probe_bucket))
    local probe, err = dict:add(probe_key, 1, probe_seconds + 1)
    if probe then
        set_ctx(ctx, {
            circuit_state      = "half_open",
            circuit_mode       = c.mode,
            circuit_cause      = cause,
            circuit_probe      = true,
            circuit_open_until = open_until,
        })
        return true, false
    end
    if err ~= "exists" then
        log_dict_error("probe", err)
        if ctx then ctx.circuit_degraded = true end
        return true, false
    end

    if c.mode == "enforce" then
        return reject(ctx, c, "half_open", open_until, cause)
    end
    return shadow_allow(ctx, c, "half_open", open_until, cause)
end

local function parse_upstream_status(raw)
    if not raw or raw == "" or raw == "-" then return nil end
    local seen = false
    local hard = false
    for token in tostring(raw):gmatch("%d%d%d") do
        seen = true
        local status = tonumber(token)
        if status == 502 or status == 503 or status == 504 then hard = true end
    end
    if not seen then return nil end
    return hard
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

local function sample_from_ngx(c)
    local hard = parse_upstream_status(ngx.var.upstream_status)
    if hard == nil then return nil end -- request never reached an upstream
    local upstream_time = max_upstream_time(ngx.var.upstream_response_time)
    local slow = upstream_time ~= nil
        and upstream_time >= (tonumber(c.slow_seconds) or 2)
    return {
        hard = hard,
        slow = slow,
        upstream_time = upstream_time,
    }
end

local function transition(ctx, c, host, old_state, new_state, metrics, duration,
                          cause)
    set_ctx(ctx, {
        circuit_transition = old_state .. ">" .. new_state,
        circuit_state      = new_state,
        circuit_cause      = cause,
        circuit_total      = metrics and metrics.total or nil,
        circuit_rps        = metrics and metrics.rps or nil,
        circuit_slow_ratio = metrics and metrics.slow_ratio or nil,
        circuit_hard_ratio = metrics and metrics.hard_ratio or nil,
        circuit_open_for   = duration,
    })
    ngx.log(ngx.WARN, "[l7_circuit] transition host=", host,
        " state=", old_state, ">", new_state,
        " n=", tostring(metrics and metrics.total or "-"),
        " rps=", tostring(metrics and metrics.rps or "-"),
        " slow=", tostring(metrics and metrics.slow_ratio or "-"),
        " hard=", tostring(metrics and metrics.hard_ratio or "-"),
        " cause=", tostring(cause or "-"),
        " open_for=", tostring(duration or "-"),
        " mode=", tostring(c.mode))
end

local function trip(dict, ctx, c, host, metrics, t, old_state, cause)
    cause = cause or "hard"
    -- Adjacent evaluator buckets can finish concurrently at a second boundary.
    -- Elect one opener so a single failure episode cannot increment backoff
    -- twice merely because two workers crossed that boundary together.
    local elected, elect_err = dict:add(key(host, "trip_lock"), 1, 1)
    if not elected then
        if elect_err ~= "exists" then
            log_dict_error("trip_lock", elect_err)
            if ctx then ctx.circuit_degraded = true end
        end
        return false
    end

    local stable_reset = math.max(tonumber(c.stable_reset_seconds) or 300, 30)
    local reopen_key = key(host, "reopen")
    local reopen, err = incr_with_ttl(dict, reopen_key, 1, stable_reset)
    if not reopen then
        log_dict_error("reopen", err)
        if ctx then ctx.circuit_degraded = true end
        return false
    end
    -- `DICT:incr` preserves the original TTL.  Refresh it explicitly so
    -- stable_reset_seconds means "time since the latest trip", not "time
    -- since the first trip in this episode".
    local refreshed, refresh_err = dict:set(reopen_key, reopen, stable_reset)
    if not refreshed then
        log_dict_error("reopen_ttl", refresh_err)
        if ctx then ctx.circuit_degraded = true end
    end

    local base = math.max(tonumber(c.open_seconds) or 5, 1)
    local maximum = math.max(tonumber(c.max_open_seconds) or 60, base)
    local duration = math.min(base * math.pow(2, math.max(reopen - 1, 0)), maximum)
    local open_until = t + duration
    -- Keep the timestamp beyond its deadline so access phase enters HALF-OPEN
    -- instead of silently treating an expired key as CLOSED.
    local ok, set_err = dict:set(
        key(host, "open_until"), open_until, duration + stable_reset)
    if not ok then
        log_dict_error("open_until", set_err)
        if ctx then ctx.circuit_degraded = true end
        return false
    end
    local cause_ok, cause_err = dict:set(
        key(host, "cause"), cause, duration + stable_reset)
    if not cause_ok then
        log_dict_error("cause", cause_err)
        if ctx then ctx.circuit_degraded = true end
    end
    delete_key(dict, key(host, "probe_ok"))
    if ctx then ctx.circuit_open_until = open_until end
    transition(ctx, c, host, old_state or "closed", "open", metrics, duration,
        cause)
    return true
end

local function clear_sample_window(dict, c, host, t)
    -- Samples collected before OPEN describe the old failure episode.  Keeping
    -- them after successful probes would let the very first CLOSED request
    -- reopen the host from stale evidence (especially when window > cooldown).
    local window = math.max(math.floor(tonumber(c.window_seconds) or 10), 1)
    local second = math.floor(t)
    for sec = second - window + 1, second do
        delete_key(dict, key(host, "b:" .. sec .. ":n"))
        delete_key(dict, key(host, "b:" .. sec .. ":s"))
        delete_key(dict, key(host, "b:" .. sec .. ":h"))
    end
end

local function close_after_probe(dict, ctx, c, host, sample, t)
    local needed = math.max(math.floor(tonumber(c.recover_successes) or 3), 1)
    local ttl = math.max(tonumber(c.stable_reset_seconds) or 300, 30)
    local count, err = incr_with_ttl(dict, key(host, "probe_ok"), 1, ttl)
    if not count then
        log_dict_error("probe_ok", err)
        if ctx then ctx.circuit_degraded = true end
        return
    end
    if ctx then ctx.circuit_probe_successes = count end
    if count < needed then return end

    delete_key(dict, key(host, "open_until"))
    delete_key(dict, key(host, "cause"))
    delete_key(dict, key(host, "probe_ok"))
    clear_sample_window(dict, c, host, t)
    transition(ctx, c, host, "half_open", "closed", {
        total = count,
        rps = 0,
        slow_ratio = sample.slow and 1 or 0,
        hard_ratio = sample.hard and 1 or 0,
    }, nil, (ctx and ctx.circuit_cause) or "hard")
end

local function bucket_incr(dict, host, second, suffix, ttl)
    return incr_with_ttl(dict,
        key(host, "b:" .. tostring(second) .. ":" .. suffix), 1, ttl)
end

local function read_window(dict, host, second, window)
    local total, slow, hard = 0, 0, 0
    for sec = second - window + 1, second do
        total = total + (tonumber(dict:get(key(host, "b:" .. sec .. ":n"))) or 0)
        slow  = slow  + (tonumber(dict:get(key(host, "b:" .. sec .. ":s"))) or 0)
        hard  = hard  + (tonumber(dict:get(key(host, "b:" .. sec .. ":h"))) or 0)
    end
    return {
        total      = total,
        slow       = slow,
        hard       = hard,
        rps        = total / window,
        slow_ratio = total > 0 and slow / total or 0,
        hard_ratio = total > 0 and hard / total or 0,
    }
end

local function evaluate_thresholds(c, metrics)
    local min_samples = math.max(tonumber(c.min_samples) or 30, 1)
    local min_rps = math.max(tonumber(c.min_dynamic_rps) or 3, 0)
    local slow_setting = c.slow_candidate_ratio
    if slow_setting == nil then slow_setting = c.slow_ratio end
    local slow_ratio = clamp(slow_setting, 0, 1)
    local hard_ratio = clamp(c.hard_error_ratio, 0, 1)
    local eligible = metrics.total >= min_samples
                 and metrics.rps >= min_rps
    return {
        eligible       = eligible,
        hard            = eligible and metrics.hard_ratio >= hard_ratio,
        slow_candidate  = eligible and metrics.slow_ratio >= slow_ratio,
    }
end

-- Log phase.  Only a request with a real upstream sample is learned.  Requests
-- that would have been rejected in shadow mode are ignored so shadow simulates
-- the same recovery traffic that enforce mode would actually observe.
function _M.after(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" or not dynamic_request(ctx) then return end
    if ctx and ctx.circuit_shadow_reject and not ctx.circuit_probe then return end

    -- `nil` = request chua bao gio toi upstream.
    --
    -- PHAI de lai dau, nhung CHI MOT MAU moi giay moi host. Khong co dau thi
    -- "0 dong `cb=` trong log" mang HAI nghia khac nhau — breaker chay nhung
    -- chua du luu luong, HAY `upstream_status` khong doc duoc o log phase va
    -- breaker la ma chet. Khong mot file nao khac trong cay nay doc
    -- `ngx.var.upstream_status`, nen gia dinh do chua tung duoc kiem tren may
    -- that.
    --
    -- Dung bau theo giay (cung co che voi evaluator) chu khong danh dau MOI
    -- request: tren 28-246 co 666.752 dong/24h, va phan lon request dynamic
    -- khong toi upstream la cac request chinh antibot da chan (PoW page, 403,
    -- 429) — danh dau het la tu lam phong log de tra loi mot cau hoi chi can
    -- mot mau. Mot mau/giay/host la du de phan biet 0 voi khong-doc-duoc.
    local sample = sample_from_ngx(c)
    if not sample then
        local dict = dictionary()
        if dict and ctx then
            local host = safe_host(ctx)
            local second = math.floor(now())
            local probe_key = key(host, "nosample:" .. tostring(second))
            if dict:add(probe_key, 1, 2) then
                ctx.circuit_no_sample = true
            end
        end
        return
    end

    local dict = dictionary()
    if not dict then
        if ctx then ctx.circuit_degraded = true end
        return
    end

    local host = safe_host(ctx)
    local t = now()

    if ctx and ctx.circuit_probe then
        -- More than one probe can be in flight because leases are issued once
        -- per interval while an unhealthy upstream may take several intervals
        -- to answer.  Accept only results from the OPEN epoch that granted the
        -- lease.  Otherwise a late probe from the previous epoch could close a
        -- newly reopened circuit or increase its backoff a second time.
        local expected_epoch = tonumber(ctx.circuit_open_until)
        local current_epoch = tonumber(dict:get(key(host, "open_until")))
        if not expected_epoch or current_epoch ~= expected_epoch then
            ctx.circuit_probe_stale = true
            return
        end

        if ctx then ctx.circuit_probe_slow = sample.slow end
        if sample.hard then
            delete_key(dict, key(host, "probe_ok"))
            trip(dict, ctx, c, host, {
                total = 1,
                rps = 1,
                slow_ratio = sample.slow and 1 or 0,
                hard_ratio = sample.hard and 1 or 0,
            }, t, "half_open", "hard")
        else
            -- A slow 200 proves the hard outage has recovered.  Record its
            -- latency, but do not turn the hard breaker into a slow-page WAF.
            close_after_probe(dict, ctx, c, host, sample, t)
        end
        return
    end

    local window = math.max(math.floor(tonumber(c.window_seconds) or 10), 1)
    local second = math.floor(t)
    local ttl = window + math.max(math.floor(tonumber(c.bucket_grace_seconds) or 10), 2)
    local value, err = bucket_incr(dict, host, second, "n", ttl)
    if not value then
        log_dict_error("bucket_total", err)
        if ctx then ctx.circuit_degraded = true end
        return
    end
    if sample.slow then
        value, err = bucket_incr(dict, host, second, "s", ttl)
        if not value then
            log_dict_error("bucket_slow", err)
            if ctx then ctx.circuit_degraded = true end
        end
    end
    if sample.hard then
        value, err = bucket_incr(dict, host, second, "h", ttl)
        if not value then
            log_dict_error("bucket_hard", err)
            if ctx then ctx.circuit_degraded = true end
        end
    end

    local interval = math.max(tonumber(c.eval_interval) or 1, 0.1)
    local eval_bucket = math.floor(t / interval)
    local elected, elect_err = dict:add(
        key(host, "eval:" .. tostring(eval_bucket)), 1, interval + 1)
    if not elected then
        if elect_err ~= "exists" then
            log_dict_error("evaluator", elect_err)
            if ctx then ctx.circuit_degraded = true end
        end
        return
    end

    -- The current bucket was just created/updated by the first request that
    -- won this evaluator slot, so it is necessarily partial.  Read the prior
    -- complete window instead.  At exactly 3 req/s this yields 30/10, rather
    -- than the old 28/10 caused by nine full seconds plus one current sample.
    local metrics = read_window(dict, host, second - 1, window)
    local thresholds = evaluate_thresholds(c, metrics)
    set_ctx(ctx, {
        circuit_evaluated  = true,
        circuit_state      = "closed",
        circuit_mode       = c.mode,
        circuit_eligible   = thresholds.eligible,
        circuit_slow_candidate = thresholds.slow_candidate,
        circuit_total      = metrics.total,
        circuit_rps        = metrics.rps,
        circuit_slow_ratio = metrics.slow_ratio,
        circuit_hard_ratio = metrics.hard_ratio,
    })

    -- A request that started while CLOSED may finish after another worker has
    -- opened the host.  Do not count that completion as another reopen/backoff.
    local open_until = tonumber(dict:get(key(host, "open_until")))
    if open_until then return end

    if thresholds.hard then
        trip(dict, ctx, c, host, metrics, t, "closed", "hard")
    end
end

return _M
