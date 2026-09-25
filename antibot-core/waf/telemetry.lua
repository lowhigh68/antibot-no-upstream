local _M = {}

local function now(rt)
    if rt and rt.now then return rt.now() end
    return os.clock()
end

local function safe_component(value, limit)
    value = tostring(value or "-"):lower()
    value = value:gsub("[^a-z0-9_.:-]", "_")
    return value:sub(1, limit or 96)
end

local function dict_for(config, rt)
    local telemetry = config and config.telemetry or {}
    if telemetry.enabled == false or not rt or not rt.shared then return nil end
    return rt.shared[telemetry.shared_dict or "antibot_cache"]
end

local function incr(dict, key, amount)
    if not dict or type(dict.incr) ~= "function" then return false end
    local ok = pcall(dict.incr, dict, key, amount or 1, 0)
    return ok
end

function _M.start(ctx, config, rt)
    ctx.waf_telemetry = ctx.waf_telemetry or {}
    ctx.waf_telemetry.started = now(rt)
    ctx.waf_telemetry.recorded = false
    ctx.waf_telemetry.finished = false
    ctx.waf_telemetry.options = config and config.telemetry or {}
end

function _M.record(ctx, state, decision, rt)
    local t = ctx.waf_telemetry or {}
    if t.recorded then return end
    t.recorded = true
    ctx.waf_telemetry = t

    local config = state.config or {}
    local opts = config.telemetry or {}
    local prefix = opts.prefix or "waf:v2:"
    local dict = dict_for(config, rt)

    incr(dict, prefix .. "requests", 1)
    incr(dict, prefix .. "action:" .. safe_component(decision.action), 1)
    incr(dict, prefix .. "would:" .. safe_component(decision.would_action), 1)
    if decision.reason then
        incr(dict, prefix .. "decision:" .. safe_component(decision.action) .. ":" ..
                   safe_component(decision.reason), 1)
    end
    if decision.shadow and decision.would_reason then
        incr(dict, prefix .. "shadow:" .. safe_component(decision.would_reason), 1)
    end

    for i = 1, #state.hits do
        local hit = state.hits[i]
        incr(dict, prefix .. "rule:" .. safe_component(hit.rule), 1)
        if hit.excepted then
            incr(dict, prefix .. "excepted:" .. safe_component(hit.rule), 1)
        end
    end

    local body = ctx.waf_body
    if body then
        local scan = safe_component(body.scan or "unknown")
        local bytes = tonumber(body.len)
        if not bytes or bytes < 0 then bytes = 0 end
        t.scan_status = scan
        t.body_bytes = bytes
        t.body_source = body.source
        incr(dict, prefix .. "scan:" .. scan, 1)
        incr(dict, prefix .. "body_bytes_sum", bytes)
        if body.spill then incr(dict, prefix .. "body_spill", 1) end
    end

    if opts.per_host then
        local host = safe_component(state.request.host, opts.host_limit or 96)
        incr(dict, prefix .. "host:" .. host .. ":action:" ..
                   safe_component(decision.action), 1)
    end
end

function _M.finish(ctx, rt)
    local t = ctx and ctx.waf_telemetry
    if not t or t.finished then return end
    t.finished = true
    local elapsed = (now(rt) - (t.started or now(rt))) * 1000
    if elapsed < 0 then elapsed = 0 end
    t.duration_ms = elapsed

    local config = { telemetry = t.options or {} }
    local opts = config.telemetry or {}
    local prefix = opts.prefix or "waf:v2:"
    local dict = dict_for(config, rt)
    -- Milliseconds are accumulated as integers so averages can be calculated
    -- without storing one key per request.
    incr(dict, prefix .. "latency_ms_sum", math.floor(elapsed + 0.5))
    incr(dict, prefix .. "latency_count", 1)
end

return _M
