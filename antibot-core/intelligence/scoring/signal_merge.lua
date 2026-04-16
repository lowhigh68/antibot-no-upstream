local _M = {}

local SIGNAL_MAP = {
    { name = "rate_flag",       field = "rate_flag",      type = "bool"  },
    { name = "burst_flag",      field = "burst_flag",     type = "bool"  },
    { name = "slow",            field = "slow",           type = "bool"  },
    { name = "behavior_score",  field = "behavior_score", type = "score" },
    { name = "session_flag",    field = "session_flag",   type = "score" },
    { name = "graph_score",     field = "graph_score",    type = "score" },
    { name = "cluster_score",   field = "cluster_score",  type = "score" },
    { name = "anomaly_score",   field = "anomaly_score",  type = "score" },
    { name = "bot_score",       field = "bot_score",      type = "score" },
    { name = "h2_bot_confidence", field = "h2_bot_confidence", type = "score" },
    { name = "ip_rep",          field = "ip_rep",         type = "score" },
    { name = "asn_rep",         field = "asn_rep",        type = "score" },
    { name = "ja3_rep",         field = "ja3_rep",        type = "score" },
    { name = "h2_rep",          field = "h2_rep",         type = "score" },
    { name = "ip_score",        field = "ip_score",       type = "score" },
    { name = "entropy_inv",     field = "entropy",        type = "inv"   },
    { name = "corr_score",      field = "corr_score",     type = "score" },
    { name = "mismatch",        field = "mismatch",       type = "score" },
    { name = "risk",            field = "risk",           type = "score" },
}

local function normalize(name, raw, sig_type)
    if raw == nil then return nil end

    local val
    if sig_type == "bool" then
        val = (raw == true) and 1.0 or 0.0

    elseif sig_type == "inv" then
        local v = (type(raw) == "number") and raw or 0.35
        val = 1.0 - v

    else
        if type(raw) ~= "number" then
            ngx.log(ngx.WARN,
                "[signal_merge] ", name, " is not a number: ",
                type(raw), "=", tostring(raw), " → using 0.0")
            return 0.0
        end
        val = raw
    end

    if val < 0.0 or val > 1.0 then
        ngx.log(ngx.WARN,
            "[signal_merge] ", name, " out of range: ",
            string.format("%.4f", val), " → clamping")
        val = math.max(0.0, math.min(1.0, val))
    end

    return val
end

function _M.run(ctx)
    ctx.signals = ctx.signals or {}

    local violations = 0

    for _, sig in ipairs(SIGNAL_MAP) do
        local raw = ctx[sig.field]
        local val = normalize(sig.name, raw, sig.type)

        if val ~= nil then
            ctx.signals[sig.name] = val
        end
    end

    for k, v in pairs(ctx.signals) do
        if type(v) == "number" and (v < 0.0 or v > 1.0) then
            ngx.log(ngx.WARN,
                "[signal_merge] ctx.signals.", k, " out of range: ",
                string.format("%.4f", v))
            ctx.signals[k] = math.max(0.0, math.min(1.0, v))
            violations = violations + 1
        end
    end

    if violations > 0 then
        ngx.log(ngx.WARN,
            "[signal_merge] ", violations, " signal violations clamped")
    end

    ngx.log(ngx.DEBUG,
        "[signal_merge] merged ", #SIGNAL_MAP, " signals, ",
        "direct=", (function()
            local n = 0
            for _ in pairs(ctx.signals) do n = n + 1 end
            return n
        end)())
end

return _M
