local _M = {}

local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local top = ctx.top_signals or {}

    local parts = {}
    for i, s in ipairs(top) do
        parts[i] = string.format("%s=%.0f%%",
            s.signal or "?", s.contribution_pct or 0)
    end

    local rules_fired = {}
    for _, r in ipairs(ctx.corr_rules or {}) do
        rules_fired[#rules_fired + 1] = tostring(r.rule or "?")
    end

    ctx.action_reason = string.format(
        "score=%.1f class=%s | top:[%s] | rules:[%s] | fp_quality=%.2f",
        ctx.score or 0,
        ctx.req_class or "?",
        table.concat(parts, ", "),
        table.concat(rules_fired, ", "),
        ctx.fp_quality or 0
    )

    local fp = ctx.fp_light
    if not fp then
        ngx.log(ngx.DEBUG, "[explain] no fp, skip persist")
        return
    end

    local ok, cjson = pcall(require, "cjson")
    if not ok then return end

    local ok2, payload = pcall(cjson.encode, {
        ts           = ngx.time(),
        fp           = fp,
        ip           = ctx.ip,
        score        = ctx.score,
        eff_score    = ctx.effective_score,
        req_class    = ctx.req_class,
        action       = ctx.action,
        action_reason= ctx.action_reason,
        top_signals  = #top > 0 and top or cjson.empty_array,
        fp_quality   = ctx.fp_quality,
        fp_degraded  = ctx.fp_degraded or false,
        corr_rules   = #rules_fired > 0 and rules_fired or cjson.empty_array,
        domain       = (ctx.req and ctx.req.host) or ngx.var.host or "?",
    })
    if not ok2 then return end

    local p = payload
    local t = (cfg and cfg.ttl and cfg.ttl.explain) or 3600
    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end
        red:setex("explain:" .. fp, t, p)
        pool.put(red)
    end)

    ngx.log(ngx.DEBUG, "[explain] ", ctx.action_reason)
end

return _M
