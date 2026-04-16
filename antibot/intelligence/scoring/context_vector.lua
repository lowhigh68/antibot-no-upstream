local _M  = {}
local cfg = require "antibot.core.config"

local function get_hour_factor()
    local hour = tonumber(os.date("%H")) or 12
    return (hour >= 2 and hour <= 6) and 1.2 or 1.0
end

local function is_api_request()
    local accept = ngx.var.http_accept or ""
    local ct     = ngx.var.http_content_type or ""
    return accept:find("application/json", 1, true) ~= nil
        or ct:find("application/json", 1, true) ~= nil
end

function _M.run(ctx)
    local uri    = (ctx.req and ctx.req.uri) or ngx.var.request_uri or "/"
    local api    = is_api_request()
    local ep     = cfg.endpoint_sens(uri)
    local hour_f = get_hour_factor()
    local fp_q   = ctx.fp_quality or 0.25

    local base = ep * hour_f

    local fp_mult = 1.0 + (1.0 - fp_q) * 0.5

    ctx.context_multipliers = {
        ja3_rep          = base * fp_mult,
        h2_rep           = base * fp_mult,
        mismatch         = base * fp_mult,
        h2_bot_confidence= base * fp_mult,

        behavior_score   = api and base * 0.5  or base,
        session_flag     = api and base * 0.3  or base,
        graph_score      = api and base * 0.3  or base,
        rate_flag        = api and base * 0.6  or base,
        burst_flag       = api and base * 0.7  or base,

        cluster_score    = base,

        bot_score        = base,
        anomaly_score    = base,

        ip_score         = base,
        ip_rep           = base,
        asn_rep          = base,

        corr_score       = base * 1.1,

        entropy_inv      = api and base * 0.4  or base,

        risk             = base,

        slow             = base * 1.2,
    }

    ctx.is_api_request = api

    ngx.log(ngx.DEBUG,
        "[context_vector] ep_sens=", string.format("%.2f", ep),
        " hour_f=", string.format("%.2f", hour_f),
        " fp_q=", string.format("%.2f", fp_q),
        " api=", tostring(api))
end

return _M
