local _M = {}

local function bool_val(v)
    if v == true then return 1.0 end
    if type(v) == "number" then return v end
    return 0.0
end

function _M.run(ctx)
    ctx.corr_rules = {}

    local function fire(name, condition, score_add, reason)
        if condition then
            ctx.corr_rules[#ctx.corr_rules + 1] = {
                rule   = name,
                score  = score_add,
                reason = reason,
            }
        end
    end

    local ip_score    = ctx.ip_score      or 0
    local cluster     = ctx.cluster_score or 0
    local entropy     = ctx.entropy       or 0.35
    local bot         = ctx.bot_score     or 0
    local anomaly     = ctx.anomaly_score or 0
    local mismatch    = ctx.mismatch      or 0
    local rate_flag   = bool_val(ctx.rate_flag)
    local burst_flag  = bool_val(ctx.burst_flag)

    fire("cluster_headless",
         cluster > 0.4 and entropy < 0.3,
         0.4,
         string.format("cluster=%.2f+entropy=%.2f", cluster, entropy))

    fire("bad_ip_rate",
         ip_score > 0.5 and rate_flag > 0,
         0.35,
         string.format("ip_risk=%.2f+rate_flag", ip_score))

    fire("mismatch_bot",
         mismatch > 0.4 and bot > 0.4,
         0.4,
         string.format("mismatch=%.2f+bot=%.2f", mismatch, bot))

    fire("burst_headless",
         burst_flag > 0 and entropy < 0.2,
         0.35,
         string.format("burst+entropy=%.2f", entropy))

    fire("anomaly_rep",
         anomaly > 0.5 and (ctx.ip_rep or 0) > 0.3,
         0.3,
         string.format("anomaly=%.2f+ip_rep=%.2f", anomaly, ctx.ip_rep or 0))

    fire("ip_risk_cluster",
         ip_score > 0.6 and cluster > 0.3,
         0.35,
         string.format("ip_risk=%.2f+cluster=%.2f", ip_score, cluster))
end

return _M
