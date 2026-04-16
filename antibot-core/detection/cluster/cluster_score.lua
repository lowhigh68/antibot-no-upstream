local _M = {}
local cfg = require "antibot.core.config"

local C = cfg.cluster

local function norm(v, max)
    if not v or v == 0 then return 0.0 end
    return math.min(1.0, v / max)
end

function _M.run(ctx)
    local raw = 0.0
    raw = raw + norm(ctx.ua_cluster,  C.ua_count_normalize_max)  * 0.3
    raw = raw + norm(ctx.ip_cluster,  C.ip_count_normalize_max)  * 0.3
    raw = raw + norm(ctx.uri_cluster, C.uri_count_normalize_max) * 0.2
    raw = raw + norm(ctx.tls_cluster, C.tls_count_normalize_max) * 0.1
    raw = raw + ((ctx.swarm == true) and 0.1 or 0.0)

    if ctx.baseline_ua and (ctx.subnet_diversity or 99) < C.subnet_diversity_nat_max then
        raw = raw * C.nat_discount_factor
    end

    if ctx.baseline_ua then
        raw = math.min(raw, C.baseline_ua_score_cap)
    end

    ctx.cluster_score = math.max(0.0, math.min(1.0, raw))
end

return _M
