local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    if not ctx.ja3 then ctx.tls_cluster = 0; return end
    local count = pool.safe_incr("cluster:tls:" .. ctx.ja3, 600) or 0
    ctx.tls_cluster = math.min(count, cfg.cluster.tls_count_normalize_max)
end

return _M
