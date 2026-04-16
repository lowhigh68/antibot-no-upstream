local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local ip   = ctx.ip or ""
    local ip24 = ip:match("^(%d+%.%d+%.%d+)%.") or ip
    local count = pool.safe_incr("cluster:ip:" .. ip24, 600) or 0
    ctx.ip_cluster = math.min(count, cfg.cluster.ip_count_normalize_max)
end

return _M
