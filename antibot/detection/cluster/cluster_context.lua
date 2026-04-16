local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    if not ctx.baseline_ua then
        ctx.subnet_diversity = 99
        return
    end

    local ua_hash = ngx.md5(
        (ctx.ua or ""):gsub("/%d+[%d%.]*", ""):sub(1, 200)
    )
    local hll_key = "cluster:subnet_count:" .. ua_hash
    local ip24    = (ctx.ip or ""):match("^(%d+%.%d+%.%d+)%.") or ctx.ip or "?"

    local red, err = pool.get()
    if not red then ctx.subnet_diversity = 0; return end

    red:init_pipeline()
    red:pfadd(hll_key, ip24)
    red:expire(hll_key, 600)
    red:pfcount(hll_key)
    local res, perr = red:commit_pipeline()
    pool.put(red)

    ctx.subnet_diversity = (res and type(res[3]) == "number") and res[3] or 0
end

return _M
