local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local id = ctx.identity or ctx.fp_light
    if not id then ctx.burst = 0; return end

    -- Bucket nam trong TEN khoa, nen EXPIRE co refresh cung khong keo lich su
    -- sang giay ke tiep. Bo session grace: truoc day L7 doc session_flag TRUOC
    -- session_analyze, gia tri khoi tao 0 lam moi sess_len>=5 duoc tat dem burst.
    local window = cfg.ttl.burst
    local t = ngx.now and ngx.now() or ngx.time()
    local bucket = math.floor(t / window)
    local count = pool.safe_incr(
        "burst:" .. id .. ":" .. bucket,
        window + 1)
    ctx.burst = count or 0
end

return _M
