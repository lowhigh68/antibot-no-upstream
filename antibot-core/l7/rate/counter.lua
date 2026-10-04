local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local identity_mod = require "antibot.core.fingerprint.identity"

local WINDOW = cfg.ttl.rate

local function ensure_identity(ctx)
    if ctx.identity and ctx.identity ~= "" then return ctx.identity end
    if not ctx.ip or ctx.ip == "" then return nil end
    local id = identity_mod.build_from(ctx.ip, ctx.ua)
    ctx.identity = id
    return id
end

local function keys(prefix, subject, t)
    local bucket = math.floor(t / WINDOW)
    return prefix .. subject .. ":" .. bucket,
           prefix .. subject .. ":" .. (bucket - 1),
           (WINDOW - (t - bucket * WINDOW)) / WINDOW
end

-- Approximate sliding window = current bucket + previous bucket * remaining
-- fraction. Khac idle-expiry counter cu: request o phut sau KHONG gia han va
-- mang toan bo lich su cua phut truoc sang vo han.
function _M.run(ctx)
    if ctx.skip_rate then
        ctx.rate, ctx.ip_rate, ctx.burst = 0, 0, 0
        return true, false
    end

    local weight = ctx.rate_weight or 1.0
    local ip     = ctx.ip or "?"
    local id     = ensure_identity(ctx)
    local t      = ngx.now and ngx.now() or ngx.time()

    local ip_cur, ip_prev, carry = keys("rl:ip:", ip, t)
    local id_cur, id_prev
    if id then id_cur, id_prev = keys("rl:id:", id, t) end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[counter] redis unavailable: ", err)
        ctx.rate, ctx.ip_rate, ctx.burst = 0, 0, 0
        ctx.rate_degraded = true
        return true, false
    end

    red:init_pipeline()
    red:incrbyfloat(ip_cur, weight)     -- 1
    red:expire(ip_cur, WINDOW * 2 + 2) -- 2
    red:get(ip_prev)                    -- 3

    if id then
        red:incrbyfloat(id_cur, weight)     -- 4
        red:expire(id_cur, WINDOW * 2 + 2) -- 5
        red:get(id_prev)                    -- 6
    else
        red:get("__noop__")
        red:get("__noop__")
        red:get("__noop__")
    end

    local res, perr = red:commit_pipeline()
    pool.put(red)
    if not res then
        ngx.log(ngx.WARN, "[counter] pipeline error: ", tostring(perr))
        ctx.rate, ctx.ip_rate, ctx.burst = 0, 0, 0
        ctx.rate_degraded = true
        return true, false
    end

    local ip_current = tonumber(res[1]) or 0
    local ip_old     = tonumber(res[3]) or 0
    local id_current = id and (tonumber(res[4]) or 0) or 0
    local id_old     = id and (tonumber(res[6]) or 0) or 0

    ctx.ip_rate = ip_current + ip_old * carry
    ctx.rate    = id_current + id_old * carry
    ctx.burst   = 0 -- burst_counter la nguon su that duy nhat cho burst

    ngx.log(ngx.DEBUG,
        "[counter] class=", ctx.req_class or "?",
        " ip=", ip,
        " id_rate=", string.format("%.2f", ctx.rate),
        " ip_rate=", string.format("%.2f", ctx.ip_rate),
        " weight=", weight,
        " carry=", string.format("%.2f", carry))

    return true, false
end

return _M
