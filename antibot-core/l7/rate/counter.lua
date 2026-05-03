local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local identity_mod = require "antibot.core.fingerprint.identity"

local TTL = cfg.ttl.rate

local function ensure_identity(ctx)
    if ctx.identity and ctx.identity ~= "" then
        return ctx.identity
    end
    if ctx.ip == "" or ctx.ip == nil then
        return nil
    end
    local id = identity_mod.build_from(ctx.ip, ctx.ua)
    ctx.identity = id
    return id
end

-- Retry detection: cùng URI từ cùng identity trong < RETRY_WINDOW giây
-- → likely browser retry vì packet loss / TCP reset, không phải attack.
-- Discount weight 70% để rate counter không bùng do mạng yếu.
-- Bot scan đa URI vẫn full weight vì URI khác hash khác.
local RETRY_WINDOW = 3
local RETRY_TTL    = 5
local RETRY_DISCOUNT = 0.3

local function maybe_discount_for_retry(ctx, weight)
    local id = ctx.identity or ctx.ip
    local uri = ctx.req and ctx.req.uri or "/"
    if not id or id == "" then return weight end

    local key = "retry:" .. id .. ":" .. ngx.md5(uri):sub(1, 8)
    local last = pool.safe_get(key)
    local now  = ngx.time()
    pool.safe_set(key, tostring(now), RETRY_TTL)

    if last and (now - (tonumber(last) or 0)) < RETRY_WINDOW then
        ctx.is_retry = true
        ngx.log(ngx.DEBUG,
            "[counter] retry_discount uri=", uri:sub(1, 40),
            " id=", id:sub(1, 8))
        return weight * RETRY_DISCOUNT
    end
    return weight
end

function _M.run(ctx)
    if ctx.skip_rate then
        ctx.rate    = 0
        ctx.ip_rate = 0
        ctx.burst   = 0
        return true, false
    end

    local weight = ctx.rate_weight or 1.0
    local ip     = ctx.ip or "?"
    local id     = ensure_identity(ctx)

    weight = maybe_discount_for_retry(ctx, weight)

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[counter] redis unavailable: ", err)
        ctx.rate    = 0
        ctx.ip_rate = 0
        ctx.burst   = 0
        return true, false
    end

    red:init_pipeline()

    red:incrbyfloat("rl:" .. ip, weight)
    red:expire("rl:" .. ip, TTL)

    if id then
        red:incrbyfloat("rl:" .. id, weight)
        red:expire("rl:" .. id, TTL)
    else
        red:get("__noop__")
        red:get("__noop__")
    end

    local res, perr = red:commit_pipeline()
    pool.put(red)

    if not res then
        ctx.rate    = 0
        ctx.ip_rate = 0
        ctx.burst   = 0
        ngx.log(ngx.WARN, "[counter] pipeline error: ", tostring(perr))
        return true, false
    end

    local ip_rate = tonumber(res[1]) or 0
    local id_rate = id and (tonumber(res[3]) or 0) or 0

    ctx.ip_rate = ip_rate
    ctx.rate    = id_rate

    local burst_thresh = cfg.rate.burst_threshold or 30
    ctx.burst = (ctx.rate / TTL) > (burst_thresh / 60) and 1 or 0

    ngx.log(ngx.DEBUG,
        "[counter] class=", ctx.req_class or "?",
        " ip=", ip,
        " id_rate=", id_rate,
        " ip_rate=", ip_rate,
        " weight=", weight,
        " burst=", ctx.burst)

    return true, false
end

return _M
