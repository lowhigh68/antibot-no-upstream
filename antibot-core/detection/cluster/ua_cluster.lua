local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local GENERIC = { Chrome=true, Firefox=true, Safari=true, Edge=true, Opera=true }

local function normalize_ua(ua)
    if not ua or ua == "" then return "EMPTY_UA" end
    return ua:gsub("/%d+[%d%.]*", ""):gsub("%s+", " "):sub(1, 200)
end

function _M.run(ctx)
    local ua   = ctx.ua or ""
    local norm = normalize_ua(ua)
    local hash = ngx.md5(norm)

    ctx.baseline_ua = false
    for browser in pairs(GENERIC) do
        if ua:find(browser, 1, true) then
            ctx.baseline_ua = true; break
        end
    end

    local key = "cluster:ua:" .. hash
    local ttl = 600

    local count = pool.safe_incr(key, ttl) or 0

    local mult  = ctx.baseline_ua and cfg.cluster.ua_baseline_threshold_mult or 1
    local limit = cfg.cluster.ua_count_normalize_max * mult
    ctx.ua_cluster = math.min(count, limit)
end

return _M
