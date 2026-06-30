local _M = {}

local pool       = require "antibot.core.redis_pool"
local intel_pool = require "antibot.core.redis_intel_pool"

-- check: reads cross-server IP reputation into ctx.ext_rep ∈ [0,1].
--
-- Fast path: local Redis "iprep:local:<ip>" (1h cache, ~0.1ms).
-- Slow path: Central Redis "iprep:known_bad:<ip>" on cache miss (~5-20ms).
-- Fail open: Central Redis unreachable → ctx.ext_rep = 0, pipeline continues.
function _M.check(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then
        ctx.ext_rep = 0
        return true
    end

    local c = require("antibot.core.config").intel
    if not c or not c.enabled then
        ctx.ext_rep = 0
        return true
    end

    -- Fast path: local 1h cache
    local cached = pool.safe_get("iprep:local:" .. ip)
    if cached ~= nil then
        ctx.ext_rep = tonumber(cached) or 0
        return true
    end

    -- Slow path: Central Redis
    local val, err = intel_pool.safe_get("iprep:known_bad:" .. ip)
    if err and err ~= "intel disabled" then
        ngx.log(ngx.WARN, "[iprep] central read err: ", tostring(err))
    end

    local score = val and math.min(1.0, tonumber(val) or 0.0) or 0.0

    -- Cache locally (writes "0.00" for clean IPs to avoid repeated central checks)
    pool.safe_set("iprep:local:" .. ip, string.format("%.2f", score), c.local_cache_ttl)

    ctx.ext_rep = score
    return true
end

return _M
