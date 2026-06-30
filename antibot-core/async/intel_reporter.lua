local _M = {}

local pool       = require "antibot.core.redis_pool"
local intel_pool = require "antibot.core.redis_intel_pool"

-- Reasons that indicate an OPERATIONAL ban (re-ban or fleet block),
-- not a new detection. These should NOT propagate to the intel network
-- because the source IP reputation is already known.
local EXCLUDED_REASONS = {
    banned_ip                = true,
    banned_id                = true,
    whitelisted              = true,
    good_bot_verified        = true,
    good_bot_asn_verified    = true,
    good_bot_asn_lite        = true,
    good_bot_rate_polite     = true,
    good_bot_rate_moderate   = true,
    good_bot_rate_aggressive = true,
}

local function qualifies(ctx, c)
    if not c or not c.enabled then return false end
    if ctx.action ~= "block" then return false end

    local reason = ctx.action_reason or ""

    -- Fleet dynamic blocks have variable suffix ("fleet_dyn_block_24:<cidr>")
    if reason:find("^fleet_dyn_block", 1, true) then return false end
    if EXCLUDED_REASONS[reason] then return false end

    -- engine BLOCK already implies effective_score >= 80 (T.BLOCK in engine.lua).
    -- min_score guard here is a safety net if thresholds change.
    if (ctx.effective_score or 0) < c.min_score then return false end

    return true
end

-- report: called from ngx.timer.at(0) in init.lua:_M.log() after a block.
-- Writes iprep:known_bad:<ip> to Central Redis.
-- Rate-limited to 1 report/IP/24h to avoid flooding the intel key on repeat attacks.
function _M.report(ctx)
    local c = require("antibot.core.config").intel
    if not qualifies(ctx, c) then return end

    local ip = ctx.ip
    if not ip or ip == "" then return end

    -- Rate limit: 1 report per IP per 24h (local Redis guard)
    local rate_key = "iprep:rate:" .. ip .. ":24h"
    if pool.safe_get(rate_key) then return end

    -- Write to Central Redis
    local ok, err = intel_pool.safe_set("iprep:known_bad:" .. ip, "1", c.known_bad_ttl)
    if not ok then
        if err ~= "intel disabled" then
            ngx.log(ngx.WARN, "[intel_reporter] write failed ip=", ip, " err=", tostring(err))
        end
        return
    end

    -- Mark rate limit (local, 24h)
    pool.safe_set(rate_key, "1", c.report_ttl)

    -- Immediately update local cache so THIS server also treats the IP as known-bad
    pool.safe_set("iprep:local:" .. ip, "1", c.local_cache_ttl)

    local host = (ctx.req and ctx.req.host) or "?"
    ngx.log(ngx.WARN,
        "[intel_reporter] reported",
        " ip=", ip,
        " eff=", math.floor(ctx.effective_score or 0),
        " reason=", ctx.action_reason or "?",
        " domain=", host,
        " server=", c.server_id or "?")
end

return _M
