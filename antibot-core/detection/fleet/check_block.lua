local _M   = {}
local pool = require "antibot.core.redis_pool"

-- Fleet dynamic-block enforcement check.
--
-- Runs as the FIRST step inside STEPS_COMMON (right after ctx_layer.init,
-- before the fleet aggregator) so blocked requests cost only 1 Redis RTT
-- and never touch session/ban/transport/score pipelines.
--
-- Reads two keys per request via a single Redis pipeline (GET x2):
--   fl:dyn:<cidr_24>   written by analyzer.update_sustained() after a /24
--                      stays "confirm" for cfg.enforce.sustained_minutes.
--   fl:dyn:<cidr_16>   written by analyzer when rollup count >= rollup.min.
--
-- Either present → ngx.exit(444) with `action_reason = fleet_dyn_block_<24|16>:<cidr>`
-- and `ctx.fleet_blocked = matched_cidr` for downstream logging.
--
-- Why 444 (nginx-specific TCP RST) instead of 403:
--   - Subnet block is a NETWORK-LEVEL decision, not a per-request decision.
--     RST matches the semantic "this network endpoint is not for you".
--   - ~15x bandwidth saving: no response headers, no body, single RST
--     packet vs full HTTP teardown (FIN ack + payload + content-length).
--   - Avoids TIME_WAIT socket accumulation under sustained block load.
--   - Crawler interpretation: bots typically treat persistent connection
--     resets as "host unreachable" and drop URLs from queue, while 403
--     reads as "try again later" and invites retry cycles.
--   - SEO risk if accidentally applied to search engines (Google may
--     deindex on persistent RST) — empirically not an issue because
--     Googlebot/Bingbot distribute traffic across many /16 and never
--     cross fleet thresholds; if it ever happens, operator catches via
--     Search Console "URL unreachable" and DELs the dyn key in minutes.
--
-- Enforcement is independent of `cfg.fleet_detection.mode`: if dyn keys
-- exist they are honored, even if mode is later flipped back to "shadow".
-- Keys carry their own TTL (cfg.timing.dyn_block_ttl, default 1h) so a
-- false dyn block self-heals; operator can also `DEL fl:dyn:<cidr>` to
-- revoke immediately.
--
-- Fail-open: any Redis error → return without blocking. Better to let a
-- known-fleet request through than to 403 all real users when Redis is
-- unreachable.

local function ip_to_cidr_24(ip)
    local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. "." .. c .. ".0/24"
end

local function ip_to_cidr_16(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. ".0.0/16"
end

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then return true, false end
    if ip == "127.0.0.1" then return true, false end
    if ip:find(":", 1, true) then return true, false end

    local cidr_24 = ip_to_cidr_24(ip)
    if not cidr_24 then return true, false end
    local cidr_16 = ip_to_cidr_16(ip)

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[fleet.check_block] redis err: ", tostring(err))
        return true, false
    end

    red:init_pipeline()
    red:get("fl:dyn:" .. cidr_24)
    if cidr_16 then red:get("fl:dyn:" .. cidr_16) end
    local res, perr = red:commit_pipeline()
    pool.put(red)
    if not res then
        ngx.log(ngx.WARN, "[fleet.check_block] pipeline err: ", tostring(perr))
        return true, false
    end

    local function val(x)
        if x == nil or x == ngx.null then return nil end
        return x
    end

    local v24 = val(res[1])
    local v16 = cidr_16 and val(res[2]) or nil
    if not v24 and not v16 then return true, false end

    local matched, scope, info
    if v24 then matched, scope, info = cidr_24, "24", v24
    else        matched, scope, info = cidr_16, "16", v16 end

    ctx.action = "block"
    ctx.action_reason   = "fleet_dyn_block_" .. scope .. ":" .. matched
    ctx.fleet_blocked   = matched
    ctx.fleet_block_info = info

    ngx.log(ngx.WARN,
        "[fleet.check_block] blocked ip=", ip,
        " match=", matched,
        " scope=/", scope,
        " info=", tostring(info))

    -- TCP RST without HTTP response. See header comment for rationale.
    ngx.exit(444)
    return true, true
end

return _M
