local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- adaptive_limit — per-IP rate decisions in two tiers (hybrid model).
--
-- Tier 1 (SIGNAL): ip_rate > cfg.rate.ip_surge_threshold (~25 req/s).
--   Sets ctx.ip_surge=true → contributes weight in intelligence/scoring/compute.
--   Engine decides via aggregate score, not a unilateral ban. Real users with
--   extension/multi-tab/AI-agent activity can briefly exceed this threshold;
--   their clean browser fingerprint keeps total score below action threshold.
--
-- Tier 2 (HARD BAN): ip_rate > cfg.rate.ip_surge_extreme (~83 req/s)
--   AND distinct identities seen from this IP < cfg.rate.ip_surge_distinct_min.
--   Implausible rate for a single host of legitimate browsing, gated by NAT
--   sanity check — CGNAT/office shared IP carries many distinct identities
--   so escapes the hard-ban path.
--
-- TTL for hard ban is short (cfg.rate.ip_surge_ban_ttl, default 300s) so a
-- mis-tune auto-recovers; repeat surge re-bans naturally.
--
-- Identity tracking is fed by counter.lua (SADD rate:ids:<ip> per request).
--
-- Previous version (pre-hybrid) hard-banned on ip_surge_threshold alone with
-- 1800s TTL. False-positive on:
--   - User installing/testing browser extensions (Claude Code, ad-blockers,
--     screenshot tools) — initial 60s of activity often spikes 1000-1500 req
--   - NAT with multiple active users (office, Vietnam mobile carrier CGNAT)
--   - Power users with 5+ tabs of e-commerce product pages (each ~50 resources)
-- See update log in antibot-core/CLAUDE.md for the incident that motivated
-- this rewrite (IP 118.70.131.98 banned via Claude Code extension first-run).

function _M.run(ctx)
    local base   = cfg.rate.base_threshold
    local risk   = ctx.ip_score or 0
    local thresh = math.floor(base * (1.0 - risk * cfg.rate.risk_factor))

    local id_rate = ctx.rate    or 0
    local ip_rate = ctx.ip_rate or 0

    ctx.rate_flag = id_rate > thresh

    local ip_surge_thresh = cfg.rate.ip_surge_threshold or (base * 5)
    ctx.ip_surge = ip_rate > ip_surge_thresh

    if ctx.rate_flag then
        ngx.log(ngx.INFO,
            "[rate] id violation id_rate=", id_rate,
            " thresh=", thresh,
            " ip=", ctx.ip)
        local id = ctx.identity or ctx.fp_light
        if id then
            ngx.timer.at(0, function()
                local r = pool.get()
                if r then
                    r:incr("viol:" .. id)
                    r:expire("viol:" .. id, cfg.ttl.violation)
                    pool.put(r)
                end
            end)
        end
    end

    if ctx.ip_surge and not ctx.rate_flag then
        ngx.log(ngx.INFO,
            "[rate] ip surge ip_rate=", ip_rate,
            " thresh=", ip_surge_thresh,
            " ip=", ctx.ip,
            " (shared IP, identity rate ok)")
    end

    -- Tier 2 hard-ban: only when extreme rate AND single-source surge.
    -- Both gates must trip together — extreme rate alone could be CGNAT
    -- aggregate, low diversity alone is normal for single-user.
    if ctx.ip_surge
       and ctx.ip and ctx.ip ~= ""
       and ip_rate > (cfg.rate.ip_surge_extreme or 5000)
    then
        local distinct = pool.safe_scard("rate:ids:" .. ctx.ip) or 0
        local distinct_min = cfg.rate.ip_surge_distinct_min or 3
        if distinct < distinct_min then
            local ttl = cfg.rate.ip_surge_ban_ttl or 300
            pool.safe_set("ban:" .. ctx.ip, "1", ttl)
            pool.safe_set("ban:hit:" .. ctx.ip, tostring(ngx.time()), 300)
            ngx.log(ngx.WARN,
                "[rate] HARD BAN ip_surge_extreme",
                " ip=", ctx.ip,
                " ip_rate=", ip_rate,
                " extreme_thresh=", cfg.rate.ip_surge_extreme,
                " distinct=", distinct,
                " distinct_min=", distinct_min,
                " ttl=", ttl, "s")
        else
            ngx.log(ngx.WARN,
                "[rate] ip_surge_extreme suppressed (NAT diversity)",
                " ip=", ctx.ip,
                " ip_rate=", ip_rate,
                " distinct=", distinct,
                " distinct_min=", distinct_min)
        end
    end
end

return _M
