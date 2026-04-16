local _M = {}

local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local DECAY_FACTOR         = 0.95
local RISE_FACTOR_NAVIGATE = 0.30
local RISE_FACTOR_INTERACT = 0.15
local MIN_RISK_STORE       = 0.01

-- Attack 1 — UA switching / cloaking:
-- Identity = md5(ip+ua). Changing UA → new identity, risk resets to 0.
-- Fix: track ip_risk:{ip} in parallel with risk:{id}.
-- Bot gets challenged → ip_risk rises → that IP is flagged even with a new
-- identity (new UA). ip_risk decays faster than identity risk to avoid
-- false positives for VPN users who switch servers.

local IP_RISK_DECAY        = 0.85   -- faster decay than identity risk
local IP_RISK_RISE         = 0.20   -- slower rise than identity risk
local IP_RISK_TTL          = 3600   -- 1 hour (shorter than identity TTL)
local MIN_IP_RISK_STORE    = 0.01

-- Network resilience — ip_risk guard for packet loss / reconnect scenarios:
--
-- Problem: when a mobile user experiences packet loss or network reconnect,
-- the browser retries requests automatically. These retries arrive with
-- partial/missing headers (TCP reassembly issues), triggering anomaly_score.
-- The resulting challenge/block causes ip_risk to rise, which then blocks
-- the same user after reconnect with a new IP.
--
-- Solution: only raise ip_risk when COMPOUND evidence of bot behaviour is
-- present. A single anomaly_score spike from a bad network is NOT sufficient.
-- Required conditions to raise ip_risk:
--   1. action is "challenge" or "block" (not monitor or allow)
--   2. bot_score > BOT_SCORE_GUARD: genuine bot UA/structural signal
--   3. NOT verified: already-verified sessions should never raise ip_risk
--   4. NOT resource class: static asset requests are noise
--   5. NOT api_callback: payment gateways, webhooks (server-to-server)
--
-- When ctx.verified=true (user passed PoW), identity risk decays with
-- an accelerated factor (VERIFIED_DECAY) to quickly clear any ip_risk
-- that accumulated during the network instability period.

local BOT_SCORE_GUARD  = 0.3    -- minimum bot_score to raise ip_risk
local VERIFIED_DECAY   = 0.50   -- fast decay for verified users (vs 0.85)

local function should_raise_ip_risk(ctx, action, class)
    -- Must be an adversarial action
    if action ~= "challenge" and action ~= "block" then
        return false
    end
    -- Already-verified sessions should not raise ip_risk (network issue FP)
    if ctx.verified then
        return false
    end
    -- Resource and callback classes are excluded
    if class == "resource" or class == "api_callback" then
        return false
    end
    -- Require compound bot evidence — pure anomaly/rate from network issues
    -- is not enough on its own
    local bot_score = ctx.bot_score or 0.0
    if bot_score < BOT_SCORE_GUARD then
        return false
    end
    return true
end

function _M.run(ctx)
    local id    = ctx.identity
    local class = ctx.req_class or "unknown"

    if not id or class == "resource" then
        return
    end

    local score    = ctx.score  or 0
    local action   = ctx.action or "allow"
    local ip       = ctx.ip or ""
    local verified = ctx.verified or false

    local rise_factor = class == "interaction"
        and RISE_FACTOR_INTERACT
        or  RISE_FACTOR_NAVIGATE

    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end

        -- ── Identity risk ──────────────────────────────────────
        local current = tonumber(red:get("risk:" .. id)) or 0.0
        local new_risk

        if action == "allow" or action == "monitor" then
            -- Verified users decay faster: reconnecting with a valid session
            -- after network disruption should clear accumulated risk quickly.
            local decay = verified and VERIFIED_DECAY or DECAY_FACTOR
            new_risk = current * decay
        else
            new_risk = current * (1 - rise_factor)
                     + (score / 100) * rise_factor
        end

        new_risk = math.max(0.0, math.min(1.0, new_risk))

        if new_risk > MIN_RISK_STORE then
            red:setex("risk:" .. id, cfg.ttl.risk,
                      string.format("%.4f", new_risk))
        else
            red:del("risk:" .. id)
        end

        -- ── IP-level risk (Attack 1 + network resilience) ──────
        -- Only update for valid, non-local IPs.
        if ip ~= "" and ip ~= "127.0.0.1" and ip ~= "::1" then

            local ip_cur = tonumber(red:get("ip_risk:" .. ip)) or 0.0
            local ip_new

            if action == "allow" or action == "monitor" then
                -- Verified users: fast decay clears network-instability
                -- false positives after successful reconnect.
                local decay = verified and VERIFIED_DECAY or IP_RISK_DECAY
                ip_new = ip_cur * decay
            elseif should_raise_ip_risk(ctx, action, class) then
                -- Compound bot evidence confirmed — raise ip_risk.
                ip_new = ip_cur * (1 - IP_RISK_RISE)
                       + (score / 100) * IP_RISK_RISE
            else
                -- Adversarial action but insufficient compound evidence
                -- (e.g. challenge triggered by anomaly_score alone, likely
                -- a network-related false positive). Decay gently instead
                -- of raising, to avoid penalising the IP.
                ip_new = ip_cur * IP_RISK_DECAY
                ngx.log(ngx.DEBUG,
                    "[risk_update] ip_risk guard skipped raise ip=", ip,
                    " action=", action,
                    " bot_score=", string.format("%.3f", ctx.bot_score or 0),
                    " verified=", tostring(verified))
            end

            ip_new = math.max(0.0, math.min(1.0, ip_new))

            if ip_new > MIN_IP_RISK_STORE then
                red:setex("ip_risk:" .. ip, IP_RISK_TTL,
                          string.format("%.4f", ip_new))
            else
                red:del("ip_risk:" .. ip)
            end

            if math.abs(ip_new - ip_cur) > 0.01 then
                ngx.log(ngx.DEBUG,
                    "[risk_update] ip_risk ip=", ip,
                    " prev=",   string.format("%.3f", ip_cur),
                    " new=",    string.format("%.3f", ip_new),
                    " action=", action,
                    " verified=", tostring(verified))
            end
        end

        pool.put(red)

        ngx.log(ngx.DEBUG,
            "[risk_update]",
            " class=",   class,
            " id=",      id:sub(1, 8), "...",
            " prev=",    string.format("%.3f", current),
            " new=",     string.format("%.3f", new_risk),
            " action=",  action,
            " verified=", tostring(verified))
    end)
end

return _M
