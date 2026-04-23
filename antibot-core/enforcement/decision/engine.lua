local _M = {}
local cfg  = require "antibot.core.config"
local pool = require "antibot.core.redis_pool"

local T = {
    MONITOR   = 25,
    CHALLENGE = 55,
    BLOCK     = 80,
}

local RESOURCE_MAX_SCORE = 40
local RESOURCE_BOOST_MAX = 15

local KILL_CHALLENGE_RAW = 80
local KILL_BLOCK_RAW     = 95

local KILL_CHALLENGE_EFF = 60
local KILL_BLOCK_EFF     = 85

local FP_DEGRADED_PENALTY  = 5
local FP_QUALITY_PENALTY   = 3
local FP_QUALITY_THRESHOLD = 0.5
-- JA3_PARTIAL_PENALTY = 0 vì kiến trúc no-stream không bao giờ capture được
-- cipher list → ja3_partial = true là CONSTANT của kiến trúc, không phải
-- signal detect bot. Penalty cũ = 2 áp lên MỌI request HTTPS legit → không
-- mang thông tin hữu ích. 3 signal khác (chrome+no_h2, chrome+tls12,
-- h2_tls_mismatch) đủ đánh bot dùng JA3/TLS mismatch.
local JA3_PARTIAL_PENALTY  = 0

-- Attack 1 — UA switching:
-- Nếu IP đã có ip_risk cao (từ identity trước đó bị challenge/block),
-- hạ threshold challenge để bắt identity mới từ cùng IP.
local IP_RISK_THRESHOLD_LOWER = 0.4  -- ip_risk > 0.4 → hạ threshold
local IP_RISK_CHALLENGE_CAP   = 40   -- threshold mới khi ip_risk cao

local function calc_resource_boost(raw_score)
    if raw_score < T.MONITOR then return 0 end
    return (raw_score / 100) * RESOURCE_BOOST_MAX
end

local function calc_fp_penalty(ctx)
    local class = ctx.req_class or "navigation"

    if class == "resource" then
        return ctx.ja3_partial and JA3_PARTIAL_PENALTY or 0
    end

    local scale   = (class == "interaction" or class == "api_callback") and 0.5 or 1.0
    local penalty = 0

    if ctx.fp_degraded then
        penalty = penalty + FP_DEGRADED_PENALTY * scale
    elseif (ctx.fp_quality or 1.0) < FP_QUALITY_THRESHOLD then
        penalty = penalty + FP_QUALITY_PENALTY * scale
    end

    if ctx.ja3_partial then
        penalty = penalty + JA3_PARTIAL_PENALTY * scale
    end

    return penalty
end

local function calc_trust_multiplier(ctx)
    local trust     = cfg.trust
    local sess_len  = ctx.sess_len  or 0
    local sess_flag = ctx.session_flag or 0.0
    local class     = ctx.req_class or "navigation"

    if class == "api_callback" or class == "unknown" then
        return 1.0, nil
    end

    if sess_len <= 0 then return 1.0, nil end
    if sess_flag >= trust.session_flag_max then return 1.0, nil end

    if sess_len >= trust.session_min then
        return trust.score_multiplier, "trusted_session"
    end

    if sess_len >= trust.session_active_min then
        return trust.score_mult_active, "active_session"
    end

    return 1.0, nil
end

-- Attack 1: đọc ip_risk để điều chỉnh threshold
local function get_ip_risk(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return 0.0
    end
    -- ip_risk đã được đọc trong ip_reputation.lua → dùng ctx.ip_risk
    return ctx.ip_risk or 0.0
end

function _M.run(ctx)
    if ctx.whitelisted == true then
        ctx.action = "allow"
        return "allow"
    end

    -- DNS-verified good bot (Googlebot, AdsBot, facebookexternalhit, …):
    -- reverse PTR + forward A/AAAA đã match — không thể forge.
    -- JA3/H2/entropy signals chắc chắn fire cho mọi bot thật → bypass scoring.
    if ctx.good_bot_verified == true then
        ctx.action        = "allow"
        ctx.action_reason = "good_bot_verified"
        return "allow"
    end

    local raw_score  = ctx.score or 0
    local multiplier = ctx.score_multiplier or 1.0
    local class      = ctx.req_class or "navigation"

    local trust_mult, trust_reason = calc_trust_multiplier(ctx)
    if trust_mult < 1.0 then
        multiplier = multiplier * trust_mult
        ctx.trust_reason = trust_reason
    end

    local effective_score = raw_score * multiplier

    local fp_penalty = calc_fp_penalty(ctx)
    effective_score = effective_score + fp_penalty

    local kill_reason = nil
    if class == "resource" then
        local boost = calc_resource_boost(raw_score)
        effective_score = effective_score + boost

        if effective_score > RESOURCE_MAX_SCORE then
            effective_score = RESOURCE_MAX_SCORE
        end

        if raw_score >= KILL_BLOCK_RAW then
            if effective_score < KILL_BLOCK_EFF then
                effective_score = KILL_BLOCK_EFF
                kill_reason     = "kill_block"
            end
        elseif raw_score >= KILL_CHALLENGE_RAW then
            if effective_score < KILL_CHALLENGE_EFF then
                effective_score = KILL_CHALLENGE_EFF
                kill_reason     = "kill_challenge"
            end
        end
    end

    ctx.effective_score = math.max(0, effective_score)
    ctx.kill_reason     = kill_reason

    -- Attack 1 — dynamic threshold dựa trên ip_risk
    local challenge_threshold = T.CHALLENGE
    local ip_risk = get_ip_risk(ctx)
    if ip_risk >= IP_RISK_THRESHOLD_LOWER and class ~= "api_callback" then
        challenge_threshold = IP_RISK_CHALLENGE_CAP
        ctx.ip_risk_lowered = true
        ngx.log(ngx.DEBUG,
            "[engine] ip_risk lowered threshold ip=", ctx.ip or "?",
            " ip_risk=", string.format("%.2f", ip_risk),
            " threshold=", challenge_threshold)
    end

    local s = ctx.effective_score
    local action

    if s >= T.BLOCK then
        action = "block"
    elseif s >= challenge_threshold then
        action = "challenge"
    elseif s >= T.MONITOR then
        action = "monitor"
        ctx.monitor_flag = true
    else
        action = "allow"
    end

    -- Trust cap
    if trust_reason and action == "challenge" then
        local cap = cfg.trust.action_cap or "monitor"
        ngx.log(ngx.INFO,
            "[engine] trust cap reason=", trust_reason,
            " action=", action, "->", cap,
            " eff=", math.floor(ctx.effective_score),
            " ip=", ctx.ip or "?")
        action = cap
        ctx.monitor_flag = true
    end

    ctx.action = action

    if kill_reason then
        ngx.log(ngx.WARN,
            "[engine] kill-switch=", kill_reason,
            " raw=", math.floor(raw_score),
            " eff=", math.floor(ctx.effective_score),
            " action=", action,
            " ip=", ctx.ip or "?",
            " uri=", ngx.var.uri or "?")
    end

    if ngx.var.antibot_debug == "1" then
        ngx.header["X-Bot-Score"]    = tostring(math.floor(s))
        ngx.header["X-Bot-Raw"]      = tostring(math.floor(raw_score))
        ngx.header["X-Bot-Mult"]     = tostring(multiplier)
        ngx.header["X-Bot-Penalty"]  = tostring(fp_penalty)
        ngx.header["X-Bot-Action"]   = action
        ngx.header["X-Bot-Reason"]   = ctx.action_reason or ""
        ngx.header["X-Bot-Kill"]     = kill_reason or "none"
        ngx.header["X-Bot-FP"]       = ctx.fp_light or "nil"
        ngx.header["X-Bot-Class"]    = class
        ngx.header["X-Bot-FPDeg"]    = ctx.fp_degraded and "1" or "0"
        ngx.header["X-Bot-FPQual"]   = ctx.fp_quality and
                                        string.format("%.2f", ctx.fp_quality) or "nil"
        ngx.header["X-Bot-Trust"]    = trust_reason or "none"
        ngx.header["X-Bot-SessLen"]  = tostring(ctx.sess_len or 0)
        ngx.header["X-Bot-IpRisk"]     = string.format("%.2f", ip_risk)
        ngx.header["X-Bot-HeaderFlag"] = string.format("%.3f", ctx.header_flag or 0)
        ngx.header["X-Bot-UAFlag"]     = string.format("%.3f", ctx.ua_flag or 0)
        ngx.header["X-Bot-DevType"]    = tostring(ctx.device_type or "-")
        ngx.header["X-Bot-TLS13"]      = ctx.tls13 == true  and "1"
                                      or ctx.tls13 == false and "0" or "-"
        ngx.header["X-Bot-JA3Partial"] = ctx.ja3_partial == true  and "1"
                                      or ctx.ja3_partial == false and "0" or "-"
        if ctx.top_signals and ctx.top_signals[1] then
            ngx.header["X-Bot-TopSignal"] = string.format("%s=%d%%",
                ctx.top_signals[1].signal,
                ctx.top_signals[1].contribution_pct)
        end
    end

    return action
end

function _M.thresholds()
    return { monitor=T.MONITOR, challenge=T.CHALLENGE, block=T.BLOCK }
end

return _M
