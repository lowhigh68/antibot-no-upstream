local _M = {}
local cfg  = require "antibot.core.config"
local pool = require "antibot.core.redis_pool"

-- ============================================================
-- Good-bot expensive-request throttle (Hybrid scoring)
-- ============================================================
-- Verified bots (Bingbot/Meta/Googlebot/...) hammer expensive query
-- patterns: WooCommerce filter facets, search forms, faceted nav,
-- deep pagination. Combinatorial → uncacheable → backend overload.
--
-- Strategy 3 layers:
--   1. HARD threshold (qs_len ≥ 200 OR params ≥ 8) → undeniable
--      abuse. Counts toward RPM immediately.
--   2. SOFT scoring (weighted sum of 4 sub-signals) ≥ 0.7 → compound
--      subtle expensive cases. Also counts toward RPM.
--   3. RPM gate (8 expensive request / minute / bot_name): chỉ thực
--      sự throttle khi đã vượt budget. Request expensive đầu phút
--      vẫn pass — bot có headroom crawl normally.
--
-- Action: "throttled" (action mới, không trùng block/challenge/monitor).
-- Status 429 + Retry-After 120s. Bot SDK respect → backoff → quay lại.
-- Không escalate viol, không penalty SEO ranking.
--
-- Sub-signal contributions sum max ≈ 1.45, dư đệm cho borderline cases.
-- All thresholds in-code constants — git history tracks tuning.
--
-- Vietnamese URL handled natively: UTF-8 encoding inflates qs_len bytes,
-- không cần locale-aware logic. Single Vietnamese search vẫn pass; chỉ
-- combo (search + filter + page) mới đủ score.

-- HARD thresholds — single signal đủ kết luận expensive
local HARD_QS_LEN          = 200
local HARD_PARAM_COUNT     = 8

-- SOFT scoring threshold
local SOFT_SCORE_THRESHOLD = 0.7

-- RPM gate
local GOOD_BOT_RPM         = 8
local GOOD_BOT_RETRY_AFTER = 120

-- Generic verified good-bot rate ceiling with adaptive class promotion.
-- Replaces the ad-hoc per-ASN Meta limit (was `throttle_meta_asn`).
-- Industry pattern (Cloudflare Bot Categories, Akamai Crawler Profiles).
--
-- Config lives in cfg.rate.good_bot_rate (core/config.lua):
--   classes:  per-class req/min ceiling (polite/moderate/aggressive/default)
--   map:      bot_name -> class (small finite list of known verified bots)
--   thresholds: adaptive promotion ladder
--
-- Adaptive promotion: every 429 increments `gb_aggression:<bot>` (TTL 600s
-- = 10-min sliding window via TTL refresh, same pattern as ip_risk). When
-- aggression crosses threshold, effective_class steps up:
--   < 10            -> base class
--   >= 10           -> +1 tier
--   >= 30           -> +2 tier (skip straight to aggressive)
-- Bot quiet 10 min -> aggression key expires -> class restored to base.
local CLASS_LADDER  = { polite = 1, moderate = 2, aggressive = 3 }
local CLASS_LABELS  = { "polite", "moderate", "aggressive" }

-- Sub-signal contributions (graduated, none alone is sufficient)
local CONTRIB_QS_LEN_120 = 0.50
local CONTRIB_QS_LEN_80  = 0.35
local CONTRIB_QS_LEN_40  = 0.15
local CONTRIB_PARAM_5    = 0.40
local CONTRIB_PARAM_3    = 0.20
local CONTRIB_COMMA_4    = 0.40
local CONTRIB_COMMA_2    = 0.25
local CONTRIB_COMMA_1    = 0.10
local CONTRIB_SEARCH     = 0.15

local function expensive_score(qs)
    local s = 0.0

    -- 1. Query string length (graduated)
    local len = #qs
    if     len >= 120 then s = s + CONTRIB_QS_LEN_120
    elseif len >= 80  then s = s + CONTRIB_QS_LEN_80
    elseif len >= 40  then s = s + CONTRIB_QS_LEN_40
    end

    -- 2. Parameter count (graduated)
    local pc = 1
    for _ in qs:gmatch("&") do pc = pc + 1 end
    if     pc >= 5 then s = s + CONTRIB_PARAM_5
    elseif pc >= 3 then s = s + CONTRIB_PARAM_3
    end

    -- 3. Comma density (multi-value combinatorial — both raw `,` and `%2C`)
    local commas = 0
    for _ in qs:gmatch(",")        do commas = commas + 1 end
    for _ in qs:gmatch("%%2[Cc]")  do commas = commas + 1 end
    if     commas >= 4 then s = s + CONTRIB_COMMA_4
    elseif commas >= 2 then s = s + CONTRIB_COMMA_2
    elseif commas >= 1 then s = s + CONTRIB_COMMA_1
    end

    -- 4. Search-term hint (lenient — single short Vietnamese search vẫn pass)
    if qs:find("+", 1, true) or qs:find("%20", 1, true) then
        s = s + CONTRIB_SEARCH
    end

    return s
end

-- effective_class: resolve base class -> effective class via adaptive promotion.
-- Reads `gb_aggression:<bot>` (Redis counter, TTL self-decay).
-- Returns (effective_class_label, aggression_score).
local function effective_class(bot)
    local conf       = cfg.rate.good_bot_rate
    local base_class = conf.map[bot] or "default"
    local agg        = tonumber(pool.safe_get("gb_aggression:" .. bot)) or 0

    if agg < conf.promotion_threshold_1 then
        return base_class, agg, base_class
    end

    -- "default" class falls under moderate semantics for promotion ladder
    local base_for_ladder = (base_class == "default") and "moderate" or base_class
    local base_idx        = CLASS_LADDER[base_for_ladder] or 2
    local promotion       = (agg >= conf.promotion_threshold_2) and 2 or 1
    local new_idx         = math.min(3, base_idx + promotion)
    return CLASS_LABELS[new_idx], agg, base_class
end

local function throttle_good_bot_rate(ctx)
    local bot                       = ctx.good_bot_name or "unknown"
    local conf                      = cfg.rate.good_bot_rate
    local eff_class, agg, base_class = effective_class(bot)
    local limit                     = conf.classes[eff_class] or conf.classes.default

    -- Expose to logger/explain for debugging (always, not just on throttle)
    ctx.good_bot_class_base = base_class
    ctx.good_bot_class      = eff_class
    ctx.good_bot_aggression = agg
    ctx.good_bot_rate_limit = limit

    local minute = math.floor(ngx.time() / 60)
    local key    = "gb_rate:" .. bot .. ":" .. minute
    local count  = pool.safe_incr(key, 65) or 0
    ctx.good_bot_rate_count = count

    if count <= limit then return false end

    -- Violation -> tăng aggression score (TTL self-decay = sliding window)
    pool.safe_incr("gb_aggression:" .. bot, conf.aggression_decay_ttl)

    ctx.action        = "throttled"
    ctx.action_reason = "good_bot_rate_" .. eff_class

    ngx.log(ngx.WARN,
        "[engine] good_bot rate exceeded",
        " bot=", bot,
        " base_class=", base_class,
        " effective_class=", eff_class,
        " aggression=", agg,
        " count=", count, "/min",
        " limit=", limit,
        " ip=", ctx.ip or "?")

    ngx.status = 429
    ngx.header["Retry-After"]   = tostring(conf.retry_after)
    ngx.header["Cache-Control"] = "no-cache"
    ngx.header["Content-Type"]  = "text/plain"
    ngx.say("Rate limited — retry after ", conf.retry_after, "s")
    ngx.exit(429)
    return true
end

local function classify_request(qs)
    -- HARD short-circuit: undeniable abuse
    if #qs >= HARD_QS_LEN then
        return true, "hard_qs_len", 1.0
    end
    local pc = 1
    for _ in qs:gmatch("&") do pc = pc + 1 end
    if pc >= HARD_PARAM_COUNT then
        return true, "hard_param_count", 1.0
    end

    -- SOFT scoring
    local s = expensive_score(qs)
    if s >= SOFT_SCORE_THRESHOLD then
        return true, "soft_score", s
    end
    return false, nil, s
end

local function throttle_good_bot(ctx)
    local req = ctx.req or {}

    -- Chỉ GET mới throttle (POST thường có CSRF/nonce protection)
    if (req.method or "GET") ~= "GET" then return false end

    local uri = req.uri or ""
    local qmark = uri:find("?", 1, true)
    if not qmark then return false end
    local qs = uri:sub(qmark + 1)
    if qs == "" then return false end

    local expensive, trigger, score = classify_request(qs)
    if not expensive then return false end

    -- RPM gate per bot_name + minute window
    local bot = ctx.good_bot_name or "unknown"
    local minute = math.floor(ngx.time() / 60)
    local key = "gb_throttle:" .. bot .. ":" .. minute
    local count = pool.safe_incr(key, 65) or 0   -- 65s TTL > 60s window

    -- Trong budget — allow nhưng đã tính cho RPM. Bot vẫn được fetch
    -- vài expensive URL đầu phút normal speed.
    if count <= GOOD_BOT_RPM then
        ctx.expensive_score   = score
        ctx.expensive_trigger = trigger
        return false
    end

    -- Vượt budget → 429
    ctx.action        = "throttled"
    ctx.action_reason = "good_bot_throttled"
    ctx.expensive_score   = score
    ctx.expensive_trigger = trigger

    ngx.log(ngx.WARN,
        "[engine] good_bot throttled bot=", bot,
        " trigger=", trigger,
        " score=", string.format("%.2f", score),
        " count=", count, "/min",
        " uri=", uri:sub(1, 80),
        " ip=", ctx.ip or "?")

    ngx.status = 429
    ngx.header["Retry-After"]   = tostring(GOOD_BOT_RETRY_AFTER)
    ngx.header["Cache-Control"] = "no-cache"
    ngx.header["Content-Type"]  = "text/plain"
    ngx.say("Rate limited — please retry after ",
            GOOD_BOT_RETRY_AFTER, "s")
    ngx.exit(429)
    return true
end

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

-- Generic kill-switch cho mọi dampened class KHÁC resource (resource đã có
-- kill riêng ở trên với threshold thấp hơn do mult=0.2). Áp dụng cho
-- interaction (0.6), api_callback (0.5), feed_or_meta (0.4), inapp_browser
-- (0.4), unknown (0.5) — tất cả classes có score_multiplier < 1.0.
--
-- Lý do tồn tại: dampening class mult được thiết kế để giảm FP cho normal
-- traffic. Nhưng khi raw_score cực cao (≥110), đây không còn là normal —
-- pure threat signal storm. Dampening "che chở" sai cho bot rõ ràng → bot
-- ở mãi challenge eff=70 không lên được block 80 (incident 20.9.70.139:
-- Azure UA-empty, raw 140 nhưng eff cap 70 → challenge mãi không block).
--
-- Threshold cao hơn resource kill (resource: raw 80/95) vì các class này
-- mult ít aggressive hơn (0.4-0.6 vs 0.2) → cần raw cao hơn mới cần kill.
--
-- raw ≥ 150 → floor 85% raw (signal storm — bot rõ ràng, near-full enforcement)
-- raw ≥ 110 → floor 65% raw (high signal — vẫn cần block path)
local KILL_DAMP_HARD_RAW = 150
local KILL_DAMP_SOFT_RAW = 110
local KILL_DAMP_HARD_PCT = 0.85
local KILL_DAMP_SOFT_PCT = 0.65

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
        ctx.action        = "allow"
        ctx.action_reason = ctx.action_reason or "whitelisted"
        return "allow"
    end

    -- DNS-verified good bot (Googlebot, AdsBot, facebookexternalhit, …):
    -- reverse PTR + forward A/AAAA đã match — không thể forge.
    -- JA3/H2/entropy signals chắc chắn fire cho mọi bot thật → bypass scoring.
    if ctx.good_bot_verified == true then
        -- Throttle expensive URLs (filter facets, price ranges) BEFORE allow.
        -- Bot SDK respect 429+Retry-After, không bị flag blocked, backend
        -- không bị flood combinatorial WP_Query.
        if throttle_good_bot(ctx) then
            return "throttled"
        end
        -- Generic verified-bot rate ceiling with adaptive class promotion.
        -- Replaces old Meta-specific per-ASN limit. Catches Meta + any
        -- verified bot exceeding its class ceiling. Aggression EMA promotes
        -- misbehaving bots toward `aggressive` class automatically.
        if throttle_good_bot_rate(ctx) then
            return "throttled"
        end
        ctx.action        = "allow"
        -- Giữ reason riêng nếu đã set (vd "good_bot_asn_lite" từ
        -- lite_verify) để antibot.log distinguish path verification.
        ctx.action_reason = ctx.action_reason or "good_bot_verified"
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
    elseif multiplier < 1.0 then
        -- Generic kill-switch cho dampened class non-resource. Khi raw_score
        -- cực cao, dampening "che chở" sai cho bot rõ ràng → áp floor theo
        -- % raw để escalation block path hoạt động.
        if raw_score >= KILL_DAMP_HARD_RAW then
            local floor = raw_score * KILL_DAMP_HARD_PCT
            if effective_score < floor then
                effective_score = floor
                kill_reason     = "kill_damp_hard"
            end
        elseif raw_score >= KILL_DAMP_SOFT_RAW then
            local floor = raw_score * KILL_DAMP_SOFT_PCT
            if effective_score < floor then
                effective_score = floor
                kill_reason     = "kill_damp_soft"
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

    -- S2.5 attest cap (Q17=b): contact-attested or analyzer-attested bots
    -- never become user-visible challenge/block. Bot SDKs don't execute JS
    -- → challenge=fail=effective_block, so capping at monitor is the only
    -- way "cap" actually prevents blocking. Cap at monitor also stops the
    -- risk:<id> EMA loop (async/risk_update decays on monitor/allow).
    -- bot_score=0 from S2.5 already prevents ip_risk:<ip> from rising via
    -- the existing bot_score>0.3 guard in risk_update.
    if ctx.bot_identity_tier == "S2.5"
       and (action == "block" or action == "challenge") then
        ngx.log(ngx.INFO,
            "[engine] S2.5 cap action=", action, "->monitor",
            " attest=", ctx.action_reason or "?",
            " eff=", math.floor(ctx.effective_score),
            " ip=", ctx.ip or "?")
        action = "monitor"
        ctx.action_reason = "s25_cap_monitor"
        ctx.monitor_flag  = true
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
