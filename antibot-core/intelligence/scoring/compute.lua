local _M = {}
local pool = require "antibot.core.redis_pool"

local DEFAULT_WEIGHTS = {

    rate_flag           = 30,
    burst_flag          = 25,
    -- ip_surge: aggregate per-IP rate exceeded cfg.rate.ip_surge_threshold.
    -- Weight kept moderate — alone, ip_surge=1 contributes 25 toward MONITOR
    -- threshold (engine.lua T.MONITOR=25), not CHALLENGE (55) or BLOCK (80).
    -- A real bot at high rate usually also fires ua_flag/header_flag/cluster
    -- → combined score reaches block. A clean-fingerprint browser bursting
    -- briefly contributes ip_surge alone → stays at monitor → allowed.
    ip_surge            = 25,
    behavior_score      = 20,
    session_flag        = 20,
    graph_flag          = 20,

    bot_score           = 45,
    ua_flag             = 30,

    anomaly_score       = 35,

    ip_score            = 25,
    ip_rep              = 45,

    asn_rep             = 35,

    ip_risk             = 15,

    mismatch            = 55,
    risk                = 30,
    h2_bot_confidence   = 55,
    ja3_allowlist_miss  = 50,

    cluster_score       = 25,

    entropy_inv         = 35,

    canvas_change       = 50,
    fast_solve          = 25,

    resource_starved    = 30,

    -- session_richness: NEGATIVE weight = TRUST signal (trừ score).
    -- ctx.session_richness ∈ [0,1] đo client state với server (cookie payload,
    -- auth header). Logged-in user (r=0.8) trừ 24 pts → đẩy fresh-warmup
    -- FP (mismatch + h2_bot_confidence khi connection coalescing) dưới
    -- challenge threshold. Bot fake cookie vẫn phải qua anomaly/h2_bot/
    -- ip_score → không bypass detection.
    -- Lưu ý compute loop dưới: pts âm không vào top_signals (filter pts>0.5),
    -- nhưng vẫn trừ vào total. Antibot.log có field richness riêng để debug.
    session_richness    = -30,

    -- headless_score: JS beacon confirmed headless browser signals (webdriver,
    -- domAutomation, chrome.runtime absent). Weight 70 = single strong signal
    -- (wd=1 alone → 59.5 pts effective → CHALLENGE; wd+da → 70+ → near BLOCK).
    -- Only fires when ctx.beacon_received=true (JS ran → bot must execute JS).
    headless_score      = 70,

    -- ext_rep: cross-server IP reputation from Central Redis intel network.
    -- IPs confirmed blocked on ANY of the 15 servers (eff_score>=60, new detection)
    -- propagate here with 7-day TTL. Weight 40 < ip_rep=45 (same-server EMA) to
    -- account for possible cross-server FP (shared hosting IP, ISP NAT range).
    ext_rep             = 40,

    -- beh_void: desktop user with zero mouse movement AND zero scroll over 3s
    -- time-on-page → strong bot signal. Only fires when beacon_received=true and
    -- device_is_mobile==false (mouse events don't fire on touchscreens).
    -- Weight 35 alone reaches MONITOR (25) but not CHALLENGE (55) — contributes
    -- to aggregate score alongside other signals.
    beh_void            = 35,

    wp_attack_score     = 80,

    swarm_attack        = 120,

    fp_degraded_pen     = 0,
    correlated_boost    = 15,
    corr_rule_weight    = 50,
}

local SIGNAL_SOURCE = {
    cluster_score  = "cluster",
    anomaly_score  = "anomaly",
    entropy_inv    = "browser",
}

local function safe_val(v)
    if type(v) == "boolean" then return v and 1.0 or 0.0 end
    if type(v) == "number"  then return v end
    return 0.0
end

local function get_signal(name, ctx)
    if name == "rate_flag"          then return safe_val(ctx.rate_flag) end
    if name == "burst_flag"         then return safe_val(ctx.burst_flag) end
    if name == "ip_surge"           then return ctx.ip_surge and 1.0 or 0.0 end
    if name == "behavior_score"     then return safe_val(ctx.behavior_score) end
    if name == "session_flag"       then return safe_val(ctx.session_flag) end
    if name == "graph_flag"         then return safe_val(ctx.graph_flag) end
    if name == "bot_score"          then return safe_val(ctx.bot_score) end
    if name == "ua_flag"            then return safe_val(ctx.ua_flag) end
    if name == "anomaly_score"      then return safe_val(ctx.anomaly_score) end
    if name == "ip_score"           then return safe_val(ctx.ip_score) end
    if name == "ip_rep"             then return safe_val(ctx.ip_rep) end
    if name == "asn_rep"            then return safe_val(ctx.asn_rep) end
    if name == "ip_risk"            then return safe_val(ctx.ip_risk) end
    if name == "mismatch"           then return safe_val(ctx.mismatch) end
    if name == "risk"               then return safe_val(ctx.risk) end
    if name == "h2_bot_confidence"  then return safe_val(ctx.h2_bot_confidence) end
    if name == "ja3_allowlist_miss" then return safe_val(ctx.ja3_allowlist_miss) end
    if name == "cluster_score"      then return safe_val(ctx.cluster_score) end
    if name == "entropy_inv" then
        if not ctx.beacon_received then return 0.0 end
        local e = ctx.entropy or 1.0
        return math.max(0.0, 1.0 - e)
    end

    if name == "canvas_change" then
        if not ctx.ip or ctx.ip == "" then return 0.0 end
        local v = pool.safe_get("fp:canvas_change:" .. ctx.ip)
        local changes = tonumber(v) or 0

        return math.min(1.0, changes * 0.5)
    end

    if name == "resource_starved" then
        return ctx.resource_starved and 1.0 or 0.0
    end

    if name == "session_richness" then
        return ctx.session_richness or 0.0
    end

    if name == "headless_score" then
        return safe_val(ctx.headless_score)
    end

    if name == "ext_rep" then
        return safe_val(ctx.ext_rep)
    end

    if name == "beh_void" then
        if not ctx.beacon_received then return 0.0 end
        if ctx.device_is_mobile ~= false then return 0.0 end  -- only explicit desktop
        local beh = ctx.browser and ctx.browser.beh
        if not beh then return 0.0 end
        -- No mouse AND no scroll over 3+ seconds on a desktop = bot pattern.
        -- td=0 means page loaded less than 2s before beacon (2s delay in JS)
        -- or navigationStart unavailable — skip to avoid FP on fast page loads.
        if (beh.mm or 0) == 0 and (beh.sc or 0) == 0
           and (beh.td or 0) > 3000 then
            return 1.0
        end
        return 0.0
    end

    if name == "wp_attack_score" then
        return safe_val(ctx.wp_attack_score)
    end

    if name == "swarm_attack" then
        return safe_val(ctx.swarm_attack)
    end

    if name == "fast_solve" then
        if not ctx.identity then return 0.0 end
        local v = pool.safe_get("fp:fast_solve:" .. ctx.identity)
        local count = tonumber(v) or 0

        return math.min(1.0, count * 0.35)
    end
    return 0.0
end

function _M.run(ctx)
    local weights = DEFAULT_WEIGHTS
    local skip    = ctx.skip_layers or {}

    local total      = 0.0
    local pos_total  = 0.0  -- Sum of positive contributions cho %, không bị
                            -- méo bởi trust signal âm (session_richness).
    local top        = {}
    local corr_bonus = 0.0

    for name, weight in pairs(weights) do

        local src = SIGNAL_SOURCE[name]
        if src and skip[src] then goto continue end

        if (name == "canvas_change" or name == "fast_solve"
           or name == "resource_starved")
           and (ctx.req_class == "api_callback"
	   	or ctx.req_class == "resource") then
            goto continue
        end

        local val = get_signal(name, ctx)

        if name == "fp_degraded_pen" then
            if ctx.fp_degraded then
                total     = total     + weight
                pos_total = pos_total + weight
            end
            goto continue
        end

        if name == "correlated_boost" then
            goto continue
        end

        if name == "corr_rule_weight" then
            if ctx.corr_rules then
                for _, rule in ipairs(ctx.corr_rules) do
                    local add = (rule.score or 0) * weight
                    corr_bonus = corr_bonus + add
                    if add > 0 then pos_total = pos_total + add end
                end
            end
            goto continue
        end

        local pts = val * weight
        if pts > 0.5 then
            top[#top+1] = { signal = name, pts = pts, weight = weight, val = val }
            pos_total = pos_total + pts
        end
        -- pts âm (trust signal như session_richness) vẫn vào total nhưng KHÔNG
        -- vào pos_total → contribution_pct của các signal threat không bị méo.
        total = total + pts

        ::continue::
    end

    total = total + corr_bonus

    table.sort(top, function(a, b) return a.pts > b.pts end)

    local top_out = {}
    local top_n   = math.min(5, #top)
    for i = 1, top_n do
        top_out[i] = {
            signal           = top[i].signal,
            pts              = top[i].pts,
            contribution_pct = math.floor(top[i].pts / math.max(pos_total, 1) * 100),
        }
    end

    ctx.score       = math.max(0, total)
    ctx.top_signals = top_out
end

return _M
