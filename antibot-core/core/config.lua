local _M = {}

_M.redis = {
    host        = "127.0.0.1",
    port        = 6379,
    timeout_ms  = 200,
    pool_size   = 100,
    pool_idle_s = 30,
    db          = 0,
}

_M.thresholds = {
    allow     = 0,
    monitor   = 25,
    challenge = 80,  -- nâng từ 65: fresh residential user không bị interrupt
    block     = 100, -- nâng từ 80: chỉ block khi nhiều signal bot rõ ràng
}

_M.weights = {
    rate_flag        = 25,
    burst_flag       = 35,
    slow             = 50,
    behavior_score   = 30,
    session_flag     = 20,
    graph_score      = 30,
    cluster_score    = 25,
    anomaly_score    = 35,
    bot_score        = 45,
    h2_bot_confidence= 55,
    ip_rep           = 45,
    asn_rep          = 35,
    ja3_rep          = 35,
    h2_rep           = 35,
    ip_score         = 20,
    entropy_inv      = 25,
    corr_score       = 45,
    mismatch         = 55,
    risk             = 30,
    ja3_allowlist_miss = 50,
    fp_degraded_pen  = 15,
    correlated_boost = 15,
    corr_rule_weight = 50,
}

_M.signal_threshold = 0.7

_M.endpoint_sensitivity = {
    ["/admin"]      = 2.0,
    ["/login"]      = 1.8,
    ["/register"]   = 1.6,
    ["/checkout"]   = 1.8,
    ["/payment"]    = 2.0,
    ["/api/"]       = 1.2,
    ["/search"]     = 1.3,
    ["/"]           = 0.8,
    default         = 1.0,
}

_M.ttl = {
    geo              = 3600,
    asn              = 3600,
    fp               = 86400,
    fp_quality       = 86400,
    session          = 7200,
    session_max_len  = 20,
    sequence_use_len = 10,
    rate             = 60,
    burst            = 1,
    ban_steps        = {300, 3600, 86400, 0},
    violation        = 172800,  -- 48h: đủ dài để xuyên qua ban step 3 (24h), đủ ngắn để user thật không mang violation cũ
    risk             = 86400,
    dns              = 600,
    rep_ip           = 900,
    rep_asn          = 3600,
    rep_ja3          = 3600,
    rep_h2           = 3600,
    nonce            = 60,
    verified         = 604800,  -- 7 ngày (mobile 4G: cookie persist qua đổi mạng)
    explain          = 3600,
    antibot_tls      = 10,
    whitelist_cache  = 60,
    model_weight     = 0,
}

_M.rate = {
    base_threshold        = 300,
    burst_threshold       = 30,
    slow_threshold_s      = 10,
    risk_factor           = 0.5,
    -- ip_surge_threshold: SIGNAL trigger (~25 req/s sustained over 60s window).
    -- Beyond this, set ctx.ip_surge=true → contributes weight in scoring
    -- (intelligence/scoring/compute.lua). Engine decides via aggregate score,
    -- not a unilateral ban. Allows extension/multi-tab/AI-agent users (single
    -- identity, clean fingerprint) to pass even when bursting briefly.
    ip_surge_threshold    = 1500,
    -- ip_surge_extreme: HARD-BAN trigger (~83 req/s sustained over 60s window).
    -- This rate is implausible for human + browser even with aggressive
    -- extension/multi-tab activity. Gated additionally by distinct-identity
    -- count to protect CGNAT (Vietnam carriers, office NAT). Pairs with
    -- ip_surge_distinct_min and ip_surge_ban_ttl below.
    ip_surge_extreme      = 5000,
    -- ip_surge_distinct_min: minimum distinct identities seen from this IP in
    -- the current rate window. ≥ this → CGNAT/shared infra (multiple users
    -- behind 1 IP), do NOT hard-ban regardless of aggregate rate. < this →
    -- single-source surge (single host hammering), hard-ban applies.
    ip_surge_distinct_min = 3,
    -- ip_surge_ban_ttl: hard-ban duration when extreme path fires. Shortened
    -- from legacy 1800s to 300s — auto-recovery after 5 min, repeat surges
    -- re-ban naturally. Reduces blast radius if extreme threshold is mis-tuned.
    ip_surge_ban_ttl      = 300,

    -- Class-aware burst factor: multiplies burst_threshold per req_class.
    -- Orthogonal với session_richness lift — combine multiplicative cho
    -- effective_threshold = base × class_factor × (1 + richness × 2).
    --
    -- Nguyên tắc:
    --   < 1.0 = tighten (request type không tự nhiên burst → bot signal)
    --   > 1.0 = relax  (request type có legitimate burst pattern)
    --
    -- Calibration:
    --   navigation 0.67   → 20/s. Human khó burst > 20 nav/s ngay cả khi
    --                       F5 storm hoặc multi-tab bookmark "Open All".
    --                       Retry discount (counter.lua) đã xử lý same-URI
    --                       F5 ở rate layer. Tighten đây bắt nav-crawl bot.
    --   interaction 1.5  → 45/s. SPA frontend (Magento Luma, Shopify,
    --                       headless Next.js) fire 30-50 XHR đồng thời on
    --                       page load. Đây là vùng FP cao nhất.
    --   api_callback 2.0 → 60/s. Server-to-server webhook retry (Stripe,
    --                       MoMo, VNPay) có thể burst nếu integration lỗi.
    --   auth_endpoint 0.8 → 24/s. Login không có lý do burst. Tighten chống
    --                       credential stuffing 1-second hammer.
    --   feed_or_meta 0.5 → 15/s. Crawler hit individually (1 IP = 1-3 fetch
    --                       per minute), không có per-identity burst.
    --   inapp_browser/unknown: giữ baseline 1.0.
    --   resource: giá trị bất kỳ (resource skip burst counter qua STEPS_RESOURCE).
    class_burst_factor = {
        resource      = 1.0,
        navigation    = 0.67,
        interaction   = 1.5,
        api_callback  = 2.0,
        auth_endpoint = 0.8,
        feed_or_meta  = 0.5,
        inapp_browser = 1.0,
        unknown       = 1.0,
    },

    -- Verified good-bot rate ceiling (replaces hard-coded per-ASN limits).
    --
    -- Each verified bot (after DNS/ASN verification in detection/bot/) is
    -- assigned a class. Class -> req/min ceiling. Operator tune by editing
    -- table below. Industry pattern (Cloudflare Bot Categories, Akamai
    -- Crawler Profiles, DataDome bot tiers).
    --
    -- Adaptive promotion: every 429 (rate exceeded) increments
    -- `gb_aggression:<bot>` (TTL 600s = 10-min self-decay). When aggression
    -- score crosses threshold, effective_class is promoted toward the most
    -- restrictive tier. Bot quiet 10 min -> aggression key expires -> class
    -- restored to base. Same pattern as `ip_risk` EMA decay in
    -- async/risk_update.lua.
    --
    -- Class ladder (low -> high restriction): polite -> moderate -> aggressive
    -- Aggression score thresholds (count of 429s in last 10-min sliding window):
    --   <  promotion_t1 -> base class
    --   >= promotion_t1 -> +1 tier
    --   >= promotion_t2 -> +2 tier (skip straight to aggressive)
    --
    -- `map` is enumeration of KNOWN verified bots — finite (~20 globally),
    -- stable list, paired with bot verification registry (data/goodbot.json).
    -- This is metadata for tuning, NOT a detection pattern list.
    good_bot_rate = {
        classes = {
            polite     = 180,  -- 3 req/sec — search engine ổn định
            moderate   = 60,   -- 1 req/sec — verified nhưng từng có history aggressive
            aggressive = 30,   -- 0.5 req/sec — known low-quality crawl
            default    = 60,   -- unknown verified bot fallback
        },
        map = {
            -- Polite: established search engines, stable crawl patterns
            googlebot   = "polite",
            bingbot     = "polite",
            applebot    = "polite",
            duckduckbot = "polite",

            -- Moderate: verified but observed aggressive on this stack
            meta             = "moderate",
            coccocbot        = "moderate",
            yandexbot        = "moderate",

            -- Aggressive: known low-value or aggressive crawlers
            bytespider  = "aggressive",
            semrushbot  = "aggressive",
            ahrefsbot   = "aggressive",
            mj12bot     = "aggressive",
        },

        -- Adaptive promotion tunables
        aggression_decay_ttl  = 600,  -- 10-min sliding window via TTL refresh
        promotion_threshold_1 = 10,   -- score >= 10  -> +1 tier
        promotion_threshold_2 = 30,   -- score >= 30  -> +2 tier
        retry_after           = 60,   -- 429 Retry-After header value
    },
}

_M.trust = {
    session_min        = 5,
    session_active_min = 3,
    session_flag_max   = 0.4,
    score_multiplier   = 0.5,
    score_mult_active  = 0.75,
    action_cap         = "monitor",
}

-- Verified-state anti-sharing tracking (applies to ALL verified paths).
--
-- Bot scrapers compromise the verified-user state in multiple ways:
--   - Cookie sharing: solve PoW once, replicate `antibot_fp` cookie to
--     35+ IPs (43.172.0.0/15 attack 2026-06-18)
--   - Device-canvas reuse: PoW once per UA, then ANY IP within same /16
--     using that UA matches `device_ua:<ua_hash>:<ip16>` -> verified
--     (continued 43.172/43.173 attack after cookie defense deployed)
--
-- Defense: track distinct source IPs per verified handle in Redis SET
-- `verified_ips:<scope>:<handle>` (TTL 86400s). Atomic SADD+EXPIRE+SCARD
-- on every verified-path hit. If SCARD > max -> handle is shared ->
-- revoke (DEL all related keys) -> request falls through to re-challenge.
--
-- Scopes:
--   cookie  -> verified_ips:cookie:<cookie>   (init.lua check_verified_cookie)
--   device  -> verified_ips:device:<dev_id>   (whitelist.lua lookup_device_by_ua)
--
-- Threshold tuning (max_ips_per_handle):
--   2 -> too tight, FP on mobile users (4G/wifi switch in same day)
--   3 -> sweet spot: home wifi + mobile + occasional public wifi
--   5 -> permissive, bot still has 5-IP budget
-- Real users observed: 1-3 distinct IPs/day. Bot: 35+ IPs immediately.
_M.verified_share = {
    max_ips_per_handle = 3,
    ip_tracking_ttl    = 86400,  -- 24h window
}

-- Backward-compat alias (older code references cfg.cookie.*)
_M.cookie = _M.verified_share

_M.cluster = {
    ua_baseline_threshold_mult = 10,
    subnet_diversity_nat_max   = 3,
    nat_discount_factor        = 0.4,
    baseline_ua_score_cap      = 0.4,
    ua_count_normalize_max     = 500,
    ip_count_normalize_max     = 200,
    uri_count_normalize_max    = 100,
    tls_count_normalize_max    = 300,
}

_M.pow = {
    difficulty       = "000",
    challenge_secret = "c516565b589841e4a540c309ed301f83",
}

_M.fp_quality_threshold = 0.55

_M.debug = false

function _M.endpoint_sens(uri)
    if not uri then return _M.endpoint_sensitivity.default end
    for pattern, sens in pairs(_M.endpoint_sensitivity) do
        if pattern ~= "default" and uri:find(pattern, 1, true) then
            return sens
        end
    end
    return _M.endpoint_sensitivity.default
end

return _M
