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
    base_threshold      = 300,
    burst_threshold     = 30,
    slow_threshold_s    = 10,
    risk_factor         = 0.5,
    ip_surge_threshold  = 1500,
}

_M.trust = {
    session_min        = 5,
    session_active_min = 3,
    session_flag_max   = 0.4,
    score_multiplier   = 0.5,
    score_mult_active  = 0.75,
    action_cap         = "monitor",
}

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
