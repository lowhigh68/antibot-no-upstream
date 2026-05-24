local _M = {}

local LOG_FILE = "/var/log/antibot/antibot.log"

local DEVICE_GROUP = {
    mobile_chrome_android = "mobile",
    mobile_safari_ios     = "mobile",
    mobile_safari_ios_old = "mobile",
    custom_tab            = "mobile",
    inapp                 = "mobile",
    tablet_ipad           = "tablet",
    tablet_android        = "tablet",
    desktop_chrome        = "desktop",
    desktop_safari        = "desktop",
    desktop_firefox       = "desktop",
    desktop_other         = "desktop",
}

local function classify_intent(ctx)
    -- Good bot: đã DNS verify
    if ctx.good_bot_verified == true then
        return "good_bot"
    end

    local action    = ctx.action    or "allow"
    local bot_score = ctx.bot_score or 0.0
    local ua_flag   = ctx.ua_flag   or 0.0
    local ip_rep    = ctx.ip_rep    or 0.0
    local ip_risk   = ctx.ip_risk   or 0.0

    -- Bot: action đã kết luận là xấu + có bot evidence
    -- action là output của toàn bộ scoring pipeline — đây là signal đáng tin nhất
    if (action == "block" or action == "challenge") then
        if bot_score >= 0.3
        or ua_flag >= 0.5
        or ip_rep > 0
        or ip_risk >= 0.4 then
            return "bot"
        end
    end

    -- Bot: score rõ ràng ngay cả khi action=monitor
    if bot_score >= 0.6 or ua_flag >= 0.7 or ip_risk >= 0.7 then
        return "bot"
    end

    -- Human: verified PoW
    if ctx.verified == true then
        return "human"
    end

    -- Human: action=allow → hệ thống không tìm thấy gì đáng ngờ
    -- Benefit of the doubt: nếu không có bot evidence thì là người thật
    if action == "allow" then
        if bot_score < 0.2 and ua_flag < 0.3 and ip_risk < 0.3 then
            return "human"
        end
    end

    -- Ambiguous: action=monitor, hoặc allow với signal nhẹ
    return "ambiguous"
end

local function write_stats(premature, host, class, action, date, device_type, intent, beacon_got)
    if premature then return end
    local ok, pool = pcall(require, "antibot.core.redis_pool")
    if not ok then return end
    local red, err = pool.get()
    if not red then return end

    local ttl_7d = 86400 * 7
    local dg = DEVICE_GROUP[device_type or ""] or "unknown"

    red:init_pipeline()

    red:incr("stat:" .. host .. ":req:" .. date)
    red:expire("stat:" .. host .. ":req:" .. date, ttl_7d)

    red:incr("stat:" .. host .. ":" .. action .. ":" .. date)
    red:expire("stat:" .. host .. ":" .. action .. ":" .. date, ttl_7d)

    red:incr("stat:" .. host .. ":" .. class .. "_" .. action .. ":" .. date)
    red:expire("stat:" .. host .. ":" .. class .. "_" .. action .. ":" .. date, ttl_7d)

    -- Device group stats
    red:incr("stat:" .. host .. ":dev_" .. dg .. ":" .. date)
    red:expire("stat:" .. host .. ":dev_" .. dg .. ":" .. date, ttl_7d)

    if action == "block" or action == "challenge" then
        red:incr("stat:" .. host .. ":dev_" .. dg .. "_" .. action .. ":" .. date)
        red:expire("stat:" .. host .. ":dev_" .. dg .. "_" .. action .. ":" .. date, ttl_7d)
    end

    -- Intent stats: bot vs human vs ambiguous
    local ig = intent or "ambiguous"
    red:incr("stat:" .. host .. ":intent_" .. ig .. ":" .. date)
    red:expire("stat:" .. host .. ":intent_" .. ig .. ":" .. date, ttl_7d)

    if action == "block" or action == "challenge" then
        red:incr("stat:" .. host .. ":intent_" .. ig .. "_" .. action .. ":" .. date)
        red:expire("stat:" .. host .. ":intent_" .. ig .. "_" .. action .. ":" .. date, ttl_7d)
    end

    -- Intent per device group: biết desktop có bao nhiêu bot vs người thật
    local ibd_key = "stat:" .. host .. ":ibd_" .. dg .. "_" .. ig .. ":" .. date
    red:incr(ibd_key)
    red:expire(ibd_key, ttl_7d)

    -- Beacon coverage telemetry (Step 0 — baseline cho canvas/webgl signal upgrade).
    -- Nil = không phải HTML-eligible request → không count.
    -- false = HTML-eligible nhưng beacon chưa về (first visit / inject blocked / JS off).
    -- true  = HTML-eligible và có beacon data sẵn trong Redis (canvas/webgl analyzable).
    -- Coverage = beacon_got / beacon_elig; thấp → cần fix inject trước khi tăng weight.
    if beacon_got ~= nil then
        local elig_key = "stat:" .. host .. ":beacon_elig:" .. date
        red:incr(elig_key)
        red:expire(elig_key, ttl_7d)
        if beacon_got then
            local got_key = "stat:" .. host .. ":beacon_got:" .. date
            red:incr(got_key)
            red:expire(got_key, ttl_7d)
        end
    end

    -- Sample UA cho unknown device: lưu tối đa 20 UA gần nhất để admin debug
    if dg == "unknown" and device_type == "unknown" and ua and ua ~= "" then
        local sample_key = "stat:ua_unknown_sample"
        red:lpush(sample_key, ua:sub(1, 120))
        red:ltrim(sample_key, 0, 19)
        red:expire(sample_key, 86400)
    end

    red:commit_pipeline()
    pool.put(red)
end

-- Write one log line to dedicated antibot log file.
-- Called from log_by_lua_block — response is already sent,
-- blocking I/O here does not affect latency seen by the client.
local function write_log_line(line)
    local fh, err = io.open(LOG_FILE, "a")
    if not fh then
        -- Fallback to nginx error log only on open failure (permission, missing dir)
        ngx.log(ngx.WARN, "[antibot] cannot open log file: ", tostring(err))
        return
    end
    fh:write(line, "\n")
    fh:close()
end

function _M.run(ctx)
    if not ctx then return end

    local top_str = ""
    if ctx.top_signals then
        local parts = {}
        for _, s in ipairs(ctx.top_signals) do
            parts[#parts+1] = string.format("%s=%d%%",
                s.signal or "?", s.contribution_pct or 0)
        end
        top_str = table.concat(parts, ",")
    end

    local host  = (ctx.req and ctx.req.host) or ngx.var.host or "unknown"
    local class = ctx.req_class or "unknown"

    -- UA truncate để grep debug (googlebot, bingbot, facebook, ...).
    -- Nếu UA chứa space/= sẽ vỡ format parser → thay bằng _.
    local ua_log = (ctx.ua or "-"):sub(1, 120):gsub("[%s\"]", "_")

    -- Throttle decision details — chỉ append cho action=throttled để tránh
    -- bloat log line cho các request bình thường. trigger ∈ {hard_qs_len,
    -- hard_param_count, soft_score}; exp_score là weighted sum 0..1.45.
    local throttle_str = ""
    if ctx.action == "throttled" then
        throttle_str = string.format(
            " trigger=%s exp_score=%.2f",
            tostring(ctx.expensive_trigger or "-"),
            ctx.expensive_score or 0)
    end

    -- S2.5 tier details — chỉ append khi attest path fired.
    -- Lets `grep tier=S2.5 antibot.log` audit attest decisions.
    -- marker= present only for analyzer_attested (Path 2).
    local tier_str = ""
    if ctx.bot_identity_tier then
        tier_str = " tier=" .. ctx.bot_identity_tier
        if ctx.analyzer_marker then
            tier_str = tier_str .. " marker=" .. ctx.analyzer_marker
        end
    end

    -- Beacon coverage state (Step 0 telemetry).
    -- skip = không phải HTML-eligible (resource/api/auth) — beacon không áp dụng
    -- 1    = HTML eligible + có beacon data (canvas/webgl signal khả dụng)
    -- 0    = HTML eligible nhưng beacon chưa về (first visit / JS blocked / CSP fail)
    local beacon_state = "skip"
    if ctx.inject_candidate then
        beacon_state = ctx.beacon_received and "1" or "0"
    end

    -- Build structured log line — all fields on one line, space-separated key=value.
    -- richness ∈ [0,1] = ctx.session_richness, trust proxy (cookie payload +
    -- auth header). Log mỗi request để debug/audit; volume control qua daily
    -- rotate. grep richness=0\\.[89] antibot.log → tìm logged-in user, grep
    -- richness=0\\.0 → first-visit/bot pattern.
    local line = string.format(
        "[%s] [antibot] ts=%d domain=%s class=%s id=%s" ..
        " ip=%s ua=%s tls13=%s h2=%s ja3=%s ja3p=%s" ..
        " score=%.1f eff=%.1f mult=%s action=%s beacon=%s richness=%.2f inapp=%.2f" ..
        " top=%s reason=%s%s%s",
        os.date("%Y-%m-%d %H:%M:%S"),
        ngx.time(),
        host,
        class,
        tostring(ctx.identity or ctx.fp_light or "-"),
        tostring(ctx.ip or "-"),
        ua_log,
        tostring(ctx.tls13),
        tostring(ctx.h2_is_h2),
        tostring(ctx.ja3 or "-"),
        tostring(ctx.ja3_partial or false),
        ctx.score or 0,
        ctx.effective_score or 0,
        tostring(ctx.score_multiplier or 1.0),
        tostring(ctx.action or "-"),
        beacon_state,
        ctx.session_richness or 0,
        ctx.inapp_likeness or 0,
        top_str,
        tostring(ctx.action_reason or "-"),
        throttle_str,
        tier_str
    )

    write_log_line(line)

    -- Escalated events also go to nginx error log for visibility
    if ctx.action == "block" or ctx.action == "challenge" then
        ngx.log(ngx.WARN,
            "[antibot] ", ctx.action,
            " ip=", tostring(ctx.ip or "-"),
            " score=", string.format("%.1f", ctx.score or 0),
            " domain=", host,
            " top=", top_str)
    end

    -- Chỉ skip stats cho "infrastructure" whitelist (wp-cron LAN, bypass
    -- resource, admin IP/URL config, antibot endpoints). Các reason verified
    -- (cookie/device/earlyid) là human thật → vẫn count vào Clean để dashboard
    -- phản ánh đúng human traffic, không chỉ riêng fresh-visit pass detection.
    local SKIP_STATS_REASONS = {
        antibot_internal = true,
        lan_internal     = true,
        ip_whitelist     = true,
        url_whitelist    = true,
        bypass_path      = true,
    }
    if ctx.whitelisted and SKIP_STATS_REASONS[ctx.action_reason or ""] then
        return
    end

    local action = ctx.action or "allow"
    local date   = os.date("%Y%m%d")

    local device_type = ctx.device_type or "unknown"
    local intent      = classify_intent(ctx)

    -- beacon_got = nil cho non-HTML request (skip counter), bool cho HTML-eligible.
    local beacon_got
    if ctx.inject_candidate then
        beacon_got = ctx.beacon_received == true
    end

    local ok, err = ngx.timer.at(0, write_stats, host, class, action, date, device_type, intent, beacon_got)
    if not ok then
        ngx.log(ngx.DEBUG, "[logger] timer.at failed: ", tostring(err))
    end

    -- Track sess_res cho resource request trong logger (async).
    -- session_store chỉ chạy trong STEPS_FULL_DETECTION (navigation) —
    -- resource request chạy STEPS_RESOURCE không có detection_layer →
    -- sess_res không bao giờ được incr trong session_store →
    -- resource_ratio = 0 → resource_starved false positive với mọi user thật.
    -- Fix: incr sess_res ở đây cho resource class, dùng fp_light làm key.
    if class == "resource" then
        local fp = ctx.fp_light or ctx.identity
        if fp and fp ~= "" and fp ~= "-" then
            local res_key = "sess_res:" .. fp
            local ok2, err2 = ngx.timer.at(0, function(premature)
                if premature then return end
                local ok3, pool2 = pcall(require, "antibot.core.redis_pool")
                if not ok3 then return end
                local red2, _ = pool2.get()
                if not red2 then return end
                red2:incr(res_key)
                red2:expire(res_key, 300)
                pool2.put(red2)
            end)
            if not ok2 then
                ngx.log(ngx.DEBUG, "[logger] sess_res timer failed: ", tostring(err2))
            end
        end
    end
end

return _M
