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

local function write_stats(premature, host, class, action, date, device_type, intent)
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

    -- Build structured log line — all fields on one line, space-separated key=value
    local line = string.format(
        "[%s] [antibot] ts=%d domain=%s class=%s id=%s" ..
        " ip=%s ua=%s tls13=%s h2=%s ja3=%s ja3p=%s" ..
        " score=%.1f eff=%.1f mult=%s action=%s" ..
        " top=%s reason=%s",
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
        top_str,
        tostring(ctx.action_reason or "-")
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

    if ctx.whitelisted then return end

    local action = ctx.action or "allow"
    local date   = os.date("%Y%m%d")

    local device_type = ctx.device_type or "unknown"
    local intent      = classify_intent(ctx)
    local ok, err = ngx.timer.at(0, write_stats, host, class, action, date, device_type, intent)
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
