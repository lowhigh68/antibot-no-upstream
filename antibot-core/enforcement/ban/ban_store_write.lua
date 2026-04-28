local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

function _M.run(ctx)
    local id    = ctx.identity or ctx.fp_light
    local ip    = ctx.ip
    local ttl   = ctx.ban_ttl
    local class = ctx.req_class or "unknown"

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_write] redis unavailable: ", err)
        return
    end

    local ctx_json = ""
    local ok, cjson = pcall(require, "cjson")
    if ok then
        local host = (ctx.req and ctx.req.host) or ngx.var.host or "unknown"
        local ok2, json = pcall(cjson.encode, {
            domain      = host,
            score       = math.floor(ctx.score or 0),
            eff_score   = math.floor(ctx.effective_score or 0),
            action      = ctx.action or "block",
            req_class   = class,
            ts          = ngx.time(),
            identity    = id or "",
            fp_deg      = ctx.fp_degraded or false,
            device_type = ctx.device_type or "unknown",
            ua          = (ctx.ua or ""):sub(1, 120),
            ip          = ctx.ip or "",
            bot_score   = ctx.bot_score or 0,
        })
        if ok2 then ctx_json = json end
    end

    local ctx_ttl = (ttl and ttl > 0) and ttl or 86400

    local ip_risk_val   = ctx.ip_risk or 0.0
    local swarm_active  = ctx.swarm == true

    -- Lấy viol counter hiện tại (đọc trước khi incr ở dưới) để escalate IP ban.
    -- Repeat offender → ban IP bất kể ip_risk thấp; permanent sau viol≥4.
    local viol_count = id and (tonumber(pool.safe_get("viol:" .. id)) or 0) or 0

    local should_ban_ip = ip and (
        ip_risk_val >= 0.7
        or (ip_risk_val >= 0.5 and swarm_active)
        or viol_count >= 3   -- repeat offender → ban IP kể cả risk thấp
    )

    local ip_ban_ttl
    if viol_count >= 4 then
        ip_ban_ttl = 0           -- permanent: confirmed repeat bot
    elseif viol_count >= 3 then
        ip_ban_ttl = 86400       -- 24h: cảnh báo nặng
    elseif ip_risk_val >= 0.95 then
        ip_ban_ttl = 1800        -- 30 phút: bot tấn công tích cực
    elseif ip_risk_val >= 0.85 then
        ip_ban_ttl = 900         -- 15 phút: risk cao
    elseif ip_risk_val >= 0.7 then
        ip_ban_ttl = 300         -- 5 phút: ngưỡng tối thiểu
    else
        ip_ban_ttl = 180         -- 3 phút: swarm case
    end

    red:init_pipeline()

    local now_ts = tostring(ngx.time())

    if id then
        if ttl and ttl > 0 then
            red:setex("ban:" .. id, ttl, "1")
        else
            red:set("ban:" .. id, "1")
        end
        -- Fresh ban → ACTIVE ngay trong 5 phút đầu, không phải chờ hit kế tiếp.
        red:setex("ban:hit:" .. id, 300, now_ts)
        -- Mỗi lần ban = +1 violation để ban_escalation lũy tiến TTL lần sau.
        -- Trước đây viol chỉ tăng khi rate-limit/challenge-fail → score-based
        -- block (GPTBot/DotBot...) luôn dừng ở step 1 = 5m dù quay lại nhiều lần.
        red:incr("viol:" .. id)
        red:expire("viol:" .. id, cfg.ttl.violation)
    end

    if should_ban_ip then
        if ip_ban_ttl > 0 then
            red:setex("ban:" .. ip, ip_ban_ttl, "1")
        else
            red:set("ban:" .. ip, "1")  -- permanent
        end
        red:setex("ban:hit:" .. ip, 300, now_ts)
    end

    if ctx_json ~= "" then
        if id then
            red:setex("ban_ctx:" .. id, ctx_ttl, ctx_json)
        end
        if should_ban_ip then
            red:setex("ban_ctx:" .. ip, ip_ban_ttl, ctx_json)
        end
    end

    red:commit_pipeline()
    pool.put(red)

    ngx.log(ngx.WARN,
        "[ban_write]",
        " class=", class,
        " ip=", ip or "?",
        " ip_risk=", string.format("%.3f", ip_risk_val),
        " ban_ip=", tostring(should_ban_ip ~= false and should_ban_ip ~= nil),
        " ip_ttl=", should_ban_ip and ip_ban_ttl or "-",
        " id=", id and id:sub(1, 8) .. "..." or "nil",
        " ttl=", ttl == 0 and "permanent" or tostring(ttl) .. "s",
        " score=", ctx.score or 0,
        " eff=", ctx.effective_score or 0)
end

return _M
