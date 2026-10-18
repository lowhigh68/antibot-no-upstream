-- Generic automation traffic meter.
--
-- Claim recognition is structural (bot/spider/crawler or RFC contact marker),
-- not a list of AI brands. This module runs before every early exit so banned,
-- WAF-blocked and admission-limited automation still appears in telemetry.
-- It uses the existing shared dict only: no Redis RTT and no nginx.conf change.
--
-- `unknown` and verified automation remain observation-only. The separately
-- proven operator/contradicted tiers may be paced when config selects enforce;
-- `autwould` stays the measurement and `autthr` records an actual 429.

local _M = {}

local cfg = require "antibot.core.config"
local operator_network = require "antibot.core.operator_network"

local function conf()
    return cfg.automation or {}
end

local function digest(value)
    value = tostring(value or "-")
    if ngx.md5 then return ngx.md5(value) end
    -- Test/fallback only. OpenResty always provides ngx.md5.
    return value:gsub("[^%w_.-]", "_"):sub(1, 64)
end

local function bump(dict, key, delta, ttl)
    local added, err = dict:add(key, delta, ttl)
    if added then return delta end
    if err ~= "exists" then return nil, err end
    return dict:incr(key, delta)
end

local function key(axis, identity, window, now)
    return "auto:" .. axis .. ":" .. digest(identity)
        .. ":" .. window .. ":" .. math.floor(now / window)
end

local function pair(dict, axis, identity, windows, cost, now)
    local short = tonumber(windows.short) or 10
    local long  = tonumber(windows.long) or 60
    local sv, se = bump(dict, key(axis, identity, short, now), cost, short * 2 + 2)
    local lv, le = bump(dict, key(axis, identity, long, now), cost, long * 2 + 2)
    return sv, lv, se or le
end

local function consider(ctx, axis, short_value, long_value, limits, top)
    if not limits then return top end
    local sr = limits.short and short_value and short_value / limits.short or 0
    local lr = limits.long  and long_value  and long_value  / limits.long  or 0
    local ratio, window = sr, "short"
    if lr > ratio then ratio, window = lr, "long" end
    if ratio > (top.ratio or 0) then
        top = { ratio = ratio, axis = axis .. ":" .. window }
    end
    if sr >= 1 or lr >= 1 then
        ctx.automation_would_throttle = true
        -- Remember WHICH axis broke, not just that something did. The reject
        -- reason and the operator's tuning both need the axis; `autaxis` alone
        -- carries the highest ratio, which is not always the one over 1.
        local breached = ctx.automation_breached or {}
        breached[#breached + 1] = axis .. ":" .. (sr >= 1 and "short" or "long")
        ctx.automation_breached = breached
    end
    return top
end

-- Throttle self-identified automation that exceeded its own tier budget.
--
-- 429 + Retry-After, deliberately: it is the response every published crawler
-- documents as a back-off signal, so a well-behaved operator slows down and
-- returns. 403 would read as "never come back" and 503 would mark the SITE as
-- unhealthy to search/AI indexes. This is a pace limit, not a verdict about
-- the client, so nothing here touches bot score, reputation or ban state.
--
-- No `Retry-After` smaller than the short window: telling a crawler to come
-- back sooner than the budget refills just converts one burst into a retry
-- storm on the same budget.
local function throttle(ctx, c, axis)
    local windows = c.windows or {}
    local retry = tonumber(c.retry_after)
        or math.max(tonumber(windows.short) or 10, 1)

    ctx.automation_throttled = true
    ctx.action = "throttled"
    ctx.action_reason = "automation_guard:" .. tostring(ctx.automation_tier
        or "unknown") .. ":" .. tostring(axis or "-")

    ngx.header["Retry-After"]      = tostring(retry)
    ngx.header["Cache-Control"]    = "no-store"
    ngx.header["Content-Type"]     = "text/plain"
    ngx.header["X-Bot-Action"]     = "throttled"
    ngx.status = tonumber(c.status) or 429
    ngx.say("Too many requests. Please slow down and retry.")
    ngx.exit(ngx.status)
    -- Tra `true` TUONG MINH chu khong `return ngx.exit(...)`: tren OpenResty
    -- that `ngx.exit` khong tra ve nen hai cach giong nhau, nhung trong test
    -- stub no tra ve ma trang thai va `exit=429` khong phai `exit=true` —
    -- hop dong cua pipeline la mot boolean. Mot khac biet chi lo ra o test la
    -- mot khac biet co that.
    return true
end

-- Temporarily stop one proven operator before it can consume a rate bucket or
-- reach an upstream.  This is intentionally stricter than `throttle()`:
-- 403 means that this principal is suspended, whereas 429 means it may return
-- after its budget refills.  Requiring tier `operator` is the safety boundary;
-- principal text/UA alone is not sufficient evidence.
local function suspend_operator(ctx, c, principal)
    ctx.automation_observed = true
    ctx.automation_suspended = true

    -- Keep the existing enforcement telemetry contract.  `autthr=true` means
    -- an automation request was actually rejected; `autactual=403` and
    -- `autbreach=suspend` distinguish this hard suspension from a rate 429.
    ctx.automation_would_throttle = true
    ctx.automation_throttled = true
    ctx.automation_top_axis = "suspend"
    ctx.automation_top_use = 100
    ctx.automation_breached = { "suspend" }

    ctx.action = "block"
    ctx.action_reason = "automation_guard:operator:suspend:" .. principal

    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "text/plain"
    ngx.header["X-Bot-Action"] = "blocked"
    ngx.status = tonumber(c.suspend_status) or 403
    ngx.say("Crawler temporarily disabled.")
    ngx.exit(ngx.status)
    return true
end

function _M.evaluate(ctx)
    if not ctx.automation_observed then return true, false end
    local c = conf()
    local limits = c.provisional_limits or {}
    local tiers = limits.tiers or {}
    local tier = ctx.automation_tier or "unknown"
    local top = { ratio = 0, axis = "-" }

    ctx.automation_would_throttle = false
    top = consider(ctx, "principal", ctx.automation_principal_short,
        ctx.automation_principal_long, tiers[tier] or tiers.unknown, top)
    top = consider(ctx, "ip", ctx.automation_ip_short,
        ctx.automation_ip_long, limits.ip, top)
    top = consider(ctx, "host", ctx.automation_host_short,
        ctx.automation_host_long, limits.host, top)
    -- `fleet` dung TRUOC `server` co y: `breached[1]` la truc duoc bao trong
    -- `action_reason`, va khi ca hai vuot thi truc co tinh PHAN BIET (principal
    -- nao dang keo) huu ich hon truc tran chung (toan may dang day).
    top = consider(ctx, "fleet", ctx.automation_fleet_short,
        ctx.automation_fleet_long, limits.fleet, top)
    top = consider(ctx, "server", ctx.automation_server_short,
        ctx.automation_server_long, limits.server, top)

    ctx.automation_tier = tier
    ctx.automation_top_axis = top.axis
    ctx.automation_top_use = math.floor((top.ratio or 0) * 100 + 0.5)

    if not ctx.automation_would_throttle then return true, false end

    -- Enforcement is opt-in per mode and NEVER applies to a degraded meter:
    -- when the shared dict failed we do not know the real rate, and throttling
    -- on a number we could not read is how a measurement bug becomes an
    -- outage. Fail open, keep the telemetry.
    if ctx.automation_degraded then return true, false end

    local mode = c.mode or "shadow"
    if mode ~= "enforce" then return true, false end

    -- A tier may stay in observation while others enforce. This is what makes
    -- the rollout safe: the operator can pace OpenAI without touching the
    -- `unknown` tier, where real users misclassified as automation would land.
    local enforce_tiers = c.enforce_tiers
    if type(enforce_tiers) == "table" and enforce_tiers[tier] ~= true then
        return true, false
    end

    local axis = (ctx.automation_breached or {})[1] or top.axis
    return false, throttle(ctx, c, axis)
end

function _M.run(ctx)
    local c = conf()
    if c.enabled == false or c.mode == "off" then return true, false end
    if not ctx.automation_meter_claimed and not ctx.automation_claimed then
        return true, false
    end
    if ngx.is_subrequest then return true, false end

    -- One cached Redis lookup only for machine-shaped/claimed automation, not
    -- for ordinary traffic.  Positive evidence changes the meter tier but does
    -- not bypass any detector or access rule.
    operator_network.resolve(ctx)

    ctx.automation_mode = c.mode or "shadow"
    ctx.automation_tier = ctx.automation_tier or "unknown"
    ctx.automation_principal = ctx.automation_principal or "automation-client"

    -- Suspension is decided here but APPLIED after the meters below, so a
    -- suspended principal still shows its real pull in the log. Thoat ngay o
    -- day thi `pair()` khong chay va `autcost=`/`autps=`/`autfs=`/`autss=`
    -- thanh `-` — tuc mat dung cot dung de tra loi "gptbot dang keo bao nhieu"
    -- va khong con so sanh duoc truoc/sau khi bat cong tac. 403 van den TRUOC
    -- backend vi `run()` la buoc 3 cua STEPS_ADMISSION, truoc l7_admission,
    -- endpoint_guard, circuit va surge.
    local suspended_now = false
    do
        local p = tostring(ctx.automation_principal):lower()
        local suspended = c.suspended_principals
        suspended_now = ctx.automation_mode == "enforce"
            and ctx.automation_tier == "operator"
            and type(suspended) == "table"
            and suspended[p] == true
    end

    local dict = ngx.shared and ngx.shared.antibot_cache
    if not dict then
        ctx.automation_observed = true
        ctx.automation_degraded = true
        -- Meter hong thi KHONG fail-open o day: suspend la quyet dinh cua
        -- operator, khong phu thuoc mot con so doc duoc. `throttle()` moi can
        -- fail-open vi no throttle THEO so.
        if suspended_now then
            return false, suspend_operator(ctx, c,
                tostring(ctx.automation_principal):lower())
        end
        return _M.evaluate(ctx)
    end

    local class = ctx.req_class or "unknown"
    local cost = tonumber((c.costs or {})[class]) or 1
    local host = ((ctx.req and ctx.req.host) or ngx.var.host or "-"):lower()
    local ip = tostring(ctx.ip or "-")
    local principal = tostring(ctx.automation_principal)
    local now = ngx.time()
    local windows = c.windows or { short = 10, long = 60 }

    local ps, pl, pe = pair(dict, "p", host .. "\0" .. principal,
        windows, cost, now)
    local is, il, ie = pair(dict, "i", host .. "\0" .. ip,
        windows, cost, now)
    local hs, hl, he = pair(dict, "h", host, windows, cost, now)
    local ss, sl, se = pair(dict, "s", "server", windows, cost, now)
    -- Truc `fleet`: principal tren TOAN MAY, khong gan host.
    --
    -- Truc `p` o tren khoa theo `(host, principal)`, nen mot crawler quet N
    -- domain nhan N ngan sach doc lap. Do duoc tren cloud28-246 18-10: GPTBot
    -- di qua 17 domain, tuc han muc operator 8/10s thanh hieu dung 136/10s.
    -- Day la phep NHAN mau so, va no khong sua duoc bang cach ha `p` (ha nua
    -- thi mot site don le bi siet oan) cung khong sua dung bang `server` (truc
    -- do gop MOI principal, nen Perplexity voi 20/5.929 request bi chan vi
    -- OpenAI keo).
    --
    -- `canonical_name` (core/ctx/init.lua:146) da chuan hoa doc lap host, nen
    -- dung truc tiep lam khoa.
    local fs, fl, fe = pair(dict, "f", principal, windows, cost, now)

    ctx.automation_observed = true
    ctx.automation_cost = cost
    ctx.automation_principal_short = ps
    ctx.automation_principal_long  = pl
    ctx.automation_ip_short = is
    ctx.automation_ip_long  = il
    ctx.automation_host_short = hs
    ctx.automation_host_long  = hl
    ctx.automation_server_short = ss
    ctx.automation_server_long  = sl
    ctx.automation_fleet_short = fs
    ctx.automation_fleet_long  = fl
    if pe or ie or he or se or fe then ctx.automation_degraded = true end

    -- Ap dung suspend SAU khi moi dong ho da cong: `autfs`/`autfl`/`autps`
    -- giu nguyen gia tri that, nen `autthr.sh` muc 5 van doc duoc dinh tai
    -- cua principal bi tam dung va so sanh duoc voi truoc khi bat cong tac.
    if suspended_now then
        return false, suspend_operator(ctx, c,
            tostring(ctx.automation_principal):lower())
    end

    return _M.evaluate(ctx)
end

return _M
