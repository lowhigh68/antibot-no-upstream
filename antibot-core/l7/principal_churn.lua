-- Generic automation-principal churn quarantine.
--
-- A source that calls itself several unrelated automation operators in one
-- short window is contradictory regardless of the vendor names involved.  We
-- count canonical principals, never maintain an AI-bot list here, and use two
-- axes: source IP and source IP + JA3 when transport evidence is available.
-- The temporary quarantine is capacity control only; it writes no reputation
-- and no durable ban.

local _M  = {}
local cfg = require "antibot.core.config"
local policy = require "antibot.core.policy"
local decision = require "antibot.core.decision"

local last_dict_error = 0

local function conf(ctx)
    return policy.section(ctx, "principal_churn", cfg.principal_churn or {})
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function dictionary()
    return ngx.shared and ngx.shared.antibot_cache
end

local function digest(value)
    value = tostring(value or "")
    if ngx.md5 then return ngx.md5(value):sub(1, 16) end
    return value:gsub("[^%w_.-]", "_"):sub(1, 64)
end

local function log_dict_error(where, err)
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR, "[principal_churn] shared-dict error at ", where,
            ": ", tostring(err or "unknown"), " (fail-open)")
    end
end

local function principal(ctx)
    if not ctx or ctx.automation_meter_claimed ~= true then return nil end
    local value = tostring(ctx.automation_principal or ""):lower()
    if value == "" or value == "-" then return nil end
    return value
end

local function source(ctx)
    local value = tostring((ctx and ctx.ip) or ngx.var.remote_addr or "")
    if value == "" or value == "-" then return nil end
    return value
end

local function increment(dict, key, ttl)
    local value, err = dict:incr(key, 1)
    if not value then
        if err ~= "not found" then return nil, err end
        local added, add_err = dict:add(key, 1, ttl)
        if added then
            value = 1
        elseif add_err == "exists" then
            value, err = dict:incr(key, 1)
            if not value then return nil, err end
        else
            return nil, add_err
        end
    end
    if dict.expire then
        local ok, expire_err = dict:expire(key, ttl)
        if not ok then return value, expire_err or "expire failed" end
    end
    return value
end

local function observe_axis(dict, axis, subject, principal_value,
                            threshold, c, ctx, t)
    local hold = math.max(math.floor(tonumber(c.hold_seconds) or 120), 1)
    local open_key = "pc:" .. axis .. ":" .. subject .. ":open"
    local open_until = tonumber(dict:get(open_key))
    if open_until and open_until > t then
        return true, tonumber(dict:get(
            "pc:" .. axis .. ":" .. subject .. ":last_n")) or threshold
    end

    local window = math.max(math.floor(tonumber(c.window) or 30), 1)
    local bucket = math.floor(t / window)
    local ttl = window * 2 + 2
    local base = "pc:" .. axis .. ":" .. subject .. ":"
        .. tostring(bucket)
    local count_key = base .. ":n"
    local count = tonumber(dict:get(count_key)) or 0
    local fresh = false

    -- Stop allocating marker keys once the bounded threshold has been met.
    -- Attacker-selected product strings cannot create unbounded state for one
    -- source/window.
    if count < threshold then
        local marker = base .. ":p:" .. digest(principal_value)
        local added, add_err = dict:add(marker, 1, ttl)
        if added then
            fresh = true
            local n, nerr = increment(dict, count_key, ttl)
            if not n then
                ctx.principal_churn_degraded = true
                log_dict_error(axis .. "_count", nerr)
                return false, count
            end
            if nerr then
                -- The count changed but its expiry is not trustworthy.  Keep
                -- telemetry and force every enforce decision to fail open.
                ctx.principal_churn_degraded = true
                log_dict_error(axis .. "_count_ttl", nerr)
            end
            count = n
        elseif add_err ~= "exists" then
            ctx.principal_churn_degraded = true
            log_dict_error(axis .. "_marker", add_err)
            return false, count
        end
    end

    if count < threshold or not fresh or ctx.principal_churn_degraded then
        return false, count
    end
    local until_at = t + hold
    local ok, err = dict:set(open_key, until_at, hold)
    if not ok then
        ctx.principal_churn_degraded = true
        log_dict_error(axis .. "_open", err)
        return false, count
    end
    dict:set("pc:" .. axis .. ":" .. subject .. ":last_n", count, hold)
    return true, count
end

local function reject(ctx, c, axis)
    local status = tonumber(c.status) or 429
    ctx.principal_churn_rejected = true
    ctx.action = "throttled"
    ctx.action_reason = "principal_churn:" .. tostring(axis)
    decision.set(ctx, {
        kind = "security", source = "principal_churn", rule = axis,
        mode = "enforce", scope = axis == "ja3" and "ip_ja3" or "ip",
        subject = ctx.ip, upstream = false,
    })
    ngx.header["Retry-After"] = tostring(c.retry_after or 30)
    ngx.header["Cache-Control"] = "no-store"
    ngx.status = status
    ngx.say("Conflicting automation identities. Please retry later.")
    ngx.exit(status)
    return false, true
end

local function observe(ctx, include_ja3)
    local c = conf(ctx)
    local mode = tostring(c.mode or "off")
    if not c.enabled or mode == "off" or ngx.is_subrequest then
        return true, false
    end
    ctx.principal_churn_mode = mode

    local p, ip = principal(ctx), source(ctx)
    if not p or not ip then return true, false end
    if not include_ja3 then
        ctx.principal_churn_early_principal = p
    end
    -- On a verified reverse proxy ctx.ip is the edge, not one client.  Mixing
    -- tenants there would manufacture churn and is an unacceptable FP source.
    if ctx.behind_proxy == true then
        ctx.principal_churn_proxy_skip = true
        return true, false
    end

    local dict = dictionary()
    if not dict then
        ctx.principal_churn_degraded = true
        return true, false
    end
    local t = now()
    local ip_subject = digest(ip)
    local ip_threshold = math.max(math.floor(
        tonumber(c.ip_threshold) or 4), 2)
    -- Full bot detection may refine a display/canonical name.  The IP axis was
    -- already observed early, so reuse that exact principal at the late hook;
    -- otherwise one request could manufacture two identities by itself.
    local ip_principal = ctx.principal_churn_early_principal or p
    local ip_open, ip_n = observe_axis(dict, "ip", ip_subject, ip_principal,
        ip_threshold, c, ctx, t)
    ctx.principal_churn_ip_count = ip_n
    ctx.principal_churn_ip_limit = ip_threshold

    local ja3_open, ja3_n = false, nil
    local ja3 = include_ja3 and tostring(ctx.ja3 or "") or ""
    if ja3 ~= "" and ja3 ~= "-" then
        local ja3_threshold = math.max(math.floor(
            tonumber(c.ja3_threshold) or 3), 2)
        ja3_open, ja3_n = observe_axis(dict, "ja3",
            digest(ip .. "|" .. ja3), p, ja3_threshold, c, ctx, t)
        ctx.principal_churn_ja3_count = ja3_n
        ctx.principal_churn_ja3_limit = ja3_threshold
    end

    local open = ip_open or ja3_open
    if open then
        local axis = ja3_open and "ip_ja3" or "ip"
        ctx.principal_churn_open = true
        ctx.principal_churn_axis = axis
        ctx.principal_churn_would_reject = true
        -- Observe every automation claim, but only shed work classified as
        -- dynamic. A real static hit does not consume PHP capacity; a static
        -- miss is corrected to dynamic by admission and caught at admit().
        if mode == "enforce" and ctx.admission_group == "dynamic"
           and not ctx.principal_churn_degraded then
            return reject(ctx, c, axis)
        end
    end
    return true, false
end

-- Early IP-only observation sees churn before expensive WAF/detection work.
-- The late call adds JA3 without double-counting the same canonical principal.
function _M.before(ctx)
    return observe(ctx, false)
end

function _M.admit(ctx)
    return observe(ctx, true)
end

return _M
