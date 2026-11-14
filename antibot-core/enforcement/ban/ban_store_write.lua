local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local ip_scope = require "antibot.core.ip_scope"
local quarantine = require "antibot.core.network_quarantine"

-- One incident advances the actor ladder exactly once.  Concurrent requests
-- behind the winner observe the existing seal and only refresh the short hit
-- marker; they do not become separate offences.
local BAN_CLAIM_SCRIPT = [[
local existing = redis.call("EXISTS", KEYS[1])
if existing == 1 then
    local viol = tonumber(redis.call("GET", KEYS[2])) or 0
    local ttl  = redis.call("TTL", KEYS[1])
    redis.call("SETEX", KEYS[3], 300, ARGV[2])
    return {0, viol, ttl}
end

local viol = redis.call("INCR", KEYS[2])
redis.call("EXPIRE", KEYS[2], tonumber(ARGV[1]))
local count = tonumber(ARGV[3]) or 1
local idx = viol
if idx < 1 then idx = 1 end
if idx > count then idx = count end
local ttl = tonumber(ARGV[4 + idx])

redis.call("SETEX", KEYS[1], ttl, "1")
redis.call("SETEX", KEYS[3], 300, ARGV[2])
local context = ARGV[4]
if context and context ~= "" then
    context = string.gsub(context,
        '"ban_viol":"__BAN_VIOL__"',
        '"ban_viol":' .. tostring(viol), 1)
    redis.call("SETEX", KEYS[4], ttl, context)
end
return {1, viol, ttl}
]]

local function sentence_steps(qcfg)
    local source = qcfg.steps or {300, 3600, 86400}
    local out = {}
    for i = 1, #source do
        local ttl = math.floor(tonumber(source[i]) or 0)
        if ttl > 0 then out[#out + 1] = ttl end
    end
    if #out == 0 then out[1] = 300 end
    return out
end

local function claim_actor(red, keys, steps, violation_ttl, now_ts, context)
    local argv = {
        BAN_CLAIM_SCRIPT, 4,
        keys.ban, keys.viol, keys.hit, keys.context,
        tostring(violation_ttl), tostring(now_ts), tostring(#steps),
        context or "",
    }
    for i = 1, #steps do argv[#argv + 1] = tostring(steps[i]) end
    local result, err = red:eval(unpack(argv))
    if not result then return nil, err end
    return {
        created   = tonumber(result[1]) == 1,
        violation = tonumber(result[2]) or 0,
        ttl       = tonumber(result[3]) or -2,
    }
end

function _M.run(ctx)
    if not ctx then return end
    local keys = quarantine.keys(ctx, "host")
    if not keys or ip_scope.is_self(ctx) then
        ctx.ban_created   = false
        ctx.ban_persisted = false
        ctx.ban_violation = nil
        ctx.ban_ttl       = nil
        ctx.ban_suppressed = keys and "self_traffic" or "no_presented_actor"
        return
    end

    ctx.ban_id_kind = "actor"
    ctx.ban_id       = keys.id
    ctx.ban_scope    = "host"
    ctx.ban_host     = keys.host
    ctx.ban_key      = keys.ban

    local context = ""
    local ok, cjson = pcall(require, "cjson")
    if ok then
        local good, encoded = pcall(cjson.encode, {
            domain      = keys.host,
            score       = math.floor(ctx.score or 0),
            eff_score   = math.floor(ctx.effective_score or 0),
            action      = ctx.action or "block",
            reason      = ctx.action_reason or "score_block",
            req_class   = ctx.req_class or "unknown",
            ts          = ngx.time(),
            actor_id    = keys.id,
            actor_kind  = ctx.actor_kind or "signed",
            network_id  = ctx.network_id or "", -- telemetry, never subject
            ban_scope   = "host",
            ban_host    = keys.host,
            ban_key     = keys.ban,
            ban_viol    = "__BAN_VIOL__",
            ip          = ctx.ip or "",
            ua          = (ctx.ua or ""):sub(1, 180),
        })
        if good then context = encoded end
    end

    local red, err = pool.get()
    if not red then
        ctx.ban_created   = false
        ctx.ban_persisted = false
        ctx.ban_suppressed = "redis_unavailable"
        ngx.log(ngx.ERR, "[ban_write] redis unavailable: ", tostring(err))
        return
    end

    local qcfg = cfg.network_quarantine or {}
    local claim, claim_err = claim_actor(
        red, keys, sentence_steps(qcfg),
        qcfg.violation_ttl or cfg.ttl.violation or 172800,
        ngx.time(), context)
    pool.put(red)

    if not claim then
        ctx.ban_created   = false
        ctx.ban_persisted = false
        ctx.ban_suppressed = "claim_failed"
        ngx.log(ngx.ERR, "[ban_write] actor claim failed: ", tostring(claim_err))
        return
    end

    ctx.ban_created       = claim.created
    ctx.ban_persisted     = true
    ctx.ban_violation     = claim.violation
    ctx.ban_previous_viol = math.max(claim.violation - 1, 0)
    ctx.ban_ttl           = claim.ttl
    ctx.ban_suppressed    = nil

    ngx.log(ngx.INFO,
        "[ban_write] actor=", keys.id:sub(1, 8), "...",
        " host=", keys.host,
        " created=", tostring(claim.created),
        " viol=", tostring(claim.violation),
        " ttl=", tostring(claim.ttl),
        " reason=", ctx.action_reason or "score_block")
end

return _M
