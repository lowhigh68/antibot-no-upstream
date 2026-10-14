local _M = {}

local pool         = require "antibot.core.redis_pool"
local cfg          = require "antibot.core.config"
local identity_mod = require "antibot.core.fingerprint.identity"
local ua_claim     = require "antibot.detection.bot.ua_claim"

local function extend_to_current_id(cookie, ip, ua, ttl)
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then return end
    local current_id = identity_mod.build_from(ip, ua)
    if not current_id or current_id == "" or current_id == cookie then return end
    if pool.safe_get("verified:" .. current_id) == "1" then return end
    pool.safe_set("verified:" .. current_id, "1", ttl)
    ngx.log(ngx.DEBUG,
        "[verified_human] ip_change_extend cookie=", cookie:sub(1, 8),
        " new_id=", current_id:sub(1, 8), " ip=", ip)
end

-- Resolve only the verified-HUMAN cookie lane. A crawler claim is not proof
-- that the caller is legitimate, but it identifies the verification lane:
-- bot claims must go through DNS/ASN policy and never through this fast path.
--
-- The optional side effects belong to the full access path. The root fast
-- path deliberately keeps its historical one-GET cost.
function _M.check_cookie(ctx, opts)
    opts = opts or {}
    local ua = (ctx and ctx.ua) or ngx.var.http_user_agent or ""
    if ua_claim.claims_good_bot(ua) then
        if ctx then ctx.verified_human_rejected_bot_claim = true end
        return false, "crawler_claim"
    end

    local cookie = ngx.var.cookie_antibot_fp
    if not cookie or cookie == "" then return false, "missing" end
    if pool.safe_get("verified:" .. cookie) ~= "1" then
        return false, "unverified"
    end

    ctx.verified = true
    ctx.identity = cookie
    ctx.fp_light = cookie

    local ttl = cfg.ttl.verified or 7200
    if opts.renew then
        pool.safe_set("verified:" .. cookie, "1", ttl)
    end
    if opts.mark_beacon then
        pool.safe_set("beacon:" .. cookie, "1", 600)
    end
    if opts.extend then
        pcall(extend_to_current_id, cookie, ctx.ip or "", ua, ttl)
    end

    return true, cookie
end

return _M
