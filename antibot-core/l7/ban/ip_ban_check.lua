local _M   = {}
local pool = require "antibot.core.redis_pool"
local ua_claim = require "antibot.detection.bot.ua_claim"
local decision = require "antibot.core.decision"

local CRAWLER_PREFIX = "crawler:"

-- Substring token trong UA để nhận diện claim "good bot".
-- Match ở đây CHỈ để defer, không để allow. DNS verify ở
-- detection/bot sẽ là người quyết định cuối cùng.
function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end
    -- Missing/invalid client header behind a trusted proxy leaves ctx.ip at
    -- the shared edge.  Never read a historical collective ban for that edge.
    if ctx.ip_is_aggregate == true then return true, false end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ip_ban] redis unavailable: ", tostring(err))
        return true, false
    end
    red:init_pipeline()
    red:get("ban:manual:" .. ip)
    red:get("ban:" .. ip)
    red:ttl("ban:" .. ip)
    local result = red:commit_pipeline()
    pool.put(red)
    local manual = result and result[1]
    local banned = result and result[2]
    local ttl = result and tonumber(result[3]) or -2

    -- Automatic IP state is now an immediate capacity brake only.  Old
    -- 24h/30d collective sentences remain in Redis for forensic visibility but
    -- cannot keep blocking a reassigned mobile/CGNAT address.  Permanent
    -- operator intent has its own `ban:manual:<ip>` namespace; an old TTL=-1
    -- in the automatic namespace is therefore legacy too, not proof of intent.
    if banned == "1" and (ttl < 1 or ttl > 3600) then
        ctx.ip_ban_legacy_ignored = true
        ctx.ip_ban_legacy_ttl = ttl
        banned = nil
    end

    if manual == "1" or banned == "1" then
        -- Chi defer khi IP DA co positive verdict do lan xac minh truoc ghi.
        -- Self-claim khong phai bang chung: neu chi kiem UA, fake Googlebot mo
        -- duoc seal IP ban va bat he thong tra DNS/full pipeline moi request.
        local ua = ngx.var.http_user_agent or ""
        local crawler_verified = ua_claim.claims_good_bot(ua)
            and pool.safe_get(CRAWLER_PREFIX .. ip) == "1"
        if crawler_verified then
            ngx.log(ngx.INFO,
                "[ip_ban] defer cached_verified_crawler ip=", ip,
                " ua=", ua:sub(1, 60))
            return true, false
        end

        ctx.banned        = true
        ctx.action        = "block"
        ctx.action_reason = "banned_ip"
        ctx.ip_ban_ttl = manual == "1" and -1 or ttl
        ctx.ip_ban_manual = manual == "1"
        decision.set(ctx, {
            kind = "security", source = "ip_ban", rule = "banned_ip",
            mode = "enforce", scope = "ip", subject = ip,
            upstream = false,
        })
        pool.safe_set("ban:hit:" .. ip, tostring(ngx.time()), 300)
        ngx.log(ngx.INFO, "[ip_ban] blocked ip=", ip)
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true
    end

    return true, false
end

return _M
