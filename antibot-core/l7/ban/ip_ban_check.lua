local _M   = {}
local pool = require "antibot.core.redis_pool"
local ua_claim = require "antibot.detection.bot.ua_claim"

local CRAWLER_PREFIX = "crawler:"

-- Substring token trong UA để nhận diện claim "good bot".
-- Match ở đây CHỈ để defer, không để allow. DNS verify ở
-- detection/bot sẽ là người quyết định cuối cùng.
function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    local banned = pool.safe_get("ban:" .. ip)
    if banned == "1" then
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
