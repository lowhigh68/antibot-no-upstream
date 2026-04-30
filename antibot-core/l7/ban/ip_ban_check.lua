local _M   = {}
local pool = require "antibot.core.redis_pool"

-- Substring token trong UA để nhận diện claim "good bot".
-- Match ở đây CHỈ để defer, không để allow. DNS verify ở
-- detection/bot sẽ là người quyết định cuối cùng.
local function ua_claims_good_bot(ua)
    if not ua or ua == "" then return false end
    local ul = ua:lower()
    return ul:find("bot", 1, true) ~= nil
        or ul:find("spider", 1, true) ~= nil
        or ul:find("crawler", 1, true) ~= nil
        or ul:find("facebookexternal", 1, true) ~= nil
        or ul:find("mediapartners", 1, true) ~= nil
        or ul:find("bingpreview", 1, true) ~= nil
        or ul:match("meta%-external") ~= nil
end

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    local banned = pool.safe_get("ban:" .. ip)
    if banned == "1" then
        -- Defer nếu UA claim good bot — để DNS verify ở detection/bot quyết định.
        -- Bot thật (IP thuộc Google/Bing/FB) → pass good_bot_verified → allow.
        -- UA spoof từ IP không phải crawler → DNS verify fail → scoring re-block.
        -- Tránh stale ban (từ trước khi có engine short-circuit) chặn oan good bot.
        local ua = ngx.var.http_user_agent or ""
        if ua_claims_good_bot(ua) then
            ngx.log(ngx.INFO,
                "[ip_ban] defer good_bot_claim ip=", ip,
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
