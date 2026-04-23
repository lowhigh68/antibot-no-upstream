local _M   = {}
local pool = require "antibot.core.redis_pool"

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
    local id = ctx.fp_light or ctx.identity
    if not id or id == "" then
        ctx.banned = false
        return false, false
    end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_store] redis unavailable: ", err)
        ctx.banned = false
        return false, false
    end

    local val, rerr = red:get("ban:" .. id)
    pool.put(red)

    if val == "1" then
        -- Defer nếu UA claim good bot — để DNS verify ở detection/bot quyết định.
        local ua = ctx.ua or ngx.var.http_user_agent or ""
        if ua_claims_good_bot(ua) then
            ngx.log(ngx.INFO,
                "[ban_store] defer good_bot_claim id=", id:sub(1, 8),
                " ua=", ua:sub(1, 60))
            ctx.banned = false
            return false, false
        end

        ctx.banned = true
        pool.safe_set("ban:hit:" .. id, tostring(ngx.time()), 300)
        ngx.log(ngx.INFO, "[ban_store] blocked id=", id:sub(1, 8), "...")
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true
    end

    ctx.banned = false
    return false, false
end

return _M
