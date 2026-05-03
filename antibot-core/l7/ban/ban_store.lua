local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local ESCALATE_RATE_LIMIT = 60   -- 1 viol incr / 60s tối đa per identity

-- Grace period sau lần ban đầu tiên: user mất mạng / mất internet vài phút,
-- F5 retry → 403 → nếu escalate ngay sẽ thành permanent ban oan. Đợi 5 phút
-- mới escalate — bot persistent vẫn vượt threshold này, user thường giải
-- quyết network rồi quay lại sau ban TTL.
local BAN_ESCALATE_GRACE = 300

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
    -- PHẢI cùng order với enforcement/ban/ban_store_write.lua (identity trước
    -- fp_light). identity = md5(ip+ua_norm); fp_light = md5(ip+ua+asn+ja3+h2).
    -- Hai hash KHÁC NHAU → nếu order ngược, write key X mà read key Y →
    -- ban Redis tồn tại nhưng không bao giờ được tìm thấy → bot lọt mãi.
    local id = ctx.identity or ctx.fp_light
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
        local now = ngx.time()

        -- Mỗi 403 hit = bot vẫn cố tấn công → escalate viol để tiến tới
        -- permanent ban nhanh hơn (thay vì chờ ban expire rồi mới incr).
        -- Rate limit 1 incr/60s để không spam Redis (bot retry 30/min không
        -- thành 30 viol). Tận dụng ban:hit:<id> làm timestamp.
        local last_hit = pool.safe_get("ban:hit:" .. id)
        local should_escalate = (not last_hit) or
                                (now - (tonumber(last_hit) or 0) > ESCALATE_RATE_LIMIT)

        -- Grace period: chỉ escalate sau khi ban đã active >= BAN_ESCALATE_GRACE.
        -- User mất mạng F5 retry trong 5 phút đầu KHÔNG bị tăng TTL ban.
        -- Bot persistent ≥ 5 phút vẫn bị escalate bình thường.
        local ban_age_key = "ban:age:" .. id
        local ban_age_str = pool.safe_get(ban_age_key)
        if not ban_age_str then
            pool.safe_set(ban_age_key, tostring(now), 86400)
            should_escalate = false
        else
            local age = now - (tonumber(ban_age_str) or now)
            if age < BAN_ESCALATE_GRACE then
                should_escalate = false
                ngx.log(ngx.DEBUG,
                    "[ban_store] escalate_grace id=", id:sub(1, 8),
                    " ban_age=", age, "s")
            end
        end

        if should_escalate then
            local new_viol = pool.safe_incr("viol:" .. id, cfg.ttl.violation) or 1
            local steps    = cfg.ttl.ban_steps
            local idx      = math.min(new_viol, #steps)
            local new_ttl  = steps[idx]
            if new_ttl == 0 then
                pool.safe_set("ban:" .. id, "1")          -- permanent
            elseif new_ttl > 0 then
                pool.safe_set("ban:" .. id, "1", new_ttl) -- extend
            end
            ngx.log(ngx.INFO,
                "[ban_store] escalate id=", id:sub(1, 8),
                " viol=", new_viol,
                " ttl=", new_ttl == 0 and "permanent" or tostring(new_ttl) .. "s")
        end

        pool.safe_set("ban:hit:" .. id, tostring(now), 300)
        ngx.log(ngx.INFO, "[ban_store] blocked id=", id:sub(1, 8), "...")
        ctx.action        = "block"
        ctx.action_reason = "banned_id"
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
