local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local ESCALATE_RATE_LIMIT = 60   -- 1 viol incr / 60s tối đa per identity

-- Grace period sau lần ban đầu tiên: user mất mạng / mất internet vài phút,
-- F5 retry → 403 → nếu escalate ngay sẽ thành permanent ban oan. Đợi 5 phút
-- mới escalate — bot persistent vẫn vượt threshold này, user thường giải
-- quyết network rồi quay lại sau ban TTL.
local BAN_ESCALATE_GRACE = 300

-- Ngưỡng "phiên đã thiết lập" (đăng nhập) — GIỮ ĐỒNG BỘ với
-- enforcement/decision/engine.lua AUTH_SESSION_RICHNESS + cfg.ip_tour.richness_max.
local SHARED_ID_RICHNESS = 0.5

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

    -- One round-trip: operator identity-whitelist (admin UI "Whitelist identity")
    -- + ban state. wl:id takes precedence and bypasses the pipeline.
    red:init_pipeline()
    red:get("wl:id:" .. id)
    red:get("ban:" .. id)
    local res = red:commit_pipeline()
    pool.put(red)

    local wl_val = res and res[1]
    local val    = res and res[2]

    if wl_val == "1" then
        ctx.whitelisted   = true
        ctx.action_reason = "id_whitelist"
        ctx.banned        = false
        ngx.log(ngx.INFO, "[ban_store] id_whitelist bypass id=", id:sub(1, 8))
        return false, false
    end

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

        -- ── Shared-identity FP guard (Fix A + Fix B) ─────────────────────
        -- identity = md5(ip+ua_norm), mà ua_norm gộp Chrome về "Chrome/<major>"
        -- (bỏ minor/build/OS) → cả một văn phòng (chung IP NAT + cùng major
        -- browser) COLLAPSE về MỘT identity. ban:<id> khi đó KHÔNG per-device mà
        -- per-(IP, browser-major) → một ban khóa cả văn phòng, và mỗi F5 của mọi
        -- người còn escalate ban tới permanent. Hai lối thoát cho NGƯỜI THẬT,
        -- giữ nguyên seal cho bot (richness~0, không giải nổi PoW):
        local richness = ctx.session_richness or 0

        -- Fix A — phiên đã đăng nhập. session_richness tính PER-REQUEST từ
        -- cookie/auth của CHÍNH request → phân biệt được từng người trong cùng
        -- identity hash bị collapse. Bỏ seal + KHÔNG escalate, trả về pipeline
        -- cho scoring phán LIVE (score~0 → allow). Nhất quán auth_session_cap
        -- (engine) nhưng áp ở ĐÚNG tầng — ban read seal TRƯỚC khi engine chạy.
        if richness >= SHARED_ID_RICHNESS then
            ngx.log(ngx.INFO, "[ban_store] richness_bypass id=", id:sub(1, 8),
                " r=", string.format("%.2f", richness))
            ctx.banned = false
            return false, false
        end

        -- Fix B — IP chia sẻ (văn phòng/CGNAT: distinct raw-UA ≥ 6). Nhân viên
        -- DUYỆT ẨN DANH (richness thấp) vẫn dính collapse. Với request render
        -- được HTML (Accept: text/html) → serve PoW thay vì seal 403: người thật
        -- giải 1 lần → verified:<cookie> → bypass ở cookie fast-path (init.lua)
        -- cho MỌI request sau; bot không giải nổi → vẫn chặn hiệu quả. KHÔNG
        -- escalate (challenge không phải bằng chứng bot). Request không render
        -- HTML (XHR/static) rơi xuống seal cứng bên dưới — nhưng navigation đầu
        -- tiên đã verify nên các request sau được cookie fast-path tha.
        local accept = (ctx.req and ctx.req.accept) or ngx.var.http_accept or ""
        if ctx.ip_shared and accept:find("text/html", 1, true) then
            pool.safe_set("ban:hit:" .. id, tostring(ngx.time()), 300)
            ctx.action        = "challenge"
            ctx.action_reason = "banned_id_shared_challenge"
            ngx.log(ngx.INFO, "[ban_store] shared_challenge id=", id:sub(1, 8),
                " ip=", ctx.ip or "?", " r=", string.format("%.2f", richness))
            require("antibot.enforcement.challenge").run(ctx)  -- serve PoW + exit 200
            return true, true
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
