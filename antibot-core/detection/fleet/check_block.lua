local _M   = {}
local pool = require "antibot.core.redis_pool"

-- GIỮ ĐỒNG BỘ với CRAWLER24_PREFIX trong detection/bot/init.lua.
local CRAWLER24_PREFIX = "crawler24:"

-- Fleet dynamic-block enforcement check.
--
-- Runs inside STEPS_COMMON right AFTER the fleet aggregator (init.lua:50 then
-- :54) — deliberately, so traffic that is already dyn-blocked keeps feeding the
-- bucket and the analyzer has something to re-detect from. Blocked requests
-- still short-circuit here, before session/ban/transport/score.
--
-- Reads two keys per request via a single Redis pipeline (GET x2):
--   fl:dyn:<cidr_24>   written by analyzer.update_sustained() after a /24
--                      stays "confirm" for cfg.enforce.sustained_minutes.
--   fl:dyn:<cidr_16>   written by analyzer when rollup count >= rollup.min.
--
-- Either present → ngx.exit(444) with `action_reason = fleet_dyn_block_<24|16>:<cidr>`
-- and `ctx.fleet_blocked = matched_cidr` for downstream logging.
--
-- MIỄN TRỪ crawler đã xác minh (`ctx.is_known_crawler`, do fleet/aggregator đặt):
--   Fleet chạy TRƯỚC toàn bộ tầng xác minh, nên crawler hợp lệ phân tán trên
--   nhiều IP (cấu trúc giống hệt một đội cào) bị chặn ở cửa và KHÔNG BAO GIỜ có
--   cơ hội chứng minh mình là ai. Đo 2026-08-08: 20.042 lượt Baiduspider thật bị
--   RST mỗi ngày trên cloud168-101 = 25% tổng số lệnh chặn.
--   Xem chú thích CRAWLER_PREFIX trong detection/bot/init.lua để biết dấu được
--   cấp cho những bằng chứng nào (và vì sao KHÔNG cấp cho cloud attest).
--
-- KHÔNG log ở nhánh miễn trừ: request được thả sẽ tự hiện trong antibot.log với
-- reason=good_bot_verified/contact_* — đó đã là dấu vết kiểm toán. Log thêm ở đây
-- là hàng chục nghìn dòng/ngày cho đúng nhóm đông nhất (đã mắc lỗi này ngày
-- 2026-08-06 với `[dns_rev] bad suffix`).
--
-- Why 444 (nginx-specific TCP RST) instead of 403:
--   - Subnet block is a NETWORK-LEVEL decision, not a per-request decision.
--     RST matches the semantic "this network endpoint is not for you".
--   - ~15x bandwidth saving: no response headers, no body, single RST
--     packet vs full HTTP teardown (FIN ack + payload + content-length).
--   - Avoids TIME_WAIT socket accumulation under sustained block load.
--   - Crawler interpretation: bots typically treat persistent connection
--     resets as "host unreachable" and drop URLs from queue, while 403
--     reads as "try again later" and invites retry cycles.
--   - SEO risk if accidentally applied to search engines (Google may
--     deindex on persistent RST) — empirically not an issue because
--     Googlebot/Bingbot distribute traffic across many /16 and never
--     cross fleet thresholds; if it ever happens, operator catches via
--     Search Console "URL unreachable" and DELs the dyn key in minutes.
--
-- Enforcement is independent of `cfg.fleet_detection.mode`: if dyn keys
-- exist they are honored, even if mode is later flipped back to "shadow".
-- Keys carry their own TTL (cfg.timing.dyn_block_ttl, default 1h) so a
-- false dyn block self-heals; operator can also `DEL fl:dyn:<cidr>` to
-- revoke immediately.
--
-- Fail-open: any Redis error → return without blocking. Better to let a
-- known-fleet request through than to 403 all real users when Redis is
-- unreachable.

local function ip_to_cidr_24(ip)
    local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. "." .. c .. ".0/24"
end

local function ip_to_cidr_16(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. ".0.0/16"
end

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then return true, false end
    if ip == "127.0.0.1" then return true, false end
    if ip:find(":", 1, true) then return true, false end

    local cidr_24 = ip_to_cidr_24(ip)
    if not cidr_24 then return true, false end
    local cidr_16 = ip_to_cidr_16(ip)

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[fleet.check_block] redis err: ", tostring(err))
        return true, false
    end

    red:init_pipeline()
    red:get("fl:dyn:" .. cidr_24)
    if cidr_16 then red:get("fl:dyn:" .. cidr_16) end
    red:get(CRAWLER24_PREFIX .. cidr_24)
    local res, perr = red:commit_pipeline()
    pool.put(red)
    if not res then
        ngx.log(ngx.WARN, "[fleet.check_block] pipeline err: ", tostring(perr))
        return true, false
    end

    local function val(x)
        if x == nil or x == ngx.null then return nil end
        return x
    end

    local v24 = val(res[1])
    local v16 = cidr_16 and val(res[2]) or nil

    -- Dấu /24 đọc kèm trong CÙNG pipeline (không thêm RTT). Đặt cờ TRƯỚC mọi
    -- đường thoát để detection/bot/init.lua biết khỏi ghi lại dấu còn hạn.
    ctx.crawler_subnet_marked = val(res[cidr_16 and 3 or 2]) ~= nil

    if not v24 and not v16 then return true, false end

    -- Crawler đã chứng minh danh tính ở lượt trước → thả xuống pipeline như
    -- thường. Nó vẫn bị chấm điểm, vẫn chịu trần good_bot_rate; chỉ không bị
    -- fleet RST oan. Cờ do fleet/aggregator đặt — nó chạy TRƯỚC module này
    -- (xem thứ tự STEPS_COMMON trong init.lua) nên ở đây không tốn Redis.
    if ctx.is_known_crawler then return true, false end

    -- Miễn trừ cả /24 khi dải đó đã có crawler chứng minh bằng DNS hai chiều.
    -- Đây là mảnh khép vòng: dấu per-IP không cứu nổi IP MỚI trong một /24 đang
    -- bị chặn (nó chết trước khi kịp xác minh), nên cờ được nuôi vô hạn.
    -- Xem chú thích CRAWLER24_PREFIX ở detection/bot/init.lua để biết vì sao
    -- ranh giới cấp dấu hẹp hơn hẳn dấu per-IP.
    if ctx.crawler_subnet_marked then return true, false end

    local matched, scope, info
    if v24 then matched, scope, info = cidr_24, "24", v24
    else        matched, scope, info = cidr_16, "16", v16 end

    ctx.action = "block"
    ctx.action_reason   = "fleet_dyn_block_" .. scope .. ":" .. matched
    ctx.fleet_blocked   = matched
    ctx.fleet_block_info = info

    ngx.log(ngx.WARN,
        "[fleet.check_block] blocked ip=", ip,
        " match=", matched,
        " scope=/", scope,
        " info=", tostring(info))

    -- TCP RST without HTTP response. See header comment for rationale.
    ngx.exit(444)
    return true, true
end

return _M
