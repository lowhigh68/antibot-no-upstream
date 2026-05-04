local _M   = {}
local pool = require "antibot.core.redis_pool"

-- Distributed Swarm Detector — bắt residential-proxy botnet rotate IP.
--
-- Pattern: cùng UA chính xác + cùng domain đích + rất nhiều /24 khác nhau
-- trong cửa sổ ngắn. User thật không bao giờ có pattern này (1 user = 1 /24,
-- CGNAT cùng ISP /24 vẫn chỉ đếm = 1).
--
-- Lưu trữ: Redis HyperLogLog count unique /24 per (domain, ua_hash).
-- O(1) memory/request, PFCOUNT chính xác đủ ở scale hàng trăm.
--
-- Window sliding 60s (EXPIRE reset mỗi request). Attack dừng > 60s thì reset.
--
-- Class-aware thresholds (calibrated cho VN e-commerce traffic patterns):
--   navigation: NỚI rộng — popular product page giờ vàng tự nhiên có
--     30+ /24 cùng UA Chrome (organic flash crowd). Bot thật cần đến
--     45+ /24 mới hard.
--   auth_endpoint: SIẾT — login page rất hiếm có nhiều user concurrent.
--     8+ /24 cùng UA hit /wp-login = credential stuffing botnet.
--   api_callback: SIẾT — webhook server-to-server rất hiếm distributed.
--   feed_or_meta: NỚI — Bingbot/Googlebot crawl sitemap fan-out
--     từ many /24 hợp pháp.
--   interaction / inapp_browser: trung gian.
--   unknown: giữ legacy default conservative.
--
-- Weight (compute.lua DEFAULT_WEIGHTS.swarm_attack = 120) GIỮ NGUYÊN —
-- chỉ thay đổi sensitivity per class, không thay đổi scoring math.
--
-- Thresholds đặt in-code (git tracked) thay vì Redis để dễ audit + revert.

local WINDOW_TTL = 60   -- HLL tự reset sau 60s không có request mới

local THRESHOLDS = {
    navigation    = { soft = 25, hard = 45 },
    interaction   = { soft = 20, hard = 35 },
    api_callback  = { soft = 12, hard = 25 },
    auth_endpoint = { soft = 8,  hard = 15 },
    feed_or_meta  = { soft = 45, hard = 90 },
    inapp_browser = { soft = 20, hard = 35 },
    unknown       = { soft = 15, hard = 30 },
}
local DEFAULT_TH = { soft = 15, hard = 30 }

local function get_ip24(ip)
    if not ip or ip == "" then return nil end
    local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. "." .. c
end

function _M.run(ctx)
    -- Whitelist/verified đã pass → không cần đếm vào swarm
    if ctx.whitelisted or ctx.verified then return true, false end

    -- Resource request (CSS/JS/image) không phải target của swarm; skip để
    -- không làm nhiễu counter (real user load 1 page kéo theo hàng chục resource).
    local class = ctx.req_class or "unknown"
    if class == "resource" then return true, false end

    local ip = ctx.ip
    local ua = ctx.ua
    if not ip or ip == "" or not ua or ua == "" then
        return true, false
    end

    local ip24 = get_ip24(ip)
    if not ip24 then return true, false end

    local host = (ctx.req and ctx.req.host) or ngx.var.host
    if not host or host == "" then return true, false end

    local ua_hash = ngx.md5(ua):sub(1, 12)
    local key = "swarm:" .. host .. ":" .. ua_hash

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[swarm] redis err: ", tostring(err))
        return true, false
    end

    red:init_pipeline()
    red:pfadd(key, ip24)
    red:pfcount(key)
    red:expire(key, WINDOW_TTL)
    local res, perr = red:commit_pipeline()
    pool.put(red)

    if not res then return true, false end

    local count = tonumber(res[2]) or 0
    ctx.swarm_subnet_count = count

    -- Class-aware threshold lookup — bypass scoring quá nặng cho flash crowd
    local th = THRESHOLDS[class] or DEFAULT_TH

    if count >= th.hard then
        ctx.swarm_attack = 1.0
        ngx.log(ngx.WARN,
            "[swarm] DISTRIBUTED ATTACK",
            " host=", host,
            " class=", class,
            " ua_hash=", ua_hash,
            " unique_24=", count, "/", th.hard,
            " ip=", ip)
    elseif count >= th.soft then
        -- Ramp soft→hard tuyến tính → 0.3→0.9. Tránh false positive cho
        -- flash crowd, vẫn góp score đủ để action=monitor/challenge.
        local span = th.hard - th.soft
        ctx.swarm_attack = 0.3 + (count - th.soft) / span * 0.6
        ngx.log(ngx.INFO,
            "[swarm] emerging pattern",
            " host=", host,
            " class=", class,
            " ua_hash=", ua_hash,
            " unique_24=", count,
            " (soft=", th.soft, " hard=", th.hard, ")")
    end

    return true, false
end

return _M
