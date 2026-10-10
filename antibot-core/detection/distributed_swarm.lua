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

-- SHADOW (07-10-2026) — MẪU SỐ, chưa dùng để quyết định.
--
-- Khoá `swarm:<host>:<ua_hash>` chỉ đếm TỬ SỐ: bao nhiêu /24 dùng MỘT UA.
-- Con số đó tỉ lệ với LƯỢNG KHÁCH của site, không tỉ lệ với mức tấn công:
-- site đông khách dùng UA phổ biến thì mọi khách bị tính vào cùng counter.
--
-- Đo 06-10 trên cloud168-123, khách thật `14.231.233.109` (bot_score=0,
-- upload POST 4,8 MB, một identity 257 lượt): `swarm_attack` trung bình
-- 75-80% của score ~90 (≈70 điểm / trọng số 120 ⇒ count≈27 trên soft=20),
-- đẩy eff 52,6 → 85,3. **4 lượt** trong 24.964 vượt ngưỡng block 80, một
-- trong số đó ghi `banned_id` → 257 lượt chặn → viol≥3 → ngày 07 `ban:<ip>`
-- TTL 86400 → 9.035 lượt `banned_ip`. Ngày 05 cùng khách cùng swarm nhưng
-- eff max 54 — THIẾU 1 ĐIỂM so với challenge 55 ⇒ 0 block.
--
-- Nâng ngưỡng tuyệt đối chỉ DỜI điểm vỡ, nên 07-10 tôi đo mẫu số:
-- `swarm:all:<host>` đếm MỌI /24 truy cập host trong cùng cửa sổ, bất kể UA.
--
-- ĐO XONG 10-10 — GIẢ THUYẾT TỈ LỆ BỊ BÁC BỎ. Giữ lại nguyên văn để không ai
-- (kể cả tôi) thử lại hướng này.
--
-- Giả thuyết: "botnet thay thế phần lớn lưu lượng host, nên `swn/swall` cao;
-- khách dùng UA phổ biến thì tỉ lệ thấp." Số đo trên cloud168-123, 12 giờ,
-- 93.205 dòng có `swr=`:
--   * 8.346 lượt `swarm_attack` bắn: `swn` trung bình **24,9**, `swall` trung
--     bình **9.929,5** ⇒ `swr ≈ 0,0025`. TẤT CẢ nằm trong bucket `swr < 0,05`.
--   * Ngược lại, 1.064 lượt có `swr = 1,00` và luật KHÔNG bắn ở đó.
--   * Một cổng `swr >= 0,15` giữ lại **0 / 8.346** lượt — tức GỠ module, không
--     phải nới ngưỡng.
--
-- Vì sao tỉ lệ không mang thông tin: các lượt `swr` cao đều có `swn` = 1..3 và
-- `swall` = 1..4 (`phutunglexus.net` 1/1 ×325 lượt, `meily.vn` 2/3 ×115). `swr`
-- = 1,0 nghĩa là MỘT dải /24 trên tổng MỘT dải — host có đúng một khách trong
-- 60 giây. Nên `swr` đo ĐỘ ĐÔNG CỦA HOST, không đo tính tập trung của một UA:
-- `swn` và `swall` cùng tăng theo lượng khách nên tỉ lệ triệt tiêu thông tin.
-- Và tiền đề cũng sai: một botnet rotate IP tự nó đóng góp vào `swall`, nên tỉ
-- lệ của nó vẫn thấp khi host có khách thật.
--
-- `swn`/`swall`/`swr` được GIỮ trong log: chúng vô hại (cùng pipeline, 0 RTT
-- thêm) và là phép đo chẩn đoán tốt. Chúng KHÔNG được vào nhánh quyết định.
--
-- Trục còn lại chưa thử — và nó đã tự chứng minh trong dữ liệu thật chứ không
-- phải suy ra rồi mới đo: SỐ IDENTITY trên cùng một UA. Ca FP có `id=52b05ed1`
-- ổn định suốt 257 lượt; đàn bot ngày 06 có 1.874 identity × 1 lượt block và
-- `risk` dừng ở 17% vì không identity nào ở lại đủ lâu. Botnet rotate IP mua
-- được nhiều /24 nhưng không mua được identity có cookie ở lại. Hướng này cần
-- shadow đo TRƯỚC khi vào quyết định, như mọi hướng khác.

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
    local key     = "swarm:" .. host .. ":" .. ua_hash
    local all_key = "swarm:all:" .. host   -- SHADOW: mẫu số, mọi UA

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[swarm] redis err: ", tostring(err))
        return true, false
    end

    -- 6 op / 1 RTT. Thứ tự CỐ ĐỊNH để chỉ số `res` xác định được:
    --   res[2] = pfcount(key)      tử số (UA này)
    --   res[5] = pfcount(all_key)  mẫu số (mọi UA trên host)
    red:init_pipeline()
    red:pfadd(key, ip24)
    red:pfcount(key)
    red:expire(key, WINDOW_TTL)
    red:pfadd(all_key, ip24)
    red:pfcount(all_key)
    red:expire(all_key, WINDOW_TTL)
    local res, perr = red:commit_pipeline()
    pool.put(red)

    if not res then return true, false end

    local count = tonumber(res[2]) or 0
    ctx.swarm_subnet_count = count

    -- SHADOW: mẫu số + tỉ lệ. KHÔNG dùng để quyết định (xem đầu file).
    -- `all` luôn >= `count` vì cùng một `ip24` được PFADD vào cả hai khoá
    -- trong MỘT pipeline, nên tỉ lệ nằm trong (0, 1]. Guard `all > 0` vẫn
    -- cần: HLL có thể trả 0 nếu Redis lỗi giữa pipeline (fail-open).
    local all = tonumber(res[5]) or 0
    if all > 0 then
        ctx.swarm_host_subnets = all
        ctx.swarm_ratio        = count / all
    end

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
