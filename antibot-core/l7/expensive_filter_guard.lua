local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Expensive faceted-filter guard — RESOURCE-keyed, not caller-keyed.
--
-- Vấn đề: cả (a) verified bot (Meta) cào filter dạng PATH `/loc-a,b,c.html` lẫn
-- (b) botnet phân tán cào filter dạng QUERY `?filter_attr=a.b.c` đều nện cùng
-- một tài nguyên — không gian URL combinatorial của endpoint faceted-filter
-- (mỗi request = 1 truy vấn DB lọc nặng, uncacheable). Chúng chỉ khác 2 trục mà
-- defense hiện tại chia theo rồi RÒ: hình dạng URL (path/query) và danh tính
-- kẻ gọi (verified/scored). Kẻ tấn công XOAY chính danh tính (IP → per-IP score,
-- UA → per-bot_name rate, canvas → verified lane) để làm phân mảnh mọi bộ đếm
-- theo-caller. Xem enforcement/CLAUDE.md + [[reference_swarm_flags]].
--
-- Bất biến DUY NHẤT = tài nguyên đích (base listing path). Guard này đếm áp lực
-- combinatorial PER-BASE-PATH, gộp MỌI kẻ gọi — bất biến với IP, UA, verified.
-- Phân tán IP/UA KHÔNG giúp né: 1000 IP → 1000 đóng góp vào MỘT counter, càng
-- đông càng trip nhanh. Đặt trong STEPS_COMMON (trước ngã rẽ good_bot/verified).
--
-- Discriminator người-vs-crawler = ĐỘ ĐA DẠNG tổ hợp (distinct combos), KHÔNG
-- phải rate: người thật lọc vài tổ hợp; crawler enumerate hàng trăm. Flash-crowd
-- (rate cao, cùng vài view) → distinct thấp → không trip. KHÔNG miễn theo verified
-- (verify chiếm được — ca Meta), metric tự phân biệt.
--
-- Redis: HLL `xf:combos:<host>:<base>:<bucket>` (O(1) bộ nhớ), `xf:hits:...`.
-- Fail-open. mode: shadow (chỉ đo+log) | enforce (429 khi vượt budget) | off.

local function sep_count(s)
    -- Đếm dấu ngăn giá trị (comma/dot raw + encoded). Một field chứa nhiều
    -- giá trị ngăn cách = multi-select facet = combinatorial.
    local n = 0
    for _ in s:gmatch("[,%.]")     do n = n + 1 end
    for _ in s:gmatch("%%2[CcEe]") do n = n + 1 end
    return n
end

-- Ghi ban:<ip> 24h theo bằng chứng per-IP. Mirror enforcement/ban/ban_store_write
-- (ban:<ip> + ban:hit:<ip> + ban_ctx:<ip>) để IP hiện đúng trong admin BAN table
-- và bị seal ở cửa bởi l7/ban/ip_ban_check ở request kế. Guard exit 403 ngay tại
-- STEPS_COMMON nên enforcement/ban_store_write KHÔNG chạy — phải tự viết ở đây.
local function write_ip_ban(ctx, ip, host, base, ip_combos, hits, ttl)
    local red = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[xf] ban redis unavailable ip=", ip)
        return
    end
    local ctx_json = ""
    local ok, cjson = pcall(require, "cjson")
    if ok then
        -- score = ip_combos: số đo trung thực + sortable trong admin (guard không
        -- chạy scoring engine). Field khớp shape ban_store_write để admin render.
        local ok2, json = pcall(cjson.encode, {
            domain      = host,
            score       = ip_combos,
            eff_score   = ip_combos,
            action      = "block",
            req_class   = ctx.req_class or "unknown",
            ts          = ngx.time(),
            identity    = ctx.identity or "",
            reason      = "expensive_filter_ban",
            xf_base     = base,
            xf_ipcombos = ip_combos,
            xf_hits     = hits,
            fp_deg      = false,
            device_type = ctx.device_type or "unknown",
            ua          = (ctx.ua or ""):sub(1, 120),
            ip          = ip,
            bot_score   = 0,
        })
        if ok2 then ctx_json = json end
    end
    local now_ts = tostring(ngx.time())
    red:init_pipeline()
    red:setex("ban:" .. ip, ttl, "1")
    red:setex("ban:hit:" .. ip, 300, now_ts)   -- ACTIVE ngay trong admin
    if ctx_json ~= "" then
        red:setex("ban_ctx:" .. ip, ttl, ctx_json)
    end
    red:commit_pipeline()
    pool.put(red)
end

-- Self-declared good bot (same def as core/access/whitelist + l7/ban/ban_store).
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
    local gc = cfg.expensive_filter
    if not gc or gc.mode == "off" then return true, false end

    -- Bỏ qua infra whitelist (LAN/admin/internal) — không phải traffic cần đo.
    if ctx.whitelisted then return true, false end

    -- Resource (css/js/img): không phải target faceted-filter. Skip để tránh
    -- false-trigger trên versioned asset query (`js.cookie.min.js?ver=...`) +
    -- giảm overhead. ctx.req_class đã set (classifier.run chạy trước STEPS_COMMON).
    if ctx.req_class == "resource" then return true, false end

    -- Self-declared good bot (Googlebot/Bing/Meta): loại khỏi CẢ meter lẫn enforce.
    -- Chúng đi lane DNS/ASN registry (bằng chứng hạ tầng KHÔNG giả được — khác
    -- IP/UA/canvas) và đã bị siết bởi good_bot rate ceiling (lane riêng). Loại
    -- khỏi PHÉP ĐO để crawl hợp pháp của chúng (Googlebot ~109 combos) KHÔNG thổi
    -- phồng base counter → tránh collateral 429 cho người thật đến sau. Bot giả
    -- UA good-bot → fail DNS/ASN verify ở detection → bị scoring xử lý.
    if ua_claims_good_bot(ctx.ua or "") then return true, false end

    local uri  = ngx.var.uri  or ""
    local args = ngx.var.args or ""

    -- 1. Nhận diện chữ ký faceted-filter (generic, PATH lẫn QUERY, không
    --    enumerate tên param). card = số giá trị con lớn nhất trong MỘT field.
    local card = 0
    if args ~= "" then
        for pair in args:gmatch("[^&]+") do
            local v = pair:match("=(.*)$")
            if v then
                local c = sep_count(v)
                if c > card then card = c end
            end
        end
    end
    for seg in uri:gmatch("[^/]+") do
        -- path segment: chỉ đếm comma (dot = .html false trigger)
        local c = 0
        for _ in seg:gmatch(",") do c = c + 1 end
        if c > card then card = c end
    end

    if card < (gc.min_values or 4) then
        return true, false          -- không phải faceted-filter tốn kém
    end

    -- 2. Key tài nguyên = base listing path (bất biến với caller VÀ với tổ hợp
    --    filter). Query không nằm trong uri; strip mọi path-segment chứa comma
    --    (path-style facet) → gộp mọi biến thể của một trang listing về 1 key.
    local host = (ctx.req and ctx.req.host) or ngx.var.host or "?"
    local base = uri:gsub("/[^/]*,[^/]*", "")
    if base == "" then base = "/" end

    -- 3. Chữ ký tổ hợp NÀY (để đếm distinct combos). Query-style: md5(query);
    --    path-style: md5(uri) (đã chứa segment loc-combo).
    local sig = ngx.md5(args ~= "" and args or uri)

    -- 4. Đo distinct-combo per-base qua HLL (gộp mọi caller), + raw hits.
    local window = gc.window or 300
    local bucket = math.floor(ngx.time() / window)
    local ckey   = "xf:combos:" .. host .. ":" .. base .. ":" .. bucket
    local hkey   = "xf:hits:"   .. host .. ":" .. base .. ":" .. bucket
    -- Per-IP distinct-combo (bằng chứng crawler TẬP TRUNG — tách khỏi counter
    -- aggregate). Chỉ IP tự mình cào nhiều tổ hợp mới chạm ngưỡng ban; user thật
    -- lỡ dính 429 lúc base bị cào chỉ đóng góp 1-2 combo → không bao giờ bị ban.
    local ip     = ctx.ip or ""
    local ipckey = "xf:ipc:" .. host .. ":" .. base .. ":" .. ip .. ":" .. bucket

    local combos, hits, ip_combos = 0, 0, 0
    local red = pool.get()
    if red then
        red:init_pipeline()
        red:pfadd(ckey, sig)
        red:pfcount(ckey)
        red:expire(ckey, window + 10)
        red:incr(hkey)
        red:expire(hkey, window + 10)
        red:pfadd(ipckey, sig)
        red:pfcount(ipckey)
        red:expire(ipckey, window + 10)
        local res = red:commit_pipeline()
        pool.put(red)
        if res then
            combos    = tonumber(res[2]) or 0
            hits      = tonumber(res[4]) or 0
            ip_combos = tonumber(res[7]) or 0
        end
    end

    ctx.xf_expensive = true
    ctx.xf_base      = base
    ctx.xf_combos    = combos
    ctx.xf_hits      = hits
    ctx.xf_ipcombos  = ip_combos

    local over = combos > (gc.combos_threshold or 60)

    -- Human power-user / phiên đã thiết lập (richness cao) làm multi-facet filter:
    -- MIỄN 429 (FP protection) nhưng VẪN được đếm ở trên (để lộ nếu bot gaming
    -- cookie đạt richness cao — sẽ thấy trong xf log). Chỉ traffic KHÔNG tin cậy
    -- (richness thấp, không good-bot) mới bị chặn khi base vượt budget.
    local human_exempt = (ctx.session_richness or 0) >= (gc.exempt_richness or 0.5)

    -- 5a. BAN 24h — CHỈ theo bằng chứng PER-IP (ip_combos), TÁCH RỜI khỏi `over`.
    --     Một IP tự nó cào >= ban_ip_combos tổ hợp filter nặng trong 1 window =
    --     crawler tập trung bất khả chối (người thật 1-3). Vì không phụ thuộc
    --     `over` (resource-aggregate), user thật lỡ dính 429 lúc botnet cào KHÔNG
    --     bao giờ bị ban. Exempt: good bot + whitelist (đã return sớm ở trên),
    --     Tier-2 shared IP (office/CGNAT nhiều user cookie thật — 1 IP không được
    --     ban nuke cả nhà), phiên đã login (human_exempt). Distributed 1-req/IP
    --     swarm ~1 combo/IP → không chạm ngưỡng → giữ nguyên nhánh 429 bên dưới.
    local ip_bannable = gc.ban_enabled
        and ip ~= "" and ip ~= "127.0.0.1" and ip ~= "::1"
        and not ctx.ip_shared_verified
        and not human_exempt
        and ip_combos >= (gc.ban_ip_combos or 20)

    if gc.mode == "enforce" and ip_bannable then
        ctx.action        = "block"
        ctx.action_reason = "expensive_filter_ban"
        ctx.xf_over       = over
        write_ip_ban(ctx, ip, host, base, ip_combos, hits, gc.ban_ttl or 86400)
        -- ngx.ERR chứ KHÔNG phải ngx.WARN: chạy ở access phase, mà per-domain
        -- conf ghi đè `error_log .../<fqdn>.error.log` không kèm level → mặc
        -- định `error` → WARN bị lọc sạch. Sự kiện nặng nhất của module này mà
        -- vô hình thì không chấp nhận được.
        ngx.log(ngx.ERR,
            "[xf] BAN host=", host, " base=", base,
            " ip=", ip, " ip_combos=", ip_combos,
            " combos=", combos, " hits=", hits, " card=", card,
            " ttl=", gc.ban_ttl or 86400,
            " ua=", (ctx.ua or "-"):sub(1, 40))
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true
    end

    -- 5b. ENFORCE 429: chặn khi mode=enforce AND base vượt budget AND không miễn.
    if gc.mode == "enforce" and over and not human_exempt then
        ctx.action        = "throttled"
        ctx.action_reason = "expensive_filter"
        ngx.log(ngx.WARN,
            "[xf] THROTTLE host=", host, " base=", base,
            " combos=", combos, " hits=", hits, " card=", card,
            " verified=", tostring(ctx.verified or false),
            " ip=", ctx.ip or "?",
            " ua=", (ctx.ua or "-"):sub(1, 40))
        ngx.status = 429
        ngx.header["Retry-After"]   = tostring(gc.retry_after or 120)
        ngx.header["Cache-Control"] = "no-cache"
        ngx.header["Content-Type"]  = "text/plain"
        ngx.say("Rate limited — retry after ", gc.retry_after or 120, "s")
        ngx.exit(429)
        return true, true
    end

    -- SHADOW / under-budget: KHÔNG spam error.log. Telemetry per-request đi vào
    -- antibot.log qua async/logger.lua (fields xf_base/xf_combos/xf_hits/xf_over),
    -- nơi có đủ context (ip/ua/class/richness/reason) để correlate + hiệu chỉnh.
    -- ctx.xf_* mang dữ liệu sang log phase.
    ctx.xf_over = over
    return true, false
end

return _M
