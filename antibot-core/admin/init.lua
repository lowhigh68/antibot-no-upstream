local _M = {}
local pool = require "antibot.core.redis_pool"
local cjson = require "cjson"

local AUTH_USER = "admin-antibot"
local AUTH_PASS = "Vungoimora@6868@2025"

local function auth()
    local h = ngx.req.get_headers()["authorization"]
    if not h then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot v4.3.6"'
        ngx.exit(401); return false
    end
    local encoded = h:match("Basic%s+(.+)")
    local decoded = ngx.decode_base64(encoded or "")
    if decoded ~= AUTH_USER .. ":" .. AUTH_PASS then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot v4.3.6"'
        ngx.exit(401); return false
    end
    return true
end

-- `limit` chỉ chặn số KẾT QUẢ, KHÔNG chặn số vòng quét — đó là lỗ hổng chi phí.
-- Một mẫu ít khoá (`fl:dyn:*` 1 khoá / trần 500, `nonce:*`, `ban_ctx:*`) không
-- bao giờ chạm trần kết quả nên vòng `until cursor == "0"` quét TRỌN keyspace
-- rồi trả về vài khoá. Mười tám mẫu như vậy trong một lần dựng trang, mà trang
-- tự nạp lại theo `setInterval` ở cuối file.
--
-- Đo 2026-08-09 (`INFO commandstats`): **57.470.696 lệnh SCAN** = 46,5% tổng số
-- lệnh Redis và **94,5% tổng thời gian xử lý lệnh** (2.000 trên 2.117 giây).
-- SCAN đắt gấp 27 lần GET (34,81 µs so với 2,13 µs).
--
-- Đặt lại tỷ lệ cho đúng: 2.000 giây CPU trên `uptime` 141.704 giây = **1,5%
-- một core**, nên đây KHÔNG phải nguồn của load average (thủ phạm là php-fpm).
-- Vẫn sửa vì chi phí thật nằm ở phía OpenResty: mỗi vòng SCAN là một lượt
-- round-trip cosocket kèm cấp phát bảng Lua, và nó tăng tuyến tính theo độ
-- phình của keyspace.
--
-- COUNT 100 → 1000: giảm 10 lần số round-trip cho cùng phạm vi quét.
-- SCAN_MAX_ITER: trần CỨNG, chặn chi phí bất kể keyspace lớn cỡ nào.
--
-- 2026-08-31 — COUNT 1000 → 10000. Trần phủ cũ (1000 × 100 = 100.000 khoá)
-- THẤP HƠN keyspace thật: `DBSIZE` đo được 250.647 / 259.071 / 317.756 trên ba
-- máy. Hậu quả KHÔNG phải "thiếu phần đuôi" mà là ba máy CÙNG DỮ LIỆU cho ba
-- kết quả KHÁC NHAU — bảng "Good Bot DNS Registry" hiện 18 / 17 / 15 mục trong
-- khi Redis có đủ 41 trên cả ba (`EXISTS goodbot:dns:<tên>` = 1 với mọi tên).
-- Các tập con còn chồng chéo lộn xộn: máy A có `googlebot-video` mà không có
-- `googlebot`, máy B thì ngược lại.
--
-- Vì sao cùng code cùng dữ liệu lại khác kết quả: bảo đảm "mọi khoá tồn tại
-- suốt quá trình lặp đều được trả về ít nhất một lần" của SCAN **chỉ có hiệu
-- lực khi chạy HẾT tới `cursor == 0`**. Cắt ở vòng 100 là tự bước ra ngoài cam
-- kết. Ngoài cam kết thì vị trí một khoá là `hash(tên) & (cỡ_bảng − 1)`, mà
-- bảng băm co giãn theo TỔNG số khoá (2^18 với 250k, 2^19 với 318k) ⇒ cùng một
-- tên rơi vào bucket khác nhau trên mỗi máy; điểm dừng ở vòng 100 lại phụ thuộc
-- mật độ của 250.000 khoá KHÔNG liên quan gì tới mẫu đang tìm.
--
-- Nâng COUNT chứ KHÔNG nâng MAX_ITER — cùng khối lượng duyệt keyspace nhưng:
--   COUNT 10000  → ~32 round-trip cho 318k khoá, trần phủ 1.000.000
--   MAX_ITER 400 → ~318 round-trip cho 318k khoá, trần phủ 400.000
-- Đánh đổi phải biết: Redis đơn luồng, mỗi lệnh SCAN chặn lâu hơn (~0,5ms thay
-- vì ~0,1ms). Panel admin mở thủ công nên chấp nhận được. Và COUNT chỉ là GỢI
-- Ý — Redis có quyền trả ít hơn mỗi vòng, nên "vòng × COUNT" là cận trên lạc
-- quan; cờ `truncated` vẫn là thứ duy nhất nói thật.
--
-- KHÔNG ảnh hưởng xử lý request. Đường xác minh đọc ĐÍCH DANH
-- (`detection/bot/ua_check.lua:100` — `safe_get("goodbot:dns:" .. tên)`), không
-- hề quét. Lỗi này thuần hiển thị: 15/41 trên bảng mà bot vẫn verify đủ.
local SCAN_COUNT    = 10000
local SCAN_MAX_ITER = 100   -- ≤ 1.000.000 khoá được soi mỗi mẫu

-- `max_iter` cho phép nới trần vòng lặp cho vài mẫu mà con số PHẢI đúng
-- (`ban:*` — bảng Bans có phân trang, cần đủ khoá thì tổng mới thật). Mặc định
-- vẫn là SCAN_MAX_ITER cho mọi mẫu chỉ cần lấy mẫu.
-- Lưu ý: MATCH lọc SAU khi quét, nên chi phí tỉ lệ với TỔNG keyspace chứ không
-- phải số khoá khớp — nới trần là nới chi phí thật, đừng nới đại trà.
local function scan_keys(red, pattern, limit, max_iter)
    local cursor, results, scanned = "0", {}, 0
    limit = limit or 500
    max_iter = max_iter or SCAN_MAX_ITER
    local iter = 0
    repeat
        local res = red:scan(cursor, "MATCH", pattern, "COUNT", SCAN_COUNT)
        if not res then break end
        cursor = res[1]
        for _, k in ipairs(res[2]) do
            table.insert(results, k)
            scanned = scanned + 1
            if scanned >= limit then
                -- Cắt vì đủ `limit`. Đây là đường CẮT ÂM THẦM nguy hiểm nhất:
                -- SCAN duyệt theo thứ tự bucket (ngẫu nhiên với người đọc), nên
                -- phần bị bỏ lại KHÔNG phải "phần đuôi" mà là một tập tuỳ ý —
                -- một domain có thể còn khoá `req` nhưng mất khoá `allow`, cho
                -- ra Total=21.297 / Clean=0 trong khi domain bên cạnh vẫn đủ.
                --
                -- `truncated` để nơi gọi biết con số mình có chỉ là CẬN DƯỚI.
                -- Không có cờ này thì `#results` trông y hệt một tổng thật, và
                -- dashboard đi hiển thị đúng hằng số `limit` như thể nó là số
                -- liệu (đã xảy ra: "Threat Feed IPs" đứng yên ở 5000).
                results.truncated = true
                ngx.log(ngx.WARN, "[admin] scan_keys cham tran ket qua pattern=",
                        pattern, " limit=", limit, " — BANG HIEN THI BI CAT")
                return results
            end
        end
        iter = iter + 1
        if iter >= max_iter then
            -- Bảng hiển thị bị cắt. Log để người vận hành biết đang nhìn dữ
            -- liệu thiếu chứ không tưởng là keyspace đã hết.
            results.truncated = true
            ngx.log(ngx.WARN, "[admin] scan_keys cham tran vong lap pattern=",
                    pattern, " iter=", iter, " ket_qua=", scanned)
            break
        end
    until cursor == "0"
    return results
end

local function time_ago(ts)
    if not ts then return "-" end
    local diff = ngx.time() - tonumber(ts)
    if diff < 60 then return diff.."s ago"
    elseif diff < 3600 then return math.floor(diff/60).."m ago"
    else return math.floor(diff/3600).."h ago" end
end

local function handle_whitelist_api()
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    local ok, req = pcall(cjson.decode, body)
    if not ok or not req then
        ngx.status = 400
        ngx.say(cjson.encode({error="Invalid JSON"}))
        return
    end

    local red, err = pool.get()
    if not red then
        ngx.status = 500
        ngx.say(cjson.encode({error="Redis: "..tostring(err)}))
        return
    end

    local action = req.action
    local result = {}

    if action == "wl_ip_add" and req.ip then
        red:set("wl:" .. req.ip, "1")
        red:del("ban:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." whitelisted & unbanned"}

    elseif action == "wl_ip_del" and req.ip then
        red:del("wl:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." removed from whitelist"}

    elseif action == "unban_ip" and req.ip then
        red:del("ban:" .. req.ip)
        red:del("rep:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." unbanned"}

    elseif action == "unban_id" and req.id then
        local id = req.id
        red:del("ban:"      .. id)
        red:del("risk:"     .. id)
        red:del("viol:"     .. id)
        red:del("verified:" .. id)
        result = {ok=true, msg="Identity "..id:sub(1,16).."... unbanned & cleared"}

    elseif action == "wl_id" and req.id then
        local id = req.id
        red:set("wl:id:"   .. id, "1")   -- persistent identity whitelist (ban_store checks this)
        red:del("ban:"     .. id)
        red:del("risk:"    .. id)
        red:del("viol:"    .. id)
        red:del("ban:age:" .. id)
        result = {ok=true, msg="Identity "..id:sub(1,16).."... whitelisted (persistent) & cleared"}

    elseif action == "wl_url_add" and req.prefix then
        local prefix = req.prefix
        red:sadd("wl:url_set", prefix)
        local members = red:smembers("wl:url_set") or {}
        red:set("wl:url_list", table.concat(members, "\n"))
        result = {ok=true, msg="URL prefix '"..prefix.."' whitelisted"}

    elseif action == "wl_url_del" and req.prefix then
        local prefix = req.prefix
        red:srem("wl:url_set", prefix)
        local members = red:smembers("wl:url_set") or {}
        red:set("wl:url_list", table.concat(members, "\n"))
        result = {ok=true, msg="URL prefix '"..prefix.."' removed"}

    elseif action == "ua_add" and req.pattern then
        local pat = req.pattern
        red:sadd("badbot:ua_custom_set", pat)
        red:del("badbot:ua_patterns")
        result = {ok=true, msg="Bad bot pattern '"..pat.."' added. Cache cleared."}

    elseif action == "ua_del" and req.pattern then
        local pat = req.pattern
        red:srem("badbot:ua_custom_set", pat)
        red:del("badbot:ua_patterns")
        result = {ok=true, msg="Pattern '"..pat.."' removed. Cache cleared."}

    elseif action == "goodbot_dns_add" and req.name and req.suffixes then
        red:set("goodbot:dns:" .. req.name:lower(), req.suffixes)
        result = {ok=true, msg="Good bot DNS: "..req.name.." → "..req.suffixes}

    elseif action == "goodbot_dns_del" and req.name then
        red:del("goodbot:dns:" .. req.name:lower())
        result = {ok=true, msg="Good bot DNS removed: "..req.name}

    -- `asn_type_set`/`asn_type_del` ĐÃ GỠ (2026-08-31). Chúng ghi `asn:type:<n>`,
    -- mà khoá đó chảy vào `ctx.ip_net_type` và DỪNG Ở ĐÓ — không module nào đọc
    -- (`ip_classify.lua:113` ghim `ctx.ip_score = 0.0`, quyết định đúng: iCloud
    -- Private Relay / Zscaler / VPN doanh nghiệp khiến "datacenter = đáng ngờ"
    -- thành máy sinh FP). Nút bấm báo thành công rồi không đổi một điểm nào.
    --
    -- Tệ hơn "vô dụng": admin ghi KHÔNG TTL, mà `threat_feed_sync.sh:251` lại
    -- `continue` khi thấy `asn:type:<n>` tồn tại — `continue` đó nhảy qua CẢ
    -- dòng ghi `rep:asn:<n>` ngay dưới. `rep:asn:` mới là thứ sống (trọng số 35
    -- qua `intelligence/threat/asn_reputation.lua`). Nên đánh dấu tay một ASN là
    -- "datacenter" lại GỠ MẤT hình phạt datacenter của chính nó — ngược hẳn ý
    -- định người bấm, im lặng, vĩnh viễn.
    --
    -- Ba nhu cầu khai báo ASN có thật đều đã giải bằng hardcode đi qua git:
    --   ISP tiêu dùng bị gắn nhầm  → MANUAL_OVERRIDE_RESIDENTIAL (xoá rep:asn:)
    --   datacenter VN feed không biết → VN_DATACENTER_ASNS
    --   good bot trên ASN mới        → goodbot:asn: qua core/data/goodbot.json
    -- Không cái nào dùng `asn:type:`. ĐỪNG dựng lại panel này.

    elseif action == "ja3_allow" and req.hash then
        red:set("ja3:allow:" .. req.hash, "1")
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... added to allowlist"}

    elseif action == "ja3_block" and req.hash then
        red:set("ja3:block:" .. req.hash, "1")
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... added to blocklist"}

    elseif action == "ja3_remove" and req.hash then
        red:del("ja3:allow:" .. req.hash)
        red:del("ja3:block:" .. req.hash)
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... removed"}

    elseif action == "ua_sync" then
        local ok2 = os.execute(
            "bash /usr/local/openresty/nginx/conf/scripts/ua_sync.sh > " ..
            "/var/log/ua_sync.log 2>&1 &")
        result = {ok=true, msg="UA sync triggered. Check /var/log/ua_sync.log"}

    else
        result = {ok=false, msg="Unknown action: "..(action or "nil")}
    end

    pool.put(red)
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(result))
end

local function render_data()
    ngx.header["Content-Type"] = "application/json; charset=utf-8"

    local red, err = pool.get()
    if not red then
        ngx.say(cjson.encode({error="Redis: "..tostring(err)}))
        return
    end

    -- `ban:*` là mẫu DUY NHẤT được nới trần: bảng Bans có phân trang nên con số
    -- tổng phải thật, không được là cỡ trang trá hình. Mỗi IP bị cấm sinh tới 2
    -- khoá (`ban:<ip>` + `ban:hit:<ip>`), identity thêm `ban:age:<id>` — nên
    -- 1.884 IP đang cấm đã ngốn quá 5.000 khoá cũ.
    -- 800 vòng × COUNT 1000 ≈ 800.000 khoá soi được, trên `DBSIZE` đo được
    -- 331.906 (2026-08-10) ⇒ biên gấp 2,4 lần. Đừng hạ sát nút: `COUNT` chỉ là
    -- GỢI Ý, Redis có quyền trả ít hơn mỗi vòng, nên "vòng × COUNT" là cận
    -- trên lạc quan chứ không phải bảo đảm. Chạm trần thì `truncated` bật và
    -- error.log có dòng WARN — đó là lúc nới tiếp.
    local ban_keys  = scan_keys(red, "ban:*",     40000, 800)
    local rep_keys  = scan_keys(red, "rep:*",       500)
    local risk_keys = scan_keys(red, "risk:*",     5000)
    -- `rep:*` chỉ dùng để lấy 20 dòng mẫu cho tab Threats (vòng lặp dưới break
    -- ở 20). Quét 5000 khoá để lấy 20 là lãng phí thuần tuý — feed nạp hàng
    -- trăm nghìn khoá `rep:` nên mọi giới hạn đều là mẫu, không phải "top".
    -- 500 giữ nguyên tính chất mẫu với 1/10 chi phí.
    -- (`rl:*` từng được quét ở đây cho thẻ "Rate Abusers" — đã gỡ, xem HTML.)
    local wl_ip_keys = scan_keys(red, "wl:*",      1000)
    -- (`nonce:*` từng được quét cho thẻ "Pending Challenge" — đã gỡ. Số nonce
    --  chưa giải tại một thời điểm không nói lên điều gì mà "Challenge hôm nay"
    --  cộng "Phiên đã xác minh" chưa nói rõ hơn.)
    local verified_keys = scan_keys(red, "verified:*", 500)
    local today_key = os.date("%Y%m%d")

    -- ── Danh sách domain của hôm nay ─────────────────────────────────────
    -- Chỉ mục `stat:hosts:<ngày>` do async/logger.lua dựng. SCAN `stat:*` giờ
    -- chỉ còn là ĐƯỜNG LÙI cho ngày deploy đầu tiên — mọi số liệu thống kê đọc
    -- đích danh từ danh sách này, không qua SCAN nữa.
    --
    -- Vì sao bắt buộc phải bỏ SCAN ở đây: mỗi domain sinh ~50-60 khoá stat mỗi
    -- ngày, nên `limit` cắt giữa chừng theo thứ tự bucket. Với bảng Domain nó
    -- cho ra Total=21.297/Clean=0; với tab Devices nó còn tệ hơn — tử số
    -- (`ibd_<nhóm>_<ý định>`) và mẫu số (`dev_<nhóm>`) là các KHOÁ RIÊNG, bị
    -- cắt ĐỘC LẬP nhau, nên tỷ lệ vọt lên **Human 114%** dù về mặt ghi log
    -- chúng luôn tăng cùng nhau đúng 1:1.
    local host_set = red:smembers("stat:hosts:" .. today_key)
    if not host_set or host_set == ngx.null then host_set = {} end
    if #host_set == 0 then
        local seen = {}
        -- Mẫu khớp ĐỦ BA phần để `stat:hosts:<ngày>` (hai phần) không bị đọc
        -- nhầm thành một domain tên "hosts".
        for _, k in ipairs(scan_keys(red, "stat:*:" .. today_key, 5000)) do
            local h = k:match("^stat:([^:]+):[^:]+:%d+$")
            if h and not seen[h] then
                seen[h] = true
                table.insert(host_set, h)
            end
        end
    end

    local ban_ctx_keys  = scan_keys(red, "ban_ctx:*",  500)
    local ua_count     = red:get("badbot:ua_count") or "0"
    local ua_sync_time = red:get("badbot:ua_sync_time") or "never"
    local ua_custom    = red:smembers("badbot:ua_custom_set") or {}

    local function is_ipv4(s)
        return s ~= "" and s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
    end
    local function is_identity(s)
        return s ~= "" and #s == 32 and s:match("^[0-9a-f]+$") ~= nil
    end

    -- ── Danh sách ban ────────────────────────────────────────────────────
    -- Bản cũ đọc TUẦN TỰ: mỗi mục 3-4 lệnh `red:get`/`red:ttl` riêng lẻ, mỗi
    -- lệnh một round-trip. Với 1.884 IP đang cấm thì là ~7.500 round-trip cho
    -- một lần tải trang — không dùng được, và đó chính là lý do có cái `break`
    -- ở 50. Cái trần đó rồi lại bị đem hiển thị như thể là tổng.
    --
    -- Nay đọc theo LÔ: một pipeline cho IP, một cho identity ⇒ 2 round-trip
    -- bất kể bao nhiêu mục. Nhờ vậy mới đủ dữ liệu cho phân trang thật.
    --
    -- Show entry nếu còn ý nghĩa:
    --   ACTIVE (đang enforce) → luôn show
    --   IDLE + TTL >= 60s     → vẫn trong thời gian ban → show với badge IDLE
    --   IDLE + TTL < 60s      → sắp expire + không enforce → ẩn khỏi bảng
    --   PERMANENT (TTL = -1)  → show (không bao giờ hết hạn)
    --
    -- `ban:hit:*` và `ban:age:*` tự bị loại vì không khớp is_ipv4/is_identity.
    -- Đo thật 2026-08-10 trên cloud28-246: 6.623 IP + 10.630 identity đang bị
    -- cấm. Con số 5.000 đặt trước đó là sizing theo một mẫu chưa đo (1.884) —
    -- đúng loại "hằng số cỡ trang trá hình" mà chính đợt sửa này đi dọn.
    -- 20.000 để dôi cho tăng trưởng; chạm trần thì `ban_detail_capped` bật.
    -- Vì sao tích tụ tới cỡ đó: `cfg.ttl.ban_steps` bậc cuối là 2.592.000s =
    -- 30 NGÀY, nên tổng luôn xấp xỉ "dòng vào mỗi ngày × 30".
    local BAN_DETAIL_MAX = 20000

    local ip_cands, id_cands = {}, {}
    for _, k in ipairs(ban_keys) do
        local v = k:gsub("^ban:", "")
        if     is_ipv4(v)     then table.insert(ip_cands, v)
        elseif is_identity(v) then table.insert(id_cands, v) end
    end
    -- Tổng THẬT (đếm chuỗi thuần, không chạm Redis) — độc lập với việc lấy
    -- chi tiết bên dưới có bị cắt hay không.
    local ban_ip_count, ban_id_count = #ip_cands, #id_cands

    local function trim(t, n)
        while #t > n do table.remove(t) end
    end
    trim(ip_cands, BAN_DETAIL_MAX)
    trim(id_cands, BAN_DETAIL_MAX)

    local function val_of(x)
        if x == nil or x == ngx.null then return nil end
        return x
    end

    local ban_ip_list, ban_id_list = {}, {}
    local ban_ip_hidden_count, ban_id_hidden_count = 0, 0

    if #ip_cands > 0 then
        red:init_pipeline()
        for _, v in ipairs(ip_cands) do
            red:ttl("ban:" .. v)
            red:get("ban:hit:" .. v)
            red:get("rep:" .. v)
            red:get("ip_risk:" .. v)
        end
        local res = red:commit_pipeline()
        if res then
            for i, v in ipairs(ip_cands) do
                local b        = (i - 1) * 4
                local ttl      = tonumber(res[b + 1]) or -1
                local hit      = val_of(res[b + 2])
                local status   = (hit and hit ~= "") and "active" or "idle"
                local last_hit = tonumber(hit) or 0
                if status ~= "active" and ttl > 0 and ttl < 60 then
                    ban_ip_hidden_count = ban_ip_hidden_count + 1
                else
                    table.insert(ban_ip_list, {
                        ip      = v,
                        rep     = tonumber(val_of(res[b + 3])) or 0,
                        ip_risk = tonumber(val_of(res[b + 4])) or 0,
                        ttl     = ttl > 0 and (math.floor(ttl / 60) .. "m") or "perm",
                        ttl_sec = ttl,
                        status  = status,
                        last_hit = last_hit > 0 and time_ago(last_hit) or "-",
                    })
                end
            end
        end
    end

    -- Bảng Bans CHỈ vẽ identity nào có IP cũng đang bị cấm (nó lồng identity
    -- dưới dòng IP). Trước đây cả 10.630 bản ghi vẫn được gửi xuống rồi bị
    -- trình duyệt vứt — vài MB mỗi 60 giây cho thứ không bao giờ hiện.
    -- Lọc ngay tại đây. Số bị loại vẫn được đếm và báo ra, không im lặng.
    local ip_banned = {}
    for _, r in ipairs(ban_ip_list) do ip_banned[r.ip] = true end
    local ban_id_orphan = 0

    if #id_cands > 0 then
        red:init_pipeline()
        for _, v in ipairs(id_cands) do
            red:ttl("ban:" .. v)
            red:get("ban:hit:" .. v)
            red:get("risk:" .. v)
            red:get("ban_ctx:" .. v)
        end
        local res = red:commit_pipeline()
        if res then
            for i, v in ipairs(id_cands) do
                local b        = (i - 1) * 4
                local ttl      = tonumber(res[b + 1]) or -1
                local hit      = val_of(res[b + 2])
                local status   = (hit and hit ~= "") and "active" or "idle"
                local last_hit = tonumber(hit) or 0
                if status ~= "active" and ttl > 0 and ttl < 60 then
                    ban_id_hidden_count = ban_id_hidden_count + 1
                else
                    local dev, ua_short, ip_addr, bs = "?", "", "", 0
                    local ctx_raw = val_of(res[b + 4])
                    if ctx_raw then
                        local ok3, obj = pcall(cjson.decode, ctx_raw)
                        if ok3 and obj then
                            dev     = obj.device_type or "?"
                            ip_addr = obj.ip          or ""
                            bs      = obj.bot_score   or 0
                            ua_short = (obj.ua or ""):sub(1, 60)
                        end
                    end
                    if not ip_banned[ip_addr] then
                        ban_id_orphan = ban_id_orphan + 1
                        goto next_id
                    end
                    table.insert(ban_id_list, {
                        id      = v,
                        risk    = tonumber(val_of(res[b + 3])) or 0,
                        ttl     = ttl > 0 and (math.floor(ttl / 60) .. "m") or "perm",
                        ttl_sec = ttl,
                        device  = dev, ua = ua_short, ip = ip_addr, bot_score = bs,
                        status  = status,
                        last_hit = last_hit > 0 and time_ago(last_hit) or "-",
                    })
                end
                ::next_id::
            end
        end
    end

    table.sort(ban_ip_list,  function(a,b) return math.max(a.rep,a.ip_risk) > math.max(b.rep,b.ip_risk) end)
    table.sort(ban_id_list,  function(a,b) return a.risk > b.risk end)

    local high_risk = {}
    for _, k in ipairs(risk_keys) do
        local fp  = k:gsub("^risk:", "")
        local val = tonumber(red:get(k)) or 0
        if val >= 0.5 then
            table.insert(high_risk, {id=fp, risk=val})
        end
        if #high_risk >= 15 then break end
    end
    table.sort(high_risk, function(a,b) return a.risk > b.risk end)

    local rep_ips = {}
    for _, k in ipairs(rep_keys) do
        local key = k:gsub("^rep:", "")
        if not key:find(":", 1, true) and is_ipv4(key) then
            local val = tonumber(red:get(k)) or 0
            if val > 0 then
                table.insert(rep_ips, {ip=key, score=val})
            end
        end
        if #rep_ips >= 20 then break end
    end
    table.sort(rep_ips, function(a,b) return a.score > b.score end)

    -- "Rate Abusers" ĐÃ GỠ. Ba lý do, theo thứ tự quan trọng:
    --   1. Nó gần như luôn rỗng, và rỗng vì lý do CẤU TRÚC chứ không phải vì
    --      hệ thống sạch: `rl:<ip>` chỉ sống 60 giây, còn kẻ lạm dụng nặng
    --      nhất đã bị `l7/ban/ip_ban_check` chặn ở cửa TRƯỚC khi tầng l7 kịp
    --      đếm ⇒ đúng nhóm cần thấy thì không bao giờ xuất hiện ở đây.
    --   2. Mẫu lấy từ SCAN 2000 khoá theo thứ tự bucket, nên kể cả khi có kẻ
    --      vượt 100 req/phút thì cũng dễ nằm ngoài mẫu.
    --   3. Nội dung trùng tab Bans/Threats — nơi đã có bằng chứng đầy đủ hơn.
    local wl_ips = {}
    for _, k in ipairs(wl_ip_keys) do
        if k:match("^wl:%d+%.%d+%.%d+%.%d+$") then
            table.insert(wl_ips, (k:gsub("^wl:", "")))
        end
    end

    local wl_urls = {}
    local url_members = red:smembers("wl:url_set") or {}
    for _, u in ipairs(url_members) do
        table.insert(wl_urls, u)
    end
    table.sort(wl_urls)

    local last_sync  = red:get("threat:last_sync") or "-"
    local stats_raw  = red:get("threat:stats")
    local tsync      = {ip_loaded=0, asn_loaded=0, last_sync=last_sync}
    if stats_raw then
        local ok2, obj = pcall(cjson.decode, stats_raw)
        if ok2 then
            tsync.ip_loaded  = obj.ip or 0
            -- 2026-08-31 — TRƯỚC ĐÂY đọc `obj.asn`, mà `threat_feed_sync.sh:365`
            -- ghi ra `{"ip":…,"asn_rep":…,"asn_type":…}`. Không có trường `asn`
            -- ⇒ `or 0` ⇒ ô "ASNs Loaded" **luôn hiện 0** kể từ khi có nó. Trông
            -- như số liệu vô nghĩa nên không ai buồn hỏi.
            --
            -- Giá của việc để nó hỏng: hôm nay phát hiện hai máy chạy bản
            -- threat_feed_sync.sh đời cũ, chỉ nạp 27 ASN thay vì 53.610 — tức
            -- `asn_rep` (trọng số 35) gần như mù suốt nhiều ngày. Nếu ô này
            -- chạy đúng thì nó đã hiện 27 cạnh 53.610 và lộ ra trong một cái
            -- liếc, thay vì phải lần từ log.
            --
            -- Chỉ hiện `asn_rep`. `asn_type` cố tình BỎ: khoá `asn:type:` không
            -- ảnh hưởng quyết định nào (xem nhánh action đã gỡ), hiện nó ra chỉ
            -- là dựng lại đúng thứ vừa dọn đi.
            tsync.asn_loaded = obj.asn_rep or 0
        end
    end

    local today = os.date("%Y%m%d")
    local domain_map = {}

    local device_map = {}  -- global across all domains
    local intent_map      = {}  -- bot vs human vs ambiguous
    local intent_by_device = {}  -- intent per device group

    -- ── Nhóm client + ý định: đọc ĐÍCH DANH, không qua SCAN ─────────────
    -- Tên khoá con là hữu hạn và biết trước, nên liệt kê được. Cái giá của
    -- việc liệt kê (phải sửa ở đây khi thêm nhóm/ý định mới) rẻ hơn nhiều so
    -- với cái giá của SCAN: tử số và mẫu số bị cắt độc lập ⇒ **Human 114%**.
    -- `verified` + `gate` KHÔNG phải loại thiết bị — chúng là hai lối đi mà
    -- `device_classifier` (STEPS_COMMON bước 10) không được chạy: cookie
    -- fast-path return trước cả STEPS_COMMON, còn ip_ban_check/fleet_check_block
    -- exit sớm hơn. Trước đây cả hai bị dồn vào "unknown" nên ô đó vừa to vừa
    -- vô nghĩa (người thật đã giải PoW nằm chung với lệnh chặn ở cửa).
    local DEV_GROUPS  = {"desktop","mobile","tablet","crawler","tool","unknown","no_ua","verified","gate"}
    local INTENTS     = {"human","goodbot","watch","bot"}
    -- Đúng bộ action mà logger ghi khoá riêng (mọi action khác `allow`).
    -- `allow` cố tình KHÔNG có khoá — nó là phần dư, và phần dư đó mới là Clean.
    local ACTIONS     = {"monitor","throttled","challenge","block"}

    local dev_fields = {}      -- tên khoá con cần đọc cho MỖI host
    for _, g in ipairs(DEV_GROUPS) do
        table.insert(dev_fields, {kind="dev_total",  key="dev_"..g, g=g})
        for _, a in ipairs(ACTIONS) do
            table.insert(dev_fields, {kind="dev_act", key="dev_"..g.."_"..a, g=g, a=a})
        end
        for _, ig in ipairs(INTENTS) do
            table.insert(dev_fields, {kind="ibd", key="ibd_"..g.."_"..ig, g=g, i=ig})
        end
    end
    for _, ig in ipairs(INTENTS) do
        table.insert(dev_fields, {kind="int_total", key="intent_"..ig, i=ig})
        for _, a in ipairs(ACTIONS) do
            table.insert(dev_fields, {kind="int_act", key="intent_"..ig.."_"..a, i=ig, a=a})
        end
    end

    -- Khởi tạo ĐỦ mọi ô về 0. Nhờ vậy nhóm không có lưu lượng vẫn hiện thành
    -- dòng "0" thay vì biến mất khỏi bảng — vắng mặt và bằng không là hai
    -- thông tin khác nhau.
    for _, g in ipairs(DEV_GROUPS) do
        device_map[g]       = {total=0, monitor=0, throttled=0, challenge=0, block=0}
        intent_by_device[g] = {bot=0, human=0, watch=0, goodbot=0}
    end
    for _, ig in ipairs(INTENTS) do
        intent_map[ig] = {total=0, monitor=0, throttled=0, challenge=0, block=0}
    end

    if #host_set > 0 then
        red:init_pipeline()
        for _, h in ipairs(host_set) do
            for _, f in ipairs(dev_fields) do
                red:get("stat:" .. h .. ":" .. f.key .. ":" .. today)
            end
        end
        local res = red:commit_pipeline()
        if res then
            local i = 0
            for _ = 1, #host_set do
                for _, f in ipairs(dev_fields) do
                    i = i + 1
                    local v = res[i]
                    local n = (v ~= nil and v ~= ngx.null) and (tonumber(v) or 0) or 0
                    if n > 0 then
                        if     f.kind == "dev_total" then device_map[f.g].total = device_map[f.g].total + n
                        elseif f.kind == "dev_act"   then device_map[f.g][f.a]  = device_map[f.g][f.a]  + n
                        elseif f.kind == "ibd"       then intent_by_device[f.g][f.i] = intent_by_device[f.g][f.i] + n
                        elseif f.kind == "int_total" then intent_map[f.i].total = intent_map[f.i].total + n
                        elseif f.kind == "int_act"   then intent_map[f.i][f.a]  = intent_map[f.i][f.a]  + n
                        end
                    end
                end
            end
        end
    end

    -- `throttled` PHẢI có mặt: logger đếm nó vào `req` như mọi action khác,
    -- nhưng trước đây bảng không có cột nào cho nó ⇒ Total luôn lớn hơn tổng
    -- bốn cột còn lại mà không giải thích được. Trên cloud28-246 ngày
    -- 2026-08-10 nó là 14.674/187.647 = 7,8% lưu lượng — không phải sai số làm
    -- tròn, mà là một cột bị thiếu.
    local DOMAIN_FIELDS = {"req", "allow", "monitor", "throttled", "challenge", "block"}
    if #host_set > 0 then
        red:init_pipeline()
        for _, h in ipairs(host_set) do
            for _, f in ipairs(DOMAIN_FIELDS) do
                red:get("stat:" .. h .. ":" .. f .. ":" .. today)
            end
        end
        local res = red:commit_pipeline()
        if res then
            local i = 0
            for _, h in ipairs(host_set) do
                -- Gộp `www.example.com` vào `example.com`: cùng một site, cùng
                -- một server block (server_name khai cả hai). Tách đôi chỉ bắt
                -- người đọc tự cộng nhẩm.
                local key = (h:gsub("^www%.", ""))
                local d = domain_map[key]
                if not d then
                    d = {req=0, allow=0, monitor=0, throttled=0,
                         challenge=0, block=0}
                    domain_map[key] = d
                end
                for _, f in ipairs(DOMAIN_FIELDS) do
                    i = i + 1
                    local v = res[i]
                    if v ~= nil and v ~= ngx.null then
                        -- CỘNG DỒN, không gán: sau khi gộp www thì mỗi ô nhận
                        -- số liệu từ hai host.
                        d[f] = d[f] + (tonumber(v) or 0)
                    end
                end
            end
        end
    end

    -- Tổng hôm nay, cộng từ domain_map (đã chính xác từ khi bỏ SCAN cho bảng
    -- Domain). Đây là con số DUY NHẤT ở Overview không lặp lại tab nào: tab
    -- Domains chỉ liệt kê từng dòng, không có hàng tổng.
    local today_tot = {req=0, allow=0, monitor=0, throttled=0, challenge=0, block=0}
    for _, s in pairs(domain_map) do
        for _, f in ipairs(DOMAIN_FIELDS) do
            today_tot[f] = today_tot[f] + (s[f] or 0)
        end
    end

    -- ── Chuỗi 7 ngày cho biểu đồ Overview ───────────────────────────────
    -- Khoá `stat:*` có TTL 7 ngày (async/logger.lua) nên 7 là ĐÚNG cửa sổ dữ
    -- liệu còn tồn tại — xin nhiều hơn chỉ ra cột rỗng.
    --
    -- Dùng danh sách host của HÔM NAY cho cả 7 ngày, không đọc
    -- `stat:hosts:<ngày cũ>`: chỉ mục đó mới có từ 2026-08-10 nên các ngày
    -- trước chưa có. Tập domain trên một máy shared hosting gần như đứng yên,
    -- nên sai số chỉ nằm ở domain vừa tạo/vừa xoá trong tuần — chấp nhận được,
    -- và tự hết sau 7 ngày.
    local daily = {}
    if #host_set > 0 then
        local days = {}
        for back = 6, 0, -1 do
            table.insert(days, os.date("%Y%m%d", os.time() - back * 86400))
        end
        red:init_pipeline()
        for _, dkey in ipairs(days) do
            for _, h in ipairs(host_set) do
                for _, f in ipairs(DOMAIN_FIELDS) do
                    red:get("stat:" .. h .. ":" .. f .. ":" .. dkey)
                end
            end
        end
        local res = red:commit_pipeline()
        if res then
            local i = 0
            for _, dkey in ipairs(days) do
                local row = {day = dkey:sub(7, 8) .. "/" .. dkey:sub(5, 6),
                             req=0, allow=0, monitor=0, throttled=0,
                             challenge=0, block=0}
                for _ = 1, #host_set do
                    for _, f in ipairs(DOMAIN_FIELDS) do
                        i = i + 1
                        local v = res[i]
                        if v ~= nil and v ~= ngx.null then
                            row[f] = row[f] + (tonumber(v) or 0)
                        end
                    end
                end
                table.insert(daily, row)
            end
        end
    end

    -- Build device stats list. Dùng lại DEV_GROUPS ở trên thay vì khai một
    -- danh sách thứ hai cùng nội dung — hai bản sao thì sớm muộn cũng lệch.
    local device_stats = {}
    for _, g in ipairs(DEV_GROUPS) do
        local s = device_map[g] or {total=0, monitor=0, throttled=0, challenge=0, block=0}
        -- Cột cũ tên "Cho qua" chứ không phải "Clean" là CÓ LÝ DO: nó là hiệu
        -- `total - block - challenge`, tức gộp cả `monitor` (cho đi nhưng đã
        -- ghi sổ) lẫn `throttled` (429 — bị từ chối). Gọi hiệu đó là "sạch" thì
        -- sai. Nay `monitor`/`throttled` có khoá riêng nên phần dư mới đúng
        -- nghĩa `allow`, và tên "Clean" mới trung thực — cùng nghĩa với Overview.
        local clean = math.max(0, s.total - s.monitor - s.throttled
                                          - s.challenge - s.block)
        table.insert(device_stats, {
            group     = g,
            total     = s.total,
            clean     = clean,
            monitor   = s.monitor,
            throttled = s.throttled,
            challenge = s.challenge,
            block     = s.block,
        })
    end

    local domain_list = {}
    for host, s in pairs(domain_map) do
        table.insert(domain_list, {
            host=host, req=s.req, allow=s.allow, monitor=s.monitor,
            throttled=s.throttled, challenge=s.challenge, block=s.block,
        })
    end
    table.sort(domain_list, function(a,b) return a.req > b.req end)

    local ban_ctx_list = {}
    for _, k in ipairs(ban_ctx_keys) do
        local key = (k:gsub("^ban_ctx:", ""))
        if key:match("^%d+%.%d+%.%d+%.%d+$") then
            local raw = red:get(k)
            if raw then
                local ok2, obj = pcall(cjson.decode, raw)
                if ok2 and obj then
                    local ttl_left = red:ttl(k)
                    table.insert(ban_ctx_list, {
                        ip       = key,
                        identity = obj.identity or "",
                        domain   = obj.domain   or "?",
                        score    = obj.score     or 0,
                        action   = obj.action    or "block",
                        ttl      = ttl_left > 0 and (math.floor(ttl_left/60).."m") or "perm",
                    })
                end
            end
        end
        if #ban_ctx_list >= 50 then break end
    end
    table.sort(ban_ctx_list, function(a,b) return a.score > b.score end)

    -- Good bot DNS registry
    local goodbot_keys = scan_keys(red, "goodbot:dns:*", 200)
    local goodbot_dns = {}
    for _, k in ipairs(goodbot_keys) do
        local name = k:gsub("^goodbot:dns:", "")
        local suffixes = red:get(k) or ""
        table.insert(goodbot_dns, {name=name, suffixes=suffixes})
    end
    table.sort(goodbot_dns, function(a,b) return a.name < b.name end)

    -- (Bảng "ASN Type Overrides" đã gỡ — xem chú thích ở nhánh action. Cùng lúc
    --  bỏ luôn `scan_keys(red, "asn:type:*", 500)`: quét 500 khoá mỗi lần tải
    --  trang để dựng một bảng không ảnh hưởng quyết định nào.)

    -- JA3 overrides
    local ja3_allow_keys = scan_keys(red, "ja3:allow:*", 200)
    local ja3_block_keys = scan_keys(red, "ja3:block:*", 200)
    local ja3_list = {}
    for _, k in ipairs(ja3_allow_keys) do
        table.insert(ja3_list, {hash=k:gsub("^ja3:allow:",""), status="allow"})
    end
    for _, k in ipairs(ja3_block_keys) do
        table.insert(ja3_list, {hash=k:gsub("^ja3:block:",""), status="block"})
    end

    -- Unknown UA samples để debug
    local ua_unknown_samples = red:lrange("stat:ua_unknown_sample", 0, 19) or {}

    -- Fleet detection candidates: read /24 flags + scores from Redis.
    -- MUST run before pool.put(red) — connection used below.
    local fleet_candidates = {}
    do
        local flag_keys = scan_keys(red, "fl:flag:24:*", 500)
        for _, fkey in ipairs(flag_keys) do
            local cidr = fkey:gsub("^fl:flag:24:", "")
            local status = red:get(fkey)
            if status and status ~= ngx.null then
                local score      = tonumber(red:get("fl:score:24:" .. cidr)) or 0
                local fp_poverty = tonumber(red:get("fl:axis:fp:"    .. cidr)) or 0
                local path_conv  = tonumber(red:get("fl:axis:path:"  .. cidr)) or 0
                local cookie_vac = tonumber(red:get("fl:axis:ck:"    .. cidr)) or 0
                local hits       = tonumber(red:get("fl:last:hits:"  .. cidr)) or 0
                local d_ips      = tonumber(red:get("fl:last:ips:"   .. cidr)) or 0
                local d_fp       = tonumber(red:get("fl:last:fp:"    .. cidr)) or 0
                local first_seen = tonumber(red:get("fl:first:"      .. cidr)) or 0
                table.insert(fleet_candidates, {
                    cidr             = cidr,
                    status           = status,
                    score            = score,
                    fp_poverty       = fp_poverty,
                    path_convergence = path_conv,
                    cookie_vacuum    = cookie_vac,
                    hits             = hits,
                    distinct_ips     = d_ips,
                    distinct_fp      = d_fp,
                    first_seen       = first_seen,
                })
            end
        end
        table.sort(fleet_candidates, function(a, b) return a.score > b.score end)
    end

    -- /16 roll-up flags
    local fleet_rollup_16 = {}
    do
        local rkeys = scan_keys(red, "fl:flag:16:*", 200)
        for _, fkey in ipairs(rkeys) do
            local cidr = fkey:gsub("^fl:flag:16:", "")
            local status = red:get(fkey)
            if status and status ~= ngx.null then
                local sub_count = tonumber(red:get("fl:rollup:count:" .. cidr)) or 0
                local first_seen = tonumber(red:get("fl:first:16:" .. cidr)) or 0
                table.insert(fleet_rollup_16, {
                    cidr        = cidr,
                    status      = status,
                    sub_count   = sub_count,
                    first_seen  = first_seen,
                })
            end
        end
        table.sort(fleet_rollup_16, function(a, b) return a.sub_count > b.sub_count end)
    end

    -- Dynamic blocks (enforce mode only)
    local fleet_dyn_blocks = {}
    do
        local dkeys = scan_keys(red, "fl:dyn:*", 500)
        for _, dkey in ipairs(dkeys) do
            local cidr = dkey:gsub("^fl:dyn:", "")
            local val = red:get(dkey)
            local ttl = red:ttl(dkey)
            if val and val ~= ngx.null then
                table.insert(fleet_dyn_blocks, {
                    cidr = cidr,
                    info = val,
                    ttl  = tonumber(ttl) or 0,
                })
            end
        end
    end

    local fleet_mode = "shadow"
    do
        local ok, cfg_mod = pcall(require, "antibot.core.config")
        if ok and cfg_mod.fleet_detection and cfg_mod.fleet_detection.mode then
            fleet_mode = cfg_mod.fleet_detection.mode
        end
    end

    pool.put(red)

    local function arr(t)
        if not t or #t == 0 then
            return setmetatable({}, cjson.array_mt)
        end
        return t
    end

    ngx.say(cjson.encode({
        summary = {
            ban_total     = #ban_keys,
            -- Tổng THẬT (đếm chuỗi), khác `ban_ip_shown` là số dòng vẽ được.
            ban_ip        = ban_ip_count,
            ban_id        = ban_id_count,
            ban_ip_shown  = #ban_ip_list,
            ban_id_shown  = #ban_id_list,
            -- SCAN `ban:*` chạm trần ⇒ hai con số trên chỉ là CẬN DƯỚI. UI thêm
            -- dấu "≥" thay vì im lặng trình bày chúng như tổng.
            ban_capped    = ban_keys.truncated and true or false,
            ban_ip_hidden = ban_ip_hidden_count,
            ban_id_hidden = ban_id_hidden_count,
            -- Identity bị cấm nhưng IP của nó KHÔNG bị cấm ⇒ bảng không có chỗ
            -- lồng nó vào. Lọc ở server để khỏi gửi thừa, nhưng đếm và báo ra.
            ban_id_orphan = ban_id_orphan,
            ban_detail_capped = (ban_ip_count > BAN_DETAIL_MAX
                                 or ban_id_count > BAN_DETAIL_MAX),
            -- (`risk_total`/`wl_ip_total`/`wl_url_total` đã gỡ cùng các thẻ
            --  Overview tương ứng — số liệu đó thuộc về tab Threats/Whitelist,
            --  nơi đã có danh sách đầy đủ.)
            verified      = #verified_keys,
            -- Cùng bệnh với ban: `verified:*` quét tối đa 500 nên khi vượt
            -- ngưỡng, thẻ sẽ đứng yên ở đúng 500. Đánh dấu để UI thêm "≥".
            verified_capped = verified_keys.truncated and true or false,
        },
        today = today_tot,
        daily = arr(daily),
        ban_ip_list  = arr(ban_ip_list),
        ban_id_list  = arr(ban_id_list),
        high_risk    = arr(high_risk),
        rep_ips      = arr(rep_ips),
        wl_ips       = arr(wl_ips),
        -- `wl:` là MIỄN TRỪ TOÀN PHẦN (whitelist.lua:161 → init.lua:162 return
        -- ngay, bỏ qua l7 + detection + enforcement). Soát an ninh trên một
        -- danh sách bị cắt âm thầm là soát hụt mà không biết mình đang hụt.
        wl_capped    = wl_ip_keys.truncated and true or false,
        wl_urls      = arr(wl_urls),
        threat_sync  = tsync,
        domain_stats = arr(domain_list),
        ban_ctx_list = arr(ban_ctx_list),
        ua_info = {
            count     = tonumber(ua_count) or 0,
            sync_time = ua_sync_time,
            custom    = arr(ua_custom),
        },
        goodbot_dns  = arr(goodbot_dns),
        -- Ba cờ dưới đây tồn tại vì 2026-08-31: ba máy cùng dữ liệu hiện ba
        -- danh sách khác nhau và KHÔNG có gì báo là đang nhìn dữ liệu thiếu.
        -- Xem khối chú thích ở `SCAN_COUNT`.
        goodbot_capped = goodbot_keys.truncated and true or false,
        ja3_list     = arr(ja3_list),
        ja3_capped   = (ja3_allow_keys.truncated or ja3_block_keys.truncated)
                       and true or false,
        device_stats         = arr(device_stats),
        ua_unknown_samples   = arr(ua_unknown_samples),
        intent_by_device     = intent_by_device,
        intent_stats         = {
            human   = intent_map["human"],
            goodbot = intent_map["goodbot"],
            bot     = intent_map["bot"],
            watch   = intent_map["watch"],
        },
        fleet_mode       = fleet_mode,
        fleet_candidates = arr(fleet_candidates),
        fleet_rollup_16  = arr(fleet_rollup_16),
        fleet_dyn_blocks = arr(fleet_dyn_blocks),
    }))
end

local function render_dashboard()
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say([[<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AntiBot v4.3.6 — SOC Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
.hdr{background:#161b22;border-bottom:1px solid #30363d;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.hdr h1{color:#58a6ff;font-size:18px;font-weight:600}
.badge{font-size:11px;padding:3px 9px;border-radius:20px;border:1px solid #30363d;color:#8b949e}
.badge.live{border-color:#3fb950;color:#3fb950}
.main{padding:20px 24px;max-width:1400px;margin:0 auto}
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #30363d;padding-bottom:0}
.tab{padding:8px 16px;cursor:pointer;font-size:13px;color:#8b949e;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#58a6ff;border-color:#58a6ff}
.tab:hover{color:#e6edf3}
.pane{display:none}.pane.active{display:block}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}
@media(max-width:900px){.g4{grid-template-columns:1fr 1fr}.g2,.g3{grid-template-columns:1fr}}
.sc{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;text-align:center}
.sv{font-size:32px;font-weight:700;line-height:1.1;margin-bottom:2px}
.sl{font-size:12px;color:#8b949e}
.red{color:#f85149}.orange{color:#f0883e}.green{color:#3fb950}.blue{color:#58a6ff}.gray{color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:6px}
.dot{width:7px;height:7px;border-radius:50%;background:#3fb950;display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#21262d;color:#8b949e;font-weight:500;text-align:left;padding:7px 10px;border-bottom:1px solid #30363d}
td{padding:7px 10px;border-bottom:1px solid #21262d}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2129}
.tag{display:inline-block;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:500}
.tag-red{background:#3d1a1a;color:#f85149;border:1px solid #5c2323}
.tag-orange{background:#2d1f0e;color:#f0883e;border:1px solid #4d3213}
.tag-blue{background:#0e1f3d;color:#58a6ff;border:1px solid #1347a0}
.tag-green{background:#0e2d1a;color:#3fb950;border:1px solid #1a5c30}
.tag-gray{background:#1c2129;color:#8b949e;border:1px solid #30363d}
.mono{font-family:monospace;font-size:11px}
.bar-w{background:#21262d;border-radius:3px;overflow:hidden;width:70px;display:inline-block;vertical-align:middle;margin-right:5px;height:5px}
.bar{height:5px;border-radius:3px;transition:width .4s}
.inp{background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:13px;width:260px}
.inp:focus{border-color:#58a6ff;outline:none}
.btn{padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500}
.btn-blue{background:#1347a0;color:#58a6ff}.btn-blue:hover{background:#1a5cbf}
.btn-red{background:#3d1a1a;color:#f85149}.btn-red:hover{background:#5c2323}
.btn-green{background:#0e2d1a;color:#3fb950}.btn-green:hover{background:#1a5c30}
.btn-gray{background:#21262d;color:#8b949e}.btn-gray:hover{background:#2d333b}
.wl-form{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.msg{font-size:12px;padding:6px 12px;border-radius:6px;margin-top:8px;display:none}
.msg.ok{background:#0e2d1a;color:#3fb950;border:1px solid #1a5c30}
.msg.err{background:#3d1a1a;color:#f85149;border:1px solid #5c2323}
#status{font-size:12px;color:#3fb950}
</style>
</head>
<body>

<div class="hdr">
  <h1>🛡 AntiBot v4.3.6 — SOC Dashboard</h1>
  <div style="display:flex;gap:10px;align-items:center">
    <span id="status">Loading...</span>
    <span class="badge live">● LIVE</span>
  </div>
</div>

<div class="main">

  <!-- -->
  <div class="tabs">
    <div class="tab active" onclick="showTab('overview')">📊 Overview</div>
    <div class="tab" onclick="showTab('bans')">🚫 Bans</div>
    <div class="tab" onclick="showTab('threats')">🔴 Threats</div>
    <div class="tab" onclick="showTab('whitelist')">✅ Whitelist</div>
    <div class="tab" onclick="showTab('sync')">📡 Feed &amp; Registry</div>
    <div class="tab" onclick="showTab('domains')">🌐 Domains</div>
    <div class="tab" onclick="showTab('devices')">📱 Devices</div>
    <div class="tab" onclick="showTab('fleet')">🎯 Fleet Detection</div>
  </div>

  <!-- -->
  <div id="tab-overview" class="pane active">
    <div class="card" style="padding:10px 14px">
      <h2 style="margin:0">📊 Kết cục lưu lượng — 7 ngày</h2>
      <div style="font-size:12px;color:var(--color-text-secondary);margin-top:4px">
        Tổng của mọi domain. Số lớn = <b>hôm nay</b>; cột cuối cùng (viền sáng) cũng là hôm nay
        và còn đang chạy nên thấp hơn là bình thường. Tab Domains chỉ liệt kê từng dòng,
        không có hàng tổng — nên đây là số liệu duy nhất ở màn hình này không lặp lại tab khác.
      </div>
    </div>
    <div id="ov-charts" class="g4" style="grid-template-columns:repeat(5,1fr)"></div>

    <div class="card" style="padding:10px 14px">
      <h2 style="margin:0">🔒 Đang thực thi — ngay lúc này</h2>
      <!-- Chỉ hiện khi thực sự có số bị cắt. Đo 2026-08-17 trên cloud28-246:
           `ban:*`=17.680/trần 40.000, `verified:*`=105/trần 500, DBSIZE=299.935
           ⇒ không trần nào bị chạm, dấu ≥ không bao giờ xuất hiện. Để dòng này
           hiện thường trực là giải thích một ký hiệu vô hình. Nhưng xoá hẳn thì
           ngày `ban:*` vượt trần, con số sẽ lặng lẽ đứng yên mà không ai hiểu
           vì sao — nên giữ cơ chế, chỉ bỏ phần thường trực. -->
      <div id="ov-cap-note" style="display:none;font-size:12px;color:var(--color-accent-orange,#f0883e);margin-top:4px">
        ⚠ Dấu <b>≥</b> nghĩa là SCAN đã chạm trần nên con số là <b>cận dưới</b>, không phải tổng —
        nới <code>scan_keys</code> trong <code>admin/init.lua</code>.
      </div>
    </div>
    <div class="g4">
      <div class="sc"><div class="sv red" id="s-ban">—</div><div class="sl">IP đang cấm</div></div>
      <div class="sc"><div class="sv red" id="s-banid">—</div><div class="sl">Identity đang cấm</div></div>
      <div class="sc"><div class="sv orange" id="s-t-chal">—</div><div class="sl">Challenge hôm nay</div></div>
      <div class="sc"><div class="sv" id="s-verif">—</div><div class="sl">Phiên đã xác minh</div></div>
    </div>

    <div class="card">
      <div style="font-size:12px;color:var(--color-text-secondary);line-height:1.7">
        <b>Overview chỉ giữ số tổng.</b> Mọi danh sách chi tiết nằm ở đúng tab của nó, không lặp lại ở đây:<br>
        🚫 <b>Bans</b> — danh sách IP/identity kèm nút gỡ cấm &nbsp;·&nbsp;
        🔴 <b>Threats</b> — IP rủi ro cao từ feed &nbsp;·&nbsp;
        ✅ <b>Whitelist</b> — IP/URL đã tha<br>
        📡 <b>Feed Sync</b> — số IP/ASN đã nạp và lần đồng bộ gần nhất &nbsp;·&nbsp;
        🌐 <b>Domains</b> — từng domain &nbsp;·&nbsp;
        🎯 <b>Fleet Detection</b> — dải đang bị chặn
      </div>
    </div>
  </div>

  <!-- -->
  <div id="tab-bans" class="pane">
    <div class="card">
      <h2>🚫 Bans — nhóm theo IP <span id="ban-count" class="tag tag-red">0</span></h2>
      <div style="font-size:12px;color:var(--color-text-secondary);margin-bottom:10px">
        Chỉ hiển thị <b>IP đang bị ban</b>, kèm các <b>identity</b> (md5(ip+ua)) bị ban trên IP đó.
        <b>TTL</b> = thời gian ban còn lại (<i>vĩnh viễn</i> = permanent). Trỏ chuột vào identity để xem UA.
        Unban/Whitelist riêng cho từng cấp. Sắp xếp theo risk giảm dần, <b>100 IP mỗi trang</b>.
        Trang đang xem được giữ nguyên qua mỗi lần tự nạp lại (60 giây).
      </div>
      <div id="ban-filter" style="margin-bottom:8px"></div>
      <div id="ban-pager" style="margin-bottom:10px"></div>
      <table>
        <thead><tr>
          <th>IP / Identity</th>
          <th>Device</th>
          <th>Risk</th>
          <th>TTL</th>
          <th>Status</th>
          <th>Actions</th>
        </tr></thead>
        <tbody id="t-ban-grouped"></tbody>
      </table>
    </div>
  </div>

  <!-- -->
  <div id="tab-threats" class="pane">
    <div class="g2">
      <div class="card">
        <h2>🔴 Threat Intelligence Feed</h2>
        <table><thead><tr><th>IP</th><th>Score</th><th>Level</th></tr></thead>
        <tbody id="t-rep"></tbody></table>
      </div>
      <div class="card">
        <h2>⚠️ High Risk Identities</h2>
        <table><thead><tr><th>Identity</th><th>Risk</th><th>Level</th></tr></thead>
        <tbody id="t-risk"></tbody></table>
      </div>
    </div>
  </div>

  <!-- -->
  <div id="tab-whitelist" class="pane">
    <div class="card">
      <h2>✅ IP Whitelist</h2>
      <div class="wl-form">
        <input class="inp" id="inp-wl-ip" placeholder="1.2.3.4" type="text">
        <button class="btn btn-green" onclick="wlAction('wl_ip_add','ip','inp-wl-ip')">+ Whitelist IP</button>
        <button class="btn btn-red" onclick="wlAction('unban_ip','ip','inp-wl-ip')">Unban IP</button>
        <button class="btn btn-gray" onclick="wlAction('wl_ip_del','ip','inp-wl-ip')">Remove WL</button>
      </div>
      <div class="msg" id="msg-ip"></div>
      <table><thead><tr><th>IP</th><th>Action</th></tr></thead>
      <tbody id="t-wl-ip"></tbody></table>
    </div>
    <div class="card">
      <h2>✅ URL Prefix Whitelist</h2>
      <div style="margin-bottom:8px;font-size:12px;color:#8b949e">
        Thêm URL prefix để bypass antibot (VD: /media/, /fpc/, /api/)
      </div>
      <div class="wl-form">
        <input class="inp" id="inp-wl-url" placeholder="/api/v1/" type="text">
        <button class="btn btn-green" onclick="wlAction('wl_url_add','prefix','inp-wl-url')">+ Add URL</button>
        <button class="btn btn-gray" onclick="wlAction('wl_url_del','prefix','inp-wl-url')">Remove</button>
      </div>
      <div class="msg" id="msg-url"></div>
      <table><thead><tr><th>URL Prefix</th><th>Action</th></tr></thead>
      <tbody id="t-wl-url"></tbody></table>
    </div>
  </div>

  <!-- -->
  <!-- Feed & Registry — gộp tab Intelligence cũ vào đây (2026-08-31).
       Ba khối dưới cùng một bản chất: dữ liệu nạp từ NGOÀI vào Redis rồi
       antibot đọc ra. `threat_feed_sync.sh` sinh cả ba — IP/ASN reputation,
       JA3 DB dựng từ access log — còn registry good-bot thì seed từ
       `core/data/goodbot.json`. Tách chúng ra hai tab chỉ làm rối. -->
  <div id="tab-sync" class="pane">
    <div class="g3">
      <div class="sc"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">Last Sync</div><div id="sync-time" style="font-size:14px">—</div></div>
      <div class="sc"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">IPs Loaded</div><div id="sync-ip" style="font-size:28px;font-weight:700;color:#58a6ff">—</div></div>
      <div class="sc">
        <div style="font-size:12px;color:#8b949e;margin-bottom:6px">ASN Reputation</div>
        <div id="sync-asn" style="font-size:28px;font-weight:700;color:#3fb950">—</div>
        <div style="font-size:11px;color:#8b949e;margin-top:4px">
          Số khoá <code>rep:asn:</code> — nguồn của tín hiệu <code>asn_rep</code>.
          Vài chục thay vì vài chục nghìn = <code>threat_feed_sync.sh</code> lỗi hoặc chạy bản cũ.
        </div>
      </div>
    </div>

    <div class="card">
      <h2>🤖 Good Bot DNS Registry</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
        Bots tự xưng là crawler sẽ được DNS-verified theo domain suffix đã đăng ký.
        Danh sách chuẩn nằm ở <code>core/data/goodbot.json</code> và tự seed vào Redis mỗi lần
        reload; thêm tay ở đây chỉ nên dùng để cầm máu, sau đó đưa vào file cho mọi máy cùng có.
      </div>
      <div class="wl-form">
        <input class="inp" id="inp-gb-name" placeholder="googlebot" type="text" style="width:130px">
        <input class="inp" id="inp-gb-sfx" placeholder="googlebot.com,google.com" type="text" style="width:240px">
        <button class="btn btn-green" onclick="goodbotDnsAdd()">+ Add</button>
      </div>
      <table><thead><tr><th>Bot Name</th><th>DNS Suffixes</th><th>Action</th></tr></thead>
      <tbody id="t-goodbot-dns"></tbody></table>
    </div>

    <div class="card">
      <h2>🔐 JA3 TLS Fingerprint</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
        Allowlist: browser JA3 từ production log. Blocklist: known bot TLS fingerprint.
      </div>
      <div class="wl-form">
        <input class="inp" id="inp-ja3" placeholder="32-char hex JA3 hash" type="text" style="width:320px">
        <button class="btn btn-green" onclick="ja3Action('ja3_allow')">+ Allow</button>
        <button class="btn btn-red" onclick="ja3Action('ja3_block')">Block</button>
      </div>
      <table><thead><tr><th>JA3 Hash</th><th>Status</th><th>Action</th></tr></thead>
      <tbody id="t-ja3-list"></tbody></table>
    </div>
  </div>

  <!-- -->
  <div id="tab-domains" class="pane">
    <div class="card">
      <h2>🌐 Domain Traffic — Hôm nay</h2>
      <table>
        <thead><tr>
          <th>Domain</th><th>Total</th><th>Clean</th>
          <th>Monitor</th><th>Throttled</th><th>Challenge</th><th>Block</th><th>Block%</th>
        </tr></thead>
        <tbody id="t-domain-stats"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>🚫 Recent Bans by Domain</h2>
      <table>
        <thead><tr>
          <th>IP</th><th>Identity</th><th>Domain</th><th>Score</th><th>Expires</th><th>Action</th>
        </tr></thead>
        <tbody id="t-ban-domain"></tbody>
      </table>
    </div>
  </div>

</div><!-- -->

  <!-- Tab "Intelligence" ĐÃ GỠ (2026-08-31). Nó chứa ba thẻ:
         Good Bot DNS Registry  → chuyển sang tab Feed & Registry
         JA3 TLS Fingerprint    → chuyển sang tab Feed & Registry
         ASN Type Overrides     → XOÁ HẲN, xem chú thích ở nhánh action
       Còn lại một thẻ thì không đáng một tab riêng, nên gộp luôn: cả ba khối
       ở tab kia đều là "dữ liệu nạp từ ngoài vào Redis". 9 tab → 8. -->

</div><!-- -->

  <!-- Devices pane -->
  <div id="tab-devices" class="pane">
    <div class="g4" style="grid-template-columns:repeat(3,1fr);margin-bottom:20px">
      <div class="sc">
        <div class="sv blue" id="dev-desktop-total">—</div>
        <div class="sl">🖥 Browser · Desktop</div>
      </div>
      <div class="sc">
        <div class="sv blue" id="dev-mobile-total">—</div>
        <div class="sl">📱 Browser · Mobile</div>
      </div>
      <div class="sc">
        <div class="sv blue" id="dev-tablet-total">—</div>
        <div class="sl">📟 Browser · Tablet</div>
      </div>
      <div class="sc">
        <div class="sv orange" id="dev-crawler-total">—</div>
        <div class="sl">🕷 Crawler</div>
      </div>
      <div class="sc">
        <div class="sv orange" id="dev-tool-total">—</div>
        <div class="sl">🔧 Tool (HTTP client)</div>
      </div>
      <div class="sc">
        <div class="sv gray" id="dev-unknown-total">—</div>
        <div class="sl">❓ Unknown (UA lạ)</div>
      </div>
      <div class="sc">
        <div class="sv red" id="dev-no_ua-total">—</div>
        <div class="sl" title="Không gửi header User-Agent — tín hiệu bot đứng riêng, không phải 'chưa nhận dạng được'">🕳 Không gửi UA</div>
      </div>
      <div class="sc">
        <div class="sv green" id="dev-verified-total">—</div>
        <div class="sl" title="Cookie PoW còn hiệu lực — thoát ở fast-path trước STEPS_COMMON">🍪 Verified (fast-path)</div>
      </div>
      <div class="sc">
        <div class="sv red" id="dev-gate-total">—</div>
        <div class="sl" title="ban IP / fleet dyn-block — exit trước khi device_classifier chạy">🚪 Chặn ở cửa</div>
      </div>
    </div>
    <div class="g2">
      <div class="card">
        <h2>🧭 Client Distribution — Hôm nay</h2>
        <div style="font-size:12px;color:var(--color-text-secondary);margin-bottom:10px">
          Hai <b>trục khác nhau</b>, đừng cộng chéo:
          <b>AI TRUY CẬP</b> = phân loại ý định (mỗi request rơi vào đúng một ô ⇒ hàng cộng đúng 100%);
          <b>XỬ LÝ</b> = kết cục enforcement (5 cột cộng đúng bằng Tổng, cùng bộ từ vựng với Overview).
          Một "Bad bot" vẫn có thể Clean nếu điểm chưa tới ngưỡng.
          <br><b>Nhóm client = UA nói gì</b>, không phải phán quyết: <i>Crawler</i>/<i>Tool</i> là UA tự khai
          là máy, nên không bao giờ có ô Human. <i>Verified</i> và <i>Chặn ở cửa</i> không phải loại thiết bị —
          đó là hai lối request thoát TRƯỚC khi device_classifier kịp chạy (cookie fast-path và ban ở cửa),
          nên không có thông tin thiết bị để nói. <i>Không gửi UA</i> cũng không phải loại thiết bị: nó là
          <b>tín hiệu bot đứng riêng</b> — trước đây nằm lẫn trong Unknown và chiếm 95% ô đó, chôn mất
          nhóm UA-lạ-thật-sự vốn mới là thứ đáng soi.
        </div>
        <table>
          <thead>
            <tr>
              <th rowspan="2">Nhóm client</th>
              <th rowspan="2">Tổng</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--color-border,#30363d)">👥 Ai truy cập</th>
              <th colspan="6" style="text-align:center;border-bottom:1px solid var(--color-border,#30363d)">⚖️ Xử lý</th>
            </tr>
            <tr>
              <th style="font-weight:400;font-size:11px">Thành phần (=100%)</th>
              <th class="red">Bad bot</th>
              <th class="green">Clean</th>
              <th>Monitor</th>
              <th class="orange">Throttled</th>
              <th class="orange">Challenge</th>
              <th class="red">Block</th>
              <th>Block%</th>
            </tr>
          </thead>
          <tbody id="t-device-stats"></tbody>
        </table>
      </div>
      <div class="card">
        <h2>🚫 Blocked by Device Type — Hôm nay</h2>
        <div id="dev-bar-chart" style="padding:8px 0"></div>
      </div>
    </div>
    <div class="card" style="margin-top:0">
      <h2>🎯 Intent Classification — Hôm nay</h2>
      <div style="font-size:12px;color:var(--color-text-secondary);margin-bottom:10px">
        Phân loại request theo hành vi thực tế, không phụ thuộc loại thiết bị.
      </div>
      <table>
        <thead><tr>
          <th>Intent</th><th>Total</th>
          <th class="green">Clean</th>
          <th>Monitor</th>
          <th class="orange">Throttled</th>
          <th class="orange">Challenge</th>
          <th class="red">Block</th>
          <th>Block%</th>
        </tr></thead>
        <tbody id="t-intent-stats"></tbody>
      </table>
    </div>
    <div class="card" style="margin-top:0">
      <h2>❓ Unknown Client — UA Samples (24h gần nhất)</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
        UA có dáng browser nhưng KHÔNG khớp rule nào — crawler, HTTP tool, verified fast-path và "chặn ở cửa"
        đều đã tách thành nhóm riêng, nên bucket này giờ mới thực sự nhỏ và đáng soi.
        Phình lên = browser mới / UA lạ, cần thêm rule vào device_classifier.lua.
        (Trước đây danh sách này luôn RỖNG: hàm ghi tham chiếu biến <code>ua</code> chưa khai báo ⇒ luôn nil ⇒ không lần nào lưu mẫu.)
      </div>
      <table><thead><tr><th>User-Agent</th></tr></thead>
      <tbody id="t-ua-unknown"></tbody></table>
    </div>
  </div>

  <!-- Fleet Detection pane -->
  <div id="tab-fleet" class="pane">
    <div class="card">
      <h2>🎯 Fleet Detection — Distributed Web Scraping with Rotating IP Fleet</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:10px">
        Active /24 + /16 detection via 3-axis confidence:
        <b>fp_poverty</b> (distinct_IPs / distinct_fingerprints — bot fleet rotates IPs cheaper than fingerprints),
        <b>path_convergence</b> (top-3 path share — bots target few endpoints),
        <b>cookie_vacuum</b> (1 − cookie present ratio — bots have no cookies).
        Mode: <b id="fleet-mode">—</b>.
        Confirm ≥ 0.7 → fleet detected. Suspect ≥ 0.5 → eligible for /16 roll-up.
      </div>
    </div>
    <div class="card">
      <h2>🔴 /24 Candidates <span id="fleet-cand-count" class="tag tag-red">0</span></h2>
      <table>
        <thead><tr>
          <th>/24 CIDR</th>
          <th>Status</th>
          <th>Score</th>
          <th>fp_poverty</th>
          <th>path_conv</th>
          <th>cookie_vac</th>
          <th>Hits</th>
          <th>D-IPs</th>
          <th>D-FP</th>
          <th>First seen</th>
        </tr></thead>
        <tbody id="t-fleet-24"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>🌐 /16 Roll-up <span id="fleet-r16-count" class="tag tag-orange">0</span></h2>
      <table>
        <thead><tr>
          <th>/16 CIDR</th>
          <th>Status</th>
          <th>Confirmed /24 inside</th>
          <th>First seen</th>
        </tr></thead>
        <tbody id="t-fleet-16"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>⛔ Dynamic Blocks (enforce mode) <span id="fleet-dyn-count" class="tag tag-red">0</span></h2>
      <table>
        <thead><tr>
          <th>CIDR</th>
          <th>Info</th>
          <th>TTL (s)</th>
        </tr></thead>
        <tbody id="t-fleet-dyn"></tbody>
      </table>
    </div>
  </div>

<script>
// ── Helpers ───────────────────────────────────────────────────
function tag(score){
  if(score>=0.8) return '<span class="tag tag-red">CRITICAL</span>'
  if(score>=0.6) return '<span class="tag tag-orange">HIGH</span>'
  if(score>=0.4) return '<span class="tag tag-blue">MEDIUM</span>'
  return '<span class="tag tag-gray">LOW</span>'
}
function bar(v,w){
  w=w||70
  var c=v>=0.8?'#f85149':v>=0.5?'#f0883e':'#3fb950'
  return '<div class="bar-w" style="width:'+w+'px"><div class="bar" style="width:'+Math.round(v*100)+'%;background:'+c+'"></div></div>'
}
function trunc(s,n){return s&&s.length>n?s.substring(0,n)+'…':s||'-'}
function setText(id,v){var e=document.getElementById(id);if(e)e.textContent=v}
function setHTML(id,v){var e=document.getElementById(id);if(e)e.innerHTML=v}
function showTab(name){
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'))
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'))
  document.getElementById('tab-'+name).classList.add('active')
  event.target.classList.add('active')
}

// ── Whitelist API ──────────────────────────────────────────────
function wlAction(action,field,inputId){
  var val=document.getElementById(inputId).value.trim()
  if(!val){alert('Vui lòng nhập giá trị');return}
  var body={action:action}
  body[field]=val
  var msgId=inputId.includes('url')?'msg-url':'msg-ip'
  fetch('/antibot-admin/wl',{
    method:'POST',
    credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)
  })
  .then(r=>r.json())
  .then(d=>{
    var el=document.getElementById(msgId)
    el.className='msg '+(d.ok?'ok':'err')
    el.textContent=d.msg||d.error||'Done'
    el.style.display='block'
    setTimeout(()=>el.style.display='none',3000)
    if(d.ok){document.getElementById(inputId).value='';load()}
  })
}
function removeWlIp(ip){
  if(!confirm('Remove whitelist: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_ip_del',ip:ip})
  }).then(()=>load())
}
function removeWlUrl(prefix){
  if(!confirm('Remove whitelist URL: '+prefix+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_url_del',prefix:prefix})
  }).then(()=>load())
}
function unbanIp(ip){
  if(!confirm('Unban IP: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'unban_ip',ip:ip})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function unbanId(id){
  if(!confirm('Unban Identity: '+id.substring(0,16)+'...?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'unban_id',id:id})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function whitelistId(id){
  if(!confirm('Whitelist Identity: '+id.substring(0,16)+'...?\n(persistent allow + clear ban/risk/viol)'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_id',id:id})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}

// ── Main data load ─────────────────────────────────────────────
function load(){
  fetch('/antibot-admin/data', {credentials:'include'})
  .then(r=>{
    if(!r.ok) throw new Error('HTTP '+r.status)
    return r.json()
  })
  .then(d=>{
    var s=d.summary
    // ── Overview: 5 biểu đồ cột 7 ngày ──
    renderOverviewCharts(d.daily||[], d.today||{})
    setText('s-t-chal',  ((d.today||{}).challenge||0).toLocaleString())

    // ── Overview: trạng thái thực thi ──
    // "≥" khi SCAN chạm trần: con số là cận dưới, không phải tổng. Lời giải
    // thích chỉ hiện khi có ít nhất một số thật sự bị cắt — không có gì bị cắt
    // thì cũng không có ký hiệu nào cần giải thích.
    var ge = s.ban_capped ? '≥' : ''
    setText('s-ban',   ge+s.ban_ip)
    setText('s-banid', ge+s.ban_id)
    setText('s-verif', (s.verified_capped ? '≥' : '')+s.verified)
    var capNote = document.getElementById('ov-cap-note')
    if(capNote) capNote.style.display = (s.ban_capped || s.verified_capped) ? '' : 'none'

    // Ẩn khỏi bảng: IDLE + TTL < 60s (sắp expire, không enforce).
    // IDLE với TTL còn lớn vẫn hiển thị với badge IDLE.
    var hiddenTotal = (s.ban_ip_hidden||0) + (s.ban_id_hidden||0)
    var hiddenSfx = hiddenTotal > 0 ? ' (+'+hiddenTotal+' sắp hết hạn, đã ẩn)' : ''
    // Bảng chỉ vẽ tối đa 50 dòng (mỗi dòng tốn 3 lệnh Redis). Nói rõ ra thay vì
    // để người đọc tưởng tổng bằng số dòng đang thấy.
    var shownSfx = (s.ban_ip_shown < s.ban_ip) ? ' — nạp được '+s.ban_ip_shown : ''
    var orphanSfx = (s.ban_id_orphan||0) > 0
      ? ' · '+s.ban_id_orphan.toLocaleString()+' identity không thuộc IP nào đang cấm (không hiện)'
      : ''
    setText('ban-count',
      ge+s.ban_ip.toLocaleString()+' IP · '+s.ban_id.toLocaleString()+' identity'
      + shownSfx + hiddenSfx + orphanSfx)

    // Status tag: active = L7 có hit trong 5 phút; idle = entry vẫn còn TTL
    // nhưng không có hit → traffic đã ngừng tới L7 (L3 lọc upstream hoặc bot dừng)
    function statusTag(r){
      if(r.status==='active'){
        return `<span class="tag tag-red" style="font-size:9px" title="L7 hit: ${r.last_hit||'-'}">ACTIVE</span>`
      }
      return `<span class="tag tag-gray" style="font-size:9px" title="No L7 hit in 5m — L3 or traffic stopped">IDLE</span>`
    }

    // Bảng "Top Banned IPs" của Overview ĐÃ GỠ: nó cắt 10 dòng đầu của cùng
    // `ban_ip_list` mà tab Bans vẽ đầy đủ kèm identity con và nút gỡ cấm —
    // trùng lặp thuần tuý, lại còn khiến thẻ "50" và bảng "10 dòng" mâu thuẫn
    // nhau ngay trên một màn hình.

    // Bans tab: ONLY banned IPs, each with its banned identities (tidy)
    // Group headers = chỉ IP đang bị ban. Identity chỉ hiện nếu IP của nó cũng bị ban.
    var groups={}
    for(var r of d.ban_ip_list||[]){
      groups[r.ip]={ip:r.ip,risk:Math.max(r.rep||0,r.ip_risk||0),
                    ttl_sec:r.ttl_sec,status:r.status,last_hit:r.last_hit,ids:[]}
    }
    for(var r of d.ban_id_list||[]){
      if(r.ip && groups[r.ip]) groups[r.ip].ids.push(r)   // bỏ identity trên IP chưa bị ban
    }
    BANS.groups = groups
    BANS.keys = Object.keys(groups).sort(function(a,b){return (groups[b].risk||0)-(groups[a].risk||0)})
    // Giữ nguyên trang đang xem qua các lần tự nạp lại 60s — nhảy về trang 1
    // mỗi phút thì không ai đọc hết được 19 trang.
    renderBansPage(BANS.page)

    // Threats: rep IPs
    var rt=''
    for(var r of d.rep_ips||[]){
      rt+=`<tr><td class="mono">${r.ip}</td><td>${bar(r.score)}${(r.score*100).toFixed(0)}%</td><td>${tag(r.score)}</td></tr>`
    }
    setHTML('t-rep', rt||nodata(3))

    // Threats: high risk FP
    var rk=''
    for(var r of d.high_risk||[]){
      rk+=`<tr><td class="mono">${trunc(r.id,20)}</td><td>${bar(r.risk)}${(r.risk*100).toFixed(0)}%</td><td>${tag(r.risk)}</td></tr>`
    }
    setHTML('t-risk', rk||nodata(3))

    // Whitelist IPs
    var wi=''
    for(var ip of d.wl_ips||[]){
      wi+=`<tr><td class="mono">${ip}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="removeWlIp('${ip}')">Remove</button></td></tr>`
    }
    setHTML('t-wl-ip', (d.wl_capped?caprow(2):'')+(wi||nodata(2)))

    // Whitelist URLs
    var wu=''
    for(var u of d.wl_urls||[]){
      wu+=`<tr><td class="mono">${u}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="removeWlUrl('${u}')">Remove</button></td></tr>`
    }
    setHTML('t-wl-url', wu||nodata(2))

    // Feed sync
    var ts=d.threat_sync||{}
    setText('sync-time', ts.last_sync||'-')
    setText('sync-ip',   (ts.ip_loaded||0).toLocaleString())
    setText('sync-asn',  (ts.asn_loaded||0).toLocaleString())

    setText('status','Updated: '+new Date().toLocaleTimeString('vi-VN'))
    renderDomains(d)
    renderDevices(d)
    renderFleet(d)
    // UA info
    if(d.ua_info){
      setText('ua-count', (d.ua_info.count||0).toLocaleString())
      setText('ua-sync-time', d.ua_info.sync_time||'never')
      var uc=''
      for(var p of (d.ua_info.custom||[])){
        uc+=`<tr><td class="mono">${p}</td>
        <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px"
            onclick="removeUaCustom('${p}')">Remove</button></td></tr>`
      }
      setHTML('t-ua-custom', uc||nodata(2))
    }
    // Intelligence tab data — inside .then(d) so 'd' is in scope
    // Good bot DNS
    var gb=''
    for(var r of (d.goodbot_dns||[])){
      gb+=`<tr><td class="mono">${r.name}</td><td class="mono gray">${r.suffixes}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="goodbotDnsDel('${r.name}')">Remove</button></td></tr>`
    }
    setHTML('t-goodbot-dns', (d.goodbot_capped?caprow(3):'')+(gb||nodata(3)))
    // JA3 list
    var jl=''
    for(var r of (d.ja3_list||[])){
      var sc=r.status==='allow'?'tag-green':'tag-red'
      jl+=`<tr><td class="mono" style="font-size:10px">${r.hash}</td>
      <td><span class="tag ${sc}">${r.status}</span></td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="ja3Remove('${r.hash}')">Remove</button></td></tr>`
    }
    setHTML('t-ja3-list', (d.ja3_capped?caprow(3):'')+(jl||nodata(3)))
  })
  .catch(e=>setText('status','Error: '+e.message))
}

// ── Overview: 5 biểu đồ cột 7 ngày ──────────────────────────────────────
// Small multiples chứ không gộp một biểu đồ: năm đại lượng lệch nhau hàng chục
// lần (Tổng ~400k, Challenge ~1k), vẽ chung một trục thì bốn cột dưới bẹp thành
// đường kẻ. Mỗi biểu đồ tự chuẩn hoá theo đỉnh CỦA CHÍNH NÓ, nên đọc được
// XU HƯỚNG; con số tuyệt đối nằm ở dòng lớn phía trên và trong tooltip.
function renderOverviewCharts(daily, today){
  var METRICS=[
    {k:'req',       label:'Tổng request', color:'#58a6ff'},
    {k:'allow',     label:'Clean',        color:'#3fb950'},
    {k:'monitor',   label:'Monitor',      color:'#8b949e'},
    {k:'throttled', label:'Throttled',    color:'#f0883e'},
    {k:'block',     label:'Block',        color:'#f85149'}
  ]
  if(!daily || daily.length===0){
    setHTML('ov-charts','<div class="sc"><div class="sl">chưa có dữ liệu 7 ngày</div></div>')
    return
  }
  var tot=today.req||0
  var html=''
  for(var m of METRICS){
    var vals=daily.map(function(r){ return r[m.k]||0 })
    var max=Math.max.apply(null,[1].concat(vals))
    var cur=today[m.k]||0
    var sub=(m.k!=='req'&&tot>0) ? ((cur/tot)*100).toFixed(1)+'% lưu lượng' : 'hôm nay'

    var bars='', axis=''
    for(var i=0;i<vals.length;i++){
      var v=vals[i]
      var h=Math.round((v/max)*100)
      if(v>0&&h<3) h=3           // giá trị khác 0 luôn phải nhìn thấy được
      var last=(i===vals.length-1)
      var op=last?'1':'.5'
      var ring=last?';box-shadow:0 0 0 1px '+m.color:''
      bars+='<div title="'+(daily[i].day||'')+': '+v.toLocaleString()+'" '
          + 'style="flex:1;display:flex;align-items:flex-end;height:52px">'
          + '<div style="width:100%;height:'+h+'%;min-height:1px;background:'+m.color
          + ';opacity:'+op+';border-radius:2px 2px 0 0'+ring+'"></div></div>'
      axis+='<div style="flex:1;text-align:center;font-size:9px;color:#8b949e">'
          + (daily[i].day||'').split('/')[0]+'</div>'
    }
    html+='<div class="sc" style="text-align:left;padding:10px 12px">'
      + '<div style="font-size:11px;color:#8b949e">'+m.label+'</div>'
      + '<div style="font-size:20px;font-weight:700;color:'+m.color+';line-height:1.25">'
      +   cur.toLocaleString()+'</div>'
      + '<div style="font-size:10px;color:#8b949e;margin-bottom:6px">'+sub+'</div>'
      + '<div style="display:flex;gap:2px;align-items:flex-end">'+bars+'</div>'
      + '<div style="display:flex;gap:2px;margin-top:2px">'+axis+'</div>'
      + '</div>'
  }
  setHTML('ov-charts', html)
}

// ── Bảng Bans: phân trang phía client ────────────────────────────────────
// Dữ liệu về một lần rồi giữ trong BANS; nút chuyển trang chỉ vẽ lại, không
// gọi lại API. `page` được giữ qua mỗi lần tự nạp 60s — nhảy về trang 1 mỗi
// phút thì không ai đọc hết được 19 trang.
// `filter` mặc định 'active' — chỉ những IP CÒN ĐANG đâm vào tường.
// Lý do: đo 2026-08-10 trên cloud28-246 có 6.623 IP + 10.630 identity đang bị
// cấm, nhưng chỉ 44 khoá `ban:hit:*` (TTL 300s) tồn tại ⇒ **99,7% lệnh cấm
// đang ngủ**. Chúng là hồ sơ, không phải sự việc. Mặc định mở ra 67 trang hồ
// sơ ngủ thì không ai lật hết; mặc định 'active' cho thẳng thứ đang xảy ra.
var BANS={keys:[],groups:{},page:1,per:100,filter:'active'}

// Một IP tính là "đang hit" nếu chính nó, hoặc một identity dưới nó, có
// `ban:hit:` còn hạn (nghĩa là L7 vừa thi hành lệnh cấm trong 5 phút qua).
function banGroupActive(g){
  if(g.status==='active') return true
  for(var r of g.ids){ if(r.status==='active') return true }
  return false
}
function banVisibleKeys(){
  if(BANS.filter!=='active') return BANS.keys
  var groups=BANS.groups
  return BANS.keys.filter(function(k){ return banGroupActive(groups[k]) })
}
function setBanFilter(f){
  BANS.filter=f
  BANS.page=1
  renderBansPage(1)
}

var devIcons={'mobile':'📱','tablet':'📟','desktop':'🖥️','crawler':'🕷','tool':'🔧','unknown':'❓'}
var devMap={
  'mobile_chrome_android':'mobile','mobile_safari_ios':'mobile',
  'mobile_safari_ios_old':'mobile','custom_tab':'mobile','inapp':'mobile',
  'tablet_ipad':'tablet','tablet_android':'tablet',
  'desktop_chrome':'desktop','desktop_safari':'desktop',
  'desktop_firefox':'desktop','desktop_other':'desktop',
  'crawler':'crawler','http_client':'tool',
}
function devLabelOf(dev){
  var dg=devMap[dev||'']||'unknown'
  var di=devIcons[dg]||'❓'
  return dev&&dev!='?'?(di+' '+dev):'❓'
}
// TTL còn lại: -1 = vĩnh viễn, else s/m/h/d
function fmtTTL(sec){
  if(sec===undefined||sec===null) return '-'
  if(sec<0) return 'vĩnh viễn'
  if(sec<60) return sec+'s'
  if(sec<3600) return Math.floor(sec/60)+'m '+(sec%60)+'s'
  if(sec<86400) return Math.floor(sec/3600)+'h '+Math.floor((sec%3600)/60)+'m'
  return Math.floor(sec/86400)+'d '+Math.floor((sec%86400)/3600)+'h'
}
// Mọi dòng ở đây ĐỀU đang bị ban → badge BANNED; "đang hit" nếu còn traffic.
function banBadge(r){
  var hit = r.status==='active'
    ? ' <span class="gray" style="font-size:9px" title="Vẫn đang bị hit ('+(r.last_hit||'')+')">· đang hit</span>'
    : ''
  return '<span class="tag tag-red" style="font-size:9px">BANNED</span>'+hit
}
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;')}

function renderBansPage(page){
  var groups=BANS.groups, per=BANS.per
  var gkeys=banVisibleKeys()

  // Thanh lọc — luôn hiện cả hai con số để không ai nhầm "44 dòng" là tổng.
  var nActive=0
  for(var k of BANS.keys){ if(banGroupActive(groups[k])) nActive++ }
  var fbtn=function(f,label,n){
    var on=BANS.filter===f
    if(on) return `<span class="tag tag-red" style="padding:4px 10px;margin-right:6px">${label} (${n.toLocaleString()})</span>`
    return `<button class="btn btn-gray" style="font-size:11px;padding:4px 10px;margin-right:6px" onclick="setBanFilter('${f}')">${label} (${n.toLocaleString()})</button>`
  }
  setHTML('ban-filter',
    fbtn('active','⚡ Đang hit',nActive)+fbtn('all','📋 Tất cả',BANS.keys.length)+
    `<span class="gray" style="font-size:11px">— "đang hit" = L7 vừa thi hành lệnh cấm trong 5 phút qua. Phần còn lại là hồ sơ còn hạn nhưng không có lưu lượng.</span>`)

  var pages=Math.max(1, Math.ceil(gkeys.length/per))
  if(page<1) page=1
  if(page>pages) page=pages
  BANS.page=page
  var from=(page-1)*per, to=Math.min(from+per, gkeys.length)

  var gh=''
  for(var k of gkeys.slice(from,to)){
    var g=groups[k]
    // ── IP group-header row (IP này CHẮC CHẮN đang bị ban) ──
    gh+=`<tr style="background:rgba(248,81,73,.07)">
      <td class="mono"><b>${g.ip}</b></td>
      <td class="gray" style="font-size:11px">IP · ${g.ids.length} id</td>
      <td>${bar(g.risk)}${(g.risk*100).toFixed(0)}%</td>
      <td class="gray" style="font-size:11px">${fmtTTL(g.ttl_sec)}</td>
      <td>${banBadge(g)}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px" onclick="unbanIp('${g.ip}')">Unban IP</button>
          <button class="btn btn-green" style="font-size:11px;padding:2px 7px;margin-left:4px" onclick="wlFromBan('${g.ip}')">Whitelist IP</button></td>
    </tr>`
    // ── identity rows under this IP (UA ở tooltip để soi bot giả) ──
    for(var r of g.ids){
      gh+=`<tr>
        <td class="mono" style="font-size:11px;padding-left:20px" title="UA: ${esc(r.ua)}">↳ ${trunc(r.id,20)}</td>
        <td style="font-size:11px" title="UA: ${esc(r.ua)}">${devLabelOf(r.device)}</td>
        <td>${bar(r.risk)}${(r.risk*100).toFixed(0)}%</td>
        <td class="gray" style="font-size:11px">${fmtTTL(r.ttl_sec)}</td>
        <td>${banBadge(r)}</td>
        <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px" onclick="unbanId('${r.id}')">Unban</button>
            <button class="btn btn-green" style="font-size:11px;padding:2px 7px;margin-left:4px" onclick="whitelistId('${r.id}')">Whitelist</button></td>
      </tr>`
    }
  }
  setHTML('t-ban-grouped', gh||nodata(6))

  // Thanh chuyển trang. Chỉ hiện khi thật sự có nhiều hơn một trang.
  if(pages<=1){ setHTML('ban-pager',''); return }
  var btn=function(p,label,dis){
    if(dis) return `<span class="tag tag-gray" style="padding:3px 9px;margin-right:4px">${label}</span>`
    return `<button class="btn btn-gray" style="font-size:11px;padding:3px 9px;margin-right:4px" onclick="renderBansPage(${p})">${label}</button>`
  }
  var nav=btn(1,'« đầu',page===1)+btn(page-1,'‹ trước',page===1)
  // Cửa sổ 5 số quanh trang hiện tại — 19 trang mà liệt kê hết thì rối mắt.
  var lo=Math.max(1,page-2), hi=Math.min(pages,lo+4)
  lo=Math.max(1,hi-4)
  for(var p=lo;p<=hi;p++){
    nav += p===page
      ? `<span class="tag tag-red" style="padding:3px 9px;margin-right:4px"><b>${p}</b></span>`
      : btn(p,String(p),false)
  }
  nav+=btn(page+1,'sau ›',page===pages)+btn(pages,'cuối »',page===pages)
  nav+=`<span class="gray" style="font-size:11px;margin-left:8px">trang ${page}/${pages} — IP ${from+1}–${to} / ${gkeys.length}</span>`
  setHTML('ban-pager', nav)
}

function renderDomains(d){
  // Domain stats table
  var ds=''
  for(var r of (d.domain_stats||[])){
    var total=r.req||0
    var blk=r.block||0
    var pct=total>0?((blk/total)*100).toFixed(1)+'%':'0%'
    var cls=blk>100?'red':blk>20?'orange':'green'
    ds+=`<tr>
      <td class="mono"><b>${r.host}</b></td>
      <td>${total.toLocaleString()}</td>
      <td class="green">${(r.allow||0).toLocaleString()}</td>
      <td class="gray">${(r.monitor||0).toLocaleString()}</td>
      <td class="orange">${(r.throttled||0).toLocaleString()}</td>
      <td class="orange">${(r.challenge||0).toLocaleString()}</td>
      <td class="red">${blk.toLocaleString()}</td>
      <td class="${cls}"><b>${pct}</b></td>
    </tr>`
  }
  setHTML('t-domain-stats', ds||nodata(8))

  // Ban context table
  var bc=''
  for(var r of (d.ban_ctx_list||[])){
    bc+=`<tr>
      <td class="mono">${r.ip}</td>
      <td class="mono gray" style="font-size:10px">${trunc(r.identity||'',16)}</td>
      <td class="mono">${r.domain}</td>
      <td>${bar(r.score/100)}${r.score}</td>
      <td class="gray" style="font-size:11px">${r.ttl}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px"
          onclick="unbanIp('${r.ip}')">Unban IP</button>
          <button class="btn btn-green" style="font-size:11px;padding:2px 7px;margin-left:4px"
          onclick="wlFromBan('${r.ip}')">Whitelist</button></td>
    </tr>`
  }
  setHTML('t-ban-domain', bc||nodata(6))
}

function nodata(cols){
  return `<tr><td colspan="${cols}" style="text-align:center;color:#484f58;padding:16px">Không có dữ liệu</td></tr>`
}
// Dòng cảnh báo chèn ĐẦU bảng khi `scan_keys` chạm trần. Không có nó thì một
// danh sách thiếu trông y hệt một danh sách đủ — đúng cách lỗi 2026-08-31 sống
// sót: ba máy hiện 18/17/15 mục trên tổng 41, không máy nào báo gì.
function caprow(cols){
  return `<tr><td colspan="${cols}" style="color:var(--color-accent-orange,#f0883e);font-size:11px;padding:6px 8px">`
       + `⚠ Danh sách BỊ CẮT — SCAN chạm trần, đây không phải toàn bộ. `
       + `Đối chiếu bằng <code>redis-cli --scan</code>, và xem <code>scan_keys cham tran</code> trong error.log.</td></tr>`
}
function uaAction(action){
  var pat=document.getElementById('inp-ua-pat').value.trim()
  if(!pat){alert('Nhập pattern UA');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:action,pattern:pat})
  }).then(r=>r.json()).then(d=>{
    var el=document.getElementById('msg-ua')
    el.className='msg '+(d.ok?'ok':'err')
    el.textContent=d.msg
    el.style.display='block'
    setTimeout(()=>el.style.display='none',3000)
    if(d.ok){document.getElementById('inp-ua-pat').value='';load()}
  })
}
function uaSync(){
  if(!confirm('Sync UA patterns từ github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ua_sync'})
  }).then(r=>r.json()).then(d=>alert(d.msg))
}
function removeUaCustom(pat){
  if(!confirm('Remove UA pattern: '+pat+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ua_del',pattern:pat})
  }).then(()=>load())
}
function goodbotDnsAdd(){
  var name=document.getElementById('inp-gb-name').value.trim()
  var sfx=document.getElementById('inp-gb-sfx').value.trim()
  if(!name||!sfx){alert('Nhập bot name và DNS suffixes');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'goodbot_dns_add',name:name,suffixes:sfx})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function goodbotDnsDel(name){
  if(!confirm('Remove good bot: '+name+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'goodbot_dns_del',name:name})
  }).then(r=>r.json()).then(d=>{load()})
}
function ja3Action(action){
  var hash=document.getElementById('inp-ja3').value.trim()
  if(!hash||hash.length!==32){alert('Nhập JA3 hash (32 hex chars)');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:action,hash:hash})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function ja3Remove(hash){
  if(!confirm('Remove JA3: '+hash.substring(0,8)+'...?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ja3_remove',hash:hash})
  }).then(r=>r.json()).then(d=>{load()})
}
function wlFromBan(ip){
  if(!confirm('Whitelist & unban IP: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_ip_add',ip:ip})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}

function renderDevices(d){
  var devs = d.device_stats || []
  var icons = {desktop:'🖥',mobile:'📱',tablet:'📟',crawler:'🕷',tool:'🔧',unknown:'❓',no_ua:'🕳',verified:'🍪',gate:'🚪'}
  var labels = {desktop:'Browser · Desktop',mobile:'Browser · Mobile',tablet:'Browser · Tablet',
                crawler:'Crawler',tool:'Tool',unknown:'Unknown (UA lạ)',no_ua:'Không gửi UA',
                verified:'Verified (cookie fast-path)',gate:'Chặn ở cửa'}
  var notes  = {unknown:'UA có dáng browser nhưng không khớp rule nào trong device_classifier',
                no_ua:'Không gửi header User-Agent. Bản thân điều đó là tín hiệu bot (ua_anomaly đặt ua_flag=0.5), không phải "chưa nhận dạng được"',
                verified:'Đã giải PoW từ trước, cookie còn hiệu lực — thoát trước STEPS_COMMON nên không phân loại thiết bị',
                gate:'ban IP / fleet dyn-block — exit trước device_classifier (STEPS_COMMON bước 10)'}

  // Summary cards
  for(var dev of devs){
    setText('dev-'+dev.group+'-total', (dev.total||0).toLocaleString())
  }

  // Bảng hai trục. Trục "ai truy cập" luôn cộng đúng 100% vì async/logger.lua
  // tăng `dev_<nhóm>` và `ibd_<nhóm>_<ý định>` CÙNG MỘT LẦN cho mỗi request.
  // Nếu chúng lệch nhau thì đó là lỗi ĐỌC chứ không phải lỗi ghi — nên hiển thị
  // cảnh báo thay vì lặng lẽ in ra một tỷ lệ vô lý (Human 114%).
  var rows = ''
  var ibd  = d.intent_by_device || {}
  var maxTotal = Math.max(1, ...devs.map(d=>d.total||0))
  var grand = 0
  for(var dv of devs){ grand += dv.total||0 }

  var INTENT_VIEW = [
    {k:'human',   label:'Human',    color:'#3fb950'},
    {k:'goodbot', label:'Good bot', color:'#58a6ff'},
    {k:'watch',   label:'Watch',    color:'#8b949e'},
    {k:'bot',     label:'Bad bot',  color:'#f85149'}
  ]

  for(var dev of devs){
    var total   = dev.total     || 0
    var clean   = dev.clean     || 0
    var mon     = dev.monitor   || 0
    var thr     = dev.throttled || 0
    var chal    = dev.challenge || 0
    var blk     = dev.block     || 0
    var pct     = total > 0 ? ((blk/total)*100).toFixed(1)+'%' : '0%'
    var cls     = blk > total*0.3 ? 'red' : blk > total*0.1 ? 'orange' : 'green'
    var dg      = dev.group
    var src     = ibd[dg] || {}

    // Mẫu số là TỔNG CÁC Ô Ý ĐỊNH, không phải `dev_<nhóm>`. Nhờ vậy thanh luôn
    // đúng 100% kể cả khi hai nguồn lệch; phần lệch được nêu riêng ở cột Tổng.
    var isum = 0
    for(var iv of INTENT_VIEW){ isum += (src[iv.k]||0) }

    var seg = '', legend = ''
    if(isum > 0){
      for(var iv of INTENT_VIEW){
        var n = src[iv.k]||0
        if(n === 0) continue
        var w = (n/isum)*100
        seg += '<div title="'+iv.label+': '+n.toLocaleString()+' ('+w.toFixed(1)+'%)" '
             + 'style="width:'+w+'%;background:'+iv.color+'"></div>'
        if(w >= 8) legend += '<span style="color:'+iv.color+';margin-right:8px">'
             + iv.label+' '+w.toFixed(0)+'%</span>'
      }
    }
    var barCell = isum > 0
      ? '<div style="display:flex;height:9px;border-radius:3px;overflow:hidden;min-width:120px">'+seg+'</div>'
        + '<div style="font-size:10px;margin-top:3px">'+legend+'</div>'
      : '<span class="gray" style="font-size:11px">chưa có dữ liệu</span>'

    var botPct = isum > 0 ? (((src.bot||0)/isum)*100).toFixed(0)+'%' : '-'
    var botCls = (src.bot||0) > isum*0.5 ? 'red' : (src.bot||0) > isum*0.2 ? 'orange' : 'gray'

    // Lệch > 1% giữa hai nguồn = dấu hiệu số liệu bị cắt. Nêu ra, đừng giấu.
    var drift = (total > 0 && isum > 0) ? Math.abs(isum-total)/total : 0
    var warn = drift > 0.01
      ? ' <span class="orange" style="font-size:10px" title="dev_'+dg+'='+total.toLocaleString()
        +' nhưng tổng các ô ý định='+isum.toLocaleString()+'. Hai nguồn phải bằng nhau — lệch nghĩa là dữ liệu đọc bị thiếu.">⚠ lệch '
        +(drift*100).toFixed(0)+'%</span>'
      : ''
    var share = grand > 0 ? ' <span class="gray" style="font-size:10px">'
                + ((total/grand)*100).toFixed(1)+'%</span>' : ''

    var note = notes[dg] ? ' <span class="gray" style="cursor:help" title="'+notes[dg]+'">ⓘ</span>' : ''

    rows += '<tr>'
      + '<td><b>' + (icons[dg]||'') + ' ' + (labels[dg]||dg) + '</b>' + note + '</td>'
      + '<td>' + total.toLocaleString() + share + warn + '</td>'
      + '<td style="min-width:150px">' + barCell + '</td>'
      + '<td class="' + botCls + '"><b>' + botPct + '</b></td>'
      + '<td class="green">' + clean.toLocaleString() + '</td>'
      + '<td class="gray">' + mon.toLocaleString() + '</td>'
      + '<td class="orange">' + thr.toLocaleString() + '</td>'
      + '<td class="orange">' + chal.toLocaleString() + '</td>'
      + '<td class="red">' + blk.toLocaleString() + '</td>'
      + '<td class="' + cls + '"><b>' + pct + '</b></td>'
      + '</tr>'
  }
  setHTML('t-device-stats', rows || nodata(10))

  // Bar chart
  var chart = ''
  for(var dev of devs){
    var total  = dev.total   || 0
    var blk    = dev.block   || 0
    var chal   = dev.challenge || 0
    // `monitor` (ghi sổ nhưng cho đi) và `throttled` (429) gộp thành một dải
    // giữa — chúng không sạch mà cũng không phải bị chặn hẳn.
    var mid    = (dev.monitor||0) + (dev.throttled||0)
    var clean  = dev.clean || 0
    if(total === 0) continue
    var wPct   = Math.round((total/maxTotal)*100)
    var blkW   = total > 0 ? Math.round((blk/total)*100)  : 0
    var chalW  = total > 0 ? Math.round((chal/total)*100) : 0
    var midW   = total > 0 ? Math.round((mid/total)*100)  : 0
    var actW   = Math.max(0, 100 - blkW - chalW - midW)
    chart += '<div style="margin-bottom:14px">'
      + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
      + '<span style="font-size:12px">' + (icons[dev.group]||'') + ' ' + (labels[dev.group]||dev.group) + '</span>'
      + '<span style="font-size:11px;color:#8b949e">' + total.toLocaleString() + ' reqs</span>'
      + '</div>'
      + '<div style="background:#21262d;border-radius:4px;height:18px;overflow:hidden;display:flex">'
      + '<div style="width:'+actW+'%;background:#3fb950;transition:width .4s" title="Clean: '+clean+'"></div>'
      + '<div style="width:'+midW+'%;background:#8b949e;transition:width .4s" title="Monitor + Throttled: '+mid+'"></div>'
      + '<div style="width:'+chalW+'%;background:#f0883e;transition:width .4s" title="Challenge: '+chal+'"></div>'
      + '<div style="width:'+blkW+'%;background:#f85149;transition:width .4s" title="Block: '+blk+'"></div>'
      + '</div>'
      + '<div style="display:flex;gap:12px;margin-top:3px;font-size:10px;color:#8b949e">'
      + '<span style="color:#3fb950">■ Clean: '+clean.toLocaleString()+'</span>'
      + '<span style="color:#8b949e">■ Monitor+Throttled: '+mid.toLocaleString()+'</span>'
      + '<span style="color:#f0883e">■ Challenge: '+chal.toLocaleString()+'</span>'
      + '<span style="color:#f85149">■ Block: '+blk.toLocaleString()+'</span>'
      + '</div>'
      + '</div>'
  }
  setHTML('dev-bar-chart', chart || '<div style="color:#8b949e;font-size:12px;padding:16px">Chưa có dữ liệu hôm nay</div>')

  // Unknown UA samples
  var samples = d.ua_unknown_samples || []
  var sr = ''
  for(var ua of samples){
    var cls = ua.match(/python|curl|go-http|java|scrapy|okhttp|requests/i)
      ? 'red' : ua.match(/mozilla|webkit|gecko/i) ? 'orange' : 'gray'
    sr += '<tr><td class="mono ' + cls + '" style="font-size:11px;word-break:break-all">' + ua + '</td></tr>'
  }
  setHTML('t-ua-unknown', sr || nodata(1))

  // Intent stats
  var intents = d.intent_stats || {}
  var irows = ''
  var imap = [
    {key:'human',   label:'👤 Human',      cls:'green'},
    {key:'goodbot', label:'✅ Good bot',   cls:'blue'},
    {key:'bot',     label:'🤖 Bad bot',    cls:'red'},
    {key:'watch',   label:'👁 Watch',      cls:'orange'},
  ]
  for(var im of imap){
    var s = intents[im.key] || {total:0,monitor:0,throttled:0,challenge:0,block:0}
    // Cùng nguyên tắc như bảng trên: Clean là phần dư SAU KHI trừ hết mọi
    // action có tên, không phải "mọi thứ không bị chặn".
    var clean = Math.max(0, (s.total||0) - (s.monitor||0) - (s.throttled||0)
                                         - (s.challenge||0) - (s.block||0))
    var pct = s.total > 0 ? (((s.block||0)/s.total)*100).toFixed(1)+'%' : '0%'
    irows += '<tr>'
      + '<td><b class="'+im.cls+'">'+im.label+'</b></td>'
      + '<td>'+(s.total||0).toLocaleString()+'</td>'
      + '<td class="green">'+clean.toLocaleString()+'</td>'
      + '<td class="gray">'+((s.monitor||0)).toLocaleString()+'</td>'
      + '<td class="orange">'+((s.throttled||0)).toLocaleString()+'</td>'
      + '<td class="orange">'+((s.challenge||0)).toLocaleString()+'</td>'
      + '<td class="red">'+((s.block||0)).toLocaleString()+'</td>'
      + '<td class="'+im.cls+'"><b>'+pct+'</b></td>'
      + '</tr>'
  }
  setHTML('t-intent-stats', irows || nodata(8))
}

function fmtFirstSeen(ts){
  if(!ts || ts<=0) return '-'
  var diff = Math.floor(Date.now()/1000) - ts
  if(diff < 60)    return diff + 's ago'
  if(diff < 3600)  return Math.floor(diff/60) + 'm ago'
  if(diff < 86400) return Math.floor(diff/3600) + 'h ago'
  return Math.floor(diff/86400) + 'd ago'
}

function fleetStatusTag(s){
  if(s === 'confirm') return '<span class="tag tag-red">CONFIRM</span>'
  if(s === 'suspect') return '<span class="tag tag-orange">SUSPECT</span>'
  return '<span class="tag tag-gray">'+(s||'-')+'</span>'
}

function renderFleet(d){
  setText('fleet-mode', d.fleet_mode || 'shadow')

  var cands = d.fleet_candidates || []
  setText('fleet-cand-count', cands.length)
  var rows = ''
  for(var c of cands){
    var scoreCls = c.score >= 0.7 ? 'red' : (c.score >= 0.5 ? 'orange' : 'gray')
    rows += '<tr>'
      + '<td class="mono"><b>' + c.cidr + '</b></td>'
      + '<td>' + fleetStatusTag(c.status) + '</td>'
      + '<td class="' + scoreCls + '"><b>' + (c.score||0).toFixed(2) + '</b></td>'
      + '<td>' + (c.fp_poverty||0).toFixed(2) + '</td>'
      + '<td>' + (c.path_convergence||0).toFixed(2) + '</td>'
      + '<td>' + (c.cookie_vacuum||0).toFixed(2) + '</td>'
      + '<td class="mono">' + (c.hits||0).toLocaleString() + '</td>'
      + '<td class="mono">' + (c.distinct_ips||0) + '</td>'
      + '<td class="mono">' + (c.distinct_fp||0) + '</td>'
      + '<td>' + fmtFirstSeen(c.first_seen) + '</td>'
      + '</tr>'
  }
  setHTML('t-fleet-24', rows || nodata(10))

  var r16 = d.fleet_rollup_16 || []
  setText('fleet-r16-count', r16.length)
  var rows16 = ''
  for(var r of r16){
    rows16 += '<tr>'
      + '<td class="mono"><b>' + r.cidr + '</b></td>'
      + '<td>' + fleetStatusTag(r.status) + '</td>'
      + '<td class="mono">' + (r.sub_count||0) + '</td>'
      + '<td>' + fmtFirstSeen(r.first_seen) + '</td>'
      + '</tr>'
  }
  setHTML('t-fleet-16', rows16 || nodata(4))

  var dyn = d.fleet_dyn_blocks || []
  setText('fleet-dyn-count', dyn.length)
  var rowsd = ''
  for(var dn of dyn){
    rowsd += '<tr>'
      + '<td class="mono"><b>' + dn.cidr + '</b></td>'
      + '<td style="font-size:11px;color:#8b949e">' + (dn.info||'-') + '</td>'
      + '<td class="mono">' + (dn.ttl||0) + '</td>'
      + '</tr>'
  }
  setHTML('t-fleet-dyn', rowsd || nodata(3))
}

// 10s -> 60s. Moi lan nap chay ~18 lenh scan_keys, moi lenh la mot loat
// round-trip SCAN sang Redis. Mot tab de mo o 10s = ~18 vong quet keyspace
// moi 10 giay, chay lien tuc ca ngay. Xem chu thich scan_keys dau file.
setInterval(load,60000)
load()
</script>
</body>
</html>]])
end

function _M.router()
    if not auth() then return end

    local uri = (ngx.var.uri or ""):gsub("//+","/"):gsub("/+$","")
    local method = ngx.var.request_method or "GET"

    if uri == "/antibot-admin" or uri == "/antibot-admin/index" then
        return render_dashboard()
    end
    if uri == "/antibot-admin/data" then
        return render_data()
    end
    if uri == "/antibot-admin/wl" and method == "POST" then
        return handle_whitelist_api()
    end

    ngx.status = 404
    ngx.say("Not found")
end

return _M
