local _M = {}

local LOG_FILE = "/var/log/antibot/antibot.log"

local DEVICE_GROUP = {
    mobile_chrome_android = "mobile",
    mobile_safari_ios     = "mobile",
    mobile_safari_ios_old = "mobile",
    custom_tab            = "mobile",
    inapp                 = "mobile",
    tablet_ipad           = "tablet",
    tablet_android        = "tablet",
    desktop_chrome        = "desktop",
    desktop_safari        = "desktop",
    desktop_firefox       = "desktop",
    desktop_other         = "desktop",
    crawler               = "crawler",
    http_client           = "tool",
    -- Ba nhóm dưới KHÔNG do device_classifier sinh ra. Xem `_M.run` để biết vì
    -- sao phải tách: gộp chúng vào "unknown" là trộn bốn dân số khác hẳn nhau
    -- vào một dòng rồi bắt người đọc tự hiểu.
    verified_fastpath     = "verified",
    gate_exit             = "gate",
    -- `no_ua` — request KHÔNG gửi header User-Agent. Đo 2026-08-20 trên
    -- cloud28-246: **14.095/14.768 = 95,4%** ô `unknown` là nhóm này, và 92%
    -- trong đó bị chặn. Nó không phải "chưa nhận dạng được" — nó là một tín
    -- hiệu bot đứng riêng (`ua_anomaly.run` đặt thẳng `ua_flag = 0.5` cho UA
    -- rỗng). Trộn chung khiến 673 UA thật-mà-không-khớp-rule bị chôn dưới nó.
    no_ua                 = "no_ua",
}

-- ── Nhãn ý định theo `action_reason` ─────────────────────────────────────
-- VÌ SAO PHẢI CÓ BẢNG NÀY, chứ không chỉ dựa vào bốn trường bằng chứng:
-- `bot_score` / `ua_flag` / `ip_rep` / `ip_risk` đều CHỈ được điền ở tầng
-- detection + intelligence — chạy SAU khi dispatch theo class. Mà mọi lệnh
-- chặn "khoá ở cửa" đều thoát TRƯỚC đó:
--     banned_ip          l7/ban/ip_ban_check          STEPS_COMMON bước 6
--     banned_id          l7/ban/ban_store             trước detection
--     fleet_dyn_block_*  detection/fleet/check_block  STEPS_COMMON bước 4
--     xmlrpc_ua_reject / wp_login_notc_repeat / expensive_filter_ban  thoát sớm
-- Với chúng cả bốn trường VĨNH VIỄN = 0 (mặc định từ core/ctx/init.lua), nên
-- điều kiện "block + có bằng chứng" bên dưới KHÔNG BAO GIỜ đúng ⇒ chúng rơi
-- hết xuống nhánh cuối `watch`.
--
-- Đo 2026-08-10 trên cloud28-246: trong 59.708 lượt block, **58.765 = 98,4%**
-- đi đường khoá-ở-cửa; chỉ 921 lượt (1,5%) qua đường chấm điểm — đường DUY
-- NHẤT sinh ra bằng chứng. Hệ quả là hai ô bị đảo vai:
--   `watch` chứa phần lớn kẻ ĐÃ bị kết án  ⇒ block% > 65%
--   `bot`   chứa phần lớn kẻ MỚI bị nghi (crawler trượt verify, bot_score cao
--           nhưng tổng điểm chưa tới ngưỡng ⇒ vẫn allow) ⇒ block% chỉ 14%
--
-- `action_reason` BẮT BUỘC được đặt trước mọi `ngx.exit` (quy tắc của repo),
-- nên ở tầng log nó là bằng chứng đáng tin nhất còn dùng được.
--
-- Nguyên tắc chọn: CHỈ nhận những lý do là KẾT ÁN dựa trên bằng chứng đã thu,
-- không nhận biện pháp phòng ngừa.
local REASON_BOT = {
    banned_ip            = true,  -- lệnh cấm tồn tại VÌ bằng chứng ở lượt trước
    banned_id            = true,
    xmlrpc_ua_reject     = true,  -- chữ ký UA, không phải suy đoán
    wp_login_notc_repeat = true,  -- POST login lặp không cookie = dò mật khẩu
    expensive_filter_ban = true,  -- ≥20 tổ hợp filter/IP: crawler bất khả chối
}
-- CỐ Ý KHÔNG có mặt ở bảng trên:
--   `banned_id_shared_challenge` — chính nhánh đó tồn tại vì `ctx.identity` gộp
--       cả văn phòng về một hash, tức người bị khớp có thể VÔ TỘI. Gán `bot`
--       sẽ sai đúng ca mà nhánh này sinh ra để bảo vệ.
--   `ip_farm_suspect` / `expensive_filter` — phòng ngừa (challenge / 429 theo
--       tài nguyên), có thể trúng người thật. Để `watch` là đúng nghĩa.

-- Crawler tự khai VÀ chứng minh được danh tính. "goodbot" ở đây nghĩa là
-- **đã định danh được**, không phải "có ích" — Ahrefs/SemRush/DataForSEO vẫn
-- vào ô này. Trước đây chúng rơi vào `human`: S2.5 cố ý đặt `bot_score = 0`
-- nên hàm này không còn tín hiệu nào, mà chúng thì `action=allow`.
local REASON_GOODBOT = {
    good_bot_verified      = true,
    good_bot_asn_verified  = true,
    good_bot_asn_lite      = true,
    contact_ptr_match      = true,
    contact_org_match      = true,
    contact_cloud_attested = true,
    analyzer_attested      = true,
    s25_cap_monitor        = true,
}

local function classify_intent(ctx)
    local reason = ctx.action_reason or ""

    -- Good bot: đã DNS verify
    if ctx.good_bot_verified == true then
        return "goodbot"
    end
    if REASON_GOODBOT[reason] then return "goodbot" end
    -- Nguồn thứ hai cho cùng kết luận: reason có thể bị action khác ghi đè
    -- (vd bot S2.5 sau đó chạm trần tốc độ), cờ tier thì không.
    if ctx.bot_identity_tier == "S2.5" then return "goodbot" end
    -- `good_bot_rate_<lớp>` (engine.lua:180) — bot ĐÃ xác minh bị chặn tốc độ.
    -- Khớp tiền tố vì tên lớp polite/moderate/aggressive/default nằm ở đuôi.
    if reason:sub(1, 14) == "good_bot_rate_" then return "goodbot" end

    if REASON_BOT[reason] then return "bot" end
    -- `fleet_dyn_block_24:<cidr>` / `_16:<cidr>` — CIDR ở đuôi nên khớp tiền tố.
    if reason:sub(1, 16) == "fleet_dyn_block_" then return "bot" end

    local action    = ctx.action    or "allow"
    local bot_score = ctx.bot_score or 0.0
    local ua_flag   = ctx.ua_flag   or 0.0
    local ip_rep    = ctx.ip_rep    or 0.0
    local ip_risk   = ctx.ip_risk   or 0.0

    -- Bot: action đã kết luận là xấu + có bot evidence
    -- action là output của toàn bộ scoring pipeline — đây là signal đáng tin nhất
    if (action == "block" or action == "challenge") then
        if bot_score >= 0.3
        or ua_flag >= 0.5
        or ip_rep > 0
        or ip_risk >= 0.4 then
            return "bot"
        end
    end

    -- Bot: score rõ ràng ngay cả khi action=monitor
    if bot_score >= 0.6 or ua_flag >= 0.7 or ip_risk >= 0.7 then
        return "bot"
    end

    -- UA TỰ KHAI là máy thì không thể là "human". `device_classifier` đặt
    -- `crawler` khi UA có token bot/spider/crawler hoặc URL liên hệ `(+http`,
    -- và `http_client` khi UA thiếu cả `Mozilla/` lẫn engine token (curl,
    -- python-requests, Go-http, okhttp…). Cả hai là khai báo cấu trúc, không
    -- phải suy đoán.
    --
    -- Trước bản vá này chúng rơi xuống nhánh `allow` bên dưới — nhánh đó chỉ
    -- kiểm "không tìm thấy bằng chứng xấu", mà KHÔNG-CÓ-BẰNG-CHỨNG thì không
    -- phải BẰNG-CHỨNG-LÀ-NGƯỜI. Kết quả: dòng Crawler và Tool ở tab Devices
    -- hiện phần lớn là "Human" — đúng phép tính, sai kết luận.
    --
    -- Trả `watch` chứ không phải `bot`: một crawler tự khai mà không nằm
    -- trong registry và không attest được (không PTR, không contact URL) thì
    -- mới chỉ là CHƯA ĐỊNH DANH ĐƯỢC, chưa có gì nói nó có hại. Mọi crawler
    -- đã định danh đều đã thoát ở nhóm goodbot phía trên; mọi crawler có bằng
    -- chứng xấu đã thoát ở nhánh điểm số phía trên.
    local dt = ctx.device_type
    if dt == "crawler" or dt == "http_client" then
        return "watch"
    end

    -- Human: verified PoW
    if ctx.verified == true then
        return "human"
    end

    -- Human: action=allow → hệ thống không tìm thấy gì đáng ngờ
    -- Benefit of the doubt: nếu không có bot evidence thì là người thật
    if action == "allow" then
        if bot_score < 0.2 and ua_flag < 0.3 and ip_risk < 0.3 then
            return "human"
        end
    end

    -- Watch: CHƯA KẾT LUẬN ĐƯỢC — monitor, hoặc allow kèm tín hiệu nhẹ, hoặc
    -- các biện pháp phòng ngừa (ip_farm_suspect, expensive_filter,
    -- banned_id_shared_challenge) vốn có thể trúng người thật.
    --
    -- Sau bản vá này `watch` KHÔNG còn là sọt đựng mọi thứ: 98,4% lệnh chặn
    -- từng rơi vào đây giờ đã về đúng ô `bot`.
    --
    -- Còn một chỗ chưa chỉnh, ghi lại để khỏi quên: request trên IP đã
    -- whitelist (`ip_whitelist`, 11.771 lượt/9h trên 246) có mọi trường bằng
    -- chứng = 0 nên vào ô `human`, kể cả khi đó là máy (vd cron WordPress tự
    -- gọi mình). Whitelist là quyết định KHÔNG phán xét của người vận hành,
    -- nên để nguyên; chỉ cần biết ô `human` có lẫn phần này.
    return "watch"
end

local function write_stats(premature, host, class, action, date, device_type, intent, ua, beacon_got)
    if premature then return end
    local ok, pool = pcall(require, "antibot.core.redis_pool")
    if not ok then return end
    local red, err = pool.get()
    if not red then return end

    local ttl_7d = 86400 * 7
    local dg = DEVICE_GROUP[device_type or ""] or "unknown"

    red:init_pipeline()

    red:incr("stat:" .. host .. ":req:" .. date)
    red:expire("stat:" .. host .. ":req:" .. date, ttl_7d)

    -- Chỉ mục domain của ngày. Có nó thì dashboard đọc bảng Domain bằng MGET
    -- ĐÚNG các khoá cần, thay vì SCAN `stat:*:<ngày>` rồi bị cắt ở `limit`.
    -- SCAN cắt theo thứ tự bucket nên phần mất là tuỳ ý: một domain còn `req`
    -- mà mất `allow` ⇒ dashboard hiện Total=21.297 / Clean=0. Mỗi domain sinh
    -- ~50-60 khoá stat mỗi ngày (req + action + class_action + dev_* +
    -- intent_* + ibd_*), nên vài chục domain là đã vượt trần.
    -- SADD idempotent, tập chỉ vài chục phần tử — rẻ hơn hẳn cái nó thay thế.
    red:sadd("stat:hosts:" .. date, host)
    red:expire("stat:hosts:" .. date, ttl_7d)

    red:incr("stat:" .. host .. ":" .. action .. ":" .. date)
    red:expire("stat:" .. host .. ":" .. action .. ":" .. date, ttl_7d)

    red:incr("stat:" .. host .. ":" .. class .. "_" .. action .. ":" .. date)
    red:expire("stat:" .. host .. ":" .. class .. "_" .. action .. ":" .. date, ttl_7d)

    -- Device group stats
    red:incr("stat:" .. host .. ":dev_" .. dg .. ":" .. date)
    red:expire("stat:" .. host .. ":dev_" .. dg .. ":" .. date, ttl_7d)

    -- Đếm MỌI action khác `allow`, không chỉ block/challenge. Trước đây chỉ có
    -- hai cái đó nên dashboard buộc phải suy ra phần còn lại bằng phép trừ
    -- `total - block - challenge` rồi gọi nó là "Cho qua" — mà hiệu đó gộp cả
    -- `monitor` lẫn `throttled` (429). Nói cách khác cột ấy KHÔNG phải traffic
    -- sạch, và không thể đổi tên thành "Clean" chừng nào chưa tách hai action
    -- này ra. Điều kiện `~= "allow"` để action mới trong tương lai tự có ô.
    if action ~= "allow" then
        red:incr("stat:" .. host .. ":dev_" .. dg .. "_" .. action .. ":" .. date)
        red:expire("stat:" .. host .. ":dev_" .. dg .. "_" .. action .. ":" .. date, ttl_7d)
    end

    -- Intent stats: human vs goodbot vs bot vs watch
    local ig = intent or "watch"
    red:incr("stat:" .. host .. ":intent_" .. ig .. ":" .. date)
    red:expire("stat:" .. host .. ":intent_" .. ig .. ":" .. date, ttl_7d)

    if action ~= "allow" then   -- cùng lý do như dev_ ở trên
        red:incr("stat:" .. host .. ":intent_" .. ig .. "_" .. action .. ":" .. date)
        red:expire("stat:" .. host .. ":intent_" .. ig .. "_" .. action .. ":" .. date, ttl_7d)
    end

    -- Intent per device group: biết desktop có bao nhiêu bot vs người thật
    local ibd_key = "stat:" .. host .. ":ibd_" .. dg .. "_" .. ig .. ":" .. date
    red:incr(ibd_key)
    red:expire(ibd_key, ttl_7d)

    -- Beacon coverage telemetry (Step 0 — baseline cho canvas/webgl signal upgrade).
    -- Nil = không phải HTML-eligible request → không count.
    -- false = HTML-eligible nhưng beacon chưa về (first visit / inject blocked / JS off).
    -- true  = HTML-eligible và có beacon data sẵn trong Redis (canvas/webgl analyzable).
    -- Coverage = beacon_got / beacon_elig; thấp → cần fix inject trước khi tăng weight.
    if beacon_got ~= nil then
        local elig_key = "stat:" .. host .. ":beacon_elig:" .. date
        red:incr(elig_key)
        red:expire(elig_key, ttl_7d)
        if beacon_got then
            local got_key = "stat:" .. host .. ":beacon_got:" .. date
            red:incr(got_key)
            red:expire(got_key, ttl_7d)
        end
    end

    -- Sample UA cho unknown device: lưu tối đa 20 UA gần nhất để admin debug.
    -- `ua` TRƯỚC ĐÂY KHÔNG PHẢI THAM SỐ của hàm này — nó là biến toàn cục chưa
    -- khai báo ⇒ luôn nil ⇒ điều kiện luôn sai ⇒ bảng "Unknown Client — UA
    -- Samples" chưa từng có một dòng nào. Nay truyền `ctx.ua` xuống đây.
    if device_type == "unknown" and ua and ua ~= "" then
        local sample_key = "stat:ua_unknown_sample"
        red:lpush(sample_key, ua:sub(1, 120))
        red:ltrim(sample_key, 0, 19)
        red:expire(sample_key, 86400)
    end

    red:commit_pipeline()
    pool.put(red)
end

-- Write one log line to dedicated antibot log file.
-- Called from log_by_lua_block — response is already sent,
-- blocking I/O here does not affect latency seen by the client.
local function write_log_line(line)
    local fh, err = io.open(LOG_FILE, "a")
    if not fh then
        -- Fallback to nginx error log only on open failure (permission, missing dir)
        ngx.log(ngx.WARN, "[antibot] cannot open log file: ", tostring(err))
        return
    end
    fh:write(line, "\n")
    fh:close()
end

function _M.run(ctx)
    if not ctx then return end

    local top_str = ""
    if ctx.top_signals then
        local parts = {}
        for _, s in ipairs(ctx.top_signals) do
            parts[#parts+1] = string.format("%s=%d%%",
                s.signal or "?", s.contribution_pct or 0)
        end
        top_str = table.concat(parts, ",")
    end

    local host  = (ctx.req and ctx.req.host) or ngx.var.host or "unknown"
    local class = ctx.req_class or "unknown"

    -- UA truncate để grep debug (googlebot, bingbot, facebook, ...).
    -- Nếu UA chứa space/= sẽ vỡ format parser → thay bằng _.
    -- `or "-"` CHỈ bắt `nil`, mà `ctx.ua` khi thiếu header là chuỗi RỖNG (xem
    -- core/ctx/init.lua). Hệ quả: trường ghi ra là ` ua= ` trống — và mọi lệnh
    -- `grep -oP ' ua=\K\S+'` lặng lẽ bỏ qua nó vì `\S+` không khớp được dấu
    -- cách. Đúng cái bẫy đó đã làm phép kiểm "UA rỗng" ngày 2026-08-20 trượt
    -- 100%: nó tìm `-` trong khi thực tế là `""`. Chuẩn hoá cả hai về `-`.
    local ua_raw = ctx.ua
    if ua_raw == nil or ua_raw == "" then ua_raw = "-" end
    local ua_log = ua_raw:sub(1, 120):gsub("[%s\"]", "_")

    -- ── Nhóm thiết bị + hai header khảo sát ──────────────────────────────
    -- `device_classifier` là bước 10 của STEPS_COMMON (init.lua:64), nên KHÔNG
    -- phải request nào cũng đi qua nó: cookie fast-path (init.lua:153) return
    -- TRƯỚC cả STEPS_COMMON, còn fleet_check_block (bước 5) và ip_ban_check
    -- (bước 8) ngx.exit sớm hơn. Cả hai để `ctx.device_type = nil`. Gộp chúng
    -- vào "unknown" là trộn ba dân số khác hẳn nhau — người thật đã giải PoW,
    -- lệnh chặn ở cửa, và UA lạ thật sự — nên tách bằng hai nhãn riêng.
    -- Suy ra MỘT LẦN ở đây rồi dùng lại cho cả dòng log lẫn phần thống kê.
    local dev_log = ctx.device_type
    if dev_log == nil or dev_log == "" then
        dev_log = ctx.verified and "verified_fastpath" or "gate_exit"
    elseif dev_log == "unknown" and (ctx.ua == nil or ctx.ua == "") then
        -- `device_classifier.classify` trả "unknown" ngay ở nhánh ĐẦU TIÊN khi
        -- không có UA — cùng một nhãn với "UA có dáng browser mà không khớp
        -- rule nào", dù hai thứ chẳng liên quan gì nhau. Tách ở đây chứ không
        -- trong classify: `device_type` là đầu vào của `header_anomaly`, đổi
        -- giá trị ở đó là đổi hành vi chấm điểm. Ở đây thì thuần nhãn.
        dev_log = "no_ua"
    end

    -- `sf` / `chm` — BƯỚC 1 của khảo sát WebView (2026-08-17), CHỈ ĐO, không
    -- đụng chấm điểm.
    --
    -- Đo được trên 34.141 UA phân biệt: nhóm `custom_tab` chiếm 8,3% lưu lượng,
    -- và 27.661/27.669 = **99,97%** trong đó là WebView Chromium hiện đại
    -- (`wv` + `Chrome/`). Nhưng `device_classifier` cấp cho CẢ nhóm
    -- `sec_fetch_expected = false` + `ch_ua_mobile_expected = false` — sự miễn
    -- trừ vốn viết cho trình duyệt AOSP đời cũ, mà nhánh đó đo được đúng
    -- **8 request** (Android 2.2 / 2.3.7 / 4.4.2).
    --
    -- "WebView Chromium thì phải gửi Sec-Fetch" là suy luận TỪ KIẾN TRÚC, chưa
    -- phải đo đạc. Rủi ro không đối xứng: bật kỳ vọng nhầm thì 8,3% lưu lượng
    -- người thật ăn thêm 0,30 điểm mỗi request (header_anomaly:49). Nên đo
    -- trước. `chm` rủi ro hơn `sf`: Sec-Fetch-* nằm ở network stack của
    -- Chromium, còn UA client hints thì WebView từng không gửi nhiều phiên bản.
    --
    -- Đọc thẳng `ngx.var`: log phase luôn có, không phụ thuộc `ctx.req` (request
    -- thoát ở cookie fast-path không có `ctx.req` đầy đủ). Cùng ba header mà
    -- `header_anomaly:120-124` dùng, để hai bên không lệch định nghĩa.
    local sf_log = (((ngx.var.http_sec_fetch_mode or "") ~= "")
                 or ((ngx.var.http_sec_fetch_site or "") ~= "")
                 or ((ngx.var.http_sec_fetch_dest or "") ~= "")) and 1 or 0
    local chm_log = ((ngx.var.http_sec_ch_ua_mobile or "") ~= "") and 1 or 0

    -- Throttle decision details — chỉ append cho action=throttled để tránh
    -- bloat log line cho các request bình thường. trigger ∈ {hard_qs_len,
    -- hard_param_count, soft_score}; exp_score là weighted sum 0..1.45.
    local throttle_str = ""
    if ctx.action == "throttled" then
        throttle_str = string.format(
            " trigger=%s exp_score=%.2f",
            tostring(ctx.expensive_trigger or "-"),
            ctx.expensive_score or 0)
    end

    -- Good-bot rate fields — ALWAYS append for good_bot_verified requests
    -- (not just on throttle) so operator có thể audit "đến lúc nào bot bị
    -- siết". `bot=` = good_bot_name từ verification, `base_class` = static
    -- assignment trong cfg.rate.good_bot_rate.map, `eff_class` = effective
    -- class sau adaptive promotion, `agg` = aggression score (sliding 10
    -- min), `rpm` = count/limit cho phút hiện tại.
    --
    -- Khi base_class != eff_class -> grep nhanh case bot bị auto-promote:
    --   grep -E 'base_class=moderate eff_class=aggressive' antibot.log
    --
    -- Khi action=throttled với reason=good_bot_rate_<class> -> rate ceiling hit.
    local gbrate_str = ""
    if ctx.good_bot_class then
        gbrate_str = string.format(
            " bot=%s base_class=%s eff_class=%s agg=%d rpm=%d/%d",
            tostring(ctx.good_bot_name or "-"),
            tostring(ctx.good_bot_class_base or "-"),
            tostring(ctx.good_bot_class or "-"),
            ctx.good_bot_aggression or 0,
            ctx.good_bot_rate_count or 0,
            ctx.good_bot_rate_limit or 0)
    end

    -- S2.5 tier details — chỉ append khi attest path fired.
    -- Lets `grep tier=S2.5 antibot.log` audit attest decisions.
    -- marker= present only for analyzer_attested (Path 2).
    local tier_str = ""
    if ctx.bot_identity_tier then
        tier_str = " tier=" .. ctx.bot_identity_tier
        if ctx.analyzer_marker then
            tier_str = tier_str .. " marker=" .. ctx.analyzer_marker
        end
    end

    -- Auth-endpoint provenance (bước 1 measurement — đánh giá bỏ AUTH_LEGACY_PATHS).
    -- Chỉ append cho class=auth_endpoint. prov ∈ generic|generic+legacy|legacy_only|body.
    -- legacy_only = tập CHỈ path-list bắt được → nếu bỏ list sẽ mất case này.
    --   grep 'auth_prov=' antibot.log | grep -oP 'auth_prov=\S+' | sort | uniq -c
    --   grep 'auth_prov=legacy_only' antibot.log | grep -oP 'auth_legacy=\S+' | sort | uniq -c
    local auth_str = ""
    if ctx.auth_prov then
        auth_str = " auth_prov=" .. ctx.auth_prov
        if ctx.auth_legacy then
            auth_str = auth_str .. " auth_legacy=" .. ctx.auth_legacy
        end
    end

    -- Shared-session-key telemetry. sclients = distinct cookie-set cùng dùng
    -- sess:<fp_light>; sshared=true → session_flag+graph_flag đã bị bỏ qua.
    -- Hiệu chỉnh cfg.session_shared.clients_min:
    --   grep -oP 'sclients=\d+' antibot.log | sort | uniq -c
    local sc_str = ""
    if ctx.sess_clients then
        sc_str = string.format(" sclients=%d sshared=%s",
            ctx.sess_clients, tostring(ctx.sess_shared or false))
    end

    -- Expensive faceted-filter guard telemetry (l7/expensive_filter_guard.lua).
    -- Chỉ append cho request bị coi là faceted-filter tốn kém. combos = distinct
    -- tổ hợp/base/window (metric người-vs-crawler); over = đã vượt combos_threshold.
    -- Shadow calibration: grep antibot.log — correlate với richness/class/ip sẵn có:
    --   grep 'xf_base=' antibot.log | grep -oP 'xf_base=\S+ xf_combos=\d+' | sort | uniq -c
    local xf_str = ""
    if ctx.xf_expensive then
        xf_str = string.format(" xf_base=%s xf_combos=%d xf_ipcombos=%d xf_hits=%d xf_over=%s",
            tostring(ctx.xf_base or "-"),
            ctx.xf_combos or 0,
            ctx.xf_ipcombos or 0,
            ctx.xf_hits or 0,
            tostring(ctx.xf_over or false))
    end

    -- mismatch telemetry (intelligence/correlation/consistency_check.lua).
    -- mm     = danh sách NHÁNH đã bắn; mm_raw = tổng TRƯỚC khi chặn trần 1.0
    -- (mm_raw > 1.0 = bão hoà, mismatch phẳng 55 điểm, mất khả năng phân biệt);
    -- h2bc   = h2_bot_confidence, ghi kèm để đo DOUBLE-COUNT: hai signal cùng
    --          weight 55 và cùng bắn trên h2_bot_pattern / h2_tls_mismatch.
    -- Hiệu chỉnh:
    --   grep -oP 'mm=\K\S+' antibot.log | tr ',' '\n' | sort | uniq -c | sort -rn
    --   grep -oP 'mm=\S*tls12\S*' antibot.log | wc -l     # nhánh mới sống
    --   grep 'mm=' antibot.log | grep -oP 'h2bc=\K\S+' | sort | uniq -c
    local mm_str = ""
    if ctx.mm_rules and ctx.mm_rules ~= "" then
        mm_str = string.format(" mm=%s mm_raw=%.2f h2bc=%.2f",
            ctx.mm_rules,
            ctx.mm_raw or 0,
            ctx.h2_bot_confidence or 0)
    end

    -- Beacon coverage state (Step 0 telemetry).
    -- skip = không phải HTML-eligible (resource/api/auth) — beacon không áp dụng
    -- 1    = HTML eligible + có beacon data (canvas/webgl signal khả dụng)
    -- 0    = HTML eligible nhưng beacon chưa về (first visit / JS blocked / CSP fail)
    local beacon_state = "skip"
    if ctx.inject_candidate then
        beacon_state = ctx.beacon_received and "1" or "0"
    end

    -- Build structured log line — all fields on one line, space-separated key=value.
    -- richness ∈ [0,1] = ctx.session_richness, trust proxy (cookie payload +
    -- auth header). Log mỗi request để debug/audit; volume control qua daily
    -- rotate. grep richness=0\\.[89] antibot.log → tìm logged-in user, grep
    -- richness=0\\.0 → first-visit/bot pattern.
    local line = string.format(
        "[%s] [antibot] ts=%d domain=%s class=%s id=%s" ..
        " ip=%s ua=%s tls13=%s h2=%s ja3=%s ja3p=%s" ..
        " score=%.1f eff=%.1f mult=%s action=%s beacon=%s richness=%.2f inapp=%.2f" ..
        " dev=%s sf=%d chm=%d" ..
        " top=%s reason=%s%s%s%s%s%s%s%s",
        os.date("%Y-%m-%d %H:%M:%S"),
        ngx.time(),
        host,
        class,
        tostring(ctx.identity or ctx.fp_light or "-"),
        tostring(ctx.ip or "-"),
        ua_log,
        tostring(ctx.tls13),
        tostring(ctx.h2_is_h2),
        tostring(ctx.ja3 or "-"),
        tostring(ctx.ja3_partial or false),
        ctx.score or 0,
        ctx.effective_score or 0,
        tostring(ctx.score_multiplier or 1.0),
        tostring(ctx.action or "-"),
        beacon_state,
        ctx.session_richness or 0,
        ctx.inapp_likeness or 0,
        dev_log,
        sf_log,
        chm_log,
        top_str,
        tostring(ctx.action_reason or "-"),
        throttle_str,
        tier_str,
        gbrate_str,
        auth_str,
        xf_str,
        sc_str,
        mm_str
    )

    write_log_line(line)

    -- Escalated events also go to nginx error log for visibility
    if ctx.action == "block" or ctx.action == "challenge" then
        ngx.log(ngx.WARN,
            "[antibot] ", ctx.action,
            " ip=", tostring(ctx.ip or "-"),
            " score=", string.format("%.1f", ctx.score or 0),
            " domain=", host,
            " top=", top_str)
    end

    -- Chỉ skip stats cho "infrastructure" whitelist (wp-cron LAN, bypass
    -- resource, admin IP/URL config, antibot endpoints). Các reason verified
    -- (cookie/device/earlyid) là human thật → vẫn count vào Clean để dashboard
    -- phản ánh đúng human traffic, không chỉ riêng fresh-visit pass detection.
    local SKIP_STATS_REASONS = {
        antibot_internal = true,
        lan_internal     = true,
        ip_whitelist     = true,
        url_whitelist    = true,
        bypass_path      = true,
    }
    if ctx.whitelisted and SKIP_STATS_REASONS[ctx.action_reason or ""] then
        return
    end

    local action = ctx.action or "allow"
    local date   = os.date("%Y%m%d")

    -- Dùng lại `dev_log` đã suy ra ở đầu hàm — MỘT nơi định nghĩa cho cả dòng
    -- log lẫn counter, để hai bên không bao giờ lệch nhau. Lý do phải tách
    -- `verified_fastpath`/`gate_exit` khỏi `unknown` ghi ở đó.
    -- (Chính vì trước đây gộp mà người đọc thấy "đã Unknown rồi mà vẫn flag ra
    -- badbot": phần badbot ấy là 40.623 `banned_ip` + 1.369 `fleet_dyn_block`
    -- đo 2026-08-10 trên cloud28-246 — chúng thoát trước device_classifier.)
    local device_type = dev_log
    local intent      = classify_intent(ctx)

    -- beacon_got = nil cho non-HTML request (skip counter), bool cho HTML-eligible.
    local beacon_got
    if ctx.inject_candidate then
        beacon_got = ctx.beacon_received == true
    end

    -- `ua` đặt TRƯỚC `beacon_got` vì beacon_got có thể nil (non-HTML request);
    -- giữ tham số nil ở vị trí cuối cùng để không có nil ở giữa danh sách.
    local ok, err = ngx.timer.at(0, write_stats, host, class, action, date,
                                 device_type, intent, ctx.ua or "", beacon_got)
    if not ok then
        ngx.log(ngx.DEBUG, "[logger] timer.at failed: ", tostring(err))
    end

    -- Track sess_res cho resource request trong logger (async).
    -- session_store chỉ chạy trong STEPS_FULL_DETECTION (navigation) —
    -- resource request chạy STEPS_RESOURCE không có detection_layer →
    -- sess_res không bao giờ được incr trong session_store →
    -- resource_ratio = 0 → resource_starved false positive với mọi user thật.
    -- Fix: incr sess_res ở đây cho resource class, dùng fp_light làm key.
    if class == "resource" then
        local fp = ctx.fp_light or ctx.identity
        if fp and fp ~= "" and fp ~= "-" then
            local res_key = "sess_res:" .. fp
            local ok2, err2 = ngx.timer.at(0, function(premature)
                if premature then return end
                local ok3, pool2 = pcall(require, "antibot.core.redis_pool")
                if not ok3 then return end
                local red2, _ = pool2.get()
                if not red2 then return end
                red2:incr(res_key)
                red2:expire(res_key, 300)
                pool2.put(red2)
            end)
            if not ok2 then
                ngx.log(ngx.DEBUG, "[logger] sess_res timer failed: ", tostring(err2))
            end
        end
    end
end

return _M
