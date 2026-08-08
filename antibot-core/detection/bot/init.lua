local _M        = {}
local ua_check  = require "antibot.detection.bot.ua_check"
local dns_rev   = require "antibot.detection.bot.dns_reverse"
local dns_fwd   = require "antibot.detection.bot.dns_forward"
local bot_score = require "antibot.detection.bot.bot_score"
local cloud_sx  = require "antibot.detection.bot.cloud_suffixes"
local pool      = require "antibot.core.redis_pool"

local CLOUD_PTR_SUFFIXES = cloud_sx.CLOUD_PTR_SUFFIXES

-- Phán quyết "UA khai good bot nhưng xác minh TRƯỢT" — đọc bởi
-- l7/ban/ban_store.lua để thôi defer lệnh cấm. GIỮ ĐỒNG BỘ tiền tố hai file.
-- TTL ngắn có chủ đích: khoá ban seal ở l7 nên module này không chạy nữa →
-- phán quyết không được làm mới → sau 30 phút tự hết hạn và bot được xác minh
-- lại. Bot dựng đúng PTR/A tự thoát, không cần thao tác tay.
local FAKE_VERDICT_PREFIX = "botverdict:fake:"
local FAKE_VERDICT_TTL    = 1800

-- Dấu "IP này là crawler đã chứng minh danh tính" — đọc bởi
-- detection/fleet/check_block.lua và fleet/aggregator.lua. GIỮ ĐỒNG BỘ tiền tố
-- với check_block.lua.
--
-- Vì sao cần: fleet chạy ở STEPS_COMMON, TRƯỚC toàn bộ tầng xác minh, và chặn
-- bằng ngx.exit(444) (RST ở tầng TCP). Crawler hợp lệ phân tán trên nhiều IP
-- trông giống hệt một đội cào về mặt cấu trúc nên bị gắn cờ /24, rồi chết ở cửa
-- trước khi kịp chứng minh mình là ai. Đo 2026-08-08 trên cloud168-101:
-- 20.042 lượt Baiduspider THẬT bị RST mỗi ngày (PTR baiduspider-*.crawl.baidu.com,
-- xác nhận xuôi khớp) = 25% tổng số lệnh chặn của máy.
--
-- ASN KHÔNG dùng được cho lớp bài toán này: dải 116.179.0.0/16 của Baidu thuộc
-- AS4837 (China Unicom Backbone) — ASN dùng chung lớn nhất nhì thế giới. Mở cổng
-- theo ASN đó tương đương miễn trừ fleet cho mọi máy thuê ở Trung Quốc chỉ cần
-- gắn chữ "spider" vào UA. Bằng chứng dùng được của Baidu nằm ở DNS hai chiều,
-- không nằm ở quyền sở hữu IP.
--
-- CHỈ cấp cho bằng chứng GẮN VỚI TÊN MIỀN của chính chủ:
--   good_bot_verified (S4/S3 registry) | contact_ptr_match | contact_org_match
-- KHÔNG cấp cho contact_cloud_attested / analyzer_attested — hai đường đó chỉ
-- chứng minh "có thuê máy ở cloud", mà "nhiều IP thuê ở cloud" đúng là thứ fleet
-- sinh ra để bắt. Cấp dấu cho chúng là tự tháo chốt.
local CRAWLER_PREFIX = "crawler:"
local CRAWLER_TTL    = 3600

-- Suffix-match helper: ptr ends with "." .. host, or equals host (case-insensitive).
-- Used by Path 1 (contact attest) and Path 2 (analyzer attest).
local function ptr_suffix_matches(ptr, host)
    if not ptr or not host or ptr == "" or host == "" then return false end
    local p = ptr:lower():gsub("%.+$", "")
    local h = host:lower()
    if p == h then return true end
    return p:sub(-(#h + 1)) == "." .. h
end

-- ── Path 1c helper: cùng tổ chức, KHÁC TLD ───────────────────────────────
-- Nhãn đăng ký "chung" KHÔNG được dùng làm căn cứ khớp. Nếu bot_contact_host
-- là eTLD+1 nhiều thành phần (`example.com.vn`) thì nhãn trích ra sẽ là `com`,
-- và khớp theo nó sẽ trúng gần như mọi PTR trên đời.
local GENERIC_LABELS = {
    ["com"] = true, ["net"] = true, ["org"] = true, ["edu"] = true,
    ["gov"] = true, ["mil"] = true, ["int"] = true, ["co"]  = true,
    ["ne"]  = true, ["or"]  = true, ["ac"]  = true, ["go"]  = true,
    ["web"] = true, ["info"] = true, ["biz"] = true,
}
local MIN_LABEL_LEN = 4   -- thương hiệu 3 ký tự (ovh, bbc) không đi đường này

local function split_labels(host)
    local h = host:lower():gsub("%.+$", "")
    local t = {}
    for part in h:gmatch("[^%.]+") do t[#t + 1] = part end
    return t
end

local function org_label(host)
    local p = split_labels(host)
    if #p < 2 then return nil end
    local label = p[#p - 1]
    if #label < MIN_LABEL_LEN or GENERIC_LABELS[label] then return nil end
    return label
end

-- Nhãn đăng ký của PTR trùng nhãn của contact host, HOẶC TLD của PTR chính là
-- nhãn đó (brand gTLD — `.amazon` do chính Amazon sở hữu).
local function ptr_matches_org(ptr, contact_host)
    if not ptr or not contact_host then return false end
    local label = org_label(contact_host)
    if not label then return false end
    local p = split_labels(ptr)
    if #p < 2 then return false end
    return p[#p - 1] == label or p[#p] == label
end

-- Cloud-provider PTR check (Path 2): ptr ends in one of the hardcoded
-- CLOUD_PTR_SUFFIXES. PTR is set by IP block owner — not spoofable.
local function ptr_matches_cloud(ptr)
    if not ptr or ptr == "" then return false end
    local p = ptr:lower():gsub("%.+$", "")
    for _, suffix in ipairs(CLOUD_PTR_SUFFIXES) do
        local s = suffix:lower()
        if p == s or p:sub(-(#s + 1)) == "." .. s then
            return true
        end
    end
    return false
end

-- Path 1 — contact attest (S2.5). Two sub-paths:
--
--   1a (strong) — PTR suffix matches contact URL eTLD+1.
--      Example: UA `(Pinterestbot/1.0; +http://www.pinterest.com/bot.html)`
--               + PTR `crawl-54-236-1-11.pinterest.com` → match → S2.5
--               reason="contact_ptr_match".
--
--   1c (cùng tổ chức, khác TLD) — nhãn đăng ký của PTR trùng nhãn của contact
--      URL, hoặc TLD của PTR chính là nhãn đó.
--      Ví dụ: UA `(AhrefsBot/7.0; +http://ahrefs.com/robot/)` (nhãn `ahrefs`)
--             + PTR `proxy-ca017-san100.ahrefs.NET` → khớp → S2.5
--             reason="contact_org_match".
--      Mẫu hình "website .com, hạ tầng crawl .net" rất phổ biến; Amazon thì
--      dùng brand gTLD `.amazon` cho PTR còn `amazon.com` cho website.
--      **Không dùng xác nhận xuôi làm điều kiện** — đo 2026-08-06: PTR của
--      Ahrefs KHÔNG có bản ghi A nào, nên forward-confirm sẽ chặn đúng ca cần
--      cứu. Bù lại, việc này không làm S2.5 yếu đi so với 1a: hôm nay kẻ sở
--      hữu `evil.com` đã có thể đặt PTR `foo.evil.com` + UA `+http://evil.com`
--      là qua rồi; 1c chỉ mở thêm trường hợp cùng tổ chức khác đuôi. Nhãn
--      chung (`com`/`co`/`ne`…) và nhãn dưới 4 ký tự bị loại — xem GENERIC_LABELS.
--
--   1b (cloud fallback) — compliant UA + PTR ends in a known cloud provider
--      suffix. Operator runs from major cloud but does NOT setup their
--      domain's reverse DNS for cloud-rented IPs (very common — only Pinterest,
--      Google, Microsoft do the full PTR-on-AWS-pool work).
--      Example: UA `(pingbot/2.0; +http://www.pingdom.com/)` from AWS
--               + PTR `ec2-54-153-18-201.us-west-1.compute.amazonaws.com`
--               → contact URL host `pingdom.com` does NOT appear in PTR,
--               but PTR ends in `amazonaws.com` (cloud list) → S2.5
--               reason="contact_cloud_attested".
--
-- Threat model 1b: attacker needs domain (~$10) + cloud account (anti-abuse
-- friction) + matching compliant UA. Higher bar than UA-only residential spoof.
-- Cap monitor (engine.lua) still scores via anomaly/behavior — true bad actors
-- get caught by signals, not bypassed entirely.
--
-- Both sub-paths set tier S2.5, bot_score=0, skip cluster+graph. Do NOT set
-- good_bot_verified (engine still scores, caps action at monitor).
local function contact_attest(ctx)
    if not ctx.bot_ua_compliant then return false end
    if not ctx.bot_contact_host then return false end
    if not ctx.dns_rev then return false end

    local reason
    if ptr_suffix_matches(ctx.dns_rev, ctx.bot_contact_host) then
        reason = "contact_ptr_match"
    elseif ptr_matches_org(ctx.dns_rev, ctx.bot_contact_host) then
        reason = "contact_org_match"
    elseif ptr_matches_cloud(ctx.dns_rev) then
        reason = "contact_cloud_attested"
    else
        return false
    end

    ctx.bot_identity_tier = "S2.5"
    ctx.bot_score         = 0.0
    ctx.action_reason     = reason
    ctx.skip_layers       = ctx.skip_layers or {}
    ctx.skip_layers.cluster = true
    ctx.skip_layers.graph   = true

    ngx.log(ngx.INFO,
        "[bot] S2.5 ", reason,
        " bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?",
        " ptr=", ctx.dns_rev,
        " host=", ctx.bot_contact_host)
    return true
end

-- Path 2 — analyzer attest (S2.5).
-- Fires when UA is browser-pattern + has tool marker (Chrome-Lighthouse,
-- GTmetrix, ...) + IP PTR ends in a recognized cloud provider suffix.
-- Independent of good_bot_claimed — runs when UA does NOT trigger bot path
-- (i.e. PageSpeed, GTmetrix have browser UAs, no "bot" token).
local function analyzer_attest(ctx)
    if not ctx.browser_ua_pattern then return false end
    if not ctx.analyzer_marker then return false end

    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return false
    end

    -- PTR not yet looked up (good_bot path didn't run dns_rev).
    -- Use the exported cache-aware helper.
    local ptr = ctx.dns_rev
    if not ptr then
        ptr = dns_rev.lookup_ptr(ip)
        ctx.dns_rev = ptr  -- cache on ctx for downstream + logging
    end
    if not ptr then return false end
    if not ptr_matches_cloud(ptr) then return false end

    ctx.bot_identity_tier = "S2.5"
    ctx.action_reason     = "analyzer_attested"
    ctx.skip_layers       = ctx.skip_layers or {}
    ctx.skip_layers.cluster = true
    ctx.skip_layers.graph   = true

    ngx.log(ngx.INFO,
        "[bot] S2.5 analyzer_attested marker=", ctx.analyzer_marker,
        " ip=", ip,
        " ptr=", ptr)
    return true
end

-- ASN fallback verify: dùng khi PTR/A verification fail nhưng bot UA + ASN
-- owner thật khớp với registry → tin được. Sở hữu ASN từ RIR (RIPE/ARIN/APNIC)
-- yêu cầu pháp nhân + IP block delegation — attack difficulty tương đương
-- spoof PTR.
--
-- Áp dụng cho mọi bot có ctx.good_bot_asns (không gated vào ptr_only).
-- ptr_only chỉ điều khiển: có skip forward DNS hay không.
local function asn_fallback_verify(ctx)
    local expected = ctx.good_bot_asns
    if not expected or #expected == 0 then return false end
    local actual = ctx.asn and ctx.asn.asn_number
    if not actual then return false end
    for _, asn in ipairs(expected) do
        if asn == actual then
            ngx.log(ngx.INFO,
                "[bot] VERIFIED asn_fallback bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?", " asn=AS", actual)
            return true
        end
    end
    ngx.log(ngx.INFO,
        "[bot] asn_fallback miss bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?", " actual=AS", actual,
        " expected=AS", table.concat(expected, ",AS"))
    return false
end

function _M.run(ctx)
    ua_check.run(ctx)

    if ctx.good_bot_claimed then
        dns_rev.run(ctx)

        -- ── THANG BẰNG CHỨNG ĐƠN ĐIỆU ────────────────────────────────────
        -- Bất biến: thêm bằng chứng chỉ được phép NÂNG mức tin cậy, không bao
        -- giờ hạ. Cấu trúc cũ vi phạm điều đó — nó rẽ nhánh LOẠI TRỪ theo
        -- `dns_rev_valid`, nên PTR khớp registry mà forward trượt thì kết luận
        -- `fake_good_bot` NGAY, không bao giờ thử tới contact_attest.
        --
        -- Hệ quả phản trực giác đã trả giá thật (2026-08-06): thêm `ahrefsbot`
        -- vào registry làm Ahrefs bị đánh giá XẤU ĐI (0.9 thay vì S2.5), vì mục
        -- registry đẩy nó sang nhánh trên rồi chết ở đó — PTR của Ahrefs không
        -- có bản ghi A nào. Cung cấp thêm thông tin đúng lại cho kết quả tệ hơn.
        --
        -- Nay: mỗi bậc chỉ chạy khi bậc mạnh hơn CHƯA cho ra kết quả.
        -- Bậc 1 (mạnh nhất) — rDNS xác nhận hai chiều.
        if ctx.dns_rev_valid == true then
            dns_fwd.run(ctx)
        end

        -- Bậc 2/3 — chỉ khi bậc 1 chưa xác minh được.
        if ctx.good_bot_verified ~= true then
            if contact_attest(ctx) then
                -- bot_score=0 set inside; fall through to bot_score.run
                -- which honors tier S2.5 and keeps it at 0.
                ctx.bot_ua = "good_bot_contact_attested"
            elseif asn_fallback_verify(ctx) then
                -- Cho ptr_only bot (Meta family): fallback sang ASN verification.
                -- Reverse DNS không đáng tin với rotating pool / no-PTR IP blocks.
                ctx.good_bot_verified = true
                ctx.bot_score         = 0.0
                ctx.bot_ua            = "good_bot_asn_verified"
            elseif ctx.dns_rev_timeout or ctx.dns_fwd_timeout then
                -- Resolver không phản hồi = sự cố TẠM THỜI, không phải bằng
                -- chứng giả mạo. Không kết luận gì; bot_score.lua bảo toàn 0.
                ctx.bot_ua = "dns_timeout"
            else
                ctx.bot_ua            = "fake_good_bot"
                -- math.max: giữ 0.9 mà dns_fwd đã đặt (PTR khớp registry nhưng
                -- forward phản đối — đáng ngờ hơn 0.85 = "không có bằng chứng").
                ctx.bot_score         = math.max(ctx.bot_score or 0, 0.85)
                ctx.good_bot_verified = false
            end
        end
    else
        -- Path 2 (analyzer attest) — for browser-pattern UAs with a tool
        -- marker tail (Chrome-Lighthouse, GTmetrix, ...). These don't have
        -- a "bot" token in UA so they never enter the good_bot_claimed
        -- branch. PTR check against hardcoded cloud suffix list grants S2.5.
        if analyzer_attest(ctx) then
            ctx.bot_ua = "analyzer_attested"
        end
    end

    bot_score.run(ctx)

    -- Ghi dấu crawler cho tầng fleet (xem chú thích CRAWLER_PREFIX ở đầu file).
    -- Đặt SAU bot_score.run để action_reason của contact_attest đã ổn định.
    --
    -- `ctx.is_known_crawler ~= true` là chốt chặn ghi thừa: fleet/aggregator đã
    -- GET khoá này ở đầu request rồi, nên dấu còn hạn thì bỏ qua hẳn lệnh ghi.
    -- Không có chốt đó thì mỗi request crawler đã xác minh tốn một lệnh SET —
    -- đo 2026-08-08: ~68.000 lượt/ngày trên cloud168-101. Dấu hết hạn thì lượt
    -- kế tiếp tự ghi lại; lỡ một nhịp không hại gì vì lúc dấu lapse thì /24 gần
    -- như chắc chắn cũng đã hết cờ (chính nhờ việc thôi tính vào bucket).
    local r = ctx.action_reason
    if ctx.ip and ctx.ip ~= ""
       and ctx.is_known_crawler ~= true
       and (ctx.good_bot_verified == true
            or r == "contact_ptr_match"
            or r == "contact_org_match") then
        pool.safe_set(CRAWLER_PREFIX .. ctx.ip, "1", CRAWLER_TTL)
    end

    -- Ghi phán quyết xác minh cho tầng ban, CHỈ khi ban_store vừa defer một
    -- lệnh cấm đang tồn tại (ctx.ban_deferred_gb). Không có bước này thì
    -- `ban:<id>` của bot giả danh chưa từng được thi hành — xem chú thích dài
    -- ở l7/ban/ban_store.lua nhánh defer.
    -- Verified hoặc S2.5 attest ⇒ KHÔNG ghi, để lượt sau vẫn được defer.
    if ctx.ban_deferred_gb
       and ctx.good_bot_verified ~= true
       and ctx.bot_identity_tier ~= "S2.5" then
        local id = ctx.identity or ctx.fp_light
        if id and id ~= "" then
            pool.safe_set(FAKE_VERDICT_PREFIX .. id, "1", FAKE_VERDICT_TTL)
            ngx.log(ngx.ERR,
                "[bot] verify FAILED with ban present → seal id=", id:sub(1, 8),
                " bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?",
                " ttl=", FAKE_VERDICT_TTL, "s")
        end
    end

    return true, false
end

return _M
