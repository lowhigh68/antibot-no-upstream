local _M = {}

-- ── DOC MAT KHAU REDIS TU TEP, KHONG VIET VAO DAY ────────────────────
--
-- `secaudit.sh` do duoc 04-10: `core/config.lua` tenant DOC DUOC. Nen viet mat khau
-- thang vao tep nay la BIEN mot bi mat thanh mot bi mat ai cung doc — dung cai lo
-- ma Review 4 muc 4.3 chi ra. Mat khau nam o mot tep RIENG, chmod 600 root:root,
-- va tep do KHONG nam trong cay deploy nen `deploy.sh` khong ghi de len.
--
-- Khong co tep -> chuoi rong -> KHONG gui AUTH -> hanh vi y nguyen ban cu. Vi vay
-- bat o Redis TRUOC khi tao tep la hong, va tao tep truoc khi bat o Redis cung hong:
-- hai viec phai di cung nhau (xem thu tu lenh trong `waf/CLAUDE.md`).
--
-- `io.open` khong phai cosocket nen chay duoc o moi phase. Nhung CHU Y AI doc:
-- cay nay KHONG co `init_by_lua`, chi co `init_worker_by_lua_block`
-- (`nginx/nginx.conf:124`), tuc `config.lua` duoc `require` lan dau trong WORKER —
-- da ha quyen sang `user nginx`. Vi vay `/etc/antibot/redis.pass` phai de `nginx`
-- doc duoc (`640 root:nginx`), KHONG phai `600 root:root`: dat 600 thi worker doc
-- ra chuoi rong, khong gui AUTH, va MOI phep Redis that bai IM LANG.
-- `deploy.sh` buoc [9] kiem dung dieu nay.
local function doc_mat_khau()
    local p = os.getenv("ANTIBOT_REDIS_PASS_FILE") or "/etc/antibot/redis.pass"
    local f = io.open(p, "r")
    if not f then return "" end
    local s = f:read("*l") or ""
    f:close()
    -- Trim: tep tao bang `echo` co `\n`, va sua tay tu Windows co the co `\r`.
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

_M.redis = {
    host        = "127.0.0.1",
    port        = 6379,
    timeout_ms  = 200,
    pool_size   = 100,
    pool_idle_s = 30,
    db          = 0,
    -- Redis giu `verified:*`, whitelist, ban va khoa FIM, nen no la CONTROL PLANE:
    -- ai ghi duoc vao day thi tu cap cho minh ve di qua lop cham diem.
    --
    -- SAU noi phai khop khi bat mat khau (5 script + Lua nay):
    --   `requirepass` cua Redis
    --   /etc/antibot/redis.pass            <- Lua doc o day
    --   ANTIBOT_REDIS_PASS                 <- fim.sh, threat_feed_sync, measure,
    --                                         postdeploy, monitor_ip_sync
    -- Lech chieu nao cung lam MOI phep Redis that bai IM LANG (fail-open, khong
    -- phai cham). `secaudit.sh` muc 2 do lai ket qua that tu UID tenant.
    password    = doc_mat_khau(),
}

-- NGƯỠNG QUYẾT ĐỊNH — nay là NGUỒN SỰ THẬT DUY NHẤT.
--
-- CẢNH BÁO VỀ CON SỐ CŨ TRONG FILE NÀY: bảng này trước ghi `challenge = 80`,
-- `block = 100` kèm chú thích "nâng từ 65" / "nâng từ 80". **Chưa một dòng nào
-- trong cây nguồn đọc bảng này** — `enforcement/decision/engine.lua` viết cứng
-- 25/55/80 và quyết định bằng con số của nó. Nên lần nâng đó **chưa bao giờ có
-- hiệu lực**, và hệ thống đã chạy ở 55/80 suốt từ đầu.
--
-- Con số dưới đây là con số ĐANG THỰC SỰ CHẠY, chép lại cho đúng sự thật —
-- không phải một lần hạ ngưỡng. Engine giờ đọc từ đây, nên đổi ở đây là đổi
-- thật.
--
-- MUỐN NÂNG LÊN 80/100 THÌ ĐỌC TIẾP. Việc đó giờ chỉ là sửa hai số ở đây, và
-- `KILL_CHALLENGE_EFF`/`KILL_BLOCK_EFF` trong engine sẽ tự đi theo (chúng được
-- dẫn xuất). Nhưng hai kill-switch cho class bị giảm điểm là PHẦN TRĂM nên
-- không tự đi theo:
--
--   KILL_DAMP_SOFT: raw 110 × 0,65 = 71,5 — với challenge=80 thì KHÔNG còn
--                   tạo được challenge nữa.
--   KILL_DAMP_HARD: raw 140 × 0,85 = 119 — vẫn ≥ 100, còn sống; nhưng ca đã
--                   ghi trong `enforcement/CLAUDE.md` (20.9.70.139, raw 140 ⇒
--                   eff 91 ⇒ block) sẽ tụt xuống chỉ còn challenge.
--
-- `waf/scripts/contract_test.lua` mục 7 kiểm các bất biến này, nên cổng [3b]
-- sẽ báo đỏ trước khi deploy chứ không hỏng âm thầm. Và trước khi nâng, hãy đo
-- xem dải 55–80 hiện đang chứa bao nhiêu lưu lượng và là ai:
--
--   awk '{for(i=1;i<=NF;i++){if($i~/^eff=/)e=substr($i,5);
--         if($i~/^action=/)a=substr($i,8)}
--        if(e+0>=55 && e+0<80) print a}' /var/log/antibot/antibot.log \
--     | sort | uniq -c | sort -rn
_M.thresholds = {
    allow     = 0,
    monitor   = 25,
    challenge = 55,
    block     = 80,
}

-- ── THANG BA NẤC CHO CIPHER LIST CỦA JA3 ────────────────────────────────
--
-- `ngx.ssl.clienthello.get_client_hello_ciphers()` CÓ trên cả 5 máy (đo
-- 2026-09-06: OpenResty 1.29.2.3 / 1.31.1.1, lua-resty-core 0.1.33 / 0.1.34).
-- Nghĩa là lấy được cipher NGAY trong `ssl_client_hello_by_lua`, không đụng tới
-- mô hình OpenResty→Apache. Đánh đổi "no-stream" là thật, nhưng nó không còn
-- buộc JA3 phải partial.
--
-- KHÔNG bật thẳng, vì có ĐÚNG MỘT rủi ro và nó là rủi ro CÀI ĐẶT:
-- `intelligence/threat/ja3_allowlist.lua` chấm `cipher_count < 5 → 0.6`, nhân
-- trọng số 50 = **30 điểm**. Nếu API trả về dạng mà bộ phân tích không đợi thì
-- danh sách cipher rỗng ⇒ 30 điểm cho TẤT CẢ. Không đoán hình dạng trả về:
-- `parse_ciphers` trong `ja3.lua` xử lý cả bảng lẫn chuỗi byte, và nấc `probe`
-- in ra hình dạng thật.
--
--   "off"   — như hiện nay. Không gọi API. (mặc định)
--
--   "probe" — GỌI API, đếm cipher, ghi vào log `ja3c=`, nhưng **KHÔNG đưa vào
--             hash**: `ja3_partial` vẫn true, chuỗi JA3 y hệt nấc "off".
--             ⇒ HÀNH VI KHÔNG ĐỔI MỘT CHÚT NÀO. Đây là nấc để kiểm.
--             Kiểm gì (xem log `[ja3] cipher_probe` mức ERR, lấy mẫu 1/200):
--               shape=table|string  — hình dạng API thật sự trả về
--               n=<số cipher>       — PHẢI ≥ 5 với trình duyệt thật.
--                                     n=0 hoặc n<5 hàng loạt ⇒ ĐỪNG lên "on",
--                                     đó đúng là ca 30 điểm oan.
--             Và trong antibot.log: `ja3c=` phải có số, `ja3p=` vẫn `true`.
--
--   "on"    — dùng cipher thật. `ja3_partial=false` ⇒ `ja3_allowlist` bắt đầu
--             chạy (trước nay chưa từng chạy — `ja3_db` đã bị xoá vì không ai
--             đọc đầu ra của nó), và
--             **hash JA3 đổi ⇒ `fp_light` đổi một lượt** ⇒ `sess:` mồ côi,
--             `ban:` hết khớp, counter reset. Reload vào giờ thấp điểm.
--             Theo dõi `j3m=` trong antibot.log: đó là `ja3_allowlist_miss`.
--             Trình duyệt thật phải ra 0.00. Thấy 0.60 hàng loạt = quay lại
--             "probe" ngay.
--
-- HAI CHỐT ĐÃ ĐẶT SẴN cho ca "30 điểm oan", nên nấc "on" không còn là cú nhảy
-- niềm tin (2026-09-06):
--   1. `parse_ciphers` trả thêm `valid`. Chuỗi lẻ byte, phần tử bảng không
--      phải số nguyên 0..65535, hoặc kiểu trả về lạ ⇒ VỨT CẢ DANH SÁCH thay
--      vì cứu vớt phần đọc được. Đầu vào hỏng không còn thành "JA3 đầy đủ".
--   2. `ja3.lua` chỉ bỏ cờ `partial` khi bắt được ≥ `MIN_PLAUSIBLE_CIPHERS`
--      (= 5, đúng bằng ngưỡng phạt bên `ja3_allowlist`). Dưới ngưỡng thì giữ
--      `partial` (0 điểm) và ghi `[ja3] cipher_too_few` ở mức ERR.
-- Cả hai đều rơi về đúng hành vi nấc "off" khi có nghi ngờ.
_M.tls = {
    ja3_cipher = "probe",
}


_M.signal_threshold = 0.7

_M.endpoint_sensitivity = {
    ["/admin"]      = 2.0,
    ["/login"]      = 1.8,
    ["/register"]   = 1.6,
    ["/checkout"]   = 1.8,
    ["/payment"]    = 2.0,
    ["/api/"]       = 1.2,
    ["/search"]     = 1.3,
    ["/"]           = 0.8,
    default         = 1.0,
}

_M.ttl = {
    asn              = 3600,
    fp               = 86400,
    fp_quality       = 86400,
    session          = 7200,
    session_max_len  = 20,
    sequence_use_len = 10,
    rate             = 60,
    burst            = 1,
    -- Bậc cuối là 30 NGÀY, KHÔNG phải vĩnh viễn (0). Đo 2026-08-06 trên
    -- cloud28-246: 8.261 lệnh cấm IP vĩnh viễn đã tích luỹ, trong đó chỉ 33
    -- (0,4%) còn `ban_ctx` để giải thích lý do — và 13 trong số 33 đó là
    -- AhrefsBot THẬT (PTR `proxy-*.ahrefs.net`). Cấm vĩnh viễn không có cơ chế
    -- rà soát nào, nên sai lầm nằm lại mãi và IP đổi chủ thành mìn.
    -- 30 ngày giữ gần như nguyên hiệu quả (bot lì leo lại thang trong vài phút)
    -- nhưng danh sách TỰ DỌN — 69,5% số IP kia đã ngừng hoạt động.
    ban_steps        = {300, 3600, 86400, 2592000},
    violation        = 172800,  -- 48h: đủ dài để xuyên qua ban step 3 (24h), đủ ngắn để user thật không mang violation cũ
    risk             = 86400,
    dns              = 600,
    rep_ip           = 900,
    rep_asn          = 3600,
    -- 60 → 300. Cửa sổ này KHÔNG còn phải chứa thời gian giải PoW (bộ giải
    -- đồng bộ mới xong trong ~3 lát 30ms, kể cả khi tab chạy nền), mà phải
    -- chứa: tải trang + thiết bị yếu + khách chuyển sang app khác rồi quay lại
    -- + tối đa 3 lần thử gửi có giãn cách (~28s). Với 60s, đúng những khách đó
    -- về tới nơi là `nonce not found` → 403 → tải lại → vòng lặp mà người dùng
    -- nhìn thấy là "quay mãi không xong". `label:<id>` dùng chung TTL này.
    nonce            = 300,
    verified         = 604800,  -- 7 ngày (mobile 4G: cookie persist qua đổi mạng)
    explain          = 3600,
    antibot_tls      = 10,
    whitelist_cache  = 60,
}

-- P1 network-UA quarantine.  This is deliberately separate from `_M.ttl`:
-- the old ladder is still used by IP/global hard bans, while a coarse
-- (IP, normalized-UA) subject must not receive a fleet-wide 30-day sentence.
--
-- Do not add OS, language, Client-Hints or browser build to this key merely to
-- split office NATs.  Managed-company machines are commonly cloned and updated
-- together, so those fields still collide while making the key churn on update.
-- Collision recovery belongs to host scope + challenge-first browser handling.
_M.network_quarantine = {
    enabled       = true,
    steps         = {300, 3600, 86400}, -- 5m -> 1h -> 24h, never 30d
    violation_ttl = 172800,              -- only fresh block decisions increment
    legacy_read   = true,                -- old ban:<id> drains naturally; never refreshed
    global_reasons = {
        fake_good_bot = true,            -- registered identity contradicted by proof
    },
}

_M.rate = {
    base_threshold        = 300,
    burst_threshold       = 30,
    slow_threshold_s      = 10,
    risk_factor           = 0.5,
    -- ip_surge_threshold: SIGNAL trigger (~25 req/s sustained over 60s window).
    -- Beyond this, set ctx.ip_surge=true → contributes weight in scoring
    -- (intelligence/scoring/compute.lua). Engine decides via aggregate score,
    -- not a unilateral ban. Allows extension/multi-tab/AI-agent users (single
    -- identity, clean fingerprint) to pass even when bursting briefly.
    ip_surge_threshold    = 1500,
    -- ip_surge_extreme: HARD-BAN trigger (~83 req/s sustained over 60s window).
    -- This rate is implausible for human + browser even with aggressive
    -- extension/multi-tab activity. IP ban immunity comes only from
    -- ctx.ip_shared_verified (real first-party-cookie users), not raw UA count.
    ip_surge_extreme      = 5000,
    -- ip_surge_ban_ttl: hard-ban duration when extreme path fires. Shortened
    -- from legacy 1800s to 300s — auto-recovery after 5 min, repeat surges
    -- re-ban naturally. Reduces blast radius if extreme threshold is mis-tuned.
    ip_surge_ban_ttl      = 300,

    -- Class-aware burst factor: multiplies burst_threshold per req_class.
    -- Orthogonal với session_richness lift — combine multiplicative cho
    -- effective_threshold = base × class_factor × (1 + richness × 2).
    --
    -- Nguyên tắc:
    --   < 1.0 = tighten (request type không tự nhiên burst → bot signal)
    --   > 1.0 = relax  (request type có legitimate burst pattern)
    --
    -- Calibration:
    --   navigation 0.67   → 20/s. Human khó burst > 20 nav/s ngay cả khi
    --                       F5 storm hoặc multi-tab bookmark "Open All".
    --                       Rate layer khong discount same-URI stream: mot
    --                       endpoint bi hammer la tai that, khong phai retry vo han.
    --   interaction 1.5  → 45/s. SPA frontend (Magento Luma, Shopify,
    --                       headless Next.js) fire 30-50 XHR đồng thời on
    --                       page load. Đây là vùng FP cao nhất.
    --   api_callback 2.0 → 60/s. Server-to-server webhook retry (Stripe,
    --                       MoMo, VNPay) có thể burst nếu integration lỗi.
    --   auth_endpoint 0.8 → 24/s. Login không có lý do burst. Tighten chống
    --                       credential stuffing 1-second hammer.
    --   feed_or_meta 0.5 → 15/s. Crawler hit individually (1 IP = 1-3 fetch
    --                       per minute), không có per-identity burst.
    --   inapp_browser/unknown: giữ baseline 1.0.
    --   resource: giá trị bất kỳ (resource skip burst counter qua STEPS_RESOURCE).
    class_burst_factor = {
        resource      = 1.0,
        navigation    = 0.67,
        interaction   = 1.5,
        api_callback  = 2.0,
        auth_endpoint = 0.8,
        feed_or_meta  = 0.5,
        inapp_browser = 1.0,
        unknown       = 1.0,
    },

    -- Verified good-bot rate ceiling (replaces hard-coded per-ASN limits).
    --
    -- Each verified bot (after DNS/ASN verification in detection/bot/) is
    -- assigned a class. Class -> req/min ceiling. Operator tune by editing
    -- table below. Industry pattern (Cloudflare Bot Categories, Akamai
    -- Crawler Profiles, DataDome bot tiers).
    --
    -- Adaptive promotion: every 429 (rate exceeded) increments
    -- `gb_aggression:<bot>` (TTL 600s = 10-min self-decay). When aggression
    -- score crosses threshold, effective_class is promoted toward the most
    -- restrictive tier. Bot quiet 10 min -> aggression key expires -> class
    -- restored to base. Same pattern as `ip_risk` EMA decay in
    -- async/risk_update.lua.
    --
    -- Class ladder (low -> high restriction): polite -> moderate -> aggressive
    -- Aggression score thresholds (count of 429s in last 10-min sliding window):
    --   <  promotion_t1 -> base class
    --   >= promotion_t1 -> +1 tier
    --   >= promotion_t2 -> +2 tier (skip straight to aggressive)
    --
    -- `map` is enumeration of KNOWN verified bots — finite (~20 globally),
    -- stable list, paired with bot verification registry (data/goodbot.json).
    -- This is metadata for tuning, NOT a detection pattern list.
    good_bot_rate = {
        -- 2026-08-09: hạ toàn thang còn 2/3 (180/60/30/60 → 120/40/20/40).
        --
        -- Bối cảnh đo trên cloud28-246: `nproc`=6, load average **7.62** =
        -- 127% quá tải, `%Cpu 0.0 id / 0.0 wa`, `sy` 51,7% > `us` 47,5% (32
        -- tiến trình php-fpm tranh 6 core). Bot chiếm **37–59% số request** của
        -- ba domain ngốn CPU nhất (vietship.net 37%, inachau.net 38%,
        -- xaydungachau.net 59%), và toàn bộ là `action=allow` ⇒ chạy PHP đầy đủ.
        --
        -- Chọn 2/3 chứ không phải 1/2: đủ để đo được tác động mà chưa cắt sâu,
        -- còn dư địa siết tiếp nếu số liệu ngày mai cho thấy cần.
        --
        -- KHÔNG có rủi ro SEO: 429 kèm `Retry-After` là tín hiệu CHUẨN mà
        -- Google/Bing hiểu và tự giảm nhịp cào — không phải lỗi, không ảnh
        -- hưởng chỉ mục. 120 lượt/phút vẫn là 2 req/giây dành riêng cho
        -- Googlebot trên một máy dùng chung.
        --
        -- ĐỪNG KỲ VỌNG QUÁ: ước lượng phần cắt được ~10.000 lượt/ngày trên nền
        -- ~400.000 ≈ 2,5%. Gốc của 127% KHÔNG nằm ở antibot mà ở cache trang và
        -- `pm.max_children` (32 tiến trình trên 6 core là tự bóp cổ). Siết bot
        -- là việc đúng nhưng không thay thế được hai thứ đó.
        classes = {
            polite     = 120,  -- 2 req/sec — search engine ổn định
            moderate   = 40,   -- verified nhưng từng có history aggressive
            aggressive = 20,   -- known low-quality crawl
            default    = 40,   -- unknown verified bot fallback
        },
        map = {
            -- Polite: established search engines, stable crawl patterns
            googlebot   = "polite",
            bingbot     = "polite",
            applebot    = "polite",
            duckduckbot = "polite",

            -- Moderate: verified but observed aggressive on this stack
            -- Khoá ở đây là tên HỌ. engine.lua:class_for_bot khớp chính xác
            -- trước, trượt thì lấy khoá dài nhất là tiền tố — nên `meta` bắt
            -- được `meta-externalagent` và `coccocbot` bắt được `coccocbot-web`.
            -- Trước 2026-08-09 cả hai lệch khoá và âm thầm rơi về `default`.
            meta             = "moderate",
            coccocbot        = "moderate",

            -- Aggressive: known low-value or aggressive crawlers
            bytespider  = "aggressive",
            semrushbot  = "aggressive",
            ahrefsbot   = "aggressive",
            mj12bot     = "aggressive",
            -- amazonbot: xác minh DNS được (PTR crawl.amazonbot.amazon) nhưng
            -- gần như không sinh truy cập giới thiệu cho site tiếng Việt →
            -- đón nhưng siết 30/phút.
            amazonbot   = "aggressive",
            -- baiduspider: DNS hai chiều sạch (PTR baiduspider-*.crawl.baidu.com
            -- → A trỏ ngược đúng IP) nhưng site tiếng Việt gần như không nhận
            -- lượt giới thiệu nào từ Baidu. Trước 2026-08-08 nó bị fleet RST
            -- 20.042 lượt/ngày — tức KHÔNG có trần nào, chỉ có bức tường. Nay đón
            -- vào cửa chính và siết 30/phút. Mọi biến thể (Baiduspider-image/
            -- -video/-news/-render) đều rút về cùng tên `baiduspider` ở ua_check
            -- nên chia CHUNG một hạn mức — rotation IP không nhân được nó lên.
            baiduspider = "aggressive",
            -- yandex: khoá HỌ, phủ yandexbot / yandexrenderresourcesbot /
            -- yandexmobilebot / … nhờ khớp tiền tố. Yandex tự sở hữu AS13238 và
            -- tài liệu chính thức yêu cầu xác minh PTR + xác nhận xuôi, nên nó
            -- đủ tiêu chuẩn S4 bằng DNS hai chiều — KHÔNG cần mở cổng ASN nào,
            -- khác hẳn ca Baidu (đi nhờ AS4837) và PetalBot (cloud bán lẻ).
            --
            -- Trước 2026-08-09 mục này là `yandexbot = "moderate"` và là CẤU
            -- HÌNH CHẾT: trần nằm trong nhánh good_bot_verified mà Yandex không
            -- có trong registry nên không bao giờ vào được nhánh đó. Cùng cảnh
            -- ngộ: bytespider, semrushbot, mj12bot, duckduckbot — chúng vẫn
            -- chết cho tới khi được đưa vào goodbot.json.
            yandex      = "aggressive",
            -- seranking / petalbot: đo 2026-08-09 phát hiện CẢ HAI đều không có
            -- trong bảng ⇒ rơi về `default`, tức tầng RỘNG GẤP ĐÔI `aggressive`
            -- — đúng chiều ngược lại với giá trị chúng mang lại.
            --
            -- SE Ranking là công cụ phân tích backlink: nó cào site của khách
            -- hàng để bán dữ liệu cho người khác, chủ site không nhận lại gì.
            -- Một IP duy nhất `95.217.114.145` (PTR
            -- `discovery-crawler30.blex.seranking.com`) gửi **2.173 request chỉ
            -- riêng vietship.net**. Khoá `seranking` khớp tiền tố nên phủ cả
            -- `serankingbacklinksbot` lẫn các biến thể khác.
            --
            -- Cả hai đi đường S2.5 (`contact_ptr_match`) chứ không vào registry
            -- — đúng nguyên tắc: registry dành cho bot có giá trị SEO/truyền
            -- thông, bảng này chỉ là cái trần đặt sẵn cho ai tự chứng minh được
            -- tới S2.5.
            seranking   = "aggressive",
            petalbot    = "aggressive",
        },

        -- Adaptive promotion tunables
        aggression_decay_ttl  = 600,  -- 10-min sliding window via TTL refresh
        promotion_threshold_1 = 10,   -- score >= 10  -> +1 tier
        promotion_threshold_2 = 30,   -- score >= 30  -> +2 tier
        retry_after           = 60,   -- 429 Retry-After header value
    },
}

-- L7 admission control — phanh tai nguyen cuc bo, DOC LAP voi bot scoring.
--
-- Tat ca request (ke ca verified/resource/whitelist) di qua lop nay truoc khi
-- duoc phep fast-path. Counter tai su dung `antibot_cache` da co trong cau hinh
-- hien tai, khong doi nginx.conf va khong phu thuoc Redis.
--
-- Hai cua so la fixed buckets. `long` chan luong duy tri, `short` chan spike.
-- Cac nguong mac dinh co y dat cao de rollout an toan tren shared hosting;
-- phai hieu chinh theo capacity/log that cua tung cum may.
-- Generic automation governor. Every self-identified automation client is
-- metered by principal+host, IP+host and server aggregate. Enforcement is
-- explicitly restricted below to operator/contradicted tiers; unknown and
-- verified automation remain telemetry-only to contain FP risk.
-- Units approximate backend cost rather than raw object count, so one page
-- with many CSS/images is not treated like the same burst of dynamic work.
_M.automation = {
    enabled = true,
    -- ENFORCE tu 18-10-2026. Truoc do `shadow`, va doc code thi ro vi sao
    -- khong co gi bi chan: `evaluate()` chi dat `automation_would_throttle`
    -- roi tra ve, khong bao gio goi `ngx.exit`. Gioi han operator 30/10s hien
    -- ra trong log suot thoi gian do nhung khong rang buoc gi.
    --
    -- Do duoc tren cloud28-246: 48.798 luot `opnet=openai` trong 48h di thang
    -- vao backend; `max_children=10` can kiet, 499 chiem 91%, HTTP 200 con
    -- DUNG MOT luot trong cua so 10 phut.
    mode = "enforce",
    status = 429,
    -- Khong nho hon `windows.short`: bao crawler quay lai som hon luc ngan
    -- sach day lai chi bien mot dot thanh mot con bao retry tren cung ngan
    -- sach do.
    retry_after = 10,

    -- Emergency isolation switch (18-10-2026).  This is deliberately keyed
    -- by canonical automation principal AND is consumed only when the request
    -- has reached tier `operator` (published network + matching claim).  A
    -- random client that merely writes "GPTBot" in its UA is therefore not
    -- granted a new blocking primitive.
    --
    -- Two production machines now show the same causal shape:
    --   - GPTBot: 2,144 / 2,621 attempts per hour, 68.9% / 71.0% already 429;
    --   - admitted samples still hold upstream for 6.52s / 15.40s on average;
    --   - exact-UA access logs rank `/wp-json/oembed/1.0/embed` and `/` first,
    --     spread across many domains (77.7% / 73.9% unique URLs for the day).
    -- Rate tuning has therefore not isolated the remaining expensive tail.
    -- Suspend the verified training crawler completely for a few hours and
    -- compare worker-seconds/load.  OAI-SearchBot and ChatGPT-User remain on
    -- their normal independent budgets.
    suspended_principals = {
        gptbot = true,
    },
    suspend_status = 403,

    -- Chỉ các tầng có bằng chứng máy đủ mạnh bên dưới mới bị pace. `unknown`
    -- CỐ Ý để ngoài: đó là nơi một khách thật bị phân loại nhầm thành automation
    -- sẽ rơi vào. `cloud_automation` không phải vendor trust; nó chỉ chứng minh
    -- UA crawler có contact hợp lệ đang chạy từ hạ tầng cloud, đủ để giới hạn
    -- tài nguyên nhưng không đủ để whitelist/cap quyết định.
    --
    -- `unknown` CO Y de ngoai: do la noi mot khach
    -- that bi phan loai nham thanh automation se roi vao, va uu tien so mot
    -- cua he thong nay la khong chan nham. `verified` (S3/S4 good bot) cung
    -- de ngoai: Googlebot/Bingbot da qua DNS hai chieu va viec ha xep hang
    -- tim kiem cua khach dat hon nhieu so voi tai ma chung tao ra.
    --
    -- `operator` = IP nam trong dai CONG BO cua nha cung cap VA UA tu khai
    -- khop (`operator_network.lua:owner_matches_claim`). Mot host AWS bat ky
    -- KHONG vao duoc tang nay: `mon:<ip>` chi duoc ghi tu feed chinh thuc.
    -- `contradicted` = da co bang chung mau thuan voi loi tu khai.
    enforce_tiers = {
        operator     = true,
        -- Compliant contact UA + generic cloud PTR proves machine automation,
        -- not ownership of the claimed vendor. It is safe to pace but receives
        -- none of the S2.5 trust/cap privileges.
        cloud_automation = true,
        contradicted = true,
    },

    windows = { short = 10, long = 60 },
    costs = {
        resource      = 0.1,
        navigation    = 1.0,
        feed           = 1.0,
        meta           = 0.5,
        interaction   = 2.0,
        unknown       = 2.0,
        api_callback  = 3.0,
        auth_endpoint = 4.0,
    },
    provisional_limits = {
        tiers = {
            verified     = { short = 30, long = 120 },
            -- Published source network + matching self-identification. This is
            -- not S4 good-bot trust: scoring remains active and only the final
            -- block/challenge decision is capped at monitor.
            --
            -- HA 30/120 -> 8/30 (18-10-2026). Ly do la bat doi xung o chinh
            -- cac feed cong bo, dem duoc khi dong bo:
            --     openai-chatgpt-user  36.496 IP   (cap feed 65536)
            --     openai-gptbot         2.704 IP
            --     openai-searchbot      2.560 IP
            --     openai-adsbot           256 IP
            --     anthropic             1.136 IP
            --     perplexitybot            18 IP
            -- OpenAI cong bo 42.016 IP, Anthropic 1.136 — gap 37 lan. Han
            -- muc o day tinh theo (host, principal) chu khong theo IP, nen
            -- so IP khong tu dong nhan han muc len; nhung no cho thay quy mo
            -- ha tang dung de keo, va 30 don vi chi phi / 10 giay tren MOT
            -- host chia se la qua rong cho mot ben keo lien tuc.
            --
            -- 8/10s voi `navigation` cost 1.0 la ~0,8 trang/giay/host — van
            -- du de index het mot site vai nghin trang trong vai gio, nhung
            -- khong du de lam can mot pool `max_children=10`.
            operator     = { short = 8,  long = 30  },
            cloud_automation = { short = 8, long = 30 },
            attested     = { short = 20, long = 60  },
            unknown      = { short = 12, long = 40  },
            contradicted = { short = 8,  long = 20  },
        },
        ip     = { short = 20,  long = 60  },
        host   = { short = 100, long = 400 },

        -- Truc PRINCIPAL TOAN MAY (them 18-10-2026). Sua dung phep nhan mau so
        -- da do duoc, thay vi ap mot tran chung len moi principal:
        --     GPTBot di qua 17 domain -> 17 ngan sach `(host, principal)`
        --     doc lap -> han muc operator 8/10s thanh hieu dung 136/10s.
        --
        -- Co so cho con so: 5.909/5.929 request operator trong 60 phut la
        -- OpenAI = 1,641 req/s. Voi `navigation` cost 1.0:
        --     long  60/60s = 1,000 don vi/s -> OpenAI ve ~61% toc do keo
        --     short 15/10s = 1,500 don vi/s -> chan dot, khong chan deu
        --
        -- Vi sao truc nay can thiet du da co `server`: Anthropic cong
        -- Perplexity chi chiem 20/5.929 = 0,34% request operator, tuc
        -- 0,0056 req/s — cach nguong fleet 293 lan nen KHONG THE bi chan oan.
        -- Truc `server` thi gop moi principal, nen chung bi chan chi vi OpenAI
        -- dang keo. Hai truc do hai thu khac nhau va deu can.
        -- SIET 15/60 -> 10/30 (18-10-2026, sau khi do `autthr.sh` tren 28-246).
        -- Truc nay CO phan biet, nen no la truc nen gong tai:
        --     gptbot        autfs max  66.4 | autfl max 122.7  -> vuot 4,1x
        --     oai-searchbot autfs max   6.0 | autfl max  14.0  -> 0,47x
        --     claudebot     autfs max   6.0 | autfl max  12.0  -> 0,40x
        -- O muc 10/30, claudebot con cach tran 2,5 lan nen khong the bi chan
        -- oan, trong khi gptbot bi siet manh hon truoc.
        fleet  = { short = 10,  long = 30  },

        -- HA 300/1200 -> 20/60 (18-10-2026), sau so lieu production 60 phut:
        -- 5.516 automation request da vao upstream, trung binh 6,905 giay
        -- (~10,6 request dong thoi theo Little's law), trong khi traffic trai
        -- tren 53 domain va GPTBot rieng di qua 17 domain. Per-host principal
        -- limit vi vay bi nhan thanh 17 ngan sach doc lap; server-axis cu chua
        -- tung breach va khong bao ve duoc pool backend chung.
        --
        -- Day la DON VI CHI PHI tren TOAN MAY, khong phai so request thuan:
        -- navigation=1, api_callback=3, auth_endpoint=4... Tat ca automation
        -- tier deu GHI vao counter chung, nhung chi operator/contradicted trong
        -- `enforce_tiers` moi bi 429 khi counter day. Human traffic khong di
        -- qua meter nay; verified/unknown automation chi gop ap luc va tu no
        -- van khong bi throttle. Counter nam trong ngx.shared.antibot_cache,
        -- chung giua worker/domain tren MOT may, khong phai Redis/fleet-global.
        -- NOI 20/60 -> 45/180 (18-10-2026). Day la sua mot FP DA DO DUOC, khong
        -- phai noi long cho de chiu.
        --
        -- `autthr.sh` tren 28-246 sau moc deploy:
        --     server:long  2459 luot vuot  ┐ 3937 tong — vo GAN NHU LIEN TUC
        --     server:short 1478 luot vuot  ┘
        --     fleet:short    95 luot       ┐  186 tong
        --     fleet:long     91 luot       ┘
        -- Truc `server` vo gap 21,2 lan truc `fleet`, dung nhu phep tinh truoc
        -- deploy da canh bao (luu luong automation 2,86 don vi/s so voi nguong
        -- 1,000 don vi/s = 2,9 lan).
        --
        -- FP that, doc tu muc 3 cua autthr.sh:
        --     claudebot bi chan 20 luot — TAT CA qua `server:*`, 0 qua `fleet:*`
        --     trong khi `autfl max` cua no chi la 12,0 tren tran 60 (0,20x).
        -- Tuc Anthropic bi 429 CHI VI OpenAI dang keo. Do la dieu truc `server`
        -- khong the tranh: no gop MOI principal vao mot counter.
        -- (6 luot `googlebot` bi chan la tier `contradicted` =
        -- `registered_evidence_mismatch`, tuc Googlebot GIA — chan dung.)
        --
        -- 45/180 = gap 3 lan `fleet` (10/30), nghia la "BA principal lon cung
        -- dat tran rieng thi moi phanh toan may". Do moi la luoi an toan.
        -- Mot may chi co vai principal lon (gptbot, oai-searchbot, claudebot,
        -- bingbot), nen 3x la nguong co that chu khong phai ma chet.
        -- GO TINH TOAN 18-10-2026. Khong dat `server` nua -> `consider()` tra
        -- ve ngay o dong `if not limits then return top end`, nen truc nay chi
        -- con DEM (`autss=`/`autsl=` van ghi log) ma khong rang buoc ai.
        --
        -- VI SAO GO, do duoc qua hai vong tren 28-246:
        --   vong 1, server 20/60 : server:* vuot 3937 | fleet:* 186
        --   vong 2, server 45/180: server:* vuot 4781 | fleet:* 667
        -- Noi tran len GAP BA ma so luot vuot lai TANG. Doc code ra ly do:
        -- `pair()` cong counter o dong 187-205 CON `evaluate()` chay o dong
        -- 221, nen mot request da bi 429 VAN cong du chi phi vao `server`.
        -- Truc nay do "tong request DEN", khong do "tai thuc vao backend", nen
        -- khong co tran nao thang duoc mot principal dang keo manh.
        --
        -- Va no khong phan biet duoc. Toan bo 22 luot FP vong 2 di qua no:
        --   claudebot      9 luot | autfl max  6,0 / tran 30 = 0,20x
        --   oai-searchbot 10 luot | autfl max 17,0 / tran 30 = 0,57x
        --   chatgpt-user   1 luot | autfl max  8,0 / tran 30 = 0,27x
        --   perplexitybot  2 luot | (14 luot khac qua principal: DUNG)
        -- Khong con nao tu cham tran rieng; chung bi chan vi OpenAI dang keo.
        --
        -- Gia phai tra: mat 856 luot chan cua gptbot. Nhung gptbot VAN bi chan
        -- 608 luot qua `fleet` va cac request do se day `fleet` len cao hon,
        -- nen phan lon se bi chan lai boi truc CO phan biet.
        --
        -- Mo lai chi khi do duoc mot ca NHIEU principal cung keo manh ma
        -- `fleet` khong giu duoc — luc do sua `pair()` de khong cong vao
        -- `server` sau khi da chan, roi moi dat tran.
        -- server = { short = 45, long = 180 },
    },
}

-- Whole-server concurrency for evidence-backed automation.
--
-- This is deliberately separate from the fixed-window governor above:
-- `fleet=10/30` controls arrival bursts, while this gate controls how much
-- backend work remains alive.  One canonical principal shares ONE slot pool
-- across every source IP, tenant host and URI.  Slot lifetime naturally makes
-- a 15-second request cost more capacity than a 200ms request without guessing
-- from req_class.
--
-- SHADOW first.  GPTBot remains on the emergency suspension above, because
-- removing it while this gate only observes would restore the production load
-- incident.  Validate `autcn/autcwould/autcdur/autcup/autcdeg` on other proven
-- operators; then remove only `suspended_principals.gptbot` and promote only
-- `principals.gptbot.mode` to `enforce` in the same deployment.
_M.automation_concurrency = {
    enabled = true,
    mode = "shadow",             -- default; tier/principal may opt into enforce
    limit = 3,
    status = 429,
    retry_after = 10,

    -- Same leak-resistant slot geometry already proven by endpoint_guard.
    -- Retention exceeds the measured GPTBot upstream maximum (~62s).  A request
    -- living beyond 180s ages out fail-open and is exposed by `autcexp=true`.
    slot_bucket_seconds = 30,
    slot_retention_seconds = 180,

    -- Per-principal rollout knob.  Keep explicit even while it equals the
    -- default so reopening GPTBot is a one-principal change, not a fleet-wide
    -- change that also affects Claude/Perplexity/OAI-SearchBot.
    principals = {
        gptbot = { mode = "shadow", limit = 3 },
    },

    -- Unlike published-feed operators, a cloud claim is not bound to its
    -- principal: production saw one IP alternate GrokBot and DeepSeekBot.
    -- Enforce both a whole-server principal pool and a source-IP pool so a UA
    -- swap cannot multiply capacity. Human traffic cannot enter this tier.
    tiers = {
        cloud_automation = {
            mode = "enforce",
            limit = 3,
            source_limit = 3,
        },
    },
}

_M.l7_admission = {
    enabled       = true,
    mode          = "enforce", -- shadow | enforce | off
    status        = 429,
    retry_after   = 2,
    route_shards  = 64,        -- cardinality co dinh / host, chong key-flood

    -- Static MISS dung ngan sach `dynamic`, khong phai `resource`.
    --
    -- `req_classifier` chi biet "GET/HEAD + duoi tinh" = static CANDIDATE. Tep
    -- co that thi Nginx phuc vu truc tiep (re thuc su); tep thieu thi
    -- `try_files` -> `@static_backend` -> Apache/PHP, va voi WordPress thi
    -- `.htaccess` rewrite thanh `index.php`. Do la tai dynamic du duoi la `.jpg`.
    --
    -- Do duoc truoc khi co co nay (1 host, 2000 IP, `.jpg` khong ton tai):
    -- 2000 IP x 2 req/s ben vung 60s -> 3.200 req/s lot toi Apache (80%). Cung
    -- luu luong do voi `.php` chi 350 req/s lot.
    --
    -- `static_probe = false` tat phep do (moi resource lai dung ngan sach
    -- resource nhu truoc). Giu lai de co duong lui nhanh neu `io.open` gay van
    -- de hieu nang tren may cu — nhung ket qua da duoc cache nen mot flood vao
    -- cung duong dan chi ton MOT `io.open` moi `static_probe_ttl` giay.
    static_probe     = true,
    static_probe_ttl = 30,     -- giay; ngan de upload tep moi khong bi hieu sai lau
    windows = {
        short = 1,
        long  = 10,
    },
    limits = {
        -- Toan bo OpenResty instance / mot virtual host, moi request deu tinh.
        global = { short = 20000, long = 160000 },
        host   = { short = 5000,  long = 40000  },

        -- Tach resource candidate va dynamic. Lua access phase khong biet ket
        -- qua `try_files`, nen khong co budget static-miss rieng neu khong sua
        -- Nginx; resource candidate van chiu host/route/IP budget o day.
        host_group = {
            resource = { short = 4000, long = 32000 },
            dynamic  = { short = 500,  long = 3500  },
        },
        route_group = {
            resource = { short = 1200, long = 9000 },
            dynamic  = { short = 150,  long = 1000 },
        },

        -- Per-IP short ceiling. IP sau reverse proxy da xac minh bo qua truc
        -- nay; host/global/route budgets van con nguyen.
        ip = {
            resource      = { short = 250, long = 1800 },
            navigation    = { short = 80,  long = 500  },
            interaction   = { short = 120, long = 800  },
            api_callback  = { short = 100, long = 700  },
            auth_endpoint = { short = 30,  long = 180  },
            feed_or_meta  = { short = 60,  long = 400  },
            inapp_browser = { short = 80,  long = 500  },
            unknown       = { short = 80,  long = 500  },
            default       = { short = 80,  long = 500  },
        },

        -- Endpoint noi bo goi admission ngay trong Lua content handler; khong
        -- can sua location trong file Nginx da generate.
        endpoints = {
            verify = {
                host = { short = 250, long = 1600 },
                ip   = { short = 20,  long = 120  },
            },
            beacon = {
                host = { short = 1000, long = 7500 },
                ip   = { short = 80,   long = 500  },
            },
        },
    },
}

-- Generic endpoint-cost guard with a WordPress policy overlay.
--
-- This protects the axis that per-IP/fingerprint/rate scoring cannot see: a
-- low request rate spread over thousands of IPs where every request occupies
-- expensive PHP/DB work.  All rules start in SHADOW.  Promotion is per axis,
-- so production may enforce the low-FP capacity rule for oEmbed without also
-- enforcing URL-host or REST-user policy.
--
-- Counts live in the existing local `antibot_cache`; no Redis or Nginx change.
-- Rate limits are per proven WordPress root + endpoint, not per IP and not per
-- query value.  Consequently changing `url=` cannot create a new budget.
_M.endpoint_guard = {
    enabled          = true,
    retry_after      = 2,
    rate_status      = 429,
    inflight_status  = 503,
    shape_status     = 400,
    windows = {
        short = 10,
        long  = 60,
    },
    slot_bucket_seconds    = 30,
    slot_retention_seconds = 180,
    endpoints = {
        -- Production incident 18-10-2026: 3,385 IP, 5.7 req/s aggregate,
        -- responses held PHP for 10-79s.  20/10s catches that aggregate while
        -- remaining far above ordinary on-demand embed discovery.  The more
        -- important signal is 3 concurrent requests per WordPress root.
        wp_oembed_embed = {
            -- Emergency brake 18-10-2026: public discovery is temporarily
            -- disabled before backend.  `wp_oembed_proxy` (editor/admin) is a
            -- separate endpoint and remains available.  Set mode="off" to
            -- restore the measured rate/inflight policy below.
            emergency  = { mode = "enforce", status = 429, retry_after = 300 },
            -- Route-shape swarm is independent of caller identity.  It records
            -- whether many source networks converge on this one endpoint;
            -- emergency remains the active brake during the incident.
            swarm      = { mode = "shadow", scope = "server", window = 10,
                           requests = 12, networks = 6, hold = 60 },
            rate       = { mode = "shadow", short = 20, long = 100 },
            -- ENFORCE 18-10-2026 after production showed about 17 concurrent
            -- oEmbed calls against one docroot: 31/34 ended as 499/500 and
            -- requests held up to 29s. This is the backup capacity gate after
            -- emergency is turned off; it does not score or ban the caller.
            -- Rate/shape/cross-host remain independent shadow signals.
            inflight   = { mode = "enforce", limit = 3 },
            shape_mode = "shadow",
            -- Cross-host URL is measured separately.  Do not enforce until
            -- aliases/pointers on the production fleet have been observed.
            cross_host_mode = "shadow",
        },
        -- Core protects this route with `edit_posts`, but a capacity ceiling
        -- still prevents a valid/admin caller or plugin hook from consuming a
        -- whole PHP pool.
        wp_oembed_proxy = {
            rate       = { mode = "shadow", short = 20, long = 120 },
            inflight   = { mode = "shadow", limit = 4 },
            shape_mode = "shadow",
            cross_host_mode = "shadow",
        },
        -- Public user listing is primarily a reconnaissance/privacy concern.
        -- Keep conservative budgets in shadow; do not turn privacy preference
        -- into a fleet-wide compatibility break for author/headless clients.
        wp_users_collection = {
            rate       = { mode = "shadow", short = 30, long = 180 },
            inflight   = { mode = "shadow", limit = 6 },
            shape_mode = "shadow",
            cross_host_mode = "off",
        },
        -- Mutation remains subject to WordPress authentication/capability.
        -- This guard supplies only a host capacity backstop.
        wp_users_mutation = {
            rate       = { mode = "shadow", short = 20, long = 100 },
            inflight   = { mode = "shadow", limit = 4 },
            shape_mode = "off",
            cross_host_mode = "off",
        },
        -- `_embed` expands linked REST resources; it is distinct from the
        -- oEmbed endpoint and common enough to require a deliberately high,
        -- telemetry-only starting threshold.
        wp_rest_embed_expand = {
            rate       = { mode = "shadow", short = 100, long = 600 },
            inflight   = { mode = "shadow", limit = 10 },
            shape_mode = "off",
            cross_host_mode = "off",
        },
        -- Generic invariant: `.html` is the end of a WordPress permalink on
        -- this fleet.  Any non-empty PATH_INFO after `.html/` is rejected,
        -- independent of whether today's bot writes tel:, sms: or a new token.
        wp_html_pathinfo = {
            rate       = { mode = "off" },
            inflight   = { mode = "off" },
            -- Every suffix variant is already collapsed to this one bounded
            -- endpoint id.  Shape enforcement blocks from request one; swarm
            -- telemetry labels the cross-IP campaign without banning callers.
            swarm      = { mode = "shadow", scope = "server", window = 10,
                           requests = 12, networks = 6, hold = 60 },
            shape_mode = "enforce",
            shape_status = 404,
            cross_host_mode = "off",
        },
        -- Same incident: item reads against tags/posts consumed roughly
        -- 1,004s/756s respectively, but these are legitimate public REST API
        -- routes.  Measure query/cookie split and real concurrency on every
        -- server before promoting either axis independently.
        wp_rest_tags_read = {
            -- Emergency brake: block GET/HEAD collection and every tags
            -- sub-route locally.  This can affect Gutenberg/tag consumers;
            -- turn only this switch off after backend pressure is stable.
            emergency  = { mode = "enforce", status = 429, retry_after = 300 },
            swarm      = { mode = "shadow", scope = "server", window = 10,
                           requests = 12, networks = 6, hold = 60 },
            rate       = { mode = "shadow", short = 20, long = 100 },
            inflight   = { mode = "shadow", limit = 4 },
            shape_mode = "off",
            cross_host_mode = "off",
        },
        wp_rest_posts_item = {
            swarm      = { mode = "shadow", scope = "server", window = 10,
                           requests = 12, networks = 6, hold = 60 },
            rate       = { mode = "shadow", short = 20, long = 100 },
            inflight   = { mode = "shadow", limit = 4 },
            shape_mode = "off",
            cross_host_mode = "off",
        },
    },
}

-- Per-host dynamic in-flight surge guard.  This closes the main Lua-only gap
-- between fixed request-rate budgets and the completed-response circuit
-- breaker: a small number of long dynamic requests can occupy backend capacity
-- without exceeding requests/second and before any 502/503/504 exists.
--
-- The counter is acquired only after WAF/antibot allows the request to proceed
-- and is released in log phase.  Static hits, subrequests and locally blocked
-- requests therefore do not consume slots.  It measures dynamic Nginx request
-- lifetime, not exact PHP-FPM busy workers; `sgdur` versus `sgup` telemetry is
-- provided to quantify buffering/slow-client overcount before enforcement.
--
-- Shadow is mandatory for the initial rollout.  `max_inflight=20` is a
-- measurement candidate, not a fleet capacity claim.  Tune it from real per-
-- host distributions and PHP-FPM/Apache capacity before changing to enforce.
-- All state reuses `antibot_cache`; no Redis or Nginx configuration is added.
_M.l7_surge_guard = {
    enabled          = true,
    mode             = "shadow", -- shadow | enforce | off
    status           = 503,
    retry_after      = 2,

    max_inflight     = 20,
    surge_ratio      = 0.75, -- NORMAL -> SURGE at 15/20 active requests
    recover_ratio    = 0.50, -- hysteresis: leave SURGE/SHED at <=10
    recovery_seconds = 2,

    -- Slot counters rotate by start-time bucket.  This bounds a leaked slot
    -- after worker crash even when the host remains continuously busy; newer
    -- traffic cannot refresh an old bucket forever.  Requests older than the
    -- retention horizon deliberately age out of this Lua proxy.
    slot_bucket_seconds    = 60,
    slot_retention_seconds = 300,
    state_ttl              = 300,
    sample_interval        = 1, -- at most one ordinary row/host/second
}

-- Per-host backend circuit breaker.  Unlike admission (pre-set request
-- budgets), this control learns whether Apache/PHP is actually slow or failing
-- and temporarily sheds only dynamic work for the affected virtual host.
--
-- Shadow is the safe rollout default.  It runs the complete CLOSED/OPEN/
-- HALF-OPEN state machine for HARD failures and logs `cb*` fields, but never
-- returns 503.  Slow 200 is telemetry only (`cbslowcand=true`) and cannot open
-- the breaker.  Promote hard failures to `enforce` only after real-fleet data.
-- All state reuses `antibot_cache`; no Redis or nginx change.
_M.l7_circuit_breaker = {
    enabled              = true,
    mode                 = "shadow", -- shadow | enforce | off
    status               = 503,
    retry_after          = 5,

    window_seconds       = 10,
    bucket_grace_seconds = 10,
    eval_interval        = 1,

    -- PHAN PHOI SHADOW DO TREN HAI MAY (mau trong cua so 10 giay):
    --
    --   mau/cua so       171-96       28-246
    --   0-2                 444          425
    --   3-4                  63          135
    --   5-9                  19           36
    --   10-19                 9            0
    --   20-43                14            0
    --   >=30                  6            0
    --
    -- Dinh do duoc la 43 mau/10s tren 171-96; 6 cua so >=30 chiem xap xi
    -- 1% tap cua so cua may do. `min_samples=30` vi vay la san chon loc, khong
    -- phai code ngu: no van bat duoc duoi phan phoi tai thoi diem host co tai
    -- lien tuc. Voi dung 30 mau, `hard_error_ratio=0.30` doi hoi 9 loi
    -- 502/503/504 trong 10 giay moi dat CANDIDATE. OPEN chi xay ra khi lan
    -- danh gia ke tiep van vuot nguong VA bucket mot giay moi hoan tat van co
    -- hard error. Day la cong freshness: loi cu trong cua so 10 giay khong
    -- duoc mo circuit sau khi backend da phuc hoi.
    --
    -- Day la CONG LUU LUONG DUY NHAT. `rps=total/window` van duoc log de do,
    -- nhung khong co cong RPS thu hai: voi window co dinh, them ca hai chi la
    -- viet cung mot dieu kien hai lan va lam nguoi van hanh tuong co hai tin
    -- hieu doc lap. Evaluator doc bucket da hoan tat nen co ~1s detection lag;
    -- burst cung giay la trach nhiem cua admission.lua.
    min_samples          = 30,

    -- Hard failures are the only state-machine trigger.
    hard_error_ratio     = 0.30, -- only 502/503/504

    -- Slow 200 stays observable but never writes OPEN state.  It must get a
    -- separate policy backed by fleet data before it can ever shed traffic.
    slow_seconds         = 2.0,
    slow_candidate_ratio = 0.60,

    open_seconds         = 5,
    max_open_seconds     = 60,
    probe_interval       = 1,
    recover_successes    = 3,
    stable_reset_seconds = 300,
}

_M.trust = {
    session_min        = 5,
    session_active_min = 3,
    session_flag_max   = 0.4,
    score_multiplier   = 0.5,
    score_mult_active  = 0.75,
    action_cap         = "monitor",
}

-- IP-Tour detection (cross-domain shared-hosting bot tour).
--
-- Catches the ONE invariant a shared-hosting tour bot can't hide: a single
-- source touching MANY distinct tenant domains in a short window. Every tenant
-- domain funnels through the same OpenResty + Redis, so this is visible here in
-- a way no per-site WAF can see. Per-IP rate stays under ip_surge and per
-- (IP,domain) rate stays under burst → this is the only layer that catches it.
-- See detection/ip_tour.lua for the full mechanism.
--
-- distinct_domains is a CARDINALITY (distinct hostnames), not a request count —
-- a real user browsing ONE site for hours stays at 1 forever → zero FP on long
-- sessions.
_M.ip_tour = {
    enabled          = true,
    window           = 90,    -- HLL / strike TTL seconds (sliding)
    distinct_domains = 5,     -- >= this distinct hosts from one IP → touring
    -- NAT gate: an office/CGNAT hitting many domains ALSO carries many distinct
    -- UAs; a single bot touring carries 1-2. Flag only when distinct UAs is LOW.
    distinct_ua_max  = 3,     -- distinct UAs < this → single-source
    -- shared_ua_min: distinct UAs per IP >= this → HIGH-USER shared IP (mobile
    -- CGNAT / mobile farm / office WAN). Sets ctx.ip_shared → per-IP reputation
    -- (ip_risk/ip_rep/ext_rep) is dampened and the engine ip_risk threshold-lower
    -- is skipped, so one bad actor on the shared IP doesn't punish everyone else.
    -- A single household rarely shows >5 distinct UAs in the window; offices /
    -- carriers show many. Judge those clients PER-DEVICE, not per-IP.
    shared_ua_min    = 6,
    -- ban_immune_real_min: Tier-2 (STRICT) gate for IP-ban immunity. A shared IP
    -- only becomes ban-immune (ctx.ip_shared_verified) when it ALSO carries this
    -- many distinct cookie-bearing identities in the window — REAL returning
    -- users. This blocks the UA-rotation game: a single bot spinning >=6 UAs on a
    -- dedicated IP looks "shared" (Tier 1) but has 0 real cookies → stays
    -- IP-bannable. Office/CGNAT/mobile-farm-with-real-victims clear it easily.
    ban_immune_real_min = 3,
    -- One old-window grace after worker reload lets the new strict HLL warm up.
    -- It is a rollout guard, not a permanent dual-read: after 90s only
    -- first-party-cookie cardinality can grant Tier-2 immunity.
    tier2_migration_grace = 90,
    -- Phase 2 — mobile-farm signature on a shared IP. A benign carrier/office IP
    -- carries many RETURNING users (cookies) so its cookie-ratio stays up; a farm
    -- is mostly ephemeral fresh devices → cookie-ratio ≈ 0. When distinct-UA is
    -- high AND cookie-ratio is very low, fresh un-cookied identities on that IP are
    -- floored to CHALLENGE (engine) — never IP-banned. Challenge is the human/farm
    -- discriminator (humans solve once → cookie → exempt; farm devices don't).
    -- ratio_max=0.15 (not 0.20) is the lower-FP choice: only VERY low-cookie IPs
    -- trip it. Both tunable; action is challenge-only so mis-tune is low-cost.
    farm_ua_min           = 15,
    farm_cookie_ratio_max = 0.15,
    -- A logged-in multi-site admin managing their own domains has rich cookies.
    richness_max     = 0.5,   -- session_richness >= this → exempt
    -- Ban-if-repeat: flagged requests that never obtain a verified cookie (i.e.
    -- never solve the PoW challenge) accumulate strikes → direct ban:<ip>.
    strike_ban       = 12,    -- strikes (unsolved flagged reqs) before ban
    ban_ttl          = 300,   -- first ban 5 min
    ban_ttl_repeat   = 3600,  -- repeat offender 1 h
}

-- Expensive faceted-filter guard (l7/expensive_filter_guard.lua) — RESOURCE-keyed
-- combinatorial-crawl protection. Catches BOTH verified-bot path-filter crawl
-- (Meta `/loc-a,b,c.html`) and distributed-botnet query-filter crawl
-- (`?filter_attr=a.b.c`) at one point, because it meters per base-listing-path
-- across ALL callers (invariant to IP/UA/verified — the axes caller-keyed
-- defenses leak through). See l7/expensive_filter_guard.lua header.
-- Ngưỡng chốt từ shadow 24h (2026-07-08): người thật 1-3 combos/base/window,
-- good bot (đã loại khỏi meter) ~28-109, attack botnet 320-543. threshold=60 =
-- 20× biên trên người thật, dưới đáy mọi combinatorial crawl. exempt_richness
-- miễn 429 cho power-user đã đăng nhập. Revert nhanh: mode="shadow".
_M.expensive_filter = {
    mode             = "enforce", -- shadow (đo+log) | enforce (429) | off
    window           = 300,       -- HLL window giây (base tự phục hồi khi ngừng cào)
    min_values       = 4,         -- >= số giá-trị-con trong 1 field → faceted filter tốn kém
    combos_threshold = 45,        -- distinct combos / base / window → vượt budget (60→45, hạ để bắt sớm hơn; 30 nếu tải dư còn cao)
    exempt_richness  = 0.5,       -- session_richness >= this → miễn 429/ban (vẫn được đếm)
    retry_after      = 120,       -- 429 Retry-After
    -- Ban 24h — CHỈ theo bằng chứng PER-IP, KHÔNG theo trip resource-aggregate.
    -- 429 fire khi base vượt budget (gộp mọi caller) → user thật lỡ ghé listing
    -- đang bị cào cũng dính 429, TUYỆT ĐỐI không được ban họ. Ban chỉ khi MỘT IP
    -- tự nó đóng góp >= ban_ip_combos distinct combo trong 1 window (crawler tập
    -- trung bất khả chối; người thật 1-3). Distributed 1-req/IP swarm ~1 combo/IP
    -- → không chạm ngưỡng → KHÔNG ban được (đúng thiết kế), giữ nguyên 429.
    -- MẶC ĐỊNH FALSE — chế độ CHỈ ĐO. Counter per-IP vẫn chạy và `xf_ipcombos`
    -- vẫn vào antibot.log, nhưng không ban ai. Lý do: ngưỡng 20 dưới đây suy ra
    -- từ số liệu AGGREGATE của đợt shadow, chưa từng có phân bố PER-IP thật; mà
    -- công cụ để đo phân bố đó nằm chung trong chính gói này. Bật một cơ chế
    -- trừng phạt 24h ở ngưỡng chưa ai nhìn thấy dữ liệu là sai thứ tự.
    -- Hiệu chỉnh rồi mới bật:
    --   grep -oP 'xf_ipcombos=\K\d+' /var/log/antibot/antibot.log | sort -n | uniq -c
    ban_enabled      = false,     -- true = ban 24h; false = chỉ 429 + đo
    ban_ip_combos    = 20,        -- distinct combo / IP / base / window → IP tự tố là crawler
    ban_ttl          = 86400,     -- 24h
}

-- Fleet Detection (Distributed Web Scraping with Rotating IP Fleet).
--
-- Active subnet-level detection. Three independent axes aggregated into a
-- single confidence score in [0,1]:
--
--   fp_poverty       (weight 0.6) — distinct_IPs / distinct_fingerprints
--                                   ratio. Bot fleet rotate IPs cheaper than
--                                   fingerprints → high ratio. Real users
--                                   ratio ~1 (each IP = unique device).
--   path_convergence (weight 0.25) — share of top-3 paths over total hits.
--                                    Bots target few endpoints; real users
--                                    spread.
--   cookie_vacuum    (weight 0.15) — fraction without verified cookie nor
--                                    any cookie. Bots zero; real users mixed.
--
-- Final score = fp_poverty*0.6 + path_convergence*0.25 + cookie_vacuum*0.15
--   > thresholds.confirm → confirmed fleet
--   > thresholds.suspect → suspect, eligible for /16 roll-up
--   < suspect            → ignored
--
-- /16 roll-up: when ≥ rollup.min_24s_per_16 distinct /24 inside same /16
-- are confirmed in the same window → /16 marked confirmed too.
--
-- Modes (rollout knob, edit here + reload):
--   "shadow"  — aggregate Redis + write flags, DO NOT affect scoring/blocking.
--               Operator observes dashboard candidates to tune thresholds.
--   "scoring" — confirm/suspect contribute weight into ctx.score (engine
--               handles via per-request scoring pipeline).
--   "enforce" — sustained confirm ≥ enforce.sustained_minutes → auto write
--               dynamic block key; subsequent requests from that /24 (or /16
--               on roll-up) → immediate 403.
--
-- trusted_asn: ASN allowlist that SKIPS aggregation entirely (performance —
-- VN consumer ISPs have huge legitimate traffic; skipping saves Redis ops).
-- Detection correctness is independent of this list — false negatives if a
-- listed ASN turns out to host a bot fleet are acceptable in v1.
_M.fleet_detection = {
    mode = "enforce",

    weights = {
        fp_poverty       = 0.6,
        path_convergence = 0.25,
        cookie_vacuum    = 0.15,
    },

    thresholds = {
        suspect  = 0.5,
        confirm  = 0.7,

        -- Slow path: previous CLOSED 5-min bucket. Statistically reliable
        -- but ~5-6 min latency from attack start to first dyn block.
        min_hits     = 20,    -- /24 floor over 5-min closed bucket
        min_hits_16  = 30,    -- /16 floor over 5-min closed bucket

        -- Fast path: CURRENT (still-filling) bucket. Higher floors so
        -- partial-bucket data stays statistically meaningful, bypasses
        -- sustained counter — fires dyn block on first confirm. Cuts
        -- detection latency from ~5 min down to 30-90s for heavy attacks
        -- (target: < 2 min for any attack pushing PHP-FPM into overload).
        --
        -- FP safety: fp_poverty axis (weight 0.6) is the actual
        -- discriminator. Real CGNAT NAT pools with diverse devices keep
        -- distinct_fp high → fp_poverty ~0 regardless of hit count.
        -- min_hits is only a floor for compute, not a confidence trigger.
        min_hits_fast    = 80,   -- /24 floor over current partial bucket
        min_hits_16_fast = 50,   -- /16 floor over current partial bucket
    },

    rollup = {
        min_24s_per_16 = 3,
    },

    timing = {
        bucket_ttl       = 900,   -- Redis bucket retention (15 min = 3 buckets)
        flag_ttl         = 600,   -- /24 + /16 flag TTL (10 min)
        dyn_block_ttl    = 3600,  -- dynamic block TTL when enforce mode (1h)
        evaluator_period = 30,    -- timer interval (analyzer dedups internally)
    },

    scoring = {
        weight_suspect = 25,
        weight_confirm = 50,
    },

    enforce = {
        -- Semantics: consecutive closed 5-min buckets that stay "confirm".
        -- 1 = fire dynamic block on FIRST confirmed bucket (lowest latency,
        -- 5-6 minutes from attack start to block). Raise for more
        -- conservative behaviour (each unit = +5 min latency).
        sustained_minutes = 1,
    },

    -- Empty by default — every request from every ASN goes through the
    -- aggregator. Adds ~0.5 ms / request (single Redis pipeline) but keeps
    -- detection 100% data-driven with no operator-curated blind spots.
    -- Populate later from real log analysis if Redis load becomes a
    -- bottleneck (top-N ASNs by verified-cookie hit volume = candidates).
    trusted_asn = {},
}

_M.cluster = {
    ua_baseline_threshold_mult = 10,
    subnet_diversity_nat_max   = 3,
    nat_discount_factor        = 0.4,
    baseline_ua_score_cap      = 0.4,
    ua_count_normalize_max     = 500,
    ip_count_normalize_max     = 200,
    uri_count_normalize_max    = 100,
}

-- Shared-session-key guard. `sess:<fp_light>` là khoá của session+graph, mà
-- fp_light = md5(ip + ua_thô + asn + ja3) — TOÀN thuộc tính (mạng +
-- trình duyệt). Văn phòng dùng image đồng nhất (cùng IP, cùng bản Chrome,
-- ja3 luôn = NO_JA3 ở kiến trúc no-stream) → mọi máy COLLAPSE về một fp_light
-- → session của nhiều người bị trộn làm một. `detect_loop` trong graph bắn 0.9
-- khi 1 URI lặp >=4 lần trong 10 request cuối — phiên trộn LUÔN thoả điều kiện
-- đó → graph_flag(20) + session_flag(20) sinh tới ~38 điểm GIẢ, không từ hành vi.
--
-- Bộ dò: đếm distinct cookie-set cùng dùng một sess:<fp> (HLL). Người thật mỗi
-- người một session cookie → đếm cao. Bot fleet dùng chung fp thường không có
-- cookie → md5("") giống nhau → đếm = 1 → signal VẪN chạy (không tạo FN).
-- KHÔNG dùng ctx.ip_shared được: nó = distinct-UA >= 6, mà văn phòng đồng nhất
-- chỉ có 1 UA → không bao giờ fire.
-- clients_min=4 thận trọng: cookie của MỘT người cũng đổi vài lần trong window
-- (đăng nhập, thêm giỏ hàng) → 2-3 trạng thái là bình thường.
--
-- ĐO THỰC TẾ 2026-07-31 (55k request) — GIẢ THUYẾT KHÔNG ĐƯỢC XÁC NHẬN:
--   54040 sclients=1 | 1305 =2 | 44 =3 | chỉ 19 request có >=4 (0.034%)
--   Bảng top-signal: graph_flag KHÔNG xuất hiện lần nào, session_flag chỉ 0.8%.
--   → Tiền đề "phiên trộn sinh ~38 điểm FP" SAI trên traffic này.
--
-- Và bộ dò có CHẾ ĐỘ HỎNG: site set cookie mới mỗi response → Cookie header đổi
-- giá trị → sclients tăng 1/request cho CÙNG một client (quan sát: 1 id, 1 IP,
-- 17 giây, sclients 4→8, richness bò 0.40→0.50 cùng lúc). Hậu quả là FN: một bot
-- Chrome/60 Android (richness=0, score 125.8) đạt sclients=7 → session_flag +
-- graph_flag bị zero cho chính con bot đó.
--
-- → enforce=false: GIỮ phép đo (rẻ, 3 op trong pipeline sẵn có, dùng để hiệu
--   chỉnh sau) nhưng KHÔNG còn tác động lên scoring. Bật lại chỉ khi có bằng
--   chứng phiên bị trộn thật VÀ bộ dò đã miễn nhiễm cookie-churn (ví dụ hash
--   TÊN cookie thay vì giá trị, hoặc đếm distinct identity thay vì cookie-set).
_M.session_shared = {
    enabled     = true,   -- đo + log sclients/sshared (không ảnh hưởng điểm)
    enforce     = false,  -- true = zero session_flag+graph_flag khi sshared
    clients_min = 4,      -- distinct cookie-set / sess:<fp> / window → coi là khoá dùng chung
    window      = 300,    -- giây
}

_M.pow = {
    difficulty       = "000",
    challenge_secret = "c516565b589841e4a540c309ed301f83",
}

_M.fp_quality_threshold = 0.55

-- Cross-server IP intelligence network.
-- enabled=false by default — requires explicit configuration of redis.host.
-- When enabled: on confirmed block (action=block, eff_score>=60, new detection)
-- intel_reporter writes iprep:known_bad:<ip> to Central Redis (TTL 7 days).
-- iprep.check reads this on every non-banned IP (1h local cache).
-- Fail open: Central Redis unreachable → ctx.ext_rep=0, pipeline continues.
_M.intel = {
    enabled         = false,
    redis = {
        host         = "",        -- Central Redis host (empty = skip even if enabled)
        port         = 6379,
        timeout      = 200,       -- ms, fail fast to avoid request latency impact
        pool_size    = 5,         -- low frequency operations, small pool
        pool_idle_s  = 30,
        password     = "",        -- empty = no auth
        db           = 1,         -- separate DB from local Redis (DB 0)
    },
    min_score       = 60,         -- safety guard (BLOCK already implies eff>=80)
    report_ttl      = 86400,      -- 1 report/IP/24h rate limit
    known_bad_ttl   = 604800,     -- 7-day persistence in Central Redis
    local_cache_ttl = 3600,       -- 1h local cache of ext_rep per IP
    server_id       = "server01", -- unique identifier per server for log attribution
}

-- Beacon JS injection endpoint.
-- Must match the nginx location{} that routes to beacon_handler.handle().
-- Change here + change nginx location name to obfuscate from scrapers.
_M.beacon = {
    endpoint = "/antibot/beacon",
}

-- So ten cookie ma TUNG HOST thuc su cap phat (core/cookie_registry.lua).
--
-- `enabled = false` la CONG TAC TAT: `learn` ngung ghi, `known` luon tra `nil`,
-- nen ca cong tin cay lan mien tru ban IP quay ve dung hanh vi truoc GD 2.
-- Thieu cong tac nay la thieu sot cua ban dau (2026-09-12): mot thay doi o
-- duong TIN CAY ma muon vo hieu phai sua ma roi deploy lai — qua cham khi dang
-- co su co that.
_M.cookie_registry = {
    enabled = true,

    -- So ten toi thieu trong so truoc khi `known()` duoc phep tra `false`.
    --
    -- Loi hoc-tung-phan, do duoc tren bestcargo.vn 2026-09-12: so moi hoc duoc
    -- DUNG MOT ten (`wp-saving-post`), nen cookie dang nhap that cua admin
    -- khong khop gi ca. `false` khi do KHONG co nghia "cookie ngoai lai" ma chi
    -- la "khong khop ten nao ta TINH CO hoc duoc". Duoi nguong nay `known()`
    -- tra `nil` thay vi `false`.
    --
    -- CHI chan cau tra loi `false`. Mot lan khop van tra `true` ngay ca khi so
    -- con non: do la bang chung DUONG TINH that, khong can so dong.
    min_names = 3,

    -- Mien tao `ban:<ip>` cho phien co bang chung (enforcement/ban/
    -- ban_store_write.lua). Dat `false` de tat rieng phan nay ma van giu cong
    -- tin cay.
    ip_ban_exempt = true,

    -- Nguong richness cua CHINH request cho mien tru tren. Phai khop
    -- AUTH_SESSION_RICHNESS trong enforcement/decision/engine.lua.
    richness_min = 0.5,
}

-- Tran cho ASN duoc phan loai `vpn` (intelligence/threat/asn_reputation.lua).
--
-- VI SAO CAN. `threat_feed_sync.sh` ghi hai bac:
--     datacenter -> rep:asn: = 0.45   (x35 = 15,75 diem tho)
--     vpn        -> rep:asn: = 0.75   (x35 = 26,25 diem tho)
-- Tuc he thong dang coi VPN DANG NGO HON datacenter. Do la SAI THU TU, khong
-- phai mot con so to: mot egress VPN tieu dung cho phan lon la NGUOI THAT, con
-- mot IP datacenter chay UA trinh duyet thi kha nang tu dong hoa cao hon han.
--
-- 26,25 diem la gan mot nua nguong CHALLENGE (55). Nguoi dung VPN bat dau o do
-- truoc khi lam bat cu viec gi — cong them mot tin hieu nho nua la bi thu thach.
-- Tren ha tang co khach dung VPN/WARP pho bien, do la nguon chan nham CO HE
-- THONG.
--
-- TRAN chu khong phai HE SO NHAN: he so nhan van troi theo feed, con tran thi
-- giu nguyen y nghia du nguon doi 0.75 thanh bao nhieu. Va no phai nam DUOI bac
-- datacenter de thu tu khong bao gio dao lai lan nua.
--
-- Day KHONG phai mien tru: VPN van la mot tien nghiem hop le, chi la tien
-- nghiem YEU. Bang chung truc tiep ve chinh client van do cac tang khac lo.
_M.asn_rep = {
    vpn_max = 0.30,   -- x35 = 10,5 diem tho, thap hon bac datacenter 15,75
}

-- Dia chi cua chinh may KHONG khai o day. `nginx/deploy.sh` sinh chung tai cho
-- tren tung may vao `conf/antibot/self_addrs.txt`, va `core/ip_scope.lua` doc
-- file do. Ly do: `config.lua` deploy CHUNG cho ca dan may, nen khai tay se bat
-- moi may mang danh sach IP cua moi may khac — va may thu sau lai phai sua tay
-- lan nua.

_M.debug = false

function _M.endpoint_sens(uri)
    if not uri then return _M.endpoint_sensitivity.default end
    for pattern, sens in pairs(_M.endpoint_sensitivity) do
        if pattern ~= "default" and uri:find(pattern, 1, true) then
            return sens
        end
    end
    return _M.endpoint_sensitivity.default
end

return _M
