local _M = {}

local classifier         = require "antibot.core.req_classifier"
local ctx_layer          = require "antibot.core.ctx"
local session_richness   = require "antibot.core.session_richness"
local proxy_origin       = require "antibot.core.proxy_origin"
local cookie_registry    = require "antibot.core.cookie_registry"
local fleet              = require "antibot.detection.fleet"
local fleet_check_block  = require "antibot.detection.fleet.check_block"
local ip_ban_check       = require "antibot.l7.ban.ip_ban_check"
local ip_tour            = require "antibot.detection.ip_tour"
local xfilter_guard      = require "antibot.l7.expensive_filter_guard"
local iprep              = require "antibot.core.iprep"
local asn_layer          = require "antibot.core.fingerprint.asn"
local device_classifier  = require "antibot.core.fingerprint.device_classifier"
local access_layer       = require "antibot.core.access"
local fingerprint_layer  = require "antibot.core.fingerprint"
local transport_layer    = require "antibot.transport"
local l7_layer           = require "antibot.l7"
local l7_admission       = require "antibot.l7.admission"
local l7_circuit         = require "antibot.l7.circuit_breaker"
local l7_surge           = require "antibot.l7.surge_guard"
local detection_layer    = require "antibot.detection"
local bot_lite_verify    = require "antibot.detection.bot.lite_verify"
local res_ip_counter     = require "antibot.l7.rate.res_ip_counter"
local intelligence_layer = require "antibot.intelligence"
local enforcement_layer  = require "antibot.enforcement"
local risk_update        = require "antibot.async.risk_update"
local intel_reporter     = require "antibot.async.intel_reporter"
local logger             = require "antibot.async.logger"
local waf_layer          = require "antibot.waf"
local waf_logger         = require "antibot.async.waf_logger"
local pool               = require "antibot.core.redis_pool"

-- Admission bat buoc cho MOI request, truoc verified/whitelist/resource exit.
-- Chi dung local shared dict + IP ban; khong chay detection/Redis rate pipeline.
local STEPS_ADMISSION = {
    { layer = ctx_layer,         fn = "init"          },
    { layer = classifier,        fn = "run_fast"      },
    { layer = proxy_origin,      fn = "run"           },
    { layer = l7_admission,      fn = "run"           },
    -- Per-host backend health gate.  Admission has already classified static
    -- hit vs dynamic/static-miss, so the breaker never penalizes real assets.
    { layer = l7_circuit,        fn = "before"        },
    -- Cheap early capacity gate.  The actual slot is acquired only after the
    -- request survives WAF/detection, immediately before content/upstream.
    { layer = l7_surge,          fn = "before"        },
    -- Redis ban lookup dung SAU local budget: flood tu mot IP da ban khong duoc
    -- phep bien thanh unlimited Redis traffic.
    { layer = ip_ban_check,      fn = "run"           },
}

local STEPS_COMMON = {
    -- asn: resolve ctx.asn (mmdb lookup, local, cheap) BEFORE the fleet
    -- aggregator so fleet's good-crawler exemption (trusted.is_good_crawler)
    -- can read the ASN. Previously asn.run ran only in the fingerprint layer
    -- (after class dispatch) → ctx.asn was nil at fleet time → fleet's ASN
    -- bypass silently never fired and legit crawler /16s got dyn-blocked.
    -- asn.run is idempotent, so the later fingerprint-layer call no-ops.
    { layer = asn_layer,         fn = "run"           },
    -- fleet: aggregate FIRST, BEFORE check_block. The analyzer must keep
    -- seeing fleet traffic that's already dyn-blocked, otherwise as soon
    -- as a dyn key fires, the bucket goes empty and the 1h dyn TTL
    -- expires with nothing to re-detect from — bot returns for the
    -- expiry gap, then cycle repeats. With aggregate-first, blocked
    -- requests keep refreshing the dyn key continuously while the
    -- attack continues, and the key only expires when the attack
    -- genuinely stops (bucket drops below min_hits naturally).
    --
    -- Cost: ~1 extra Redis RTT per blocked request (full 27-op
    -- pipeline). Acceptable: blocked traffic is small fraction of
    -- total once attack is identified.
    { layer = fleet,             fn = "run"           },
    -- fleet_check_block: GET fl:dyn:<cidr_24|16> — short-circuit 403 if
    -- the analyzer auto-promoted this subnet to a dynamic block.
    -- Runs AFTER aggregator so blocked traffic still counts (see above).
    { layer = fleet_check_block, fn = "run"           },
    -- session_richness: compute ctx.session_richness ∈ [0,1] từ cookie
    -- payload + auth header. Generic trust proxy (không phụ thuộc CMS).
    -- Đặt SỚM để mọi step sau (rate/burst/scoring) đọc được.
    { layer = session_richness,  fn = "run"           },
    -- proxy_origin + ip_ban_check da chay trong STEPS_ADMISSION, truoc moi
    -- fast-path. Vi vay ctx.ip/behind_proxy o day da la ket qua da sanitize.
    -- iprep: cross-server IP reputation check (Central Redis, 1h local cache).
    -- Runs after ip_ban_check so locally-banned IPs exit before reaching this.
    -- Sets ctx.ext_rep ∈ [0,1]; fails open (ext_rep=0) if Central Redis down.
    { layer = iprep,             fn = "check"         },
    { layer = device_classifier, fn = "run"           },
    { layer = access_layer,      fn = "run"           },
    -- ip_tour: cross-domain shared-hosting tour detector. Runs AFTER
    -- access_layer so ctx.whitelisted is known (LAN/admin skip counting) and
    -- AFTER session_richness (trust gate). Sets ctx.ip_tour; engine floors it
    -- to challenge after the good_bot_verified short-circuit (verified crawlers
    -- exempt). Strike counter here escalates repeat offenders to a direct ban.
    { layer = ip_tour,           fn = "run"           },
    -- expensive_filter_guard: RESOURCE-keyed combinatorial-crawl meter. Nhanh
    -- verified cung goi guard truoc khi thoat (khong co session lift); nhanh nay
    -- chay sau session_richness/access nen co them first-party FP protection.
    -- mode=shadow by default (đo+log, chưa chặn) — tune combos_threshold rồi bật
    -- enforce. Complements ip_tour (per-IP) + distributed_swarm (per-/24): the
    -- first axis keyed purely on the target resource, immune to IP/UA rotation.
    { layer = xfilter_guard,     fn = "run"           },
    { layer = transport_layer,   fn = "run"           },
}

local STEPS_FULL_DETECTION = {
    { layer = fingerprint_layer,  fn = "run", fatal = true },
    { layer = l7_layer,           fn = "run"               },
    { layer = detection_layer,    fn = "run"               },
    { layer = intelligence_layer, fn = "run"               },
    { layer = enforcement_layer,  fn = "run"               },
}

local STEPS_INTERACTION = {
    { layer = fingerprint_layer,  fn = "run", fatal = true },
    { layer = l7_layer,           fn = "run"               },
    { layer = detection_layer,    fn = "run"               },
    { layer = intelligence_layer, fn = "run"               },
    { layer = enforcement_layer,  fn = "run"               },
}

local STEPS_RESOURCE_PRE = {
    -- res_ip_counter ĐẦU TIÊN: tăng res_ip:<ip> để session_store.lua
    -- (chạy ở các class khác) đọc và verify IP có resource activity
    -- trước khi fire resource_starved. Không phụ thuộc identity (resource
    -- skip fingerprint nên ctx.identity = nil). 1 INCR + 1 EXPIRE rẻ.
    { layer = res_ip_counter,     fn = "run" },
    -- Lite bot verify TRƯỚC intelligence: chạy ua_check + asn lookup +
    -- ASN match (cached, rẻ). Set good_bot_verified=true cho Googlebot/Bingbot
    -- fetch image → engine bypass scoring → không bị kill_block FP. Skip
    -- DNS reverse (đắt) — ASN match đủ tin vì RIR delegation chỉ cho IP owner.
    { layer = bot_lite_verify,    fn = "run" },
}

local STEPS_RESOURCE_FINAL = {
    { layer = intelligence_layer, fn = "run" },
    { layer = enforcement_layer,  fn = "run" },
}

local function run_steps(steps, ctx)
    for i, step in ipairs(steps) do
        local ok, exit = step.layer[step.fn](ctx)
        if exit == true then return true end
        if ok == false and step.fatal then
            ngx.log(ngx.ERR, "[antibot] fatal error at step ", i)
            ngx.exit(500)
            return true
        end
    end
    return false
end

local function check_verified_cookie(ctx)
    local cookie = ngx.var.cookie_antibot_fp
    if not cookie or cookie == "" then return false end

    local verified = pool.safe_get("verified:" .. cookie)
    if verified == "1" then
        ctx.verified = true
        ctx.identity = cookie
        ctx.fp_light = cookie
        -- Populate minimal ctx so fleet aggregator can record this hit as
        -- a verified observation (raises verified_count in the /24 bucket,
        -- which lowers cookie_vacuum → keeps real-user subnets below the
        -- fleet trigger threshold).
        -- ctx da duoc khoi tao boi STEPS_ADMISSION; khong ghi de IP da sanitize.
        ctx.ip = ctx.ip or ngx.var.remote_addr
        ctx.ua = ctx.ua or ngx.var.http_user_agent or ""
        ctx.req = ctx.req or { uri = ngx.var.uri or "" }
        fleet.aggregate(ctx)
        ngx.log(ngx.DEBUG, "[antibot] cookie_fast_path id=", cookie)
        return true
    end

    return false
end

-- Có tín hiệu WAF nào đủ sức lật cửa thoát tin cậy không.
--
-- MỘT nguồn sự thật cho cả hai cửa bên dưới.
--
-- TIÊU CHÍ VÀO DANH SÁCH NÀY LÀ TRỌNG SỐ, KHÔNG PHẢI "có phải tín hiệu WAF".
-- Chỉ tín hiệu có `DEFAULT_WEIGHTS > 0` mới được vào. Tín hiệu trọng số 0 đang
-- ở chế độ quan sát: nó phải KHÔNG đổi gì trong hành vi hệ thống, kể cả luồng
-- đi của request.
--
-- Vì sao ranh giới nằm đúng ở đó. Bản `3a99bdc` để `waf_arg` (trọng số 0) trong
-- danh sách này, và hậu quả không phải là chi phí — nó đầu độc chính phép đo mà
-- chế độ quan sát sinh ra để phục vụ. Một client có cookie verified gửi
-- `?f=../x` mất fast-path, chạy hết pipeline, rồi bị một tín hiệu KHÁC đưa lên
-- challenge. waf.log ghi `rule=arg_traversal ... final=challenge`, đọc lên
-- tưởng luật gây FP — trong khi nó cộng 0 điểm. Nhưng cũng không vô can: không
-- có luật thì request đã `allow`. Luật đổi phán quyết qua đường ĐỔI LUỒNG chứ
-- không qua điểm số, và cột `final=` vốn thêm vào để chống lệch lại là chỗ lệch.
--
-- `contract_test.lua` kiểm HAI CHIỀU theo trọng số, nên danh sách này không còn
-- phải nhớ bằng tay: quên nối một tín hiệu có trọng số → chiều một báo đỏ; để
-- sót một tín hiệu trọng số 0 ở đây → chiều hai báo đỏ. Ngày nâng `waf_arg` lên
-- khỏi 0, sửa `compute.lua` rồi chạy `[3b]` là biết phải thêm gì vào đây.
--
-- `ctx.waf_body_php` có mặt ở đây từ 2026-09-12. Chú thích cũ tại đúng dòng này
-- ghi "KHÔNG gộp `ctx.waf_body` vào đây: đó là telemetry thuần, không phải tín
-- hiệu" — đúng vào ngày nó được viết, và sai kể từ lúc `<?php` trong thân có
-- trọng số 50. Nếu không nối, một client đã giải PoW cứ thế POST mã PHP và cả
-- tầng WAF không thấy gì: đúng lỗ hổng mà tầng này sinh ra để bịt.
local function waf_signal(ctx)
    if ctx.waf_wp_path then return ctx.waf_wp_path end
    return ctx.waf_body_php
end

-- Acquire a dynamic in-flight slot at the last common point before content.
-- Keeping this separate from STEPS_ADMISSION is intentional: a request that
-- WAF/challenge/ban terminates must never look like backend concurrency.
local function admit_dynamic(ctx)
    local _, exit = l7_surge.admit(ctx)
    return exit == true
end

function _M.run()
    local ctx = ngx.ctx.antibot or {}
    ngx.ctx.antibot = ctx

    -- Phanh cuc bo chay truoc body scan/Redis-heavy pipeline. Neu dat WAF truoc,
    -- flood POST lon van doc/scan body xong roi moi bi 429 — dung nguoc muc tieu
    -- capacity protection. WAF van o truoc moi trust exit ben duoi.
    if run_steps(STEPS_ADMISSION, ctx) then return end

    -- WAF chạy TRƯỚC cả hai cửa thoát tin cậy bên dưới, không phải sau.
    -- Cookie `antibot_fp` còn hạn là thoát sạch pipeline trong 7200s; với quản
    -- lý bot đó là đúng, với WAF thì đó là 2 giờ upload không ai soi. Lý do đầy
    -- đủ nằm ở khối chú thích đầu `waf/init.lua`.
    if waf_layer.run_pre(ctx) then return end

    -- `run_pre` CHỈ trả true ở nhánh block. Luật `signal` đặt `ctx.waf_wp_path`
    -- rồi trả false — và nếu để dòng dưới thoát sớm thì `compute.lua` không bao
    -- giờ đọc tới: tín hiệu vẫn vào waf.log nhưng không tác động gì tới phán
    -- quyết. Tức là chạy trước cửa tin cậy chỉ cứu được hard-block, còn signal
    -- thì vẫn bị che đúng như cũ.
    --
    -- Nên tín hiệu WAF vô hiệu hoá fast-path: bằng chứng về NỘI DUNG được quyền
    -- lật một lối tắt dựa trên DANH TÍNH. Cookie kia chỉ chứng minh client đã
    -- giải một PoW `difficulty = "000"` — vài chục ms với trình duyệt, và với
    -- kẻ tấn công là 7200s soi-không-tới nếu không có điều kiện này.
    -- Gọi qua `waf_signal(ctx)` chứ KHÔNG so thẳng `not ctx.waf_wp_path`: danh
    -- sách tín hiệu nào đủ tư cách lật cửa này thuộc về một chỗ duy nhất, và
    -- tiêu chí của nó là trọng số — xem khối chú thích của `waf_signal` ở trên.
    --
    -- Hàm gom lại cũng để lần sau nâng một tín hiệu WAF lên khỏi trọng số 0 thì
    -- chỉ phải sửa MỘT chỗ, chứ không phải nhớ ra hai cửa thoát nằm cách nhau
    -- 15 dòng. `f9124a3` đã quên đúng chuyện đó với `waf_arg`.
    local verified = check_verified_cookie(ctx)
    if verified and not waf_signal(ctx) then
        -- Verification khong phai quyen enumerate vo han mot faceted endpoint.
        -- Guard tu tra ngay, khong cham Redis, neu URL khong co multi-value
        -- signature; do do van giu duoc fast-path cho traffic thong thuong.
        local _, xf_exit = xfilter_guard.run(ctx)
        if xf_exit then return end
        admit_dynamic(ctx)
        return
    end

    -- Full classifier co the doc body form-urlencoded de tim auth semantic.
    -- Chi request khong thoat verified moi tra chi phi nay.
    classifier.run(ctx)
    if run_steps(STEPS_COMMON, ctx) then return end

    -- Short-circuit cho cả verified (PoW) và whitelisted (admin rule, LAN,
    -- loopback, url/ip whitelist…). Trước đây chỉ check verified → các
    -- whitelist khác vẫn tiếp tục vào l7 counter + detection + enforcement
    -- dù access layer đã "allow" → rate counter lên LAN IP oan (wp-cron).
    --
    -- `waf_wp_path` vô hiệu cửa này với cùng lý lẽ ở trên, nhưng CHỈ với
    -- `verified`. `whitelisted` là quyết định tường minh của người vận hành
    -- (admin rule, LAN, loopback, ip/url whitelist) và WAF không lật quyết định
    -- đó — ranh giới có nguyên tắc, không phải chỗ nào cũng ép.
    if ctx.whitelisted then
        admit_dynamic(ctx)
        return
    end
    if ctx.verified and not waf_signal(ctx) then
        admit_dynamic(ctx)
        return
    end

    local class = ctx.req_class or "unknown"
    local exited = false

    if class == "resource" then
        if run_steps(STEPS_RESOURCE_PRE, ctx) then return end
        -- Claimed crawler ma lite ASN khong xac minh duoc phai di full lane.
        -- Khong duoc giu bot_score=0 roi vao thang resource enforcement.
        if ctx.bot_lite_needs_full then
            exited = run_steps(STEPS_FULL_DETECTION, ctx)
        else
            exited = run_steps(STEPS_RESOURCE_FINAL, ctx)
        end
    elseif class == "interaction" then
        exited = run_steps(STEPS_INTERACTION, ctx)
    else
        exited = run_steps(STEPS_FULL_DETECTION, ctx)
    end

    if not exited then admit_dynamic(ctx) end
end

function _M.log()
    local ctx = ngx.ctx.antibot
    if not ctx then return end

    -- Shared-dict only: legal directly in log phase (unlike Redis/cosocket).
    -- Release the in-flight slot before logging; circuit learning then records
    -- the completed upstream outcome.  Both expose their elected sample or
    -- transition in this same antibot.log line.
    l7_surge.after(ctx)
    l7_circuit.after(ctx)

    if ctx.req_class ~= "resource" and ctx.identity then
        ngx.timer.at(0, function()
            risk_update.run(ctx)
        end)
        -- `adaptive_weight.run(ctx)` ĐÃ GỠ (2026-09-06). Chết hai lần:
        --   1. Chữ ký là `run(ctx, feedback)` và dòng đầu là
        --      `if not feedback then return end`. Chỗ gọi DUY NHẤT là dòng này,
        --      và nó **không truyền `feedback`** ⇒ thoát ngay, mọi lần, từ đầu.
        --   2. Kể cả nếu chạy, nó ghi `model:weight` trong Redis — mà
        --      `compute.lua` dùng thẳng `DEFAULT_WEIGHTS`, không đọc khoá đó.
        -- Gỡ đi bớt được MỘT `ngx.timer.at` cho mỗi request non-resource.
    end

    -- Intel reporter: propagate confirmed blocks to Central Redis.
    -- qualifies() gates on action=block + reason not excluded + enabled config.
    if ctx.action == "block" then
        ngx.timer.at(0, function()
            intel_reporter.report(ctx)
        end)
    end

    -- Hoc ten cookie ma host nay cap phat. PHAI o log phase: day la noi duy
    -- nhat doc duoc `Set-Cookie` cua phan hoi. Ban than ham tu defer moi phep
    -- cham Redis qua `ngx.timer.at` vi cosocket bi CAM o day.
    cookie_registry.learn(ctx)

    logger.run(ctx)
    -- run_log TRƯỚC waf_logger: nó điền `ctx.waf_target_exists` mà waf.log đọc,
    -- và là nơi DUY NHẤT đánh dấu host là WordPress (access phase chỉ đọc cờ đó).
    waf_layer.run_log(ctx)
    waf_logger.run(ctx)
    -- Dòng đo body ghi RIÊNG, nhãn `[waf-body]`. Nó bắn cho mọi POST soi được,
    -- còn `run` ở trên chỉ bắn khi có luật khớp — hai dân số khác hẳn nhau nên
    -- không gộp chung định dạng.
    waf_logger.run_body(ctx)
end

function _M.init_worker()
    local mem_guard = require "antibot.async.memory_guard"
    mem_guard.start()

    -- Nap cau hinh runtime cua WAF V2.
    --
    -- MOI WORKER, khong phai chi worker 0: `waf/init.lua` giu `compiled_config` o
    -- cap module, tuc mot ban RIENG trong tung tien trinh worker. Goi o worker 0
    -- thi cac worker khac van chay mac dinh, va lua luong se chia doi giua hai
    -- chinh sach — dung loai lech am tham khong the doc ra tu log.
    --
    -- Thieu buoc nay thi co che per-domain/exception/profile chi TON TAI trong ma
    -- nguon chu khong co hieu luc: do la trang thai truoc 25-09, mot lop cau hinh
    -- trong nhu da chay. `waf.configure()` chi duoc test goi, khong noi nao khac.
    --
    -- `pcall` vi file cau hinh la thu NGUOI VAN HANH SUA: mot dau phay thieu
    -- khong duoc lam nginx khong khoi dong duoc. Khi no hong thi WAF chay mac
    -- dinh — an toan hon ban cau hinh moi theo dinh nghia, vi mac dinh la thu da
    -- chay tren dan may.
    --
    -- KHONG dung `ngx.timer.at`: `configure()` khong cham Redis lan DNS, no chi
    -- doc mot bang Lua. Defer no se de mot khoang thoi gian dau doi worker chay
    -- bang cau hinh mac dinh, va khoang do khong quan sat duoc.
    do
        local ok_cfg, runtime = pcall(require, "antibot.waf.runtime_config")
        if not ok_cfg then
            ngx.log(ngx.ERR, "[waf-v2] config: khong nap duoc ",
                    "waf/runtime_config.lua, dung MAC DINH: ", tostring(runtime))
        else
            local ok_ap, errors = waf_layer.configure(runtime)
            if not ok_ap then
                -- Ghi TUNG loi, khong gop: mot dong "cau hinh sai" khong noi
                -- duoc sai o dau, va nguoi doc log la nguoi vua sua file do.
                local list = type(errors) == "table" and errors or { tostring(errors) }
                for i = 1, #list do
                    ngx.log(ngx.ERR, "[waf-v2] config: ", tostring(list[i]))
                end
                ngx.log(ngx.ERR, "[waf-v2] config: GIU cau hinh cu (mac dinh). ",
                        "Khong ap mot phan nao — sua file roi reload.")
            end
        end
    end

    -- Seed default good-bot DNS registry vào Redis (worker 0 only).
    -- core/data/goodbot.json đi cùng repo → git pull sync list.
    -- Admin override qua redis-cli SET không bị ghi đè.
    --
    -- PHẢI defer qua ngx.timer.at vì cosocket (Redis network) bị DISABLE
    -- trong init_worker_by_lua* context. Timer 0s = chạy ngay sau init_worker
    -- trong context cho phép cosocket.
    if ngx.worker.id() == 0 then
        -- Tạo sẵn waf.log để sự vắng mặt của nó có nghĩa duy nhất là "hỏng",
        -- không phải "chưa có luật nào bắn". KHÔNG defer: file I/O thường,
        -- không phải cosocket. Chạy ở đây nên mỗi `nginx -s reload` cũng dựng
        -- lại file nếu ai đó lỡ xoá.
        waf_logger.ensure()

        local ok, err = ngx.timer.at(0, function(premature)
            if premature then return end
            local ok2, seed = pcall(require, "antibot.core.goodbot_seed")
            if ok2 and seed and seed.run then
                local ok3, serr = pcall(seed.run)
                if not ok3 then
                    ngx.log(ngx.ERR, "[goodbot_seed] run error: ", tostring(serr))
                end
            end
        end)
        if not ok then
            ngx.log(ngx.ERR, "[init_worker] timer.at failed: ", tostring(err))
        end

        -- Fleet detection analyzer timer — periodic 3-axis evaluation of
        -- previous-minute /24 buckets. Worker 0 only to avoid N-way
        -- duplicate evaluation across worker processes. Deferred via
        -- timer.at(0) for the same cosocket-disabled-in-init_worker reason.
        local ok_fl, err_fl = ngx.timer.at(0, function(premature)
            if premature then return end
            local ok2 = pcall(fleet.start_timer)
            if not ok2 then
                ngx.log(ngx.ERR, "[fleet.timer] start failed")
            end
        end)
        if not ok_fl then
            ngx.log(ngx.ERR, "[init_worker] fleet timer.at failed: ", tostring(err_fl))
        end
    end
end

return _M
