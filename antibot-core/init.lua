local _M = {}

local classifier         = require "antibot.core.req_classifier"
local ctx_layer          = require "antibot.core.ctx"
local session_richness   = require "antibot.core.session_richness"
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
local detection_layer    = require "antibot.detection"
local bot_lite_verify    = require "antibot.detection.bot.lite_verify"
local res_ip_counter     = require "antibot.l7.rate.res_ip_counter"
local intelligence_layer = require "antibot.intelligence"
local enforcement_layer  = require "antibot.enforcement"
local risk_update        = require "antibot.async.risk_update"
local adaptive_weight    = require "antibot.async.adaptive_weight"
local intel_reporter     = require "antibot.async.intel_reporter"
local logger             = require "antibot.async.logger"
local pool               = require "antibot.core.redis_pool"

local STEPS_COMMON = {
    { layer = ctx_layer,         fn = "init"          },
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
    { layer = ip_ban_check,      fn = "run"           },
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
    -- expensive_filter_guard: RESOURCE-keyed combinatorial-crawl meter. Runs
    -- here so it sees EVERY caller (before the good_bot/verified short-circuit
    -- after COMMON) and after session_richness/access (richness+whitelist known).
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

local STEPS_RESOURCE = {
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
    { layer = intelligence_layer, fn = "run" },
    { layer = enforcement_layer,  fn = "run" },
}

local function run_steps(steps, ctx)
    for i, step in ipairs(steps) do
        local ok, exit = step.layer[step.fn](ctx)
        if exit == true then return end
        if ok == false and step.fatal then
            ngx.log(ngx.ERR, "[antibot] fatal error at step ", i)
            ngx.exit(500)
            return
        end
    end
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
        ctx.ip = ngx.var.remote_addr
        ctx.ua = ngx.var.http_user_agent or ""
        ctx.req = ctx.req or { uri = ngx.var.uri or "" }
        fleet.aggregate(ctx)
        ngx.log(ngx.DEBUG, "[antibot] cookie_fast_path id=", cookie)
        return true
    end

    return false
end

function _M.run()
    local ctx = ngx.ctx.antibot or {}
    ngx.ctx.antibot = ctx

    if check_verified_cookie(ctx) then return end

    classifier.run(ctx)
    run_steps(STEPS_COMMON, ctx)

    -- Short-circuit cho cả verified (PoW) và whitelisted (admin rule, LAN,
    -- loopback, url/ip whitelist…). Trước đây chỉ check verified → các
    -- whitelist khác vẫn tiếp tục vào l7 counter + detection + enforcement
    -- dù access layer đã "allow" → rate counter lên LAN IP oan (wp-cron).
    if ctx.verified or ctx.whitelisted then return end

    local class = ctx.req_class or "unknown"

    if class == "resource" then
        run_steps(STEPS_RESOURCE, ctx)
    elseif class == "interaction" then
        run_steps(STEPS_INTERACTION, ctx)
    else
        run_steps(STEPS_FULL_DETECTION, ctx)
    end
end

function _M.log()
    local ctx = ngx.ctx.antibot
    if not ctx then return end

    if ctx.req_class ~= "resource" and ctx.identity then
        ngx.timer.at(0, function()
            risk_update.run(ctx)
        end)
        ngx.timer.at(0, function()
            adaptive_weight.run(ctx)
        end)
    end

    -- Intel reporter: propagate confirmed blocks to Central Redis.
    -- qualifies() gates on action=block + reason not excluded + enabled config.
    if ctx.action == "block" then
        ngx.timer.at(0, function()
            intel_reporter.report(ctx)
        end)
    end

    logger.run(ctx)
end

function _M.init_worker()
    local mem_guard = require "antibot.async.memory_guard"
    mem_guard.start()

    -- Seed default good-bot DNS registry vào Redis (worker 0 only).
    -- core/data/goodbot.json đi cùng repo → git pull sync list.
    -- Admin override qua redis-cli SET không bị ghi đè.
    --
    -- PHẢI defer qua ngx.timer.at vì cosocket (Redis network) bị DISABLE
    -- trong init_worker_by_lua* context. Timer 0s = chạy ngay sau init_worker
    -- trong context cho phép cosocket.
    if ngx.worker.id() == 0 then
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
