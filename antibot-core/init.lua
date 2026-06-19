local _M = {}

local classifier         = require "antibot.core.req_classifier"
local ctx_layer          = require "antibot.core.ctx"
local session_richness   = require "antibot.core.session_richness"
local subnet_block       = require "antibot.core.access.subnet_block"
local ip_ban_check       = require "antibot.l7.ban.ip_ban_check"
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
local logger             = require "antibot.async.logger"
local pool               = require "antibot.core.redis_pool"
local cfg                = require "antibot.core.config"

local STEPS_COMMON = {
    { layer = ctx_layer,         fn = "init"          },
    -- subnet_block: deterministic CIDR block list for empirically-confirmed
    -- pure-bot subnets (cfg.subnet_block). Runs EARLY (after ctx populated,
    -- before any Redis ops) to short-circuit bot traffic at minimum cost.
    -- Pure bit ops on pre-parsed CIDR tuples — zero Redis, sub-microsecond.
    { layer = subnet_block,      fn = "run"           },
    -- session_richness: compute ctx.session_richness ∈ [0,1] từ cookie
    -- payload + auth header. Generic trust proxy (không phụ thuộc CMS).
    -- Đặt SỚM để mọi step sau (rate/burst/scoring) đọc được.
    { layer = session_richness,  fn = "run"           },
    { layer = ip_ban_check,      fn = "run"           },
    { layer = device_classifier, fn = "run"           },
    { layer = access_layer,      fn = "run"           },
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

-- Cookie fast-path with anti-sharing defense.
--
-- Bot scrapers solve PoW once, capture the verified cookie, then replay
-- across many IPs to bypass detection (35-IP distributed attack from
-- 43.172.0.0/15 observed 2026-06-18). Defense: track distinct source IPs
-- per cookie in Redis SET `cookie_ips:<cookie>` (TTL 86400s). When the
-- set grows past `cfg.cookie.max_ips_per_cookie`, the cookie is treated
-- as shared and revoked (DEL verified:<cookie> + DEL cookie_ips:<cookie>),
-- forcing re-challenge. Real users stay under threshold 3 normally.
local function check_verified_cookie(ctx)
    local cookie = ngx.var.cookie_antibot_fp
    if not cookie or cookie == "" then return false end

    local verified = pool.safe_get("verified:" .. cookie)
    if verified ~= "1" then return false end

    -- Cookie marked verified by PoW solve. Now enforce anti-sharing.
    -- ctx.ip is not yet populated (ctx_layer.init runs later) — read ngx.var directly.
    local ip = ngx.var.remote_addr
    if not ip or ip == "" then
        -- No source IP available — fail open to legacy fast-path behavior
        ctx.verified = true
        ctx.identity = cookie
        ctx.fp_light = cookie
        return true
    end

    local max_ips = cfg.verified_share.max_ips_cookie
    local ttl     = cfg.verified_share.ip_tracking_ttl
    local ips_key = "verified_ips:cookie:" .. cookie

    -- Atomic batch: SADD ip + refresh TTL + read distinct count = 1 RTT
    local results = pool.pipeline(function(red)
        red:sadd(ips_key, ip)
        red:expire(ips_key, ttl)
        red:scard(ips_key)
    end)

    local distinct = 1
    if results and results[3] then
        distinct = tonumber(results[3]) or 1
    end

    if distinct > max_ips then
        -- Cookie shared across too many IPs -> revoke verification.
        -- Bot fleet must now re-solve PoW per IP (defeats the bypass).
        pool.pipeline(function(red)
            red:del("verified:" .. cookie)
            red:del(ips_key)
        end)
        ngx.log(ngx.WARN, "[antibot] verified_share revoked scope=cookie shared=",
                distinct, " handle=", cookie:sub(1, 16),
                " ip=", ip)
        return false  -- Fall through to normal pipeline (re-challenge)
    end

    ctx.verified = true
    ctx.identity = cookie
    ctx.fp_light = cookie
    return true
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
    end
end

return _M
