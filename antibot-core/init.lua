local _M = {}

local classifier         = require "antibot.core.req_classifier"
local ctx_layer          = require "antibot.core.ctx"
local ip_ban_check       = require "antibot.l7.ban.ip_ban_check"
local device_classifier  = require "antibot.core.fingerprint.device_classifier"
local access_layer       = require "antibot.core.access"
local fingerprint_layer  = require "antibot.core.fingerprint"
local transport_layer    = require "antibot.transport"
local l7_layer           = require "antibot.l7"
local detection_layer    = require "antibot.detection"
local intelligence_layer = require "antibot.intelligence"
local enforcement_layer  = require "antibot.enforcement"
local risk_update        = require "antibot.async.risk_update"
local adaptive_weight    = require "antibot.async.adaptive_weight"
local logger             = require "antibot.async.logger"
local pool               = require "antibot.core.redis_pool"

local STEPS_COMMON = {
    { layer = ctx_layer,         fn = "init"          },
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

    logger.run(ctx)
end

function _M.init_worker()
    local mem_guard = require "antibot.async.memory_guard"
    mem_guard.start()
end

return _M
