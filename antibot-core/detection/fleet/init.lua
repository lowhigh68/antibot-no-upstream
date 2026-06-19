local _M = {}

local aggregator = require "antibot.detection.fleet.aggregator"
local analyzer   = require "antibot.detection.fleet.analyzer"
local cfg        = require "antibot.core.config"

-- Public API for the fleet detection module.
--
-- Pipeline integration: call `aggregate(ctx)` once per request, after ctx.ip
-- and ctx.ua are populated. Called from TWO sites in antibot.run():
--   1. Inside check_verified_cookie() when the cookie short-circuits the
--      pipeline (so verified hits get counted into the bucket).
--   2. As a step inside STEPS_COMMON, after ctx_layer.init.
--
-- Timer: call `start_timer()` once from init_worker on worker 0 to launch
-- the periodic analyzer.

function _M.aggregate(ctx)
    -- Cheap no-op when disabled.
    local fdc = cfg.fleet_detection
    if not fdc then return end
    aggregator.write(ctx)
end

-- STEPS_COMMON-compatible signature so this module can be added as a step.
function _M.run(ctx)
    _M.aggregate(ctx)
    return true, false
end

local TIMER_STARTED = false

function _M.start_timer()
    if TIMER_STARTED then return end
    TIMER_STARTED = true

    local fdc = cfg.fleet_detection
    if not fdc then return end
    local timing = fdc.timing or {}
    local period = timing.evaluator_period or 30

    local ok, err = ngx.timer.every(period, function(premature)
        if premature then return end
        local ok2, eerr = pcall(analyzer.evaluate)
        if not ok2 then
            ngx.log(ngx.ERR, "[fleet.timer] evaluate error: ", tostring(eerr))
        end
    end)
    if not ok then
        ngx.log(ngx.ERR, "[fleet.timer] start failed: ", tostring(err))
    else
        ngx.log(ngx.INFO, "[fleet.timer] started period=", period, "s")
    end
end

return _M
