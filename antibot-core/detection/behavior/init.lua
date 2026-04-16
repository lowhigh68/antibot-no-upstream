local _M = {}

local timing  = require "antibot.detection.behavior.request_timing"
local pattern = require "antibot.detection.behavior.rate_pattern"
local score   = require "antibot.detection.behavior.behavior_score"

function _M.run(ctx)
    timing.run(ctx)
    pattern.run(ctx)
    score.run(ctx)
end

return _M
