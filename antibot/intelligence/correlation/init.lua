local _M = {}

local profile   = require "antibot.intelligence.correlation.identity_profile"
local consist   = require "antibot.intelligence.correlation.consistency_check"
local rules     = require "antibot.intelligence.correlation.cross_layer_rules"
local corr_score= require "antibot.intelligence.correlation.correlation_score"
local risk_load = require "antibot.intelligence.correlation.risk_load"

function _M.run(ctx)
    profile.run(ctx)
    consist.run(ctx)
    rules.run(ctx)
    corr_score.run(ctx)
    risk_load.run(ctx)
end

return _M
