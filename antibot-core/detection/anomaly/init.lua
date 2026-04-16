local _M = {}

local header_anomaly   = require "antibot.detection.anomaly.header_anomaly"
local protocol_anomaly = require "antibot.detection.anomaly.protocol_anomaly"
local ua_anomaly       = require "antibot.detection.anomaly.ua_anomaly"
local anomaly_score    = require "antibot.detection.anomaly.anomaly_score"

function _M.run(ctx)
    header_anomaly.run(ctx)
    protocol_anomaly.run(ctx)
    ua_anomaly.run(ctx)
    anomaly_score.run(ctx)
end

return _M
