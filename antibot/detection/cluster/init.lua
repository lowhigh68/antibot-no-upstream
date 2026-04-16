local _M = {}

local ua_cluster      = require "antibot.detection.cluster.ua_cluster"
local ip_cluster      = require "antibot.detection.cluster.ip_cluster"
local uri_cluster     = require "antibot.detection.cluster.uri_cluster"
local tls_cluster     = require "antibot.detection.cluster.tls_cluster"
local swarm           = require "antibot.detection.cluster.swarm_detect"
local cluster_context = require "antibot.detection.cluster.cluster_context"
local score           = require "antibot.detection.cluster.cluster_score"

function _M.run(ctx)
    ua_cluster.run(ctx)
    ip_cluster.run(ctx)
    uri_cluster.run(ctx)
    tls_cluster.run(ctx)
    swarm.run(ctx)
    cluster_context.run(ctx)
    score.run(ctx)
end

return _M
