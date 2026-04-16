local _M = {}

local collect_path = require "antibot.detection.graph.collect_path"
local seq_builder  = require "antibot.detection.graph.sequence_builder"
local pattern      = require "antibot.detection.graph.pattern_detect"
local score        = require "antibot.detection.graph.graph_score"

function _M.run(ctx)
    collect_path.run(ctx)
    seq_builder.run(ctx)
    pattern.run(ctx)
    score.run(ctx)
end

return _M
