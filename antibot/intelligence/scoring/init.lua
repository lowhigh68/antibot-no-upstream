local _M = {}

local signal_merge   = require "antibot.intelligence.scoring.signal_merge"
local context_vector = require "antibot.intelligence.scoring.context_vector"
local compute        = require "antibot.intelligence.scoring.compute"

function _M.run(ctx)
    signal_merge.run(ctx)

    context_vector.run(ctx)

    compute.run(ctx)
end

return _M
