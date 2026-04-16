local _M = {}

local store   = require "antibot.detection.session.session_store"
local load_   = require "antibot.detection.session.session_load"
local analyze = require "antibot.detection.session.session_analyze"

function _M.run(ctx)
    store.run(ctx)

    if not ctx.session or #ctx.session == 0 then
        load_.run(ctx)
    end

    analyze.run(ctx)
end

return _M
