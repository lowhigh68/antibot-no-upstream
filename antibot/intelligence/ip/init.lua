local _M = {}
local ip_score = require "antibot.intelligence.ip.ip_score"

function _M.run(ctx)
    ip_score.run(ctx)
    return true, false
end
return _M
