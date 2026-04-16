local _M = {}
local cfg = require "antibot.core.config"

function _M.run(ctx)
    ctx.pow = {
        difficulty = cfg.pow and cfg.pow.difficulty or "000",
        algorithm  = "sha256",
    }
    return true, false
end
return _M
