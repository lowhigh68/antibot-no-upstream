local _M = {}

local ja3  = require "antibot.transport.tls.ja3"
local ja3s = require "antibot.transport.tls.ja3s"

function _M.run(ctx)
    ja3.run(ctx)
    ja3s.run(ctx)
end

return _M
