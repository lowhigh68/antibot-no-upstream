local _M = {}

local tls   = require "antibot.transport.tls"
local http2 = require "antibot.transport.http2"

function _M.run(ctx)
    tls.run(ctx)

    http2.run(ctx)

    return true, false
end

return _M
