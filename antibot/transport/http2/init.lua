local _M = {}

local pseudo_header  = require "antibot.transport.http2.pseudo_header"
local hpack_sequence = require "antibot.transport.http2.hpack_sequence"
local window_size    = require "antibot.transport.http2.window_size"
local frame_pattern  = require "antibot.transport.http2.frame_pattern"
local signature      = require "antibot.transport.http2.signature"

function _M.run(ctx)
    pseudo_header.run(ctx)

    hpack_sequence.run(ctx)

    window_size.run(ctx)

    frame_pattern.run(ctx)

    signature.run(ctx)
end

return _M
