local _M = {}

local ban_store  = require "antibot.l7.ban.ban_store"
local counter    = require "antibot.l7.rate.counter"
local adaptive   = require "antibot.l7.rate.adaptive_limit"
local burst_ctr  = require "antibot.l7.burst.burst_counter"
local burst_dec  = require "antibot.l7.burst.burst_decision"
local slow       = require "antibot.l7.slow.slow_detect"

function _M.run(ctx)

    local banned, exit = ban_store.run(ctx)
    if exit then return true, true end

    counter.run(ctx)
    adaptive.run(ctx)

    burst_ctr.run(ctx)
    burst_dec.run(ctx)

    slow.run(ctx)

    return true, false
end

return _M
