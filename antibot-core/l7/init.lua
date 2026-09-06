local _M = {}

local ban_store  = require "antibot.l7.ban.ban_store"
local counter    = require "antibot.l7.rate.counter"
local adaptive   = require "antibot.l7.rate.adaptive_limit"
local burst_ctr  = require "antibot.l7.burst.burst_counter"
local burst_dec  = require "antibot.l7.burst.burst_decision"

-- `slow/slow_detect.lua` DA BI XOA (2026-09-06). Chet HAI lan:
--   1. `ctx.slow` khong noi nao doc
--   2. no doc `ngx.var.request_time` o ACCESS phase — luc do request chua xu
--      ly xong nen gia tri gan 0, khong bao gio vuot nguong. Ke ca co nguoi
--      doc thi tin hieu van luon false.

function _M.run(ctx)

    local banned, exit = ban_store.run(ctx)
    if exit then return true, true end

    counter.run(ctx)
    adaptive.run(ctx)

    burst_ctr.run(ctx)
    burst_dec.run(ctx)

    return true, false
end

return _M
