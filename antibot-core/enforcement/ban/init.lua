local _M = {}

local escalation  = require "antibot.enforcement.ban.ban_escalation"
local store_write = require "antibot.enforcement.ban.ban_store_write"
local sync        = require "antibot.enforcement.ban.ban_sync"

function _M.run(ctx)
    escalation.run(ctx)
    store_write.run(ctx)
    sync.run(ctx)
end

return _M
