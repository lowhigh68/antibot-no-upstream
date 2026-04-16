local _M = {}

local ip_rep      = require "antibot.intelligence.threat.ip_reputation"
local asn_rep     = require "antibot.intelligence.threat.asn_reputation"
local ja3_db      = require "antibot.intelligence.threat.ja3_db"
local h2_db       = require "antibot.intelligence.threat.http2_db"
local ja3_allow   = require "antibot.intelligence.threat.ja3_allowlist"

function _M.run(ctx)
    ip_rep.run(ctx)
    asn_rep.run(ctx)
    ja3_db.run(ctx)
    h2_db.run(ctx)
    ja3_allow.run(ctx)
end

return _M
