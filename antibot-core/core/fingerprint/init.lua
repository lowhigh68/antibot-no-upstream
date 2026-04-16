local _M = {}

local geoip       = require "antibot.core.fingerprint.geoip"
local asn         = require "antibot.core.fingerprint.asn"
local ip_classify = require "antibot.core.fingerprint.ip_classify"
local collect_req = require "antibot.core.fingerprint.collect_request"
local build_light = require "antibot.core.fingerprint.build_light"
local session_load = require "antibot.detection.session.session_load"

function _M.run(ctx)
    collect_req.run(ctx)

    geoip.run(ctx)
    asn.run(ctx)
    ip_classify.run(ctx)

    local ok, err = build_light.run(ctx)
    if not ok then
        ngx.log(ngx.CRIT, "[fingerprint] build_light failed: ", err)
        return false, false
    end

    session_load.run(ctx)

    return true, false
end

return _M
