local _M = {}

local ip_layer      = require "antibot.intelligence.ip"
local threat_layer  = require "antibot.intelligence.threat"
local corr_layer    = require "antibot.intelligence.correlation"
local scoring_layer = require "antibot.intelligence.scoring"

local function safe_run(mod, label, ctx)
    local ok, err = pcall(mod.run, ctx)
    if not ok then
        ngx.log(ngx.ERR, "[intelligence.", label, "] error: ", tostring(err))
    end
end

function _M.run(ctx)
    safe_run(ip_layer,      "ip",          ctx)
    safe_run(threat_layer,  "threat",      ctx)
    safe_run(corr_layer,    "correlation", ctx)
    safe_run(scoring_layer, "scoring",     ctx)

    return true, false
end

return _M
