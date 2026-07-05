local _M = {}

-- NOTE: the old `intelligence.ip` layer (ip_score.lua) used to overwrite
-- ctx.ip_score = ctx.ip_risk, but ran BEFORE ip_reputation populated ip_risk →
-- it silently zeroed ip_score. Removed: IP-type scoring is disabled at source
-- (core/fingerprint/ip_classify.lua) and per-IP reputation is handled by ip_rep/
-- ip_risk/ext_rep directly. Reviving this layer would double-count ip_risk.
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
    safe_run(threat_layer,  "threat",      ctx)
    safe_run(corr_layer,    "correlation", ctx)
    safe_run(scoring_layer, "scoring",     ctx)

    return true, false
end

return _M
