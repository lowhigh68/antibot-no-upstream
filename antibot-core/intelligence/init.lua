local _M = {}

-- The old `intelligence.ip`/`ip_score` axis has been removed end-to-end.
-- IP ownership/type is not a reliable user/bot discriminator on shared
-- hosting. The independent `ip_rep`, `ip_risk` and `ext_rep` axes remain;
-- reviving `ip_score` would only double-charge IP-level evidence.
local threat_layer  = require "antibot.intelligence.threat"
local corr_layer    = require "antibot.intelligence.correlation"
local scoring_layer = require "antibot.intelligence.scoring"

local function safe_run(mod, label, ctx)
    local ok, err = pcall(mod.run, ctx)
    if not ok then
        -- Preserve fail-open, but make a partial intelligence pipeline visible
        -- on the same request row. The detailed exception stays in error.log.
        ctx.intelligence_degraded = true
        local layers = ctx.intelligence_degraded_layers
        if type(layers) ~= "table" then
            layers = {}
            ctx.intelligence_degraded_layers = layers
        end
        layers[#layers + 1] = label
        ngx.log(ngx.ERR, "[intelligence.", label, "] error: ", tostring(err))
        return false
    end
    return true
end

function _M.run(ctx)
    safe_run(threat_layer,  "threat",      ctx)
    safe_run(corr_layer,    "correlation", ctx)
    safe_run(scoring_layer, "scoring",     ctx)

    return true, false
end

return _M
