local _M = {}

-- `identity_profile.lua` và `correlation_score.lua` ĐÃ BỊ XOÁ (2026-09-06).
--   identity_profile  → `ctx.profile`    : không nơi nào đọc
--   correlation_score → `ctx.corr_score` : không nơi nào đọc — `compute.lua`
--                        đi thẳng vào `ctx.corr_rules` qua `corr_rule_weight`,
--                        không qua giá trị gộp này.
local consist   = require "antibot.intelligence.correlation.consistency_check"
local rules     = require "antibot.intelligence.correlation.cross_layer_rules"
local risk_load = require "antibot.intelligence.correlation.risk_load"

function _M.run(ctx)
    consist.run(ctx)
    rules.run(ctx)
    risk_load.run(ctx)
end

return _M
