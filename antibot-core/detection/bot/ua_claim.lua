-- Compatibility facade for the broad crawler-claim gate.
--
-- A claim is a HOLD signal, never positive trust. Callers use it in two
-- opposite safe directions: defer a ban until DNS verification, and prevent
-- a crawler-shaped UA from entering the verified-human lane. Verification
-- itself remains in detection/bot/ua_check.lua.
--
-- The token set used to be copied across several files and drifted. P1.2 puts
-- parser and static identity metadata in core/goodbot_registry.lua; this
-- facade keeps every existing caller stable.

local registry = require "antibot.core.goodbot_registry"

local _M = {}

function _M.claims_good_bot(ua)
    return registry.claims_operator(ua)
end

-- Broader trust-lane gate: RFC contact clients are automation too, but this
-- must not be reused by ban/fleet exemptions. A self-claim can withhold human
-- trust; it cannot earn crawler trust.
function _M.claims_automation(ua)
    return registry.claims_automation(ua)
end

return _M
