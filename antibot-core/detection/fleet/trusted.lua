local _M  = {}
local cfg = require "antibot.core.config"

-- Trusted ASN allowlist — SKIPS fleet aggregation entirely.
-- Performance optimization only: detection correctness is independent of
-- this list. ASNs listed serve high-volume legitimate Vietnamese / SEA
-- consumer traffic; skipping saves ~5 Redis ops per request.
--
-- An ASN that turns out to host a fleet (false negative) is acceptable
-- in v1 — operator can remove the entry to re-enable aggregation.

local function asn_table()
    local fd = cfg.fleet_detection or {}
    return fd.trusted_asn or {}
end

function _M.is_trusted(ctx)
    if not ctx.asn or not ctx.asn.asn_number then
        return false
    end
    return asn_table()[ctx.asn.asn_number] ~= nil
end

function _M.label(asn_number)
    return asn_table()[asn_number]
end

return _M
