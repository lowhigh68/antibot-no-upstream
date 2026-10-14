local _M = {}

-- These ASNs contain both the official crawler and general-purpose cloud
-- workloads.  Ownership of the network proves infrastructure, not which
-- process sent the request, so ASN match may corroborate DNS but may not grant
-- `good_bot_verified` by itself.
local CORROBORATIVE = {
    [15169] = "google_shared_cloud",
    [8075]  = "microsoft_shared_cloud",
}

function _M.is_corroborative(asn)
    return CORROBORATIVE[tonumber(asn)] ~= nil
end

function _M.label(asn)
    return CORROBORATIVE[tonumber(asn)]
end

function _M.matches(expected, actual)
    actual = tonumber(actual)
    if not actual or type(expected) ~= "table" then return false end
    for _, asn in ipairs(expected) do
        if tonumber(asn) == actual then return true end
    end
    return false
end

function _M.can_verify_directly(expected, actual)
    return _M.matches(expected, actual) and not _M.is_corroborative(actual)
end

return _M
