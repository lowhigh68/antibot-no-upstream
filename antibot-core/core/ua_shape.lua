-- Pure structural User-Agent predicates shared by request and device
-- classification.  A self-claim is never trust; this module only prevents two
-- classifiers from assigning incompatible intent to the same UA.
local _M = {}

-- A browser wrapper is a complete browser product followed by an automation
-- product.  This is deliberately structural: the caller may be Safari,
-- Chromium, Firefox or a future registered preview client.  The automation
-- name is supplied by the unified registry, so this module does not maintain
-- a vendor list of its own.
local BROWSER_PRODUCTS = {
    "chrome/", "crios/", "fxios/", "firefox/", "safari/", "edg/",
    "opr/", "samsungbrowser/", "version/",
}

local function complete_browser_prefix(ua)
    if type(ua) ~= "string" or ua == "" then return false end
    local lower = ua:lower()
    if not lower:find("mozilla/", 1, true) then return false end
    if not (lower:find("applewebkit/", 1, true)
            or lower:find("gecko/", 1, true)) then
        return false
    end
    for i = 1, #BROWSER_PRODUCTS do
        if lower:find(BROWSER_PRODUCTS[i], 1, true) then return true end
    end
    return false
end

function _M.browser_wrapped_claim(ua, canonical_name)
    if type(ua) ~= "string" or type(canonical_name) ~= "string"
       or canonical_name == "" then
        return false
    end

    local lower = ua:lower()
    local claim_pos = lower:find(canonical_name:lower(), 1, true)
    if not claim_pos or claim_pos <= 1 then return false end

    -- Canonical crawlers may pad their compatible comment with browser tokens.
    -- Only `compatible;` BEFORE the claimed product disqualifies the wrapper.
    -- A suffix after the product belongs to the appended client and must not
    -- turn an otherwise complete human-browser prefix into impersonation.
    local compatible_pos = lower:find("compatible;", 1, true)
    if compatible_pos and compatible_pos < claim_pos then return false end

    return complete_browser_prefix(ua:sub(1, claim_pos - 1))
end

_M.complete_browser_prefix = complete_browser_prefix

function _M.self_declared_crawler(ua)
    if not ua or ua == "" then return false end
    local lower = ua:lower()
    return lower:find("spider",  1, true) ~= nil
        or lower:find("crawler", 1, true) ~= nil
        -- Boundary after `bot` avoids device/model names such as CUBOT-X70.
        or lower:find("bot/", 1, true) ~= nil
        or lower:find("bot;", 1, true) ~= nil
        or lower:find("bot)", 1, true) ~= nil
        or lower:find("bot ", 1, true) ~= nil
        -- RFC-style operator contact is itself an automation declaration.
        or lower:find("+http://",  1, true) ~= nil
        or lower:find("+https://", 1, true) ~= nil
        or lower:find("+mailto:",  1, true) ~= nil
end

return _M

