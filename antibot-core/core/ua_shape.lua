-- Pure structural User-Agent predicates shared by request and device
-- classification.  A self-claim is never trust; this module only prevents two
-- classifiers from assigning incompatible intent to the same UA.
local _M = {}

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

