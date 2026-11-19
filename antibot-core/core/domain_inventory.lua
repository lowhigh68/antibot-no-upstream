-- Authoritative hosted-domain inventory for the Admin control plane.
-- Traffic logs are not an inventory: a quiet domain would disappear and an
-- attacker-controlled Host header could appear.  DirectAdmin owns this file.

local _M = {}

local DEFAULT_PATH = "/etc/virtual/domainowners"

local function normalize(value)
    return tostring(value or ""):lower():gsub("%.$", "")
end

local function valid_domain(value)
    if #value < 1 or #value > 253 or value:find("..", 1, true) then return false end
    for label in value:gmatch("[^.]+") do
        if #label > 63
           or (not label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$")
               and not label:match("^[a-z0-9]$")) then
            return false
        end
    end
    return value:find("%.") ~= nil
end

function _M.load(path)
    path = path or os.getenv("ANTIBOT_DOMAINOWNERS_FILE") or DEFAULT_PATH
    local fh, err = io.open(path, "r")
    if not fh then return nil, "cannot read " .. path .. ": " .. tostring(err) end
    local seen, out = {}, {}
    for line in fh:lines() do
        local raw_domain, raw_owner = line:match("^%s*([^:#%s]+)%s*:%s*([^%s#]+)")
        local domain = normalize(raw_domain)
        if valid_domain(domain) and not seen[domain] then
            seen[domain] = true
            out[#out + 1] = {
                domain = domain,
                owner = tostring(raw_owner or "-"):sub(1, 64),
            }
        end
    end
    fh:close()
    table.sort(out, function(a, b) return a.domain < b.domain end)
    return out, nil, path
end

function _M.contains(entries, domain)
    domain = normalize(domain)
    for i = 1, #(entries or {}) do
        if entries[i].domain == domain then return true end
    end
    return false
end

_M._valid_for_test = valid_domain

return _M
