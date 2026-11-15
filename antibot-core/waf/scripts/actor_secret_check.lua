-- Canonical actor-secret preflight used by deploy and telemetry scripts.
-- It deliberately reuses core/secrets.lua rather than duplicating JSON rules
-- in shell/jq.  No secret value is ever returned or printed.
local _M = {}

local function with_slash(path)
    if type(path) ~= "string" or path == "" then return nil end
    return path:sub(-1) == "/" and path or (path .. "/")
end

function _M.check(source_root, secret_path)
    local root = with_slash(source_root)
    if not root then return nil, "source root is empty" end
    secret_path = secret_path or "/etc/antibot/secrets.json"

    local loader, load_err = loadfile(root .. "core/secrets.lua")
    if not loader then
        return nil, "cannot load core/secrets.lua: " .. tostring(load_err)
    end
    local ok_module, secrets = pcall(loader)
    if not ok_module or type(secrets) ~= "table" then
        return nil, "cannot initialize core/secrets.lua: " .. tostring(secrets)
    end

    local state, state_err = secrets.load(true, secret_path)
    if not state then return nil, tostring(state_err) end
    -- Read the already validated value returned for this explicit path.  Do
    -- not call actor_secrets() here: that accessor resolves the configured
    -- production path and would replace a test/canary pathname immediately.
    local actor = state.actor_secrets
    if not actor then return nil, "actor secret is not configured" end

    return {
        current_bytes = #actor.current,
        has_previous  = actor.previous ~= nil,
    }
end

return _M
