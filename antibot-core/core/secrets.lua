-- Protected, per-node secret loader.
--
-- Secrets never belong in config.lua or an nginx generator.  The default file
-- lives outside the deployed source tree and is read once per worker, then
-- cached in Lua memory.  No request performs filesystem I/O after the first
-- successful/failed load.
local _M = {}

local DEFAULT_PATH = "/etc/antibot/secrets.json"
local cached
local cached_error
local cached_path

local function decoder()
    local ok, mod = pcall(require, "cjson.safe")
    if ok and mod then
        return function(raw) return mod.decode(raw) end
    end
    local cjson = require "cjson"
    return function(raw)
        local good, value = pcall(cjson.decode, raw)
        if good then return value end
        return nil, value
    end
end

local decode_json = decoder()

local function nonempty(v, min_len, max_len)
    return type(v) == "string"
       and #v >= (min_len or 1)
       and #v <= (max_len or 4096)
end

local function validate_account(role, account, required)
    if account == nil and not required then return nil end
    if type(account) ~= "table" then
        return nil, "admin." .. role .. " must be an object"
    end
    if not nonempty(account.username, 1, 128)
       or account.username:find(":", 1, true) then
        return nil, "admin." .. role .. ".username is invalid"
    end
    if not nonempty(account.password, 16, 512) then
        return nil, "admin." .. role .. ".password must be 16-512 bytes"
    end
    return {
        username = account.username,
        password = account.password,
        role     = role,
    }
end

local function validate(obj)
    if type(obj) ~= "table" then return nil, "root must be an object" end
    if tonumber(obj.schema_version) ~= 1 then
        return nil, "schema_version must equal 1"
    end
    if type(obj.admin) ~= "table" then
        return nil, "admin must be an object"
    end

    local operator, err = validate_account("operator", obj.admin.operator, true)
    if not operator then return nil, err end
    local viewer
    viewer, err = validate_account("viewer", obj.admin.viewer, false)
    if err then return nil, err end
    if viewer and viewer.username == operator.username then
        return nil, "viewer and operator usernames must differ"
    end

    local pow = obj.pow
    if type(pow) ~= "table" or not nonempty(pow.challenge_secret, 32, 512) then
        return nil, "pow.challenge_secret must be 32-512 bytes"
    end

    local accounts = { operator }
    if viewer then accounts[#accounts + 1] = viewer end
    return {
        schema_version = 1,
        admin_accounts = accounts,
        pow_secret     = pow.challenge_secret,
    }
end

local function configured_path(path)
    if path and path ~= "" then return path end
    local from_env = os.getenv("ANTIBOT_SECRETS_FILE")
    if from_env and from_env ~= "" then return from_env end
    return DEFAULT_PATH
end

function _M.load(force, path)
    path = configured_path(path)
    -- Unit tests inject a fully validated in-memory value.  Keep that value
    -- isolated from the production path lookup; otherwise admin_accounts()
    -- would immediately replace it by trying /etc/antibot/secrets.json.
    if not force and cached_path == "<test>" then
        return cached, cached_error
    end
    if not force and cached_path == path then
        return cached, cached_error
    end

    cached, cached_error, cached_path = nil, nil, path
    local fh, open_err = io.open(path, "rb")
    if not fh then
        cached_error = "cannot read " .. path .. ": " .. tostring(open_err)
        return nil, cached_error
    end
    local raw = fh:read("*a")
    fh:close()
    if not raw or #raw > 64 * 1024 then
        cached_error = "secret file is empty or larger than 64 KiB"
        return nil, cached_error
    end

    local obj, decode_err = decode_json(raw)
    if obj == nil then
        cached_error = "invalid JSON in " .. path .. ": " .. tostring(decode_err)
        return nil, cached_error
    end
    local value, validation_err = validate(obj)
    if not value then
        cached_error = "invalid secret schema in " .. path .. ": "
            .. tostring(validation_err)
        return nil, cached_error
    end
    cached = value
    return cached
end

function _M.admin_accounts()
    local value, err = _M.load(false)
    return value and value.admin_accounts or nil, err
end

function _M.pow_secret()
    local value, err = _M.load(false)
    return value and value.pow_secret or nil, err
end

function _M.path()
    return cached_path or configured_path()
end

-- Test hooks never accept individual secrets through production call sites.
function _M._reset_for_test(path)
    cached, cached_error, cached_path = nil, nil, nil
    if path then return _M.load(true, path) end
end

function _M._set_for_test(value)
    cached = assert(value)
    cached_error = nil
    cached_path = "<test>"
end

return _M
