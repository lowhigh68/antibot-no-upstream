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

    -- Actor signing is optional at schema level so a node can fail open while
    -- the fleet is being rolled out.  It is never allowed to borrow the PoW
    -- secret: the two keys have different rotation and exposure boundaries.
    local actor_secrets
    if obj.actor ~= nil then
        if type(obj.actor) ~= "table"
           or not nonempty(obj.actor.current, 32, 512) then
            return nil, "actor.current must be 32-512 bytes"
        end
        if obj.actor.previous ~= nil
           and not nonempty(obj.actor.previous, 32, 512) then
            return nil, "actor.previous must be 32-512 bytes when present"
        end
        if obj.actor.previous == obj.actor.current then
            return nil, "actor.previous must differ from actor.current"
        end
        if obj.actor.current == pow.challenge_secret then
            return nil, "actor.current must differ from pow.challenge_secret"
        end
        if obj.actor.previous ~= nil
           and obj.actor.previous == pow.challenge_secret then
            return nil, "actor.previous must differ from pow.challenge_secret"
        end
        actor_secrets = {
            current  = obj.actor.current,
            previous = obj.actor.previous,
        }
    end

    -- Origin proof is optional so nodes that do not front any site through a
    -- shared proxy keep operating.  Missing proof material fails closed only
    -- for client-IP restoration: the proxy edge remains aggregate and the
    -- request still traverses WAF/L7/scoring.
    local origin_proof_secrets
    if obj.origin_proof ~= nil then
        if type(obj.origin_proof) ~= "table"
           or not nonempty(obj.origin_proof.current, 32, 512) then
            return nil, "origin_proof.current must be 32-512 bytes"
        end
        if obj.origin_proof.previous ~= nil
           and not nonempty(obj.origin_proof.previous, 32, 512) then
            return nil, "origin_proof.previous must be 32-512 bytes when present"
        end
        if obj.origin_proof.previous == obj.origin_proof.current then
            return nil, "origin_proof.previous must differ from origin_proof.current"
        end
        local reserved = { pow.challenge_secret }
        if actor_secrets then
            reserved[#reserved + 1] = actor_secrets.current
            if actor_secrets.previous then
                reserved[#reserved + 1] = actor_secrets.previous
            end
        end
        for i = 1, #reserved do
            if obj.origin_proof.current == reserved[i] then
                return nil, "origin_proof.current must not reuse another secret"
            end
            if obj.origin_proof.previous ~= nil
               and obj.origin_proof.previous == reserved[i] then
                return nil, "origin_proof.previous must not reuse another secret"
            end
        end
        origin_proof_secrets = {
            current  = obj.origin_proof.current,
            previous = obj.origin_proof.previous,
        }
    end

    -- One Cloudflare API token manages every zone visible to that token.  It
    -- is optional because many nodes have no Cloudflare-managed zones; the
    -- Admin mutation fails closed when an operator tries to enable API-managed
    -- origin proof without this credential.  Keep the token opaque: Cloudflare
    -- may change its printable format, so only length/control-byte invariants
    -- belong here.
    local cloudflare_api
    if obj.cloudflare ~= nil then
        if type(obj.cloudflare) ~= "table"
           or not nonempty(obj.cloudflare.api_token, 20, 2048)
           or obj.cloudflare.api_token:find("[%c]") then
            return nil, "cloudflare.api_token must be 20-2048 printable bytes"
        end
        cloudflare_api = { api_token = obj.cloudflare.api_token }
    end

    local accounts = { operator }
    if viewer then accounts[#accounts + 1] = viewer end
    return {
        schema_version = 1,
        admin_accounts = accounts,
        pow_secret     = pow.challenge_secret,
        actor_secrets  = actor_secrets,
        origin_proof_secrets = origin_proof_secrets,
        cloudflare_api = cloudflare_api,
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

function _M.actor_secrets()
    local value, err = _M.load(false)
    if not value then return nil, err end
    if not value.actor_secrets then
        return nil, "actor secret is not configured"
    end
    return value.actor_secrets, nil
end

function _M.origin_proof_secrets()
    local value, err = _M.load(false)
    if not value then return nil, err end
    if not value.origin_proof_secrets then
        return nil, "origin proof secret is not configured"
    end
    return value.origin_proof_secrets, nil
end

function _M.cloudflare_api()
    local value, err = _M.load(false)
    if not value then return nil, err end
    if not value.cloudflare_api then
        return nil, "cloudflare API token is not configured"
    end
    return value.cloudflare_api, nil
end

function _M.path()
    return cached_path or configured_path()
end

-- Test hooks never accept individual secrets through production call sites.
function _M._reset_for_test(path)
    cached, cached_error, cached_path = nil, nil, nil
    if path then
        local value, err = _M.load(true, path)
        -- A fixture loaded by the test hook must remain the source for later
        -- public accessor calls.  Leaving the temporary pathname here makes
        -- actor_secrets()/pow_secret()/admin_accounts() switch back to the
        -- production file because configured_path() differs.  That made the
        -- same suite pass on a machine without /etc/antibot/secrets.json and
        -- fail on a production node where the real file contains actor keys.
        cached_path = "<test>"
        return value, err
    end
end

function _M._set_for_test(value)
    cached = assert(value)
    cached_error = nil
    cached_path = "<test>"
end

return _M
