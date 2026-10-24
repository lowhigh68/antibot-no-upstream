-- Read-only init-worker policy loader.
--
-- The request path never calls this module.  Each worker reads at most two
-- bounded JSON files during init_worker, validates/compiles one complete
-- artifact and then serves requests exclusively from core/policy.lua RAM.
-- Disk writes, promotion and rollback belong to policy_tool.lua/policyctl.sh.
local policy = require "antibot.core.policy"
local _M = {}

local DEFAULT_DIR = "/etc/antibot/policy"
local MAX_BYTES = 1024 * 1024

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

local function configured_dir(value)
    if value and value ~= "" then return value:gsub("/+$", "") end
    local env = os.getenv("ANTIBOT_POLICY_DIR")
    if env and env ~= "" then return env:gsub("/+$", "") end
    return DEFAULT_DIR
end

local function paths(opts)
    opts = opts or {}
    local dir = configured_dir(opts.dir)
    return opts.active_path or (dir .. "/active.json"),
           opts.lkg_path or (dir .. "/last-good.json")
end

local function read_bounded(path)
    local fh, open_err = io.open(path, "rb")
    if not fh then return nil, "cannot read " .. path .. ": " .. tostring(open_err) end
    local raw = fh:read(MAX_BYTES + 1)
    local close_ok, close_err = fh:close()
    if not close_ok then
        return nil, "cannot close " .. path .. ": " .. tostring(close_err)
    end
    if not raw or raw == "" then return nil, path .. " is empty" end
    if #raw > MAX_BYTES then
        return nil, path .. " is larger than " .. tostring(MAX_BYTES) .. " bytes"
    end
    return raw
end

local function decode_candidate(path)
    local raw, read_err = read_bounded(path)
    if not raw then return nil, read_err end
    local value, decode_err = decode_json(raw)
    if value == nil then
        return nil, "invalid JSON in " .. path .. ": " .. tostring(decode_err)
    end
    return value
end

local function error_text(value)
    if type(value) ~= "table" then return tostring(value) end
    local out = {}
    for i = 1, #value do out[#out + 1] = tostring(value[i]) end
    if #out == 0 then return "unknown validation error" end
    return table.concat(out, "; ")
end

local function try_activate(path)
    local candidate, load_err = decode_candidate(path)
    if not candidate then return nil, load_err end
    local accepted, result = policy.configure(candidate)
    if not accepted then return nil, error_text(result) end
    return result
end

function _M.load(opts)
    local active_path, lkg_path = paths(opts)
    local failures = {}

    local version, active_err = try_activate(active_path)
    if version then
        return {
            source = "active", path = active_path, version = version,
            degraded = false, failures = failures,
        }
    end
    failures[#failures + 1] = { source = "active", path = active_path,
                               error = active_err }

    local lkg_version, lkg_err = try_activate(lkg_path)
    if lkg_version then
        return {
            source = "last-good", path = lkg_path, version = lkg_version,
            degraded = true, failures = failures,
        }
    end
    failures[#failures + 1] = { source = "last-good", path = lkg_path,
                               error = lkg_err }

    local builtin_version = policy.use_builtin()
    return {
        source = "builtin", path = "-", version = builtin_version,
        degraded = true, critical = true, failures = failures,
    }
end

function _M.paths(opts)
    return paths(opts)
end

function _M.max_bytes()
    return MAX_BYTES
end

return _M
