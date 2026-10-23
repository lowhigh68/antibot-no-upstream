-- Compiled request policy for the bot-manager/capacity layers.
--
-- P1.0 deliberately does only three things:
--   * validate a closed, typed policy surface;
--   * resolve global -> server -> tenant/docroot -> principal;
--   * expose one deterministic policy version to the decision ledger.
--
-- Loading, last-known-good persistence, staged rollout and rollback belong to
-- P1.1.  This module never reads Redis or the network on the request path.

local defaults = require "antibot.core.config"
local _M = {}

local SCHEMA_VERSION = "1"
local ROOT_KEYS = {
    schema = true, version = true, global = true,
    servers = true, tenants = true, principals = true,
}
local SCOPE_KEYS = { settings = true }

-- Closed on purpose.  Redis credentials, secret locations and low-level
-- transport state are not policy knobs.  Adding a section requires an
-- explicit code review and a consumer that calls policy.section().
local REGISTERED = {
    automation = true,
    automation_concurrency = true,
    principal_churn = true,
    l7_admission = true,
    endpoint_guard = true,
    dynamic_guard = true,
    l7_surge_guard = true,
    l7_circuit_breaker = true,
    expensive_filter = true,
    ip_tour = true,
}

local function copy(value, seen)
    if type(value) ~= "table" then return value end
    seen = seen or {}
    if seen[value] then return seen[value] end
    local out = {}
    seen[value] = out
    for k, v in pairs(value) do out[copy(k, seen)] = copy(v, seen) end
    return out
end

local function table_count(value)
    local n = 0
    for _ in pairs(value or {}) do n = n + 1 end
    return n
end

local function array_shape(value)
    if type(value) ~= "table" then return false end
    local count, maximum = 0, 0
    for k in pairs(value) do
        if type(k) ~= "number" or k < 1 or k % 1 ~= 0 then return false end
        count = count + 1
        if k > maximum then maximum = k end
    end
    -- An empty table is treated as a map because its element type is unknown.
    return count > 0 and count == maximum
end

local function finite_number(value)
    return type(value) == "number" and value == value
        and value ~= math.huge and value ~= -math.huge
end

local function add_error(errors, path, message)
    errors[#errors + 1] = path .. " " .. message
end

local function validate_patch(patch, base, path, errors, depth)
    depth = depth or 0
    if depth > 16 then
        add_error(errors, path, "is nested too deeply")
        return
    end

    local base_type = type(base)
    if base_type ~= "table" then
        if type(patch) ~= base_type then
            add_error(errors, path, "must be " .. base_type)
        elseif base_type == "number" and not finite_number(patch) then
            add_error(errors, path, "must be a finite number")
        end
        return
    end
    if type(patch) ~= "table" then
        add_error(errors, path, "must be a table")
        return
    end

    if array_shape(base) then
        if table_count(patch) == 0 then return end -- explicit empty replacement
        if not array_shape(patch) then
            add_error(errors, path, "must be a dense array")
            return
        end
        local exemplar = base[1]
        for i = 1, #patch do
            validate_patch(patch[i], exemplar, path .. "[" .. i .. "]",
                           errors, depth + 1)
        end
        return
    end

    for key, value in pairs(patch) do
        if type(key) ~= "string" and type(key) ~= "number" then
            add_error(errors, path, "contains a non-scalar key")
        elseif base[key] == nil then
            add_error(errors, path .. "." .. tostring(key),
                      "is not a registered setting")
        else
            validate_patch(value, base[key], path .. "." .. tostring(key),
                           errors, depth + 1)
        end
    end
end

local function reject_unknown(value, allowed, path, errors)
    if type(value) ~= "table" then
        add_error(errors, path, "must be a table")
        return false
    end
    for key in pairs(value) do
        if type(key) ~= "string" or not allowed[key] then
            add_error(errors, path .. "." .. tostring(key), "is unknown")
        end
    end
    return true
end

local function validate_scope(scope, path, errors)
    if not reject_unknown(scope, SCOPE_KEYS, path, errors) then return end
    local settings = scope.settings
    if settings == nil then return end
    if type(settings) ~= "table" then
        add_error(errors, path .. ".settings", "must be a table")
        return
    end
    for section, patch in pairs(settings) do
        local section_path = path .. ".settings." .. tostring(section)
        if type(section) ~= "string" or not REGISTERED[section] then
            add_error(errors, section_path, "is not a registered policy section")
        else
            validate_patch(patch, defaults[section], section_path, errors, 0)
        end
    end
end

local function normalize_server(value)
    return tostring(value or ""):lower():gsub("^%s+", ""):gsub("%s+$", "")
end

local function normalize_principal(value)
    return tostring(value or ""):lower():gsub("^%s+", ""):gsub("%s+$", "")
end

local function normalize_tenant(value)
    local out = tostring(value or ""):gsub("\\", "/")
    out = out:gsub("/+", "/"):gsub("/$", "")
    if out == "" then return "" end
    return out
end

local function validate_selector_map(value, name, normalizer, errors)
    if value == nil then return end
    if type(value) ~= "table" then
        add_error(errors, "policy." .. name, "must be a table")
        return
    end
    if table_count(value) > 1024 then
        add_error(errors, "policy." .. name, "has more than 1024 entries")
    end
    local normalized = {}
    for selector, scope in pairs(value) do
        local path = "policy." .. name .. "." .. tostring(selector)
        if type(selector) ~= "string" then
            add_error(errors, path, "selector must be a string")
        else
            local key = normalizer(selector)
            if key == "" or #key > 256 or key:find("%z") then
                add_error(errors, path, "selector is empty or invalid")
            elseif normalized[key] then
                add_error(errors, path, "duplicates selector " .. key)
            else
                normalized[key] = true
            end
        end
        validate_scope(scope, path, errors)
    end
end

function _M.validate(raw)
    local errors = {}
    if type(raw) ~= "table" then return false, { "policy must be a table" } end
    reject_unknown(raw, ROOT_KEYS, "policy", errors)
    if tostring(raw.schema or "") ~= SCHEMA_VERSION then
        add_error(errors, "policy.schema", "must equal " .. SCHEMA_VERSION)
    end
    if type(raw.version) ~= "string" or raw.version == ""
       -- logger.lua caps pver at 64 bytes; reserve "+" plus 8 hex bytes so
       -- the distinguishing digest is never truncated from telemetry.
       or #tostring(raw.version) > 55
       or not raw.version:match("^[%w%._%-]+$") then
        add_error(errors, "policy.version", "must be a non-empty token up to 55 bytes")
    end
    if raw.global ~= nil then
        validate_scope(raw.global, "policy.global", errors)
    end
    validate_selector_map(raw.servers, "servers", normalize_server, errors)
    validate_selector_map(raw.tenants, "tenants", normalize_tenant, errors)
    validate_selector_map(raw.principals, "principals", normalize_principal, errors)
    return #errors == 0, errors
end

local function merge_into(dst, src)
    if type(src) ~= "table" then return src end
    if array_shape(src) then return copy(src) end
    for key, value in pairs(src) do
        if type(value) == "table" and not array_shape(value)
           and type(dst[key]) == "table" and not array_shape(dst[key]) then
            merge_into(dst[key], value)
        else
            dst[key] = copy(value)
        end
    end
    return dst
end

local function canonical(value)
    local kind = type(value)
    if kind == "nil" then return "n" end
    if kind == "boolean" then return value and "b1" or "b0" end
    if kind == "number" then return "d" .. string.format("%.17g", value) end
    if kind == "string" then return "s" .. #value .. ":" .. value end
    if kind ~= "table" then return "x" .. kind end
    local keys = {}
    for key in pairs(value) do keys[#keys + 1] = key end
    table.sort(keys, function(a, b)
        return type(a) .. ":" .. tostring(a) < type(b) .. ":" .. tostring(b)
    end)
    local out = { "{" }
    for i = 1, #keys do
        local key = keys[i]
        out[#out + 1] = canonical(key)
        out[#out + 1] = canonical(value[key])
    end
    out[#out + 1] = "}"
    return table.concat(out)
end

-- Non-cryptographic digest: this is a deployment identity, not a signature.
-- P1.1 will authenticate distributed policy artifacts separately.
local function digest(value)
    local h, mod = 5381, 2147483647
    local text = canonical(value)
    for i = 1, #text do h = (h * 33 + text:byte(i)) % mod end
    return string.format("%08x", h)
end

local function compile_map(source, normalizer)
    local out = {}
    for selector, scope in pairs(source or {}) do
        out[normalizer(selector)] = { settings = copy(scope.settings or {}) }
    end
    return out
end

function _M.compile(raw)
    local valid, errors = _M.validate(raw)
    if not valid then return nil, errors end
    local effective_defaults = {}
    for section in pairs(REGISTERED) do
        effective_defaults[section] = defaults[section]
    end
    local normalized = {
        schema = SCHEMA_VERSION,
        declared_version = raw.version,
        -- The artifact alone is insufficient: changing a shipped default in
        -- core/config.lua also changes effective policy.  Include a digest of
        -- every registered default so pver cannot stay equal across those two
        -- behaviours merely because policy_runtime.lua was untouched.
        defaults_digest = digest(effective_defaults),
        global = { settings = copy((raw.global or {}).settings or {}) },
        servers = compile_map(raw.servers, normalize_server),
        tenants = compile_map(raw.tenants, normalize_tenant),
        principals = compile_map(raw.principals, normalize_principal),
    }
    normalized.policy_version = raw.version .. "+" .. digest(normalized)
    return normalized, nil
end

local builtin = assert(_M.compile({
    schema = SCHEMA_VERSION,
    version = "builtin-p1.0",
    global = { settings = {} },
    servers = {}, tenants = {}, principals = {},
}))
local active = builtin

function _M.configure(raw)
    local candidate, errors = _M.compile(raw)
    if not candidate then return false, errors end
    -- A single reference swap: a worker sees either the old complete policy or
    -- the new complete policy, never a partially merged table.
    active = candidate
    return true, candidate.policy_version
end

function _M.current_version()
    return active.policy_version
end

function _M.status()
    return {
        schema = active.schema,
        declared_version = active.declared_version,
        policy_version = active.policy_version,
        defaults_digest = active.defaults_digest,
        servers = table_count(active.servers),
        tenants = table_count(active.tenants),
        principals = table_count(active.principals),
    }
end

local function runtime_selector(ctx, selectors)
    local var = (ngx and ngx.var) or {}
    local server = (selectors and selectors.server) or var.hostname or ""
    local tenant = (selectors and selectors.tenant) or (ctx and ctx.policy_tenant)
        or var.document_root or ""
    local principal = (selectors and selectors.principal)
        or (ctx and ctx.automation_principal) or ""
    return normalize_server(server), normalize_tenant(tenant),
           normalize_principal(principal)
end

local function scope_settings(scope)
    return scope and scope.settings or nil
end

local function apply_scope(merged, scope)
    local settings = scope_settings(scope)
    if not settings or next(settings) == nil then return merged end
    if not merged then merged = {} end
    merge_into(merged, settings)
    return merged
end

function _M.resolve(ctx, selectors)
    ctx = ctx or {}
    local server, tenant, principal = runtime_selector(ctx, selectors)
    local merged
    merged = apply_scope(merged, active.global)
    merged = apply_scope(merged, active.servers[server])
    merged = apply_scope(merged, active.tenants[tenant])
    merged = apply_scope(merged, active.principals[principal])
    ctx.policy_settings = merged
    ctx.policy_section_cache = nil
    ctx.policy_version = active.policy_version
    ctx.policy_resolved_principal = principal
    ctx.policy_resolved_server = server
    ctx.policy_resolved_tenant = tenant
    return ctx.policy_settings, active.policy_version
end

function _M.section(ctx, name, fallback)
    if not REGISTERED[name] then return fallback end
    local current_principal = normalize_principal(
        ctx and ctx.automation_principal or "")
    if not ctx or ctx.policy_version ~= active.policy_version
       or ctx.policy_resolved_principal ~= current_principal then
        ctx = ctx or {}
        -- Preserve the already selected node/tenant when only late bot proof
        -- refines the principal.  Apart from being cheaper, this avoids asking
        -- ngx.var again from Lua endpoint/test contexts where that API may not
        -- be available.
        _M.resolve(ctx, {
            server = ctx.policy_resolved_server,
            tenant = ctx.policy_resolved_tenant,
            principal = current_principal,
        })
    end
    local patch = ctx.policy_settings and ctx.policy_settings[name]
    if patch == nil then return fallback end
    local cache = ctx.policy_section_cache
    if not cache then cache = {}; ctx.policy_section_cache = cache end
    if cache[name] ~= nil then return cache[name] end
    local resolved = copy(fallback or {})
    merge_into(resolved, patch)
    cache[name] = resolved
    return resolved
end

function _M.registered_sections()
    return copy(REGISTERED)
end

return _M
