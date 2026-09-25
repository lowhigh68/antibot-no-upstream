local _M = {}

-- Configuration is deliberately plain Lua.  It is compiled once per worker by
-- waf.init.configure(), then resolved per host from a small in-worker cache.
-- No request is allowed to mutate DEFAULT.
local DEFAULT = {
    version = "2.0",

    -- observe: collect facts only
    -- shadow:  compute would_action but never terminate a request
    -- enforce: enforce rules whose own mode is also "enforce"
    mode = "enforce",

    profiles = {
        generic   = true,
        wordpress = true,
    },

    -- Score enforcement is intentionally off initially.  Existing hard
    -- invariants still block; ambiguous rules and correlations must earn an
    -- evidence base in shadow mode first.
    score_enforcement = false,
    threshold_mode    = "shadow",
    thresholds = {
        block = 100,
    },

    rules        = {},
    families     = {},
    correlations = {},
    exceptions   = {},
    domains      = {},

    telemetry = {
        enabled       = true,
        shared_dict   = "antibot_cache",
        prefix        = "waf:v2:",
        per_host      = false,
        host_limit    = 96,
    },
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

local function merge(dst, src)
    if type(src) ~= "table" then return dst end
    for k, v in pairs(src) do
        if k ~= "domains" and k ~= "exceptions" then
            if type(v) == "table" and type(dst[k]) == "table" then
                merge(dst[k], v)
            else
                dst[k] = copy(v)
            end
        end
    end
    return dst
end

local function append(dst, src)
    if type(src) ~= "table" then return end
    for i = 1, #src do dst[#dst + 1] = copy(src[i]) end
end

local function clean_host(host)
    host = tostring(host or "-"):lower()
    -- ngx.var.host normally has no port, but tests and non-standard callers may.
    host = host:gsub("%.$", "")
    return host
end

local VALID_MODE = { observe = true, shadow = true, enforce = true }
local VALID_ACTION = { observe = true, signal = true, block = true }

local function validate_scope(scope, path, errors, allow_domains)
    if type(scope) ~= "table" then
        errors[#errors + 1] = path .. " must be a table"
        return
    end
    if scope.mode ~= nil and not VALID_MODE[scope.mode] then
        errors[#errors + 1] = path .. ".mode is invalid"
    end
    if scope.threshold_mode ~= nil and not VALID_MODE[scope.threshold_mode] then
        errors[#errors + 1] = path .. ".threshold_mode is invalid"
    end
    if scope.score_enforcement ~= nil and type(scope.score_enforcement) ~= "boolean" then
        errors[#errors + 1] = path .. ".score_enforcement must be boolean"
    end
    if scope.telemetry ~= nil then
        if type(scope.telemetry) ~= "table" then
            errors[#errors + 1] = path .. ".telemetry must be a table"
        else
            if scope.telemetry.enabled ~= nil and
               type(scope.telemetry.enabled) ~= "boolean" then
                errors[#errors + 1] = path .. ".telemetry.enabled must be boolean"
            end
            for _, field in ipairs({ "shared_dict", "prefix" }) do
                if scope.telemetry[field] ~= nil and
                   type(scope.telemetry[field]) ~= "string" then
                    errors[#errors + 1] = path .. ".telemetry." .. field ..
                                          " must be a string"
                end
            end
            if scope.telemetry.per_host ~= nil and
               type(scope.telemetry.per_host) ~= "boolean" then
                errors[#errors + 1] = path .. ".telemetry.per_host must be boolean"
            end
        end
    end
    if scope.thresholds ~= nil then
        if type(scope.thresholds) ~= "table" then
            errors[#errors + 1] = path .. ".thresholds must be a table"
        elseif type(scope.thresholds.block) ~= "number" or scope.thresholds.block < 0 then
            errors[#errors + 1] = path .. ".thresholds.block must be non-negative"
        end
    end
    if scope.profiles ~= nil then
        if type(scope.profiles) ~= "table" then
            errors[#errors + 1] = path .. ".profiles must be a table"
        else
            for profile, enabled in pairs(scope.profiles) do
                if type(enabled) ~= "boolean" then
                    errors[#errors + 1] = path .. ".profiles." .. tostring(profile) ..
                                          " must be boolean"
                end
            end
        end
    end
    for _, section_name in ipairs({ "rules", "families", "correlations" }) do
        local section = scope[section_name]
        if section ~= nil then
            if type(section) ~= "table" then
                errors[#errors + 1] = path .. "." .. section_name .. " must be a table"
            else
                for id, override in pairs(section) do
                    local item = path .. "." .. section_name .. "." .. tostring(id)
                    if type(override) ~= "table" then
                        errors[#errors + 1] = item .. " must be a table"
                    else
                        if override.mode ~= nil and not VALID_MODE[override.mode] then
                            errors[#errors + 1] = item .. ".mode is invalid"
                        end
                        if override.action ~= nil and not VALID_ACTION[override.action] then
                            errors[#errors + 1] = item .. ".action is invalid"
                        end
                        if override.enabled ~= nil and type(override.enabled) ~= "boolean" then
                            errors[#errors + 1] = item .. ".enabled must be boolean"
                        end
                        if override.score ~= nil and
                           (type(override.score) ~= "number" or override.score < 0) then
                            errors[#errors + 1] = item .. ".score must be non-negative"
                        end
                    end
                end
            end
        end
    end
    if scope.exceptions ~= nil then
        if type(scope.exceptions) ~= "table" then
            errors[#errors + 1] = path .. ".exceptions must be an array"
        else
            for i = 1, #scope.exceptions do
                local ex = scope.exceptions[i]
                if type(ex) ~= "table" then
                    errors[#errors + 1] = path .. ".exceptions." .. i ..
                                          " must be a table"
                else
                    for _, field in ipairs({
                        "id", "rule", "family", "host", "method", "target",
                        "uri", "uri_prefix",
                    }) do
                        if ex[field] ~= nil and type(ex[field]) ~= "string" then
                            errors[#errors + 1] = path .. ".exceptions." .. i ..
                                "." .. field .. " must be a string"
                        end
                    end
                    if ex.enabled ~= nil and type(ex.enabled) ~= "boolean" then
                        errors[#errors + 1] = path .. ".exceptions." .. i ..
                                              ".enabled must be boolean"
                    end
                end
            end
        end
    end
    if allow_domains and scope.domains ~= nil then
        if type(scope.domains) ~= "table" then
            errors[#errors + 1] = path .. ".domains must be a table"
        else
            for host, domain in pairs(scope.domains) do
                validate_scope(domain, path .. ".domains." .. tostring(host), errors, false)
            end
        end
    end
end

function _M.validate(compiled)
    local errors = {}
    validate_scope(compiled, "config", errors, true)
    return #errors == 0, errors
end

function _M.compile(runtime)
    local out = copy(DEFAULT)
    runtime = type(runtime) == "table" and runtime or {}
    merge(out, runtime)
    if runtime.domains == nil then
        out.domains = {}
    elseif type(runtime.domains) ~= "table" then
        out.domains = runtime.domains -- kept so validate() can reject it
    else
        out.domains = {}
        for host, domain in pairs(runtime.domains) do
            out.domains[clean_host(host)] = copy(domain)
        end
    end
    out.exceptions = {}
    append(out.exceptions, DEFAULT.exceptions)
    append(out.exceptions, runtime.exceptions)
    return out
end

function _M.resolve(compiled, host)
    compiled = compiled or _M.compile()
    host = clean_host(host)

    local out = copy(compiled)
    local domains = compiled.domains or {}
    local domain = domains[host]
    if type(domain) == "table" then
        merge(out, domain)
        out.exceptions = {}
        append(out.exceptions, compiled.exceptions)
        append(out.exceptions, domain.exceptions)
    end
    out.domains = nil
    out.host = host
    return out
end

function _M.host(host)
    return clean_host(host)
end

function _M.defaults()
    return copy(DEFAULT)
end

_M.copy = copy
_M.merge = merge

return _M
