local _M = {}

local bit = require "bit"
local secrets = require "antibot.core.secrets"

local CSRF_TTL = 900
local MUTATION_LIMIT = 30
local MAX_MUTATION_BODY = 8192
local AUDIT_FILE = "/var/log/antibot/admin_audit.log"

local random_ok, random = pcall(require, "resty.random")
local string_ok, resty_string = pcall(require, "resty.string")

local function constant_equal(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    local na, nb = #a, #b
    local maximum = math.max(na, nb)
    if maximum > 1024 then return false end
    local diff = bit.bxor(na, nb)
    for i = 1, maximum do
        diff = bit.bor(diff, bit.bxor(a:byte(i) or 0, b:byte(i) or 0))
    end
    return diff == 0
end

local function headers()
    return (ngx.req and ngx.req.get_headers and ngx.req.get_headers()) or {}
end

local function client_ip()
    return tostring((ngx.var and ngx.var.remote_addr) or "-")
end

local function csrf_dict()
    return ngx.shared and ngx.shared.antibot_cache
end

local function csrf_binding(principal)
    return table.concat({
        tostring(principal.role or "-"),
        tostring(principal.username or "-"),
        client_ip(),
    }, "|")
end

local function unauthorized(status, message)
    ngx.status = status
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    if ngx.say then
        ngx.say('{"ok":false,"error":"' .. tostring(message or "denied") .. '"}')
    end
    if ngx.exit then ngx.exit(status) end
    return nil
end

function _M.authenticate()
    local accounts, load_err = secrets.admin_accounts()
    if not accounts then
        ngx.log(ngx.ERR, "[admin] secret configuration unavailable: ",
                tostring(load_err))
        return unauthorized(503, "admin credentials unavailable")
    end

    local h = headers()["authorization"]
    if type(h) ~= "string" or #h > 2048 then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot"'
        return unauthorized(401, "authentication required")
    end
    local encoded = h:match("^[Bb]asic%s+([A-Za-z0-9+/=]+)$")
    local decoded = encoded and ngx.decode_base64(encoded) or nil

    -- Evaluate every configured account.  Do not return on the first match;
    -- role position must not create a useful timing oracle.
    local matched
    for i = 1, #accounts do
        local account = accounts[i]
        local expected = account.username .. ":" .. account.password
        if constant_equal(decoded or "", expected) then matched = account end
    end
    if not matched then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot"'
        return unauthorized(401, "authentication failed")
    end
    return { username = matched.username, role = matched.role }
end

local function random_token()
    if not random_ok or not random or not random.bytes
       or not string_ok or not resty_string or not resty_string.to_hex then
        return nil, "secure random provider unavailable"
    end
    local raw, err = random.bytes(32, true)
    if not raw then return nil, err or "random.bytes failed" end
    return resty_string.to_hex(raw)
end

function _M.issue_csrf(principal)
    local dict = csrf_dict()
    if not dict then return nil, "antibot_cache unavailable" end
    local token, err = random_token()
    if not token then return nil, err end
    local key = "admin:csrf:" .. ngx.md5(token)
    local ok, set_err = dict:set(key, csrf_binding(principal), CSRF_TTL)
    if not ok then return nil, set_err or "shared dict set failed" end
    return token
end

local function cookie_value(raw, name)
    if type(raw) ~= "string" then return nil end
    for part in raw:gmatch("[^;]+") do
        local key, value = part:match("^%s*([^=]+)=(.*)$")
        if key == name then return value end
    end
    return nil
end

local function same_origin(h)
    local origin = h["origin"]
    if origin == nil or origin == "" then return true end
    if origin == "null" then return false end
    local authority = origin:match("^https?://([^/]+)$")
    local host = h["host"] or (ngx.var and ngx.var.host)
    if not authority or not host then return false end
    return authority:lower() == tostring(host):lower()
end

local function within_rate(dict, principal)
    local minute = math.floor(ngx.time() / 60)
    local key = table.concat({
        "admin:mut", principal.username or "-", client_ip(), minute,
    }, ":")
    local value, err = dict:incr(key, 1)
    if value == nil and err == "not found" then
        local ok, add_err = dict:add(key, 1, 65)
        if ok then value = 1
        elseif add_err == "exists" then value = dict:incr(key, 1)
        else return false, add_err end
    end
    if value == nil then return false, err end
    return value <= MUTATION_LIMIT, value
end

function _M.authorize_mutation(principal)
    if not principal or principal.role ~= "operator" then
        return false, 403, "operator role required"
    end
    if tostring(ngx.var.request_method or "") ~= "POST" then
        return false, 405, "POST required"
    end
    local h = headers()
    local ct = tostring(h["content-type"] or ""):lower()
    if ct ~= "application/json" and not ct:match("^application/json%s*;") then
        return false, 415, "application/json required"
    end
    if not same_origin(h) then return false, 403, "origin mismatch" end
    local content_length = tonumber(h["content-length"])
    if content_length and content_length > MAX_MUTATION_BODY then
        return false, 413, "mutation body too large"
    end
    local fetch_site = tostring(h["sec-fetch-site"] or ""):lower()
    if fetch_site ~= "" and fetch_site ~= "same-origin" then
        return false, 403, "cross-site mutation denied"
    end

    local header_token = h["x-antibot-csrf"]
    local cookie_token = cookie_value(h["cookie"], "ab_admin_csrf")
    if not constant_equal(header_token or "", cookie_token or "")
       or not header_token or #header_token ~= 64 then
        return false, 403, "invalid csrf token"
    end

    local dict = csrf_dict()
    if not dict then return false, 503, "csrf state unavailable" end
    local stored = dict:get("admin:csrf:" .. ngx.md5(header_token))
    if not constant_equal(stored or "", csrf_binding(principal)) then
        return false, 403, "csrf token expired or not bound to this operator"
    end
    local allowed, count_or_err = within_rate(dict, principal)
    if not allowed then
        if type(count_or_err) == "number" then
            return false, 429, "admin mutation rate exceeded"
        end
        return false, 503, "admin rate state unavailable"
    end
    return true
end

local SIMPLE_ACTIONS = {
    ua_sync = true,
}
local IP_ACTIONS = {
    wl_ip_add = true, wl_ip_del = true, unban_ip = true,
}
local ID_ACTIONS = {
    unban_id = true, wl_id = true,
}
local URL_ACTIONS = {
    wl_url_add = true, wl_url_del = true,
}
local UA_ACTIONS = {
    ua_add = true, ua_del = true,
}
local GOODBOT_DELETE_ACTIONS = {
    goodbot_dns_del = true,
}
local JA3_ACTIONS = {
    ja3_allow = true, ja3_block = true, ja3_remove = true,
}

local function plain_string(value, minimum, maximum)
    return type(value) == "string"
       and #value >= (minimum or 1)
       and #value <= (maximum or 512)
       and not value:find("[%c]")
end

local function valid_goodbot_name(value)
    return plain_string(value, 1, 64)
       and value:match("^[A-Za-z0-9_.-]+$") ~= nil
end

local function valid_suffixes(value)
    if not plain_string(value, 1, 1024) then return false end
    local count = 0
    for suffix in value:gmatch("[^,%s]+") do
        count = count + 1
        if #suffix > 253 or suffix:match("^[A-Za-z0-9.-]+$") == nil
           or suffix:sub(1, 1) == "." or suffix:sub(-1) == "."
           or not suffix:find("%.") then
            return false
        end
    end
    return count > 0 and count <= 32
end

-- Validate the mutation object before opening Redis.  The dashboard is an
-- explicit control plane; accepting unknown action/field shapes here only
-- creates malformed persistent keys and makes audit records ambiguous.
function _M.validate_payload(req, body_size)
    if type(req) ~= "table" then return false, "JSON object required" end
    if tonumber(body_size) and tonumber(body_size) > MAX_MUTATION_BODY then
        return false, "mutation body too large"
    end
    local action = req.action
    if type(action) ~= "string" then return false, "action must be a string" end

    if SIMPLE_ACTIONS[action] then return true end
    if IP_ACTIONS[action] then
        if not plain_string(req.ip, 3, 64)
           or req.ip:match("^[0-9A-Fa-f:.]+$") == nil then
            return false, "invalid ip"
        end
        return true
    end
    if ID_ACTIONS[action] then
        if type(req.id) ~= "string" or req.id:match("^[0-9A-Fa-f]+$") == nil
           or #req.id ~= 32 then
            return false, "invalid identity"
        end
        return true
    end
    if URL_ACTIONS[action] then
        if not plain_string(req.prefix, 1, 512)
           or req.prefix:sub(1, 1) ~= "/" then
            return false, "invalid URL prefix"
        end
        return true
    end
    if UA_ACTIONS[action] then
        if not plain_string(req.pattern, 1, 512) then
            return false, "invalid UA pattern"
        end
        return true
    end
    if action == "goodbot_dns_add" then
        if not valid_goodbot_name(req.name) then
            return false, "invalid good-bot name"
        end
        if not valid_suffixes(req.suffixes) then
            return false, "invalid DNS suffix list"
        end
        return true
    end
    if GOODBOT_DELETE_ACTIONS[action] then
        if not valid_goodbot_name(req.name) then
            return false, "invalid good-bot name"
        end
        return true
    end
    if JA3_ACTIONS[action] then
        if type(req.hash) ~= "string" or #req.hash ~= 32
           or req.hash:match("^[0-9A-Fa-f]+$") == nil then
            return false, "invalid JA3 hash"
        end
        return true
    end
    return false, "unknown action"
end

local function audit_token(v, maximum)
    local s = tostring(v == nil and "-" or v):sub(1, maximum or 256)
    return (s:gsub("[%c%s=]", "_"))
end

function _M.audit(principal, action, target, result, before, after)
    local line = string.format(
        "[%s] ts=%d user=%s role=%s ip=%s action=%s target=%s result=%s before=%s after=%s\n",
        os.date("%Y-%m-%d %H:%M:%S"), ngx.time(),
        audit_token(principal and principal.username, 128),
        audit_token(principal and principal.role, 32),
        audit_token(client_ip(), 64),
        audit_token(action, 128), audit_token(target, 256),
        audit_token(result, 64), audit_token(before, 128),
        audit_token(after, 256))
    local fh, err = io.open(AUDIT_FILE, "a")
    if not fh then
        ngx.log(ngx.ERR, "[admin-audit] cannot open audit log: ", tostring(err),
                " action=", audit_token(action, 128),
                " result=", audit_token(result, 64))
        return false
    end
    fh:write(line)
    fh:close()
    return true
end

function _M.deny_mutation(status, message)
    return unauthorized(status, message)
end

_M._constant_equal = constant_equal
_M._cookie_value = cookie_value

return _M
