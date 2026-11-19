-- Cloudflare control-plane client used only by the authenticated Admin UI.
--
-- This module never runs on the request hot path.  It deliberately manages
-- one rule (identified by MANAGED_REF) through rule-specific endpoints; it
-- never PUTs an entire phase ruleset and therefore cannot erase a customer's
-- unrelated Transform Rules.
--
-- HTTPS is delegated to the system curl trust store through ngx.pipe.  The API
-- token is supplied in curl's stdin configuration, not argv, so it is absent
-- from `ps`.  No nginx TLS/resolver directive is required.

local _M = {}

local cjson   = require "cjson.safe"
local secrets = require "antibot.core.secrets"

local API_BASE       = "https://api.cloudflare.com/client/v4"
local CURL_PATH      = "/usr/bin/curl"
local PHASE          = "http_request_late_transform"
local MANAGED_REF    = "antibot_origin_proof_v2"
local MANAGED_DESC   = "AntiBot managed origin proof V2 - do not edit"
local HEADER_NAME    = "X-Antibot-Origin-Proof"
local STATUS_MARKER  = "__ANTIBOT_HTTP_STATUS__:"
local MAX_BODY_BYTES = 2 * 1024 * 1024

local transport_override

local function normalize_name(value)
    return tostring(value or ""):lower():gsub("%.$", "")
end

local function valid_dns_name(value)
    if type(value) ~= "string" or #value < 1 or #value > 253 then return false end
    if value:find("..", 1, true) or value:sub(1, 1) == "." then return false end
    for label in value:gmatch("[^.]+") do
        if #label > 63
           or (not label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$")
               and not label:match("^[a-z0-9]$")) then
            return false
        end
    end
    return true
end

local function valid_id(value)
    return type(value) == "string" and #value >= 1 and #value <= 128
       and value:match("^[A-Za-z0-9_-]+$") ~= nil
end

local function curl_quote(value)
    value = tostring(value or "")
    if value:find("[%c]") then return nil, "curl config contains control bytes" end
    value = value:gsub("\\", "\\\\"):gsub('"', '\\"')
    return '"' .. value .. '"'
end

local function redact_error(value)
    value = tostring(value or "cloudflare API error")
    value = value:gsub("v2%.[A-Za-z0-9%.%-]+%.[0-9a-fA-F]+%.[0-9a-fA-F]+",
                       "[origin-proof-redacted]")
    value = value:gsub("[%c]+", " "):sub(1, 512)
    return value ~= "" and value or "cloudflare API error"
end

local function default_transport(method, path, body, api_token)
    local ok_pipe, ngx_pipe = pcall(require, "ngx.pipe")
    if not ok_pipe or not ngx_pipe or type(ngx_pipe.spawn) ~= "function" then
        return nil, nil, "ngx.pipe is unavailable"
    end
    local phase = type(ngx) == "table" and type(ngx.get_phase) == "function"
        and ngx.get_phase() or "-"
    if phase ~= "content" and phase ~= "timer" then
        return nil, nil, "Cloudflare API is allowed only in control-plane phases"
    end
    if method ~= "GET" and method ~= "POST" and method ~= "DELETE" then
        return nil, nil, "unsupported HTTP method"
    end
    if type(path) ~= "string" or path:sub(1, 1) ~= "/"
       or path:find("[%c%s]") then
        return nil, nil, "invalid Cloudflare API path"
    end

    local quoted_url, url_err = curl_quote(API_BASE .. path)
    local quoted_auth, auth_err = curl_quote("Authorization: Bearer " .. api_token)
    local quoted_body, body_err
    if body ~= nil then quoted_body, body_err = curl_quote(body) end
    if not quoted_url or not quoted_auth or (body ~= nil and not quoted_body) then
        return nil, nil, url_err or auth_err or body_err
    end

    local lines = {
        "silent",
        "show-error",
        "proto = \"=https\"",
        "connect-timeout = 3",
        "max-time = 12",
        "max-filesize = " .. tostring(MAX_BODY_BYTES),
        "request = \"" .. method .. "\"",
        "url = " .. quoted_url,
        "header = " .. quoted_auth,
        "header = \"Accept: application/json\"",
        "header = \"Content-Type: application/json\"",
        "user-agent = \"antibot-origin-control/2\"",
        "write-out = \"\\n" .. STATUS_MARKER .. "%{http_code}\"",
    }
    if quoted_body then lines[#lines + 1] = "data-binary = " .. quoted_body end
    local config = table.concat(lines, "\n") .. "\n"

    local proc, spawn_err = ngx_pipe.spawn(
        { CURL_PATH, "--config", "-" },
        { merge_stderr = true, buffer_size = 16384 }
    )
    if not proc then return nil, nil, "cannot start curl: " .. tostring(spawn_err) end
    proc:set_timeouts(2000, 15000, 15000, 15000)
    local written, write_err = proc:write(config)
    if not written then return nil, nil, "cannot feed curl: " .. tostring(write_err) end
    if tonumber(written) ~= #config then return nil, nil, "short write to curl" end
    local shut, shut_err = proc:shutdown("stdin")
    if not shut then return nil, nil, "cannot close curl stdin: " .. tostring(shut_err) end

    local output, read_err, partial = proc:stdout_read_all()
    output = output or partial
    local wait_ok, wait_reason, wait_status = proc:wait()
    if not output then
        return nil, nil, "curl output failed: " .. tostring(read_err or wait_reason)
    end
    if not wait_ok or tonumber(wait_status) ~= 0 then
        return nil, nil, "curl failed: " .. redact_error(output)
    end
    local payload, status = output:match("^(.*)\n" .. STATUS_MARKER .. "(%d%d%d)%s*$")
    if not status then return nil, nil, "curl response has no HTTP status" end
    return tonumber(status), payload, nil
end

local function error_message(doc, status)
    local parts = {}
    local function collect(values)
        if type(values) ~= "table" then return end
        for i = 1, math.min(#values, 4) do
            local item = values[i]
            if type(item) == "table" then item = item.message or item.code end
            if item ~= nil then parts[#parts + 1] = redact_error(item) end
        end
    end
    if type(doc) == "table" then
        collect(doc.errors)
        collect(doc.messages)
    end
    if #parts == 0 then parts[1] = "HTTP " .. tostring(status or "-") end
    return table.concat(parts, "; "):sub(1, 512)
end

local function call(method, path, value)
    local credential, secret_err = secrets.cloudflare_api()
    if not credential then return nil, secret_err end
    local encoded
    if value ~= nil then
        encoded = cjson.encode(value)
        if not encoded then return nil, "cannot encode Cloudflare request" end
    end
    local runner = transport_override or default_transport
    local status, raw, transport_err = runner(method, path, encoded,
                                               credential.api_token)
    if not status then return nil, redact_error(transport_err) end
    local doc, decode_err = cjson.decode(raw or "")
    if not doc then
        return nil, "invalid Cloudflare JSON response: " .. redact_error(decode_err)
    end
    if status < 200 or status >= 300 or doc.success ~= true then
        return nil, error_message(doc, status), status
    end
    return doc.result, nil, status
end

local function find_zone(zone)
    local result, err = call("GET", "/zones?name=" .. zone .. "&per_page=50")
    if not result then return nil, err end
    if type(result) ~= "table" then return nil, "Cloudflare returned an invalid zone list" end
    local exact = {}
    for i = 1, #result do
        local item = result[i]
        if type(item) == "table" and normalize_name(item.name) == zone then
            exact[#exact + 1] = item
        end
    end
    if #exact == 0 then return nil, "zone is not visible to the Cloudflare API token" end
    if #exact ~= 1 then return nil, "Cloudflare returned an ambiguous exact zone" end
    local item = exact[1]
    if not valid_id(item.id) then return nil, "Cloudflare returned an invalid zone id" end
    if tostring(item.status or "") ~= "active" then
        return nil, "Cloudflare zone is not active"
    end
    return item
end

local function list_phase_ruleset(zone_id)
    local result, err = call("GET", "/zones/" .. zone_id .. "/rulesets")
    if not result then return nil, err end
    if type(result) ~= "table" then
        return nil, "Cloudflare returned an invalid ruleset list"
    end
    local found
    for i = 1, #result do
        local item = result[i]
        if type(item) == "table" and item.kind == "zone" and item.phase == PHASE then
            if found then return nil, "multiple zone late-transform rulesets returned" end
            found = item
        end
    end
    if found and not valid_id(found.id) then
        return nil, "Cloudflare returned an invalid ruleset id"
    end
    return found, nil
end

local function create_phase_ruleset(zone_id)
    local result, err = call("POST", "/zones/" .. zone_id .. "/rulesets", {
        name = "Zone-level Late Transform Ruleset",
        description = "Zone-level request header transforms",
        kind = "zone",
        phase = PHASE,
    })
    if not result then return nil, err end
    if not valid_id(result.id) then return nil, "Cloudflare returned an invalid ruleset id" end
    return result
end

local function get_ruleset(zone_id, ruleset_id)
    local result, err = call("GET", "/zones/" .. zone_id .. "/rulesets/" .. ruleset_id)
    if not result then return nil, err end
    if type(result.rules) ~= "table" then result.rules = {} end
    return result
end

local function managed_rules(rules)
    local out = {}
    for i = 1, #rules do
        local rule = rules[i]
        if type(rule) == "table" and rule.ref == MANAGED_REF then
            out[#out + 1] = rule
        end
    end
    return out
end

local function rule_has_token(rule, token)
    if type(rule) ~= "table" or rule.action ~= "rewrite" or rule.enabled == false
       or rule.expression ~= "true" then return false end
    local ap = rule.action_parameters
    local headers = type(ap) == "table" and ap.headers or nil
    local header
    if type(headers) == "table" then
        for name, value in pairs(headers) do
            if tostring(name):lower() == HEADER_NAME:lower() then
                header = value
                break
            end
        end
    end
    return type(header) == "table" and header.operation == "set"
       and header.value == token
end

local function delete_rule(zone_id, ruleset_id, rule_id)
    if not valid_id(rule_id) then return nil, "Cloudflare returned an invalid rule id" end
    local result, err = call("DELETE", "/zones/" .. zone_id .. "/rulesets/"
        .. ruleset_id .. "/rules/" .. rule_id)
    if result == nil and err then return nil, err end
    return true
end

function _M.status()
    local value, err = secrets.cloudflare_api()
    if not value then return false, err end
    return true
end

function _M.ensure_origin_rule(raw_zone, token)
    local zone = normalize_name(raw_zone)
    if not valid_dns_name(zone) then return nil, "invalid zone" end
    if type(token) ~= "string" or #token < 32 or #token > 1024
       or token:find("[%c]") then
        return nil, "invalid origin proof token"
    end
    local zone_item, zone_err = find_zone(zone)
    if not zone_item then return nil, zone_err end
    local ruleset, ruleset_err = list_phase_ruleset(zone_item.id)
    if ruleset_err then return nil, ruleset_err end
    if not ruleset then
        ruleset, ruleset_err = create_phase_ruleset(zone_item.id)
        if not ruleset then return nil, ruleset_err end
    end

    local full, full_err = get_ruleset(zone_item.id, ruleset.id)
    if not full then return nil, full_err end
    local ours = managed_rules(full.rules)
    if #ours == 1 and rule_has_token(ours[1], token) and valid_id(ours[1].id) then
        return {
            zone_id = zone_item.id, ruleset_id = ruleset.id,
            rule_id = ours[1].id, changed = false,
        }
    end
    for i = 1, #ours do
        local removed, remove_err = delete_rule(zone_item.id, ruleset.id, ours[i].id)
        if not removed then return nil, remove_err end
    end

    local created, create_err = call("POST", "/zones/" .. zone_item.id
        .. "/rulesets/" .. ruleset.id .. "/rules", {
        ref = MANAGED_REF,
        description = MANAGED_DESC,
        expression = "true",
        action = "rewrite",
        action_parameters = {
            headers = {
                [HEADER_NAME] = { operation = "set", value = token },
            },
        },
    })
    if not created then return nil, create_err end
    if not valid_id(created.id) then return nil, "Cloudflare returned an invalid rule id" end
    return {
        zone_id = zone_item.id, ruleset_id = ruleset.id,
        rule_id = created.id, changed = true,
    }
end

function _M.remove_origin_rule(raw_zone)
    local zone = normalize_name(raw_zone)
    if not valid_dns_name(zone) then return nil, "invalid zone" end
    local zone_item, zone_err = find_zone(zone)
    if not zone_item then return nil, zone_err end
    local ruleset, ruleset_err = list_phase_ruleset(zone_item.id)
    if ruleset_err then return nil, ruleset_err end
    if not ruleset then return { removed = 0, zone_id = zone_item.id } end
    local full, full_err = get_ruleset(zone_item.id, ruleset.id)
    if not full then return nil, full_err end
    local ours = managed_rules(full.rules)
    for i = 1, #ours do
        local removed, remove_err = delete_rule(zone_item.id, ruleset.id, ours[i].id)
        if not removed then return nil, remove_err end
    end
    return { removed = #ours, zone_id = zone_item.id, ruleset_id = ruleset.id }
end

function _M._set_transport_for_test(value)
    transport_override = value
end

_M._managed_ref_for_test = MANAGED_REF
_M._header_name_for_test = HEADER_NAME
_M._default_transport_for_test = default_transport

return _M
