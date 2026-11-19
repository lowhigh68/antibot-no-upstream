local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end

local cjson = require "cjson"
local pass, fail = 0, 0
local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL cloudflare_api: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local old_secrets = package.loaded["antibot.core.secrets"]
local old_api = package.loaded["antibot.core.cloudflare_api"]
local credential = { api_token = "cf-api-token-fixture-abcdefghijklmnopqrstuvwxyz" }
package.loaded["antibot.core.secrets"] = {
    cloudflare_api = function()
        if not credential then return nil, "not configured" end
        return credential
    end,
}
package.loaded["antibot.core.cloudflare_api"] = nil
local api = assert(loadfile(SRC .. "core/cloudflare_api.lua"))()

local empty_array = cjson.decode("[]")
local zone_visible, zone_active = true, true
local ruleset_exists = true
local rules = {
    { id="customer-rule", ref="customer_rule", action="rewrite", expression="true" },
}
local calls, next_rule, force_rule_error = {}, 0, false
local function response(result, status, success, errors)
    return status or 200, cjson.encode({
        success = success ~= false,
        result = result,
        errors = errors or empty_array,
        messages = empty_array,
    })
end
local function fake_transport(method, path, body, token)
    calls[#calls + 1] = { method=method, path=path, body=body, token=token }
    eq(token, "cf-api-token-fixture-abcdefghijklmnopqrstuvwxyz",
       "transport receives configured credential")
    ok(not path:find(token, 1, true), "credential never appears in URL")

    if method == "GET" and path:match("^/zones%?name=") then
        if not zone_visible then return response(empty_array) end
        return response({{
            id="zone1", name="example.test",
            status=zone_active and "active" or "pending",
            account={id="account1"},
        }})
    end
    if method == "GET" and path == "/zones/zone1/rulesets" then
        if not ruleset_exists then return response(empty_array) end
        return response({{
            id="set1", kind="zone", phase="http_request_late_transform",
        }})
    end
    if method == "POST" and path == "/zones/zone1/rulesets" then
        local doc = cjson.decode(body)
        eq(doc.kind, "zone", "phase ruleset kind")
        eq(doc.phase, "http_request_late_transform", "phase ruleset phase")
        ruleset_exists = true
        return response({id="set1",kind="zone",phase=doc.phase,rules=empty_array})
    end
    if method == "GET" and path == "/zones/zone1/rulesets/set1" then
        return response({id="set1",kind="zone",phase="http_request_late_transform",rules=rules})
    end
    if method == "POST" and path == "/zones/zone1/rulesets/set1/rules" then
        if force_rule_error then
            local submitted = cjson.decode(body)
            local leaked = submitted.action_parameters.headers["X-Antibot-Origin-Proof"].value
            return response(nil, 400, false, {{message="rejected " .. leaked}})
        end
        local doc = cjson.decode(body)
        next_rule = next_rule + 1
        doc.id = "managed" .. next_rule
        rules[#rules + 1] = doc
        return response(doc)
    end
    local rule_id = path:match("^/zones/zone1/rulesets/set1/rules/([A-Za-z0-9_-]+)$")
    if method == "DELETE" and rule_id then
        for i = #rules, 1, -1 do
            if rules[i].id == rule_id then table.remove(rules, i) end
        end
        return response({id="set1",rules=rules})
    end
    return response(nil, 404, false, {{message="fixture route missing"}})
end
api._set_transport_for_test(fake_transport)

eq(api.status(), true, "configured API status")
local token1 = "v2.example.test.0123456789abcdef0123456789abcdef.mac-one"
local managed, err = api.ensure_origin_rule("Example.Test.", token1)
ok(managed ~= nil and err == nil, "first ensure succeeds")
eq(managed.changed, true, "first ensure changes Cloudflare")
eq(#rules, 2, "customer rule and managed rule coexist")
eq(rules[1].ref, "customer_rule", "customer rule preserved")
eq(rules[2].ref, api._managed_ref_for_test, "managed ref is deterministic")
eq(rules[2].action_parameters.headers[api._header_name_for_test].operation,
   "set", "managed header overwrites")
eq(rules[2].action_parameters.headers[api._header_name_for_test].value,
   token1, "managed header carries V2 token")
local puts = 0
for i=1,#calls do if calls[i].method == "PUT" then puts=puts+1 end end
eq(puts, 0, "client never replaces the complete ruleset")

local before_calls = #calls
managed, err = api.ensure_origin_rule("example.test", token1)
ok(managed ~= nil and err == nil, "idempotent ensure succeeds")
eq(managed.changed, false, "matching managed rule is not rewritten")
eq(#calls, before_calls + 3, "idempotent ensure is read-only")

local token2 = "v2.example.test.ffffffffffffffffffffffffffffffff.mac-two"
managed, err = api.ensure_origin_rule("example.test", token2)
ok(managed ~= nil and err == nil and managed.changed, "generation change repairs rule")
eq(#rules, 2, "repair does not duplicate managed rule")
eq(rules[1].id, "customer-rule", "repair never deletes customer rule")
eq(rules[2].action_parameters.headers[api._header_name_for_test].value,
   token2, "repair installs new generation")

local removed
removed, err = api.remove_origin_rule("example.test")
ok(removed ~= nil and err == nil, "remove succeeds")
eq(removed.removed, 1, "remove reports one managed rule")
eq(#rules, 1, "only customer rule remains")
eq(rules[1].id, "customer-rule", "remove preserves customer rule")

ruleset_exists = false
managed, err = api.ensure_origin_rule("example.test", token1)
ok(managed ~= nil and err == nil, "missing phase ruleset is created")
eq(ruleset_exists, true, "phase ruleset creation recorded")

zone_active = false
managed, err = api.ensure_origin_rule("example.test", token1)
ok(managed == nil and tostring(err):find("not active",1,true) ~= nil,
   "inactive zone rejected")
zone_active = true
zone_visible = false
managed, err = api.ensure_origin_rule("example.test", token1)
ok(managed == nil and tostring(err):find("not visible",1,true) ~= nil,
   "zone outside token scope rejected")
zone_visible = true

local leak_token = "v2.example.test.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    .. string.rep("b", 64)
force_rule_error = true
managed, err = api.ensure_origin_rule("example.test", leak_token)
ok(managed == nil and tostring(err):find("origin-proof-redacted", 1, true) ~= nil,
   "Cloudflare error redacts submitted origin proof")
ok(not tostring(err):find(leak_token, 1, true), "origin proof never leaks in API error")
force_rule_error = false

credential = nil
eq(api.status(), false, "missing credential status is false")
managed, err = api.ensure_origin_rule("example.test", token1)
ok(managed == nil and tostring(err):find("not configured",1,true) ~= nil,
   "missing credential fails closed")

api._set_transport_for_test(nil)
package.loaded["antibot.core.cloudflare_api"] = old_api
package.loaded["antibot.core.secrets"] = old_secrets

print(("cloudflare_api_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
