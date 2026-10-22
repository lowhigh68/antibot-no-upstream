local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
package.preload["antibot.core.secrets"] = function()
    return assert(loadfile(SRC .. "core/secrets.lua"))()
end

local real_ngx = ngx
local headers = {}
local exits, says = {}, {}

local Dict = {}; Dict.__index = Dict
function Dict.new() return setmetatable({ data = {} }, Dict) end
function Dict:get(k) return self.data[k] end
function Dict:set(k, v, _ttl) self.data[k] = v; return true end
function Dict:add(k, v, _ttl)
    if self.data[k] ~= nil then return nil, "exists" end
    self.data[k] = v; return true
end
function Dict:incr(k, n)
    if self.data[k] == nil then return nil, "not found" end
    self.data[k] = self.data[k] + n; return self.data[k]
end

local dict = Dict.new()
ngx = {
    ERR = 4, header = {}, status = 200,
    var = { remote_addr = "192.0.2.10", host = "admin.example.test",
            request_method = "GET" },
    shared = { antibot_cache = dict },
    req = { get_headers = function() return headers end },
    time = real_ngx.time, md5 = real_ngx.md5,
    decode_base64 = real_ngx.decode_base64,
    encode_base64 = real_ngx.encode_base64,
    log = function() end,
    say = function(s) says[#says + 1] = s end,
    exit = function(status) exits[#exits + 1] = status end,
}

local secrets = require "antibot.core.secrets"
secrets._set_for_test({
    schema_version = 1,
    admin_accounts = {
        { username = "operator", password = "operator-password-123", role = "operator" },
        { username = "viewer", password = "viewer-password-456", role = "viewer" },
    },
    pow_secret = string.rep("p", 32),
})
package.loaded["antibot.admin.security"] = nil
local security = assert(loadfile(SRC .. "admin/security.lua"))()

local pass, fail = 0, 0
local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL admin_security: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end
local function basic(user, password)
    return "Basic " .. ngx.encode_base64(user .. ":" .. password)
end

headers = { authorization = basic("operator", "operator-password-123") }
local principal = security.authenticate()
eq(principal and principal.role, "operator", "operator authenticates")
eq(principal and principal.username, "operator", "operator name")

headers = { authorization = basic("viewer", "viewer-password-456") }
local viewer = security.authenticate()
eq(viewer and viewer.role, "viewer", "viewer authenticates")

headers = { authorization = basic("operator", "wrong-password-000") }
eq(security.authenticate(), nil, "wrong password rejected")
eq(exits[#exits], 401, "wrong password status")
ok(security._constant_equal("same", "same"), "constant compare equal")
ok(not security._constant_equal("same", "diff"), "constant compare mismatch")

dict = Dict.new(); ngx.shared.antibot_cache = dict
headers = { authorization = basic("operator", "operator-password-123") }
principal = security.authenticate()
local token, token_err = security.issue_csrf(principal)
ok(token ~= nil and token_err == nil and #token == 64, "csrf token issued")

ngx.var.request_method = "POST"
headers = {
    ["content-type"] = "application/json; charset=utf-8",
    ["origin"] = "https://admin.example.test",
    ["host"] = "admin.example.test",
    ["sec-fetch-site"] = "same-origin",
    ["x-antibot-csrf"] = token,
    ["cookie"] = "a=1; ab_admin_csrf=" .. token .. "; z=2",
}
local allowed, status = security.authorize_mutation(principal)
ok(allowed == true and status == nil, "valid mutation authorized")

ngx.var.remote_addr = "192.0.2.11"
local rebound_ok, rebound_status = security.authorize_mutation(principal)
ok(not rebound_ok and rebound_status == 403, "csrf token is bound to client IP")
ngx.var.remote_addr = "192.0.2.10"

local allowed_view, viewer_status = security.authorize_mutation(viewer)
ok(not allowed_view and viewer_status == 403, "viewer mutation denied")

headers["origin"] = "https://evil.example"
local origin_ok, origin_status = security.authorize_mutation(principal)
ok(not origin_ok and origin_status == 403, "cross origin denied")
headers["origin"] = "https://admin.example.test"

headers["x-antibot-csrf"] = string.rep("0", 64)
local csrf_ok, csrf_status = security.authorize_mutation(principal)
ok(not csrf_ok and csrf_status == 403, "wrong csrf denied")
headers["x-antibot-csrf"] = token

ngx.var.request_method = "GET"
local method_ok, method_status = security.authorize_mutation(principal)
ok(not method_ok and method_status == 405, "GET mutation denied")
ngx.var.request_method = "POST"

headers["content-type"] = "text/plain"
local ct_ok, ct_status = security.authorize_mutation(principal)
ok(not ct_ok and ct_status == 415, "non-json denied")
headers["content-type"] = "application/json"
headers["content-length"] = "9000"
local size_ok, size_status = security.authorize_mutation(principal)
ok(not size_ok and size_status == 413, "oversized mutation denied before body read")
headers["content-length"] = nil

eq(security._cookie_value("x=1; ab_admin_csrf=abc; y=2", "ab_admin_csrf"),
   "abc", "cookie parser")

local valid = security.validate_payload
ok(valid({action="wl_ip_add", ip="2001:db8::1"}, 64), "IPv6 mutation valid")
ok(not valid({action="wl_ip_add", ip="1.2.3.4\nDEL x"}, 64),
   "control characters rejected")
ok(valid({action="wl_url_add", prefix="/api/v1/"}, 64), "URL prefix valid")
ok(not valid({action="wl_url_add", prefix="api/v1"}, 64),
   "relative URL prefix rejected")
ok(valid({action="goodbot_dns_add", name="crawler-1",
          suffixes="crawler.example.com, example.net"}, 128),
   "good-bot registry payload valid")
ok(not valid({action="goodbot_dns_add", name="crawler:bad",
              suffixes="example.com"}, 128), "unsafe registry name rejected")
ok(valid({action="ja3_block", hash=string.rep("a", 32)}, 64), "JA3 valid")
ok(not valid({action="ja3_block", hash="not-a-hash"}, 64), "JA3 invalid")
ok(not valid({action="future_action"}, 32), "unknown action rejected")
ok(not valid({action="ua_sync"}, 9000), "decoded body size bounded")

headers = {
    ["content-type"] = "application/json",
    ["origin"] = "https://admin.example.test",
    ["host"] = "admin.example.test",
    ["sec-fetch-site"] = "same-origin",
    ["x-antibot-csrf"] = token,
    ["cookie"] = "ab_admin_csrf=" .. token,
}
local all_under_limit = true
-- One valid mutation was already counted above; calls 2..30 must pass.
for _ = 2, 30 do
    if not security.authorize_mutation(principal) then all_under_limit = false end
end
ok(all_under_limit, "first 30 mutations in a minute are accepted")
local overflow_ok, overflow_status = security.authorize_mutation(principal)
ok(not overflow_ok and overflow_status == 429, "31st mutation is rate limited")

ngx = real_ngx
print(("ADMIN_SECURITY_OK %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
