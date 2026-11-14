local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end

local pass, fail = 0, 0
local function ok(v, name)
    if v then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL actor: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local real_md5 = ngx.md5
local now = 1800000000
ngx = {
    ERR = 3, INFO = 1, WARN = 2,
    md5 = real_md5,
    time = function() return now end,
    log = function() end,
    var = { server_name = "one.test", host = "one.test", scheme = "https" },
    header = {},
}

local current, previous = string.rep("a", 32), string.rep("b", 32)
package.loaded["antibot.core.config"] = {
    actor = { cookie_name = "antibot_sid", ttl = 2592000, future_skew = 300 },
}
package.loaded["antibot.core.secrets"] = {
    actor_secrets = function()
        return { current = current, previous = previous }
    end,
}
package.loaded["antibot.core.site_scope"] = assert(loadfile(
    SRC .. "core/site_scope.lua"))()
package.loaded["resty.random"] = {
    bytes = function(n, _strong)
        ok(n == 16, "issuer requests 128 bits")
        return string.rep(string.char(7), n)
    end,
}

local actor = assert(loadfile(SRC .. "core/actor_token.lua"))()
local nonce = string.rep("01", 16)
local data = actor._data_for_test("one.test", nonce, now)
local mac = actor._hmac_for_test(current, data)
ok(type(mac) == "string" and #mac == 64, "HMAC-SHA256 available")
local token = table.concat({"v1", nonce, tostring(now), mac}, ".")

local id, kind = actor._verify_for_test(token, "one.test", now)
ok(type(id) == "string" and #id == 32, "valid token yields actor id")
eq(kind, "signed_current", "current key classified")
eq(actor._verify_for_test(token, "two.test", now), nil, "token is host bound")
eq(actor._verify_for_test(token:gsub(".$", "0"), "one.test", now), nil,
   "tampered token rejected")
eq(actor._verify_for_test(token, "one.test", now + 2592001), nil,
   "expired token rejected")
eq(actor._verify_for_test(token, "one.test", now - 301), nil,
   "future token outside skew rejected")

local previous_mac = actor._hmac_for_test(previous, data)
local previous_token = table.concat({"v1", nonce, tostring(now), previous_mac}, ".")
local previous_id, previous_kind = actor._verify_for_test(previous_token, "one.test", now)
eq(previous_id, id, "rotation preserves actor id")
eq(previous_kind, "signed_previous", "previous key accepted during rotation")

ngx.var.cookie_antibot_sid = token
local ctx = {}
actor.resolve(ctx)
eq(ctx.actor_id, id, "resolve stores actor id")
eq(ctx.actor_presented, true, "valid request cookie is presented")
eq(ctx.actor_valid, true, "valid request cookie marked valid")

ngx.var.cookie_antibot_sid = nil
ngx.header["Set-Cookie"] = "app=x; Path=/"
ctx = {}
local issued, issue_err = actor.issue(ctx)
ok(issued == true and issue_err == nil, "issue succeeds")
eq(ctx.actor_presented, nil, "new response cookie is not presented evidence")
eq(ctx.actor_issued, true, "issue telemetry set")
ok(type(ngx.header["Set-Cookie"]) == "table"
   and #ngx.header["Set-Cookie"] == 2, "Set-Cookie is appended")
local sid_cookie = ngx.header["Set-Cookie"][2]
ok(sid_cookie:find("antibot_sid=v1%.") ~= nil, "SID cookie emitted")
ok(sid_cookie:find("HttpOnly", 1, true) ~= nil
   and sid_cookie:find("SameSite=Lax", 1, true) ~= nil
   and sid_cookie:find("Secure", 1, true) ~= nil,
   "cookie security flags present")

local issued_token = sid_cookie:match("antibot_sid=([^;]+)")
ngx.var.cookie_antibot_sid = issued_token
local returned = {}
actor.resolve(returned)
eq(returned.actor_presented, true, "issued SID qualifies only when returned")
ok(returned.actor_id == ctx.actor_issued_id, "returned actor matches issued telemetry")

print(("actor_token_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
