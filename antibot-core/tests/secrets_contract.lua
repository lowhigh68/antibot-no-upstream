local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
package.preload["antibot.core.secrets"] = function()
    return assert(loadfile(SRC .. "core/secrets.lua"))()
end

local cjson = require "cjson"
local secrets = require "antibot.core.secrets"
local actor_checker = assert(loadfile(SRC .. "waf/scripts/actor_secret_check.lua"))()
local pass, fail = 0, 0

local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL secrets: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end
local function write_tmp(value)
    local path = os.tmpname()
    local fh = assert(io.open(path, "wb"))
    fh:write(type(value) == "string" and value or cjson.encode(value))
    fh:close()
    return path
end
local function valid()
    return {
        schema_version = 1,
        admin = {
            operator = { username = "operator", password = "operator-password-123" },
            viewer   = { username = "viewer",   password = "viewer-password-456" },
        },
        pow = { challenge_secret = string.rep("p", 32) },
        actor = {
            current  = string.rep("a", 32),
            previous = string.rep("b", 32),
        },
        origin_proof = {
            current  = string.rep("o", 32),
            previous = string.rep("r", 32),
        },
        cloudflare = {
            api_token = "cloudflare-api-token-fixture-1234567890",
        },
    }
end

local path = write_tmp(valid())
local value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "valid file loads")
eq(#value.admin_accounts, 2, "two roles")
eq(value.admin_accounts[1].role, "operator", "operator first")
eq(value.admin_accounts[2].role, "viewer", "viewer second")
eq(value.pow_secret, string.rep("p", 32), "pow secret loaded")
eq(value.actor_secrets.current, string.rep("a", 32), "actor current loaded")
eq(value.actor_secrets.previous, string.rep("b", 32), "actor previous loaded")
eq(value.origin_proof_secrets.current, string.rep("o", 32),
   "origin proof current loaded")
eq(value.origin_proof_secrets.previous, string.rep("r", 32),
   "origin proof previous loaded")
eq(value.cloudflare_api.api_token, "cloudflare-api-token-fixture-1234567890",
   "Cloudflare API token loaded")
local cf_value, cf_err = secrets.cloudflare_api()
ok(cf_value ~= nil and cf_err == nil, "Cloudflare accessor returns configured token")
local actor_state, actor_check_err = actor_checker.check(SRC, path)
ok(actor_state ~= nil and actor_check_err == nil, "actor preflight accepts valid file")
eq(actor_state.current_bytes, 32, "actor preflight reports length without value")
eq(actor_state.has_previous, true, "actor preflight reports rotation state")
os.remove(path)

local no_actor = valid()
no_actor.actor = nil
path = write_tmp(no_actor)
value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "actor block optional for fail-open rollout")
ok(value.actor_secrets == nil, "missing actor secret is explicit")
eq(secrets.path(), "<test>", "fixture remains isolated from production path")
local actor_value, actor_err = secrets.actor_secrets()
ok(actor_value == nil and type(actor_err) == "string" and actor_err ~= "",
   "actor accessor fails open with reason")
actor_state, actor_check_err = actor_checker.check(SRC, path)
ok(actor_state == nil and tostring(actor_check_err):find("not configured", 1, true) ~= nil,
   "actor deploy preflight rejects missing actor block")
os.remove(path)

local no_viewer = valid()
no_viewer.admin.viewer = nil
path = write_tmp(no_viewer)
value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "viewer optional")
eq(#value.admin_accounts, 1, "one operator account")
os.remove(path)

local no_origin_proof = valid()
no_origin_proof.origin_proof = nil
path = write_tmp(no_origin_proof)
value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "origin proof optional for fail-safe rollout")
local origin_value, origin_err = secrets.origin_proof_secrets()
ok(origin_value == nil and tostring(origin_err):find("not configured", 1, true) ~= nil,
   "origin proof accessor fails closed with reason")
os.remove(path)

local no_cloudflare = valid()
no_cloudflare.cloudflare = nil
path = write_tmp(no_cloudflare)
value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "Cloudflare API block optional")
cf_value, cf_err = secrets.cloudflare_api()
ok(cf_value == nil and tostring(cf_err):find("not configured", 1, true) ~= nil,
   "Cloudflare accessor fails closed with reason")
os.remove(path)

local bad = valid()
bad.admin.operator.password = "short"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("16%-512") ~= nil, "short password rejected")
os.remove(path)

bad = valid()
bad.pow.challenge_secret = "too-short"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("32%-512") ~= nil, "short pow secret rejected")
os.remove(path)

bad = valid()
bad.actor.current = "too-short"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("actor.current", 1, true) ~= nil,
   "short actor secret rejected")
os.remove(path)

bad = valid()
bad.actor.previous = bad.actor.current
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("must differ", 1, true) ~= nil,
   "actor rotation keys must differ")
os.remove(path)

bad = valid()
bad.actor.current = bad.pow.challenge_secret
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("pow.challenge_secret", 1, true) ~= nil,
   "actor current cannot reuse pow secret")
os.remove(path)

bad = valid()
bad.actor.previous = bad.pow.challenge_secret
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("pow.challenge_secret", 1, true) ~= nil,
   "actor previous cannot reuse pow secret")
os.remove(path)

bad = valid()
bad.origin_proof.current = "too-short"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("origin_proof.current", 1, true) ~= nil,
   "short origin proof secret rejected")
os.remove(path)

bad = valid()
bad.origin_proof.previous = bad.origin_proof.current
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("must differ", 1, true) ~= nil,
   "origin proof rotation keys must differ")
os.remove(path)

bad = valid()
bad.origin_proof.current = bad.actor.current
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("must not reuse", 1, true) ~= nil,
   "origin proof cannot reuse actor secret")
os.remove(path)

bad = valid()
bad.origin_proof.previous = bad.pow.challenge_secret
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("must not reuse", 1, true) ~= nil,
   "origin proof previous cannot reuse PoW secret")
os.remove(path)

bad = valid()
bad.cloudflare.api_token = "too-short"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("cloudflare.api_token", 1, true) ~= nil,
   "short Cloudflare API token rejected")
os.remove(path)

bad = valid()
bad.cloudflare.api_token = "valid-length-token-with-newline\n"
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("printable", 1, true) ~= nil,
   "Cloudflare API token control bytes rejected")
os.remove(path)

bad = valid()
bad.admin.viewer.username = bad.admin.operator.username
path = write_tmp(bad)
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("must differ", 1, true) ~= nil,
   "roles cannot share username")
os.remove(path)

path = write_tmp("{not-json")
value, err = secrets._reset_for_test(path)
ok(value == nil and tostring(err):find("invalid JSON", 1, true) ~= nil,
   "invalid JSON rejected")
os.remove(path)

value, err = secrets._reset_for_test("/path/that/does/not/exist/antibot.json")
ok(value == nil and tostring(err):find("cannot read", 1, true) ~= nil,
   "missing file rejected")

local function slurp(file)
    local fh = assert(io.open(file, "rb"))
    local data = fh:read("*a"); fh:close(); return data
end
local config_src = slurp(SRC .. "core/config.lua")
local admin_src = slurp(SRC .. "admin/init.lua")
ok(not config_src:match("challenge_secret%s*=%s*['\"]"),
   "config has no inline challenge secret")
ok(not admin_src:match("AUTH_PASS%s*="), "admin has no inline password")
ok(admin_src:find("antibot.admin.security", 1, true) ~= nil,
   "admin delegates authentication")

print(("secrets_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
