local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
package.preload["antibot.core.secrets"] = function()
    return assert(loadfile(SRC .. "core/secrets.lua"))()
end

local cjson = require "cjson"
local secrets = require "antibot.core.secrets"
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
    }
end

local path = write_tmp(valid())
local value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "valid file loads")
eq(#value.admin_accounts, 2, "two roles")
eq(value.admin_accounts[1].role, "operator", "operator first")
eq(value.admin_accounts[2].role, "viewer", "viewer second")
eq(value.pow_secret, string.rep("p", 32), "pow secret loaded")
os.remove(path)

local no_viewer = valid()
no_viewer.admin.viewer = nil
path = write_tmp(no_viewer)
value, err = secrets._reset_for_test(path)
ok(value ~= nil and err == nil, "viewer optional")
eq(#value.admin_accounts, 1, "one operator account")
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
