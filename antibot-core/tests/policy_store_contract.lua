-- P1.1 init-worker disk/LKG contract.
local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
table.insert(package.loaders, 1, function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    local errors = {}
    for _, path in ipairs({ SRC .. rel .. ".lua", SRC .. rel .. "/init.lua" }) do
        local chunk, err = loadfile(path)
        if chunk then return chunk end
        errors[#errors + 1] = err
    end
    return table.concat(errors, "\n")
end)

local cjson = require "cjson.safe"
local config = require "antibot.core.config"
local policy = require "antibot.core.policy"
local store = require "antibot.core.policy_store"
local pass, fail = 0, 0

local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL policy_store: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end
local function candidate(version, status)
    local value = {
        schema = "1", version = version,
        global = { settings = {} },
        servers = {}, tenants = {}, principals = {},
    }
    if status then
        value.global.settings.l7_admission = { status = status }
    end
    return value
end

local prefix = os.tmpname()
os.remove(prefix)
local active_path = prefix .. ".active.json"
local lkg_path = prefix .. ".lkg.json"
local function cleanup()
    os.remove(active_path); os.remove(lkg_path)
end
local function write(path, raw)
    local fh = assert(io.open(path, "wb"))
    assert(fh:write(raw)); assert(fh:close())
end
local function write_json(path, value)
    write(path, assert(cjson.encode(value)))
end
local opts = { active_path = active_path, lkg_path = lkg_path }

cleanup()
write_json(active_path, candidate("active-a", 430))
write_json(lkg_path, candidate("lkg-a", 431))
local state = store.load(opts)
eq(state.source, "active", "valid active wins")
eq(state.degraded, false, "active is not degraded")
ok(state.version:match("^active%-a%+") ~= nil, "active pver is compiled")
local ctx = {}
policy.resolve(ctx, { server = "x", tenant = "x", principal = "" })
eq(policy.section(ctx, "l7_admission", config.l7_admission).status, 430,
   "active values reach RAM policy")

-- Prove the request operation itself does not touch disk after init-worker.
local real_open = io.open
io.open = function() error("request path attempted file I/O") end
local request_ok = pcall(function()
    local request_ctx = {}
    policy.resolve(request_ctx, { server = "x", tenant = "x", principal = "" })
    assert(policy.section(request_ctx, "l7_admission", config.l7_admission).status == 430)
end)
io.open = real_open
ok(request_ok, "resolve/section use compiled RAM only")

write(active_path, "{broken-json")
state = store.load(opts)
eq(state.source, "last-good", "invalid active falls back to LKG")
eq(state.degraded, true, "LKG fallback is explicit degraded state")
eq(#state.failures, 1, "active rejection is retained for logging")
ctx = {}; policy.resolve(ctx, { server = "x", tenant = "x", principal = "" })
eq(policy.section(ctx, "l7_admission", config.l7_admission).status, 431,
   "complete LKG replaces invalid active")

write_json(active_path, candidate("active-bad", "wrong-type"))
state = store.load(opts)
eq(state.source, "last-good", "schema-invalid active falls back to LKG")
ok(state.failures[1].error:find("must be number", 1, true) ~= nil,
   "validator reason survives fallback")

os.remove(active_path)
state = store.load(opts)
eq(state.source, "last-good", "missing active falls back to LKG")

write(active_path, string.rep("x", store.max_bytes() + 1))
state = store.load(opts)
eq(state.source, "last-good", "oversized active is rejected before decode")
ok(state.failures[1].error:find("larger", 1, true) ~= nil,
   "oversize rejection is diagnosable")

write(active_path, "bad")
write(lkg_path, "bad")
state = store.load(opts)
eq(state.source, "builtin", "two invalid artifacts use built-in overlay")
eq(state.critical, true, "loss of active and LKG is critical")
eq(#state.failures, 2, "both rejection reasons are retained")
ok(policy.current_version():match("^builtin%-p1%.1%+") ~= nil,
   "built-in fallback has an explicit pver")
ctx = {}; policy.resolve(ctx, { server = "x", tenant = "x", principal = "" })
eq(policy.section(ctx, "l7_admission", config.l7_admission),
   config.l7_admission, "built-in fallback is behavior-identical to config")

-- Static boundary: the worker loader must never grow a write/promote path.
local fh = assert(real_open(SRC .. "core/policy_store.lua", "rb"))
local source = fh:read("*a"); fh:close()
ok(source:find("os.rename", 1, true) == nil,
   "worker loader cannot promote a file")
ok(source:find('io.open(path, "wb")', 1, true) == nil,
   "worker loader is read-only")

cleanup()
print(("policy_store_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
