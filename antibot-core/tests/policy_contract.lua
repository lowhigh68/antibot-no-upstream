-- P1.0 compiled policy contract.

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

local config = require "antibot.core.config"
local policy = require "antibot.core.policy"
local pass, fail = 0, 0

local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL policy: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) ..
       " want=" .. tostring(want))
end

local function base(version)
    return {
        schema = "1", version = version or "test-policy",
        global = { settings = {} },
        servers = {}, tenants = {}, principals = {},
    }
end

local raw = base("precedence")
raw.global.settings.l7_admission = { mode = "shadow", status = 430 }
raw.servers["NODE-A"] = {
    settings = { l7_admission = { mode = "enforce" } },
}
raw.tenants["/home/demo/domains/example/public_html/"] = {
    settings = { l7_admission = { status = 431 } },
}
raw.principals["GPTBot"] = {
    settings = { l7_admission = { retry_after = 17 } },
}

local applied, version = policy.configure(raw)
ok(applied, "valid policy accepted")
ok(type(version) == "string" and version:match("^precedence%+[%da-f]+$") ~= nil,
   "compiled version contains deterministic digest")

local ctx = { automation_principal = "gptbot" }
policy.resolve(ctx, {
    server = "node-a",
    tenant = "/home/demo/domains/example/public_html",
    principal = "gptbot",
})
local admission = policy.section(ctx, "l7_admission", config.l7_admission)
eq(admission.mode, "enforce", "server overrides global")
eq(admission.status, 431, "tenant overrides server/global")
eq(admission.retry_after, 17, "principal is final override")
eq(admission.enabled, config.l7_admission.enabled,
   "unspecified value comes from shipped config")
eq(ctx.policy_version, version, "request receives compiled version")

-- A late proof can refine the canonical principal after ctx initialization.
-- section() must refresh instead of keeping the weaker early scope forever.
local late = {}
policy.resolve(late, { server = "node-a", tenant = "-", principal = "" })
late.automation_principal = "GPTBOT"
eq(policy.section(late, "l7_admission", config.l7_admission).retry_after,
   17, "late principal refreshes resolution")

-- Request-local merged tables must not mutate the active policy or config.
admission.status = 599
local fresh = { automation_principal = "gptbot" }
policy.resolve(fresh, {
    server = "node-a",
    tenant = "/home/demo/domains/example/public_html",
    principal = "gptbot",
})
eq(policy.section(fresh, "l7_admission", config.l7_admission).status,
   431, "resolved section is request-local")
eq(config.l7_admission.status, 429, "shipped config remains immutable")

-- Empty overlays are zero-behaviour: section() returns the original table.
local empty = base("empty")
ok(policy.configure(empty), "empty policy accepted")
local empty_ctx = {}
policy.resolve(empty_ctx, { server = "none", tenant = "none", principal = "" })
eq(policy.section(empty_ctx, "l7_admission", config.l7_admission),
   config.l7_admission, "empty overlay preserves original table")
for name in pairs(policy.registered_sections()) do
    ok(config[name] ~= nil, name .. " has a shipped default")
    eq(policy.section(empty_ctx, name, config[name]), config[name],
       name .. " empty overlay is behaviour-identical")
end

-- Canonical serialization must not depend on Lua pairs() order.
local order_a = base("order")
order_a.global.settings.l7_admission = { status = 430, retry_after = 9 }
local order_b = base("order")
order_b.global.settings.l7_admission = { retry_after = 9, status = 430 }
local ca = assert(policy.compile(order_a))
local cb = assert(policy.compile(order_b))
eq(ca.policy_version, cb.policy_version, "digest independent of key order")
order_b.global.settings.l7_admission.status = 431
local cc = assert(policy.compile(order_b))
ok(cc.policy_version ~= ca.policy_version, "digest changes with policy value")

local function rejected(mutator, name)
    local candidate = base("bad")
    mutator(candidate)
    local valid, errors = policy.validate(candidate)
    ok(not valid and type(errors) == "table" and #errors > 0, name)
end

rejected(function(p) p.typo = true end, "unknown root key rejected")
rejected(function(p) p.schema = "2" end, "unknown schema rejected")
rejected(function(p) p.version = "contains space" end,
         "unsafe version token rejected")
rejected(function(p) p.version = string.rep("a", 56) end,
         "version cannot truncate digest in logger")
rejected(function(p)
    p.global.settings.redis = { timeout_ms = 1 }
end, "unregistered sensitive section rejected")
rejected(function(p)
    p.global.settings.l7_admission = { mdoe = "shadow" }
end, "unknown setting rejected")
rejected(function(p)
    p.global.settings.l7_admission = { status = "429" }
end, "wrong setting type rejected")
rejected(function(p)
    p.servers["NODE"] = { settings = {} }
    p.servers["node"] = { settings = {} }
end, "normalized duplicate server rejected")
rejected(function(p)
    p.global.settings.l7_admission = {
        limits = { ip = { made_up_class = { short = 1, long = 2 } } },
    }
end, "unknown nested setting rejected")

-- Rejecting a candidate must retain the complete previously active policy.
assert(policy.configure(empty))
local before = policy.current_version()
local bad = base("bad-apply")
bad.global.settings.l7_admission = { status = "wrong" }
local accepted, errors = policy.configure(bad)
ok(not accepted and type(errors) == "table", "invalid candidate not applied")
eq(policy.current_version(), before, "invalid candidate retains active policy")

-- The repository candidate itself is part of the deployment contract.
local runtime = assert(loadfile(SRC .. "core/policy_runtime.lua"))()
local runtime_ok, runtime_errors = policy.validate(runtime)
ok(runtime_ok, "shipped policy_runtime passes validator: " ..
   tostring(runtime_errors and runtime_errors[1]))

local decision = require "antibot.core.decision"
assert(policy.configure(runtime))
local decision_ctx = {}
decision.initialize(decision_ctx)
eq(decision_ctx.policy_version, policy.current_version(),
   "direct endpoint decision receives active policy version")

local sections = policy.registered_sections()
for _, name in ipairs({
    "automation", "automation_concurrency", "principal_churn",
    "l7_admission", "endpoint_guard", "dynamic_guard",
    "l7_surge_guard", "l7_circuit_breaker", "expensive_filter", "ip_tour",
}) do
    ok(sections[name] == true, name .. " is registered")
end

local consumers = {
    automation = "l7/automation_guard.lua",
    automation_concurrency = "l7/operator_concurrency.lua",
    principal_churn = "l7/principal_churn.lua",
    l7_admission = "l7/admission.lua",
    endpoint_guard = "l7/endpoint_guard.lua",
    dynamic_guard = "l7/dynamic_guard.lua",
    l7_surge_guard = "l7/surge_guard.lua",
    l7_circuit_breaker = "l7/circuit_breaker.lua",
    expensive_filter = "l7/expensive_filter_guard.lua",
    ip_tour = "detection/ip_tour.lua",
}
for name, file in pairs(consumers) do
    local fh = assert(io.open(SRC .. file, "rb"))
    local source = fh:read("*a"); fh:close()
    ok(source:find('policy.section(ctx, "' .. name .. '"', 1, true) ~= nil,
       name .. " has a real request-path consumer")
end

print(("policy_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
