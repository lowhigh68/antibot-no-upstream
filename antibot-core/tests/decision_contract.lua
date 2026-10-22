local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
package.preload["antibot.core.policy_meta"] = function()
    return assert(loadfile(SRC .. "core/policy_meta.lua"))()
end
package.preload["antibot.core.decision"] = function()
    return assert(loadfile(SRC .. "core/decision.lua"))()
end

local decision = require "antibot.core.decision"
local meta = require "antibot.core.policy_meta"
local pass, fail = 0, 0
local function ok(value, name)
    if value then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL decision: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local ctx = {}
decision.initialize(ctx)
eq(ctx.policy_version, meta.policy_version, "policy version initialized")
eq(ctx.decision_schema, meta.decision_schema, "decision schema initialized")

local good, err = decision.set(ctx, {
    kind = "capacity", source = "test", rule = "limit",
    mode = "enforce", scope = "server", subject = "node", ttl = 30,
    upstream = false,
})
ok(good and err == nil, "valid decision accepted")
eq(ctx.decision_kind, "capacity", "kind")
eq(ctx.decision_source, "test", "source")
eq(ctx.decision_scope, "server", "scope")
eq(ctx.decision_ttl, 30, "ttl")
eq(ctx.decision_upstream_reached, false, "local rejection did not reach upstream")

good, err = decision.set({}, {kind = "nonsense", mode = "enforce"})
ok(not good and err ~= nil, "invalid kind rejected")
good, err = decision.set({}, {kind = "policy", mode = "maybe"})
ok(not good and err ~= nil, "invalid mode rejected")

ctx = {}; decision.finalize_upstream(ctx, "200")
eq(ctx.decision_upstream_reached, true, "upstream status means reached")
ctx = {}; decision.finalize_upstream(ctx, "-")
eq(ctx.decision_upstream_reached, false, "dash means local")
ctx = {decision_upstream_reached = false}
decision.finalize_upstream(ctx, "200")
eq(ctx.decision_upstream_reached, false, "source-set local outcome is authoritative")

local function slurp(file)
    local fh = assert(io.open(file, "rb")); local s = fh:read("*a"); fh:close(); return s
end
local terminal_files = {
    "waf/init.lua", "l7/admission.lua", "l7/automation_guard.lua",
    "l7/endpoint_guard.lua", "l7/dynamic_guard.lua",
    "l7/operator_concurrency.lua", "l7/principal_churn.lua",
    "l7/circuit_breaker.lua", "l7/expensive_filter_guard.lua",
    "l7/ban/ip_ban_check.lua", "l7/ban/ban_store.lua",
    "detection/fleet/check_block.lua", "detection/wp_hardening.lua",
    "detection/browser/beacon_handler.lua",
    "l7/rate/adaptive_limit.lua", "enforcement/init.lua",
    "enforcement/challenge/init.lua", "enforcement/challenge/verify_token.lua",
}
for _, file in ipairs(terminal_files) do
    local source = slurp(SRC .. file)
    ok(source:find("antibot.core.decision", 1, true) ~= nil,
       file .. " imports decision ledger")
    ok(source:find("decision.set", 1, true) ~= nil
       or source:find("decision_ledger.set", 1, true) ~= nil,
       file .. " records a decision")
end

local logger = slurp(SRC .. "async/logger.lua")
for _, field in ipairs({"pver=", "dschema=", "dkind=", "dsrc=", "drule=",
                        "dmode=", "dscope=", "dsubject=", "dttl=", "dup="}) do
    ok(logger:find(field, 1, true) ~= nil, "logger exports " .. field)
end

print(("decision_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
