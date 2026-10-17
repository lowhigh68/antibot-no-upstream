-- Contract for published operator-network evidence.  A CIDR/IP match must be
-- bound to a compatible self-identification and must never become S4 goodbot.

local pass, fail = 0, 0
local function ok(v, n)
    if v then pass = pass + 1 else
        fail = fail + 1
        io.stderr:write("FAIL: ", n, "\n")
    end
end
local function eq(g, w, n)
    ok(g == w, n .. " (got=" .. tostring(g) .. " want=" .. tostring(w) .. ")")
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end

local store, calls = {}, 0
local dict = { data = {} }
function dict:get(k) return self.data[k] end
function dict:set(k, v) self.data[k] = v; return true end

package.loaded["antibot.core.redis_pool"] = {
    safe_get = function(k) calls = calls + 1; return store[k] end,
}
ngx = { shared = { antibot_cache = dict } }

local opnet = assert(loadfile(src .. "core/operator_network.lua"))()

local function contact(ip, domain)
    return {
        ip = ip,
        automation_meter_claimed = true,
        automation_claimed = true,
        automation_principal = "claude-user",
        automation_inspect = {
            contact_claimed = true,
            contact_domain = domain,
        },
    }
end

store["mon:203.0.113.10"] = "claim@anthropic.com"
local a = contact("203.0.113.10", "anthropic.com")
eq(opnet.resolve(a), true, "matching contact domain and network verify operator")
eq(a.automation_tier, "operator", "operator evidence has a separate tier")
eq(a.automation_proof, "published_ip", "operator proof is explicit")
eq(a.operator_network_mode, "claim", "AI provider network is claim-bound")
eq(a.operator_network_bind, "contact", "contact-domain binding is explicit")
ok(a.good_bot_verified ~= true, "operator network never grants goodbot bypass")

local before = calls
local cached = contact("203.0.113.10", "anthropic.com")
eq(opnet.resolve(cached), true, "positive operator lookup is cached")
eq(calls, before, "positive cache avoids another Redis RTT")

store["mon:203.0.113.11"] = "claim@openai.com"
local crossed = contact("203.0.113.11", "anthropic.com")
eq(opnet.resolve(crossed), false,
   "one provider network cannot verify another provider claim")

store["mon:203.0.113.12"] = "claim@anthropic.com"
local opaque = {
    ip = "203.0.113.12",
    automation_meter_claimed = true,
    automation_claimed = false,
    automation_principal = "anthropic-ai",
    automation_inspect = { machine_claimed = true },
}
eq(opnet.resolve(opaque), true,
   "opaque product binds generically to operator-domain stem")
eq(opaque.automation_claimed, true,
   "bound opaque client becomes a real automation claim")
eq(opaque.operator_network_bind, "stem",
   "opaque product records weaker stem binding")

store["mon:203.0.113.13"] = "claim@anthropic.com"
local generic = {
    ip = "203.0.113.13",
    automation_meter_claimed = true,
    automation_principal = "curl",
    automation_inspect = { machine_claimed = true },
}
eq(opnet.resolve(generic), false,
   "generic machine shape plus unrelated provider range is insufficient")

store["mon:203.0.113.15"] = "ipcap@uptrends.com"
local mode, owner = opnet.lookup("203.0.113.15")
eq(mode, "ipcap", "published uptime range retains IP-only cap policy")
eq(owner, "uptrends.com", "IP-only cap keeps operator provenance")

local human = { ip = "203.0.113.10", automation_meter_claimed = false }
before = calls
eq(opnet.resolve(human), false, "ordinary client skips operator lookup")
eq(calls, before, "ordinary client costs no Redis lookup")

store["mon:203.0.113.14"] = "1"
local legacy = contact("203.0.113.14", "anthropic.com")
eq(opnet.resolve(legacy), false,
   "legacy unowned monitor key cannot grant operator evidence")
mode, owner = opnet.lookup("203.0.113.14")
eq(mode, "legacy", "legacy monitor key survives local-cache round trip")

io.write(string.format("operator_network_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
