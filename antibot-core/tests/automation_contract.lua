-- Behavioral contract for generic automation evidence + shadow metering.

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

-- The production resolver is exercised elsewhere. Here we pin the policy that
-- consumes its evidence, without DNS/network dependencies.
package.loaded["antibot.detection.bot.ua_check"] = {
    run = function(ctx)
        if ctx.fixture_claim then
            ctx.good_bot_claimed = true
            ctx.good_bot_name = "fixture-client"
            ctx.good_bot_suffixes = {}
            ctx.good_bot_registered = ctx.fixture_registered == true
            ctx.bot_score = ctx.good_bot_registered and 0 or 0.4
        end
    end,
}
package.loaded["antibot.detection.bot.dns_reverse"] = {
    run = function(ctx) ctx.dns_rev_valid = false; return true, false end,
}
package.loaded["antibot.detection.bot.dns_forward"] = {
    run = function() return true, false end,
}
package.loaded["antibot.detection.bot.bot_score"] = { run = function() end }
package.loaded["antibot.detection.bot.cloud_suffixes"] = {
    CLOUD_PTR_SUFFIXES = {},
}
package.loaded["antibot.detection.bot.asn_policy"] = {}
package.loaded["antibot.core.redis_pool"] = {}

ngx = { INFO = 1, ERR = 3, log = function() end }
local bot = assert(loadfile(src .. "detection/bot/init.lua"))()

local unknown = {
    good_bot_registered = false,
    good_bot_verified = false,
    bot_ua = "fake_good_bot",
    bot_score = 0.85,
}
eq(bot.resolve_unverified(unknown), "unknown",
   "unregistered missing proof stays unknown")
eq(unknown.bot_ua, "automation_unknown",
   "unregistered claim is not labelled fake")
eq(unknown.bot_score, 0.4,
   "unknown claim gets neutral automation baseline")
ok(unknown.good_bot_verified ~= true,
   "unknown claim receives no verification trust")

local degraded = {
    good_bot_registered = false,
    dns_rev_degraded = true,
    bot_score = 0,
}
eq(bot.resolve_unverified(degraded), "unknown",
   "resolver failure remains unknown")
eq(degraded.bot_score, 0.4,
   "resolver failure is not a zero-point trust bonus")
eq(degraded.good_bot_dns_degraded, true,
   "resolver failure remains observable")

local contradicted = {
    good_bot_registered = true,
    dns_rev_valid = false,
    bot_score = 0,
}
eq(bot.resolve_unverified(contradicted), "contradicted",
   "registered evidence mismatch is contradicted")
eq(contradicted.bot_ua, "fake_good_bot",
   "registered contradiction preserves fake-bot verdict")
eq(contradicted.good_bot_verified, false,
   "registered contradiction is explicit negative evidence")

local integrated_unknown = {
    fixture_claim = true, fixture_registered = false,
    ip = "203.0.113.20",
}
bot.run(integrated_unknown)
eq(integrated_unknown.automation_tier, "unknown",
   "full bot lane normalizes unregistered NXDOMAIN to unknown")
eq(integrated_unknown.bot_ua, "automation_unknown",
   "full bot lane does not restore legacy fake label")

local integrated_known = {
    fixture_claim = true, fixture_registered = true,
    ip = "203.0.113.21",
}
bot.run(integrated_known)
eq(integrated_known.automation_tier, "contradicted",
   "full bot lane keeps registered NXDOMAIN contradicted")
eq(integrated_known.bot_ua, "fake_good_bot",
   "registered mismatch still reaches hard fake verdict")

package.loaded["antibot.core.redis_pool"] = {
    safe_get = function() return nil end,
}
package.loaded["antibot.core.goodbot_registry"] =
    assert(loadfile(src .. "core/goodbot_registry.lua"))()
package.loaded["antibot.detection.bot.cloud_suffixes"] = {
    BROWSER_STANDARD_TOKENS = {},
}
package.loaded["antibot.detection.bot.asn_policy"] = {
    matches = function() return false end,
    is_corroborative = function() return false end,
}
ngx = {
    DEBUG = 0, INFO = 1, log = function() end,
    var = { http_sec_fetch_site = "", http_x_internal = "" },
    shared = { antibot_ua_cache = { get = function() end, set = function() end } },
}
local ua_check = assert(loadfile(src .. "detection/bot/ua_check.lua"))()
local contact_ctx = {
    ua = "ChatGPT-User/1.0; +https://openai.com/bot",
    ip = "203.0.113.22",
}
ua_check.run(contact_ctx)
eq(contact_ctx.good_bot_claimed, true,
   "contact-only product enters full evidence lane")
eq(contact_ctx.automation_contact_only, true,
   "contact-only product is distinct from legacy crawler hold")
eq(contact_ctx.good_bot_registered, false,
   "contact-only product earns no registry status")
eq(contact_ctx.bot_score, 0.4,
   "contact-only claim starts at neutral automation baseline")
eq(contact_ctx.bot_contact_host, "openai.com",
   "HTTP contact host is available to attestation")

local mail_ctx = {
    ua = "Claude-User/1.0; +mailto:crawler@example.test",
    ip = "203.0.113.23",
}
ua_check.run(mail_ctx)
eq(mail_ctx.bot_contact_host, "example.test",
   "mailto domain is available to attestation")

local bare_mail_ctx = {
    ua = "Claude-User/1.0; +Claude-User@anthropic.com",
    ip = "203.0.113.24",
}
ua_check.run(bare_mail_ctx)
eq(bare_mail_ctx.good_bot_claimed, true,
   "bare mailbox enters neutral automation evidence lane")
eq(bare_mail_ctx.bot_ua_compliant, nil,
   "bare mailbox is not promoted to contact-attestable syntax")
eq(bare_mail_ctx.bot_score, 0.4,
   "bare mailbox keeps unknown-automation score")

-- Shadow governor: fixed buckets in existing shared memory, host-scoped and
-- cost-weighted. It must never alter action or return an exit.
local clock = 100
local Dict = {}
Dict.__index = Dict
function Dict.new() return setmetatable({ data = {}, expiry = {} }, Dict) end
function Dict:_live(k)
    if self.expiry[k] and self.expiry[k] <= clock then
        self.data[k], self.expiry[k] = nil, nil
    end
    return self.data[k]
end
function Dict:add(k, v, ttl)
    if self.full then return nil, "no memory" end
    if self:_live(k) ~= nil then return nil, "exists" end
    self.data[k], self.expiry[k] = v, clock + ttl
    return true
end
function Dict:incr(k, n)
    local v = self:_live(k)
    if v == nil then return nil, "not found" end
    self.data[k] = v + n
    return self.data[k]
end

local dict = Dict.new()
package.loaded["antibot.core.config"] = {
    automation = {
        enabled = true, mode = "shadow",
        windows = { short = 10, long = 60 },
        costs = { resource = 0.1, navigation = 1, auth_endpoint = 4 },
        provisional_limits = {
            tiers = {
                unknown = { short = 5, long = 20 },
                verified = { short = 100, long = 200 },
            },
            ip = { short = 100, long = 200 },
            host = { short = 100, long = 200 },
            server = { short = 100, long = 200 },
        },
    },
}
package.loaded["antibot.core.operator_network"] = {
    resolve = function() return false end,
}
ngx = {
    shared = { antibot_cache = dict }, var = {}, is_subrequest = false,
    time = function() return clock end,
    md5 = function(s) return s end,
}
package.loaded["antibot.l7.automation_guard"] = nil
local guard = assert(loadfile(src .. "l7/automation_guard.lua"))()

local function sample(host)
    return {
        automation_claimed = true,
        automation_meter_claimed = true,
        automation_principal = "generic-client",
        automation_tier = "unknown",
        req = { host = host }, req_class = "auth_endpoint",
        ip = "198.51.100.10", action = "allow",
    }
end

local a = sample("one.test")
local _, exit_a = guard.run(a)
eq(exit_a, false, "shadow meter never exits")
eq(a.automation_cost, 4, "auth endpoint carries backend-cost units")
eq(a.automation_would_throttle, false, "first weighted request is below provisional gate")
eq(a.action, "allow", "shadow meter does not change action")

local b = sample("one.test")
guard.run(b)
eq(b.automation_principal_short, 8,
   "same principal and host accumulates weighted units")
eq(b.automation_would_throttle, true,
   "provisional shadow gate is observable")
eq(b.action, "allow", "would-throttle remains non-enforcing")

local other = sample("two.test")
guard.run(other)
eq(other.automation_principal_short, 4,
   "principal budget is isolated per host")

b.automation_tier = "verified"
guard.evaluate(b)
eq(b.automation_would_throttle, false,
   "evidence-tier reevaluation does not increment counters")
eq(b.automation_principal_short, 8,
   "tier reevaluation preserves measured count")

dict.full = true
local broken = sample("three.test")
guard.run(broken)
eq(broken.automation_degraded, true,
   "shared-dict exhaustion is visible")
eq(broken.action, "allow", "meter failure is fail-open")

io.write(string.format("automation_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
