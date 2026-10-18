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
    if self.full or self.add_fails then return nil, "no memory" end
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
dict.add_fails = nil

-- ── Enforcement (18-10-2026) ────────────────────────────────────────
--
-- Truoc ban nay `evaluate()` chi dat `automation_would_throttle` roi tra ve,
-- nen `mode` co la gi cung khong chan. Do duoc tren cloud28-246: 48.798 luot
-- `opnet=openai` trong 48h di thang vao backend trong khi han muc operator
-- 30/10s hien ra trong log.
local exits, said = {}, {}
ngx.header = {}
ngx.status = 200
ngx.say  = function(s) said[#said + 1] = s end
ngx.exit = function(code) exits[#exits + 1] = code; return code end

local cfg_stub = package.loaded["antibot.core.config"].automation
local function enforce_cfg(tiers)
    cfg_stub.mode = "enforce"
    cfg_stub.status = 429
    cfg_stub.retry_after = 10
    cfg_stub.enforce_tiers = tiers
end

local function op_sample(host, class)
    local c = sample(host)
    c.automation_tier = "operator"
    c.req_class = class or "navigation"
    return c
end
cfg_stub.provisional_limits.tiers.operator = { short = 2, long = 8 }
cfg_stub.costs.navigation = 1

-- 1. Duoi han muc thi KHONG chan, du da enforce.
enforce_cfg({ operator = true })
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
local u1 = op_sample("ent.test")
local _, e1 = guard.run(u1)
eq(e1, false, "operator duoi han muc khong bi chan")
eq(u1.automation_throttled, nil, "duoi han muc khong danh dau throttled")
eq(#exits, 0, "duoi han muc khong ngx.exit")

-- 2. Vuot han muc thi chan bang 429 + Retry-After.
guard.run(op_sample("ent.test"))
local u3 = op_sample("ent.test")
local _, e3 = guard.run(u3)
eq(u3.automation_would_throttle, true, "vuot han muc duoc ghi nhan")
eq(e3, true, "enforce tra exit=true")
eq(exits[#exits], 429, "throttle tra 429, khong phai 403/503")
eq(ngx.header["Retry-After"], "10", "co Retry-After de crawler lui lai")
eq(u3.action, "throttled", "capacity throttle khong phai phan quyet bot")
eq(u3.automation_throttled, true, "co cot rieng de dem luot CHAN THAT")
ok(tostring(u3.action_reason):find("automation_guard:operator", 1, true) ~= nil,
   "reason neu ro tang va truc")

-- 3. Tang KHONG nam trong enforce_tiers thi chi quan sat.
--    Day la rao chan FP quan trong nhat: khach that bi phan loai nham thanh
--    automation se roi vao `unknown`, va tang do phai khong bao gio bi chan.
enforce_cfg({ operator = true })
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.unknown = { short = 1, long = 4 }
local unk1 = sample("ent.test")
unk1.req_class = "navigation"
guard.run(unk1)
local unk2 = sample("ent.test")
unk2.req_class = "navigation"
local _, eu = guard.run(unk2)
eq(unk2.automation_would_throttle, true, "unknown vuot han muc van do duoc")
eq(eu, false, "unknown KHONG bi chan khi khong nam trong enforce_tiers")
eq(unk2.automation_throttled, nil, "unknown khong bi danh dau throttled")
eq(#exits, 0, "unknown khong ngx.exit")

-- 4. Meter hong thi KHONG chan. Chan dua tren mot con so khong doc duoc
--    chinh la cach mot loi do bien thanh mot su co.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
-- Ca degraded phai dung "da vuot han muc RUNG dict hong", khong phai "dict
-- hong tu dau". Hai bien the khac han:
--
--   hong tu dau   `add` that bai -> `bump` tra nil -> counter nil -> ratio 0
--                 -> KHONG BAO GIO would_throttle -> cong fail-open khong he
--                 duoc cham toi. Dot bien go cong van xanh (MUT 2 song sot),
--                 tuc phep thu do nham mot thu khac.
--   hong giua chung  counter da co va DA vuot, roi mot truc moi (host chua
--                 co khoa) khong `add` duoc -> degraded=true VA
--                 would_throttle=true cung luc. Day moi la trang thai ma
--                 cong fail-open ton tai de xu ly.
-- Lam am counter o che do SHADOW truoc: o che do enforce, chinh cac request
-- lam am da bi chan va thoat, nen counter khong bao gio len du. (Ban dau toi
-- lam am ngay trong enforce va phep thu bao "van vuot han muc: got=false" —
-- dung la cho fail-open, sai la o thu tu dung fixture.)
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.mode = "shadow"
guard.run(op_sample("deg.test"))
guard.run(op_sample("deg.test"))
local warm = op_sample("deg.test")
guard.run(warm)
eq(warm.automation_would_throttle, true, "da vuot han muc truoc khi dict hong")
cfg_stub.mode = "enforce"
-- `bump()` thoat ngay khi `add` tra loi khac "exists", nen khi shared dict het
-- cho thi MOI counter deu la nil, `consider()` tinh ratio 0 va
-- `would_throttle` khong bao gio bat. Tuc o duong NAY, fail-open dat duoc
-- bang chinh phep tinh chu khong phai bang cong o `evaluate()`.
--
-- Ghi ro vi tri nay chu khong giau no: cong `automation_degraded` van can,
-- va duong con lai dan toi no la nhanh `not dict` (shared dict bien mat han,
-- vd doi ten zone) — nhanh do dat degraded=true TRUOC khi goi `evaluate()`.
-- Phep thu duoi day di dung nhanh ay.
dict.add_fails = true
local d3 = op_sample("deg.test")
local _, ed = guard.run(d3)
eq(d3.automation_degraded, true, "dict het cho -> meter hong duoc danh dau")
eq(d3.automation_would_throttle, false,
   "counter nil -> ratio 0, khong the ket luan vuot han muc")
eq(ed, false, "meter hong thi fail-open, khong chan")
eq(d3.automation_throttled, nil, "meter hong khong danh dau throttled")
eq(#exits, 0, "meter hong khong ngx.exit")
dict.add_fails = nil

-- Nhanh `not dict`: degraded=true duoc dat TRUOC `evaluate()`, va o day
-- counter cu van con trong ctx tu lan truoc nen gate moi that su duoc kiem.
local saved_dict = ngx.shared.antibot_cache
ngx.shared.antibot_cache = nil
exits = {}
local nd = op_sample("deg.test")
nd.automation_principal_short = 999   -- gia vo da vuot xa han muc
local _, end_exit = guard.run(nd)
eq(nd.automation_degraded, true, "mat shared dict -> degraded")
eq(end_exit, false, "mat shared dict thi fail-open du counter cao")
eq(#exits, 0, "mat shared dict khong ngx.exit")
ngx.shared.antibot_cache = saved_dict

-- 5. mode=shadow van khong chan du tang nam trong enforce_tiers.
cfg_stub.mode = "shadow"
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
guard.run(op_sample("sh.test"))
guard.run(op_sample("sh.test"))
local s3 = op_sample("sh.test")
local _, es = guard.run(s3)
eq(s3.automation_would_throttle, true, "shadow van do duoc")
eq(es, false, "shadow khong chan")
eq(#exits, 0, "shadow khong ngx.exit")
cfg_stub.mode = "enforce"

-- 6. Truc vuot duoc ghi lai, khong chi truc co ti le cao nhat.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
guard.run(op_sample("ax.test"))
guard.run(op_sample("ax.test"))
local ax = op_sample("ax.test")
guard.run(ax)
ok(ax.automation_breached ~= nil and #ax.automation_breached > 0,
   "truc vuot duoc ghi lai de tune va de ghi reason")
ok(tostring(ax.automation_breached[1]):find("principal", 1, true) ~= nil,
   "truc principal la truc vuot dau tien")

io.write(string.format("automation_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
