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

-- 7. Server-axis gom that su qua NHIEU host/principal. Day la cong bao ve
-- backend chung khi mot operator chia tai ra nhieu domain: moi principal con
-- duoi budget rieng, nhung request dat tran toan may van phai bi throttle.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.operator = { short = 100, long = 200 }
cfg_stub.provisional_limits.ip = { short = 100, long = 200 }
cfg_stub.provisional_limits.host = { short = 100, long = 200 }
cfg_stub.provisional_limits.server = { short = 3, long = 200 }

local sv1 = op_sample("one.test")
sv1.ip, sv1.automation_principal = "192.0.2.1", "gptbot"
local _, sx1 = guard.run(sv1)
local sv2 = op_sample("two.test")
sv2.ip, sv2.automation_principal = "192.0.2.2", "oai-searchbot"
local _, sx2 = guard.run(sv2)
local sv3 = op_sample("three.test")
sv3.ip, sv3.automation_principal = "192.0.2.3", "claudebot"
local _, sx3 = guard.run(sv3)

eq(sx1, false, "server-axis: request dau con duoi tran")
eq(sx2, false, "server-axis: request hai con duoi tran")
eq(sv3.automation_server_short, 3,
   "server-axis cong chi phi qua ba host/principal")
eq(sv3.automation_principal_short, 1,
   "moi principal van chi co mot don vi rieng")
eq(sx3, true, "request cham tran server bi throttle")
ok(tostring(sv3.action_reason):find("server:short", 1, true) ~= nil,
   "reason ghi dung server:short")
eq(exits[#exits], 429, "server-axis shed bang 429")

-- 8. Tier khong enforce van gop vao phep do capacity nhung khong tu bi chan.
-- Khi operator den sau, no la tier uu tien thap bi shed; khach nguoi that
-- khong vao automation meter, con verified/unknown van observation-only.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.server = { short = 2, long = 200 }
local vv1 = sample("verified-a.test")
vv1.automation_tier, vv1.automation_principal = "verified", "googlebot"
local _, vx1 = guard.run(vv1)
local vv2 = sample("verified-b.test")
vv2.automation_tier, vv2.automation_principal = "verified", "bingbot"
local _, vx2 = guard.run(vv2)
eq(vx1, false, "verified duoi server budget khong bi chan")
eq(vv2.automation_would_throttle, true,
   "verified van cho thay server capacity da day")
eq(vx2, false, "verified khong bi chan du cham tran server")
eq(#exits, 0, "verified khong ngx.exit")

local low = op_sample("operator-after-verified.test")
low.ip, low.automation_principal = "192.0.2.9", "gptbot"
local _, low_exit = guard.run(low)
eq(low_exit, true, "operator den khi server day bi shed")
ok(tostring(low.action_reason):find("server:short", 1, true) ~= nil,
   "priority shedding ghi dung truc server")

-- 10. Truc FLEET: principal toan may, chan dung phep NHAN mau so theo host.
--
-- Tinh huong do duoc tren cloud28-246 18-10: GPTBot di qua 17 domain. Truc
-- `(host, principal)` cho no 17 ngan sach doc lap, nen han muc 8/10s thanh
-- hieu dung 136/10s. Phep thu nay dung lai dung hinh dang do: MOT principal,
-- NHIEU host, moi host chi mot request — tung ngan sach principal van o 1, ma
-- tong theo principal thi vuot.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.operator = { short = 100, long = 200 }
cfg_stub.provisional_limits.ip = { short = 100, long = 200 }
cfg_stub.provisional_limits.host = { short = 100, long = 200 }
cfg_stub.provisional_limits.server = { short = 100, long = 200 }
cfg_stub.provisional_limits.fleet = { short = 3, long = 200 }

local f1 = op_sample("d1.test")
f1.ip, f1.automation_principal = "192.0.2.11", "gptbot"
local _, fx1 = guard.run(f1)
local f2 = op_sample("d2.test")
f2.ip, f2.automation_principal = "192.0.2.12", "gptbot"
local _, fx2 = guard.run(f2)
local f3 = op_sample("d3.test")
f3.ip, f3.automation_principal = "192.0.2.13", "gptbot"
local _, fx3 = guard.run(f3)

eq(fx1, false, "fleet: host dau tien con duoi tran")
eq(fx2, false, "fleet: host thu hai con duoi tran")
eq(f3.automation_principal_short, 1,
   "moi (host, principal) van chi thay MOT don vi — day la phep nhan mau so")
eq(f3.automation_fleet_short, 3,
   "truc fleet cong du ba host vao cung mot principal")
eq(fx3, true, "principal vuot tran toan may bi throttle du moi host deu thap")
ok(tostring(f3.action_reason):find("fleet:short", 1, true) ~= nil,
   "reason ghi dung fleet:short")
eq(exits[#exits], 429, "fleet shed bang 429")

-- Principal KHAC khong chia ngan sach: day la dieu truc `server` khong lam
-- duoc. Anthropic+Perplexity chiem 20/5.929 request operator, nen chung khong
-- duoc bi chan chi vi OpenAI dang keo.
local other = op_sample("d4.test")
other.ip, other.automation_principal = "192.0.2.14", "claudebot"
local _, ox = guard.run(other)
eq(other.automation_fleet_short, 1,
   "principal khac co ngan sach fleet RIENG")
eq(ox, false, "claudebot khong bi chan vi gptbot da keo het")

-- Tier khong enforce van dong gop vao counter fleet nhung khong tu bi chan.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.fleet = { short = 2, long = 200 }
local fu1 = sample("u1.test")
fu1.automation_tier, fu1.automation_principal = "unknown", "curl"
local _, fux1 = guard.run(fu1)
local fu2 = sample("u2.test")
fu2.automation_tier, fu2.automation_principal = "unknown", "curl"
local _, fux2 = guard.run(fu2)
-- `sample()` dung `req_class = "auth_endpoint"` -> cost 4, nen HAI request
-- cho counter 8 chu khong phai 2. Day KHONG phai lam tron so mong doi cho
-- khop: counter cong DON VI CHI PHI, khong cong so request, va dinh ngay vao
-- cach doc moi han muc trong `provisional_limits`. Mot han muc 60 khong co
-- nghia la 60 request.
eq(fu2.automation_cost, 4, "auth_endpoint co cost 4, khong phai 1")
eq(fu2.automation_fleet_short, 8,
   "counter fleet cong DON VI CHI PHI (2 request x cost 4), khong cong luot")
eq(fu2.automation_would_throttle, true, "unknown thay tran fleet da day")
eq(fux1, false, "unknown khong bi chan (rao chan FP chinh)")
eq(fux2, false, "unknown khong bi chan du cham tran fleet")
eq(#exits, 0, "unknown khong ngx.exit")

-- Meter hong (degraded) thi KHONG chan tren truc fleet: throttle tren mot so
-- khong doc duoc la cach mot loi do bien thanh su co.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.fleet = { short = 1, long = 200 }
local fd = op_sample("d5.test")
fd.ip, fd.automation_principal = "192.0.2.15", "gptbot"
local _, fdx1 = guard.run(fd)
eq(fdx1, true, "fleet tran 1: request dau da vuot va bi chan")
local fd2 = op_sample("d6.test")
fd2.ip, fd2.automation_principal = "192.0.2.16", "gptbot"
fd2.automation_degraded = true
local _, fdx2 = guard.run(fd2)
eq(fdx2, false, "meter degraded thi fail-open tren truc fleet")

-- Thu tu truc: `fleet` phai duoc xet TRUOC `server`, vi `breached[1]` la truc
-- di vao `action_reason`. Khi ca hai vuot, truc co tinh phan biet (principal
-- nao dang keo) huu ich hon truc tran chung (toan may dang day).
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.fleet = { short = 1, long = 200 }
cfg_stub.provisional_limits.server = { short = 1, long = 200 }
local both = op_sample("d7.test")
both.ip, both.automation_principal = "192.0.2.17", "gptbot"
local _, bx = guard.run(both)
eq(bx, true, "ca fleet va server deu vuot -> bi chan")
ok(tostring(both.action_reason):find("fleet:short", 1, true) ~= nil,
   "ca hai truc vuot thi reason bao FLEET, khong bao server")
-- Khoi phuc cho cac phep thu sau (neu co) va cho lan chay lai.
cfg_stub.provisional_limits.fleet = nil
cfg_stub.provisional_limits.server = { short = 100, long = 200 }

-- Khong cau hinh `fleet` thi truc do im lang: `consider()` tra ve ngay khi
-- `limits` la nil, nen them truc KHONG lam doi hanh vi cua may chua tune.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
local nf = op_sample("d8.test")
nf.ip, nf.automation_principal = "192.0.2.18", "gptbot"
local _, nfx = guard.run(nf)
eq(nfx, false, "khong cau hinh fleet thi khong chan")
eq(nf.automation_fleet_short, 1,
   "van DEM de do luong du chua cau hinh han muc")

-- 11. FP DA DO DUOC 18-10: principal NHO bi truc `server` chan vi principal
-- LON dang keo.
--
-- `autthr.sh` tren 28-246 sau moc deploy: claudebot bi chan 20 luot, TAT CA
-- qua `server:*`, 0 qua `fleet:*`, trong khi `autfl max` cua no moi la 12,0
-- tren tran 60 (0,20x). Tuc Anthropic bi 429 chi vi OpenAI dang keo.
--
-- Phep thu dung lai dung hinh dang do: mot principal keo day truc server, roi
-- mot principal khac den voi dung MOT request. Voi quan he `server` long hon
-- `fleet` (bat biens trong pipeline_contract), principal nho phai di qua.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.operator = { short = 100, long = 200 }
cfg_stub.provisional_limits.ip = { short = 100, long = 200 }
cfg_stub.provisional_limits.host = { short = 100, long = 200 }
cfg_stub.provisional_limits.fleet = { short = 3, long = 50 }
cfg_stub.provisional_limits.server = { short = 9, long = 150 }  -- 3x fleet

-- Principal lon keo 3 request tren 3 host khac nhau -> fleet cua no = 3, cham
-- tran rieng; server = 3, con xa 9.
for i = 1, 3 do
    local big = op_sample("big" .. i .. ".test")
    big.ip, big.automation_principal = "192.0.2.3" .. i, "gptbot"
    local _, bx = guard.run(big)
    if i < 3 then
        eq(bx, false, "principal lon: request " .. i .. " con duoi tran fleet")
    else
        eq(bx, true, "principal lon: cham tran FLEET rieng cua no")
    end
end

-- Principal NHO den voi dung MOT request. Counter server da la 3 (do principal
-- lon day len), nhung tran server la 9 nen no con cach xa.
local small = op_sample("small.test")
small.ip, small.automation_principal = "192.0.2.99", "claudebot"
local _, sx = guard.run(small)
eq(small.automation_fleet_short, 1,
   "principal nho co ngan sach fleet RIENG, chi 1 don vi")
eq(small.automation_server_short, 4,
   "nhung counter server DA bi principal lon day len 3 + 1 cua no")
eq(sx, false,
   "principal nho KHONG bi chan — day la FP da do duoc tren 28-246")
eq(small.automation_would_throttle, false,
   "va no cung khong hien ra nhu da vuot han muc")

-- Nguoc lai: neu `server` bi dat CHAT HON `fleet` thi FP quay lai. Phep thu
-- nay ghim chinh co che, khong chi ghim con so.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.fleet = { short = 50, long = 200 }
cfg_stub.provisional_limits.server = { short = 3, long = 200 }  -- CHAT hon fleet
for i = 1, 3 do
    local big = op_sample("b" .. i .. ".test")
    big.ip, big.automation_principal = "192.0.2.4" .. i, "gptbot"
    guard.run(big)
end
local victim = op_sample("victim.test")
victim.ip, victim.automation_principal = "192.0.2.98", "claudebot"
local _, vx2 = guard.run(victim)
eq(victim.automation_fleet_short, 1,
   "nan nhan chi co 1 don vi tren truc fleet")
eq(vx2, true,
   "server CHAT hon fleet -> principal nho bi chan oan (FP tai tao duoc)")
ok(tostring(victim.action_reason):find("server", 1, true) ~= nil,
   "va reason ghi dung truc server — day la dau vet de nhan ra FP trong log")

-- Khoi phuc cho lan chay lai.
cfg_stub.provisional_limits.fleet = nil
cfg_stub.provisional_limits.server = { short = 100, long = 200 }

-- 12. COUNTER DUOC CONG TRUOC KHI QUYET DINH CHAN.
--
-- Day la co che giai thich mot quan sat tuong nhu vo ly tren 28-246: noi tran
-- `server` gap BA (20/60 -> 45/180) ma so luot vuot lai TANG (3937 -> 4781).
-- `pair()` cong counter o `run()` CON `evaluate()` chay sau, nen mot request
-- da bi 429 VAN cong du chi phi vao moi truc. Truc `server` do do do "tong
-- request DEN", khong do "tai thuc vao backend".
--
-- Ghim bang test vi no la ly do `server` khong the lam truc rang buoc, va
-- neu ai doi thu tu nay thi ket luan tren se khong con dung.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.operator = { short = 1, long = 100 }
cfg_stub.provisional_limits.ip = { short = 100, long = 200 }
cfg_stub.provisional_limits.host = { short = 100, long = 200 }
cfg_stub.provisional_limits.fleet = { short = 100, long = 200 }
cfg_stub.provisional_limits.server = { short = 100, long = 200 }

local c1 = op_sample("cnt1.test")
c1.ip, c1.automation_principal = "192.0.2.51", "gptbot"
local _, cx1 = guard.run(c1)
eq(cx1, true, "tran principal = 1 nen request dau da bi chan")
eq(c1.automation_server_short, 1, "request BI CHAN van cong 1 vao server")

local c2 = op_sample("cnt2.test")
c2.ip, c2.automation_principal = "192.0.2.52", "gptbot"
local _, cx2 = guard.run(c2)
eq(cx2, true, "request thu hai cung bi chan")
eq(c2.automation_server_short, 2,
   "counter server LEN 2 du CA HAI request deu bi 429 — day la co che")
eq(c2.automation_fleet_short, 2,
   "fleet cung vay: chan khong lam giam counter")

-- 13. `server` khong dat han muc -> truc im lang nhung VAN DEM.
-- Do la hinh dang dang ship: go tinh toan, giu telemetry.
dict = Dict.new()
ngx.shared.antibot_cache = dict
exits = {}
cfg_stub.provisional_limits.tiers.operator = { short = 100, long = 200 }
cfg_stub.provisional_limits.fleet = { short = 100, long = 200 }
cfg_stub.provisional_limits.server = nil

local s1 = op_sample("sv1.test")
s1.ip, s1.automation_principal = "192.0.2.61", "gptbot"
guard.run(s1)
local s2 = op_sample("sv2.test")
s2.ip, s2.automation_principal = "192.0.2.62", "claudebot"
local _, sx2 = guard.run(s2)
eq(s2.automation_server_short, 2,
   "khong dat han muc nhung VAN DEM — telemetry `autss=` con nguyen")
eq(sx2, false, "va khong con chan ai qua truc server")
eq(s2.automation_would_throttle, false,
   "truc im lang khong lam `autwould` bao dong gia")
eq(#exits, 0, "khong co ngx.exit nao")

-- Khoi phuc cho lan chay lai.
cfg_stub.provisional_limits.fleet = nil
cfg_stub.provisional_limits.server = { short = 100, long = 200 }

io.write(string.format("automation_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
