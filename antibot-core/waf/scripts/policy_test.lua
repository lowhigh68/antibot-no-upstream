local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

-- `init.lua` require CHIN module. Thieu mot cai thi `require` di tim theo
-- `package.path` cua `resty` va bao "module not found" — hong ngay tu dong nap,
-- truoc khi chay mot assertion nao. Cung mau `body_test.lua` dung.
--
-- `redis_pool` chi can NAP duoc, khong can chay: `fim_factor` tra `nil` ngay khi
-- `detector_rule == nil` (URI cua test khong khop luat duong dan nao), nen khong
-- luot Redis nao xay ra. Stub o day de khong phu thuoc `resty.redis`.
for _, name in ipairs({
    "registry", "policy", "config", "telemetry",
    "exposed", "args", "upload", "body",
}) do
    package.preload["antibot.waf." .. name] = function()
        return dofile(SRC .. "waf/" .. name .. ".lua")
    end
end
package.preload["antibot.waf.wordpress.paths"] = function()
    return dofile(SRC .. "waf/wordpress/paths.lua")
end
package.preload["antibot.waf.body_core"] = function()
    return dofile(SRC .. "waf/body_core.lua")
end
package.preload["antibot.waf.body_worker"] = function()
    return dofile(SRC .. "waf/body_worker.lua")
end
package.preload["antibot.core.redis_pool"] = function()
    return { safe_get = function() return nil end }
end

-- `require` chu khong `dofile`: `init.lua` cung require nhung module nay, va hai
-- ban sao rieng thi `config.DEFAULT` cua test khong phai ban `init.lua` dung —
-- mot test co the bao xanh trong khi production doc bang khac.
local registry  = require "antibot.waf.registry"
local config    = require "antibot.waf.config"
local policy    = require "antibot.waf.policy"
local telemetry = require "antibot.waf.telemetry"

local pass, fail = 0, 0

local function eq(name, got, want)
    if got == want then
        pass = pass + 1
    else
        fail = fail + 1
        io.write(string.format("SAI  %-48s cho=%s duoc=%s\n",
            name, tostring(want), tostring(got)))
    end
end

local function resolved(runtime, host)
    return config.resolve(config.compile(runtime), host or "example.test")
end

local function state(runtime, host, uri, method)
    local ctx = {}
    local cfg = resolved(runtime, host)
    return ctx, policy.begin(ctx, {
        host = host or "example.test",
        uri = uri or "/index.php",
        method = method or "GET",
    }, cfg)
end

do
    local ctx, st = state()
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("hard invariant is enforced", d.action, "block")
    eq("hard invariant reason", d.reason, "dotfile_exposed")
    eq("decision exported to ctx", ctx.waf_decision, d)
end

do
    local _, st = state({ mode = "shadow" })
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("global shadow allows", d.action, "allow")
    eq("global shadow keeps would_action", d.would_action, "block")
    eq("global shadow flag", d.shadow, true)
end

do
    local _, st = state({
        exceptions = {
            { id = "health-dotfile", rule = "dotfile_exposed",
              host = "example.test", uri_prefix = "/.health/" },
        },
    }, "example.test", "/.health/.probe")
    local hit = policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("exception marks hit", hit.excepted, true)
    eq("exception suppresses verdict", d.action, "allow")
    eq("exception suppresses labels", st.labels["path.forbidden"], nil)
    eq("exception suppresses score", st.score, 0)
end

do
    local _, st = state({ profiles = { wordpress = false } })
    local hit, why = policy.emit(st, "wp_plugin_direct", { target = "URI" })
    eq("wordpress profile can be disabled", hit, nil)
    eq("disabled profile reason", why, "profile_disabled")
end

do
    local _, st = state()
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("new correlation starts shadow", d.action, "allow")
    eq("new correlation computes block", d.would_action, "block")
    eq("upload correlation reason", d.reason, "corr_upload_php_payload")
    eq("upload correlation label", st.labels["correlation.upload_php_payload"], true)
end

do
    local _, st = state({
        correlations = {
            corr_upload_php_payload = { mode = "enforce" },
        },
    })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("measured correlation can be promoted", d.action, "block")
end

do
    local _, st = state({
        rules = { dotfile_exposed = { score = 10 } },
    })
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("shadow candidate cannot mask enforce candidate", d.action, "block")
    eq("actual reason remains enforce candidate", d.reason, "dotfile_exposed")
    eq("correlation is not double-counted in score", d.score, 100)
end

do
    local cfg = config.compile({
        mode = "shadow",
        domains = {
            ["strict.test"] = {
                mode = "enforce",
                rules = { dotfile_exposed = { mode = "shadow" } },
            },
        },
    })
    local strict = config.resolve(cfg, "STRICT.TEST.")
    eq("domain override host normalization", strict.host, "strict.test")
    eq("domain override global mode", strict.mode, "enforce")
    eq("domain override rule mode", strict.rules.dotfile_exposed.mode, "shadow")
end

do
    local ok, errors = config.validate(config.compile({ mode = "enfoce" }))
    eq("invalid mode is rejected", ok, false)
    eq("invalid mode reports error", #errors > 0, true)
end

do
    local _, st = state({
        families = { upload = { action = "observe" } },
    })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("family observe does not feed correlation", d.would_action, "allow")
    eq("family observe does not add label", st.labels["upload.executable"], nil)
end

do
    local _, st = state()
    policy.emit(st, "arg_traversal", { target = "ARGS" })
    local score = st.score
    local _, why = policy.emit(st, "arg_traversal", { target = "ARGS" })
    eq("duplicate fact is identified", why, "duplicate")
    eq("duplicate fact does not add score", st.score, score)
end

do
    local _, st = state({
        score_enforcement = true,
        threshold_mode = "shadow",
        thresholds = { block = 80 },
    })
    policy.emit(st, "arg_php_wrapper", { target = "ARGS" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("score threshold starts shadow", d.action, "allow")
    eq("score threshold would block", d.would_action, "block")
    eq("score threshold reason", d.reason, "score_threshold")
end

do
    local values = {}
    local dict = {}
    function dict:incr(key, amount, initial)
        if values[key] == nil then values[key] = initial or 0 end
        values[key] = values[key] + amount
        return values[key]
    end
    local tick = 10
    local rt = {
        now = function() return tick end,
        shared = { antibot_cache = dict },
    }
    local ctx, st = state()
    telemetry.start(ctx, st.config, rt)
    policy.emit(st, "arg_traversal", { target = "ARGS" })
    local d = policy.decide(st)
    telemetry.record(ctx, st, d, rt)
    telemetry.record(ctx, st, d, rt)
    tick = 10.012
    telemetry.finish(ctx, rt)
    telemetry.finish(ctx, rt)
    eq("telemetry records request once", values["waf:v2:requests"], 1)
    eq("telemetry records rule once", values["waf:v2:rule:arg_traversal"], 1)
    eq("telemetry records latency once", values["waf:v2:latency_count"], 1)
    eq("telemetry latency ms", values["waf:v2:latency_ms_sum"], 12)
end

do
    local ok, errors = registry.validate_sources({ fake = { not_registered = {} } })
    eq("registry detects drift", ok, false)
    eq("registry reports one drift", #errors, 1)
end

-- ── Cau hinh phai TU CHOI khoa la, khong duoc im lang ────────────────────────
--
-- Bon ca duoi day do review 25-09 tim ra, va khong ca nao bi validator ban dau
-- chan. Ba ca dau lam cau hinh KHONG duoc ap (an toan hon y muon, nhung nguoi
-- van hanh tuong da ap). Ca thu tu nguy hiem theo chieu NGUOC: `uri_prefx` bi
-- bo qua nghia la exception mat rang buoc URI, tu "mot duong dan" thanh "moi
-- request tren host". Mot go sai chinh ta mo mot lo tren WAF.
do
    local ok = config.validate(config.compile({ mod = "shadow" }))
    eq("typo `mod` bi tu choi", ok, false)

    ok = config.validate(config.compile({
        rules = { arg_traversal = { mdoe = "shadow" } },
    }))
    eq("typo `mdoe` trong rule override bi tu choi", ok, false)

    ok = config.validate(config.compile({ profiles = { wordpres = false } }))
    eq("typo `wordpres` trong profiles bi tu choi", ok, false)

    ok = config.validate(config.compile({
        exceptions = { { id = "x", rule = "arg_traversal", uri_prefx = "/admin/" } },
    }))
    eq("typo `uri_prefx` trong exception bi tu choi", ok, false)

    ok = config.validate(config.compile({ telemetry = { prefixx = "a" } }))
    eq("typo trong telemetry bi tu choi", ok, false)

    ok = config.validate(config.compile({ thresholds = { blok = 10 } }))
    eq("typo trong thresholds bi tu choi", ok, false)

    -- Va ban hop le phai VAN qua: mot validator tu choi tat ca thi vo dung.
    ok = config.validate(config.compile({
        mode = "shadow",
        profiles = { wordpress = false },
        rules = { arg_traversal = { mode = "shadow", score = 5 } },
        exceptions = { { id = "x", rule = "arg_traversal", uri_prefix = "/a/" } },
        telemetry = { per_host = true, host_limit = 8 },
        thresholds = { block = 60 },
    }))
    eq("cau hinh hop le van qua", ok, true)

    -- `host` do `resolve()` gan, nen validate tren ban da resolve khong bao oan.
    ok = config.validate(config.resolve(config.compile(), "a.test"))
    eq("ban da resolve khong bao loi oan", ok, true)
end

-- ── Exception phai chan CA phan quyet VA cau tuong thich cu ──────────────────
--
-- Hai duong doc cung mot su kien: `ctx.waf_decision` cua policy, va `ctx.waf_arg`
-- ma `compute.lua` doc. Neu exception chi chan duong thu nhat thi cau hinh chi
-- TRONG NHU co hieu luc — diem cu van nap. Test ca hai.
do
    local runtime = {
        exceptions = { { id = "no-args", rule = "arg_traversal" } },
    }
    local ctx, st = state(runtime)
    local hit = policy.emit(st, "arg_traversal", { target = "ARGS" })
    eq("exception danh dau hit", hit.excepted, true)
    eq("exception ghi id", hit.exception_id, "no-args")
    eq("exception giu diem bang 0", st.score, 0)
    eq("exception khong de lai nhan", st.labels["attack.traversal"], nil)
    local d = policy.decide(st)
    eq("exception -> allow", d.action, "allow")
    eq("exception -> would_action cung allow", d.would_action, "allow")
end

-- `uri_prefix` phai RANG BUOC, khong duoc ap ngoai pham vi.
do
    local runtime = {
        exceptions = { { id = "adm", rule = "arg_traversal", uri_prefix = "/adm/" } },
    }
    local _, inside = state(runtime, "a.test", "/adm/x.php")
    eq("trong pham vi thi excepted",
       policy.emit(inside, "arg_traversal", { target = "ARGS" }).excepted, true)

    local _, outside = state(runtime, "a.test", "/other.php")
    eq("ngoai pham vi thi KHONG excepted",
       policy.emit(outside, "arg_traversal", { target = "ARGS" }).excepted, false)
end

-- ── `factor` phai ap len CA hai duong ────────────────────────────────────────
--
-- `arg_factor_body` la local trong `init.lua` nen test qua `_run_pre_with_runtime`
-- voi mot `rt` gia lap. Ba dieu phai dung cung luc:
--   1. `multipart` -> diem 5% (35 -> 1.75)
--   2. `spill` MOT MINH tren urlencoded -> KHONG giam (35 nguyen) — day la lo
--      da bi go: `spill` do ke gui dieu khien duoc bang cach nhoi padding.
--   3. cau tuong thich `ctx.waf_body_arg` cung phai mang factor, khong nap du.
do
    local waf = dofile(SRC .. "waf/init.lua")
    -- `dofile` co chu y: `init.lua` giu `compiled_config` o cap module va
    -- `configure()` sua no, nen mot ban RIENG cho khoi nay tranh ro ri sang
    -- cac test khac. Cac module NO require thi van la ban chung qua preload.

    local function run_with_body(b)
        local ctx = {}
        local rt = {
            var = { host = "a.test", uri = "/index.php", args = nil,
                    remote_addr = "127.0.0.1", document_root = "/nonexistent" },
            req = { get_method = function() return "POST" end },
            log = function() end,
            exit = function() end,
            ERR = 4,
            waf_body_probe = function(c) c.waf_body = b end,
        }
        waf._run_pre_with_runtime(ctx, rt)
        return ctx
    end

    local mp = run_with_body({ family = "multipart", spill = true, len = 1125283,
                               arg_rule = "arg_traversal" })
    eq("multipart -> 5% cua 35", string.format("%.2f", mp.waf_score or -1), "1.75")
    eq("multipart -> cau cu cung giam",
       string.format("%.4f", mp.waf_body_arg or -1),
       string.format("%.4f", 0.75 * 0.05))

    local sp = run_with_body({ family = "urlencoded", spill = true, len = 900000,
                               arg_rule = "arg_traversal" })
    eq("spill mot minh KHONG giam diem",
       string.format("%.2f", sp.waf_score or -1), "35.00")
    eq("spill mot minh KHONG giam cau cu",
       string.format("%.4f", sp.waf_body_arg or -1), "0.7500")

    local ue = run_with_body({ family = "urlencoded", spill = false, len = 179,
                               arg_rule = "arg_traversal" })
    eq("urlencoded giu nguyen 35",
       string.format("%.2f", ue.waf_score or -1), "35.00")

    -- Exception phai chan CA cau tuong thich cu.
    local ctx = {}
    local rt = {
        var = { host = "a.test", uri = "/index.php", args = nil,
                remote_addr = "127.0.0.1", document_root = "/nonexistent" },
        req = { get_method = function() return "POST" end },
        log = function() end, exit = function() end, ERR = 4,
        waf_body_probe = function(c)
            c.waf_body = { family = "urlencoded", spill = false, len = 179,
                           arg_rule = "arg_traversal" }
        end,
    }
    waf.configure({ exceptions = { { id = "skip", rule = "arg_traversal" } } })
    waf._run_pre_with_runtime(ctx, rt)
    eq("exception chan ca cau tuong thich cu", ctx.waf_body_arg, nil)
    eq("exception -> waf_score 0", ctx.waf_score, 0)
    waf.configure(nil)
end

io.write(string.format("\npolicy V2: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
