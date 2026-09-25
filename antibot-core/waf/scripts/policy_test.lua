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
    -- SUA 25-09 cung voi viec tach hai truc: assertion cu doc
    -- `d.reason == "corr_upload_php_payload"` TRONG KHI `d.action == "allow"` —
    -- tuc no ghi lai dung cai loi da sua: mot request khong bi chan mang mot ly do
    -- chan. Correlation nay o `mode = "shadow"` nen bang chung cua no thuoc truc
    -- GIA DINH, va `reason` phai la nil.
    eq("shadow correlation khong dat reason", d.reason, nil)
    eq("upload correlation would_reason", d.would_reason, "corr_upload_php_payload")
    eq("would_rule_mode noi ro no dang shadow", d.would_rule_mode, "shadow")
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
    -- SUA 25-09: assertion cu doc `d.reason == "score_threshold"` trong khi
    -- `d.action == "allow"`. Nguong diem o `threshold_mode = "shadow"` nen bang
    -- chung cua no thuoc truc GIA DINH.
    eq("nguong diem shadow khong dat reason", d.reason, nil)
    eq("score threshold would_reason", d.would_reason, "score_threshold")
    -- `score_candidate()` tra `mode = state.config.threshold_mode`, nen
    -- `would_rule_mode` phai mang dung gia tri do. Neu no ra nil thi
    -- `score_candidate` khong dat `mode` va mot nguong diem thang
    -- `better_candidate` se lam `would_rule_mode` khuyet trong khi `would_reason`
    -- co gia tri — dung kieu hai truong lech nhau ma ban nay di sua.
    eq("would_rule_mode cua nguong diem", d.would_rule_mode, "shadow")
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
    eq("telemetry records latency once", values["waf:v2:latency_us_count"], 1)
    -- MICROGIAY: `tick` di tu 10 den 10.012 giay = 12 ms = 12.000 us. Don vi nay
    -- la bat buoc vi `run_pre` chay duoi 1 ms, nen tinh theo ms thi moi mau lam
    -- tron ve 0 va cot do tre bao 0,00 bat ke that su bao nhieu.
    eq("telemetry latency us", values["waf:v2:latency_us_sum"], 12000)
    -- CA HAI khoa cu phai vang. Shared dict song sot qua `nginx -s reload`, nen
    -- neu chi doi `sum` ma giu `count` thi sau deploy `latency_us_sum` chua mau
    -- MOI trong khi `latency_count` chua ca mau cu lan moi — `snapshot()` lay tong
    -- moi chia count cu va cho ra do tre THAP GIA TAO. Mot con so sai theo huong
    -- "trong nhu moi thu on", tuc huong te nhat.
    eq("telemetry KHONG con ghi khoa sum cu",
       values["waf:v2:latency_ms_sum"], nil)
    eq("telemetry KHONG con ghi khoa count cu",
       values["waf:v2:latency_count"], nil)
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

    -- `compile()` NORMALIZE roi `validate()` moi doc — nen nhung truong bi bien
    -- dang trong buoc do phai duoc kiem tren ban RAW. Ba ca duoi day deu tung
    -- vuot qua validator:
    --
    --   `exceptions = "invalid"` -> `append()` bo gia tri khong phai table, con
    --                               lai `{}`, va `{}` thi hop le
    --   mang THUA                -> `#src` dung o lo trong dau tien, phan tu sau
    --                               do bi bo LANG LE
    --   khoa khong phai chi so   -> `append()` khong bao gio thay
    ok = config.validate(config.compile({ exceptions = "invalid" }))
    eq("exceptions khong phai mang bi tu choi", ok, false)

    ok = config.validate(config.compile({
        exceptions = { [1] = { id = "a", rule = "arg_traversal" },
                       [3] = { id = "b", rule = "arg_traversal" } },
    }))
    eq("exceptions mang THUA bi tu choi", ok, false)

    ok = config.validate(config.compile({
        exceptions = { nope = { id = "a", rule = "arg_traversal" } },
    }))
    eq("exceptions khoa khong phai chi so bi tu choi", ok, false)

    -- Exception chi co `id` khop MOI luat: `id` la ten de truy nguoc trong log,
    -- no khong loc gi ca. Do la cach de nhat de tat toan bo WAF bang mot dong
    -- trong nhu vo hai.
    ok = config.validate(config.compile({ exceptions = { { id = "chi-co-id" } } }))
    eq("exception khong co selector bi tu choi", ok, false)

    -- Ho luat phai ton tai trong registry, khong thi exception im lang vo tac
    -- dung (`exception_matches` so voi moi `rule.family` va khong bao gio khop).
    ok = config.validate(config.compile({
        exceptions = { { id = "a", family = "expsure" } },
    }))
    eq("exception voi family khong ton tai bi tu choi", ok, false)
    ok = config.validate(config.compile({
        exceptions = { { id = "a", family = "exposure" } },
    }))
    eq("exception voi family CO THAT van qua", ok, true)

    -- `domains` long trong mot domain scope: `resolve()` khong bao gio doc no.
    ok = config.validate(config.compile({
        domains = { ["a.test"] = { domains = { ["b.test"] = { mode = "shadow" } } } },
    }))
    eq("domains long hai cap bi tu choi", ok, false)

    -- `__raw` la khoa NOI BO cua `compile()`. Hai duong, va ban dau toi chi nghi
    -- ra duong thu nhat roi viet mot `reject_unknown` bo qua khoa nay o MOI cap —
    -- tuc tu mo dung duong thu hai trong luc dinh chan duong thu nhat.
    --
    --   cap goc      `compile()` dat `out[RAW_KEY]` SAU `merge`, nen mot
    --                `__raw` nguoi viet bi ghi de — vo hai, nhung la mot khoa
    --                nguoi viet tuong da co tac dung. `validate_raw` bao ra.
    --   domain scope `merge(out, domain)` trong `resolve()` KHONG loai khoa nay
    --                (no chi loai `domains` va `exceptions`), nen
    --                `domains["a"].__raw` GHI DE ban raw that tren ban resolved —
    --                luot kiem raw doc mot ban do ke viet cau hinh chon.
    ok = config.validate(config.compile({ __raw = { mode = "shadow" } }))
    eq("`__raw` o cap goc bi tu choi", ok, false)

    ok = config.validate(config.compile({
        domains = { ["a.test"] = { __raw = { mode = "shadow" } } },
    }))
    eq("`__raw` trong domain scope bi tu choi", ok, false)

    -- Va chieu nguoc: khoa do `compile()` tu dat KHONG duoc bao loi oan. Thieu
    -- phep kiem nay thi mot ban sua lam moi cau hinh hop le thanh khong hop le, va
    -- `configure()` se giu mac dinh mai mai trong im lang.
    ok = config.validate(config.compile({ mode = "shadow" }))
    eq("khoa noi bo do compile() dat khong bao loi oan", ok, true)

    -- Va ban raw phai di theo `resolve()`: neu mat thi luot kiem raw bi bo qua
    -- trong im lang tren moi ban da resolve.
    local compiled = config.compile({ exceptions = "invalid" })
    ok = config.validate(config.resolve(compiled, "a.test"))
    eq("luot kiem raw con hieu luc sau resolve()", ok, false)

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

-- ── Khong duoc ha diem theo DINH DANG hay KICH THUOC than request ────────────
--
-- Hai lan lien tiep toi mo mot duong ha diem bang mot dieu kien ke gui dieu
-- khien duoc: `spill` (kich thuoc) roi `multipart` (dinh dang). Ca hai da go.
--
-- `multipart` la lo do CHINH toi tao ra khi bit lo `spill`: `body_core` quet
-- toan bo than va khong phan biet lan khop nam trong noi dung tep, ten tep,
-- header part, hay MOT FORM FIELD THUONG. Ke gui dat `path=../../etc/passwd`
-- thanh mot text part hop le thi PHP van nap vao `$_POST` — cung ban chat tan
-- cong, nhung diem tu 35 xuong 1,75.
--
-- Bon truong hop duoi day PHAI cung diem. Mot ca lech nghia la mot nhom nao do
-- lai duoc mien tru theo mot thuoc tinh ke gui chon duoc.
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

    local function arg_case(name, b, want_score, want_bridge)
        local ctx = run_with_body(b)
        eq(name .. " — waf_score",
           string.format("%.2f", ctx.waf_score or -1), want_score)
        eq(name .. " — cau cu waf_body_arg",
           string.format("%.4f", ctx.waf_body_arg or -1), want_bridge)
    end

    -- 35.00 la thang registry; 0.7500 la thang detector `[0,1]` cua cau cu.
    arg_case("multipart + spill (9 ca FP do duoc)",
             { family = "multipart", spill = true, len = 1125283,
               arg_rule = "arg_traversal" }, "35.00", "0.7500")
    arg_case("multipart khong spill",
             { family = "multipart", spill = false, len = 5000,
               arg_rule = "arg_traversal" }, "35.00", "0.7500")
    -- DUONG NE da dong: nhoi padding cho urlencoded de vuot buffer.
    arg_case("urlencoded + spill (nhoi padding)",
             { family = "urlencoded", spill = true, len = 900000,
               arg_rule = "arg_traversal" }, "35.00", "0.7500")
    arg_case("urlencoded thuong (botnet buoc 15)",
             { family = "urlencoded", spill = false, len = 179,
               arg_rule = "arg_traversal" }, "35.00", "0.7500")

    -- Exception phai chan CA hai duong: phan quyet VA cau tuong thich cu.
    waf.configure({ exceptions = { { id = "skip", rule = "arg_traversal" } } })
    local ctx = run_with_body({ family = "urlencoded", spill = false, len = 179,
                                arg_rule = "arg_traversal" })
    eq("exception chan ca cau tuong thich cu", ctx.waf_body_arg, nil)
    eq("exception -> waf_score 0", ctx.waf_score, 0)
    waf.configure(nil)

    -- `scan = "empty"` la than RONG, khong phai vung mu. Do tren nam may:
    -- 247/247 luot `body_scan_incomplete` la `empty`, va no chiem hon mot nua
    -- toan bo dong V2. Phat luat cho no lam luat mat kha nang tra loi cau hoi
    -- "con vung mu bao lon".
    local empty_ctx = run_with_body({ family = "urlencoded", spill = false,
                                      len = 0, scan = "empty" })
    local fired = false
    for i = 1, #(empty_ctx.waf_hits or {}) do
        if empty_ctx.waf_hits[i].rule == "body_scan_incomplete" then fired = true end
    end
    eq("scan=empty KHONG phat body_scan_incomplete", fired, false)

    -- Con `spill_thread` thi PHAI phat: do moi la "co ma soi khong noi".
    local blind_ctx = run_with_body({ family = "multipart", spill = true,
                                      len = -1, scan = "spill_thread" })
    local blind = false
    for i = 1, #(blind_ctx.waf_hits or {}) do
        if blind_ctx.waf_hits[i].rule == "body_scan_incomplete" then blind = true end
    end
    eq("scan=spill_thread VAN phat body_scan_incomplete", blind, true)
end

-- ── `waf/runtime_config.lua` la file NGUOI VAN HANH SUA, nen phai kiem no ────
--
-- File do di qua `configure()` o `init_worker` tren MOI worker. Mot dau phay
-- thieu khong lam nginx hong (co `pcall`), nhung mot khoa go sai thi WAF chay mac
-- dinh trong khi nguoi van hanh tuong da ap — dung lop loi ma `reject_unknown`
-- duoc them de chan. Nen ban dang nam trong repo phai LUON qua validator.
do
    local ok_load, runtime = pcall(dofile, SRC .. "waf/runtime_config.lua")
    eq("runtime_config.lua nap duoc", ok_load, true)
    if ok_load then
        eq("runtime_config.lua tra mot bang", type(runtime), "table")
        local ok_v, errs = config.validate(config.compile(runtime))
        if not ok_v then
            for i = 1, #(errs or {}) do
                io.write("      ", tostring(errs[i]), "\n")
            end
        end
        eq("runtime_config.lua qua validator", ok_v, true)

        -- Ban dang deploy PHAI khong doi phan quyet: giai doan nay chi bat duong
        -- cau hinh, khong doi chinh sach. Neu mot ngay nao do doi that thi test
        -- nay phai duoc sua CO Y — do la muc dich cua no.
        eq("runtime_config: mode van enforce", runtime.mode, "enforce")
        eq("runtime_config: score_enforcement van tat",
           runtime.score_enforcement, false)
        eq("runtime_config: chua co exception nao", #(runtime.exceptions or {}), 0)
    end
end

-- ── Hai truc cua `decide()` khong duoc tron ─────────────────────────────────
--
-- `reason`/`rule_mode` mo ta candidate tao ra PHAN QUYET THAT.
-- `would_reason`/`would_rule_mode` mo ta candidate manh nhat neu moi luat enforce.
--
-- Ban truoc tron chung: `reason` roi ve `candidate` khi khong co enforce
-- candidate, va `rule_mode` LUON lay tu `candidate`. Hai he qua:
--   · `action = "allow"` van mang mot `reason` — doc log thay request khong bi
--     chan nhung co ly do chan.
--   · `reason` tu enforce candidate di cung `rule_mode` tu mot candidate KHAC —
--     hai gia tri mo ta hai rule khac nhau tren cung mot dong.
do
    -- (1) Luat shadow ban mot minh: se chan, nhung KHONG chan.
    local runtime = { rules = { dotfile_exposed = { mode = "shadow" } } }
    local _, st = state(runtime)
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("shadow mot minh -> action allow", d.action, "allow")
    eq("shadow mot minh -> would_action block", d.would_action, "block")
    eq("action=allow thi reason phai NIL", d.reason, nil)
    eq("action=allow thi rule_mode phai NIL", d.rule_mode, nil)
    eq("bang chung bong nam o would_reason", d.would_reason, "dotfile_exposed")
    eq("would_rule_mode noi ro no dang shadow", d.would_rule_mode, "shadow")
    eq("shadow=true khi hai truc lech", d.shadow, true)

end

-- (2) Luat enforce ban mot minh: hai truc TRUNG nhau, va do la truong hop thuong
--     gap nhat hom nay (moi luat deu enforce).
do
    local _, st2 = state()
    policy.emit(st2, "dotfile_exposed", { target = "URI" })
    local d2 = policy.decide(st2)
    eq("enforce -> action block", d2.action, "block")
    eq("enforce -> reason co gia tri", d2.reason, "dotfile_exposed")
    eq("enforce -> rule_mode la enforce", d2.rule_mode, "enforce")
    eq("enforce -> would trung voi that", d2.would_reason, "dotfile_exposed")
    eq("enforce -> shadow=false", d2.shadow, false)

end

-- (3) CA HAI cung ban: mot luat shadow diem CAO HON mot luat enforce.
--     Day la ca ma ban truoc tron hai truc — `reason` lay tu enforce candidate
--     (`wellknown_exec`) nhung `rule_mode` lay tu candidate manh nhat
--     (`dotfile_exposed`, shadow). Hai gia tri mo ta HAI RULE, va day la ca DUY
--     NHAT phan biet duoc hai thiet ke.
do
    local runtime3 = {
        rules = {
            dotfile_exposed = { mode = "shadow", score = 500 },
        },
    }
    local _, st3 = state(runtime3)
    policy.emit(st3, "dotfile_exposed", { target = "URI" })
    policy.emit(st3, "wellknown_exec", { target = "URI" })
    local d3 = policy.decide(st3)
    eq("ca hai ban -> chan bang luat ENFORCE", d3.action, "block")
    eq("reason la luat da chan THAT", d3.reason, "wellknown_exec")
    eq("rule_mode thuoc CUNG luat do", d3.rule_mode, "enforce")
    -- `would_*` mo ta candidate manh nhat, tuc luat shadow diem cao hon.
    eq("would_reason la luat shadow manh hon", d3.would_reason, "dotfile_exposed")
    eq("would_rule_mode thuoc CUNG luat do", d3.would_rule_mode, "shadow")
end

io.write(string.format("\npolicy V2: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
