-- Chay bang `run.sh` (cach dung chinh), hoac tay tu repository root:
--   ANTIBOT_SRC=antibot-core/ resty antibot-core/l7/tests/l7_regression.lua
--
-- `ANTIBOT_SRC` chu KHONG dong cung `./antibot-core/`: production deploy dat cay
-- nay tai `/conf/antibot` (ten khac), nen ban dong cung khong chay duoc o do —
-- va do la ly do bo nay tung KHONG nam trong `run.sh`. Hau qua: moi commit cham
-- L7 di qua mot cong khong kiem L7. Bat duoc 05-10 khi dem `grep -c
-- l7_regression run.sh` = 0 sau khi `run.sh` da bao rc=0.
--
-- Searcher nho nay giu nguyen `require("antibot.*")` cua code production va chi
-- anh xa layout trong regression test.
local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n")
    io.write("  chay bang: waf/scripts/run.sh\n")
    io.write("  hoac tay:  ANTIBOT_SRC=antibot-core/ resty antibot-core/l7/tests/l7_regression.lua\n")
    os.exit(2)
end
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end

table.insert(package.loaders, 1, function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    local errors = {}
    for _, path in ipairs({
        SRC .. rel .. ".lua",
        SRC .. rel .. "/init.lua",
    }) do
        local chunk, err = loadfile(path)
        if chunk then return chunk end
        errors[#errors + 1] = err
    end
    return table.concat(errors, "\n")
end)

local passed = 0

local function ok(value, label)
    if not value then error("FAIL: " .. label, 2) end
    passed = passed + 1
end

local function eq(actual, expected, label)
    if actual ~= expected then
        error(string.format("FAIL: %s (got=%s expected=%s)",
            label, tostring(actual), tostring(expected)), 2)
    end
    passed = passed + 1
end

local function read_file(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("*a")
    f:close()
    return s
end

local syntax_files = {
    "antibot-core/init.lua",
    "antibot-core/core/config.lua",
    "antibot-core/core/req_classifier.lua",
    "antibot-core/detection/bot/lite_verify.lua",
    "antibot-core/detection/browser/beacon_handler.lua",
    "antibot-core/detection/session/session_store.lua",
    "antibot-core/enforcement/challenge/verify_token.lua",
    "antibot-core/enforcement/decision/engine.lua",
    "antibot-core/async/logger.lua",
    "antibot-core/l7/admission.lua",
    "antibot-core/l7/circuit_breaker.lua",
    "antibot-core/l7/init.lua",
    "antibot-core/l7/expensive_filter_guard.lua",
    "antibot-core/l7/ban/ip_ban_check.lua",
    "antibot-core/l7/ban/ban_store.lua",
    "antibot-core/l7/burst/burst_counter.lua",
    "antibot-core/l7/burst/burst_decision.lua",
    "antibot-core/l7/rate/adaptive_limit.lua",
    "antibot-core/l7/rate/counter.lua",
    "antibot-core/l7/rate/res_ip_counter.lua",
}

for _, path in ipairs(syntax_files) do
    local chunk, err = loadfile(path)
    ok(chunk ~= nil, "syntax " .. path .. ": " .. tostring(err))
end

-- Fake ngx/shared-dict du de test semantics fixed bucket ma khong can master
-- Nginx. Expiry duoc danh gia theo dong ho `clock`.
local clock = 0
local exits = {}

local Dict = {}
Dict.__index = Dict
function Dict.new()
    return setmetatable({ data = {}, expiry = {} }, Dict)
end
function Dict:_live(key)
    local expiry = self.expiry[key]
    if expiry and expiry <= clock then
        self.data[key], self.expiry[key] = nil, nil
    end
    return self.data[key]
end
function Dict:incr(key, delta)
    local value = self:_live(key)
    if value == nil then return nil, "not found" end
    value = value + delta
    self.data[key] = value
    return value
end
function Dict:add(key, value, ttl)
    if self:_live(key) ~= nil then return nil, "exists" end
    self.data[key] = value
    self.expiry[key] = clock + ttl
    return true
end
-- `get`/`set`: `admission.static_target_exists` cache ket qua `io.open` o day.
-- Thieu hai ham nay thi module no o access phase, va mot stub thieu ham cua
-- production API la mot phep do sai chieu — no bao "qua" vi chua goi tai.
function Dict:get(key)
    return self:_live(key)
end
function Dict:set(key, value, ttl)
    if value == nil then
        self.data[key], self.expiry[key] = nil, nil
        return true
    end
    self.data[key] = value
    self.expiry[key] = ttl and (clock + ttl) or nil
    return true
end
function Dict:delete(key)
    self.data[key], self.expiry[key] = nil, nil
    return true
end

local fake_ngx = {
    var = {}, ctx = {}, header = {},
    shared = {
        antibot_cache = Dict.new(),
    },
    DEBUG = 0, INFO = 1, WARN = 2, ERR = 3,
    now = function() return clock end,
    time = function() return math.floor(clock) end,
    log = function() end,
    say = function() end,
    exit = function(code) exits[#exits + 1] = code; return code end,
    md5 = function() return "0000000a000000000000000000000000" end,
    crc32_short = function(s)
        local n = 0
        for i = 1, #s do n = (n + s:byte(i)) % 4294967296 end
        return n
    end,
    timer = {
        at = function(_, fn, ...)
            fn(false, ...)
            return true
        end,
    },
    worker = { pid = function() return 123 end },
}
_G.ngx = fake_ngx

local cfg = require "antibot.core.config"
local old_admission = cfg.l7_admission
cfg.l7_admission = {
    enabled = true, mode = "enforce", status = 429, retry_after = 1,
    route_shards = 8,
    windows = { short = 1, long = 10 },
    limits = {
        global = { short = 100, long = 1000 },
        host = { short = 100, long = 1000 },
        host_group = {
            dynamic = { short = 100, long = 1000 },
            resource = { short = 100, long = 1000 },
        },
        route_group = {
            dynamic = { short = 100, long = 1000 },
            resource = { short = 100, long = 1000 },
        },
        ip = {
            navigation = { short = 2, long = 100 },
            default = { short = 2, long = 100 },
        },
        endpoints = {
            verify = {
                host = { short = 100, long = 100 },
                ip = { short = 1, long = 100 },
            },
        },
    },
}

fake_ngx.var = {
    server_name = "example.test", host = "example.test",
    remote_addr = "203.0.113.7", uri = "/shop", request_method = "GET",
}
local admission = require "antibot.l7.admission"
local actx = { ip = "203.0.113.7", req_class = "navigation", req = {} }
local _, exit1 = admission.run(actx)
local _, exit2 = admission.run(actx)
local _, exit3 = admission.run(actx)
eq(exit1, false, "admission allows first request")
eq(exit2, false, "admission allows request at limit")
eq(exit3, true, "admission rejects over short IP budget")
eq(exits[#exits], 429, "admission returns 429")
eq(actx.admission_reason, "ip_navigation", "admission reason is observable")

-- ── adm_use: do VUNG MU dynamic ─────────────────────────────────────
--
-- VI SAO CO NHOM NAY. Cot admission truoc day chi duoc ghi khi
-- `admission_limited or resource_candidate or backend_class`. Do 04-10 tren hai
-- may that: chi 0,33% (28-246: 2.191/666.752) va 0,47% (171-96: 1.793/378.959)
-- so dong log co cot do -> 99,6% request dynamic KHONG co so lieu admission nao,
-- va `host_group.dynamic.short = 500/s` chua tung duoc doi chieu voi luu luong
-- thuc. `adm_use` la mot con so duy nhat moi dong de tinh p50/p95/p99.
--
-- Cau hinh test o tren: ip.default.short = 2, con global/host/host_group/
-- route_group deu 100. Nen voi 1 IP + 1 URI, truc CHAT NHAT la ip_* va
-- `adm_use` phai theo no.
--
-- DAP AN TINH TAY: limit = 2, nen request 1 -> floor(1/2*100) = 50;
-- request 2 -> 100 (DUNG tran, van qua vi dieu kien la `value > limit`);
-- request 3 -> 150 va bi 429.
clock = 50
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.remote_addr = "198.51.100.77"
fake_ngx.var.uri = "/dynamic-page"
local u1 = { ip = "198.51.100.77", req_class = "unknown", req = {} }
local _, ue1 = admission.run(u1)
eq(ue1, false, "adm_use: request dau duoc qua")
eq(u1.admission_use, 50, "adm_use = 50 o request 1/2")
eq(u1.admission_use_axis, "ip_unknown:short", "adm_top la truc CHAT NHAT")

local u2 = { ip = "198.51.100.77", req_class = "unknown", req = {} }
admission.run(u2)
eq(u2.admission_use, 100, "adm_use = 100 o DUNG tran (chua chan)")
eq(u2.admission_limited, nil, "dung tran thi CHUA bi gioi han")

local u3 = { ip = "198.51.100.77", req_class = "unknown", req = {} }
local _, ue3 = admission.run(u3)
eq(ue3, true, "vuot tran moi bi chan")
eq(u3.admission_use, 150, "adm_use = 150 khi da vuot")

-- `adm_use` phai co CA KHI khong bi gioi han — do la toan bo ly do no ton tai.
-- Neu no chi xuat hien luc throttle thi vung mu khong he duoc do.
local u4 = { ip = "203.0.113.200", req_class = "unknown", req = {} }
admission.run(u4)
eq(u4.admission_limited, nil, "IP moi: khong bi gioi han")
ok(u4.admission_use ~= nil, "adm_use co MAC DU khong bi gioi han")

-- `math.floor` chu KHONG lam tron len. Ba ca o tren deu chia chan (1/2, 2/2,
-- 3/2) nen dot bien `floor -> ceil` KHONG bi bat — do la lo trong phep do,
-- khong trong code. Ca nay dung mot ti le LE: ip.default.short = 2 doi thanh 3
-- cho rieng mot class, nen 1/3 = 33,33% -> floor = 33, con ceil = 34.
--
-- VI SAO `floor` moi dung: `adm_use` tra loi "con bao nhieu khoang an toan".
-- Lam tron LEN bao 34 khi thuc te moi dung 33,3% la bao THIEU khoang an toan —
-- sai lech theo chieu lam nguoi doc tuong minh gan tran hon thuc te, roi ha
-- nguong khong can thiet va tao FP. Xem [[feedback_fp_over_fn]].
cfg.l7_admission.limits.ip.api_callback = { short = 3, long = 100 }
clock = 60
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.remote_addr = "198.51.100.88"
local r1 = { ip = "198.51.100.88", req_class = "api_callback", req = {} }
admission.run(r1)
eq(r1.admission_use, 33, "adm_use dung math.floor (1/3 -> 33, khong phai 34)")
local r2 = { ip = "198.51.100.88", req_class = "api_callback", req = {} }
admission.run(r2)
eq(r2.admission_use, 66, "adm_use 2/3 -> 66, khong phai 67")
cfg.l7_admission.limits.ip.api_callback = nil

clock = 1.1
exits = {}
local _, next_bucket_exit = admission.run(actx)
eq(next_bucket_exit, false, "short fixed bucket does not inherit full old count")

clock = 30
fake_ngx.var.remote_addr = "203.0.113.9"
local _, endpoint1 = admission.run_endpoint("verify")
local _, endpoint2 = admission.run_endpoint("verify")
eq(endpoint1, false, "first verify request is allowed")
eq(endpoint2, true, "verify endpoint cannot bypass admission")

-- ── Static CANDIDATE vs static MISS ────────────────────────────────
--
-- VI SAO CO NHOM NAY. `req_classifier` chi biet "GET/HEAD + duoi tinh", tuc
-- static CANDIDATE. Tep co that -> Nginx phuc vu truc tiep (re thuc su); tep
-- thieu -> `try_files` -> `@static_backend` -> Apache/PHP, va voi WordPress thi
-- `.htaccess` rewrite thanh `index.php`. Do la tai DYNAMIC du duoi la `.jpg`.
--
-- Truoc ban nay ca hai dung CUNG ngan sach `resource`, von dat cao vi gia dinh
-- "static thi re" — gia dinh sai voi static MISS. Do duoc tren stub cung hinh
-- dang (1 host, 2000 IP, URI phan tan 64 shard, `.jpg` khong ton tai):
-- 2000 IP x 2 req/s ben vung 60s -> 3.200 req/s lot toi Apache (80%). Cung luu
-- luong do voi `.php` chi 350 req/s lot. Sau khi tach: 100 req/s.
--
-- Va chu thich o `req_classifier.lua` tung khang dinh static miss "se bi
-- @static_backend admission guard dem lai" — guard do da bi thu hoi o review 3,
-- va `da_to_openresty.sh` dat `access_by_lua_block { return; }` trong named
-- location, tuc TAT han Lua o do. Chu thich mo ta code khong ton tai; nhom nay
-- lam cho bat bien khong con nam o chu thich.
cfg.l7_admission = {
    enabled = true, mode = "enforce", status = 429, retry_after = 1,
    route_shards = 8, static_probe = true, static_probe_ttl = 30,
    windows = { short = 1, long = 10 },
    limits = {
        global = { short = 10000, long = 100000 },
        host   = { short = 10000, long = 100000 },
        -- Hai ngan sach LECH NHAU de phan biet duoc group nao duoc chon.
        host_group = {
            resource = { short = 9000, long = 90000 },
            dynamic  = { short = 3,    long = 90000 },
        },
        route_group = {
            resource = { short = 9000, long = 90000 },
            dynamic  = { short = 9000, long = 90000 },
        },
        ip = { default = { short = 9000, long = 90000 } },
    },
}

local real_open = io.open
local probe_opens = 0
local function with_fake_disk(exists_pattern, fn)
    probe_opens = 0
    io.open = function(path, mode)
        probe_opens = probe_opens + 1
        if exists_pattern and path:find(exists_pattern, 1, true) then
            -- Tra ve mot handle THAT de `fh:close()` chay duoc.
            return real_open("antibot-core/l7/admission.lua", "r")
        end
        return nil
    end
    local okc, err = pcall(fn)
    io.open = real_open
    if not okc then error(err, 0) end
end

-- Ca 1: tep CO tren dia -> group `resource`, dung ngan sach resource (9000).
clock = 100
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/u/public_html"
fake_ngx.var.uri = "/real.jpg"
with_fake_disk("/real.jpg", function()
    local c1 = { ip = "198.51.100.1", req_class = "resource", req = {} }
    local _, e1 = admission.run(c1)
    eq(e1, false, "static hit duoc phuc vu")
    eq(c1.admission_group, "resource", "tep co that dung ngan sach resource")
    eq(c1.resource_actual, true, "resource_actual=true khi tep co that")
end)

-- Ca 2: tep THIEU -> group `dynamic`. Ngan sach dynamic.short=3 nen request
-- thu 4 bi 429, chung minh no THUC SU dung bang dynamic chu khong chi doi nhan.
clock = 200
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.uri = "/fake.jpg"
with_fake_disk("/real.jpg", function()
    local last_exit, grp, actual
    for _ = 1, 4 do
        local c = { ip = "198.51.100.2", req_class = "resource", req = {} }
        local _, e = admission.run(c)
        last_exit, grp, actual = e, c.admission_group, c.resource_actual
    end
    eq(grp, "dynamic", "static MISS chuyen sang ngan sach dynamic")
    eq(actual, false, "resource_actual=false khi tep khong co")
    eq(last_exit, true, "static miss bi chan theo tran dynamic (3/giay)")
    eq(exits[#exits], 429, "static miss qua tran tra 429")
    -- Cache: 4 request cung duong dan chi ton MOT `io.open`. Day la dieu lam
    -- phep do nay re — mot flood vao cung URI khong tao 1 syscall/request.
    eq(probe_opens, 1, "ket qua probe duoc cache trong cua so TTL")
end)

-- Ca 2b: cache PHAI het han. Khong co TTL thi mot tep vua upload bi coi la
-- thieu MAI MAI — khach them anh moi se an ngan sach dynamic vinh vien. Dot
-- bien `ttl -> nil` khong bi ca 2 bat, nen bat bien nay can phep do rieng:
-- qua moc TTL thi probe chay LAI.
fake_ngx.var.uri = "/fake.jpg"
with_fake_disk("/real.jpg", function()
    local c = { ip = "198.51.100.2b", req_class = "resource", req = {} }
    admission.run(c)
    -- `with_fake_disk` reset bo dem, nhung cache tu ca 2 VAN con, nen request
    -- nay khong stat lai -> 0. Do chinh la dieu muon do.
    eq(probe_opens, 0, "trong TTL: dung cache tu truoc, khong stat lai")
    clock = clock + 31          -- static_probe_ttl = 30
    local c2 = { ip = "198.51.100.2b", req_class = "resource", req = {} }
    admission.run(c2)
    eq(probe_opens, 1, "qua TTL: probe chay lai (tep moi upload duoc nhan ra)")
end)

-- Ca 3: KHONG do duoc (document_root rong) -> PHAI fail-open ve `resource`.
-- Dot bien `exists ~= true` thay cho `exists == false` lam ca nay tut xuong
-- ngan sach dynamic, tuc mot phep do THAT BAI bien thanh 429 cho khach that.
-- FP la uu tien so mot, nen bat bien nay phai co test rieng.
clock = 300
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = ""
fake_ngx.var.uri = "/unknown.jpg"
with_fake_disk(nil, function()
    local c = { ip = "198.51.100.3", req_class = "resource", req = {} }
    local _, e = admission.run(c)
    eq(e, false, "khong do duoc thi KHONG chan")
    eq(c.admission_group, "resource", "fail-open ve resource khi khong do duoc")
    eq(probe_opens, 0, "docroot rong thi khong goi io.open")
end)

-- Ca 4: `static_probe = false` tat phep do — duong lui cho may co van de
-- hieu nang. Khi tat, static miss lai dung ngan sach resource nhu truoc.
clock = 400
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/u/public_html"
fake_ngx.var.uri = "/fake.jpg"
cfg.l7_admission.static_probe = false
with_fake_disk("/real.jpg", function()
    local c = { ip = "198.51.100.4", req_class = "resource", req = {} }
    admission.run(c)
    eq(c.admission_group, "resource", "static_probe=false giu nguyen hanh vi cu")
    eq(probe_opens, 0, "static_probe=false khong goi io.open")
end)
cfg.l7_admission.static_probe = true

-- Ca 5: class khac `resource` khong bao gio cham dia.
clock = 500
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.uri = "/wp-login.php"
with_fake_disk("/real.jpg", function()
    local c = { ip = "198.51.100.5", req_class = "auth_endpoint", req = {} }
    admission.run(c)
    eq(c.admission_group, "dynamic", "class dynamic van la dynamic")
    eq(probe_opens, 0, "class khong phai resource thi khong stat dia")
end)

fake_ngx.var.document_root = nil
cfg.l7_admission = old_admission

-- Classifier: extension chi duoc coi la resource khi GET/HEAD; Sec-Fetch-Dest
-- chi la telemetry, khong con la quyen tu chon lane nhe.
package.loaded["antibot.core.req_classifier"] = nil
local classifier = require "antibot.core.req_classifier"
local function classify(vars)
    fake_ngx.var = vars
    local ctx = {}
    classifier.run_fast(ctx)
    return ctx
end

local c1 = classify({
    uri = "/wp-login.php", args = "", request_method = "POST",
    http_content_type = "application/x-www-form-urlencoded",
    http_sec_fetch_dest = "image", http_user_agent = "curl/8",
})
eq(c1.req_class, "auth_endpoint", "Sec-Fetch image cannot hide auth POST")
eq(c1.resource_declared, true, "untrusted Sec-Fetch signal kept as telemetry")

local c2 = classify({
    uri = "/dynamic.jpg", args = "", request_method = "POST",
    http_content_type = "", http_user_agent = "curl/8",
})
ok(c2.req_class ~= "resource", "POST with static extension stays dynamic")

local c3 = classify({
    uri = "/assets/app.css", args = "v=1", request_method = "GET",
    http_user_agent = "Mozilla/5.0",
})
eq(c3.req_class, "resource", "GET static extension uses lightweight lane")

-- Per-host backend circuit breaker.  Tat ca ca nay dung shared dict local;
-- khong Redis, khong nginx directive, va state cua host A khong duoc ro sang B.
local old_circuit = cfg.l7_circuit_breaker
cfg.l7_circuit_breaker = {
    enabled = true, mode = "shadow", status = 503, retry_after = 2,
    window_seconds = 10, bucket_grace_seconds = 4, eval_interval = 1,
    min_samples = 2,
    slow_seconds = 1, hard_error_ratio = 0.5,
    slow_candidate_ratio = 0.5,
    open_seconds = 2, max_open_seconds = 8,
    probe_interval = 1, recover_successes = 2,
    stable_reset_seconds = 30,
}
fake_ngx.shared.antibot_cache = Dict.new()
package.loaded["antibot.l7.circuit_breaker"] = nil
local circuit = require "antibot.l7.circuit_breaker"

local function cbvars(host, status, upstream_time)
    fake_ngx.var = {
        server_name = host,
        host = host,
        uri = "/index.php",
        upstream_status = status,
        upstream_response_time = upstream_time,
    }
end

local function cbctx(group)
    return { req_class = group == "resource" and "resource" or "navigation",
             admission_group = group, req = {} }
end

-- Evaluator chi doc bucket DA HOAN TAT. Hai hard-error o 600/601 duoc danh
-- gia boi request dau 602; bucket 602 hien tai khong chen vao mau.
clock = 600
exits = {}
cbvars("a.test", "503", "0.100")
local ca1 = cbctx("dynamic")
circuit.after(ca1)
eq(ca1.circuit_transition, nil, "circuit khong mo khi chua du mau")
clock = 601
local ca2 = cbctx("dynamic")
circuit.after(ca2)
eq(ca2.circuit_transition, nil,
   "evaluator khong doc bucket 601 dang ghi do")
clock = 602
local ca3 = cbctx("dynamic")
circuit.after(ca3)
eq(ca3.circuit_transition, "closed>open", "hard-error du nguong mo breaker")
eq(ca3.circuit_state, "open", "host A vao OPEN")
eq(ca3.circuit_cause, "hard", "OPEN ghi ro nguyen nhan hard")
eq(ca3.circuit_total, 2, "evaluator doc hai bucket da hoan tat")
ok(ca3.circuit_open_until > clock, "OPEN co deadline")

-- Shadow mo hinh hoa phan quyet nhung tuyet doi khong 503.
local ca_shadow = cbctx("dynamic")
local _, shadow_exit = circuit.before(ca_shadow)
eq(shadow_exit, false, "shadow circuit khong terminate request")
eq(ca_shadow.circuit_would_reject, true, "shadow ghi would-reject")
eq(ca_shadow.circuit_state, "open", "shadow ghi dung state OPEN")
eq(ca_shadow.circuit_cause, "hard", "shadow giu cause cua OPEN state")

-- Host B doc lap: A OPEN khong duoc lam B bi shed.
cbvars("b.test", nil, nil)
local cb = cbctx("dynamic")
local _, b_exit = circuit.before(cb)
eq(b_exit, false, "host B khong bi anh huong boi host A")
eq(cb.circuit_state, "closed", "state tach theo canonical host")

-- Static hit tren chinh host A khong bao gio bi circuit breaker chan.
cbvars("a.test", nil, nil)
local static_ctx = cbctx("resource")
local _, static_exit = circuit.before(static_ctx)
eq(static_exit, false, "OPEN host van phuc vu static hit")
eq(static_ctx.circuit_would_reject, nil, "static khong tham gia breaker")

-- Enforce chi doi PHAN QUYET, khong doi state da hoc trong shadow.
cfg.l7_circuit_breaker.mode = "enforce"
local ca_enforce = cbctx("dynamic")
local _, enforce_exit = circuit.before(ca_enforce)
eq(enforce_exit, true, "enforce OPEN tra loi som")
eq(exits[#exits], 503, "circuit breaker dung 503, khong dung 429")
eq(ca_enforce.action_reason, "l7_circuit:open", "503 co reason capacity")

-- Het cooldown: mot probe/giay duoc qua, request thu hai van bi shed.
clock = ca3.circuit_open_until + 0.1
exits = {}
cbvars("a.test", nil, nil)
local probe1 = cbctx("dynamic")
local _, probe1_exit = circuit.before(probe1)
eq(probe1_exit, false, "HALF-OPEN cho probe dau tien di qua")
eq(probe1.circuit_probe, true, "request duoc gan probe lease")
local no_probe = cbctx("dynamic")
local _, no_probe_exit = circuit.before(no_probe)
eq(no_probe_exit, true, "HALF-OPEN shed request khong co probe lease")
eq(no_probe.circuit_state, "half_open", "shed ghi state HALF-OPEN")

-- Ket qua cua probe thuoc epoch cu khong duoc sua state moi. Day khong phai
-- ca ly thuyet: slow_seconds lon hon probe_interval tao nhieu probe in-flight.
local probe_epoch = probe1.circuit_open_until
fake_ngx.shared.antibot_cache:set(
    "cb:a.test:open_until", probe_epoch + 10, 30)
cbvars("a.test", "200", "0.100")
circuit.after(probe1)
eq(probe1.circuit_probe_stale, true,
   "late probe cua epoch cu bi bo qua")
eq(fake_ngx.shared.antibot_cache:get("cb:a.test:probe_ok"), nil,
   "late probe khong duoc cong recovery")
fake_ngx.shared.antibot_cache:set(
    "cb:a.test:open_until", probe_epoch, 30)
probe1.circuit_probe_stale = nil

-- Hai probe tot lien tiep dong breaker.  Request khong chua upstream_status
-- khong duoc tinh la probe thanh cong.
cbvars("a.test", nil, nil)
circuit.after(probe1)
eq(probe1.circuit_probe_successes, nil,
   "probe khong cham upstream khong duoc tinh thanh cong")
cbvars("a.test", "200", "0.100")
circuit.after(probe1)
eq(probe1.circuit_probe_successes, 1, "probe tot thu nhat duoc ghi")

clock = clock + 1.1
cbvars("a.test", nil, nil)
local probe2 = cbctx("dynamic")
local _, probe2_exit = circuit.before(probe2)
eq(probe2_exit, false, "giay sau cap probe recovery tiep theo")
cbvars("a.test", "200", "0.200")
circuit.after(probe2)
eq(probe2.circuit_transition, "half_open>closed",
   "du probe tot thi dong breaker")
eq(probe2.circuit_cause, "hard", "recovery dong dung hard circuit")

-- ── cbnosample: phan biet "chua du luu luong" voi "khong doc duoc" ───
--
-- VI SAO CAN. `sample_from_ngx` tra `nil` khi request khong toi upstream, va
-- ban dau `after()` thoat IM LANG o do. Hau qua: "0 dong `cb=` trong
-- antibot.log" mang HAI nghia khac nhau — breaker chay nhung chua du luu
-- luong, HAY `ngx.var.upstream_status` khong doc duoc o log phase va ca module
-- la ma chet. Khong mot tep nao khac trong cay nay doc bien do, nen gia dinh
-- "doc duoc o log phase" chua tung duoc kiem tren may that.
--
-- Day la lop loi [[feedback_flag_read_before_write]] (cot `-` thuong la "thoat
-- truoc khi tang chay", khong phai "da do, rong") cong
-- [[feedback_alert_reaches_nobody]] (kiem DUONG RA, khong chi kiem phat hien).
--
-- CHI MOT MAU moi giay moi host: tren 28-246 co 666.752 dong/24h va phan lon
-- request dynamic khong toi upstream la nhung request chinh antibot da chan
-- (PoW page, 403, 429). Danh dau het la tu lam phong log de tra loi mot cau
-- hoi chi can mot mau.
clock = 700
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
cbvars("nosample.test", nil, nil)
local ns_marked = 0
for _ = 1, 50 do
    local c = cbctx("dynamic")
    circuit.after(c)
    if c.circuit_no_sample then ns_marked = ns_marked + 1 end
end
eq(ns_marked, 1, "cbnosample ban DUNG MOT lan trong mot giay")

clock = 701
local ns2 = 0
for _ = 1, 50 do
    local c = cbctx("dynamic")
    circuit.after(c)
    if c.circuit_no_sample then ns2 = ns2 + 1 end
end
eq(ns2, 1, "giay moi -> mot mau moi")

-- Request khong toi upstream KHONG duoc tao mau cho cua so: neu nguoc lai,
-- mot host bi antibot chan hang loat se tu sinh ra `total` lon ma khong co
-- bang chung nao ve suc khoe backend.
local c3 = cbctx("dynamic")
circuit.after(c3)
eq(c3.circuit_total, nil, "khong toi upstream thi khong danh gia cua so")

-- Doi chieu: co `upstream_status` thi KHONG danh dau nosample.
clock = 702
cbvars("nosample.test", "200", "0.100")
local c4 = cbctx("dynamic")
circuit.after(c4)
eq(c4.circuit_no_sample, nil, "co upstream sample thi khong danh dau nosample")
eq(fake_ngx.shared.antibot_cache:get("cb:a.test:b:601:n"), nil,
   "dong breaker xoa mau loi cu, khong lap tuc mo lai")
eq(fake_ngx.shared.antibot_cache:get("cb:a.test:cause"), nil,
   "dong breaker xoa cause cua episode cu")

cbvars("a.test", nil, nil)
local recovered = cbctx("dynamic")
local _, recovered_exit = circuit.before(recovered)
eq(recovered_exit, false, "host phuc hoi cho dynamic traffic di qua")
eq(recovered.circuit_state, "closed", "state tro ve CLOSED")

-- 404/403 la ket qua client/application, khong phai hard backend failure.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.l7_circuit_breaker.mode = "shadow"
clock = 700
cbvars("c.test", "404", "0.100")
circuit.after(cbctx("dynamic"))
clock = 701
circuit.after(cbctx("dynamic"))
clock = 702
local c404 = cbctx("dynamic")
circuit.after(c404)
eq(c404.circuit_transition, nil, "404 khong mo circuit breaker")
eq(c404.circuit_hard_ratio, 0, "404 khong tinh hard error")

-- Slow 200 chi la candidate telemetry. Du 100% cham cung KHONG duoc ghi OPEN.
fake_ngx.shared.antibot_cache = Dict.new()
clock = 800
cbvars("slow.test", "200", "2.500")
circuit.after(cbctx("dynamic"))
clock = 801
circuit.after(cbctx("dynamic"))
clock = 802
cbvars("slow.test", "200", "0.100")
local slow_ctx = cbctx("dynamic")
circuit.after(slow_ctx)
eq(slow_ctx.circuit_transition, nil,
   "slow 200 du nguong khong mo breaker")
eq(slow_ctx.circuit_hard_ratio, 0, "slow 200 khong bi goi la hard error")
eq(slow_ctx.circuit_slow_ratio, 1, "slow ratio duoc do rieng")
eq(slow_ctx.circuit_slow_candidate, true,
   "slow candidate duoc ghi de do tren fleet")
eq(fake_ngx.shared.antibot_cache:get("cb:slow.test:open_until"), nil,
   "slow candidate khong tao OPEN state")

-- Probe 200 cham van chung minh hard outage da het. No duoc ghi telemetry
-- nhung khong duoc reopen hard circuit.
fake_ngx.shared.antibot_cache = Dict.new()
clock = 850
fake_ngx.shared.antibot_cache:set("cb:probe-slow.test:open_until", 849, 30)
fake_ngx.shared.antibot_cache:set("cb:probe-slow.test:cause", "hard", 30)
cbvars("probe-slow.test", nil, nil)
local slow_probe = cbctx("dynamic")
local _, slow_probe_exit = circuit.before(slow_probe)
eq(slow_probe_exit, false, "slow recovery probe duoc di qua")
eq(slow_probe.circuit_probe, true, "slow recovery request la probe")
cbvars("probe-slow.test", "200", "2.500")
circuit.after(slow_probe)
eq(slow_probe.circuit_probe_slow, true, "probe cham duoc ghi telemetry")
eq(slow_probe.circuit_transition, nil,
   "mot slow 200 khong reopen hard circuit")
eq(slow_probe.circuit_probe_successes, 1,
   "slow 200 van la hard-recovery success")
clock = 851.1
cbvars("probe-slow.test", nil, nil)
local slow_probe2 = cbctx("dynamic")
local _, slow_probe2_exit = circuit.before(slow_probe2)
eq(slow_probe2_exit, false, "slow recovery probe thu hai duoc di qua")
cbvars("probe-slow.test", "200", "2.500")
circuit.after(slow_probe2)
eq(slow_probe2.circuit_transition, "half_open>closed",
   "hai slow 200 dong hard circuit thay vi reopen")
eq(fake_ngx.shared.antibot_cache:get(
    "cb:probe-slow.test:open_until"), nil,
   "slow 200 recovery xoa OPEN state")

-- Resource sample va response khong co upstream khong duoc tao bucket.
fake_ngx.shared.antibot_cache = Dict.new()
clock = 900
cbvars("ignore.test", "503", "3.000")
circuit.after(cbctx("resource"))
clock = 901
cbvars("ignore.test", nil, nil)
local ignored = cbctx("dynamic")
circuit.after(ignored)
eq(ignored.circuit_evaluated, nil,
   "chi hoc tu dynamic request da cham upstream")

-- Dung 3 req/s trong 10 giay = 30 mau. Ban cu doc bucket hien tai moi co
-- mot request nen chi thay 28 va khong bao gio mo; complete buckets phai mo o
-- request dau giay 11 voi dung n=30, rps=3.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.l7_circuit_breaker.min_samples = 30
cfg.l7_circuit_breaker.hard_error_ratio = 1
clock = 1000
local exact3_last
for sec = 0, 9 do
    for hit = 1, 3 do
        clock = 1000 + sec + hit / 10
        cbvars("exact3.test", "503", "0.100")
        exact3_last = cbctx("dynamic")
        circuit.after(exact3_last)
        eq(exact3_last.circuit_transition, nil,
           "3rps khong mo truoc khi du 10 bucket")
    end
end
clock = 1010.1
cbvars("exact3.test", "503", "0.100")
local exact3_trip = cbctx("dynamic")
circuit.after(exact3_trip)
eq(exact3_trip.circuit_transition, "closed>open",
   "dung 3rps mo sau 10 bucket hoan tat")
eq(exact3_trip.circuit_total, 30, "3rps co dung 30 mau")
eq(exact3_trip.circuit_rps, 3, "config 3rps khop hanh vi 3rps")

-- Tach `min_samples` khoi RPS dan xuat: cung 30 mau nhung cua so 20s chi co
-- rps=1.5 van PHAI du dieu kien. Neu ai khoi phuc cong RPS cu voi fallback 3,
-- ca nay do. Neu ai xoa cong min_samples, cac assertion trong vong lap do som.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.l7_circuit_breaker.window_seconds = 20
clock = 1050
local sample_gate_last
for sec = 0, 9 do
    for hit = 1, 3 do
        clock = 1050 + sec + hit / 10
        cbvars("sample-gate.test", "503", "0.100")
        sample_gate_last = cbctx("dynamic")
        circuit.after(sample_gate_last)
        eq(sample_gate_last.circuit_transition, nil,
           "min_samples ngan trip som du hard ratio=1")
    end
end
clock = 1060.1
cbvars("sample-gate.test", "503", "0.100")
local sample_gate_trip = cbctx("dynamic")
circuit.after(sample_gate_trip)
eq(sample_gate_trip.circuit_transition, "closed>open",
   "30 mau la du du rps dan xuat chi 1.5")
eq(sample_gate_trip.circuit_total, 30,
   "cua so 20s van dung cong min_samples=30")
eq(sample_gate_trip.circuit_rps, 1.5,
   "rps chi la telemetry total/window, khong phai cong")
cfg.l7_circuit_breaker.window_seconds = 10

-- Circuit breaker khong hua chan burst duoi mot giay: evaluator dau giay thay
-- cua so cu. Neu traffic con tiep tuc sang giay sau, no moi thay tron burst;
-- admission.lua chiu trach nhiem chan ngay trong cung mot giay.
fake_ngx.shared.antibot_cache = Dict.new()
clock = 1100.1
local burst_same_second
for _ = 1, 100 do
    cbvars("burst.test", "503", "0.100")
    burst_same_second = cbctx("dynamic")
    circuit.after(burst_same_second)
    eq(burst_same_second.circuit_transition, nil,
       "burst cung giay khong bi circuit danh gia lai moi request")
end
eq(fake_ngx.shared.antibot_cache:get("cb:burst.test:open_until"), nil,
   "burst dung trong mot giay khong mo circuit")
clock = 1101.1
cbvars("burst.test", "503", "0.100")
local burst_next_second = cbctx("dynamic")
circuit.after(burst_next_second)
eq(burst_next_second.circuit_transition, "closed>open",
   "request giay sau thay tron burst cua giay truoc")
eq(burst_next_second.circuit_total, 100,
   "evaluator giay sau doc du 100 mau")
eq(burst_next_second.circuit_rps, 10,
   "burst 100 mau tren cua so 10s thanh 10rps")

cfg.l7_circuit_breaker = old_circuit

-- Redis rate counter: hai bucket tao approximate sliding window; traffic cu
-- phai fade thay vi bi refresh vo han boi request moi.
clock = 0
local rate_data = {}
local Redis = {}
Redis.__index = Redis
function Redis:init_pipeline() self.results = {} end
function Redis:incrbyfloat(key, delta)
    rate_data[key] = (rate_data[key] or 0) + delta
    self.results[#self.results + 1] = rate_data[key]
end
function Redis:expire() self.results[#self.results + 1] = 1 end
function Redis:get(key)
    -- Redis pipeline giu nguyen vi tri cua nil bang ngx.null. Chuoi rong cho
    -- cung semantics `tonumber(...) == nil` ma khong lam mang Lua bi co lai.
    self.results[#self.results + 1] = rate_data[key] or ""
end
function Redis:commit_pipeline() return self.results end
local redis = setmetatable({}, Redis)
package.loaded["antibot.core.redis_pool"] = {
    get = function() return redis end,
    put = function() end,
}
package.loaded["antibot.core.fingerprint.identity"] = {
    build_from = function(ip, ua) return ip .. ":" .. (ua or "") end,
}
package.loaded["antibot.l7.rate.counter"] = nil
local counter = require "antibot.l7.rate.counter"
local function rate_at(t)
    clock = t
    local ctx = {
        ip = "198.51.100.2", ua = "ua", identity = "identity-1",
        rate_weight = 1, req_class = "navigation",
    }
    counter.run(ctx)
    return ctx.rate
end
eq(rate_at(0), 1, "rate first hit")
eq(rate_at(59), 2, "rate current bucket accumulates")
local faded = rate_at(118)
ok(faded > 1.05 and faded < 1.10, "old rate bucket fades instead of accumulating")

-- Burst bucket doi key theo thoi gian va khong con session grace dat sai thu tu.
local burst_data = {}
package.loaded["antibot.core.redis_pool"] = {
    safe_incr = function(key)
        burst_data[key] = (burst_data[key] or 0) + 1
        return burst_data[key]
    end,
}
package.loaded["antibot.l7.burst.burst_counter"] = nil
local burst_counter = require "antibot.l7.burst.burst_counter"
clock = 0.9
local bctx = { identity = "b1", sess_len = 99, session_flag = 0 }
burst_counter.run(bctx)
burst_counter.run(bctx)
eq(bctx.burst, 2, "session length no longer disables burst counter")
clock = 1.0
burst_counter.run(bctx)
eq(bctx.burst, 1, "burst starts a new fixed bucket")

-- Resource good-bot claim that fails ASN proof must enter full detection.
package.loaded["antibot.detection.bot.ua_check"] = {
    run = function(ctx)
        ctx.good_bot_claimed = true
        ctx.good_bot_name = "Googlebot"
        ctx.good_bot_asns = { 15169 }
        ctx.bot_score = 0
    end,
}
package.loaded["antibot.core.fingerprint.asn"] = { run = function() end }
package.loaded["antibot.core.redis_pool"] = { safe_set = function() end }
package.loaded["antibot.detection.bot.lite_verify"] = nil
fake_ngx.var = { uri = "/photo.jpg" }
local lite = require "antibot.detection.bot.lite_verify"
local lctx = { ip = "192.0.2.9", asn = { asn_number = 64500 } }
lite.run(lctx)
eq(lctx.bot_lite_needs_full, true, "ASN mismatch escalates resource to full lane")
eq(lctx.bot_score, 0.85, "unverified good-bot claim is not score zero")

-- Integration contracts that are otherwise easy to regress by moving one
-- early return or restoring a bare `return` in a generated location.
local init_src = read_file("antibot-core/init.lua")
local admission_pos = assert(init_src:find("run_steps%(STEPS_ADMISSION, ctx%)"))
local verified_pos = assert(init_src:find("check_verified_cookie%(ctx%)", admission_pos))
local waf_pos = assert(init_src:find("waf_layer%.run_pre%(ctx%)"))
ok(admission_pos < verified_pos, "admission runs before verified-cookie exit")
ok(admission_pos < waf_pos, "admission runs before WAF body scan")
ok(init_src:find("xfilter_guard%.run%(ctx%)", verified_pos) ~= nil,
   "verified fast path still crosses faceted-filter guard")

local admission_steps = assert(init_src:match(
    "local STEPS_ADMISSION%s*=%s*{(.-)\n}"))
local local_brake_pos = assert(admission_steps:find("layer%s*=%s*l7_admission"))
local circuit_pos = assert(admission_steps:find("layer%s*=%s*l7_circuit"))
local redis_ban_pos = assert(admission_steps:find("layer%s*=%s*ip_ban_check"))
ok(local_brake_pos < circuit_pos,
   "circuit breaker reuses admission dynamic/static decision")
ok(circuit_pos < redis_ban_pos,
   "OPEN host sheds work before Redis-backed IP ban lookup")
ok(local_brake_pos < redis_ban_pos,
   "local admission shields Redis-backed IP ban lookup")

local circuit_after_pos = assert(init_src:find("l7_circuit%.after%(ctx%)"))
local logger_pos = assert(init_src:find("logger%.run%(ctx%)", circuit_after_pos))
ok(circuit_after_pos < logger_pos,
   "log-phase circuit telemetry is ready before main logger")

local generator = read_file("nginx/da_to_openresty.sh")
ok(generator:find("antibot.l7.admission", 1, true) == nil,
   "generator is not coupled to Lua admission")
ok(generator:find("limit_conn antibot_conn_", 1, true) == nil,
   "generator has no admission-specific native connection limits")
ok(generator:find("circuit_breaker", 1, true) == nil,
   "generator is not coupled to Lua circuit breaker")

local nginx_conf = read_file("nginx/nginx.conf")
ok(nginx_conf:find("antibot_l7_", 1, true) == nil,
   "nginx.conf has no admission-specific shared dict")
ok(nginx_conf:find("limit_conn_zone", 1, true) == nil,
   "nginx.conf is unchanged by Lua-only admission")
ok(nginx_conf:find("circuit_breaker", 1, true) == nil,
   "nginx.conf is unchanged by Lua-only circuit breaker")

local verify_handler = read_file(
    "antibot-core/enforcement/challenge/verify_token.lua")
local beacon_handler = read_file(
    "antibot-core/detection/browser/beacon_handler.lua")
ok(verify_handler:find('run_endpoint("verify")', 1, true) ~= nil,
   "verify handler invokes Lua-only endpoint admission")
ok(beacon_handler:find('run_endpoint("beacon")', 1, true) ~= nil,
   "beacon handler invokes Lua-only endpoint admission")

print(string.format("L7_REGRESSION_OK %d", passed))
