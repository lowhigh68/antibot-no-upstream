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

-- `error()` MOT MINH khong du de `run.sh` thay that bai.
--
-- `resty` chay tep nay trong `init_worker_by_lua`, va vong `xpcall` cua no BAT
-- moi error roi in traceback — nhung thoat voi ma 0. Do 08-10: mot dot bien lam
-- hong cu phap `distributed_swarm.lua` in ra ERROR day du va `run.sh` van bao
-- rc=0, nen `|| rc=1` o `run.sh:114` chua bao gio co hieu luc. Cung ho loi voi
-- `tools/wafdiff` (a714f72): bo kiem bao SACH khi chinh no hong.
--
-- `io.stderr` chu khong `print`: o day `print` di qua duong log cua nginx.
local function die(msg)
    io.stderr:write("L7_REGRESSION_FAIL: ", tostring(msg), "\n")
    io.stderr:flush()
    os.exit(1)
end

local function ok(value, label)
    if not value then die("FAIL: " .. label) end
    passed = passed + 1
end

local function eq(actual, expected, label)
    if actual ~= expected then
        die(string.format("FAIL: %s (got=%s expected=%s)",
            label, tostring(actual), tostring(expected)))
    end
    passed = passed + 1
end

local function read_file(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("*a")
    f:close()
    return s
end

-- Duong dan phai di qua `SRC`, KHONG dong cung `antibot-core/`: bo kiem nay
-- chay o CA HAI noi (repo lan cay da deploy `conf/antibot/`) va chinh
-- `run.sh:108-111` da ghi ro dieu do. Ban hardcode truoc day lam MOI dong
-- `loadfile` tra nil khi chay tu cay deploy — ma `ok()` dem nil la FAIL, nen
-- bo kiem bao 21 loi cu phap gia cho 21 tep hoan toan binh thuong.
local syntax_rel = {
    "init.lua",
    "core/config.lua",
    "core/policy.lua",
    "core/policy_store.lua",
    "core/policy_tool.lua",
    "core/policy_runtime.lua",
    "core/network_quarantine.lua",
    "core/operator_network.lua",
    "core/req_classifier.lua",
    "detection/bot/lite_verify.lua",
    "detection/browser/beacon_handler.lua",
    "detection/session/session_store.lua",
    "detection/distributed_swarm.lua",
    "enforcement/challenge/verify_token.lua",
    "enforcement/decision/engine.lua",
    "enforcement/ban/ban_escalation.lua",
    "enforcement/ban/ban_store_write.lua",
    "enforcement/ban/ban_sync.lua",
    "async/logger.lua",
    "l7/admission.lua",
    "l7/automation_guard.lua",
    "l7/principal_churn.lua",
    "l7/dynamic_guard.lua",
    "l7/operator_concurrency.lua",
    "l7/endpoint_guard.lua",
    "l7/circuit_breaker.lua",
    "l7/surge_guard.lua",
    "l7/init.lua",
    "l7/expensive_filter_guard.lua",
    "l7/ban/ip_ban_check.lua",
    "l7/ban/ban_store.lua",
    "l7/burst/burst_counter.lua",
    "l7/burst/burst_decision.lua",
    "l7/rate/adaptive_limit.lua",
    "l7/rate/counter.lua",
    "l7/rate/res_ip_counter.lua",
    "waf/endpoint_policy.lua",
}

local syntax_files = {}
for i, rel in ipairs(syntax_rel) do syntax_files[i] = SRC .. rel end

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
-- `full`: mo phong dict HET MEMORY. OpenResty tra loi khac "exists" o `add` khi
-- khong con cho, va do la duong DUY NHAT tien toi `dict_error` trong
-- `admission` — fail-open, request di qua ma KHONG duoc dem. Lo do do thuc tren
-- 171-96 (17 luot/94.121 mau) ma truoc 06-10 KHONG co mot ca test nao.
function Dict:add(key, value, ttl)
    if self.full then return nil, "no memory" end
    if self.fail_prefix and key:find(self.fail_prefix, 1, true) == 1 then
        return nil, "no memory"
    end
    if self:_live(key) ~= nil then return nil, "exists" end
    self.data[key] = value
    self.expiry[key] = clock + ttl
    return true
end
-- `get`/`set`: `admission.static_target_exists` cache ket qua `io.open` o day.
-- Thieu hai ham nay thi module no o access phase, va mot stub thieu ham cua
-- production API la mot phep do sai chieu — no bao "qua" vi chua goi tai.
function Dict:get(key)
    if self.get_override and self.get_override[key] ~= nil then
        return self.get_override[key]
    end
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
function Dict:expire(key, ttl)
    if self:_live(key) == nil then return nil, "not found" end
    self.expiry[key] = clock + ttl
    return true
end

local fake_ngx = {
    var = {}, ctx = {}, header = {},
    is_subrequest = false,
    shared = {
        antibot_cache = Dict.new(),
    },
    DEBUG = 0, INFO = 1, WARN = 2, ERR = 3,
    now = function() return clock end,
    time = function() return math.floor(clock) end,
    log = function() end,
    say = function() end,
    exit = function(code) exits[#exits + 1] = code; return code end,
    -- Must DEPEND on the input. A constant made every hashed key collide, so
    -- any test asking "do two different subjects get different keys" passed
    -- vacuously — `endpoint_scope` keyed on docroot is exactly such a test.
    -- Not a cryptographic hash; it only needs to separate distinct inputs
    -- and to be stable within a run (line ~1960 derives a key from it).
    md5 = function(s)
        s = tostring(s or "")
        local a, b = 5381, 52711
        for i = 1, #s do
            local c = s:byte(i)
            a = (a * 33 + c) % 4294967296
            b = (b * 31 + c * i) % 4294967296
        end
        return string.format("%08x%08x%08x%08x", a, b,
            (a + #s * 2654435761) % 4294967296,
            (b + a) % 4294967296)
    end,
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
            return real_open(SRC .. "l7/admission.lua", "r")
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
    -- KHONG cache chieu `false` (06-10): tep khong ton tai la tap VO HAN do ke
    -- gui quyet dinh, nen cache chung la tu lam day `antibot_cache` — do that
    -- tren 171-96: 17 luot `adm=*dict_error`, va `dict:set` khi het memory thi
    -- OpenResty TU LRU-evict khong bao loi, nen no day khoa counter ra ngoai.
    -- Nen 4 request vao cung URI thieu = 4 lan `io.open`. Mot `stat` tren trang
    -- cache cua kernel re hon han viec mat bo dem ngan sach.
    eq(probe_opens, 4, "static MISS KHONG duoc cache (tap vo han)")
end)

-- Ca 2b: cache chieu TRUE phai co TTL. Khong co TTL thi mot tep bi xoa van
-- duoc coi la con MAI MAI. Dot bien `ttl -> nil` khong bi ca 1 bat, nen bat
-- bien nay can phep do rieng — va no phai dung duong dan CO THAT, vi chieu
-- `false` khong con vao cache nua.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.uri = "/real.jpg"
with_fake_disk("/real.jpg", function()
    local c = { ip = "198.51.100.2b", req_class = "resource", req = {} }
    admission.run(c)
    eq(probe_opens, 1, "lan dau: stat that")
    local c1 = { ip = "198.51.100.2b", req_class = "resource", req = {} }
    admission.run(c1)
    eq(probe_opens, 1, "trong TTL: dung cache, khong stat lai")
    clock = clock + 31          -- static_probe_ttl = 30
    local c2 = { ip = "198.51.100.2b", req_class = "resource", req = {} }
    admission.run(c2)
    eq(probe_opens, 2, "qua TTL: probe chay lai (tep bi xoa duoc nhan ra)")
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

-- P1.0 end-to-end: the compiled server scope must alter the real consumer,
-- not merely produce a resolved table in policy_contract.lua.  Disable this
-- module for one node, then restore an empty overlay before later suites.
do
    local request_policy = require "antibot.core.policy"
    local applied = request_policy.configure({
        schema = "1", version = "l7-consumer-test",
        global = { settings = {} },
        servers = {
            ["node-policy"] = {
                settings = { l7_admission = { enabled = false } },
            },
        },
        tenants = {}, principals = {},
    })
    eq(applied, true, "P1.0 policy server scope nap duoc")
    fake_ngx.var.hostname = "node-policy"
    local pctx = { ip = "198.51.100.6", req_class = "navigation", req = {} }
    local _, pexit = admission.run(pctx)
    eq(pexit, false, "P1.0 override off khong chan")
    eq(pctx.admission_group, nil,
       "P1.0 override duoc consumer doc truoc khi dem admission")
    assert(request_policy.configure({
        schema = "1", version = "l7-empty",
        global = { settings = {} },
        servers = {}, tenants = {}, principals = {},
    }))
    fake_ngx.var.hostname = nil
end

fake_ngx.var.document_root = nil
cfg.l7_admission = old_admission

-- Per-host Lua-only dynamic in-flight guard.  A slot is acquired only after
-- the request has survived local policy and is released exactly once at log.
--
-- `do ... end`: LuaJIT gioi han 200 bien `local` o MAIN FUNCTION. Khoi nay
-- khong doi mot assert nao, chi dua bien cua nhom test ra khoi pham vi do.
-- Thieu no thi CA FILE khong bien dich duoc va `deploy.sh` HUY o cong
-- "bien dich duoc: moi file .lua".
--
-- Ba ten nay khai bao NGOAI khoi vi nhom test "bien enforce" o cuoi file
-- dung lai chung. Gan gia tri ben trong, doc ben ngoai.
local surge, sgvars, sgctx
do
local old_surge = cfg.l7_surge_guard
cfg.l7_surge_guard = {
    enabled = true, mode = "shadow", status = 503, retry_after = 2,
    max_inflight = 2, surge_ratio = 0.75, recover_ratio = 0.50,
    recovery_seconds = 2,
    slot_bucket_seconds = 60, slot_retention_seconds = 300,
    state_ttl = 300,
    sample_interval = 1,
}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_stats = Dict.new()
package.loaded["antibot.l7.surge_guard"] = nil
surge = require "antibot.l7.surge_guard"

sgvars = function(host, upstream_time)
    fake_ngx.var = {
        server_name = host,
        host = host,
        uri = "/index.php",
        upstream_response_time = upstream_time,
    }
end

sgctx = function(group)
    return {
        ip = "192.0.2.30",
        req_class = group == "resource" and "resource" or "navigation",
        admission_group = group,
        req = { uri = "/index.php" },
    }
end

clock = 600
exits = {}
sgvars("surge.test", "0.250")

-- Real static hits and subrequests never occupy a dynamic slot.
local sg_static = sgctx("resource")
surge.before(sg_static)
surge.admit(sg_static)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), nil,
   "static hit khong chiem surge slot")

fake_ngx.is_subrequest = true
local sg_sub = sgctx("dynamic")
surge.admit(sg_sub)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), nil,
   "subrequest khong bi dem nhu request doc lap")
fake_ngx.is_subrequest = false

-- Shadow runs the full counter/state machine but never rejects.  Exactly two
-- slots are valid; request three is the first simulated reject.
local sg1, sg2, sg3 = sgctx("dynamic"), sgctx("dynamic"), sgctx("dynamic")
local _, sg1_exit = surge.admit(sg1)
eq(sg1_exit, false, "surge slot dau tien duoc cap")
eq(sg1.surge_inflight, 1, "slot dau tien dem bang mot")
local _, sg2_exit = surge.admit(sg2)
eq(sg2_exit, false, "dung tran van duoc cap slot")
eq(sg2.surge_inflight, 2, "dung tran co hai slot")
local _, sg3_exit = surge.admit(sg3)
eq(sg3_exit, false, "shadow khong tra 503")
eq(sg3.surge_would_reject, true, "request limit+1 duoc danh dau shadow")
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), 3,
   "shadow van do concurrency thuc sau nguong")

-- Release is exactly once.  One ordinary sample/host/second is elected and
-- carries both request lifetime and upstream time for FP analysis.
clock = 600.5
surge.after(sg1)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), 2,
   "log phase tra mot slot")
eq(sg1.surge_sampled, true, "mot mau surge duoc bau trong giay")
eq(sg1.surge_upstream_time, 0.25, "sample doc upstream response time")
surge.after(sg1)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), 2,
   "goi after hai lan khong tru hai slot")
surge.after(sg2)
surge.after(sg3)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), nil,
   "tra het slot thi xoa counter")

-- No admit means a WAF/challenge/local block cannot decrement or create state.
local sg_blocked = sgctx("dynamic")
surge.after(sg_blocked)
eq(fake_ngx.shared.antibot_cache:get("sg:surge.test:slot:10"), nil,
   "request bi chan truoc admit khong cham counter")

-- Recovery hysteresis is observable and becomes normal after the quiet hold.
clock = 603
local sg_recovered = sgctx("dynamic")
surge.admit(sg_recovered)
eq(sg_recovered.surge_state, "normal", "quiet hold ket thuc recovery")
surge.after(sg_recovered)

-- A worker crash can miss after().  New traffic must not refresh that leaked
-- aggregate forever: the old start-time bucket ages out on a busy host.
fake_ngx.shared.antibot_cache = Dict.new()
clock = 900
sgvars("leak.test", "0.100")
local leaked = sgctx("dynamic")
surge.admit(leaked) -- deliberately no after(), simulating an aborted worker
eq(fake_ngx.shared.antibot_cache:get("sg:leak.test:slot:15"), 1,
   "slot ro nam trong bucket thoi gian bat dau")
for minute = 1, 5 do
    clock = 900 + minute * 60 + 1
    local live = sgctx("dynamic")
    surge.admit(live)
    surge.after(live)
end
clock = 1261
local leak_aged = sgctx("dynamic")
surge.admit(leak_aged)
eq(leak_aged.surge_inflight, 1,
   "slot ro da het han, chi con request moi tren host ban")
eq(fake_ngx.shared.antibot_cache:get("sg:leak.test:slot:15"), nil,
   "traffic moi khong refresh bucket ro cu")
surge.after(leak_aged)

-- ── NHANH `enforce` DA GO 12-10: `surge_guard` KHONG con tu choi ai ──
--
-- CHIN assertion cu o day ghim hanh vi 503 (late atomic gate + rollback + early
-- shed). Chung da duoc THAY, khong phai xoa: cac assertion duoi ghim dung dieu
-- NGUOC lai, va do moi la hop dong hien tai.
--
-- Vi sao go: do ba may — `sgn` dinh 111 vs `max_inflight = 20`, 787 luot se 503
-- tren dung domain DA co FP, con admission (phanh CHINH) chan 0 o p99 12/80.
-- Xem `project_shadow_het_han` muc 2.
--
-- Phep thu nay dat `mode = "enforce"` CO Y du khong ai dat gia tri do tren
-- production: no chung minh rang NGAY CA khi ai do bat lai bang config, module
-- cung khong con duong 503 nao — vi ham `reject()` da bi go khoi tep. Mot phep
-- thu chi chay o `shadow` se khong phat hien duoc viec nhanh enforce bi hoi sinh.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.l7_surge_guard.mode = "enforce"
clock = 700
exits = {}
sgvars("enforce.test", "0.100")
local se1, se2, se3 = sgctx("dynamic"), sgctx("dynamic"), sgctx("dynamic")
surge.before(se1)
surge.before(se2)
surge.before(se3)
surge.admit(se1)
surge.admit(se2)
local _, se3_exit = surge.admit(se3)
eq(se3_exit, false, "limit+1 KHONG con bi chan: nhanh enforce da go")
eq(#exits, 0, "khong con `ngx.exit(503)` nao tu surge_guard")
eq(se3.action_reason, nil, "khong con dat `l7_surge:capacity`")
-- TELEMETRY PHAI CON: do la gia tri duy nhat con lai cua module.
eq(se3.surge_would_reject, true,
   "`sgwould=` VAN duoc dat — go tinh toan, GIU telemetry")
eq(se3.surge_inflight, 3, "`sgn=` van dem dung so request dang chay")

-- `before()` cung khong con shed som.
local se4 = sgctx("dynamic")
local _, se4_exit = surge.before(se4)
eq(se4_exit, false, "`before()` khong con shed som")

-- Host keys are isolated; one saturated virtual host cannot shed another.
sgvars("other.test", "0.100")
local other = sgctx("dynamic")
local _, other_exit = surge.admit(other)
eq(other_exit, false, "host khac van duoc cap slot")
eq(fake_ngx.shared.antibot_cache:get("sg:other.test:slot:11"), 1,
   "counter duoc tach theo server_name")

-- The late atomic gate must use this request's own incr return.  Re-reading a
-- current bucket that already includes later workers can make several workers
-- all reject and roll back valid slots at once.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.get_override = {
    ["sg:atomic.test:slot:14"] = 99,
}
clock = 840
sgvars("atomic.test", "0.100")
local atomic_ctx = sgctx("dynamic")
local _, atomic_exit = surge.admit(atomic_ctx)
eq(atomic_exit, false, "late gate dung gia tri incr rieng cua request")
eq(atomic_ctx.surge_inflight, 1,
   "concurrent later increments khong lam request nay tu nhan limit+1")
fake_ngx.shared.antibot_cache.get_override = nil
surge.after(atomic_ctx)

-- Shared-dict pressure fails open and is explicitly observable.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.full = true
cfg.l7_surge_guard.mode = "shadow"
clock = 800
sgvars("dict-full.test", nil)
local sg_degraded = sgctx("dynamic")
local _, degraded_exit = surge.admit(sg_degraded)
eq(degraded_exit, false, "surge dict day fail-open")
eq(sg_degraded.surge_degraded, true, "dict day co telemetry degraded")
eq(sg_degraded.surge_admitted, nil, "dict day khong tao slot ao")

fake_ngx.shared.antibot_cache.full = nil
cfg.l7_surge_guard = old_surge
end

-- Endpoint policy: canonicalize pretty REST, rest_route and sub-directory
-- WordPress without applying the overlay to an unproven CMS root.
local function run_endpoint_tests()
local saved_wp_paths = package.loaded["antibot.waf.wordpress.paths"]
package.loaded["antibot.waf.wordpress.paths"] = {
    is_wp_root = function() return true end,
}
package.loaded["antibot.waf.endpoint_policy"] = nil
local endpoint_policy = require "antibot.waf.endpoint_policy"

local function classify_endpoint(vars, args, is_wp)
    fake_ngx.var = vars
    local ctx = { req = {
        uri = vars.uri, method = vars.request_method, host = vars.host,
    } }
    endpoint_policy.run(ctx, {
        args = args or {},
        is_wp_root = function(_, prefix, docroot)
            if is_wp == false then return false end
            ctx.test_prefix, ctx.test_docroot = prefix, docroot
            return true
        end,
    })
    return ctx
end

local ep1 = classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "url=x",
    request_method = "GET", host = "example.test",
    document_root = "/home/u/public_html",
}, { url = "https://example.test/post/" })
eq(ep1.endpoint_id, "wp_oembed_embed", "pretty oEmbed duoc canonicalize")
eq(ep1.endpoint_shape, "ok", "oEmbed hop le co shape=ok")
eq(ep1.endpoint_url_relation, "same", "oEmbed cung host duoc nhan ra")
eq(ep1.test_prefix, "", "WordPress root co prefix rong")

local ep2 = classify_endpoint({
    uri = "/blog/", args = "rest_route=%2Foembed%2F1.0%2Fembed",
    request_method = "GET",
    host = "www.example.test", document_root = "/home/u/public_html",
}, {
    rest_route = "/oembed/1.0/embed/",
    url = "https://example.test/post/",
})
eq(ep2.endpoint_id, "wp_oembed_embed", "rest_route oEmbed duoc canonicalize")
eq(ep2.test_prefix, "/blog", "rest_route giu prefix WordPress thu muc con")
eq(ep2.endpoint_url_relation, "www_alias", "www va apex duoc tach thanh alias")

-- Bang chung san xuat cloud28-246 18-10: thailandtranslation.net chay WPML nen
-- URI that la `/vi/wp-json/...`, `/ja/...`, `/zh/...`, `/TH/...` tren MOT ban
-- WordPress dung CHUNG mot `public_html`. Khoa capacity theo `docroot|prefix`
-- chia mot budget thanh bon, nen tran 3 thanh 3-moi-ngon-ngu va shadow ghi duoc
-- `epif=15/3`. Budget bao ve mot pool PHP-FPM, va pool la theo docroot.
local lang_scopes = {}
for _, lang in ipairs({ "/vi", "/ja", "/zh", "/TH" }) do
    local c = classify_endpoint({
        uri = lang .. "/wp-json/oembed/1.0/embed", args = "url=x",
        request_method = "GET", host = "thailandtranslation.test",
        document_root = "/home/u/public_html",
    }, { url = "https://thailandtranslation.test/p/" })
    eq(c.endpoint_id, "wp_oembed_embed",
       "tien to ngon ngu " .. lang .. " van duoc nhan dang")
    lang_scopes[#lang_scopes + 1] = c.endpoint_scope
end
local root_scope = classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "url=x",
    request_method = "GET", host = "thailandtranslation.test",
    document_root = "/home/u/public_html",
}, { url = "https://thailandtranslation.test/p/" }).endpoint_scope
for i = 1, #lang_scopes do
    eq(lang_scopes[i], root_scope,
       "tien to ngon ngu dung CHUNG budget voi goc, khong chia pool")
end
ok(classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "url=x",
    request_method = "GET", host = "other.test",
    document_root = "/home/other/public_html",
}, { url = "https://other.test/p/" }).endpoint_scope ~= root_scope,
   "docroot khac van la budget khac")
eq(classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "url=x",
    request_method = "GET", host = "thailandtranslation.test",
    document_root = "/home/u/public_html/",
}, { url = "https://thailandtranslation.test/p/" }).endpoint_scope, root_scope,
   "docroot co dau / cuoi khong tao budget thu hai")

local ep2dup = classify_endpoint({
    uri = "/",
    args = "rest_route=%2Fwp%2Fv2%2Fposts&rest_route=%2Foembed%2F1.0%2Fembed",
    request_method = "GET",
    host = "example.test", document_root = "/home/u/public_html",
}, {
    rest_route = { "/wp/v2/posts", "/oembed/1.0/embed" },
    url = "https://example.test/post/",
})
eq(ep2dup.endpoint_id, "wp_oembed_embed",
   "duplicate rest_route khong che duoc protected endpoint")
eq(ep2dup.endpoint_shape, "duplicate_rest_route",
   "duplicate rest_route co shape telemetry rieng")

fake_ngx.var = {
    uri = "/", args = "%72est_route=%2Foembed%2F1.0%2Fembed",
    request_method = "GET", host = "example.test",
    document_root = "/home/u/public_html",
}
local ep2encoded = { req = { uri = "/", method = "GET", host = "example.test" } }
endpoint_policy.run(ep2encoded, {
    args = {}, args_error = "truncated",
    is_wp_root = function() return true end,
})
eq(ep2encoded.endpoint_id, "wp_oembed_embed",
   "percent-encoded rest_route key khong bypass classifier")
eq(ep2encoded.endpoint_shape, "args_truncated",
   "truncated args duoc giu lam shape evidence")

local ep3 = classify_endpoint({
    uri = "/wp-json/wp/v2/users", args = "", request_method = "GET",
    host = "example.test", document_root = "/home/u/public_html",
}, { per_page = "100", search = "admin" })
eq(ep3.endpoint_id, "wp_users_collection", "GET users vao collection policy")
eq(ep3.endpoint_shape, "scan", "users search duoc danh dau scan, khong coi malformed")

local ep4 = classify_endpoint({
    uri = "/wp-json/wp/v2/users", args = "", request_method = "POST",
    host = "example.test", document_root = "/home/u/public_html",
}, {})
eq(ep4.endpoint_id, "wp_users_mutation", "POST users tach khoi enumeration")

local ep5 = classify_endpoint({
    uri = "/wp-json/wp/v2/posts", args = "_embed=1", request_method = "GET",
    host = "example.test", document_root = "/home/u/public_html",
}, { _embed = "1" })
eq(ep5.endpoint_id, "wp_rest_embed_expand", "REST _embed la family rieng")

do
    local ep = classify_endpoint({
        uri = "/wp-json/wp/v2/posts/123", args = "context=view",
        request_method = "GET", host = "example.test",
        document_root = "/home/u/public_html",
        http_cookie = "wordpress_logged_in_example=secret",
    }, { context = "view" })
    eq(ep.endpoint_id, "wp_rest_posts_item", "GET wp/v2 posts item duoc do rieng")
    eq(ep.endpoint_query_state, "present", "REST item ghi query presence")
    eq(ep.endpoint_cookie_state, "present", "REST item ghi cookie presence")
    eq(ep.endpoint_shape, "ok", "REST item hop le khong bi gan shape xau")
end

do
    local ep = classify_endpoint({
        uri = "/wp-json/wp/v2/tags/456", args = "", request_method = "HEAD",
        host = "example.test", document_root = "/home/u/public_html",
    }, {})
    eq(ep.endpoint_id, "wp_rest_tags_read", "HEAD wp/v2 tags item vao read family")
    eq(ep.endpoint_query_state, "none", "REST item khong query duoc tach rieng")
    eq(ep.endpoint_cookie_state, "none", "REST item khong cookie duoc tach rieng")
end

do
    local ep = classify_endpoint({
        uri = "/wp-json/wp/v2/posts/123", args = "_embed=1",
        request_method = "GET", host = "example.test",
        document_root = "/home/u/public_html",
    }, { _embed = "1" })
    eq(ep.endpoint_id, "wp_rest_embed_expand",
       "_embed tren posts item van giu family expand uu tien")
end

do
    local ep = classify_endpoint({
        uri = "/wp-json/wp/v2/tags/456", args = "_embed=1",
        request_method = "GET", host = "example.test",
        document_root = "/home/u/public_html",
    }, { _embed = "1" })
    eq(ep.endpoint_id, "wp_rest_tags_read",
       "_embed khong duoc doi family de bypass emergency tags")
end

do
    local write = classify_endpoint({
        uri = "/wp-json/wp/v2/posts/123", args = "", request_method = "POST",
        host = "example.test", document_root = "/home/u/public_html",
    }, {})
    eq(write.endpoint_id, nil, "REST posts write khong tron vao read budget")
    local collection = classify_endpoint({
        uri = "/wp-json/wp/v2/tags", args = "", request_method = "GET",
        host = "example.test", document_root = "/home/u/public_html",
    }, {})
    eq(collection.endpoint_id, "wp_rest_tags_read",
       "REST tags collection cung vao emergency read family")
end

do
    local pseudo = classify_endpoint({
        uri = "/vi/bai-viet.html/tel:0901494677", args = "utm=x",
        request_method = "GET", host = "example.test",
        document_root = "/home/u/public_html",
    }, { utm = "x" })
    eq(pseudo.endpoint_id, "wp_html_pathinfo",
       ".html/tel:number duoc nhan dien boi generic pathinfo")
    eq(pseudo.endpoint_shape, "unexpected_pathinfo", "html pathinfo co shape on dinh")
    eq(pseudo.test_prefix, "",
       "pseudo suffix chi proof docroot, khong tao prefix tu input attacker")
    eq(pseudo.endpoint_query_state, "present", "pseudo suffix cung co query marker")
end

do
    local pseudo = classify_endpoint({
        uri = "/bai-viet.html/SMS:+84-901-494-677", args = "",
        request_method = "GET", host = "example.test",
        document_root = "/home/u/public_html",
    }, {})
    eq(pseudo.endpoint_id, "wp_html_pathinfo", "sms van trung generic pathinfo")
    eq(pseudo.endpoint_shape, "unexpected_pathinfo", "sms khong can token rieng")
end

do
    for _, uri in ipairs({
        "/post.html/feed/", "/post.html/embed/", "/post.html/trackback/",
        "/post.html/amp/", "/post.html/tel:not-a-phone",
        "/post.html/callto:0901494677", "/post.html/ngay-mai-bot-doi-token",
        "/post.html/a/b/c",
    }) do
        local garbage = classify_endpoint({
            uri = uri, args = "", request_method = "GET",
            host = "example.test", document_root = "/home/u/public_html",
        }, {})
        eq(garbage.endpoint_id, "wp_html_pathinfo",
           "generic .html/<rac> khong phu thuoc token: " .. uri)
    end
end

do
    for _, uri in ipairs({ "/post.html", "/post.html/" }) do
        local canonical = classify_endpoint({
            uri = uri, args = "", request_method = "GET",
            host = "example.test", document_root = "/home/u/public_html",
        }, {})
        eq(canonical.endpoint_id, nil, "khong chan permalink html khong co PATH_INFO: " .. uri)
    end
end

do
    -- The classifier is based on the WordPress archive contract, never on the
    -- token used by today's bot.  All variants collapse to one bounded id.
    for _, uri in ipairs({
        "/tag/nhu-cao/tel:0934699229",
        "/tag/a/amp/sms:1/other",
        "/vi/tag/a/ngay-mai-bot-doi-token",
        "/tag/a/x/y/z",
    }) do
        local archive = classify_endpoint({
            uri = uri, args = "", request_method = "GET",
            host = "example.test", document_root = "/home/u/public_html",
        }, {})
        eq(archive.endpoint_id, "wp_tag_archive_suffix",
           "tag suffix la generic route family: " .. uri)
        eq(archive.endpoint_shape, "unexpected_archive_suffix",
           "tag suffix co mot shape on dinh: " .. uri)
        eq(archive.endpoint_route_source, "tag_archive",
           "tag suffix co source rieng: " .. uri)
    end

    for _, uri in ipairs({
        "/tag/a/", "/tag/a/page/2/", "/tag/a/feed/",
        "/tag/a/feed/rss2/", "/tag/a/embed/", "/tag/a/amp/",
        "/tag/a/amp/page/2/", "/tag/a/page/2/amp/",
    }) do
        local archive = classify_endpoint({
            uri = uri, args = "", request_method = "GET",
            host = "example.test", document_root = "/home/u/public_html",
        }, {})
        eq(archive.endpoint_id, nil,
           "tag archive hop le khong vao suspicious family: " .. uri)
    end

    local write = classify_endpoint({
        uri = "/tag/a/custom", args = "", request_method = "POST",
        host = "example.test", document_root = "/home/u/public_html",
    }, {})
    eq(write.endpoint_id, nil, "tag archive policy chi ap dung GET/HEAD")

    local nonwp = classify_endpoint({
        uri = "/tag/a/custom", args = "", request_method = "GET",
        host = "custom.test", document_root = "/srv/custom",
    }, {}, false)
    eq(nonwp.endpoint_id, nil, "tag suffix khong ap vao CMS chua proof WordPress")
    eq(nonwp.endpoint_candidate, "wp_tag_archive_suffix",
       "non-WP chi de lai candidate telemetry")
end

do
    local pseudo = classify_endpoint({
        uri = "/post.html/tel:0901494677", args = "", request_method = "GET",
        host = "custom.test", document_root = "/srv/custom",
    }, {}, false)
    eq(pseudo.endpoint_id, nil, "custom CMS khong nhan WordPress pseudo policy")
    eq(pseudo.endpoint_candidate, "wp_html_pathinfo",
       "html pathinfo candidate van de lai proof telemetry tren non-WP")
end

local ep6 = classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "", request_method = "GET",
    host = "example.test", document_root = "/home/u/public_html",
}, { url = "https://other.test/post/" })
eq(ep6.endpoint_url_relation, "cross", "cross-host URL chi duoc ghi telemetry")

local ep7 = classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "", request_method = "GET",
    host = "example.test", document_root = "/home/u/public_html",
}, { url = { "https://example.test/a", "https://example.test/b" } })
eq(ep7.endpoint_shape, "bad_url", "duplicate url khong duoc sap thanh scalar")

local ep_nonwp = classify_endpoint({
    uri = "/wp-json/oembed/1.0/embed", args = "", request_method = "GET",
    host = "custom.test", document_root = "/srv/custom",
}, { url = "https://custom.test/a" }, false)
eq(ep_nonwp.endpoint_id, nil, "site khong duoc chung minh WP khong nhan overlay")
eq(ep_nonwp.endpoint_candidate, "wp_oembed_embed",
   "candidate van co telemetry khi cong WP tu choi")

-- Generic endpoint guard: aggregate by tenant+endpoint, independent of IP.
local old_endpoint = cfg.endpoint_guard
cfg.endpoint_guard = {
    enabled = true, retry_after = 2,
    rate_status = 429, inflight_status = 503, shape_status = 400,
    windows = { short = 10, long = 60 },
    slot_bucket_seconds = 30, slot_retention_seconds = 180,
    endpoints = {
        wp_oembed_embed = {
            swarm = { mode = "shadow", scope = "server", window = 10, requests = 4,
                      networks = 3, hold = 30 },
            server_inflight = { mode = "shadow", limit = 10,
                                require_swarm = true, status = 503,
                                retry_after = 5 },
            rate = { mode = "shadow", short = 2, long = 5 },
            inflight = { mode = "shadow", limit = 2 },
            shape_mode = "shadow", cross_host_mode = "shadow",
        },
        wp_html_pathinfo = {
            rate = { mode = "off" }, inflight = { mode = "off" },
            swarm = { mode = "shadow", scope = "server", window = 10, requests = 4,
                      networks = 3, hold = 30 },
            shape_mode = "enforce", shape_status = 404,
            cross_host_mode = "off",
        },
        wp_rest_tags_read = {
            emergency = { mode = "enforce", status = 429, retry_after = 300 },
            swarm = { mode = "shadow", scope = "server", window = 10, requests = 4,
                      networks = 3, hold = 30 },
            rate = { mode = "shadow", short = 20, long = 100 },
            inflight = { mode = "shadow", limit = 4 },
            shape_mode = "off", cross_host_mode = "off",
        },
        wp_tag_archive_suffix = {
            swarm = { mode = "shadow", scope = "server", window = 10, requests = 4,
                      networks = 3, hold = 30 },
            server_inflight = { mode = "shadow", limit = 3,
                                require_swarm = true, status = 503,
                                retry_after = 5 },
            rate = { mode = "off", short = 20, long = 100 },
            inflight = { mode = "shadow", limit = 2 },
            shape_mode = "off", cross_host_mode = "off",
        },
    },
}
package.loaded["antibot.l7.endpoint_guard"] = nil
local endpoint_guard = require "antibot.l7.endpoint_guard"

local function epctx(scope, ip, shape, relation)
    return {
        endpoint_id = "wp_oembed_embed",
        endpoint_scope = scope or "tenant_a",
        endpoint_shape = shape or "ok",
        endpoint_url_relation = relation or "same",
        ip = ip or "192.0.2.1",
    }
end

clock = 1400
exits = {}
fake_ngx.status = 200
fake_ngx.header = {}
fake_ngx.var = { upstream_status = "200", upstream_response_time = "0.250" }
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_stats = Dict.new()

do
    exits = {}
    fake_ngx.status = 200
    fake_ngx.header = {}
    local malformed = {
        endpoint_id = "wp_html_pathinfo",
        endpoint_scope = "tenant_html", endpoint_shape = "unexpected_pathinfo",
    }
    local _, did_exit = endpoint_guard.before(malformed)
    eq(did_exit, true, "pseudo suffix enforce chan o early endpoint gate")
    eq(exits[#exits], 404, "pseudo suffix tra local 404, khong day vao PHP")
    eq(malformed.action, "throttled",
       "malformed route khong bi quy thanh reputation block")
    eq(fake_ngx.header["Retry-After"], nil,
       "deterministic 404 khong gui Retry-After vo nghia")
    eq(malformed.endpoint_admitted, nil,
       "pseudo suffix bi chan truoc khi lay backend slot")
end

do
    -- Four attempts from three /24s all share one bounded route-shape key.
    -- Each source contributes only 1-2 requests, so a per-IP limiter cannot
    -- see this campaign; the endpoint swarm meter must.
    clock = 1420
    fake_ngx.shared.antibot_cache = Dict.new()
    local attempts = {
        { scope = "tenant_a", ip = "192.0.2.1",      open = false },
        { scope = "tenant_b", ip = "198.51.100.2",   open = false },
        { scope = "tenant_c", ip = "203.0.113.3",    open = false },
        { scope = "tenant_d", ip = "192.0.2.99",     open = true  },
    }
    local last
    for _, item in ipairs(attempts) do
        exits = {}
        local malformed = {
            endpoint_id = "wp_html_pathinfo",
            endpoint_scope = item.scope,
            endpoint_shape = "unexpected_pathinfo",
            ip = item.ip,
        }
        local _, did_exit = endpoint_guard.before(malformed)
        eq(did_exit, true, "shape van chan moi rotating-IP attempt")
        eq(exits[#exits], 404, "swarm telemetry khong doi local 404")
        eq(malformed.endpoint_swarm_open or false, item.open,
           "swarm chi mo khi du ca hit va source-network")
        last = malformed
    end
    eq(last.endpoint_swarm_hits, 4, "swarm gom hit xuyen cac IP")
    eq(last.endpoint_swarm_networks, 3, "hai IP cung /24 chi tinh mot network")
    eq(last.endpoint_swarm_mode, "shadow",
       "shape invalid da enforce; swarm chi gan nhan chien dich")
    eq(last.endpoint_swarm_scope, "server",
       "swarm gom cung route-shape xuyen nhieu WordPress docroot")

    exits = {}
    fake_ngx.shared.antibot_cache = Dict.new()
    local ipv6_same64 = {
        endpoint_id = "wp_html_pathinfo", endpoint_scope = "tenant_v6",
        endpoint_shape = "unexpected_pathinfo", ip = "2001:db8:1:2::1",
    }
    endpoint_guard.before(ipv6_same64)
    exits = {}
    ipv6_same64.ip = "2001:db8:1:2::ffff"
    endpoint_guard.before(ipv6_same64)
    eq(ipv6_same64.endpoint_swarm_networks, 1,
       "IPv6 privacy addresses cung /64 khong nhan diversity")
    clock = 1400
end

do
    -- Prove the generic gate can be promoted independently for a bounded
    -- endpoint.  Repeating one /24 must never satisfy distributed evidence;
    -- three networks across four tenants must trip one server-wide budget.
    local spec = cfg.endpoint_guard.endpoints.wp_oembed_embed
    spec.swarm.mode = "enforce"
    spec.swarm.status = 429
    spec.swarm.retry_after = 45
    clock = 1430
    fake_ngx.shared.antibot_cache = Dict.new()

    for i = 1, 8 do
        exits = {}
        local one_net = epctx("noisy_tenant_" .. tostring(i),
            "192.0.2." .. tostring(i))
        local _, did_exit = endpoint_guard.before(one_net)
        eq(did_exit, false,
           "mot /24 on khong duoc suy thanh distributed route swarm")
    end

    fake_ngx.shared.antibot_cache = Dict.new()
    local distributed = {
        { "site_a", "192.0.2.1" },
        { "site_b", "198.51.100.2" },
        { "site_c", "203.0.113.3" },
        { "site_d", "192.0.2.99" },
    }
    for i, item in ipairs(distributed) do
        exits = {}
        fake_ngx.header = {}
        local candidate = epctx(item[1], item[2])
        local _, did_exit = endpoint_guard.before(candidate)
        eq(did_exit, i == 4,
           "swarm enforce chi chan khi du hai cong hit+network")
        if i == 4 then
            eq(exits[#exits], 429, "route swarm enforce tra local 429")
            eq(fake_ngx.header["Retry-After"], "45",
               "route swarm co retry-after rieng")
            eq(candidate.endpoint_admitted, nil,
               "route swarm chan truoc backend slot")
            ok(tostring(candidate.endpoint_cause):find("swarm", 1, true) ~= nil,
               "route swarm co causal reason rieng")
        end
    end
    spec.swarm.mode = "shadow"
    spec.swarm.status = nil
    spec.swarm.retry_after = nil
    clock = 1400
end


do
    -- A temporary shutdown must not fail open merely because capacity
    -- telemetry has lost its shared dict: no counter is needed to say OFF.
    exits = {}
    fake_ngx.status = 200
    fake_ngx.header = {}
    local saved_cache = fake_ngx.shared.antibot_cache
    fake_ngx.shared.antibot_cache = nil
    local tags = {
        endpoint_id = "wp_rest_tags_read", endpoint_scope = "tenant_tags",
        endpoint_shape = "ok",
    }
    local _, did_exit = endpoint_guard.before(tags)
    eq(did_exit, true, "emergency tags chan ca khi shared dict mat")
    eq(exits[#exits], 429, "emergency tags tra local 429")
    eq(fake_ngx.header["Retry-After"], "300", "emergency dung retry-after rieng")
    eq(tags.endpoint_cause, "emergency", "emergency co cause khong nhap voi rate")
    eq(tags.endpoint_admitted, nil, "emergency dung truoc backend slot")
    fake_ngx.shared.antibot_cache = saved_cache
end

exits = {}
fake_ngx.status = 200
fake_ngx.header = {}

local eg1 = epctx("tenant_a", "192.0.2.1")
local eg2 = epctx("tenant_a", "198.51.100.2")
local eg3 = epctx("tenant_a", "203.0.113.3")
endpoint_guard.admit(eg1)
endpoint_guard.admit(eg2)
local _, eg3_exit = endpoint_guard.admit(eg3)
eq(eg3_exit, false, "endpoint shadow khong chan")
eq(eg3.endpoint_short_count, 3, "counter gom ba IP vao cung tenant endpoint")
eq(eg3.endpoint_inflight, 3, "inflight gom ba IP, khong bi rotate-IP bypass")
eq(eg3.endpoint_would_reject, true, "limit+1 duoc ghi would")
ok(eg3.endpoint_cause:find("inflight", 1, true) ~= nil,
   "would neu ro nguyen nhan inflight")
ok(eg3.endpoint_cause:find("rate_short", 1, true) ~= nil,
   "would neu ro nguyen nhan rate")
eq(#exits, 0, "shadow khong ngx.exit")

clock = 1401
endpoint_guard.after(eg1)
eq(eg1.endpoint_duration, 1, "endpoint slot co duration")
eq(eg1.endpoint_upstream_time, 0.25, "endpoint log doc upstream time")
endpoint_guard.after(eg1)
endpoint_guard.after(eg2)
endpoint_guard.after(eg3)
eq(fake_ngx.shared.antibot_cache:get("ep:tenant_a:wp_oembed_embed:slot:46"), nil,
   "endpoint release idempotent va tra het slot")

-- Tenant isolation: a hot site cannot spend another site's budget.
local eg_other = epctx("tenant_b", "192.0.2.1")
endpoint_guard.admit(eg_other)
eq(eg_other.endpoint_short_count, 1, "endpoint budget tach theo WordPress root")
endpoint_guard.after(eg_other)

do
    -- Whole-server occupancy must aggregate the same bounded endpoint across
    -- tenants, but `require_swarm` prevents occupancy alone from becoming a
    -- reject candidate.  This is the central FP boundary of the replacement.
    local spec = cfg.endpoint_guard.endpoints.wp_oembed_embed
    spec.server_inflight.limit = 2
    spec.server_inflight.mode = "shadow"
    spec.server_inflight.require_swarm = true
    clock = 1470
    fake_ngx.shared.antibot_cache = Dict.new()
    exits = {}

    local quiet = {
        epctx("quiet_a", "192.0.2.1"),
        epctx("quiet_b", "198.51.100.2"),
        epctx("quiet_c", "203.0.113.3"),
    }
    for i = 1, #quiet do endpoint_guard.admit(quiet[i]) end
    eq(quiet[3].endpoint_inflight, 1,
       "moi tenant van co inflight rieng")
    eq(quiet[3].endpoint_server_inflight, 3,
       "server inflight gom mot endpoint xuyen ba tenant")
    eq(quiet[3].endpoint_server_inflight_over, true,
       "raw server over duoc ghi du swarm chua mo")
    eq(quiet[3].endpoint_would_reject, nil,
       "server over don le khong tao would khi require_swarm")
    for i = 1, #quiet do endpoint_guard.after(quiet[i]) end
    eq(fake_ngx.shared.antibot_cache:get(quiet[1].endpoint_server_slot_key), nil,
       "release tra het server endpoint slot")

    -- Open distributed evidence first, then keep three backend requests alive.
    -- All three tenants share the server axis while their tenant axis stays 1.
    fake_ngx.shared.antibot_cache = Dict.new()
    local evidence = {
        epctx("evidence_a", "192.0.2.1"),
        epctx("evidence_b", "198.51.100.2"),
        epctx("evidence_c", "203.0.113.3"),
        epctx("evidence_d", "192.0.2.99"),
    }
    for i = 1, #evidence do endpoint_guard.before(evidence[i]) end
    eq(evidence[4].endpoint_swarm_open, true,
       "fixture mo dung distributed swarm")

    local live = {
        epctx("live_a", "192.0.2.10"),
        epctx("live_b", "198.51.100.20"),
        epctx("live_c", "203.0.113.30"),
    }
    for i = 1, #live do
        endpoint_guard.before(live[i])
        endpoint_guard.admit(live[i])
    end
    eq(live[3].endpoint_server_inflight, 3,
       "compound gate thay ba live request toan may")
    eq(live[3].endpoint_would_reject, true,
       "server over + swarm tao shadow candidate")
    ok(tostring(live[3].endpoint_cause):find("server_inflight", 1, true) ~= nil,
       "compound candidate co cause server_inflight")
    eq(#exits, 0, "server inflight shadow khong chan")
    for i = 1, #live do endpoint_guard.after(live[i]) end

    -- If shared-dict pressure strikes between the tenant and server atomic
    -- increments, the first slot must be rolled back before failing open.
    fake_ngx.shared.antibot_cache = Dict.new()
    fake_ngx.shared.antibot_cache.fail_prefix = "epg:server:"
    local degraded = epctx("rollback", "192.0.2.1")
    local _, degraded_exit = endpoint_guard.admit(degraded)
    eq(degraded_exit, false, "server slot failure fail-open")
    eq(degraded.endpoint_server_inflight_degraded, true,
       "server slot failure co telemetry")
    eq(degraded.endpoint_admitted, nil,
       "server slot failure khong tao admitted ao")
    eq(fake_ngx.shared.antibot_cache:get(
        "ep:rollback:wp_oembed_embed:slot:" .. tostring(math.floor(clock / 30))), nil,
       "server slot failure rollback tenant slot")

    -- The late atomic gate remains authoritative.  A race that passes before()
    -- but increments slot number 3 must roll back BOTH axes before returning.
    fake_ngx.shared.antibot_cache = Dict.new()
    spec.server_inflight.mode = "enforce"
    local a = epctx("atomic_a", "192.0.2.1")
    local b = epctx("atomic_b", "198.51.100.2")
    local c = epctx("atomic_c", "203.0.113.3")
    a.endpoint_swarm_open = true
    b.endpoint_swarm_open = true
    c.endpoint_swarm_open = true
    endpoint_guard.admit(a)
    endpoint_guard.admit(b)
    exits = {}
    fake_ngx.header = {}
    local _, server_exit = endpoint_guard.admit(c)
    eq(server_exit, true, "server inflight enforce bat atomic limit+1")
    eq(exits[#exits], 503, "server capacity shed tra 503")
    eq(c.endpoint_admitted, false, "request bi shed khong giu tenant slot")
    eq(fake_ngx.shared.antibot_cache:get(a.endpoint_server_slot_key), 2,
       "late reject rollback server slot tu 3 ve 2")
    eq(fake_ngx.shared.antibot_cache:get(c.endpoint_slot_key), nil,
       "late reject rollback tenant slot")
    endpoint_guard.after(a)
    endpoint_guard.after(b)
    eq(fake_ngx.shared.antibot_cache:get(a.endpoint_server_slot_key), nil,
       "hai request con lai release server slot")

    spec.server_inflight.mode = "shadow"
    spec.server_inflight.limit = 10
end

-- Incident replay shape: every request uses another IP and releases before
-- the next one, so neither per-IP nor concurrency is required for detection;
-- the invariant host+endpoint rate budget still accumulates all of them.
clock = 1450
fake_ngx.shared.antibot_cache = Dict.new()
local rotated_last
for i = 1, 25 do
    local rotated = epctx("tenant_rotate", "198.51.100." .. tostring(i))
    endpoint_guard.admit(rotated)
    endpoint_guard.after(rotated)
    rotated_last = rotated
end
eq(rotated_last.endpoint_short_count, 25,
   "rotate-IP replay van cong theo host+endpoint")
eq(rotated_last.endpoint_inflight, 1,
   "replay tuan tu khong can gia concurrency")
eq(rotated_last.endpoint_would_reject, true,
   "rotate-IP replay van vuot endpoint rate budget")
ok(rotated_last.endpoint_cause:find("rate_short", 1, true) ~= nil,
   "rotate-IP replay chi ro rate cause")

-- Shape and cross-host are separate shadow candidates, never IP punishment.
local eg_shape = epctx("tenant_shape", nil, "bad_url", "invalid")
endpoint_guard.admit(eg_shape)
eq(eg_shape.endpoint_would_reject, true, "bad shape co shadow candidate")
ok(eg_shape.endpoint_cause:find("shape_bad_url", 1, true) ~= nil,
   "shape cause duoc tach rieng")
eq(eg_shape.action, nil, "shadow shape khong doi bot verdict")
endpoint_guard.after(eg_shape)

local eg_cross = epctx("tenant_cross", nil, "ok", "cross")
endpoint_guard.admit(eg_cross)
eq(eg_cross.endpoint_would_reject, true, "cross-host co shadow candidate")
eq(eg_cross.endpoint_cause, "cross_host", "cross-host co cause rieng")
endpoint_guard.after(eg_cross)

-- Promote only rate: the early gate rejects before WAF/backend, while the
-- independent inflight/shape/cross rules remain shadow.
cfg.endpoint_guard.endpoints.wp_oembed_embed.rate.mode = "enforce"
clock = 1500
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
local er1, er2 = epctx("tenant_enforce"), epctx("tenant_enforce")
endpoint_guard.admit(er1)
endpoint_guard.admit(er2)
local er3 = epctx("tenant_enforce")
local _, er3_exit = endpoint_guard.before(er3)
eq(er3_exit, true, "rate enforce chan request tiep theo o early gate")
eq(exits[#exits], 429, "rate enforce tra 429")
eq(er3.action, "throttled", "capacity reject khong gan bot block")
ok(er3.action_reason:find("endpoint_guard:wp_oembed_embed", 1, true) ~= nil,
   "endpoint reject co reason on dinh")
endpoint_guard.after(er1)
endpoint_guard.after(er2)

-- Production rollout promotes ONLY oEmbed concurrency. Rate remains shadow:
-- a short legitimate discovery burst may be fast, while holding more than the
-- bounded number of PHP workers is direct capacity pressure. The early gate
-- must reject before backend work and must use the inflight status (503).
cfg.endpoint_guard.endpoints.wp_oembed_embed.rate.mode = "shadow"
cfg.endpoint_guard.endpoints.wp_oembed_embed.rate.short = 100
cfg.endpoint_guard.endpoints.wp_oembed_embed.rate.long = 100
cfg.endpoint_guard.endpoints.wp_oembed_embed.inflight.mode = "enforce"
clock = 1510
exits = {}
fake_ngx.status = 200
fake_ngx.header = {}
fake_ngx.shared.antibot_cache = Dict.new()
local ei1, ei2 = epctx("tenant_inflight"), epctx("tenant_inflight")
endpoint_guard.admit(ei1)
endpoint_guard.admit(ei2)
local ei3 = epctx("tenant_inflight")
local _, ei3_exit = endpoint_guard.before(ei3)
eq(ei3_exit, true, "inflight enforce chan som request limit+1")
eq(exits[#exits], 503, "inflight enforce tra 503, khong dung rate 429")
eq(ei3.action, "throttled", "inflight capacity khong gan bot verdict")
ok(tostring(ei3.endpoint_cause):find("inflight", 1, true) ~= nil,
   "inflight reject co cause rieng")
ok(not tostring(ei3.endpoint_cause):find("rate_", 1, true),
   "rate shadow duoi nguong khong bi gan lam cause")
endpoint_guard.after(ei1)
endpoint_guard.after(ei2)

-- A WAF/local block never called admit(), so log phase cannot decrement a
-- slot belonging to somebody else.
local never_admitted = epctx("tenant_enforce")
endpoint_guard.after(never_admitted)
eq(never_admitted.endpoint_released, nil,
   "request khong admit khong tao release ao")

cfg.endpoint_guard = old_endpoint
package.loaded["antibot.waf.endpoint_policy"] = nil
package.loaded["antibot.waf.wordpress.paths"] = saved_wp_paths
end
run_endpoint_tests()

-- Proven-operator concurrency: one principal shares one slot pool across all
-- IPs, hosts and URIs.  Unlike endpoint_guard, no endpoint_id is required.
-- Keep this in its own function scope: the regression chunk is deliberately
-- broad and LuaJIT caps one function at 200 local variables.
cfg.__run_operator_concurrency_tests = function()
local old_operator_concurrency = cfg.automation_concurrency
cfg.automation_concurrency = {
    enabled = true, mode = "shadow", limit = 2,
    status = 429, retry_after = 10,
    slot_bucket_seconds = 30, slot_retention_seconds = 180,
    principals = { gptbot = { mode = "shadow", limit = 2 } },
    tiers = {
        cloud_automation = {
            mode = "enforce", limit = 2, source_limit = 2,
        },
        verified_aggressive = { mode = "enforce", limit = 2 },
    },
}
package.loaded["antibot.l7.operator_concurrency"] = nil
local operator_concurrency = require "antibot.l7.operator_concurrency"

local function opctx(principal, host, ip, uri, class)
    return {
        automation_observed = true,
        automation_tier = "operator",
        automation_principal = principal or "gptbot",
        operator_network_verified = true,
        req = { host = host or "a.test", uri = uri or "/" },
        req_class = class or "navigation",
        ip = ip or "192.0.2.1",
        action = "allow",
    }
end

clock = 1600
exits = {}
fake_ngx.status = 200
fake_ngx.header = {}
fake_ngx.var = { upstream_status = "200", upstream_response_time = "15.400" }
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_stats = Dict.new()

local oc1 = opctx("GPTBot", "one.test", "192.0.2.1", "/")
local oc2 = opctx("gptbot", "two.test", "198.51.100.2", "/tag/a")
local oc3 = opctx("gptbot", "three.test", "203.0.113.3",
    "/post.html/feed", "resource")
operator_concurrency.admit(oc1)
operator_concurrency.admit(oc2)
local _, oc3_exit = operator_concurrency.admit(oc3)
eq(oc3_exit, false, "operator concurrency shadow khong chan")
eq(oc3.automation_concurrency_inflight, 3,
   "principal gom moi IP host URI vao mot slot pool")
eq(oc3.automation_concurrency_would_reject, true,
   "request limit+1 ghi shadow candidate")
eq(oc3.automation_concurrency_mode, "shadow",
   "principal override van shadow khi rollout")
eq(#exits, 0, "operator concurrency shadow khong ngx.exit")

clock = 1615
operator_concurrency.after(oc1)
eq(oc1.automation_concurrency_duration, 15,
   "slot duration do tu late admit toi log phase")
eq(oc1.automation_concurrency_upstream_time, 15.4,
   "telemetry tach upstream time khoi slot lifetime")
eq(oc1.automation_concurrency_remaining, 2,
   "release mot principal slot de lai hai")
operator_concurrency.after(oc1)
eq(oc1.automation_concurrency_remaining, 2,
   "operator release idempotent")
operator_concurrency.after(oc2)
operator_concurrency.after(oc3)

-- Another principal has an independent whole-server pool: GPTBot cannot make
-- Claude hit its limit, unlike the removed aggregate server-axis.
local claude = opctx("claudebot", "one.test", "192.0.2.9", "/")
operator_concurrency.admit(claude)
eq(claude.automation_concurrency_inflight, 1,
   "principal khac co slot pool doc lap")
operator_concurrency.after(claude)

-- A UA/claim alone cannot allocate a principal key or poison the official
-- operator's capacity budget.
local spoof = opctx("gptbot", "evil.test", "198.51.100.99", "/")
spoof.automation_tier = "unknown"
spoof.operator_network_verified = false
operator_concurrency.admit(spoof)
eq(spoof.automation_concurrency_admitted, nil,
   "claim-only GPTBot khong duoc vao operator slot")

-- HAI co phai duoc kiem RIENG. Ca `spoof` o tren dat ca hai cung luc, nen bo
-- mot trong hai phep kiem trong `eligible()` van bi co con lai chan — dot bien
-- "bo kiem operator_network_verified" SONG SOT voi chi ca do. Moi co can mot ca.
local spoof_tier = opctx("gptbot", "evil.test", "198.51.100.98", "/")
spoof_tier.automation_tier = "unknown"          -- chi tier sai
operator_concurrency.admit(spoof_tier)
eq(spoof_tier.automation_concurrency_admitted, nil,
   "tier khac operator bi loai du operator_network_verified=true")
eq(spoof_tier.automation_concurrency_principal, nil,
   "va khong cap phat khoa principal nao")

local spoof_net = opctx("gptbot", "evil.test", "198.51.100.97", "/")
spoof_net.operator_network_verified = false     -- chi mang nguon sai
operator_concurrency.admit(spoof_net)
eq(spoof_net.automation_concurrency_admitted, nil,
   "mang nguon khong xac thuc bi loai du tier=operator")
eq(spoof_net.automation_concurrency_principal, nil,
   "va khong cap phat khoa principal nao")

-- Cloud fallback is evidence of automation, not vendor identity. It therefore
-- uses TWO axes: principal catches IP rotation; source catches one cloud IP
-- rotating copied GrokBot/DeepSeekBot identities as seen in production.
local function cloudctx(principal, ip)
    local c = opctx(principal, "cloud.test", ip, "/")
    c.automation_tier = "cloud_automation"
    c.operator_network_verified = false
    c.automation_proof = "contact_cloud_ptr"
    c.automation_cloud_claimed = true
    return c
end

clock = 1650
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
local cg = cloudctx("grokbot", "198.51.100.20")
local cd1 = cloudctx("deepseekbot", "198.51.100.20")
local cd2 = cloudctx("deepseekbot", "198.51.100.20")
operator_concurrency.admit(cg)
operator_concurrency.admit(cd1)
local _, cloud_source_exit = operator_concurrency.admit(cd2)
eq(cloud_source_exit, true,
   "mot cloud IP doi Grok/DeepSeek van bi source concurrency")
eq(cd2.automation_concurrency_axis, "source",
   "telemetry chi dung truc source da vo")
eq(cd2.automation_concurrency_inflight, 2,
   "principal DeepSeek rieng van chua vuot tran")
eq(cd2.automation_concurrency_source_inflight, 3,
   "nhung source chung da la request thu ba")
eq(cd2.automation_concurrency_source_remaining, 2,
   "reject rollback source slot cua chinh request")
operator_concurrency.after(cg)
operator_concurrency.after(cd1)

clock = 1660
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
local gp1 = cloudctx("grokbot", "198.51.100.31")
local gp2 = cloudctx("grokbot", "198.51.100.32")
local gp3 = cloudctx("grokbot", "198.51.100.33")
operator_concurrency.admit(gp1)
operator_concurrency.admit(gp2)
local _, cloud_principal_exit = operator_concurrency.admit(gp3)
eq(cloud_principal_exit, true,
   "cloud principal xoay IP van bi pool toan may")
eq(gp3.automation_concurrency_axis, "principal",
   "principal axis bat IP rotation")
operator_concurrency.after(gp1)
operator_concurrency.after(gp2)

local cloud_claim_only = cloudctx("grokbot", "198.51.100.40")
cloud_claim_only.automation_proof = "claim_only"
operator_concurrency.admit(cloud_claim_only)
eq(cloud_claim_only.automation_concurrency_admitted, nil,
   "UA cloud tu khai khong co PTR proof khong cap slot")

-- Verified crawler concurrency is generic by the existing policy class, not a
-- vendor allow/deny list.  Both S3/S4 proof and class=aggressive are required;
-- a copied UA or a polite crawler cannot enter this pool.
local function verified_aggressive_ctx(principal, ip)
    local c = opctx(principal, "crawler.test", ip, "/crawl")
    c.automation_tier = "verified"
    c.operator_network_verified = false
    c.good_bot_verified = true
    c.good_bot_class = "aggressive"
    return c
end

clock = 1670
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
local va1 = verified_aggressive_ctx("amazonbot", "192.0.2.41")
local va2 = verified_aggressive_ctx("amazonbot", "192.0.2.42")
local va3 = verified_aggressive_ctx("amazonbot", "192.0.2.43")
operator_concurrency.admit(va1)
operator_concurrency.admit(va2)
local _, va3_exit = operator_concurrency.admit(va3)
eq(va3_exit, true,
   "verified aggressive crawler bi chan o request dong thoi thu ba")
eq(va3.automation_concurrency_tier, "verified_aggressive",
   "telemetry noi ro generic verified-aggressive policy")
eq(va3.automation_concurrency_axis, "principal",
   "verified aggressive pool gom IP va domain theo principal")
operator_concurrency.after(va1)
operator_concurrency.after(va2)

local polite = verified_aggressive_ctx("googlebot", "192.0.2.44")
polite.good_bot_class = "polite"
operator_concurrency.admit(polite)
eq(polite.automation_concurrency_admitted, nil,
   "verified polite crawler khong bi aggressive concurrency")

local forged_verified = verified_aggressive_ctx("amazonbot", "192.0.2.45")
forged_verified.good_bot_verified = false
operator_concurrency.admit(forged_verified)
eq(forged_verified.automation_concurrency_admitted, nil,
   "class aggressive khong thay the bang chung good-bot verified")

-- Enforce is per-principal.  Exactly N requests live; N+1 is atomically rolled
-- back and receives a local 429 without changing reputation/ban state.
cfg.automation_concurrency.principals.gptbot.mode = "enforce"
clock = 1700
exits = {}
fake_ngx.status = 200
fake_ngx.header = {}
fake_ngx.shared.antibot_cache = Dict.new()
local oe1, oe2 = opctx("gptbot"), opctx("gptbot", "b.test", "192.0.2.2")
operator_concurrency.admit(oe1)
operator_concurrency.admit(oe2)
local oe3 = opctx("gptbot", "c.test", "192.0.2.3")
local _, oe3_exit = operator_concurrency.admit(oe3)
eq(oe3_exit, true, "operator enforce chan request limit+1")
eq(exits[#exits], 429, "operator concurrency tra 429")
eq(oe3.action, "throttled", "capacity reject khong gan bot verdict")
eq(oe3.automation_concurrency_rejected, true,
   "actual concurrency reject co telemetry")
eq(oe3.automation_concurrency_remaining, 2,
   "request bi reject rollback dung slot cua chinh no")
operator_concurrency.after(oe3)
eq(oe3.automation_concurrency_remaining, 2,
   "log phase khong decrement lan hai sau rollback")
operator_concurrency.after(oe1)
operator_concurrency.after(oe2)

-- Shared-dict exhaustion is fail-open and observable; a metering fault must
-- not become a crawler outage.
cfg.automation_concurrency.principals.gptbot.mode = "shadow"
clock = 1800
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.full = true
local degraded_op = opctx("gptbot")
local _, degraded_exit = operator_concurrency.admit(degraded_op)
eq(degraded_exit, false, "operator dict failure fail-open")
eq(degraded_op.automation_concurrency_degraded, true,
   "operator dict failure visible")

-- A successful INCR with a failed EXPIRE is also degraded.  The live count is
-- still useful for shadow telemetry, but it must not become an enforce denial
-- because stale slots could otherwise survive after their requests disappear.
cfg.automation_concurrency.principals.gptbot.mode = "enforce"
clock = 1810
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.expire = function()
    return nil, "expire failed"
end
local ttl_bad_1 = opctx("gptbot")
local ttl_bad_2 = opctx("gptbot", "b.test", "192.0.2.2")
local ttl_bad_3 = opctx("gptbot", "c.test", "192.0.2.3")
operator_concurrency.admit(ttl_bad_1)
operator_concurrency.admit(ttl_bad_2)
local _, ttl_bad_exit = operator_concurrency.admit(ttl_bad_3)
eq(ttl_bad_3.automation_concurrency_would_reject, true,
   "TTL failure van ghi duoc would-reject")
eq(ttl_bad_3.automation_concurrency_degraded, true,
   "TTL failure danh dau meter degraded")
eq(ttl_bad_exit, false,
   "TTL failure fail-open du mode enforce")
eq(#exits, 0, "TTL failure khong ngx.exit")
operator_concurrency.after(ttl_bad_1)
operator_concurrency.after(ttl_bad_2)
operator_concurrency.after(ttl_bad_3)

-- Slot RO: request giu slot lau hon `slot_retention_seconds` roi moi tra.
-- Day la duong hong duy nhat cua moi co che concurrency, va no PHAI tu lanh:
-- `total_inflight()` chi cong `span` bucket gan nhat, nen mot slot qua cu roi
-- khoi pham vi do. `autcexp=true` la cach duy nhat nhan ra viec do trong log —
-- khong co cot nay thi mot slot ro trong giong het mot crawler dang keo manh.
cfg.automation_concurrency.principals.gptbot.mode = "shadow"
exits = {}
fake_ngx.shared.antibot_cache = Dict.new()
clock = 3000
local leak = opctx("gptbot")
operator_concurrency.admit(leak)
eq(leak.automation_concurrency_inflight, 1, "slot duoc cap")
-- Tra slot SAU retention (180s) + mot bucket: slot cu da roi khoi cua so dem.
clock = 3000 + 180 + 30 + 1
operator_concurrency.after(leak)
eq(leak.automation_concurrency_slot_expired, true,
   "giu slot qua retention thi danh dau autcexp=true")
ok(leak.automation_concurrency_duration >= 180,
   "autcdur ghi dung thoi gian giu slot that")

-- Va slot ro KHONG lam nghen principal vinh vien: request moi sau do thay
-- dem sach, vi slot cu da roi khoi `span` bucket.
clock = 3000 + 180 + 30 + 2
local after_leak = opctx("gptbot", "d.test", "192.0.2.9")
operator_concurrency.admit(after_leak)
eq(after_leak.automation_concurrency_inflight, 1,
   "slot ro tu lanh — principal khong bi nghen vinh vien")
operator_concurrency.after(after_leak)

cfg.automation_concurrency = old_operator_concurrency
package.loaded["antibot.l7.operator_concurrency"] = nil
end
cfg.__run_operator_concurrency_tests()
cfg.__run_operator_concurrency_tests = nil

-- Generic contradictory-principal churn: no vendor list, only the count of
-- distinct canonical automation identities emitted by the existing registry.
cfg.__run_generic_guard_tests = function()
local old_principal_churn = cfg.principal_churn
cfg.principal_churn = {
    enabled = true, mode = "shadow", window = 30,
    ip_threshold = 3, ja3_threshold = 2, hold_seconds = 60,
    status = 429, retry_after = 10,
}
package.loaded["antibot.l7.principal_churn"] = nil
local principal_churn = require "antibot.l7.principal_churn"
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var = { remote_addr = "198.51.100.90" }
clock = 2000

local function pcctx(name, ip, ja3)
    return {
        ip = ip or "198.51.100.90", ja3 = ja3,
        admission_group = "dynamic",
        automation_meter_claimed = true,
        automation_principal = name, automation_tier = "unknown",
        behind_proxy = false,
    }
end

local pc1, pc2, pc3 = pcctx("vendor-a"), pcctx("vendor-b"), pcctx("vendor-c")
principal_churn.before(pc1)
principal_churn.before(pc1)
eq(pc1.principal_churn_ip_count, 1,
   "lap cung principal khong lam tang churn")
principal_churn.before(pc2)
local _, pc_exit = principal_churn.before(pc3)
eq(pc_exit, false, "principal churn shadow khong chan")
eq(pc3.principal_churn_ip_count, 3,
   "principal churn dem canonical principal rieng biet")
eq(pc3.principal_churn_open, true,
   "ba principal mau thuan mo quarantine tam")
eq(pc3.principal_churn_would_reject, true,
   "shadow ghi dung would-reject")

-- JA3 is available only at the late hook. The repeated IP observation remains
-- idempotent while IP+JA3 independently reaches its stronger threshold.
fake_ngx.shared.antibot_cache = Dict.new()
local pj1 = pcctx("one", "198.51.100.91", "ja3-x")
local pj2 = pcctx("two", "198.51.100.91", "ja3-x")
principal_churn.before(pj1); principal_churn.admit(pj1)
principal_churn.before(pj2); principal_churn.admit(pj2)
eq(pj2.principal_churn_ip_count, 2,
   "late JA3 observe khong dem doi principal tren IP")
eq(pj2.principal_churn_ja3_count, 2,
   "IP+JA3 gom principal tren cung TLS shape")
eq(pj2.principal_churn_axis, "ip_ja3",
   "JA3 threshold la bang chung churn manh hon")

fake_ngx.shared.antibot_cache = Dict.new()
local pc_refine = pcctx("early-name", "198.51.100.94", "ja3-y")
principal_churn.before(pc_refine)
pc_refine.automation_principal = "refined-name"
principal_churn.admit(pc_refine)
eq(pc_refine.principal_churn_ip_count, 1,
   "one request cannot create IP churn when detection refines its name")
eq(pc_refine.principal_churn_ja3_count, 1,
   "refined principal is still observed on late JA3 axis")

fake_ngx.shared.antibot_cache = Dict.new()
local pc_proxy = pcctx("one", "203.0.113.10")
pc_proxy.behind_proxy = true
principal_churn.before(pc_proxy)
eq(pc_proxy.principal_churn_proxy_skip, true,
   "reverse-proxy edge khong bi coi la mot client churn")
eq(pc_proxy.principal_churn_ip_count, nil,
   "proxy skip khong cap phat churn counter")

fake_ngx.shared.antibot_cache = Dict.new()
cfg.principal_churn.mode = "enforce"
cfg.principal_churn.ip_threshold = 2
local pe1 = pcctx("one", "198.51.100.92")
local pe2 = pcctx("two", "198.51.100.92")
principal_churn.before(pe1)
local _, pe_exit = principal_churn.before(pe2)
eq(pe_exit, true, "principal churn enforce tra local throttle")
eq(exits[#exits], 429, "principal churn dung 429 capacity response")
eq(pe2.action_reason, "principal_churn:ip",
   "principal churn co causal reason rieng")
eq(pe2.automation_tier, "unknown",
   "capacity quarantine khong sua tier/reputation")
local pe_static = pcctx("three", "198.51.100.92")
pe_static.admission_group = "resource"
local _, pe_static_exit = principal_churn.before(pe_static)
eq(pe_static_exit, false,
   "principal churn does not shed a real static hit")
eq(pe_static.principal_churn_would_reject, true,
   "static claim still feeds churn telemetry")

fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.expire = function()
    return nil, "expire failed"
end
local pd1 = pcctx("one", "198.51.100.93")
local pd2 = pcctx("two", "198.51.100.93")
principal_churn.before(pd1)
local _, pd_exit = principal_churn.before(pd2)
eq(pd_exit, false, "principal churn TTL failure fails open")
eq(pd2.principal_churn_degraded, true,
   "principal churn TTL failure is observable")
cfg.principal_churn = old_principal_churn

-- Generic dynamic-backend guard.  The fixture deliberately contains no CMS,
-- endpoint or attack-token name.
local old_dynamic_guard = cfg.dynamic_guard
cfg.dynamic_guard = {
    enabled = true, mode = "shadow", status = 429, retry_after = 2,
    slot_bucket_seconds = 10, slot_retention_seconds = 60,
    tenant_client = {
        mode = "shadow", limit = 2,
        first_party_limit = 4, first_party_richness = 0.5,
    },
    server_client = { mode = "shadow", limit = 4 },
    path_spray = {
        mode = "shadow", window = 10, shards = 16,
        min_hits = 3, min_paths = 3, min_costly = 1,
        costly_seconds = 2,
    },
    uri_integrity = { mode = "shadow", status = 400 },
    pressure = {
        mode = "shadow", policy = "cohort",
        window = 10, min_samples = 2,
        work_seconds = 4, slow_seconds = 2,
        hold_seconds = 5, probe_timeout = 3,
        recovery_seconds = 2, eval_interval = 1, status = 503,
        cohort_min_samples = 2, cohort_work_seconds = 4,
        cohort_min_share = 0.5,
        first_party_richness = 0.5, first_party_reserve = 2,
    },
    aborted_pressure = {
        enabled = true, window = 10, slow_seconds = 2,
    },
    server_pressure = {
        mode = "off", policy = "cohort",
        window = 10, min_samples = 2,
        work_seconds = 4, slow_seconds = 2,
        hold_seconds = 5, eval_interval = 1, status = 503,
        cohort_min_samples = 2, cohort_work_seconds = 4,
        cohort_min_share = 0.5, first_party_richness = 0.5,
    },
}
package.loaded["antibot.l7.dynamic_guard"] = nil
local dynamic_guard = require "antibot.l7.dynamic_guard"

local function dgctx(ip, uri)
    return {
        ip = ip or "198.51.100.100",
        req_class = "unknown", admission_group = "dynamic",
        req = { uri = uri or "/dynamic" },
    }
end

fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var = {
    document_root = "/home/a/public_html", server_name = "a.test",
    remote_addr = "198.51.100.100", uri = "/dynamic",
    upstream_status = nil, upstream_response_time = nil,
}
fake_ngx.status = 200
clock = 3000
local dg1, dg2, dg3 = dgctx(), dgctx(), dgctx()
dynamic_guard.before(dg1); dynamic_guard.admit(dg1)
dynamic_guard.before(dg2); dynamic_guard.admit(dg2)
dynamic_guard.before(dg3); local _, dg3_exit = dynamic_guard.admit(dg3)
eq(dg3_exit, false, "generic concurrency shadow khong chan")
eq(dg3.dynamic_tenant_inflight, 3,
   "docroot+IP gom live dynamic work")
eq(dg3.dynamic_guard_would_reject, true,
   "request limit+1 thanh shadow candidate")
ok(tostring(dg3.dynamic_guard_cause):find(
    "tenant_concurrency", 1, true) ~= nil,
   "tenant concurrency co cause rieng")

-- A new docroot gets a fresh tenant bucket but shares the whole-server IP pool.
fake_ngx.var.document_root = "/home/b/public_html"
fake_ngx.var.server_name = "b.test"
local dg4 = dgctx("198.51.100.100", "/other")
dynamic_guard.before(dg4); dynamic_guard.admit(dg4)
eq(dg4.dynamic_tenant_inflight, 1,
   "tenant concurrency tach theo docroot")
eq(dg4.dynamic_server_inflight, 4,
   "server source pool gom xuyen docroot")
local dg5 = dgctx("198.51.100.100", "/fifth")
dynamic_guard.before(dg5); dynamic_guard.admit(dg5)
eq(dg5.dynamic_server_inflight, 5,
   "server axis thay domain sharding")
ok(tostring(dg5.dynamic_guard_cause):find(
    "server_concurrency", 1, true) ~= nil,
   "server concurrency co cause rieng")
for _, item in ipairs({ dg1, dg2, dg3, dg4, dg5 }) do
    dynamic_guard.after(item); dynamic_guard.after(item)
end
eq(dg5.dynamic_server_remaining, 0,
   "generic slots release idempotent va het ve zero")

fake_ngx.shared.antibot_cache = Dict.new()
local dg_static = dgctx("198.51.100.101", "/a.css")
dg_static.admission_group = "resource"
dynamic_guard.admit(dg_static)
eq(dg_static.dynamic_guard_admitted, nil,
   "static hit khong nhan generic dynamic slot")
fake_ngx.is_subrequest = true
local dg_sub = dgctx("198.51.100.101", "/internal")
dynamic_guard.admit(dg_sub)
eq(dg_sub.dynamic_guard_admitted, nil,
   "subrequest khong bi dem lap")
fake_ngx.is_subrequest = false

-- Distinct paths are represented by a fixed number of hash shards. A prior
-- slow completion supplies cost evidence without retaining a raw URI.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/spray/public_html"
fake_ngx.var.server_name = "spray.test"
clock = 3100
local paths, sprays = { "/alpha", "/beta", "/gamma" }, {}
for i, path in ipairs(paths) do
    fake_ngx.var.uri = path
    local item = dgctx("198.51.100.102", path)
    sprays[i] = item
    dynamic_guard.before(item); dynamic_guard.admit(item)
    if i == 1 then
        fake_ngx.var.upstream_status = "404"
        fake_ngx.var.upstream_response_time = "3.000"
        dynamic_guard.after(item)
    end
end
eq(sprays[3].dynamic_path_hits, 3,
   "path spray dem dynamic hits theo source/docroot")
eq(sprays[3].dynamic_path_distinct, 3,
   "path spray nhan ba path shard rieng")
eq(sprays[3].dynamic_path_costly, 1,
   "slow completion cu tro thanh cost evidence")
eq(sprays[3].dynamic_path_candidate, true,
   "hit+diversity+cost tao generic spray candidate")
for i = 2, #sprays do
    fake_ngx.var.upstream_status = nil
    fake_ngx.var.upstream_response_time = nil
    dynamic_guard.after(sprays[i])
end

-- URI integrity is a protocol shape, not an endpoint pattern.  Ordinary URL-
-- like slugs remain valid; only a second absolute target after a serialized
-- list separator is a candidate, including one level of double encoding.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/uri/public_html"
fake_ngx.var.server_name = "uri.test"
fake_ngx.var.uri = "/article/https-example"
fake_ngx.var.request_uri = "/article/https-example"
local du_ok = dgctx("198.51.100.103", "/article/https-example")
dynamic_guard.admit(du_ok)
eq(du_ok.dynamic_uri_shape, "ok",
   "URL-like slug is not a second absolute target")
dynamic_guard.after(du_ok)
fake_ngx.var.uri = "/image.jpg 1000w, https://cdn.test/image.jpg"
fake_ngx.var.request_uri =
    "/image.jpg%25201000w%252C%2520https%253A%252F%252Fcdn.test/image.jpg"
local du_bad = dgctx("198.51.100.103", fake_ngx.var.uri)
local _, du_bad_exit = dynamic_guard.admit(du_bad)
eq(du_bad_exit, false, "URI integrity shadow does not reject")
eq(du_bad.dynamic_uri_shape, "second_absolute_target",
   "double-encoded second absolute target is normalized generically")
ok(tostring(du_bad.dynamic_guard_cause):find(
    "uri_integrity", 1, true) ~= nil,
   "URI integrity candidate has stable cause")
dynamic_guard.after(du_bad)
cfg.dynamic_guard.uri_integrity.mode = "enforce"
local du_enforce = dgctx("198.51.100.104", fake_ngx.var.uri)
local _, du_enforce_exit = dynamic_guard.admit(du_enforce)
eq(du_enforce_exit, true, "URI integrity can be promoted independently")
eq(exits[#exits], 400, "malformed request-target returns 400")
eq(du_enforce.action_reason, "dynamic_guard:uri_integrity",
   "URI integrity reject does not mention a CMS or token")
cfg.dynamic_guard.uri_integrity.mode = "shadow"
fake_ngx.var.request_uri = nil

-- Backend pressure is completed upstream-seconds per docroot. The completion
-- that opens it must itself be slow, preventing stale rolling-window residue.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/pressure/public_html"
fake_ngx.var.server_name = "pressure.test"
fake_ngx.var.uri = "/one"
clock = 3200
local dp1 = dgctx("198.51.100.110", "/one")
dynamic_guard.before(dp1); dynamic_guard.admit(dp1)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
dynamic_guard.after(dp1)
dynamic_guard.after(dp1)
eq(fake_ngx.shared.antibot_cache:get(
    "dg:pressure:" .. dp1.dynamic_guard_scope .. ":b:3200:n"), 1,
   "log hook lap khong hoc outcome hai lan")
clock = 3201.1
fake_ngx.var.uri = "/two"
local dp2 = dgctx("198.51.100.111", "/two")
dynamic_guard.before(dp2); dynamic_guard.admit(dp2)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
dynamic_guard.after(dp2)
eq(dp2.dynamic_pressure_candidate, true,
   "upstream work alone creates pressure candidate")
eq(dp2.dynamic_pressure_open, true,
   "pressure opens per docroot after fresh slow evidence")
ok(dp2.dynamic_pressure_work >= 5,
   "pressure sums backend seconds, not only request count")
clock = 3202
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil

-- Aggregate pressure is not a verdict on every request to the docroot.  A
-- different request/client shape remains normal even without Cookie state.
fake_ngx.var.uri = "/different-name.json"
local dp_normal = dgctx("198.51.100.112", "/different-name.json")
local _, dp_normal_early = dynamic_guard.before(dp_normal)
eq(dp_normal_early, false, "pressure shadow never rejects in early hook")
eq(dp_normal.dynamic_pressure_would_reject, true,
   "aggregate open state remains observable")
local _, dp_normal_exit = dynamic_guard.admit(dp_normal)
eq(dp_normal_exit, false,
   "unrelated stateless request survives docroot pressure")
eq(dp_normal.dynamic_pressure_disposition, "keep_normal",
   "unrelated request is explicitly kept normal")
eq(dp_normal.dynamic_pressure_cohort_match, false,
   "unrelated cohort did not create measured work")
dynamic_guard.after(dp_normal)

-- Cohort enforcement is deliberately late.  Same-shape contributors are
-- shed; explicit policy and a bounded first-party reserve keep users moving.
cfg.dynamic_guard.pressure.mode = "enforce"
clock = 3202.1
fake_ngx.var.uri = "/six"
local dp_untrusted = dgctx("198.51.100.116", "/six")
local _, dp_untrusted_early = dynamic_guard.before(dp_untrusted)
eq(dp_untrusted_early, false,
   "open pressure never blanket-rejects in early hook")
local _, dp_untrusted_exit = dynamic_guard.admit(dp_untrusted)
eq(dp_untrusted_exit, true, "matching incident cohort is shed late")
eq(dp_untrusted.dynamic_pressure_disposition, "shed_incident",
   "cohort pressure disposition is explicit")
eq(dp_untrusted.dynamic_pressure_cohort_match, true,
   "matching request inherits measured cohort work")
eq(dp_untrusted.dynamic_pressure_selective_rejected, true,
   "actual selective pressure reject is observable")

fake_ngx.var.uri = "/crawler"
local dp_bot = dgctx("198.51.100.117", "/crawler")
dp_bot.good_bot_verified = true
dynamic_guard.before(dp_bot)
local _, dp_bot_exit = dynamic_guard.admit(dp_bot)
eq(dp_bot_exit, false,
   "unrelated verified crawler is not blamed for shape incident")
eq(dp_bot.dynamic_pressure_disposition, "keep_normal",
   "automation must contribute work before pressure can shed it")
dynamic_guard.after(dp_bot)

fake_ngx.var.uri = "/ten"
local dp_whitelist = dgctx("198.51.100.118", "/ten")
dp_whitelist.whitelisted = true
dynamic_guard.before(dp_whitelist)
local _, dp_whitelist_exit = dynamic_guard.admit(dp_whitelist)
eq(dp_whitelist_exit, false, "explicit callback policy survives pressure")
eq(dp_whitelist.dynamic_pressure_disposition, "keep_whitelist",
   "whitelist bypass is visible")
dynamic_guard.after(dp_whitelist)

local dp_h1 = dgctx("198.51.100.119", "/abc")
local dp_h2 = dgctx("198.51.100.120", "/def")
local dp_h3 = dgctx("198.51.100.121", "/ghi")
dp_h1.verified, dp_h2.verified, dp_h3.verified = true, true, true
for i, item in ipairs({ dp_h1, dp_h2, dp_h3 }) do
    fake_ngx.var.uri = ({ "/abc", "/def", "/ghi" })[i]
    dynamic_guard.before(item)
    local _, exited = dynamic_guard.admit(item)
    item.test_exited = exited
end
eq(dp_h1.test_exited, false, "verified human gets first reserve slot")
eq(dp_h2.test_exited, false, "verified human gets second reserve slot")
eq(dp_h3.test_exited, true, "verified human above bounded reserve is shed")
eq(dp_h3.dynamic_pressure_disposition, "shed_reserve",
   "reserve exhaustion is distinct from untrusted traffic")
eq(dp_h3.dynamic_pressure_reserve_inflight, 3,
   "reserve measures live eligible requests")
dynamic_guard.after(dp_h1); dynamic_guard.after(dp_h2)

fake_ngx.var.uri = "/jkl"
local dp_state = dgctx("198.51.100.122", "/jkl")
dp_state.session_cookie_known = true
dp_state.session_richness_own = 0.7
dynamic_guard.before(dp_state)
local _, dp_state_exit = dynamic_guard.admit(dp_state)
eq(dp_state_exit, false, "registry-known rich first-party state gets reserve")
eq(dp_state.dynamic_pressure_disposition, "keep_first_party",
   "first-party keep is separately observable")
dynamic_guard.after(dp_state)

fake_ngx.var.uri = "/mno"
local dp_spoof = dgctx("198.51.100.123", "/mno")
dp_spoof.session_cookie_known = false
dp_spoof.session_richness_own = 1.0
dynamic_guard.before(dp_spoof)
local _, dp_spoof_exit = dynamic_guard.admit(dp_spoof)
eq(dp_spoof_exit, true, "richness without known cookie cannot buy priority")
eq(dp_spoof.dynamic_pressure_disposition, "shed_incident",
   "spoofable Cookie state remains untrusted")

-- After the hold, the measured cohort owns one probe.  Unrelated traffic is
-- allowed and cannot consume its lease.  A slow probe must renew the hold
-- directly; rebuilding the aggregate after shedding would be impossible.
clock = 3207
fake_ngx.var.uri = "/pqr"
local dp_probe = dgctx("198.51.100.113", "/pqr")
local _, dp_probe_exit = dynamic_guard.before(dp_probe)
eq(dp_probe_exit, false, "half-open candidate survives early local guards")
eq(dp_probe.dynamic_pressure_probe, nil,
   "early hook does not consume the only backend probe lease")
dynamic_guard.admit(dp_probe)
eq(dp_probe.dynamic_pressure_probe, true,
   "late-admitted matching cohort atomically becomes probe")

fake_ngx.var.uri = "/other-long.json"
local dp_other = dgctx("198.51.100.124", "/other-long.json")
dynamic_guard.before(dp_other)
local _, dp_other_exit = dynamic_guard.admit(dp_other)
eq(dp_other_exit, false, "unrelated traffic passes during half-open")
eq(dp_other.dynamic_pressure_disposition, "keep_normal",
   "unrelated traffic does not consume cohort probe")
dynamic_guard.after(dp_other)

fake_ngx.var.uri = "/stu"
local dp_wait = dgctx("198.51.100.114", "/stu")
local _, dp_wait_exit = dynamic_guard.before(dp_wait)
eq(dp_wait_exit, false, "second half-open candidate may still cross local WAF")
local _, dp_wait_admit_exit = dynamic_guard.admit(dp_wait)
eq(dp_wait_admit_exit, true, "second late-admitted half-open request is shed")
eq(exits[#exits], 503, "pressure breaker returns 503")
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
dynamic_guard.after(dp_probe)
eq(dp_probe.dynamic_pressure_transition, "cohort_reopen",
   "slow probe directly reopens its cohort")
ok(dp_probe.dynamic_pressure_until > clock,
   "slow probe moves open_until into the future")

clock = 3208
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
fake_ngx.var.uri = "/vwx"
local dp_renewed = dgctx("198.51.100.125", "/vwx")
dynamic_guard.before(dp_renewed)
local _, dp_renewed_exit = dynamic_guard.admit(dp_renewed)
eq(dp_renewed_exit, true,
   "matching cohort is shed throughout renewed hold")

-- A later fast probe closes only this cohort.  The expired aggregate key may
-- remain for telemetry, but a matching request becomes keep_normal.
clock = 3213.1
fake_ngx.var.uri = "/yzq"
local dp_fast_probe = dgctx("198.51.100.126", "/yzq")
dynamic_guard.before(dp_fast_probe)
dynamic_guard.admit(dp_fast_probe)
eq(dp_fast_probe.dynamic_pressure_probe, true,
   "cohort receives another probe after renewed hold")
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "0.200"
dynamic_guard.after(dp_fast_probe)
eq(dp_fast_probe.dynamic_pressure_transition, "cohort_close",
   "fast probe closes only measured cohort")

clock = 3213.5
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
fake_ngx.var.uri = "/abc"
local dp_recovered = dgctx("198.51.100.127", "/abc")
dynamic_guard.before(dp_recovered)
local _, dp_recovered_exit = dynamic_guard.admit(dp_recovered)
eq(dp_recovered_exit, false, "closed cohort returns to normal admission")
eq(dp_recovered.dynamic_pressure_disposition, "keep_normal",
   "global residue cannot shed a closed cohort")
dynamic_guard.after(dp_recovered)

-- Automation is another measured cohort, not a permanent low-priority label.
-- Two different bot principals jointly heat the automation lane; only then
-- does a later verified crawler yield, while a browser cohort stays normal.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.var.document_root = "/home/automation-pressure/public_html"
fake_ngx.var.server_name = "automation-pressure.test"
clock = 3230
local da1 = dgctx("198.51.100.130", "/first")
da1.automation_observed = true
fake_ngx.var.uri = "/first"
dynamic_guard.before(da1); dynamic_guard.admit(da1)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
dynamic_guard.after(da1)
clock = 3231.1
local da2 = dgctx("198.51.100.131", "/second-long")
da2.good_bot_verified = true
fake_ngx.var.uri = "/second-long"
dynamic_guard.before(da2); dynamic_guard.admit(da2)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
dynamic_guard.after(da2)
eq(da2.dynamic_pressure_candidate, true,
   "mixed principals can create measured automation incident")
eq(da2.dynamic_pressure_attributed, true,
   "automation lane owns enough incident work")

clock = 3232
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
fake_ngx.var.uri = "/ordinary-browser"
local da_human = dgctx("198.51.100.132", "/ordinary-browser")
dynamic_guard.before(da_human)
local _, da_human_exit = dynamic_guard.admit(da_human)
eq(da_human_exit, false,
   "browser request is not shed by automation incident")
eq(da_human.dynamic_pressure_disposition, "keep_normal",
   "automation incident does not become docroot breaker")
dynamic_guard.after(da_human)

fake_ngx.var.uri = "/third"
local da3 = dgctx("198.51.100.133", "/third")
da3.good_bot_verified = true
dynamic_guard.before(da3)
local _, da3_exit = dynamic_guard.admit(da3)
eq(da3_exit, true, "verified crawler yields to measured automation lane")
eq(da3.dynamic_pressure_disposition, "shed_incident_automation",
   "automation shed requires cohort contribution")

-- Old work can support a decision but cannot create one when the latest
-- completed response is fast.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.dynamic_guard.pressure.mode = "shadow"
fake_ngx.var.document_root = "/home/fresh/public_html"
clock = 3250
local df1 = dgctx("198.51.100.116", "/slow")
dynamic_guard.before(df1); dynamic_guard.admit(df1)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "3.500"
dynamic_guard.after(df1)
clock = 3251.1
local df2 = dgctx("198.51.100.117", "/fast")
dynamic_guard.before(df2); dynamic_guard.admit(df2)
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "0.600"
dynamic_guard.after(df2)
eq(df2.dynamic_pressure_work >= 4, true,
   "freshness fixture still exceeds aggregate work threshold")
eq(df2.dynamic_pressure_candidate, false,
   "fast latest completion cannot open on stale slow work")
ok(df2.dynamic_pressure_open ~= true,
   "freshness gate leaves docroot closed")

-- A client-aborted upstream consumed capacity but did not complete an upstream
-- verdict.  Keep it in isolated docroot/server telemetry and never let it
-- teach path cost, completed pressure or cohort guilt.  The hook is idempotent.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.dynamic_guard.pressure.mode = "shadow"
cfg.dynamic_guard.server_pressure.mode = "shadow"
fake_ngx.var.document_root = "/home/abort-a/public_html"
fake_ngx.var.server_name = "abort-a.test"
fake_ngx.var.uri = "/slow-abort"
clock = 3270
local dab1 = dgctx("198.51.100.140", "/slow-abort")
dynamic_guard.before(dab1); dynamic_guard.admit(dab1)
fake_ngx.status = 499
fake_ngx.var.upstream_status = "-"
fake_ngx.var.upstream_response_time = "10.000"
dynamic_guard.after(dab1); dynamic_guard.after(dab1)
eq(dab1.dynamic_aborted_sample, true,
   "499 with upstream time is explicit aborted sample")
eq(dab1.dynamic_aborted_doc_samples, 1,
   "499 counted once in docroot telemetry")
eq(dab1.dynamic_aborted_doc_work, 10,
   "499 occupancy seconds retained separately")
eq(dab1.dynamic_aborted_server_samples, 1,
   "499 also visible in whole-server telemetry")
eq(fake_ngx.shared.antibot_cache:get(
    "dg:pressure:" .. dab1.dynamic_guard_scope .. ":b:3270:n"), nil,
   "499 never enters completed docroot pressure")
eq(fake_ngx.shared.antibot_cache:get(
    "dg:server_pressure:b:3270:n"), nil,
   "499 never enters completed server pressure")
eq(dab1.dynamic_pressure_candidate, nil,
   "499 cannot open completed-work breaker")

fake_ngx.var.document_root = "/home/abort-b/public_html"
fake_ngx.var.server_name = "abort-b.test"
local dab2 = dgctx("198.51.100.141", "/another-abort")
dynamic_guard.before(dab2); dynamic_guard.admit(dab2)
fake_ngx.var.upstream_response_time = "12.000"
dynamic_guard.after(dab2)
eq(dab2.dynamic_aborted_doc_samples, 1,
   "aborted docroot counters remain tenant-scoped")
eq(dab2.dynamic_aborted_server_samples, 2,
   "aborted server counter combines tenants")
eq(dab2.dynamic_aborted_server_work, 22,
   "aborted server work exposes shared-pool pressure")

-- Whole-server completed pressure is an incident observer, not an aggregate
-- crawler ban.  Evidence-backed automation is keyed by canonical principal so
-- Amazon cannot make Meta inherit its hot cohort.  It starts shadow in the real
-- config; enforce capability is nevertheless regression-tested here.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.status = 200
fake_ngx.var.upstream_status = "200"
fake_ngx.var.upstream_response_time = "2.500"
clock = 3280
local function server_bot(principal, root, ip)
    fake_ngx.var.document_root = root
    fake_ngx.var.server_name = principal .. ".test"
    fake_ngx.var.uri = "/crawl"
    local c = dgctx(ip, "/crawl")
    c.automation_observed = true
    c.automation_principal = principal
    c.automation_tier = "verified"
    c.good_bot_verified = true
    return c
end
local dsp1 = server_bot("amazonbot", "/home/server-a/public_html",
    "198.51.100.150")
dynamic_guard.before(dsp1); dynamic_guard.admit(dsp1)
dynamic_guard.after(dsp1)
clock = 3281.1
local dsp2 = server_bot("amazonbot", "/home/server-b/public_html",
    "198.51.100.151")
dynamic_guard.before(dsp2); dynamic_guard.admit(dsp2)
dynamic_guard.after(dsp2)
eq(dsp2.dynamic_server_pressure_candidate, true,
   "completed work across docroots creates server candidate")
eq(dsp2.dynamic_server_pressure_open, true,
   "server pressure opens after fresh completed evidence")
eq(dsp2.dynamic_server_pressure_attributed, true,
   "principal cohort owns measured server work")

clock = 3282
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
local dsp_same = server_bot("amazonbot", "/home/server-c/public_html",
    "198.51.100.152")
dynamic_guard.before(dsp_same)
local _, dsp_same_exit = dynamic_guard.admit(dsp_same)
eq(dsp_same_exit, false, "server pressure ship mode shadow does not reject")
eq(dsp_same.dynamic_server_pressure_would_reject, true,
   "matching principal is a measurable server shed candidate")
eq(dsp_same.dynamic_server_pressure_disposition,
   "shed_incident_automation",
   "server automation disposition is explicit")

local dsp_other = server_bot("meta-externalagent",
    "/home/server-d/public_html", "198.51.100.153")
dynamic_guard.before(dsp_other)
local _, dsp_other_exit = dynamic_guard.admit(dsp_other)
eq(dsp_other_exit, false,
   "different verified principal never inherits Amazon incident")
eq(dsp_other.dynamic_server_pressure_cohort_match, false,
   "server automation attribution stays principal-specific")
eq(dsp_other.dynamic_server_pressure_disposition, "keep_normal",
   "unrelated automation is explicitly kept")

local dsp_first = server_bot("amazonbot", "/home/server-e/public_html",
    "198.51.100.154")
dsp_first.session_cookie_known = true
dsp_first.session_richness_own = 0.8
dynamic_guard.before(dsp_first)
local _, dsp_first_exit = dynamic_guard.admit(dsp_first)
eq(dsp_first_exit, false,
   "strong first-party state is absolute keep across server pressure")
eq(dsp_first.dynamic_server_pressure_disposition, "keep_first_party",
   "cross-site pressure has no finite first-party reserve")

cfg.dynamic_guard.server_pressure.mode = "enforce"
local dsp_enforce = server_bot("amazonbot", "/home/server-f/public_html",
    "198.51.100.155")
dynamic_guard.before(dsp_enforce)
local _, dsp_enforce_exit = dynamic_guard.admit(dsp_enforce)
eq(dsp_enforce_exit, true,
   "server pressure can enforce only matching measured cohort")
eq(dsp_enforce.dynamic_server_pressure_rejected, true,
   "server selective reject is observable")
eq(exits[#exits], 503, "server pressure returns local capacity 503")
cfg.dynamic_guard.server_pressure.mode = "off"
fake_ngx.status = 200

-- Axis promotion is independent and rollback preserves valid live slots.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.dynamic_guard.tenant_client.mode = "enforce"
cfg.dynamic_guard.pressure.mode = "off"
cfg.dynamic_guard.path_spray.mode = "off"
clock = 3300
fake_ngx.var.document_root = "/home/enforce/public_html"
fake_ngx.var.server_name = "enforce.test"
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
local de1, de2, de3 = dgctx("198.51.100.120"),
    dgctx("198.51.100.120"), dgctx("198.51.100.120")
dynamic_guard.admit(de1); dynamic_guard.admit(de2)
local _, de3_exit = dynamic_guard.admit(de3)
eq(de3_exit, true, "tenant concurrency enforce rejects limit+1")
eq(exits[#exits], 429, "generic source concurrency returns 429")
eq(de3.action_reason, "dynamic_guard:tenant_concurrency",
   "generic concurrency reject has stable reason")
eq(fake_ngx.shared.antibot_cache:get(de1.dynamic_guard_slots[1].key), 2,
   "rejected generic slot is rolled back atomically")
dynamic_guard.after(de1); dynamic_guard.after(de2)

-- A recognized first-party session receives a bounded tenant reserve.  It is
-- still subject to the same server axis, so this is priority rather than an
-- exemption.  The tcare.vn production regression was an authenticated browser
-- rejected at 11/10 while unrelated hostile work occupied the same tenant.
fake_ngx.shared.antibot_cache = Dict.new()
local fp = {}
for i = 1, 5 do
    fp[i] = dgctx("198.51.100.121")
    fp[i].session_cookie_known = true
    fp[i].session_richness_own = 0.8
end
for i = 1, 4 do
    local _, exited = dynamic_guard.admit(fp[i])
    eq(exited, false,
       "recognized first-party request " .. i .. " uses bounded reserve")
end
eq(fp[3].dynamic_tenant_limit, 4,
   "recognized first-party session receives configured tenant reserve")
local _, fp5_exit = dynamic_guard.admit(fp[5])
eq(fp5_exit, true, "first-party reserve still rejects limit+1")
eq(fp[5].action_reason, "dynamic_guard:tenant_concurrency",
   "first-party reserve remains a tenant capacity boundary")
for i = 1, 4 do dynamic_guard.after(fp[i]) end

-- A client-supplied Cookie header or inherited richness is not first-party
-- proof.  Without a positive registry result the ordinary limit remains.
fake_ngx.shared.antibot_cache = Dict.new()
local spoof1, spoof2, spoof3 = dgctx("198.51.100.124"),
    dgctx("198.51.100.124"), dgctx("198.51.100.124")
for _, candidate in ipairs({ spoof1, spoof2, spoof3 }) do
    candidate.session_cookie_known = false
    candidate.session_richness_own = 1.0
end
dynamic_guard.admit(spoof1); dynamic_guard.admit(spoof2)
local _, spoof3_exit = dynamic_guard.admit(spoof3)
eq(spoof3.dynamic_tenant_limit, 2,
   "unrecognized cookie cannot obtain first-party reserve")
eq(spoof3_exit, true,
   "unrecognized cookie remains on ordinary tenant limit")
dynamic_guard.after(spoof1); dynamic_guard.after(spoof2)

fake_ngx.shared.antibot_cache = Dict.new()
local weak1, weak2, weak3 = dgctx("198.51.100.126"),
    dgctx("198.51.100.126"), dgctx("198.51.100.126")
for _, candidate in ipairs({ weak1, weak2, weak3 }) do
    candidate.session_cookie_known = true
    candidate.session_richness_own = 0.4
end
dynamic_guard.admit(weak1); dynamic_guard.admit(weak2)
local _, weak3_exit = dynamic_guard.admit(weak3)
eq(weak3.dynamic_tenant_limit, 2,
   "known cookie below richness threshold gets no reserve")
eq(weak3_exit, true,
   "weak first-party evidence remains on ordinary tenant limit")
dynamic_guard.after(weak1); dynamic_guard.after(weak2)

-- Pipeline verification is independent positive evidence and receives the
-- same finite reserve even when no cookie-registry state is present.
fake_ngx.shared.antibot_cache = Dict.new()
local ver1, ver2, ver3 = dgctx("198.51.100.125"),
    dgctx("198.51.100.125"), dgctx("198.51.100.125")
ver1.verified, ver2.verified, ver3.verified = true, true, true
dynamic_guard.admit(ver1); dynamic_guard.admit(ver2)
local _, ver3_exit = dynamic_guard.admit(ver3)
eq(ver3.dynamic_tenant_limit, 4,
   "verified client receives configured tenant reserve")
eq(ver3_exit, false, "verified request above ordinary limit remains admitted")
dynamic_guard.after(ver1); dynamic_guard.after(ver2); dynamic_guard.after(ver3)

-- Whole-server source concurrency is independently enforceable across
-- docroots.  The rejected request must roll back its slot on this axis too.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.dynamic_guard.tenant_client.mode = "off"
cfg.dynamic_guard.server_client.mode = "enforce"
cfg.dynamic_guard.server_client.limit = 2
fake_ngx.var.document_root = "/home/server-a/public_html"
fake_ngx.var.server_name = "server-a.test"
local ds1 = dgctx("198.51.100.122", "/one")
dynamic_guard.admit(ds1)
fake_ngx.var.document_root = "/home/server-b/public_html"
fake_ngx.var.server_name = "server-b.test"
local ds2 = dgctx("198.51.100.122", "/two")
local ds3 = dgctx("198.51.100.122", "/three")
dynamic_guard.admit(ds2)
local _, ds3_exit = dynamic_guard.admit(ds3)
eq(ds3_exit, true, "server concurrency enforce rejects across docroots")
eq(exits[#exits], 429, "whole-server source concurrency returns 429")
eq(ds3.action_reason, "dynamic_guard:server_concurrency",
   "whole-server concurrency reject has stable reason")
eq(fake_ngx.shared.antibot_cache:get(ds1.dynamic_guard_slots[1].key), 2,
   "rejected whole-server slot is rolled back atomically")
dynamic_guard.after(ds1); dynamic_guard.after(ds2)

-- Path-spray promotion keeps the same generic hit/diversity/cost contract.
-- A prior costly completion supplies evidence; no URI token or CMS route is
-- encoded in the decision.
fake_ngx.shared.antibot_cache = Dict.new()
cfg.dynamic_guard.server_client.mode = "off"
cfg.dynamic_guard.path_spray.mode = "enforce"
fake_ngx.var.document_root = "/home/path-enforce/public_html"
fake_ngx.var.server_name = "path-enforce.test"
clock = 3350
fake_ngx.var.uri = "/alpha"
local dpe1 = dgctx("198.51.100.123", "/alpha")
dynamic_guard.admit(dpe1)
fake_ngx.var.upstream_status = "404"
fake_ngx.var.upstream_response_time = "3.000"
dynamic_guard.after(dpe1)
fake_ngx.var.upstream_status = nil
fake_ngx.var.upstream_response_time = nil
fake_ngx.var.uri = "/beta"
local dpe2 = dgctx("198.51.100.123", "/beta")
dynamic_guard.admit(dpe2)
fake_ngx.var.uri = "/gamma"
local dpe3 = dgctx("198.51.100.123", "/gamma")
local _, dpe3_exit = dynamic_guard.admit(dpe3)
eq(dpe3_exit, true, "path spray enforce rejects generic costly diversity")
eq(exits[#exits], 429, "generic path spray returns 429")
eq(dpe3.action_reason, "dynamic_guard:path_spray",
   "path spray reject has stable generic reason")
eq(dpe3.dynamic_path_hits, 3,
   "path enforce keeps the measured hit threshold")
eq(dpe3.dynamic_path_distinct, 3,
   "path enforce keeps the measured diversity threshold")
eq(dpe3.dynamic_path_costly, 1,
   "path enforce requires observed backend cost")
dynamic_guard.after(dpe2)

fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_cache.full = true
local de_full = dgctx("198.51.100.121")
local _, de_full_exit = dynamic_guard.admit(de_full)
eq(de_full_exit, false, "generic guard fail-open when shared dict is full")
eq(de_full.dynamic_guard_degraded, true,
   "generic guard exposes degraded measurement")
fake_ngx.shared.antibot_cache.full = nil
cfg.dynamic_guard = old_dynamic_guard
package.loaded["antibot.l7.principal_churn"] = nil
package.loaded["antibot.l7.dynamic_guard"] = nil
end
cfg.__run_generic_guard_tests()
cfg.__run_generic_guard_tests = nil

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

-- One structural source of truth for embedded browsers.  The iOS WebView
-- shape combines a non-canonical tail (0.30) with iOS WebKit+Mobile (0.15).
-- The global threshold remains 0.4, so a legitimate Android browser whose UA
-- merely ends without Safari is not relabelled.
local ios_webview = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html",
    http_user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        .. "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 App/1.0",
})
eq(ios_webview.req_class, "inapp_browser",
   "generic iOS WKWebView structure enters in-app class")
ok((ios_webview.inapp_likeness or 0) >= 0.4,
   "iOS WKWebView evidence crosses class threshold")

local firefox_android = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html",
    http_user_agent = "Mozilla/5.0 (Android 14; Mobile; rv:121.0) "
        .. "Gecko/121.0 Firefox/121.0",
})
eq(firefox_android.req_class, "navigation",
   "non-Safari tail alone does not relabel Firefox Android")
eq(firefox_android.inapp_likeness, 0.3,
   "weak mobile tail signal remains below in-app threshold")

local cubot_webview = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html", http_x_requested_with = "com.example.reader",
    http_user_agent = "Mozilla/5.0 (Linux; Android 14; CUBOT-X70) "
        .. "AppleWebKit/537.36 Chrome/121.0 Mobile App/1.0",
})
eq(cubot_webview.req_class, "inapp_browser",
   "CUBOT device name is not mistaken for crawler declaration")

local declared_crawler = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html", http_x_requested_with = "com.example.reader",
    http_user_agent = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
        .. "Chrome/121.0 Mobile Safari/537.36 ExampleBot/1.0",
})
eq(declared_crawler.inapp_likeness, 0.0,
   "bounded crawler declaration cannot enter in-app lane")

local safari_ios = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html",
    http_user_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        .. "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 "
        .. "Mobile/15E148 Safari/604.1",
})
eq(safari_ios.req_class, "navigation",
   "canonical iOS Safari remains normal navigation")

package.loaded["antibot.core.fingerprint.device_classifier"] = nil
local device_classifier = require "antibot.core.fingerprint.device_classifier"
fake_ngx.var = { server_protocol = "HTTP/2.0" }
local dev_inapp = {
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
        .. "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 App/1.0",
    req = { proto = "HTTP/2.0" }, req_class = ios_webview.req_class,
}
device_classifier.run(dev_inapp)
eq(dev_inapp.device_type, "inapp",
   "device classifier follows canonical request class")

local minimal_webview = classify({
    uri = "/article", args = "", request_method = "GET",
    http_accept = "text/html", http_user_agent = "Android Embedded",
    http_x_requested_with = "com.example.reader",
})
local dev_minimal = {
    ua = "Android Embedded", req = { proto = "HTTP/1.1" },
    req_class = minimal_webview.req_class,
}
device_classifier.run(dev_minimal)
eq(dev_minimal.device_type, "inapp",
   "canonical in-app result wins before local http-client label")

local dev_brand_only = {
    ua = "Zalo/1.0", req = { proto = "HTTP/1.1" }, req_class = "unknown",
}
device_classifier.run(dev_brand_only)
ok(dev_brand_only.device_type ~= "inapp",
   "brand token alone cannot grant in-app treatment")

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
eq(ca3.circuit_transition, nil, "lan vuot nguong dau chi dat candidate")
eq(ca3.circuit_candidate, "set", "candidate hard duoc ghi ro telemetry")
eq(ca3.circuit_total, 2, "evaluator doc hai bucket da hoan tat")
eq(ca3.circuit_recent_hard, 1, "candidate thay hard o bucket moi nhat")
eq(fake_ngx.shared.antibot_cache:get("cb:a.test:open_until"), nil,
   "candidate chua duoc mo breaker")

clock = 603
cbvars("a.test", "503", "0.100")
ca3 = cbctx("dynamic")
circuit.after(ca3)
eq(ca3.circuit_transition, "closed>open",
   "hai bucket hard lien tiep moi mo breaker")
eq(ca3.circuit_candidate, "confirm", "OPEN ghi ro candidate da xac nhan")
eq(ca3.circuit_state, "open", "host A vao OPEN")
eq(ca3.circuit_cause, "hard", "OPEN ghi ro nguyen nhan hard")
ok(ca3.circuit_open_until > clock, "OPEN co deadline")

-- Shadow mo hinh hoa phan quyet nhung tuyet doi khong 503.
local ca_shadow = cbctx("dynamic")
local _, shadow_exit = circuit.before(ca_shadow)
eq(shadow_exit, false, "shadow circuit khong terminate request")
eq(ca_shadow.circuit_would_reject, true, "shadow ghi would-reject")
eq(ca_shadow.circuit_state, "open", "shadow ghi dung state OPEN")
eq(ca_shadow.circuit_cause, "hard", "shadow giu cause cua OPEN state")

-- Shadow would-request van di toi upstream, nen phai ghi ket qua THAT de do
-- FP. Tuy nhien ket qua nay khong duoc hoc vao bucket: enforce se shed request
-- truoc upstream, va shadow phai mo phong cung tap recovery traffic do.
local shadow_bucket = "cb:a.test:b:" .. tostring(math.floor(clock)) .. ":n"
local bucket_before_shadow = fake_ngx.shared.antibot_cache:get(shadow_bucket)
fake_ngx.status = 200
cbvars("a.test", "502, 200", "0.050, 0.250")
circuit.after(ca_shadow)
eq(ca_shadow.circuit_actual_status, 200,
   "shadow would ghi final HTTP status that")
eq(ca_shadow.circuit_actual_upstream_status, "502,200",
   "shadow would giu chuoi retry upstream status trong mot log token")
eq(ca_shadow.circuit_actual_upstream_time, "0.050,0.250",
   "shadow would giu chuoi upstream response time")
eq(fake_ngx.shared.antibot_cache:get(shadow_bucket), bucket_before_shadow,
   "telemetry shadow would khong hoc vao circuit bucket")

-- Mot lop sau circuit co the tu choi request truoc upstream. Van phai thay
-- final status that, nhung cbup/cbuptime rong de khong nham 429 noi bo voi
-- loi backend.
local local_shadow = cbctx("dynamic")
local _, local_shadow_exit = circuit.before(local_shadow)
eq(local_shadow_exit, false, "shadow would van di tiep toi cac lop sau")
fake_ngx.status = 429
cbvars("a.test", nil, nil)
circuit.after(local_shadow)
eq(local_shadow.circuit_actual_status, 429,
   "shadow would bi lop sau chan van ghi final status")
eq(local_shadow.circuit_actual_upstream_status, nil,
   "request khong cham upstream khong gia mao upstream status")
eq(local_shadow.circuit_actual_upstream_time, nil,
   "request khong cham upstream khong gia mao upstream time")
eq(fake_ngx.shared.antibot_cache:get(shadow_bucket), bucket_before_shadow,
   "shadow would bi chan noi bo van khong hoc vao circuit bucket")

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

-- Mau fleet 168-123 ngay 17-10: ca sau aggregate breach cua
-- quatructuyen.vn deu co `cblasth=0`; hai ca con co `cblastn=0`.  Khong duoc
-- arm candidate tren rolling-window residue.  Neu arm, chi mot hard error le
-- o bucket ke tiep se xac nhan bang chung cu va OPEN nham.
do
    fake_ngx.shared.antibot_cache = Dict.new()
    cfg.l7_circuit_breaker.window_seconds = 10
    cfg.l7_circuit_breaker.min_samples = 30
    cfg.l7_circuit_breaker.hard_error_ratio = 0.30

    -- 10/33 hard trong rolling window, nhung completed-second moi nhat co
    -- 9 request khoe. Day la dung shape n=33, err=0.303, lastn=9, lasth=0
    -- da do tren production.
    clock = 740
    fake_ngx.shared.antibot_cache:set(
        "cb:stale-arm.test:b:738:n", 24, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:stale-arm.test:b:738:h", 10, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:stale-arm.test:b:739:n", 9, 30)
    cbvars("stale-arm.test", "200", "0.100")
    local stale = cbctx("dynamic")
    circuit.after(stale)
    eq(stale.circuit_total, 33,
       "fixture stale co dung 33 mau trong rolling window")
    eq(stale.circuit_recent_total, 9,
       "fixture stale co traffic khoe trong bucket moi nhat")
    eq(stale.circuit_recent_hard, 0,
       "bucket moi nhat khong co hard error")
    eq(stale.circuit_candidate, "clear_recent",
       "aggregate stale khong duoc arm candidate")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:stale-arm.test:candidate"), nil,
       "khong ghi candidate stale vao shared dict")

    -- Mot hard error le den muon trong cung giay. Ban cu da co candidate=739
    -- va se OPEN o evaluator ke tiep; ban moi chi duoc SET tai bucket 740.
    clock = 740.2
    cbvars("stale-arm.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    clock = 741
    cbvars("stale-arm.test", "200", "0.100")
    local fresh_first = cbctx("dynamic")
    circuit.after(fresh_first)
    eq(fresh_first.circuit_recent_hard, 1,
       "hard moi duoc thay trong completed-second ke tiep")
    eq(fresh_first.circuit_candidate, "set",
       "hard moi chi bat dau mot cap freshness moi")
    eq(fresh_first.circuit_transition, nil,
       "mot hard moi khong duoc xac nhan boi aggregate stale")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:stale-arm.test:open_until"), nil,
       "aggregate stale cong mot hard le khong OPEN")

    -- Bien the production `lastn=0, lasth=0`: completed-second rong cung
    -- khong duoc dung lam nua dau cua cap xac nhan.
    fake_ngx.shared.antibot_cache = Dict.new()
    clock = 750
    fake_ngx.shared.antibot_cache:set(
        "cb:empty-recent.test:b:748:n", 30, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:empty-recent.test:b:748:h", 10, 30)
    cbvars("empty-recent.test", "200", "0.100")
    local empty_recent = cbctx("dynamic")
    circuit.after(empty_recent)
    eq(empty_recent.circuit_recent_total, 0,
       "fixture co completed-second rong")
    eq(empty_recent.circuit_recent_hard, 0,
       "completed-second rong khong co hard")
    eq(empty_recent.circuit_candidate, "clear_recent",
       "bucket rong khong arm candidate")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:empty-recent.test:candidate"), nil,
       "bucket rong khong tao shared candidate")
end

-- Mau production quatructuyen.vn: aggregate 10 giay van vuot nguong, nhung
-- bucket moi nhat da khoe. Ban cu OPEN sau khi backend phuc hoi; freshness gate
-- phai xoa candidate va de request tiep tuc di qua.
do
    fake_ngx.shared.antibot_cache = Dict.new()
    cfg.l7_circuit_breaker.min_samples = 2
    cfg.l7_circuit_breaker.hard_error_ratio = 0.5
    clock = 750
    cbvars("recovered-before-open.test", "503", "2.500")
    circuit.after(cbctx("dynamic"))
    clock = 751
    cbvars("recovered-before-open.test", "503", "2.500")
    circuit.after(cbctx("dynamic"))
    clock = 752
    cbvars("recovered-before-open.test", "200", "0.100")
    local recovered_candidate = cbctx("dynamic")
    circuit.after(recovered_candidate)
    eq(recovered_candidate.circuit_candidate, "set",
       "loi cu vuot nguong chi dat candidate")
    clock = 753
    cbvars("recovered-before-open.test", "200", "0.100")
    local recovered_clear = cbctx("dynamic")
    circuit.after(recovered_clear)
    eq(recovered_clear.circuit_hard_ratio, 2 / 3,
       "aggregate cu van con vuot nguong khi backend da khoe")
    eq(recovered_clear.circuit_recent_hard, 0,
       "bucket moi nhat chung minh khong con hard error")
    eq(recovered_clear.circuit_candidate, "clear_recent",
       "freshness gate xoa candidate loi cu")
    eq(recovered_clear.circuit_transition, nil,
       "backend da khoe khong bi mo circuit muon")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:recovered-before-open.test:open_until"), nil,
       "loi stale khong tao OPEN state")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:recovered-before-open.test:candidate"), nil,
       "candidate stale duoc xoa khoi shared dict")
end

-- Hai lan vuot nguong phai thuoc hai bucket HOAN TAT lien tiep. Candidate cu
-- khong duoc nhay qua mot giay trong roi xac nhan bang bang chung moi.
do
    fake_ngx.shared.antibot_cache = Dict.new()
    cfg.l7_circuit_breaker.min_samples = 2
    cfg.l7_circuit_breaker.hard_error_ratio = 0.5
    clock = 760
    fake_ngx.shared.antibot_cache:set(
        "cb:gap-candidate.test:b:758:n", 1, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:gap-candidate.test:b:758:h", 1, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:gap-candidate.test:b:759:n", 1, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:gap-candidate.test:b:759:h", 1, 30)
    fake_ngx.shared.antibot_cache:set(
        "cb:gap-candidate.test:candidate", 757, 30)
    cbvars("gap-candidate.test", "503", "0.100")
    local gap_restart = cbctx("dynamic")
    circuit.after(gap_restart)
    eq(gap_restart.circuit_candidate, "restart",
       "candidate cach bucket moi mot khoang phai khoi dong lai")
    eq(gap_restart.circuit_transition, nil,
       "bang chung khong lien tiep khong duoc OPEN")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:gap-candidate.test:candidate"), 759,
       "restart neo candidate vao bucket moi nhat")

    clock = 761
    cbvars("gap-candidate.test", "503", "0.100")
    local gap_confirm = cbctx("dynamic")
    circuit.after(gap_confirm)
    eq(gap_confirm.circuit_candidate, "confirm",
       "bucket hard lien tiep sau restart duoc xac nhan")
    eq(gap_confirm.circuit_transition, "closed>open",
       "restart chi OPEN sau cap bucket lien tiep moi")
end

-- Candidate phai duoc DON khi aggregate tut xuong duoi nguong. Khong don thi
-- no song het TTL (`interval * 3 + 2`) va mot dot loi RIENG BIET sau do chi can
-- MOT bucket hard de OPEN — tuc gate hai-bucket bi vo hieu dung luc no can
-- nhat. Dot bien: go nhanh `clear_threshold` thi toan bo suite van xanh truoc
-- khi co hai phep nay.
do
    fake_ngx.shared.antibot_cache = Dict.new()
    cfg.l7_circuit_breaker.min_samples = 2
    cfg.l7_circuit_breaker.hard_error_ratio = 0.5
    -- Can BA tick: hai de do day bucket, tick thu ba moi doc duoc
    -- `min_samples=2` tu cac bucket DA HOAN TAT va dat candidate.
    clock = 770
    cbvars("candidate-cleanup.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    clock = 771
    cbvars("candidate-cleanup.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    -- Tick nay KHOE: bucket 771 van hard nen aggregate con vuot nguong va
    -- candidate duoc dat, nhung request hien tai khong them hard moi.
    clock = 772
    cbvars("candidate-cleanup.test", "200", "0.100")
    local armed = cbctx("dynamic")
    circuit.after(armed)
    eq(armed.circuit_candidate, "set", "dot loi dau dat candidate")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:candidate-cleanup.test:candidate"), 771,
       "candidate neo vao bucket da hoan tat")

    -- Luu luong khoe keo aggregate xuong duoi nguong. Phai bat NGAY tick dau
    -- tien aggregate tut duoi nguong: cac tick sau do candidate DA bi xoa, nen
    -- `circuit_candidate` tro lai nil va phep kiem se bao oan (da mac dung loi
    -- nay mot lan — `dict=nil` trong probe la cai chi ra).
    --
    -- 2 hard (bucket 770-771) / 10 giay: them du mau khoe de ratio < 0.5.
    -- Them response khoe vao CHINH bucket 772 sau evaluator dau giay. Khi
    -- evaluator 773 doc bucket da hoan tat, 2 hard / 7 mau < 0.5, nen no phai
    -- di dung nhanh `clear_threshold`. Fixture cu chi them mot mau khoe moi
    -- giay: aggregate van >=0.5 o tick dau, `clear_recent` xoa candidate truoc,
    -- vi vay vong lap cho `clear_threshold` thuc ra khong the thanh cong.
    for hit = 1, 4 do
        clock = 772 + hit / 10
        cbvars("candidate-cleanup.test", "200", "0.100")
        circuit.after(cbctx("dynamic"))
    end
    clock = 773
    cbvars("candidate-cleanup.test", "200", "0.100")
    local cleared = cbctx("dynamic")
    circuit.after(cleared)
    eq(cleared.circuit_candidate, "clear_threshold",
       "aggregate duoi nguong phai DON candidate o tick dau tien")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:candidate-cleanup.test:candidate"), nil,
       "candidate bi xoa khoi shared dict, khong song het TTL")
end

-- `trip()` xoa candidate. LUU Y GIOI HAN CUA PHEP NAY: go dong `delete_key`
-- trong `trip()` thi suite VAN xanh, vi `close_after_probe()` cung xoa khoa do
-- khi breaker ve CLOSED — nen tren duong di binh thuong khong quan sat duoc su
-- khac biet. Giu ca hai la phong ve nhieu lop (neu OPEN het han ma khong qua
-- probe thi `trip()` moi la noi don), khong phai ma trung lap. Phep duoi chi
-- ghim trang thai SAU trip; dung tin no bat duoc viec go dong do.
do
    fake_ngx.shared.antibot_cache = Dict.new()
    cfg.l7_circuit_breaker.min_samples = 2
    cfg.l7_circuit_breaker.hard_error_ratio = 0.5
    clock = 790
    cbvars("trip-cleanup.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    clock = 791
    cbvars("trip-cleanup.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    clock = 792
    cbvars("trip-cleanup.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
    clock = 793
    cbvars("trip-cleanup.test", "503", "0.100")
    local tripped = cbctx("dynamic")
    circuit.after(tripped)
    eq(tripped.circuit_transition, "closed>open", "hai bucket hard mo breaker")
    eq(fake_ngx.shared.antibot_cache:get(
        "cb:trip-cleanup.test:candidate"), nil,
       "trip() xoa candidate de khong ro ri sang chu ky sau")
end

-- Slow 200 chi la candidate telemetry. Du 100% cham cung KHONG duoc ghi OPEN.
--
-- `do ... end`: cung ly le voi khoi surge-guard o tren — gioi han 200 bien
-- `local` cua LuaJIT tinh theo MAIN FUNCTION. `print` tong ket nam NGOAI khoi
-- nay vi `passed` la bien o pham vi ngoai cung.
do
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
-- request dau giay 11 voi dung n=30, rps=3. Freshness gate dat candidate;
-- bucket hard lien tiep tiep theo moi duoc OPEN.
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
exact3_last = cbctx("dynamic")
circuit.after(exact3_last)
eq(exact3_last.circuit_transition, nil,
   "dung 3rps dat candidate sau 10 bucket hoan tat")
eq(exact3_last.circuit_candidate, "set", "3rps dat candidate dau")
eq(exact3_last.circuit_total, 30, "3rps co dung 30 mau")
eq(exact3_last.circuit_rps, 3, "config 3rps khop hanh vi 3rps")
for hit = 2, 3 do
    clock = 1010 + hit / 10
    cbvars("exact3.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
end
clock = 1011.1
cbvars("exact3.test", "503", "0.100")
local exact3_trip = cbctx("dynamic")
circuit.after(exact3_trip)
eq(exact3_trip.circuit_transition, "closed>open",
   "3rps hard lien tuc mo sau mot bucket xac nhan")
eq(exact3_trip.circuit_candidate, "confirm",
   "3rps OPEN qua candidate xac nhan")

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
sample_gate_last = cbctx("dynamic")
circuit.after(sample_gate_last)
eq(sample_gate_last.circuit_transition, nil,
   "30 mau dat candidate du rps dan xuat chi 1.5")
eq(sample_gate_last.circuit_candidate, "set",
   "min_samples doc lap RPS van dat candidate")
eq(sample_gate_last.circuit_total, 30,
   "cua so 20s van dung cong min_samples=30")
eq(sample_gate_last.circuit_rps, 1.5,
   "rps chi la telemetry total/window, khong phai cong")
for hit = 2, 3 do
    clock = 1060 + hit / 10
    cbvars("sample-gate.test", "503", "0.100")
    circuit.after(cbctx("dynamic"))
end
clock = 1061.1
cbvars("sample-gate.test", "503", "0.100")
local sample_gate_trip = cbctx("dynamic")
circuit.after(sample_gate_trip)
eq(sample_gate_trip.circuit_transition, "closed>open",
   "hard lien tuc xac nhan min_samples du RPS chi 1.65")
eq(sample_gate_trip.circuit_candidate, "confirm",
   "cua so 20s cung di qua freshness gate")
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
eq(burst_next_second.circuit_transition, nil,
   "request giay sau thay burst nhung chi dat candidate")
eq(burst_next_second.circuit_candidate, "set",
   "burst mot giay phai qua freshness candidate")
eq(burst_next_second.circuit_total, 100,
   "evaluator giay sau doc du 100 mau")
eq(burst_next_second.circuit_rps, 10,
   "burst 100 mau tren cua so 10s thanh 10rps")
clock = 1102.1
cbvars("burst.test", "503", "0.100")
burst_next_second = cbctx("dynamic")
circuit.after(burst_next_second)
eq(burst_next_second.circuit_transition, "closed>open",
   "hard o bucket ke tiep moi xac nhan burst con tiep dien")
eq(burst_next_second.circuit_candidate, "confirm",
   "burst lien tuc mo qua candidate xac nhan")

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
local init_src = read_file(SRC .. "init.lua")
local admission_pos = assert(init_src:find("run_steps%(STEPS_ADMISSION, ctx%)"))
local verified_pos = assert(init_src:find("check_verified_cookie%(ctx%)", admission_pos))
local waf_pos = assert(init_src:find("waf_layer%.run_pre%(ctx%)"))
ok(admission_pos < verified_pos, "admission runs before verified-cookie exit")
ok(admission_pos < waf_pos, "admission runs before WAF body scan")
ok(init_src:find("xfilter_guard%.run%(ctx%)", verified_pos) ~= nil,
   "verified fast path still crosses faceted-filter guard")

local admission_steps = assert(init_src:match(
    "local STEPS_ADMISSION%s*=%s*{(.-)\n}"))
local automation_pos = assert(admission_steps:find("layer%s*=%s*automation_guard"))
local proxy_pos = assert(admission_steps:find("layer%s*=%s*proxy_origin"))
local principal_pos = assert(admission_steps:find("layer%s*=%s*principal_churn"))
local local_brake_pos = assert(admission_steps:find("layer%s*=%s*l7_admission"))
local circuit_pos = assert(admission_steps:find("layer%s*=%s*l7_circuit"))
local surge_pos = assert(admission_steps:find("layer%s*=%s*l7_surge"))
local dynamic_pos = assert(admission_steps:find("layer%s*=%s*dynamic_guard"))
local redis_ban_pos = assert(admission_steps:find("layer%s*=%s*ip_ban_check"))
ok(automation_pos < local_brake_pos,
   "automation telemetry runs before admission fast-exit")
ok(proxy_pos < principal_pos and principal_pos < local_brake_pos,
   "principal churn sees verified proxy state before admission exit")
ok(local_brake_pos < circuit_pos,
   "circuit breaker reuses admission dynamic/static decision")
ok(circuit_pos < redis_ban_pos,
   "OPEN host sheds work before Redis-backed IP ban lookup")
ok(circuit_pos < surge_pos and surge_pos < redis_ban_pos,
   "surge early gate runs before Redis-backed IP ban lookup")
ok(surge_pos < dynamic_pos and dynamic_pos < redis_ban_pos,
   "generic pressure gate runs before Redis-backed IP ban lookup")
ok(local_brake_pos < redis_ban_pos,
   "local admission shields Redis-backed IP ban lookup")

local verified_admit_pos = assert(init_src:find("admit_dynamic%(ctx%)", verified_pos))
ok(verified_admit_pos > waf_pos,
   "verified fast path acquires surge slot only after WAF")
ok(init_src:find("if not exited then admit_dynamic%(ctx%) end") ~= nil,
   "normal pipeline acquires slot only when enforcement did not exit")

local surge_after_pos = assert(init_src:find("l7_surge%.after%(ctx%)"))
local dynamic_after_pos = assert(init_src:find("dynamic_guard%.after%(ctx%)"))
local circuit_after_pos = assert(init_src:find("l7_circuit%.after%(ctx%)"))
local logger_pos = assert(init_src:find("logger%.run%(ctx%)", circuit_after_pos))
ok(dynamic_after_pos < surge_after_pos,
   "generic source slots release before broad surge telemetry")
ok(surge_after_pos < circuit_after_pos,
   "log phase releases surge slot before circuit learning")
ok(circuit_after_pos < logger_pos,
   "log-phase circuit telemetry is ready before main logger")

-- `nginx/` nam NGOAI `antibot-core/`, nen `SRC` khong dan tới được. Tren cay da
-- deploy (`conf/antibot/`) hai tep nay KHONG ton tai, con trong repo thi co.
--
-- Truoc 08-10 chung duoc doc bang duong dan dong cung, nen chay tu `waf/scripts/`
-- la `read_file` bay `assert` — ma `error` luc do khong lam `resty` thoat khac 0,
-- nen `run.sh` van bao rc=0. Hai lo cong nhau thanh: bo kiem CHUA BAO GIO chay
-- 8 assertion nay trong `run.sh`, va cung chua bao gio bao rang no khong chay.
--
-- Nay: doc duoc thi kiem, khong doc duoc thi NOI RA. `REPO_ROOT` cho phep chi
-- dinh tay khi chay tu thu muc khac.
local repo_root = os.getenv("REPO_ROOT")
if not repo_root or repo_root == "" then
    -- `SRC` tro vao `antibot-core/`; repo root la cha cua no.
    repo_root = SRC:gsub("antibot%-core/?$", "")
    if repo_root == "" then repo_root = "./" end
end
if repo_root:sub(-1) ~= "/" then repo_root = repo_root .. "/" end

local function try_read(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local generator  = try_read(repo_root .. "nginx/da_to_openresty.sh")
local nginx_conf = try_read(repo_root .. "nginx/nginx.conf")

if not generator or not nginx_conf then
    io.write("  BO QUA 8 phep kiem `nginx/` — khong doc duoc tu ", repo_root,
             " (binh thuong khi chay tu cay da deploy; dat REPO_ROOT de kiem)\n")
else
    ok(generator:find("antibot.l7.admission", 1, true) == nil,
       "generator is not coupled to Lua admission")
    ok(generator:find("limit_conn antibot_conn_", 1, true) == nil,
       "generator has no admission-specific native connection limits")
    ok(generator:find("circuit_breaker", 1, true) == nil,
       "generator is not coupled to Lua circuit breaker")
    ok(generator:find("surge_guard", 1, true) == nil,
       "generator is not coupled to Lua surge guard")

    ok(nginx_conf:find("antibot_l7_", 1, true) == nil,
       "nginx.conf has no admission-specific shared dict")
    ok(nginx_conf:find("limit_conn_zone", 1, true) == nil,
       "nginx.conf is unchanged by Lua-only admission")
    ok(nginx_conf:find("circuit_breaker", 1, true) == nil,
       "nginx.conf is unchanged by Lua-only circuit breaker")
    ok(nginx_conf:find("surge_guard", 1, true) == nil,
       "nginx.conf is unchanged by Lua-only surge guard")
end

local verify_handler = read_file(
    SRC .. "enforcement/challenge/verify_token.lua")
local beacon_handler = read_file(
    SRC .. "detection/browser/beacon_handler.lua")
ok(verify_handler:find('run_endpoint("verify")', 1, true) ~= nil,
   "verify handler invokes Lua-only endpoint admission")
ok(beacon_handler:find('run_endpoint("beacon")', 1, true) ~= nil,
   "beacon handler invokes Lua-only endpoint admission")

-- ── dict DAY: fail-open co bo dem, va thong diep chi dung cho ────────
--
-- Lo do that tren 171-96 06-10: 17 luot `adm=*dict_error` trong 94.121 mau, ma
-- `error.log` ra 0 DONG — `last_dict_error` la bien PER-WORKER voi rate-limit
-- 60 giay, nen moi worker im lang rieng. Truoc ban nay KHONG co mot ca test nao
-- cho nhanh nay, nen ca fail-open ca duong ra deu chua tung duoc kiem.
fake_ngx.shared.antibot_cache = Dict.new()
fake_ngx.shared.antibot_stats = Dict.new()
fake_ngx.shared.antibot_cache.full = true
clock = 3000
exits = {}
fake_ngx.var.uri = "/x.php"
local dfull = { ip = "203.0.113.90", req_class = "navigation", req = {} }
local _, dfull_exit = admission.run(dfull)
-- FAIL-OPEN la co y: shared-dict het cho khong duoc bien thanh outage.
eq(dfull_exit, false, "dict day -> fail-open, KHONG chan")
ok(tostring(dfull.admission_reason or ""):find("dict_error", 1, true) ~= nil,
   "dict day ghi reason *_dict_error de log doc duoc")
-- BO DEM phai tang KE CA khi dong log bi rate-limit nuot. Day la diem khac biet
-- that: `error.log` khong dang tin, `antibot_stats` thi dang.
-- MOT request dung NHIEU truc (ip x short/long, host_group x short/long,
-- route), va moi truc goi `bucket_incr` rieng — nen mot request voi dict day
-- sinh NHIEU luot dem, khong phai mot. Do la hanh vi that, va no noi rang 17
-- DONG trong antibot.log tuong ung nhieu hon 17 lan loi noi bo.
local nfull = fake_ngx.shared.antibot_stats:get("l7adm:dicterr:full")
local nfull = fake_ngx.shared.antibot_stats:get("l7adm:dicterr:full")
ok(nfull and nfull >= 1, "bo dem antibot_stats tang khi dict day")
-- Luot thu hai trong CUNG giay: dong log bi rate-limit bo, nhung bo dem KHONG
-- duoc bo. Dot bien "dem SAU rate-limit" chi bi bat boi ca nay.
local dfull2 = { ip = "203.0.113.91", req_class = "navigation", req = {} }
admission.run(dfull2)
ok(fake_ngx.shared.antibot_stats:get("l7adm:dicterr:full") > nfull,
   "bo dem tang ca khi dong log bi rate-limit nuot")
-- Hai nguyen nhan phai dem RIENG: "thieu khai bao" va "day" can hai cach xu ly
-- khac nhau (sua nginx.conf vs tang dung luong).
eq(fake_ngx.shared.antibot_stats:get("l7adm:dicterr:missing"), nil,
   "dict day KHONG duoc dem vao o 'missing'")
fake_ngx.shared.antibot_cache.full = nil



-- ── SHADOW swarm: mau so + ti le ──────────────────────────────────────
--
-- Bo kiem nay chay THAT `distributed_swarm.run()` voi mot Redis gia, vi hai
-- bat bien chi sai duoc trong im lang:
--   1. `res[5]` la chi so CO DINH. Pipeline co 6 op; doi thu tu (vd dat
--      `expire` truoc `pfcount`) lam `all` doc nham gia tri 1/0 cua `pfadd`
--      hay `expire` — ti le van ra mot SO, chi la so sai.
--   2. `swarm_attack` KHONG duoc doi. Day la buoc shadow; neu mau so lot vao
--      nhanh quyet dinh thi luat da thay doi ma khong ai duyet.
local swarm = require "antibot.detection.distributed_swarm"
local pool  = require "antibot.core.redis_pool"

local fake_pipeline
local fake_red = {
    init_pipeline = function() fake_pipeline = {} end,
    pfadd   = function(_, k, v) fake_pipeline[#fake_pipeline+1] = {"pfadd", k, v} end,
    pfcount = function(_, k)    fake_pipeline[#fake_pipeline+1] = {"pfcount", k} end,
    expire  = function(_, k, t) fake_pipeline[#fake_pipeline+1] = {"expire", k, t} end,
}

local swarm_counts = {}
function fake_red.commit_pipeline()
    local out = {}
    for i, op in ipairs(fake_pipeline) do
        if op[1] == "pfcount" then
            out[i] = swarm_counts[op[2]] or 0
        else
            out[i] = 1
        end
    end
    return out
end

local real_get, real_put = pool.get, pool.put
pool.get = function() return fake_red, nil end
pool.put = function() end

-- 27 dai /24 dung UA nay, 500 dai /24 truy cap host => ti le 0,054.
-- Day la hinh dang DO DUOC 06-10: tu so vuot soft=20 nen luat hien tai ban,
-- nhung mau so cho thay no la 5% luu luong host — khach that, khong phai dan bot.
swarm_counts["swarm:quatructuyen.vn:" .. ngx.md5("UA-pho-bien"):sub(1, 12)] = 27
swarm_counts["swarm:all:quatructuyen.vn"] = 500

local sctx = {
    ip = "14.231.233.109", ua = "UA-pho-bien",
    req_class = "interaction", req = { host = "quatructuyen.vn" },
}
swarm.run(sctx)

eq(sctx.swarm_subnet_count, 27, "swarm: tu so doc tu res[2]")
eq(sctx.swarm_host_subnets, 500, "swarm: mau so doc tu res[5], KHONG phai res cua pfadd/expire")
ok(sctx.swarm_ratio and math.abs(sctx.swarm_ratio - 27/500) < 1e-9,
   "swarm: ti le = tu/mau")

-- Thu tu pipeline la HOP DONG, khong phai chi tiet cai dat.
eq(fake_pipeline[2][1], "pfcount", "swarm: op 2 phai la pfcount(tu so)")
eq(fake_pipeline[5][1], "pfcount", "swarm: op 5 phai la pfcount(mau so)")
eq(fake_pipeline[5][2], "swarm:all:quatructuyen.vn", "swarm: op 5 tren khoa mau so")

-- 27 >= soft 20 nen emerging; gia tri phai y NHU truoc khi co shadow.
local span = 35 - 20
ok(math.abs(sctx.swarm_attack - (0.3 + (27 - 20) / span * 0.6)) < 1e-9,
   "swarm: mau so KHONG duoc doi swarm_attack (buoc shadow)")

-- Mau so = 0 (Redis loi giua pipeline) => khong duoc chia cho 0.
swarm_counts["swarm:all:quatructuyen.vn"] = 0
local zctx = {
    ip = "14.231.233.110", ua = "UA-pho-bien",
    req_class = "interaction", req = { host = "quatructuyen.vn" },
}
swarm.run(zctx)
eq(zctx.swarm_ratio, nil, "swarm: mau so 0 -> khong ghi ti le, khong chia 0")
eq(zctx.swarm_host_subnets, nil, "swarm: mau so 0 -> khong ghi mau so")

pool.get, pool.put = real_get, real_put

-- ── Bien cua before() va admit() PHAI lech nhau dung mot don vi ───────
--
-- `before()` dung `>= limit`, `admit()` dung `> limit`. Nhin rieng thi trong
-- nhu bat doi xung, va 08-10 chinh toi da doi `before()` sang `>` cho "khop" —
-- bo kiem `full host bi shed som` bat ngay, va do la bo kiem DUY NHAT chan viec
-- do. Hai toan tu doc `count` o HAI thoi diem: `before()` truoc moi incr, nen
-- "day" la `count == limit`; `admit()` sau incr cua chinh no, nen "day" la
-- `count == limit + 1`. Cung mot trang thai vat ly, hai cach dem.
--
-- ── 12-10: NHANH `enforce` DA GO, nen bien nay khong con QUAN SAT duoc ──
--
-- Khi khong con duong 503 thi ca hai cong deu cho qua, va phep lech `>=` vs `>`
-- tro thanh khong the ghim bang HANH VI. Day la mot MAT MAT THAT cua ban go, va
-- ghi ro o day thay vi de bo kiem im lang:
--
--   · Neu ai bat lai enforce (can CA `mode = "enforce"` VA dung lai ham
--     `reject()` da go), bo kiem nay se KHONG con bat duoc viec doi `before()`
--     sang `>` — dung loi 08-10 ma chinh no tung chan.
--   · Nguoi bat lai phai doc `project_shadow_het_han` muc 2 va dung lai ca
--     khoi assertion 503 cu (xem git `c4af3a1`..HEAD cho ban day du).
--
-- Thay vao do, ghim nhung gi CON dung sau khi go: `sgn=` dem dung, `sgwould=`
-- bat dung o `count > limit`, va KHONG cong nao chan. Ba dieu do la hop dong
-- hien tai cua module.
local inv_cfg = cfg.l7_surge_guard
cfg.l7_surge_guard = {
    enabled = true, mode = "enforce", status = 503, retry_after = 2,
    max_inflight = 2, surge_ratio = 0.75, recover_ratio = 0.50,
    recovery_seconds = 2,
    slot_bucket_seconds = 60, slot_retention_seconds = 300,
    state_ttl = 300, sample_interval = 1,
}
fake_ngx.shared.antibot_cache = Dict.new()
clock = 900
exits = {}
sgvars("bound.test", "0.100")

local b1, b2 = sgctx("dynamic"), sgctx("dynamic")
surge.admit(b1)
surge.admit(b2)
eq(b2.surge_inflight, 2, "bien: host o DUNG limit (2/2)")

-- Cong SOM: day roi NHUNG khong con chan — nhanh enforce da go.
local b3 = sgctx("dynamic")
local _, b3_before = surge.before(b3)
eq(b3_before, false, "bien: o DUNG limit, before() KHONG con chan")

-- Cong MUON: cung vay, va KHONG rollback vi khong co gi bi tu choi.
local b4 = sgctx("dynamic")
local _, b4_admit = surge.admit(b4)
eq(b4_admit, false, "bien: o DUNG limit, admit() KHONG con chan")
eq(b4.surge_would_reject, true,
   "bien: `sgwould=` VAN bat o `count > limit` — telemetry con nguyen")
eq(fake_ngx.shared.antibot_cache:get("sg:bound.test:slot:15"), 3,
   "bien: khong rollback nua, slot cua b4 duoc giu (3/2 — qua limit)")

-- Nha mot slot -> con 2/2 -> van cho qua, va `sgwould=` TAT vi khong qua limit.
surge.after(b1)
local b5 = sgctx("dynamic")
local _, b5_before = surge.before(b5)
eq(b5_before, false, "bien: before() cho qua")
local _, b5_admit = surge.admit(b5)
eq(b5_admit, false, "bien: admit() cho qua")

surge.after(b5)
surge.after(b2)
cfg.l7_surge_guard = inv_cfg
end

print(string.format("L7_REGRESSION_OK %d", passed))
