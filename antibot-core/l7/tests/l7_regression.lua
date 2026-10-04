-- Chay tu repository root:
--   resty antibot-core/l7/tests/l7_regression.lua

-- Production deploy dat cay nay tai `/conf/antibot`, con source checkout co
-- ten `antibot-core`. Searcher nho nay giu nguyen require("antibot.*") cua code
-- production va chi anh xa layout trong regression test.
table.insert(package.loaders, 1, function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    local errors = {}
    for _, path in ipairs({
        "./antibot-core/" .. rel .. ".lua",
        "./antibot-core/" .. rel .. "/init.lua",
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
    self.data[key] = value
    self.expiry[key] = ttl and (clock + ttl) or nil
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
local redis_ban_pos = assert(admission_steps:find("layer%s*=%s*ip_ban_check"))
ok(local_brake_pos < redis_ban_pos,
   "local admission shields Redis-backed IP ban lookup")

local generator = read_file("nginx/da_to_openresty.sh")
ok(generator:find("antibot.l7.admission", 1, true) == nil,
   "generator is not coupled to Lua admission")
ok(generator:find("limit_conn antibot_conn_", 1, true) == nil,
   "generator has no admission-specific native connection limits")

local nginx_conf = read_file("nginx/nginx.conf")
ok(nginx_conf:find("antibot_l7_", 1, true) == nil,
   "nginx.conf has no admission-specific shared dict")
ok(nginx_conf:find("limit_conn_zone", 1, true) == nil,
   "nginx.conf is unchanged by Lua-only admission")

local verify_handler = read_file(
    "antibot-core/enforcement/challenge/verify_token.lua")
local beacon_handler = read_file(
    "antibot-core/detection/browser/beacon_handler.lua")
ok(verify_handler:find('run_endpoint("verify")', 1, true) ~= nil,
   "verify handler invokes Lua-only endpoint admission")
ok(beacon_handler:find('run_endpoint("beacon")', 1, true) ~= nil,
   "beacon handler invokes Lua-only endpoint admission")

print(string.format("L7_REGRESSION_OK %d", passed))
