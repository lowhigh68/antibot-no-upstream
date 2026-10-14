-- Contracts for changes that reduce self-generated load without changing a
-- request verdict: incremental memory cleanup, batched file append and removal
-- of a fleet Redis key with no consumer.

local pass, fail = 0, 0
local function ok(v, n)
    if v then pass = pass + 1 else fail = fail + 1; io.stderr:write("FAIL: ", n, "\n") end
end
local function eq(g, w, n)
    ok(g == w, n .. " (got=" .. tostring(g) .. " want=" .. tostring(w) .. ")")
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end

-- 1. memory_guard: exactly one SCAN page per timer tick.
do
    local cb, scans, puts = nil, 0, 0
    local deleted = {}
    local pages = {
        { "7", { "sess:a", "sess:b", "sess:ck:a" } },
        { "0", { "sess:c" } },
    }
    local red = { pipeline = nil }
    function red:scan()
        scans = scans + 1
        return pages[scans]
    end
    function red:init_pipeline() self.pipeline = {} end
    function red:exists(k)
        self.pipeline[#self.pipeline + 1] = { "exists", k }
    end
    function red:del(k)
        self.pipeline[#self.pipeline + 1] = { "del", k }
    end
    function red:commit_pipeline()
        local out = {}
        for i, op in ipairs(self.pipeline or {}) do
            if op[1] == "exists" then
                out[i] = op[2] == "rl:b" and 1 or 0
            else
                deleted[#deleted + 1] = op[2]
                out[i] = 1
            end
        end
        self.pipeline = nil
        return out
    end

    package.loaded["antibot.core.redis_pool"] = {
        get = function() return red end,
        put = function() puts = puts + 1 end,
    }
    ngx = {
        INFO = 1, WARN = 2, ERR = 3,
        log = function() end,
        timer = {
            every = function(_, fn) cb = fn; return true end,
        },
    }
    local guard = assert(loadfile(src .. "async/memory_guard.lua"))()
    guard.start()
    ok(type(cb) == "function", "memory guard registers one periodic callback")
    cb(true)
    eq(scans, 0, "premature timer does not touch Redis")
    cb(false)
    eq(scans, 1, "first tick scans one page only")
    eq(#deleted, 1, "first page deletes only orphan")
    eq(deleted[1], "sess:a", "active session is retained")
    ok(deleted[1] ~= "sess:ck:a", "shared-session HLL namespace is retained")
    cb(false)
    eq(scans, 2, "second tick resumes next cursor page")
    eq(#deleted, 2, "second page processed on next tick")
    eq(puts, 2, "Redis connection returned after every page")
end

-- 2. logger: two adjacent completions elect one delayed file append.
do
    local timers, opens, payload = {}, 0, ""
    local real_open = io.open
    io.open = function(path, mode)
        if path ~= "/var/log/antibot/antibot.log" then
            return real_open(path, mode)
        end
        opens = opens + 1
        return {
            write = function(_, ...) payload = payload .. table.concat({ ... }) end,
            close = function() end,
        }
    end

    ngx = {
        DEBUG = 0, WARN = 2, ERR = 3,
        var = {
            host = "example.test", request_method = "GET", args = nil,
            request_length = "100", http_content_length = nil,
            http_content_type = nil, http_sec_fetch_site = nil,
            http_sec_fetch_mode = nil, http_sec_fetch_dest = nil,
            http_sec_ch_ua_mobile = nil,
        },
        req = {
            get_uri_args = function() return {} end,
            get_post_args = function() return {} end,
            get_body_data = function() return nil end,
        },
        time = function() return 1700000000 end,
        log = function() end,
        timer = {
            at = function(delay, fn, ...)
                timers[#timers + 1] = { delay = delay, fn = fn, args = { ... } }
                return true
            end,
        },
    }

    local logger = assert(loadfile(src .. "async/logger.lua"))()
    local function sample(id)
        return {
            req = { host = "example.test", uri = "/", method = "GET" },
            req_class = "navigation", admission_group = "dynamic",
            identity = id, fp_light = id, ip = "203.0.113.10",
            ua = "Mozilla/5.0 Test", action = "allow", action_reason = "clean",
            score = 0, session_richness = 0,
        }
    end
    logger.run(sample("id-one"))
    local gb = sample("id-two")
    gb.good_bot_claimed = true
    gb.good_bot_name = "googlebot"
    gb.bot_ua = "dns_timeout"
    gb.dns_fwd_timeout = true
    gb.verified_human_rejected_bot_claim = true
    gb.intelligence_degraded = true
    gb.intelligence_degraded_layers = { "threat", "scoring" }
    logger.run(gb)

    -- Ca dang lo nhat: UA crawler KHONG khop registry (nen khong co
    -- `good_bot_claimed`, moi co DNS deu nil) nhung DANG GIU ve `verified:`.
    -- Neu cong in `gbverify_str` khong doc co nay thi dong nay khong co cot
    -- `gb*` nao — do la trang thai truoc 14-10 va la ly do phep dem
    -- `grep -c gbhuman=reject` khong the thay ca nay.
    local held = sample("id-three")
    held.verified_human_rejected_bot_claim = true
    held.verified_human_bot_held_cookie = true
    logger.run(held)

    local shared = sample("id-shared")
    shared.ip_shared = true
    shared.ip_tour_uas = 8
    shared.ip_real_users = 5
    shared.ip_known_users = 3
    shared.ip_shared_verified = true
    shared.ip_tier2_cookie_evidence = "known"
    shared.ip_tier2_warming = false
    logger.run(shared)

    eq(opens, 0, "request log path does not open file synchronously")

    local flushes = 0
    for i = 1, #timers do
        if timers[i].delay == 0.05 then
            flushes = flushes + 1
            timers[i].fn(false)
        end
    end
    eq(flushes, 1, "adjacent log lines elect one flush timer")
    eq(opens, 1, "one batch uses one file open")
    ok(payload:find("id%-one") ~= nil and payload:find("id%-two") ~= nil,
       "batch retains both request lines")
    ok(payload:find("gbv=dns_timeout", 1, true) ~= nil
       and payload:find("gbname=googlebot", 1, true) ~= nil
       and payload:find("gbdeg=true", 1, true) ~= nil
       and payload:find("gbhuman=reject", 1, true) ~= nil,
       "goodbot verification provenance is observable")

    -- `held_cookie` thang `reject` tren cung mot dong: hai co deu bat, nhung
    -- chi co su kien an ninh duoc in. Khong co phep nay thi mot ban sua lam
    -- `reject` thang lai se khong bi bat.
    ok(payload:find("gbhuman=held_cookie", 1, true) ~= nil,
       "crawler holding a verified ticket is logged as held_cookie")
    for line in payload:gmatch("[^\n]+") do
        if line:find("id%-three") then
            ok(line:find("gbhuman=held_cookie", 1, true) ~= nil,
               "unregistered crawler with a ticket still emits the gb* columns")
            ok(line:find("gbhuman=reject", 1, true) == nil,
               "held_cookie outranks reject on the same line")
        end
    end
    ok(payload:find("ideg=threat,scoring", 1, true) ~= nil,
       "partial intelligence pipeline is observable")
    ok(payload:find("ipuas=8 ipru=5 ipku=3 ipsv=true iptev=known iptwarm=false",
                    1, true) ~= nil,
       "Tier-2 legacy/strict populations are observable without ambiguity")
    io.open = real_open
end

-- 3. Fleet pipeline no longer writes the `uab` key that has no reader.
do
    local keys = {}
    local red = {}
    local function record(_, key) keys[#keys + 1] = tostring(key or "") end
    red.incr = record; red.expire = record; red.pfadd = record
    red.zincrby = record; red.zremrangebyrank = record; red.sadd = record

    package.loaded["antibot.core.config"] = {
        fleet_detection = { timing = { bucket_ttl = 900 } },
    }
    package.loaded["antibot.detection.fleet.trusted"] = {
        is_trusted = function() return false end,
        is_good_crawler = function() return false end,
    }
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function() return nil end,
        pipeline = function(fn) fn(red); return {}, nil end,
    }
    ngx = {
        WARN = 2, log = function() end,
        time = function() return 1700000000 end,
        md5 = function(s) return (s .. "000000000000"):sub(1, 32) end,
        var = {
            http_accept_language = "vi", http_accept_encoding = "gzip",
            http_cookie = nil, uri = "/",
        },
    }
    local agg = assert(loadfile(src .. "detection/fleet/aggregator.lua"))()
    agg.write({
        ip = "203.0.113.10", ua = "Mozilla/5.0 Chrome/120.0",
        req = { uri = "/", host = "example.test" },
    })
    local uab = false
    for i = 1, #keys do
        if keys[i]:find(":uab:", 1, true) then uab = true; break end
    end
    ok(not uab, "fleet pipeline has no dead uab write")
end

io.write(string.format("hot_path_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
