-- Behavioral contract for phase-1 network-UA quarantine.

local pass, fail = 0, 0
local function ok(v, n)
    if v then pass = pass + 1 else
        fail = fail + 1
        io.stderr:write("FAIL: ", n, "\n")
    end
end
local function eq(got, want, n)
    ok(got == want, n .. " (got=" .. tostring(got) ..
        " want=" .. tostring(want) .. ")")
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end
local real_md5 = ngx.md5

ngx = {
    DEBUG = 0, INFO = 1, WARN = 2, ERR = 3,
    md5 = real_md5,
    log = function() end,
    time = function() return 1700000000 end,
    var = {
        server_name = "one.test", host = "one.test",
        http_accept = "", http_user_agent = "",
    },
    header = {}, say = function() end,
    exit = function(code) ngx._exit = code end,
}

local identity = assert(loadfile(src .. "core/fingerprint/identity.lua"))()
package.loaded["antibot.core.fingerprint.identity"] = identity
local quarantine = assert(loadfile(src .. "core/network_quarantine.lua"))()
package.loaded["antibot.core.network_quarantine"] = quarantine

local ip = "198.51.100.44"
local ua_win = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 " ..
    "Chrome/149.0.1.0 Safari/537.36"
local ua_linux = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " ..
    "Chrome/149.9.8.7 Safari/537.36"
local same_a = identity.build_from(ip, ua_win)
local same_b = identity.build_from(ip, ua_linux)
eq(same_a, same_b,
   "same IP and browser major intentionally share one network id")
ok(identity.build_from(ip, ua_win) ~= identity.build_from(ip, ua_win:gsub("149", "150")),
   "browser-major update rotates network id")
ok(identity.build_from(ip, ua_win) ~= identity.build_from("198.51.100.45", ua_win),
   "network change rotates network id")

-- Su co 21-10-2026 (no1computer.vn): mot link-preview scraper ghep token vao
-- DUOI UA browser that. UA do khong co `(compatible; ...)` nen nhanh bot cu
-- khong thay, va no roi vao `Version/(%d+)...Mobile` -> `MobileSafari/26`,
-- TRUNG voi Safari iOS 26 that. `fake_good_bot` chan dung request do (PTR cua
-- IP khach khong khop `facebook.com`), roi `network_quarantine` ghi
-- `gban:<md5(ip|MobileSafari/26)>` 300 giay -> ban LUON moi khach Safari iOS
-- cung IP. Do duoc: 79 luot `banned_ip` tren mot phien `ckn=true
-- richness=0.58`, va khach vao lai duoc dung sau khi bac TTL 300s het.
--
-- Bat bien: mot UA mang token tu dong KHONG BAO GIO chung ro voi browser that.
do
    local ua_ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) " ..
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 " ..
        "Mobile/15E148 Safari/604.1"
    local ua_ios_fb = ua_ios ..
        " facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"
    local ua_ios_multi = ua_ios .. " facebookexternalhit/1.1 Facebot Twitterbot/1.0"

    ok(identity.build_from(ip, ua_ios_fb) ~= identity.build_from(ip, ua_ios),
       "scraper ghep duoi UA KHONG duoc chung network id voi Safari iOS that")
    ok(identity.build_from(ip, ua_ios_multi) ~= identity.build_from(ip, ua_ios),
       "UA ghep nhieu scraper cung phai tach khoi ro browser")
    eq(identity._normalize_ua(ua_ios), "MobileSafari/26",
       "browser that GIU nguyen bucket cu — ban va khong duoc doi ro cua ho")
    eq(identity._normalize_ua(ua_ios_fb):sub(1, 4), "bot:",
       "scraper vao ro bot:")

    -- Cac nhanh browser dat TRUOC nhanh bot cu deu `return` ngay khi khop, nen
    -- nhanh bot phai nam TRUOC chung. Ba ca nay chet neu ai do doi lai thu tu.
    eq(identity._normalize_ua(
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/149.0.0.0 " ..
        "Safari/537.36 Edg/149.0.0.0"), "Edge/149",
       "Edge khong bi nhanh bot an")
    eq(identity._normalize_ua(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 26_4_1 like Mac OS X) " ..
        "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/155.0.8059.37 " ..
        "Mobile/15E148 Safari/604.1"), "CriOS/155",
       "Chrome iOS khong bi nhanh bot an")
    eq(identity._normalize_ua(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        :sub(1, 4), "bot:", "Googlebot van la bot:")
end

local key_ctx = { ip = ip, ua = ua_win, req = { host = "one.test" } }
local one = quarantine.keys(key_ctx, "host")
-- `$server_name` is the primary name of the selected vhost. Request aliases
-- sharing that vhost intentionally share the quarantine bucket.
key_ctx.req.host = "www.one-alias.test"
ngx.var.host = "www.one-alias.test"
local alias = quarantine.keys(key_ctx, "host")
eq(alias.ban, one.ban, "aliases in one vhost share quarantine scope")
ngx.var.server_name, ngx.var.host = "two.test", "two.test"
local two = quarantine.keys(key_ctx, "host")
ok(one.ban ~= two.ban, "host quarantine does not cross sites")
eq(quarantine.keys(key_ctx, "global").ban, "gban:" .. same_a,
   "global strong-evidence namespace is host independent")
ngx.var.server_name, ngx.var.host = "one.test", "one.test"

-- In-memory Redis supporting the production pipeline shape.
local store, writes, ttl_map = {}, {}, {}
local red = { queued = nil }
local function write(op, key, value, ttl)
    writes[#writes + 1] = { op = op, key = key, value = value, ttl = ttl }
    if op == "del" then
        store[key], ttl_map[key] = nil, nil
    elseif op == "expire" then
        ttl_map[key] = ttl
    elseif op == "incr" then
        store[key] = (tonumber(store[key]) or 0) + 1
    elseif op == "setex" then
        store[key], ttl_map[key] = value, ttl
    elseif op == "set" then
        store[key], ttl_map[key] = value, -1
    elseif op == "safe_set" then
        store[key], ttl_map[key] = value, ttl or -1
    elseif op ~= "publish" then
        store[key] = value
    end
end
function red:init_pipeline() self.queued = {} end
function red:_queue(op, key, value, ttl)
    if self.queued then
        self.queued[#self.queued + 1] = { op, key, value, ttl }
        return "QUEUED"
    end
    if op == "get" then return store[key] end
    write(op, key, value, ttl)
    if op == "incr" then return store[key] end
    return true
end
function red:get(k) return self:_queue("get", k) end
function red:set(k, v) return self:_queue("set", k, v) end
function red:setex(k, ttl, v) return self:_queue("setex", k, v, ttl) end
function red:incr(k) return self:_queue("incr", k) end
function red:expire(k, ttl) return self:_queue("expire", k, nil, ttl) end
function red:del(k) return self:_queue("del", k) end
function red:publish(k, v) return self:_queue("publish", k, v) end
function red:eval(_script, numkeys, ...)
    local a = {...}
    eq(numkeys, 4, "atomic claim passes four Redis keys")
    local ban, viol, hit, context = a[1], a[2], a[3], a[4]
    local violation_ttl = tonumber(a[5])
    local now = a[6]
    local count = tonumber(a[7]) or 1
    local context_template = a[8] or ""

    if store[ban] == "1" then
        local ttl = ttl_map[ban] or -1
        write("setex", hit, now, 300)
        return {0, tonumber(store[viol]) or 0, ttl}
    end

    local n = (tonumber(store[viol]) or 0) + 1
    local idx = math.min(math.max(n, 1), count)
    local ttl = tonumber(a[8 + idx])
    write("incr", viol)
    write("expire", viol, nil, violation_ttl)
    write("setex", ban, "1", ttl)
    write("setex", hit, now, 300)
    if context_template ~= "" then
        local json = context_template:gsub(
            '"ban_viol":"__BAN_VIOL__"',
            '"ban_viol":' .. tostring(n), 1)
        write("setex", context, json, ttl)
    end
    return {1, n, ttl}
end
function red:commit_pipeline()
    local result, queued = {}, red.queued or {}
    red.queued = nil
    for i, q in ipairs(queued) do
        local op, key, value, ttl = q[1], q[2], q[3], q[4]
        if op == "get" then result[i] = store[key]
        else
            write(op, key, value, ttl)
            result[i] = op == "incr" and store[key] or true
        end
    end
    return result
end

local pool = {
    get = function() return red end,
    put = function() end,
    safe_get = function(k) return store[k] end,
    safe_set = function(k, v, ttl) write("safe_set", k, v, ttl); return true end,
    safe_incr = function(k, ttl)
        write("incr", k)
        write("expire", k, nil, ttl)
        return store[k]
    end,
}
local config = {
    ttl = {
        ban_steps = {300, 3600, 86400, 2592000},
        violation = 2592000,
    },
    network_quarantine = {
        enabled = true, steps = {300, 3600, 86400},
        violation_ttl = 172800, legacy_read = true,
        global_reasons = { fake_good_bot = true },
    },
    cookie_registry = { ip_ban_exempt = true, richness_min = 0.5 },
}
package.loaded["antibot.core.redis_pool"] = pool
package.loaded["antibot.core.config"] = config

-- Escalation is based only on a fresh decision and selects scope by evidence.
local escalation = assert(loadfile(src .. "enforcement/ban/ban_escalation.lua"))()
local fresh = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action_reason = "score_threshold",
}
escalation.run(fresh)
eq(fresh.ban_scope, "host", "ordinary block becomes host quarantine")
eq(fresh.ban_ttl, 300, "escalation supplies a safe provisional sentence")
local fresh_keys = quarantine.keys(fresh, "host")
store[fresh_keys.viol] = 1
local repeat_ctx = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action_reason = "score_threshold",
}
escalation.run(repeat_ctx)
eq(repeat_ctx.ban_ttl, 300,
   "non-atomic escalation stage no longer reads violation history")

local strong = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "unknown", action_reason = "fake_good_bot",
}
escalation.run(strong)
eq(strong.ban_scope, "global", "direct contradiction selects global scope")
eq(strong.ban_key, "gban:" .. same_a, "global scope uses separate key family")

-- Writer uses the chosen namespace and a coarse host sentence cannot promote
-- itself to an IP ban merely because its violation count is high.
package.loaded["antibot.core.ip_scope"] = { is_self = function() return false end }
local writer = assert(loadfile(src .. "enforcement/ban/ban_store_write.lua"))()
store, writes, ttl_map = {}, {}, {}
local write_ctx = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action = "block", action_reason = "score_threshold",
    ban_scope = "host", ban_ttl = 86400, ban_previous_viol = 4,
    ban_violation = 5, score = 100, effective_score = 100,
    ip_risk = 0, swarm = false, session_richness = 0,
}
writer.run(write_ctx)
local wk = quarantine.keys(write_ctx, "host")
eq(store[wk.ban], "1", "writer creates host quarantine seal")
eq(store[wk.viol], 1, "fresh writer records one violation")
eq(write_ctx.ban_created, true, "first concurrent claimant owns the sentence")
eq(write_ctx.ban_persisted, true, "winning atomic claim is persisted")
eq(write_ctx.ban_ttl, 300, "writer, not provisional input, selects first TTL")
eq(write_ctx.ban_violation, 1, "writer returns authoritative violation number")
local qviol_ttl_ok = false
for _, w in ipairs(writes) do
    if w.op == "expire" and w.key == wk.viol and w.ttl == 172800 then
        qviol_ttl_ok = true
    end
end
eq(qviol_ttl_ok, true, "host violation history has bounded two-day TTL")
eq(store["ban:" .. same_a], nil, "writer never creates legacy identity seal")
eq(store["ban:" .. ip], nil,
   "host quarantine repeats do not promote to collective IP ban")

-- A legacy fleet subscriber must not reinterpret a host-scoped network id as
-- the old global `ban:<id>`. New consumers still receive the explicit fields.
ngx.timer = { at = function(_, fn) fn(false); return true end }
local sync = assert(loadfile(src .. "enforcement/ban/ban_sync.lua"))()
writes = {}
sync.run(write_ctx)
local host_payload = writes[#writes] and writes[#writes].value or ""
ok(host_payload:find('"identity":""', 1, true) ~= nil,
   "host quarantine hides identity from legacy sync consumers")
ok(host_payload:find('"network_id":"' .. same_a .. '"', 1, true) ~= nil,
   "host quarantine publishes explicit network id")
ok(host_payload:find('"scope":"host"', 1, true) ~= nil,
   "host quarantine publishes explicit scope")

-- Two requests can both pass ban_store before either reaches the writer.  The
-- second atomic claim must see the first seal, leave qviol unchanged and avoid
-- publishing a duplicate sentence.
local concurrent = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action = "block",
    action_reason = "score_threshold", score = 100, effective_score = 100,
    ip_risk = 0, swarm = false, session_richness = 0,
}
escalation.run(concurrent)
writer.run(concurrent)
eq(concurrent.ban_created, false, "concurrent loser does not recreate seal")
eq(concurrent.ban_persisted, true, "concurrent loser observes persisted seal")
eq(concurrent.ban_ttl, 300, "concurrent loser sees current sentence TTL")
eq(store[wk.viol], 1, "one burst increments violation exactly once")
writes = {}
sync.run(concurrent)
eq(#writes, 0, "concurrent loser does not publish duplicate ban event")
-- Winner and loser must read the SAME number of prior incidents, because they
-- ARE the same incident. The script returns a post-INCR count to the creator
-- and a plain GET to the loser, but the loser's GET already contains the
-- winner's INCR — so both subtract one and both land on the real history.
-- `viol_count >= 4` is the boundary between 24h and 30 days, so a split here
-- would hand different IP sentences to members of one burst.
eq(concurrent.ban_previous_viol, write_ctx.ban_previous_viol,
   "concurrent loser counts the same prior incidents as the winner")
eq(concurrent.ban_previous_viol, 0,
   "a first burst has no prior incident on either branch")

-- Self traffic has no incident to count, so it must not invent one.
package.loaded["antibot.core.ip_scope"] = { is_self = function() return true end }
local self_writer = assert(loadfile(src .. "enforcement/ban/ban_store_write.lua"))()
local self_ctx = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action = "block",
    action_reason = "score_threshold", score = 100, effective_score = 100,
    ip_risk = 0, swarm = false, session_richness = 0,
}
escalation.run(self_ctx)
self_writer.run(self_ctx)
eq(self_ctx.ban_violation, nil,
   "self traffic does not fabricate a violation number for the log")
eq(self_ctx.ban_created, false, "self traffic creates no sentence")
eq(self_ctx.ban_persisted, false, "self traffic persists no sentence")
package.loaded["antibot.core.ip_scope"] = { is_self = function() return false end }

-- Once the sentence expires, a genuinely new incident may advance the ladder.
store[wk.ban], store[wk.context] = nil, nil
ttl_map[wk.ban], ttl_map[wk.context] = nil, nil
local after_expiry = {
    ip = ip, ua = ua_win, req = { host = "one.test" },
    req_class = "navigation", action = "block",
    action_reason = "score_threshold", score = 100, effective_score = 100,
    ip_risk = 0, swarm = false, session_richness = 0,
}
escalation.run(after_expiry)
writer.run(after_expiry)
eq(after_expiry.ban_created, true, "post-expiry incident creates new sentence")
eq(after_expiry.ban_violation, 2, "post-expiry incident advances violation")
eq(after_expiry.ban_ttl, 3600, "second distinct incident reaches one hour")

writes = {}
strong.ban_ttl = 300
strong.ban_created = true
strong.ban_persisted = true
sync.run(strong)
local global_payload = writes[#writes] and writes[#writes].value or ""
ok(global_payload:find('"identity":"' .. same_a .. '"', 1, true) ~= nil,
   "global evidence remains compatible with legacy sync consumers")

-- Reader behavior: challenge-first for HTML, site isolation, session recovery,
-- and no sentence refresh/escalation on a seal hit.
package.loaded["antibot.detection.bot.ua_claim"] = {
    claims_good_bot = function() return false end,
}
local challenge_count = 0
package.loaded["antibot.enforcement.challenge"] = {
    run = function() challenge_count = challenge_count + 1 end,
}
package.loaded["antibot.l7.ban.ban_store"] = nil
local reader = assert(loadfile(src .. "l7/ban/ban_store.lua"))()

store, writes, ttl_map = {}, {}, {}
local function request(host, accept)
    ngx.var.server_name, ngx.var.host = host, host
    ngx.var.http_accept = accept or ""
    ngx._exit, ngx.status, ngx.header = nil, nil, {}
    return {
        ip = ip, ua = ua_win,
        req = { host = host, accept = accept or "" },
        session_richness_own = 0,
    }
end

local html = request("one.test", "text/html,application/xhtml+xml")
local hk = quarantine.keys(html, "host")
store[hk.ban], store[hk.viol] = "1", 2
local handled, exited = reader.run(html)
eq(handled, true, "host quarantine handles matching navigation")
eq(exited, true, "challenge response exits the L7 lane")
eq(html.action_reason, "network_quarantine_challenge",
   "HTML navigation gets recoverable challenge")
eq(challenge_count, 1, "challenge module is invoked once")
eq(store[hk.viol], 2, "reader hit does not increase violation count")
eq(store[hk.ban], "1", "reader hit does not rewrite sentence")

local global_html = request("one.test", "text/html")
local gk = quarantine.keys(global_html, "global")
store[gk.ban] = "1"
local before_global_challenge = challenge_count
reader.run(global_html)
eq(global_html.action_reason, "global_identity_ban",
   "direct global evidence is not downgraded to host recovery challenge")
eq(ngx._exit, 403, "global identity seal returns 403")
eq(challenge_count, before_global_challenge,
   "global identity seal does not invoke challenge")
store[gk.ban] = nil

local other = request("two.test", "text/html")
local other_handled = reader.run(other)
eq(other_handled, false, "same network id remains free on another host")

local api = request("one.test", "application/json")
reader.run(api)
eq(api.action_reason, "network_quarantine",
   "non-HTML request receives host quarantine block")
eq(ngx._exit, 403, "host quarantine block returns 403")
eq(store[hk.viol], 2, "hard reader block still does not increase violation")

local known = request("one.test", "application/json")
known.session_cookie_known = true
known.session_richness_own = 0.8
local known_handled = reader.run(known)
eq(known_handled, false, "known first-party session bypasses coarse seal")
eq(known.banned, false, "known session continues to live scoring")

-- Migration is intentionally one-way: old keys are read, but their sentence
-- and violation state are never refreshed by the new reader.
store, writes, ttl_map = {}, {}, {}
local legacy_ctx = request("one.test", "application/json")
local legacy = quarantine.legacy_keys(legacy_ctx)
store[legacy.ban], store[legacy.viol] = "1", 9
reader.run(legacy_ctx)
eq(legacy_ctx.ban_scope, "legacy", "old identity seal remains readable")
eq(legacy_ctx.action_reason, "banned_id", "legacy log reason remains compatible")
eq(store[legacy.viol], 9, "legacy violation state is read-only")
local rewrote_legacy = false
for _, w in ipairs(writes) do
    if (w.key == legacy.ban or w.key == legacy.viol)
       and w.op ~= "get" then rewrote_legacy = true end
end
eq(rewrote_legacy, false, "legacy sentence is never refreshed")

io.write(string.format("quarantine_contract: %d pass, %d fail\n", pass, fail))
if fail > 0 then os.exit(1) end
