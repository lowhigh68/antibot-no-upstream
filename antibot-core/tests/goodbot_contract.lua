-- Behavioral contract for DNS-forward cache semantics.

local pass, fail = 0, 0
local function ok(v, n)
    if v then pass = pass + 1 else fail = fail + 1; io.stderr:write("FAIL: ", n, "\n") end
end
local function eq(g, w, n)
    ok(g == w, n .. " (got=" .. tostring(g) .. " want=" .. tostring(w) .. ")")
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end

-- P1.2: one pure parser/metadata source feeds the broad hold gate, the DNS
-- verification lane and rate-family matching. These are compatibility tests:
-- they pin existing verdict boundaries instead of silently widening trust.
do
    local registry = assert(loadfile(src .. "core/goodbot_registry.lua"))()
    package.loaded["antibot.core.goodbot_registry"] = registry

    eq(registry.claims_operator("Google"), true,
       "exact Google operator claim is preserved")
    eq(registry.claims_operator("Mozilla/5.0 Google Chrome"), false,
       "browser text containing Google is not a crawler claim")
    eq(registry.claims_operator("Mediapartners-Google/2.1"), true,
       "Mediapartners broad hold is preserved")

    local google = registry.inspect("Googlebot-Image/1.0")
    eq(google.operator_claimed, true, "Googlebot is held")
    eq(google.verification_claimed, true, "Googlebot enters verification")
    eq(google.canonical_name, "googlebot-image", "Googlebot name is canonical")
    eq(registry.asns("googlebot-image")[1], 15169,
       "Google static ASN comes from unified registry")

    local meta = registry.inspect("meta-externalagent/1.1")
    eq(meta.canonical_name, "meta-externalagent", "lowercase Meta name parses")
    eq(registry.is_ptr_only(meta.canonical_name), true,
       "Meta ptr-only policy comes from unified registry")

    local held = registry.inspect("Google")
    eq(held.operator_claimed, true, "bare Google remains held from human lane")
    eq(held.verification_claimed, false,
       "P1.2 does not silently change bare Google verdict lane")

    eq(registry.class_for_bot("coccocbot-web", {
        coccoc = "polite", coccocbot = "moderate",
    }), "moderate", "longest rate-family prefix wins")
    eq(registry.class_for_bot("googlebot", { google = "moderate", googlebot = "polite" }),
       "polite", "exact rate class wins before family prefix")

    local f = assert(io.open(src .. "core/data/goodbot.json", "r"))
    local raw = f:read("*a"); f:close()
    local data = assert(require("cjson.safe").decode(raw))
    local parsed = 0
    for name in pairs(data.bots or {}) do
        local result = registry.inspect(name .. "/1.0")
        eq(result.canonical_name, name:lower(),
           "registry entry has canonical parser: " .. name)
        parsed = parsed + 1
    end
    ok(parsed > 0, "goodbot JSON matrix is non-empty")

    local facade = assert(loadfile(src .. "detection/bot/ua_claim.lua"))()
    eq(facade.claims_good_bot("AhrefsSiteAudit/7.0"),
       registry.claims_operator("AhrefsSiteAudit/7.0"),
       "ua_claim is a facade over unified registry")
end

local cache, writes, query_mode, query_calls
package.loaded["antibot.core.config"] = { ttl = { dns = 300 } }
package.loaded["antibot.core.redis_pool"] = {
    safe_get = function(k) return cache[k] end,
    safe_set = function(k, v, ttl)
        cache[k] = v
        writes[#writes + 1] = { key = k, value = v, ttl = ttl }
        return true
    end,
}
package.loaded["resty.dns.resolver"] = {
    new = function()
        if query_mode == "init_fail" then return nil, "resolver init failed" end
        local r = { TYPE_A = 1, TYPE_AAAA = 28 }
        function r:query(_, opt)
            query_calls = query_calls + 1
            if query_mode == "timeout" then return nil, "timeout" end
            if query_mode == "no_records" then return { errcode = 3 }, nil end
            if query_mode == "success" and opt.qtype == self.TYPE_A then
                return { { type = self.TYPE_A, address = "203.0.113.10" } }, nil
            end
            return { errcode = 3 }, nil
        end
        return r
    end,
}

ngx = {
    INFO = 1, ERR = 3,
    log = function() end,
}

local dns = assert(loadfile(src .. "detection/bot/dns_forward.lua"))()

local function reset(mode)
    cache, writes, query_calls, query_mode = {}, {}, 0, mode
end
local function ctx()
    return {
        dns_rev_valid = true,
        dns_rev = "crawler.example.test",
        ip = "203.0.113.10",
        good_bot_name = "fixturebot",
    }
end

reset("timeout")
local a = ctx(); dns.run(a)
eq(cache["dns_fwd:crawler.example.test"], "TIMEOUT", "timeout co token cache rieng")
eq(writes[1].ttl, 10, "timeout cache ngan")
eq(a.dns_fwd_timeout, true, "request dau giu timeout state")
eq(a.good_bot_verified, nil, "timeout khong ket luan fake")
local calls = query_calls
query_mode = "success"
local b = ctx(); dns.run(b)
eq(query_calls, calls, "cached timeout khong lap DNS query")
eq(b.dns_fwd_timeout, true, "cached timeout van la timeout")
eq(b.good_bot_verified, nil, "cached timeout khong doi thanh fake")

reset("init_fail")
local c = ctx(); dns.run(c)
eq(cache["dns_fwd:crawler.example.test"], "TEMP", "resolver failure co token TEMP")
eq(c.dns_fwd_degraded, true, "resolver failure dat degraded")
eq(c.good_bot_verified, nil, "degraded khong ket luan fake")
local d = ctx(); dns.run(d)
eq(d.dns_fwd_degraded, true, "cached TEMP van degraded")
eq(d.good_bot_verified, nil, "cached TEMP khong doi thanh fake")

reset("no_records")
local e = ctx(); dns.run(e)
eq(cache["dns_fwd:crawler.example.test"], "NO_RECORDS",
   "no-record cache has an unambiguous semantic token")
eq(e.good_bot_verified, false, "no-record la verification mismatch")
eq(e.bot_ua, "fake_good_bot", "no-record dat fake reason")
local f = ctx(); dns.run(f)
eq(f.good_bot_verified, false, "cached NO_RECORDS van mismatch")

reset("success")
cache["dns_fwd:crawler.example.test"] = "FAIL"
local legacy = ctx(); dns.run(legacy)
eq(legacy.dns_fwd_degraded, true, "legacy forward FAIL migrates as degraded")
eq(cache["dns_fwd:crawler.example.test"], "TEMP",
   "legacy forward FAIL is rewritten to short TEMP")
eq(writes[#writes].ttl, 10, "legacy forward FAIL migration retries soon")

reset("success")
local g = ctx(); dns.run(g)
eq(g.good_bot_verified, true, "forward IP match verifies bot")
eq(g.bot_score, 0.0, "verified bot score zero")
ok((cache["dns_fwd:crawler.example.test"] or ""):find("203.0.113.10", 1, true),
   "success cache stores address")

-- Reverse lookup uses the same semantic cache split. Infrastructure failures
-- are short-lived and neutral; NXDOMAIN remains an authoritative negative.
do
    local rev_mode
    cache, writes, query_calls = {}, {}, 0
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function(k) return cache[k] end,
        safe_set = function(k, v, ttl)
            cache[k] = v
            writes[#writes + 1] = { key = k, value = v, ttl = ttl }
            return true
        end,
    }
    package.loaded["resty.dns.resolver"] = {
        new = function()
            if rev_mode == "init_fail" then return nil, "resolver init failed" end
            local r = { TYPE_PTR = 12 }
            function r:query()
                query_calls = query_calls + 1
                if rev_mode == "timeout" then return nil, "timeout" end
                if rev_mode == "nxdomain" then return { errcode = 3 }, nil end
                return { { type = self.TYPE_PTR, ptrdname = "crawler.example.test" } }
            end
            return r
        end,
    }
    local rev = assert(loadfile(src .. "detection/bot/dns_reverse.lua"))()

    rev_mode = "timeout"
    local ra = { good_bot_claimed = true, ip = "203.0.113.10" }
    rev.run(ra)
    eq(cache["dns_ptr:203.0.113.10"], "TIMEOUT", "reverse timeout has own token")
    eq(writes[#writes].ttl, 10, "reverse timeout cache is short")
    eq(ra.dns_rev_timeout, true, "reverse timeout is neutral")

    cache, writes, query_calls = {}, {}, 0
    rev_mode = "init_fail"
    local rb = { good_bot_claimed = true, ip = "203.0.113.11" }
    rev.run(rb)
    eq(cache["dns_ptr:203.0.113.11"], "TEMP", "reverse resolver failure is TEMP")
    eq(writes[#writes].ttl, 10, "reverse TEMP cache is short")
    eq(rb.dns_rev_degraded, true, "reverse TEMP sets degraded")

    cache, writes, query_calls = {}, {}, 0
    rev_mode = "nxdomain"
    local rc = { good_bot_claimed = true, ip = "203.0.113.12" }
    rev.run(rc)
    eq(cache["dns_ptr:203.0.113.12"], "NXDOMAIN", "reverse NXDOMAIN is semantic")
    eq(writes[#writes].ttl, 300, "reverse NXDOMAIN keeps normal negative TTL")
    eq(rc.dns_rev_valid, false, "reverse NXDOMAIN is verification failure")

    cache = { ["dns_ptr:203.0.113.13"] = "FAIL" }
    writes, query_calls = {}, 0
    rev_mode = "success"
    local rd = { good_bot_claimed = true, ip = "203.0.113.13" }
    rev.run(rd)
    eq(rd.dns_rev_degraded, true, "legacy reverse FAIL migrates as degraded")
    eq(query_calls, 0, "legacy reverse FAIL cache avoids immediate requery")
end

io.write(string.format("goodbot_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
