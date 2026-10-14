-- Behavioral contracts for the trust boundaries shared by root/access,
-- session richness and good-bot ASN policy.

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
local resty_md5 = ngx.md5

-- 1. Root and access share one verified-human cookie resolver. A crawler UA
-- is rejected before Redis even when it carries a valid human cookie.
do
    local kv = { ["verified:human-cookie"] = "1" }
    local gets, sets = 0, {}
    package.loaded["antibot.core.config"] = { ttl = { verified = 7200 } }
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function(k) gets = gets + 1; return kv[k] end,
        safe_set = function(k, v, ttl)
            kv[k] = v; sets[#sets + 1] = { k, v, ttl }; return true
        end,
    }
    package.loaded["antibot.core.fingerprint.identity"] = {
        build_from = function() return "early-id" end,
    }
    package.loaded["antibot.detection.bot.ua_claim"] =
        assert(loadfile(src .. "detection/bot/ua_claim.lua"))()
    ngx = {
        DEBUG = 0, log = function() end,
        var = {
            cookie_antibot_fp = "human-cookie",
            http_user_agent = "Mozilla/5.0 Chrome/120.0",
        },
    }
    local resolver = assert(loadfile(src .. "core/access/verified_human.lua"))()

    local human = { ip = "203.0.113.10", ua = ngx.var.http_user_agent }
    local hit, id = resolver.check_cookie(human)
    eq(hit, true, "human cookie is accepted")
    eq(id, "human-cookie", "human cookie id is returned")
    eq(human.identity, "human-cookie", "human identity is populated")

    local before = gets
    local crawler = { ip = "203.0.113.10", ua = "Googlebot/2.1" }
    local bot_hit, reason = resolver.check_cookie(crawler)
    eq(bot_hit, false, "crawler claim cannot use human cookie")
    eq(reason, "crawler_claim", "crawler rejection has explicit reason")
    eq(crawler.verified_human_rejected_bot_claim, true,
       "crawler rejection provenance is retained")
    eq(gets, before, "crawler gate runs before verified Redis lookup")
end

-- 2. Richness persistence uses early identity, not raw IP. Two browser majors
-- behind one CGNAT do not inherit trust; the same normalized UA still does.
do
    local store, reads, writes = {}, {}, {}
    package.loaded["antibot.core.cookie_registry"] = {
        known = function() return nil end,
    }
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function(k) reads[#reads + 1] = k; return store[k] end,
        safe_set = function(k, v, ttl)
            store[k] = v; writes[#writes + 1] = { k, v, ttl }; return true
        end,
    }
    local identity = assert(loadfile(src .. "core/fingerprint/identity.lua"))()
    package.loaded["antibot.core.fingerprint.identity"] = identity
    ngx = {
        DEBUG = 0, md5 = resty_md5, log = function() end,
        var = {},
    }
    local richness = assert(loadfile(src .. "core/session_richness.lua"))()
    local ip = "203.0.113.44"
    local ua120 = "Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0.1 Safari/537.36"
    local ua121 = "Mozilla/5.0 AppleWebKit/537.36 Chrome/121.0.1 Safari/537.36"

    ngx.var.http_cookie = "a=" .. string.rep("x", 520) .. "; b=1; c=1; d=1"
    local a = { ip = ip, ua = ua120 }
    richness.run(a)
    local id120 = identity.build_from(ip, ua120)
    ok(store["richness:max:" .. id120] ~= nil,
       "richness is persisted by early identity")
    eq(store["richness:max:" .. ip], nil,
       "raw IP richness key is never written")

    ngx.var.http_cookie = ""
    local b = { ip = ip, ua = ua121 }
    richness.run(b)
    eq(b.session_richness, 0, "different UA on same CGNAT inherits no richness")

    local c = {
        ip = ip,
        ua = "Mozilla/5.0 AppleWebKit/537.36 Chrome/120.9.9 Safari/537.36",
    }
    richness.run(c)
    ok(c.session_richness >= 0.7,
       "same normalized UA retains cross-domain richness")
    eq(c.session_richness_own, 0,
       "inherited richness does not become own request state")
end

-- 3. Shared-cloud ASN cannot directly verify a bot. Resource lane may use a
-- positive DNS-derived crawler mark; dedicated ASN behavior stays unchanged.
do
    local asn_policy = assert(loadfile(src .. "detection/bot/asn_policy.lua"))()
    eq(asn_policy.is_corroborative(15169), true, "AS15169 is corroborative")
    eq(asn_policy.is_corroborative(8075), true, "AS8075 is corroborative")
    eq(asn_policy.is_corroborative(32934), false, "AS32934 remains dedicated")
    package.loaded["antibot.detection.bot.asn_policy"] = asn_policy

    local expected, actual, known
    package.loaded["antibot.detection.bot.ua_check"] = {
        run = function(ctx)
            ctx.good_bot_claimed = true
            ctx.good_bot_name = "fixturebot"
            ctx.good_bot_asns = expected
            ctx.bot_score = 0
            return true, false
        end,
    }
    package.loaded["antibot.core.fingerprint.asn"] = {
        run = function(ctx) ctx.asn = { asn_number = actual }; return true, false end,
    }
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function(k)
            if k == "crawler:203.0.113.10" then return known end
        end,
        safe_set = function() return true end,
    }
    ngx = {
        WARN = 2, log = function() end,
        var = { uri = "/asset.css" },
    }
    local lite = assert(loadfile(src .. "detection/bot/lite_verify.lua"))()

    expected, actual, known = { 15169 }, 15169, nil
    local a = { ip = "203.0.113.10", asn = { asn_number = actual } }
    lite.run(a)
    eq(a.good_bot_verified, nil, "shared ASN alone does not lite-verify")
    eq(a.bot_lite_needs_full, true, "shared ASN resource escalates to full DNS")

    expected, actual, known = { 15169 }, 15169, "1"
    local b = { ip = "203.0.113.10", asn = { asn_number = actual } }
    lite.run(b)
    eq(b.good_bot_verified, true, "positive crawler cache permits resource lane")
    eq(b.action_reason, "good_bot_cached_lite", "cached proof is observable")

    expected, actual, known = { 32934 }, 32934, nil
    local c = { ip = "203.0.113.10", asn = { asn_number = actual } }
    lite.run(c)
    eq(c.good_bot_verified, true, "dedicated ASN retains direct verification")
end

-- 4. Full lane: shared ASN + resolver failure is neutral/degraded, dedicated
-- ASN still verifies, and only the degraded shared case receives monitor cap.
do
    local expected, dns_behavior, bot_writes = nil, "timeout", {}
    package.loaded["antibot.detection.bot.ua_check"] = {
        run = function(ctx)
            ctx.good_bot_claimed = true
            ctx.good_bot_name = "fixturebot"
            ctx.good_bot_asns = expected
            ctx.good_bot_suffixes = { "example.test" }
            ctx.bot_score = 0
            return true, false
        end,
        is_valid_suffix = function() return true end,
    }
    package.loaded["antibot.detection.bot.dns_reverse"] = {
        run = function(ctx)
            if dns_behavior == "timeout" then
                ctx.dns_rev_timeout = true
                ctx.dns_rev_valid = nil
            else
                ctx.dns_rev_valid = false
                ctx.dns_rev_nxdomain = true
            end
            return true, false
        end,
        lookup_ptr = function() return nil, "TIMEOUT" end,
    }
    package.loaded["antibot.detection.bot.dns_forward"] = {
        run = function() return true, false end,
    }
    package.loaded["antibot.detection.bot.bot_score"] = {
        run = function() return true, false end,
    }
    package.loaded["antibot.detection.bot.cloud_suffixes"] = {
        CLOUD_PTR_SUFFIXES = {}, BROWSER_STANDARD_TOKENS = {},
    }
    package.loaded["antibot.core.redis_pool"] = {
        safe_set = function(k)
            bot_writes[#bot_writes + 1] = k
            return true
        end,
    }
    ngx = { INFO = 1, ERR = 3, log = function() end }
    local bot = assert(loadfile(src .. "detection/bot/init.lua"))()

    expected = { 15169 }
    local shared = {
        ip = "203.0.113.10", asn = { asn_number = 15169 },
        identity = "shared-timeout", ban_deferred_gb = true,
    }
    bot.run(shared)
    ok(shared.good_bot_verified ~= true,
       "shared ASN is not full-lane verification")
    eq(shared.good_bot_dns_degraded, true,
       "resolver failure remains neutral/degraded")
    eq(shared.good_bot_shared_asn_degraded, true,
       "matching shared ASN marks monitor-cap eligibility")
    local sealed = false
    for _, key in ipairs(bot_writes) do
        if key == "botverdict:fake:shared-timeout" then sealed = true end
    end
    eq(sealed, false, "DNS infrastructure failure never writes fake verdict seal")

    dns_behavior = "nxdomain"
    expected = { 15169 }
    local semantic = {
        ip = "203.0.113.12", asn = { asn_number = 15169 },
    }
    bot.run(semantic)
    eq(semantic.bot_ua, "fake_good_bot",
       "shared ASN does not rescue authoritative NXDOMAIN")
    ok(semantic.good_bot_shared_asn_degraded ~= true,
       "semantic DNS failure is not eligible for monitor cap")

    dns_behavior = "timeout"
    expected = { 32934 }
    local dedicated = { ip = "203.0.113.11", asn = { asn_number = 32934 } }
    bot.run(dedicated)
    eq(dedicated.good_bot_verified, true,
       "dedicated ASN still verifies during DNS timeout")

    package.loaded["antibot.core.config"] = {
        thresholds = { monitor = 25, challenge = 55, block = 80 },
        trust = {
            session_flag_max = 0.5, session_min = 10,
            session_active_min = 3, score_multiplier = 0.7,
            score_mult_active = 0.85, action_cap = "monitor",
        },
        rate = { good_bot_rate = {
            classes = { default = 40 }, map = {},
            promotion_threshold_1 = 10, promotion_threshold_2 = 30,
            aggression_decay_ttl = 600, retry_after = 60,
        } },
    }
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function() return nil end,
        safe_incr = function() return 1 end,
    }
    ngx = {
        INFO = 1, WARN = 2, log = function() end,
        time = function() return 1700000000 end,
        var = { uri = "/", antibot_debug = "0" },
        header = {}, say = function() end, exit = function() end,
    }
    local engine = assert(loadfile(src .. "enforcement/decision/engine.lua"))()
    local guarded = {
        score = 100, score_multiplier = 1, req_class = "navigation",
        fp_quality = 1, sess_len = 0, ua = "Googlebot/2.1",
        ip = "203.0.113.10", asn = { asn_number = 15169 },
        req = { method = "GET", uri = "/" },
        good_bot_shared_asn_degraded = true,
    }
    eq(engine.run(guarded), "monitor",
       "shared-ASN DNS infrastructure failure is capped at monitor")
    eq(guarded.action_reason, "good_bot_dns_degraded_cap",
       "monitor cap reason is explicit")

    local control = {
        score = 100, score_multiplier = 1, req_class = "navigation",
        fp_quality = 1, sess_len = 0, ua = "Googlebot/2.1",
        ip = "203.0.113.10", asn = { asn_number = 15169 },
        req = { method = "GET", uri = "/" },
    }
    eq(engine.run(control), "block",
       "shared ASN without infrastructure-failure proof receives no cap")
end

io.write(string.format("trust_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
