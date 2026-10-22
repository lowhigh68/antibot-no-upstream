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
package.loaded["antibot.core.decision"] = {
    set = function() return true end,
}
local resty_md5 = ngx.md5
package.loaded["antibot.core.goodbot_registry"] =
    assert(loadfile(src .. "core/goodbot_registry.lua"))()

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

    -- Cookie o scenario nay LA mot ve hop le (`verified:human-cookie` = "1"),
    -- nen ca nay chinh la su kien an ninh dang dem: crawler giu ve that.
    eq(crawler.verified_human_bot_held_cookie, true,
       "crawler holding a live verified ticket is recorded separately")

    local contact = {
        ip = "203.0.113.10",
        ua = "ChatGPT-User/1.0; +https://openai.com/bot",
    }
    local contact_hit = resolver.check_cookie(contact)
    eq(contact_hit, false,
       "RFC contact automation cannot use the verified-human lane")
    eq(contact.verified_human_rejected_bot_claim, true,
       "contact automation rejection keeps provenance")

    -- Bat bien con lai sau khi them phep doc: khong co cookie thi KHONG cham
    -- Redis. Hot path cua crawler thong thuong (Googlebot khong cookie) van
    -- khong tra chi phi nao.
    ngx.var.cookie_antibot_fp = nil
    local nocookie_before = gets
    local bare = { ip = "203.0.113.11", ua = "Googlebot/2.1" }
    local bare_hit, bare_reason = resolver.check_cookie(bare)
    eq(bare_hit, false, "crawler without cookie is still rejected")
    eq(bare_reason, "crawler_claim", "rejection reason unchanged")
    eq(bare.verified_human_rejected_bot_claim, true,
       "claim provenance still set without a cookie")
    eq(bare.verified_human_bot_held_cookie, nil,
       "no ticket means no security event")
    eq(gets, nocookie_before,
       "crawler without cookie never reaches Redis")

    -- Va mot ve KHONG con hieu luc cung khong phai su kien.
    ngx.var.cookie_antibot_fp = "stale-cookie"
    local stale = { ip = "203.0.113.12", ua = "Googlebot/2.1" }
    resolver.check_cookie(stale)
    eq(stale.verified_human_bot_held_cookie, nil,
       "an expired ticket is not counted as held")
    ngx.var.cookie_antibot_fp = "human-cookie"
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
            ctx.good_bot_registered = true
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
    local monitor_values = {}
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function(k) return monitor_values[k] end,
        safe_incr = function() return 1 end,
    }
    package.loaded["antibot.core.operator_network"] =
        assert(loadfile(src .. "core/operator_network.lua"))()
    package.loaded["antibot.l7.automation_guard"] = {
        evaluate = function() return true, false end,
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

    monitor_values["mon:203.0.113.20"] = "claim@openai.com"
    local claim_only_ip = {
        score = 100, score_multiplier = 1, req_class = "navigation",
        fp_quality = 1, sess_len = 0, ua = "ordinary-client",
        ip = "203.0.113.20", req = { method = "GET", uri = "/" },
    }
    eq(engine.run(claim_only_ip), "block",
       "AI provider CIDR alone cannot cap an unrelated request")

    monitor_values["mon:203.0.113.21"] = "ipcap@uptrends.com"
    local uptime = {
        score = 100, score_multiplier = 1, req_class = "navigation",
        fp_quality = 1, sess_len = 0, ua = "Mozilla/5.0",
        ip = "203.0.113.21", req = { method = "GET", uri = "/" },
    }
    eq(engine.run(uptime), "monitor",
       "published uptime probes preserve the legacy IP-only cap")

    monitor_values["mon:203.0.113.22"] = "claim@openai.com"
    local bound_ai = {
        score = 100, score_multiplier = 1, req_class = "navigation",
        fp_quality = 1, sess_len = 0, ua = "ChatGPT-User/1.0",
        ip = "203.0.113.22", req = { method = "GET", uri = "/" },
        operator_network_verified = true,
        operator_network_name = "openai.com",
        operator_network_mode = "claim",
    }
    eq(engine.run(bound_ai), "monitor",
       "claim-bound AI network caps only after identity binding")
end

-- 5. Tier-2 shared-IP immunity requires first-party cookie evidence on a
-- mature host, while nil registry state preserves the legacy behavior. The
-- legacy population remains independent because the mobile-farm challenge
-- policy is outside P1.1 and must not change as a side effect.
do
    local current, calls
    local red = {}
    function red:init_pipeline() calls = {} end
    function red:pfadd(k, v) calls[#calls + 1] = { "pfadd", k, v } end
    function red:expire(k, ttl) calls[#calls + 1] = { "expire", k, ttl } end
    function red:pfcount(k) calls[#calls + 1] = { "pfcount", k } end
    function red:commit_pipeline()
        local out = {}
        for i, op in ipairs(calls) do
            if op[1] ~= "pfcount" then
                out[i] = 1
            elseif op[2]:find("iptour:dom:", 1, true) == 1 then
                out[i] = current.domains or 1
            elseif op[2]:find("iptour:ua:", 1, true) == 1 then
                out[i] = current.uas or 6
            elseif op[2]:find("iptour:ver:", 1, true) == 1 then
                out[i] = current.real_users or 0
            elseif op[2]:find("iptour:known:", 1, true) == 1 then
                out[i] = current.known_users or 0
            end
        end
        return out
    end

    package.loaded["antibot.core.config"] = {
        ip_tour = {
            enabled = true, window = 90, distinct_domains = 5,
            distinct_ua_max = 3, shared_ua_min = 6,
            ban_immune_real_min = 3, farm_ua_min = 15,
            tier2_migration_grace = 0,
            farm_cookie_ratio_max = 0.15, richness_max = 0.5,
            strike_ban = 12, ban_ttl = 300, ban_ttl_repeat = 3600,
        },
    }
    package.loaded["antibot.core.redis_pool"] = {
        get = function() return red end,
        put = function() end,
        safe_incr = function() return 0 end,
    }
    package.loaded["antibot.core.ip_scope"] = { is_self = function() return false end }
    package.loaded["antibot.detection.bot.ua_claim"] = {
        claims_good_bot = function() return false end,
    }
    local clock = 1700000000
    ngx = {
        WARN = 2, INFO = 1, log = function() end, md5 = resty_md5,
        time = function() return clock end,
        var = { host = "tenant.test", http_cookie = "wordpress_logged_in=x" },
    }
    local ip_tour = assert(loadfile(src .. "detection/ip_tour.lua"))()

    local function run_case(c, runner)
        current = c
        local ctx = {
            ip = c.ip or "203.0.113.50", ua = "Mozilla/5.0",
            req = { host = "tenant.test" },
            session_richness = c.richness or 0.8,
            session_cookie_known = c.cookie_known,
        }
        (runner or ip_tour).run(ctx)
        return ctx, calls
    end

    local known, known_calls = run_case {
        cookie_known = true, real_users = 3, known_users = 3, uas = 6,
    }
    eq(known.ip_shared_verified, true,
       "known first-party population grants Tier-2 immunity")
    eq(known.ip_tier2_cookie_evidence, "known",
       "known evidence provenance is explicit")
    local wrote_known = false
    for _, call in ipairs(known_calls) do
        if call[1] == "pfadd" and call[2]:find("iptour:known:", 1, true) == 1 then
            wrote_known = true
        end
    end
    eq(wrote_known, true, "known cookie enters strict HLL")

    local arbitrary, arbitrary_calls = run_case {
        ip = "203.0.113.51", cookie_known = false,
        real_users = 3, known_users = 0, uas = 15,
    }
    eq(arbitrary.ip_shared_verified, false,
       "arbitrary cookie cannot buy Tier-2 immunity on mature host")
    eq(arbitrary.ip_tier2_cookie_evidence, "rejected",
       "rejected cookie evidence is distinguishable")
    local arbitrary_wrote_known = false
    for _, call in ipairs(arbitrary_calls) do
        if call[1] == "pfadd" and call[2]:find("iptour:known:", 1, true) == 1 then
            arbitrary_wrote_known = true
        end
    end
    eq(arbitrary_wrote_known, false, "arbitrary cookie never enters strict HLL")
    eq(arbitrary.ip_farm_suspect, false,
       "P1.1 leaves legacy farm ratio semantics unchanged")

    local immature, immature_calls = run_case {
        ip = "203.0.113.52", cookie_known = nil,
        real_users = 3, known_users = 3, uas = 6,
    }
    eq(immature.ip_shared_verified, true,
       "immature cookie registry preserves legacy Tier-2 protection")
    eq(immature.ip_tier2_cookie_evidence, "legacy",
       "nil registry fallback is observable")
    local fallback_wrote_known = false
    for _, call in ipairs(immature_calls) do
        if call[1] == "pfadd" and call[2]:find("iptour:known:", 1, true) == 1 then
            fallback_wrote_known = true
        end
    end
    eq(fallback_wrote_known, true, "nil registry state seeds compatibility HLL")

    package.loaded["antibot.core.config"].ip_tour.tier2_migration_grace = 90
    local rollout = assert(loadfile(src .. "detection/ip_tour.lua"))()
    local warming = run_case({
        ip = "203.0.113.53", cookie_known = false,
        real_users = 3, known_users = 0, uas = 6,
    }, rollout)
    eq(warming.ip_tier2_warming, true, "new strict HLL gets one-window rollout grace")
    eq(warming.ip_shared_verified, true,
       "rollout grace does not abruptly revoke existing legacy immunity")

    clock = clock + 91
    local strict = run_case({
        ip = "203.0.113.53", cookie_known = false,
        real_users = 3, known_users = 0, uas = 6,
    }, rollout)
    eq(strict.ip_tier2_warming, false, "rollout grace expires without dual-read tail")
    eq(strict.ip_shared_verified, false,
       "after grace only first-party cardinality grants Tier-2 immunity")
end

io.write(string.format("trust_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
