local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- IP-Tour detector — antibot's structural advantage on shared hosting.
--
-- Every tenant domain funnels through the same OpenResty + same Redis, so a
-- single IP hammering domainA, domainB, domainC... is visible HERE in a way NO
-- per-site WAF (each customer's mod_security/Wordfence) can ever see — site A
-- literally cannot know the same IP is also hitting sites B, C, D on the box.
--
-- Attack shape (operator-confirmed): a few bot IPs "tour" across many domains
-- on the shared host, each domain at only MODERATE req/s, occasionally hitting
-- expensive endpoints (wp-admin, login). Per-IP rate stays under ip_surge, per
-- (IP,domain) rate stays under burst → every per-IP / per-domain defense is
-- blind, yet aggregate load on the shared PHP-FPM + MySQL spikes. This module
-- catches the one invariant the attacker can't hide: one source touching many
-- distinct tenant domains in a short window.
--
-- SIGNAL, not a hard block: sets ctx.ip_tour. The enforcement decision is made
-- in enforcement/decision/engine.lua AFTER the good_bot_verified short-circuit,
-- so verified crawlers (Googlebot/Bingbot legitimately crawl every domain) are
-- exempt automatically — no per-bot config needed. Engine floors ip_tour to
-- `challenge` (challenge-first).
--
-- Discriminators (ALL must hold to flag):
--   distinct_domains >= cfg.ip_tour.distinct_domains  — touring
--   distinct_ua      <  cfg.ip_tour.distinct_ua_max   — single-source. NAT gate:
--       an office/CGNAT hitting many domains ALSO carries many UAs → not flagged;
--       one bot touring carries 1-2 UAs. (identity isn't available this early in
--       STEPS_COMMON, so distinct-UA is the NAT proxy.)
--   session_richness <  cfg.ip_tour.richness_max      — a logged-in multi-site
--       admin managing their own domains has rich cookies → exempt.
--
-- distinct-domain is a CARDINALITY, not a request count: a real user browsing
-- ONE site for hours stays at domain_count=1 forever → zero FP on long sessions,
-- unlike a request-rate counter which drifts upward with session length.
--
-- Ban-if-repeat: each flagged request increments iptour:strike:<ip>. A real
-- user who is challenged solves the PoW → gets verified cookie → cookie
-- fast-path in init.lua → never re-enters this module → strikes stop within a
-- handful. A bot can't solve PoW → keeps touring → strikes cross strike_ban →
-- direct ban:<ip> (sealed at the door by l7/ban/ip_ban_check on EVERY domain).
-- Direct-ban is gated on NOT ua_claims_good_bot so an IP claiming Googlebot is
-- never hard-banned here — real ones verify via DNS + bypass scoring, spoofers
-- get the ip_tour signal plus DNS-fail scoring.
--
-- Storage (Redis HLL — same primitive detection/distributed_swarm.lua uses):
--   iptour:dom:<ip>    PFADD host      → PFCOUNT = distinct domains
--   iptour:ua:<ip>     PFADD md5(ua)   → PFCOUNT = distinct UAs (NAT gate)
--   iptour:strike:<ip> INCR            → ban-if-repeat counter
--   iptour:age:<ip>    first-ban stamp → TTL escalation on repeat
-- Counting is one pipeline / request (6 ops, 1 RTT). Fail-open on Redis error.

local function ua_claims_good_bot(ua)
    if not ua or ua == "" then return false end
    local ul = ua:lower()
    return ul:find("bot", 1, true) ~= nil
        or ul:find("spider", 1, true) ~= nil
        or ul:find("crawler", 1, true) ~= nil
        or ul:find("facebookexternal", 1, true) ~= nil
        or ul:find("mediapartners", 1, true) ~= nil
        or ul:find("bingpreview", 1, true) ~= nil
        or ul:match("meta%-external") ~= nil
end

function _M.run(ctx)
    local c = cfg.ip_tour
    if not c or c.enabled == false then return true, false end

    -- Whitelisted (LAN/admin/loopback) already resolved by access_layer, which
    -- runs before this step in STEPS_COMMON. Never count or ban them.
    if ctx.whitelisted then return true, false end

    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    local host = (ctx.req and ctx.req.host) or ngx.var.host
    if not host or host == "" then return true, false end

    local ua     = ctx.ua or ""
    local window = c.window or 90

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[ip_tour] redis unavailable: ", tostring(err))
        return true, false
    end

    local dom_key = "iptour:dom:" .. ip
    local ua_key  = "iptour:ua:" .. ip
    local ver_key = "iptour:ver:" .. ip

    -- Real-user evidence: distinct cookie-bearing identities on this IP. Feeds
    -- the Tier-2 ban-immunity gate — a bot ROTATING UAs on a dedicated IP looks
    -- "shared" by UA count but carries no real cookies, so it must NOT buy
    -- IP-ban immunity. session_richness>0 means the client presents a cookie.
    local has_cookie = (ctx.session_richness or 0) > 0

    red:init_pipeline()
    red:pfadd(dom_key, host)
    red:expire(dom_key, window)
    red:pfadd(ua_key, ngx.md5(ua))
    red:expire(ua_key, window)
    if has_cookie then
        red:pfadd(ver_key, ngx.md5(ngx.var.http_cookie or ""))
        red:expire(ver_key, window)
    end
    -- 3 PFCOUNTs LAST so their indices are deterministic (#res-2/-1/0)
    -- regardless of the conditional ver PFADD above.
    red:pfcount(dom_key)
    red:pfcount(ua_key)
    red:pfcount(ver_key)
    local res, perr = red:commit_pipeline()
    pool.put(red)

    if not res then
        ngx.log(ngx.WARN, "[ip_tour] pipeline error: ", tostring(perr))
        return true, false
    end

    local n          = #res
    local domains    = tonumber(res[n - 2]) or 0
    local uas        = tonumber(res[n - 1]) or 0
    local real_users = tonumber(res[n])     or 0

    ctx.ip_tour_domains = domains
    ctx.ip_tour_uas     = uas
    ctx.ip_real_users   = real_users

    -- Two-tier shared-IP judgment (mobile CGNAT / mobile farm / office WAN — many
    -- real devices behind one IP; one bad device must not punish the rest).
    --   Tier 1 (lenient, protective): many distinct UAs → dampen per-IP
    --     reputation in compute + skip engine ip_risk threshold-drop. FP here is
    --     harmless, so it is deliberately easy to trip.
    --   Tier 2 (strict, ban-immunity): Tier 1 AND enough distinct cookie-bearing
    --     real users. Grants IP-ban immunity (ban_store_write + risk_update),
    --     which is a PRIVILEGE — so it demands proof of real users. A UA-rotation
    --     bot (cookie=0) trips Tier 1 but NOT Tier 2 → stays IP-bannable.
    -- Bad devices on a shared IP are still caught PER-DEVICE (bot_score/headless/
    -- behaviour/anomaly + per-identity ban:<id>), never by IP guilt.
    ctx.ip_shared = uas >= (c.shared_ua_min or 6)
    ctx.ip_shared_verified = ctx.ip_shared
        and real_users >= (c.ban_immune_real_min or 3)

    local d_min    = c.distinct_domains or 5
    local u_max    = c.distinct_ua_max  or 3
    local r_max    = c.richness_max     or 0.5
    local richness = ctx.session_richness or 0

    -- Gate 1: not touring yet.
    if domains < d_min then return true, false end

    -- Gate 2 (NAT): many domains but many UAs = shared IP of real users.
    if uas >= u_max then
        ngx.log(ngx.INFO,
            "[ip_tour] NAT-gated ip=", ip,
            " domains=", domains, " uas=", uas,
            " (multi-UA shared IP, not single bot)")
        return true, false
    end

    -- Gate 3 (trust): logged-in multi-site admin managing own domains.
    if richness >= r_max then
        ngx.log(ngx.INFO,
            "[ip_tour] richness-exempt ip=", ip,
            " domains=", domains,
            " richness=", string.format("%.2f", richness))
        return true, false
    end

    ctx.ip_tour = true
    ngx.log(ngx.WARN,
        "[ip_tour] TOUR ip=", ip,
        " domains=", domains,
        " uas=", uas,
        " richness=", string.format("%.2f", richness),
        " host=", host,
        " ua=", ua:sub(1, 60))

    -- Ban-if-repeat: only for non-good-bot-claiming UAs. A claimer (real
    -- Googlebot OR spoofer) is never hard-banned here — real ones verify via
    -- DNS and bypass scoring; spoofers still get the ip_tour signal above plus
    -- DNS-fail scoring downstream.
    if not ua_claims_good_bot(ua) then
        local strikes = pool.safe_incr("iptour:strike:" .. ip, window) or 0
        ctx.ip_tour_strikes = strikes
        if strikes >= (c.strike_ban or 12) then
            local age_key = "iptour:age:" .. ip
            local first   = pool.safe_get(age_key)
            local ttl
            if first then
                ttl = c.ban_ttl_repeat or 3600
            else
                pool.safe_set(age_key, tostring(ngx.time()), 86400)
                ttl = c.ban_ttl or 300
            end
            pool.safe_set("ban:" .. ip, "1", ttl)
            pool.safe_set("ban:hit:" .. ip, tostring(ngx.time()), 300)
            ngx.log(ngx.WARN,
                "[ip_tour] BAN ip=", ip,
                " strikes=", strikes,
                " domains=", domains,
                " ttl=", ttl, "s")
        end
    end

    return true, false
end

return _M
