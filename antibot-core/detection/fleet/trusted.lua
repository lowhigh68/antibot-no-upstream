local _M  = {}
local cfg = require "antibot.core.config"

-- Trusted ASN allowlist — SKIPS fleet aggregation entirely.
-- Performance optimization only: detection correctness is independent of
-- this list. ASNs listed serve high-volume legitimate Vietnamese / SEA
-- consumer traffic; skipping saves ~5 Redis ops per request.
--
-- An ASN that turns out to host a fleet (false negative) is acceptable
-- in v1 — operator can remove the entry to re-enable aggregation.

local function asn_table()
    local fd = cfg.fleet_detection or {}
    return fd.trusted_asn or {}
end

function _M.is_trusted(ctx)
    if not ctx.asn or not ctx.asn.asn_number then
        return false
    end
    return asn_table()[ctx.asn.asn_number] ~= nil
end

-- Good search-engine crawler ASNs — legit distributed crawler fleets are
-- STRUCTURALLY identical to bot fleets (many IPs / few fingerprints / path
-- convergence / no cookies), so they false-trigger fleet and get their /16
-- dyn-blocked = SEO disaster (observed: Googlebot/Bingbot ranges at risk;
-- Meta's 57.141.0.0/16 was actively dyn-blocked).
--
-- Gate requires BOTH the ASN AND a self-declared crawler UA — REQUIRED because
-- AS8075 (Bing) also hosts Azure, so ASN alone would whitelist cloud-hosted
-- scrapers on that ASN. With the UA-claim requirement, a browser-UA scraper on
-- Azure is NOT exempt (fleet still catches it); a UA-spoofing fake Googlebot is
-- caught downstream by DNS reverse verification.
--
-- Meta AS32934 INCLUDED (operator policy B): meta-externalagent DOES verify
-- (prod log: good_bot_verified + ASN-lite on 57.141.0.0/16 = AS32934, both via
-- ASN fallback so PTR timeouts don't matter), so instead of fleet's oscillating
-- /16 block we exempt it from fleet and let the good_bot_rate throttle cap it
-- at a CONSISTENT per-bot-name global rate (engine.lua gb_rate:<bot>:<minute>).
-- That throttle is rotation-proof: every IP in Meta's rotating pool increments
-- the SAME key, so fast IP rotation shares one budget, it can't be multiplied.
-- A UA=meta-external SPOOFER cannot originate from AS32934 (Meta's own ASN), so
-- it fails this gate → stays subject to fleet + scoring. No gap.
local GOOD_CRAWLER_ASN = {
    [15169]  = "google",
    [8075]   = "bing",
    [135905] = "coccoc",
    [714]    = "apple",
    [6185]   = "apple",
    [2709]   = "apple",
    [32934]  = "meta",
}

-- Also matches the Meta crawler family, whose UAs carry no bot/spider/crawler
-- token (meta-externalagent, meta-externalfetcher, facebookexternalhit). Safe
-- because is_good_crawler ALSO requires the matching ASN (AS32934 = Meta-only).
local function ua_claims_good_bot(ua)
    if not ua or ua == "" then return false end
    local ul = ua:lower()
    return ul:find("bot", 1, true) ~= nil
        or ul:find("spider", 1, true) ~= nil
        or ul:find("crawler", 1, true) ~= nil
        or ul:find("meta-external", 1, true) ~= nil
        or ul:find("facebookexternalhit", 1, true) ~= nil
end

-- Exempt legit search-engine crawlers from fleet aggregation. Needs ctx.asn,
-- which is now resolved in STEPS_COMMON before the aggregator runs.
function _M.is_good_crawler(ctx)
    if not ctx.asn or not ctx.asn.asn_number then return false end
    if not GOOD_CRAWLER_ASN[ctx.asn.asn_number] then return false end
    return ua_claims_good_bot(ctx.ua)
end

function _M.label(asn_number)
    return asn_table()[asn_number]
end

return _M
