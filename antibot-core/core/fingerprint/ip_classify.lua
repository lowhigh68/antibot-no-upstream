local _M   = {}
local pool = require "antibot.core.redis_pool"

-- IP type classification using GeoLite2-ASN data (already available in ctx.asn)
-- and Redis overrides.
--
-- NO provider names or company names are hardcoded.
--
-- Classification uses two sources, in priority order:
--
--   1. Redis key  asn:type:{asn_number}
--      Admin or threat feed sets this for edge cases not detectable from asn_org.
--      Values: "datacenter" | "vpn" | "tor" | "residential" | "business"
--
--   2. asn_org functional keyword analysis (from GeoLite2-ASN.mmdb, already
--      loaded by asn.lua into ctx.asn.asn_org)
--      These are generic service-type terms, not brand names:
--        - "CLOUD", "HOSTING", "VPS", "COLO", "DATACENTER" → datacenter
--        - "TELECOM", "MOBILE", "BROADBAND", "CABLE", "DSL" → residential
--      These terms describe WHAT the network does, not WHO runs it.
--      Any new datacenter or ISP will use these same industry-standard terms.
--
-- Results are cached in ngx.shared.antibot_cache (TTL 300s) to avoid a
-- Redis round-trip on every request for the same ASN.

local ASN_CACHE_TTL = 300

local TYPE_SCORE = {
    tor         = 0.95,
    vpn         = 0.80,
    datacenter  = 0.60,
    hosting     = 0.60,
    business    = 0.30,
    residential = 0.00,
}

-- Generic functional terms that describe the SERVICE TYPE of the network.
-- These are industry-standard terms that appear across all providers.
-- A cloud provider always describes itself with these terms regardless of brand.
local DATACENTER_TERMS = {
    "CLOUD", "HOSTING", "VPS", "COLO", "COLOCATION",
    "DATACENTER", "DATA%-CENTER", "SERVER", "DEDICATED",
}

-- Terms that indicate consumer/residential internet service.
-- A retail ISP always describes its service with these terms.
local RESIDENTIAL_TERMS = {
    "TELECOM", "MOBILE", "BROADBAND", "CABLE",
    "DSL", "WIRELESS", "CELLULAR", "FIBER",
}

local shared_cache = ngx.shared.antibot_cache

local function cache_get(key)
    if not shared_cache then return nil end
    return shared_cache:get(key)
end

local function cache_set(key, val)
    if not shared_cache then return end
    shared_cache:set(key, val, ASN_CACHE_TTL)
end

local function classify_from_redis(asn_number)
    if not asn_number then return nil end
    local cache_key = "asn_type:" .. tostring(asn_number)

    local cached = cache_get(cache_key)
    if cached then return cached end

    local val = pool.safe_get("asn:type:" .. tostring(asn_number))
    if val and val ~= "" then
        cache_set(cache_key, val)
        return val
    end

    return nil
end

local function classify_from_asn_org(asn_org)
    -- Analyse the asn_org string from GeoLite2-ASN for service-type keywords.
    -- The org name is the authoritative self-description of the network operator.
    if not asn_org or asn_org == "" then return nil end

    local upper = asn_org:upper()

    -- Datacenter/cloud service indicators
    for _, term in ipairs(DATACENTER_TERMS) do
        if upper:find(term) then
            return "datacenter"
        end
    end

    -- Consumer ISP indicators
    for _, term in ipairs(RESIDENTIAL_TERMS) do
        if upper:find(term) then
            return "residential"
        end
    end

    -- No recognisable service-type keyword: cannot determine type from name alone.
    -- Return nil so the caller defaults to residential (fail open).
    return nil
end

function _M.run(ctx)
    ctx.ip_type = {
        is_datacenter  = false,
        is_vpn         = false,
        is_tor         = false,
        is_residential = true,
        source         = "default",
    }
    ctx.ip_score = 0.0

    local asn_number = ctx.asn and ctx.asn.asn_number
    local asn_org    = ctx.asn and ctx.asn.asn_org

    -- Priority 1: Redis override (admin or threat feed)
    local itype = classify_from_redis(asn_number)
    if itype then
        ctx.ip_type.source = "redis"
    else
        -- Priority 2: asn_org functional keyword analysis (GeoLite2-ASN data)
        itype = classify_from_asn_org(asn_org)
        if itype then
            ctx.ip_type.source = "asn_org"
        end
    end

    -- Default: residential (benefit of the doubt when unknown)
    itype = itype or "residential"

    ctx.ip_type.type  = itype
    ctx.ip_score      = TYPE_SCORE[itype] or 0.0

    if itype == "tor" then
        ctx.ip_type.is_tor         = true
        ctx.ip_type.is_residential = false
    elseif itype == "vpn" then
        ctx.ip_type.is_vpn         = true
        ctx.ip_type.is_residential = false
    elseif itype == "datacenter" or itype == "hosting" then
        ctx.ip_type.is_datacenter  = true
        ctx.ip_type.is_residential = false
    elseif itype == "business" then
        ctx.ip_type.is_residential = false
    end

    if ctx.ip_score > 0 then
        ngx.log(ngx.DEBUG,
            "[ip_classify] ip=", ctx.ip,
            " asn=", tostring(asn_number),
            " org=", tostring(asn_org),
            " type=", itype,
            " source=", ctx.ip_type.source,
            " score=", ctx.ip_score)
    end

    return true, false
end

return _M
