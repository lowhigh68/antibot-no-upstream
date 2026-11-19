-- Host-bound proof that a shared reverse proxy is intentionally serving one
-- origin zone.  A proxy CIDR proves only transport topology; this proof binds
-- that shared edge to the requested DNS zone before any client-IP header is
-- trusted.
--
-- Token: v2.<zone>.<generation>.<HMAC-SHA256(
--                                      secret,
--                                      "origin-proof-v2|rule|zone|generation")>
--
-- A token is static within one generation so an edge Transform Rule can
-- overwrite a header without executing code.  The registry can revoke or
-- replace that generation immediately; secret rotation remains a separate
-- fleet-wide operation requiring worker reload.

local _M = {}

local secrets = require "antibot.core.secrets"

local ffi = require "ffi"
local C   = ffi.C
local bit = require "bit"

pcall(function()
    ffi.cdef([[
        unsigned char *HMAC(const void *evp_md,
                            const void *key, int key_len,
                            const unsigned char *data, size_t data_len,
                            unsigned char *md, unsigned int *md_len);
        const void *EVP_sha256(void);
    ]])
end)

local HMAC_LEN = 32
local valid_cache = {}
local valid_cache_size = 0
local VALID_CACHE_MAX = 512

local function normalize_name(value)
    value = tostring(value or ""):lower():gsub("%.$", "")
    return value
end

local function valid_dns_name(value)
    if type(value) ~= "string" or #value < 1 or #value > 253 then return false end
    if value:find("..", 1, true) or value:sub(1, 1) == "." then return false end
    for label in value:gmatch("[^.]+") do
        if #label < 1 or #label > 63
           or not label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$")
              and not label:match("^[a-z0-9]$") then
            return false
        end
    end
    return true
end

local function host_in_zone(host, zone)
    host = normalize_name(host)
    zone = normalize_name(zone)
    if not valid_dns_name(host) or not valid_dns_name(zone) then return false end
    if host == zone then return true end
    return #host > #zone and host:sub(-#zone - 1) == "." .. zone
end

local function normalize_rule(rule)
    rule = tostring(rule or ""):lower()
    if #rule < 1 or #rule > 64 or not rule:match("^[a-z0-9][a-z0-9_%-]*$") then
        return nil
    end
    return rule
end

local function hmac_sha256(key, data)
    local ok, value = pcall(function()
        local md     = ffi.new("unsigned char[?]", HMAC_LEN)
        local md_len = ffi.new("unsigned int[1]", HMAC_LEN)
        local result = C.HMAC(C.EVP_sha256(), key, #key,
                              data, #data, md, md_len)
        if result == nil or tonumber(md_len[0]) ~= HMAC_LEN then return nil end
        local out = {}
        for i = 0, HMAC_LEN - 1 do
            out[i + 1] = string.format("%02x", md[i])
        end
        return table.concat(out)
    end)
    if not ok then return nil end
    return value
end

local function constant_time_equal(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

local function valid_generation(value)
    return type(value) == "string"
       and #value == 32
       and value:match("^[0-9a-f]+$") ~= nil
end

local function proof_data(rule, zone, generation)
    return "origin-proof-v2|" .. rule .. "|" .. zone .. "|" .. generation
end

local function parse(raw)
    if type(raw) ~= "string" or #raw > 448 then
        return nil, nil, nil, "format"
    end
    local zone, generation, mac = raw:match(
        "^v2%.([a-z0-9.%-]+)%.([0-9a-f]+)%.([0-9a-f]+)$")
    if not zone or #mac ~= 64 or not valid_dns_name(zone)
       or not valid_generation(generation) then
        return nil, nil, nil, "format"
    end
    return zone, generation, mac, nil
end

local function verify_signature(raw, rule)
    local cache_key = rule .. "|" .. raw
    local cached = valid_cache[cache_key]
    if cached then return cached.zone, cached.generation, cached.kind end

    local zone, generation, mac, parse_err = parse(raw)
    if not zone then return nil, nil, parse_err end

    local keys, key_err = secrets.origin_proof_secrets()
    if not keys then return nil, nil, key_err or "secret_unavailable" end
    local data = proof_data(rule, zone, generation)
    local expected = hmac_sha256(keys.current, data)
    local kind
    if expected and constant_time_equal(expected, mac) then
        kind = "signed_current"
    elseif keys.previous then
        expected = hmac_sha256(keys.previous, data)
        if expected and constant_time_equal(expected, mac) then
            kind = "signed_previous"
        end
    end
    if not expected then return nil, nil, "crypto_unavailable" end
    if not kind then return nil, nil, "signature" end

    if valid_cache_size >= VALID_CACHE_MAX then
        valid_cache = {}
        valid_cache_size = 0
    end
    -- The cache contains only the pure cryptographic result.  Host binding and
    -- registry state are deliberately evaluated after every cache hit.
    valid_cache[cache_key] = {
        zone = zone, generation = generation, kind = kind,
    }
    valid_cache_size = valid_cache_size + 1
    return zone, generation, kind
end

function _M.verify(raw, host, rule)
    rule = normalize_rule(rule)
    if not rule then return nil, "rule" end
    local zone, generation, kind_or_err = verify_signature(raw, rule)
    if not zone then return nil, kind_or_err end
    if not host_in_zone(host, zone) then
        return nil, "zone_mismatch", zone, generation
    end
    return true, kind_or_err, zone, generation
end

function _M.issue(zone, rule, generation)
    zone = normalize_name(zone)
    rule = normalize_rule(rule)
    if not valid_dns_name(zone) then return nil, "zone" end
    if not rule then return nil, "rule" end
    generation = tostring(generation or ""):lower()
    if not valid_generation(generation) then return nil, "generation" end
    local keys, key_err = secrets.origin_proof_secrets()
    if not keys then return nil, key_err or "secret_unavailable" end
    local mac = hmac_sha256(keys.current, proof_data(rule, zone, generation))
    if not mac then return nil, "crypto_unavailable" end
    return "v2." .. zone .. "." .. generation .. "." .. mac
end

-- Test hooks expose deterministic primitives, never secret values.
_M._host_in_zone_for_test = host_in_zone
_M._valid_generation_for_test = valid_generation
_M._reset_cache_for_test = function()
    valid_cache = {}
    valid_cache_size = 0
end

return _M
