-- Good-bot identity registry.
--
-- Owns the three pieces that previously drifted independently:
--   1. operator claim recognition (a HOLD gate, never positive trust),
--   2. verification-lane canonical-name extraction,
--   3. static infrastructure metadata and rate-family matching.
--
-- This module is deliberately pure: no ngx, Redis or file I/O. DNS suffixes
-- and admin overrides remain runtime data in Redis, seeded from
-- core/data/goodbot.json. P1.2 is compatibility-first, so the broader operator
-- claim and narrower verification claim remain distinct but are now returned
-- by one parser instead of being hidden in unrelated modules.

local _M = {}

local OPERATOR_SUBSTRINGS = {
    "bot", "spider", "crawler", "facebookexternal", "mediapartners",
    "bingpreview", "meta-external", "google-", "googleother",
    "googledocs", "playstore-google", "feedfetcher",
    "chrome privacy preserving", "ahrefssiteaudit",
}

local OPERATOR_EXACT = {
    ["google"] = true,
}

-- Lua patterns containing '%' are matched as patterns; the rest are literal
-- substrings. This preserves ua_check.lua's pre-P1.2 lane admission exactly.
local VERIFY_TOKENS = {
    "bot", "spider", "crawler", "scraper",
    "facebookexternalhit", "meta%-external",
    "google%-agent", "google%-site%-verifier", "googleother",
    "apis%-google", "mediapartners", "bingpreview",
}

-- Static infrastructure evidence available before Redis seed state. Do not
-- infer a family ASN for an absent entry: doing so changes a DNS failure into
-- verification and therefore belongs to a separate policy change.
local STATIC = {
    ["facebookexternalhit"]  = { ptr_only = true, asns = { 32934 } },
    ["facebot"]              = { ptr_only = true, asns = { 32934 } },
    ["meta-externalagent"]   = { ptr_only = true, asns = { 32934 } },
    ["meta-externalfetcher"] = { ptr_only = true, asns = { 32934 } },
    ["meta-externalads"]     = { ptr_only = true, asns = { 32934 } },

    ["googlebot"]             = { asns = { 15169 } },
    ["googlebot-image"]       = { asns = { 15169 } },
    ["googlebot-video"]       = { asns = { 15169 } },
    ["googlebot-news"]        = { asns = { 15169 } },
    ["adsbot-google"]         = { asns = { 15169 } },
    ["adsbot-google-mobile"]  = { asns = { 15169 } },
    ["mediapartners-google"]  = { asns = { 15169 } },
    ["googleother"]           = { asns = { 15169 } },
    ["googleother-image"]     = { asns = { 15169 } },
    ["googleother-video"]     = { asns = { 15169 } },
    ["apis-google"]           = { asns = { 15169 } },
    ["google-site-verifier"]  = { asns = { 15169 } },
    ["google-agent"]          = { asns = { 15169 } },
    ["storebot-google"]       = { asns = { 15169 } },
    ["google-inspectiontool"] = { asns = { 15169 } },
    ["google-read-aloud"]     = { asns = { 15169 } },
    ["google-extended"]       = { asns = { 15169 } },
    ["google-cloudvertexbot"] = { asns = { 15169 } },
    ["duplexweb-google"]      = { asns = { 15169 } },
    ["feedfetcher-google"]    = { asns = { 15169 } },

    ["bingbot"]          = { asns = { 8075 } },
    ["bingpreview"]      = { asns = { 8075 } },
    ["adidxbot"]         = { asns = { 8075 } },
    ["msnbot"]           = { asns = { 8075 } },
    ["msnbot-media"]     = { asns = { 8075 } },
    ["microsoftpreview"] = { asns = { 8075 } },

    ["applebot"]          = { asns = { 714, 6185, 2709 } },
    ["applebot-extended"] = { asns = { 714, 6185, 2709 } },

    ["coccocbot-web"]   = { asns = { 135905 } },
    ["coccocbot-image"] = { asns = { 135905 } },
}

local function operator_claimed(ua)
    if not ua or ua == "" then return false end
    local lower = ua:lower()
    if OPERATOR_EXACT[lower] then return true end
    for i = 1, #OPERATOR_SUBSTRINGS do
        if lower:find(OPERATOR_SUBSTRINGS[i], 1, true) then return true end
    end
    return false
end

local function verification_claimed(lower)
    for i = 1, #VERIFY_TOKENS do
        local token = VERIFY_TOKENS[i]
        if lower:find(token, 1, token:find("%%") == nil) then return true end
    end
    return false
end

-- Preserve the old extractor order. Greedy bot/spider/crawler forms run first
-- because the Redis key is the exact extracted token.
local function extract_name(ua, lower)
    return ua:match("([%w%-]+[Bb]ot[%w%-]*)")
        or ua:match("([%w%-]+[Ss]pider)")
        or ua:match("([%w%-]+[Cc]rawler)")
        or lower:match("(facebookexternalhit)")
        or lower:match("(facebot)")
        or lower:match("(meta%-external%w+)")
        or lower:match("(mediapartners%-google)")
        or lower:match("(googleother%-image)")
        or lower:match("(googleother%-video)")
        or lower:match("(googleother)")
        or lower:match("(google%-inspectiontool)")
        or lower:match("(google%-read%-aloud)")
        or lower:match("(google%-extended)")
        or lower:match("(google%-agent)")
        or lower:match("(google%-site%-verifier)")
        or lower:match("(duplexweb%-google)")
        or lower:match("(feedfetcher%-google)")
        or lower:match("(apis%-google)")
        or lower:match("(bingpreview)")
        or lower:match("(microsoftpreview)")
        or lower:match("(ahrefssiteaudit)")
end

function _M.inspect(ua)
    ua = ua or ""
    local lower = ua:lower()
    local verify = ua ~= "" and verification_claimed(lower) or false
    -- Extract independently from lane admission. This makes a registered name
    -- observable/testable even when compatibility policy still holds it out of
    -- DNS verification; changing that gate is an explicit verdict change.
    local name = ua ~= "" and extract_name(ua, lower) or nil
    if name then name = name:lower() end
    return {
        operator_claimed      = operator_claimed(ua),
        verification_claimed = verify,
        canonical_name       = name,
        metadata             = name and STATIC[name] or nil,
    }
end

function _M.claims_operator(ua)
    return operator_claimed(ua)
end

function _M.metadata(name)
    if not name or name == "" then return nil end
    return STATIC[tostring(name):lower()]
end

function _M.is_ptr_only(name)
    local entry = _M.metadata(name)
    return entry and entry.ptr_only == true or false
end

function _M.asns(name)
    local entry = _M.metadata(name)
    return entry and entry.asns or nil
end

function _M.class_for_bot(name, map)
    if not name or type(map) ~= "table" then return nil end
    name = tostring(name):lower()
    local exact = map[name]
    if exact then return exact end
    local best, best_len
    for family, value in pairs(map) do
        if type(family) == "string"
           and #family > (best_len or 0)
           and name:sub(1, #family) == family then
            best, best_len = value, #family
        end
    end
    return best
end

return _M
