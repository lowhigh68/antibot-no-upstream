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

-- RFC-style automation clients often identify themselves with a product token
-- plus an operator contact instead of putting "bot" in the product name, for
-- example `Product-User/1.0; +https://...` or `+mailto:...`.  The contact is a
-- claim only; it never grants trust by itself.
local function contact_info(lower)
    local contact_pos, contact_kind
    for _, item in ipairs({
        { marker = "+http://",  kind = "url" },
        { marker = "+https://", kind = "url" },
        { marker = "+mailto:",  kind = "mailto" },
    }) do
        local p = lower:find(item.marker, 1, true)
        if p and (not contact_pos or p < contact_pos) then
            contact_pos, contact_kind = p, item.kind
        end
    end

    -- Some fetchers publish a bare mailbox instead of RFC-style `mailto:`, for
    -- example `Claude-User/1.0; +Claude-User@anthropic.com`.  It is useful as
    -- a structural automation CLAIM, but deliberately not contact-attestable:
    -- an email string proves neither control of the domain nor source network.
    local email_pos = lower:find("%+[%w%.%_%-]+@[%w%.%-]+")
    if email_pos and (not contact_pos or email_pos < contact_pos) then
        contact_pos, contact_kind = email_pos, "bare_email"
    end
    return contact_pos, contact_kind
end

local function contact_position(lower)
    local p = contact_info(lower)
    return p
end

local function contact_claimed(lower)
    return contact_position(lower) ~= nil
end

local function contact_attestable(lower)
    local _, kind = contact_info(lower)
    return kind == "url" or kind == "mailto"
end

local function contact_domain(lower)
    local _, kind = contact_info(lower)
    if kind == "url" then
        return lower:match("%+https?://([%w%.%-]+)")
    end
    if kind == "mailto" then
        return lower:match("%+mailto:[%w%.%+_%-]+@([%w%.%-]+)")
    end
    if kind == "bare_email" then
        return lower:match("%+[%w%.%+_%-]+@([%w%.%-]+)")
    end
    return nil
end

-- Generic machine-client shape used ONLY by the L7 automation meter.  It does
-- not enter DNS verification and does not deny a verified-human fast path.
-- This catches opaque products such as `anthropic-ai`, `curl/8.5.0` and
-- `python-requests/2.32.0` without maintaining an AI-brand list.
local function opaque_machine_product(ua)
    if not ua or #ua < 3 or #ua > 128 then return nil end
    if ua:find("[%s%(%)%;,]") then return nil end
    local product = ua:match("^([%a][%w%._%-]*)$")
        or ua:match("^([%a][%w%._%-]*)/[%w%._%-]+$")
    return product and product:lower() or nil
end

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
    -- Do not let words inside the contact URL (for example `/bot`) upgrade a
    -- contact-only product into the legacy crawler hold gate.
    local p = contact_position(lower)
    local claim_text = p and lower:sub(1, p - 1) or lower
    for i = 1, #OPERATOR_SUBSTRINGS do
        if claim_text:find(OPERATOR_SUBSTRINGS[i], 1, true) then return true end
    end
    return false
end

local function verification_claimed(lower)
    if contact_claimed(lower) then return true end
    for i = 1, #VERIFY_TOKENS do
        local token = VERIFY_TOKENS[i]
        if lower:find(token, 1, token:find("%%") == nil) then return true end
    end
    return false
end

local function extract_contact_product(ua, lower)
    local contact_pos, contact_kind = contact_info(lower)
    if not contact_pos then return nil end

    -- Keep the last product/version token before the contact.  Iteration is
    -- deliberate: a browser-shaped automation UA can contain Mozilla,
    -- AppleWebKit and Safari before its actual final product token.
    local prefix = ua:sub(1, contact_pos - 1)
    local product
    for token in prefix:gmatch("([%w][%w%-]*)/[%w%.%-]+") do
        product = token
    end
    -- Bare mailbox form may omit a product/version token.  Its local part is
    -- still a stable meter principal, but remains claim-only evidence.
    if not product and contact_kind == "bare_email" then
        product = lower:match("%+([%w%.%_%-]+)@", contact_pos)
    end
    return product and product:lower() or nil
end

-- Preserve the old extractor order. Greedy bot/spider/crawler forms run first
-- because the Redis key is the exact extracted token.
local function extract_name(ua, lower)
    local p = contact_position(lower)
    local product_ua = p and ua:sub(1, p - 1) or ua
    local product_lower = product_ua:lower()
    return product_ua:match("([%w%-]+[Bb]ot[%w%-]*)")
        or product_ua:match("([%w%-]+[Ss]pider)")
        or product_ua:match("([%w%-]+[Cc]rawler)")
        or product_lower:match("(facebookexternalhit)")
        or product_lower:match("(facebot)")
        or product_lower:match("(meta%-external%w+)")
        or product_lower:match("(mediapartners%-google)")
        or product_lower:match("(googleother%-image)")
        or product_lower:match("(googleother%-video)")
        or product_lower:match("(googleother)")
        or product_lower:match("(google%-inspectiontool)")
        or product_lower:match("(google%-read%-aloud)")
        or product_lower:match("(google%-extended)")
        or product_lower:match("(google%-agent)")
        or product_lower:match("(google%-site%-verifier)")
        or product_lower:match("(duplexweb%-google)")
        or product_lower:match("(feedfetcher%-google)")
        or product_lower:match("(apis%-google)")
        or product_lower:match("(bingpreview)")
        or product_lower:match("(microsoftpreview)")
        or product_lower:match("(ahrefssiteaudit)")
        or extract_contact_product(ua, lower)
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
    local op_claim = operator_claimed(ua)
    local contact  = contact_claimed(lower)
    local machine  = (not op_claim and not contact)
        and opaque_machine_product(ua) or nil
    return {
        operator_claimed      = op_claim,
        verification_claimed = verify,
        automation_claimed   = op_claim or contact,
        automation_meter_claimed = op_claim or contact or machine ~= nil,
        contact_claimed      = contact,
        contact_attestable   = contact_attestable(lower),
        contact_domain       = contact_domain(lower),
        machine_claimed      = machine ~= nil,
        canonical_name       = name or machine,
        metadata             = name and STATIC[name] or nil,
    }
end

function _M.claims_operator(ua)
    return operator_claimed(ua)
end

function _M.claims_automation(ua)
    if not ua or ua == "" then return false end
    return operator_claimed(ua) or contact_claimed(ua:lower())
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
