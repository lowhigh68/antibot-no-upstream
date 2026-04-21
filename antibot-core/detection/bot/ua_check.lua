local _M   = {}
local pool = require "antibot.core.redis_pool"

local ua_cache  = ngx.shared.antibot_ua_cache
local CACHE_KEY = "ua_patterns"
local CACHE_TTL = 300

-- UA check — structural analysis and Redis-driven pattern matching.
-- No specific bot names, company names, or tool names are hardcoded.

local function is_headless_by_structure(ua)
    local ua_lower = ua:lower()

    -- Explicit automation markers in UA string
    if ua_lower:find("headless", 1, true) then return true, "headless_marker" end
    if ua_lower:find("webdriver", 1, true) then return true, "webdriver_marker" end

    -- Claims Chrome rendering engine but lacks the WebKit layout engine token.
    -- Real Chrome always includes both. Automation frameworks that fake Chrome
    -- UA often include only one. This is a structural inconsistency signal.
    if ua:find("Chrome/", 1, true)
    and not ua:find("AppleWebKit/", 1, true) then
        return true, "chrome_no_webkit"
    end

    -- Claims Firefox rendering engine but lacks Gecko layout engine token.
    if ua:find("Firefox/", 1, true)
    and not ua:find("Gecko/", 1, true) then
        return true, "firefox_no_gecko"
    end

    return false, nil
end

local KNOWN_BOT_TOKENS = {
    "bot", "spider", "crawler", "scraper",
    "facebookexternalhit",
    "meta%-external",
    "google%-agent", "google%-site%-verifier", "googleother",
    "apis%-google",
}

local function is_bot_self_identified(ua_lower)
    for _, token in ipairs(KNOWN_BOT_TOKENS) do
        if ua_lower:find(token, 1, token:find("%%") == nil) then
            return true
        end
    end
    return false
end

local function get_good_bot_suffixes(bot_name)
    local key = "goodbot:dns:" .. bot_name:lower()
    local val = pool.safe_get(key)
    if val and val ~= "" then
        local suffixes = {}
        for s in val:gmatch("[^,]+") do
            if s ~= "" then suffixes[#suffixes+1] = s:lower() end
        end
        return #suffixes > 0 and suffixes or nil
    end
    return nil
end

local function is_valid_suffix(ptr, suffixes)
    if not ptr or ptr == "" then return false end
    local ptr_lower = ptr:lower():gsub("%.+$", "")
    for _, suffix in ipairs(suffixes) do
        local s = suffix:lower()
        if ptr_lower == s or ptr_lower:sub(-(#s+1)) == "." .. s then
            return true
        end
    end
    return false
end

local function get_bad_patterns()
    local cached = ua_cache and ua_cache:get(CACHE_KEY)
    if cached then
        local ok, p = pcall(require("cjson").decode, cached)
        if ok and p then return p end
    end

    local raw = pool.safe_get("badbot:ua_patterns")
    if raw and raw ~= "" then
        local ok, p = pcall(require("cjson").decode, raw)
        if ok and p and #p > 0 then
            if ua_cache then ua_cache:set(CACHE_KEY, raw, CACHE_TTL) end
            return p
        end
    end

    ngx.log(ngx.DEBUG, "[ua_check] no badbot patterns, failing open")
    return {}
end

local function match_pattern(ua_lower, pat)
    if pat:sub(1,1) == "^" then
        return ua_lower:find(pat) ~= nil
    end
    local safe = pat:lower():gsub("([^%w])", "%%%1")
    return ua_lower:match("(^|[^%w])" .. safe .. "([^%w]|$)") ~= nil
end

function _M.run(ctx)
    local ua = ctx.ua or ""

    if ua == "" then
        ctx.bot_ua    = "empty_ua"
        ctx.bot_score = 0.6
        return true, false
    end

    local ua_lower = ua:lower()

    -- Structural headless/automation check
    local is_headless, reason = is_headless_by_structure(ua)
    if is_headless then
        -- Only confirm headless if there is no browser navigation context.
        -- A request from an actual browser (even Electron) will have Sec-Fetch headers.
        local sec_fetch  = ngx.var.http_sec_fetch_site or ""
        local x_internal = ngx.var.http_x_internal     or ""
        if sec_fetch == "" and x_internal == "" then
            ctx.bot_ua    = "headless"
            ctx.bot_score = 0.85
            ctx.bot_name  = reason
            return true, false
        end
        ngx.log(ngx.DEBUG, "[ua_check] structural headless but browser context: ", reason)
    end

    -- Bot self-identification check
    if is_bot_self_identified(ua_lower) then
        local bot_name = ua:match("([%w%-]+[Bb]ot[%w%-]*)")
                      or ua:match("([%w%-]+[Ss]pider)")
                      or ua:match("([%w%-]+[Cc]rawler)")
                      or ua:match("(facebookexternalhit)")
                      or ua:match("(Meta%-External%w+)")
                      or ua:match("(GoogleOther)")
                      or ua:match("(Google%-Agent)")
                      or ua:match("(Google%-Site%-Verifier)")
                      or ua:match("(APIs%-Google)")
        if bot_name then bot_name = bot_name:lower() end

        local suffixes = bot_name and get_good_bot_suffixes(bot_name)
        if suffixes then
            -- Known crawlbot with DNS suffixes → pass to DNS verification
            ctx.good_bot_claimed  = true
            ctx.good_bot_name     = bot_name
            ctx.good_bot_suffixes = suffixes
            ctx.bot_ua            = "good_bot_claimed"
            ctx.bot_score         = 0.0
            return true, false
        end

        -- Bot self-identified but no DNS registration in Redis.
        -- Route through DNS verify anyway — if it passes, it's legit.
        -- If DNS fails (no PTR or wrong domain), dns_reverse.lua will
        -- set bot_score=0.85.
        if bot_name then
            ctx.good_bot_claimed  = true
            ctx.good_bot_name     = bot_name
            ctx.good_bot_suffixes = {}   -- empty → dns_reverse will fail verify
            ctx.bot_ua            = "unregistered_bot"
            ctx.bot_score         = 0.0  -- dns_reverse decides the score
            return true, false
        end

        -- Could not extract a bot name → generic suspicious
        ctx.bot_ua    = "self_identified_bot"
        ctx.bot_score = 0.4
        return true, false
    end

    -- Redis-driven bad pattern list
    local patterns = get_bad_patterns()
    for _, pat in ipairs(patterns) do
        if match_pattern(ua_lower, pat:lower()) then
            ctx.bot_ua    = "bad_bot"
            ctx.bot_score = 0.85
            ctx.bot_name  = pat
            return true, false
        end
    end

    ctx.bot_ua    = "unknown"
    ctx.bot_score = 0.0
    return true, false
end

_M.is_valid_suffix = is_valid_suffix

return _M
