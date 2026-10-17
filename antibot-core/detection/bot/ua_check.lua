local _M       = {}
local pool     = require "antibot.core.redis_pool"
local cloud_sx = require "antibot.detection.bot.cloud_suffixes"
local asn_policy = require "antibot.detection.bot.asn_policy"
local registry = require "antibot.core.goodbot_registry"

local ua_cache  = ngx.shared.antibot_ua_cache
local CACHE_KEY = "ua_patterns"
local CACHE_TTL = 300

local BROWSER_TOKEN_BLACKLIST = cloud_sx.BROWSER_STANDARD_TOKENS

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

-- Path 1 (contact attest) helpers.
-- Extracts contact URL from RFC-style compliant UA: "(compatible; ...; +http://host/...)"
-- Returns: (url_string, etld_plus_one_host) — either may be nil.
-- eTLD+1 uses heuristic "last 2 labels" (Q7=b) — accepts FP on `*.co.uk` etc.
local function parse_contact_url(ua)
    local url = ua:match("%+(https?://[%w%.%-:_]+)")
    local host
    if url then
        host = url:match("https?://([%w%.%-]+)")
    else
        local mailbox, mail_host = ua:match("%+mailto:([%w%.%+_%-]+@([%w%.%-]+))")
        if mailbox then
            url = "mailto:" .. mailbox
            host = mail_host
        end
    end
    if not url then return nil, nil end
    if not host then return url, nil end
    local last2 = host:match("([%w%-]+%.[%w%-]+)$")
    return url, last2
end

-- Path 2 (analyzer attest) helpers.
-- Browser-pattern detection — UA looks like a real browser (Mozilla + WebKit + Chrome/Firefox).
-- Trinh duyet that = `Mozilla/` + MOT TOKEN DONG CO DUNG HINH.
--
-- Ban cu doi `AppleWebKit/` AND (`Chrome/` OR `Firefox/`). Nhanh `Firefox/`
-- KHONG BAO GIO voi toi duoc: UA Firefox khong he co `AppleWebKit/` — no la
-- `Gecko/20100101 Firefox/x`. Phep AND do con loai OAN ca Safari (co
-- AppleWebKit, khong co Chrome/ lan Firefox/), Chrome tren iOS (`CriOS/`) va
-- Firefox tren iOS (`FxiOS/`). Ten ham la "trong giong trinh duyet" nhung
-- nghia THAT la "Chromium tren desktop/Android".
--
-- Ban nay khoa vao TOKEN DONG CO chu khong phai TEN THUONG HIEU — dung nguyen
-- tac ghi o dau file nay: khong hardcode ten. Hai dong co phu het trinh duyet
-- dang song:
--   AppleWebKit/  WebKit + Blink: Safari, Chrome, Edge, Opera, moi thu tren iOS
--   Gecko/        Firefox. CO dau `/` — Chromium ghi `(KHTML, like Gecko)`
--                 khong co dau gach, nen hai cai khong nham nhau.
--
-- No RONG HON ban cu, va do la CHU Y. Noi DUY NHAT doc `ctx.browser_ua_pattern`
-- la `analyzer_attest` (detection/bot/init.lua:233), va phia sau no con BA cong
-- nua: phai co marker cong cu o cuoi chuoi UA, phai co PTR, va PTR phai thuoc
-- mot nha cung cap dam may. Tran cua duong nay la `monitor`, KHONG phai bo qua.
-- Vi du ve hai cong sau con giu: UA kieu ClaudeBot
-- (`Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0;
-- +claudebot@anthropic.com)`) NAY qua duoc cong nay, nhung duoi chuoi cua no
-- khong phai token PascalCase nen truot cong marker, va do 09-10 cho thay no
-- khong co PTR nen truot luon cong PTR.
--
-- Noi rong cong dau = bot phan tich chay Safari/Firefox thoi bi cham diem
-- nham. Dung huong uu tien FP cua du an.
local function is_browser_pattern(ua)
    if not ua:find("Mozilla/", 1, true) then return false end
    return ua:find("AppleWebKit/", 1, true) ~= nil
        or ua:find("Gecko/", 1, true) ~= nil
end

-- Strict marker extraction (Q23=a).
-- Tail token must be EITHER:
--   - "PascalCase-PascalCase" with hyphen (e.g. "Chrome-Lighthouse"), OR
--   - single PascalCase token ≥ 5 chars (e.g. "GTmetrix")
-- AND must NOT be in BROWSER_TOKEN_BLACKLIST (standard browser tail tokens).
-- Returns marker string or nil.
local function extract_analyzer_marker(ua)
    local tail = ua:match("(%S+)%s*$")
    if not tail or tail == "" then return nil end
    if BROWSER_TOKEN_BLACKLIST[tail] then return nil end
    if tail:find("-", 1, true) then
        if tail:match("^[A-Z][%w]+%-[A-Z][%w]+$") then
            return tail
        end
    elseif #tail >= 5 and tail:match("^[A-Z][%w]+$") then
        return tail
    end
    return nil
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

-- PTR-only verify + ASN metadata: bot dùng rotating IP pool, forward A không
-- match được IP gốc → không thể forward verify. Một số block IP còn không
-- setup reverse DNS (NXDOMAIN) → cần fallback sang ASN check.
--
-- AS15169/AS8075 là shared cloud nên chỉ hỗ trợ DNS, không tự xác minh. Các ASN
-- dedicated còn lại giữ fallback cũ. Chính sách nằm ở asn_policy.lua.
--
-- Static well-known infrastructure lives in core.goodbot_registry so name
-- extraction and evidence metadata cannot drift. Admin may still add runtime
-- metadata with:
--   SET goodbot:ptr_only:<name> "1"
--   SET goodbot:asn:<name>      "<asn1>,<asn2>,..."

local function is_ptr_only_bot(bot_name)
    if not bot_name or bot_name == "" then return false end
    local lname = bot_name:lower()
    if registry.is_ptr_only(lname) then return true end
    local val = pool.safe_get("goodbot:ptr_only:" .. lname)
    return val == "1"
end

-- Trả về list ASN owner expected cho bot. Hardcoded > Redis override.
local function get_bot_asns(bot_name)
    if not bot_name or bot_name == "" then return nil end
    local lname = bot_name:lower()
    local static = registry.asns(lname)
    if static then return static end
    local val = pool.safe_get("goodbot:asn:" .. lname)
    if val and val ~= "" then
        local out = {}
        for s in val:gmatch("[^,]+") do
            local n = tonumber(s)
            if n then out[#out+1] = n end
        end
        return #out > 0 and out or nil
    end
    return nil
end

local function mark_asn_policy(ctx)
    local actual = ctx.asn and ctx.asn.asn_number
    if asn_policy.matches(ctx.good_bot_asns, actual)
       and asn_policy.is_corroborative(actual) then
        ctx.good_bot_asn_corroborative = true
    end
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

    -- Populate Path 1/2 signals up-front, regardless of bot-claim branches.
    -- These are consumed by detection/bot/init.lua AFTER ua_check returns.
    --   bot_ua_compliant  — RFC "(compatible; ...; +http://host)" format
    --   bot_contact_host  — eTLD+1 from contact URL (Path 1 attest target)
    --   browser_ua_pattern — UA looks like real browser (Path 2 prereq)
    --   analyzer_marker   — tool token at UA tail (e.g. Chrome-Lighthouse)
    local url, contact_host = parse_contact_url(ua)
    if url then
        ctx.bot_ua_compliant = true
        if contact_host then
            ctx.bot_contact_host = contact_host
        end
    end
    if is_browser_pattern(ua) then
        ctx.browser_ua_pattern = true
        local marker = extract_analyzer_marker(ua)
        if marker then
            ctx.analyzer_marker = marker
        end
    end

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

    -- Bot self-identification and canonical-name extraction share the same
    -- pure registry used by every early claim gate.
    local claim = ctx.automation_inspect or registry.inspect(ua)
    if claim.verification_claimed then
        local bot_name = claim.canonical_name
        if bot_name then bot_name = bot_name:lower() end

        ctx.automation_claimed   = true
        ctx.automation_principal = bot_name or ctx.automation_principal
            or "automation-client"
        ctx.automation_contact_only = claim.contact_claimed == true
            and claim.operator_claimed ~= true
        ctx.automation_contact_attestable = claim.contact_attestable == true
        if ctx.operator_network_verified ~= true then
            ctx.automation_tier  = "unknown"
            ctx.automation_proof = "claim_pending"
        end

        local suffixes = bot_name and get_good_bot_suffixes(bot_name)
        if suffixes then
            -- Known crawlbot with DNS suffixes → pass to DNS verification
            ctx.good_bot_claimed  = true
            ctx.good_bot_name     = bot_name
            ctx.good_bot_suffixes = suffixes
            ctx.good_bot_ptr_only = is_ptr_only_bot(bot_name)
            ctx.good_bot_asns     = get_bot_asns(bot_name)
            ctx.good_bot_registered = true
            mark_asn_policy(ctx)
            ctx.bot_ua            = "good_bot_claimed"
            ctx.bot_score         = 0.0
            ngx.log(ngx.INFO,
                "[ua_check] good_bot_claimed name=", bot_name,
                " ptr_only=", tostring(ctx.good_bot_ptr_only),
                " asn_fallback=", ctx.good_bot_asns and #ctx.good_bot_asns or 0,
                " ip=", ctx.ip or "?")
            return true, false
        end

        -- Self-identified automation without a DNS registry entry. The
        -- evidence lane may still attest it; missing proof remains unknown.
        -- Route through DNS verify anyway — if it passes, it's legit.
        if bot_name then
            ctx.good_bot_claimed  = true
            ctx.good_bot_name     = bot_name
            ctx.good_bot_suffixes = {}   -- empty → dns_reverse will fail verify
            ctx.good_bot_asns     = get_bot_asns(bot_name)  -- ASN fallback if Redis DNS miss
            ctx.good_bot_ptr_only = is_ptr_only_bot(bot_name)
            ctx.good_bot_registered = claim.metadata ~= nil
                or ctx.good_bot_ptr_only == true
                or (ctx.good_bot_asns and #ctx.good_bot_asns > 0) or false
            mark_asn_policy(ctx)
            ctx.bot_ua            = "unregistered_bot"
            ctx.bot_score         = 0.4
            return true, false
        end

        -- Could not extract a bot name → generic suspicious
        ctx.good_bot_claimed    = true
        ctx.good_bot_name       = "automation-client"
        ctx.good_bot_suffixes   = {}
        ctx.good_bot_registered = false
        ctx.bot_ua              = "self_identified_bot"
        ctx.bot_score           = 0.4
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
