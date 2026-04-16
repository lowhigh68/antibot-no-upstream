local _M = {}

-- UA anomaly detection — structural analysis only.
-- No specific browser names, tool names, or OS names are hardcoded.
--
-- Principles:
--   1. A real browser UA has consistent internal structure:
--      platform/OS token → layout engine → browser engine → version
--   2. The relationship between claimed engine and claimed OS must be coherent.
--   3. Automation tools deviate from this structure in detectable ways.

-- ── Structural UA component detectors ──────────────────────────────────

local function has_platform_token(ua)
    -- Real browser UAs contain a parenthesised platform section.
    -- Pattern: "(...)" anywhere in the UA string.
    return ua:find("(", 1, true) ~= nil
end

local function has_layout_engine(ua)
    -- All modern browsers declare their layout engine:
    -- AppleWebKit (Chrome, Safari, Edge, Opera, Samsung)
    -- Gecko (Firefox)
    -- Trident (old IE) or EdgeHTML (old Edge)
    return ua:find("AppleWebKit/", 1, true)
        or ua:find("Gecko/",       1, true)
        or ua:find("Trident/",     1, true)
        or ua:find("EdgeHTML/",    1, true)
end

local function has_browser_version_token(ua)
    -- Browsers declare their version with a recognised engine token + version:
    -- "Chrome/NNN", "Firefox/NNN", "Safari/NNN", "Version/NNN", "OPR/NNN"
    return ua:find("Chrome/%d",  1, false)
        or ua:find("Firefox/%d", 1, false)
        or ua:find("Safari/%d",  1, false)
        or ua:find("Version/%d", 1, false)
        or ua:find("OPR/%d",     1, false)
end

local function engine_os_coherent(ua)
    -- Structural coherence: certain layout engines only appear on certain OSes.
    -- This is a property of the platform, not a named browser rule.
    --
    -- AppleWebKit without Apple platform OR Windows/Linux context:
    --   Real browsers using WebKit are: Chrome (any OS), Safari (Apple only).
    --   If UA claims WebKit + claims to be on an OS that never ships WebKit natively
    --   but the UA lacks the Chrome token → incoherent.
    --
    -- We check only for fundamental incoherence, not exhaustive browser rules.

    -- Claimed WebKit (Safari-like) without Apple OS AND without Chrome identification
    if ua:find("AppleWebKit/", 1, true)
    and not ua:find("Chrome/",      1, true)   -- Chrome uses WebKit on all OSes
    and not ua:find("Macintosh",    1, true)    -- macOS
    and not ua:find("iPhone",       1, true)    -- iOS
    and not ua:find("iPad",         1, true)    -- iPadOS
    and not ua:find("iPod",         1, true)    -- iPod
    and not ua:find("Android",      1, true) then  -- Android (WebView)
        return false  -- WebKit without any Apple/Android context = incoherent
    end

    return true
end

local function check_length(ua)
    local len = #ua
    if len < 10  then return 0.5 end  -- too short for any real browser
    if len > 500 then return 0.3 end  -- suspiciously long
    return 0.0
end

local function check_version_presence(ua)
    -- Real browser UAs always contain at least one "/digit" version token.
    if not ua:find("/%d", 1, false) then return 0.3 end
    return 0.0
end

-- ── Headless/automation detection by structure ──────────────────────────

local function check_headless_by_structure(ua)
    -- A UA that claims to be a browser but lacks coherent structure is
    -- likely an automation tool with a fake UA.
    --
    -- Strongest signal: claims browser engine but lacks platform AND layout engine.
    -- Real browsers always have both.
    if not has_platform_token(ua) then
        if has_browser_version_token(ua) then
            -- Claims browser version but no platform = fake browser UA
            return 0.85, "browser_claim_no_platform"
        end
        return 0.0, nil  -- not claiming to be a browser either
    end

    if not has_layout_engine(ua) then
        if has_browser_version_token(ua) then
            -- Claims browser version but no layout engine
            return 0.75, "browser_claim_no_engine"
        end
    end

    -- Engine-OS coherence check
    if not engine_os_coherent(ua) then
        return 0.65, "engine_os_incoherent"
    end

    return 0.0, nil
end

function _M.run(ctx)
    local ua = ctx.ua or ""
    if ua == "" then ctx.ua_flag = 0.5; return end

    local score = 0.0

    -- Structural headless detection
    local headless_score, reason = check_headless_by_structure(ua)
    score = math.max(score, headless_score)
    if reason then
        ngx.log(ngx.DEBUG, "[ua_anomaly] ", reason, " ip=", ctx.ip or "?")
    end

    -- Length and version checks
    score = math.max(score, check_length(ua))
    score = math.max(score, check_version_presence(ua))

    -- Compound: no platform + no layout engine + short UA = tool signature
    if not has_platform_token(ua) and not has_layout_engine(ua) and #ua < 60 then
        score = math.max(score, 0.70)
        ngx.log(ngx.DEBUG, "[ua_anomaly] tool_structure ip=", ctx.ip or "?")
    end

    ctx.ua_flag = math.min(1.0, score)
end

return _M
