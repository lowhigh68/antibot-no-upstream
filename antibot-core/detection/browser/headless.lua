local _M = {}

-- Score headless browser signals from ctx.browser.hd.
--
-- Fields from JS beacon (hd object):
--   wd   (0|1)   — navigator.webdriver exposed → Puppeteer/Playwright/WebDriver
--   da   (0|1)   — domAutomation/domAutomationController → Selenium/CDP injection
--   cfl  (0|1|2) — chrome.runtime check:
--                    0 = chrome.runtime present (real Chrome, extensions)
--                    1 = chrome exists but chrome.runtime missing (headless Chrome)
--                    2 = no chrome object (Firefox/Safari — NOT a headless signal)
--   langs (num)  — navigator.languages.length; headless often returns 0 or 1
--   sw, sh (num) — screen.width/height; headless default viewport often 0×0
--   nfn  (0|1)   — Function.prototype.toString tampered → CDP Runtime.evaluate injection
--
-- FP guards:
--   cfl=2 explicitly excluded (Firefox/Safari = no chrome object = normal)
--   langs<2 only counts when another signal is present (single-lang locale FP)
--   screen 0×0 requires both sw AND sh = 0 (partial 0 can occur on some mobile)
--   All signals only fire when ctx.beacon_received = true (JS ran + beacon returned)
--
-- Output: ctx.headless_score ∈ [0,1]
function _M.run(ctx)
    if not ctx.beacon_received then
        ctx.headless_score = 0
        return true
    end

    local browser = ctx.browser
    if not browser then
        ctx.headless_score = 0
        return true
    end

    local hd = browser.hd
    if not hd or type(hd) ~= "table" then
        ctx.headless_score = 0
        return true
    end

    local s = 0.0

    -- Strong automation-control signals (extremely low FP — explicit API exposure)
    if hd.wd == 1 then s = s + 0.85 end   -- navigator.webdriver = true
    if hd.da == 1 then s = s + 0.70 end   -- domAutomation global injected

    -- Chrome-specific headless indicator
    -- cfl=1: chrome object present but chrome.runtime absent → headless Chrome
    -- cfl=2 = Firefox/Safari → explicitly NOT a bot signal
    if hd.cfl == 1 then s = s + 0.45 end

    -- Native Function.prototype.toString tampered (CDP Runtime.evaluate side-effect)
    if hd.nfn == 1 then s = s + 0.25 end

    -- Screen 0×0 (headless default before --window-size or --start-maximized)
    if (hd.sw or 1) == 0 and (hd.sh or 1) == 0 then s = s + 0.15 end

    -- Navigator.languages.length < 2 (headless returns [] or ['en']).
    -- Only count as supporting evidence when another signal is already present
    -- to avoid FP on users who configure a single system language.
    if (hd.langs or 2) < 2 and s > 0 then s = s + 0.08 end

    ctx.headless_score = math.min(1.0, s)
    return true
end

return _M
