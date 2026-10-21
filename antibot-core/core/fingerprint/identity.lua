local _M = {}

local VERSION = "v1"

-- Token tu dong GAN O DUOI mot UA browser that.
--
-- Su co 21-10-2026 (no1computer.vn): khach iPhone chia se link san pham, app
-- tu fetch preview TU CHINH IP CUA KHACH voi UA
--   `Mozilla/5.0 (iPhone; ...) Version/26.0 Mobile/15E148 Safari/604.1
--    facebookexternalhit/1.1 (+http://...)`
-- UA nay KHONG co `(compatible; ...)` nen nhanh `bot_in_compat` khong thay,
-- va no roi xuong `Version/(%d+)[%d.]*%s+Mobile` -> `MobileSafari/26` — TRUNG
-- HOAN TOAN voi Safari iOS 26 that. Do duoc:
--   FB tren iPhone   -> MobileSafari/26  id=bb5c23932d437a1a1777abb8a4786a0a
--   Safari iOS thuan -> MobileSafari/26  id=bb5c23932d437a1a1777abb8a4786a0a
-- PTR cua IP khach (FPT, AS18403) khong khop `facebook.com`/`fbsv.net` nen
-- `fake_good_bot` chan dung request do, roi `network_quarantine` ghi
-- `gban:bb5c2393...` 300 giay — ban LUON moi khach Safari iOS 26 cung IP.
-- Ket qua: 79 luot `banned_ip` tren mot phien co `ckn=true richness=0.58`.
--
-- Day KHONG rieng Facebook: moi link-preview scraper deu ghep kieu nay
-- (Twitterbot, WhatsApp, TelegramBot, Slackbot, Discordbot, LinkedInBot,
-- SkypeUriPreview). Tren CGNAT/4G Viet Nam, mot rổ browser la NHIEU khach.
--
-- Giu `identity.lua` KHONG `require` gi (module nay pure va nam duoi
-- `goodbot_registry`), nen danh sach dat tai cho. `contract_test` ghim no la
-- TAP CON cua `OPERATOR_SUBSTRINGS` de hai ben khong the lech nhau.
local BOT_TOKENS = {
    "bot", "spider", "crawler", "facebookexternal", "mediapartners",
    "bingpreview", "meta-external", "feedfetcher",
}

-- Tra token XUAT HIEN SOM NHAT, khong phai token dau tien trong bang: mot UA
-- ghep nhieu scraper (`facebookexternalhit/1.1 Facebot Twitterbot/1.0`) phai
-- lay ten o dau chuoi, neu khong thi `bot` trong `facebot` thang
-- `facebookexternal` va cot log tro nen kho doc. Khong anh huong tinh dung —
-- moi nhanh nay deu nam ngoai ro browser — chi anh huong kha nang doc log.
local function bot_token_in_ua(lower)
    local best_pos, best_token
    for i = 1, #BOT_TOKENS do
        local p = lower:find(BOT_TOKENS[i], 1, true)
        if p and (not best_pos or p < best_pos
                  or (p == best_pos and #BOT_TOKENS[i] > #best_token)) then
            best_pos, best_token = p, BOT_TOKENS[i]
        end
    end
    return best_token
end

local function normalize_ua(ua)
    if ua == nil then return "?" end

    if type(ua) ~= "string" then return "?" end

    local s = ua:match("^%s*(.-)%s*$")
    if s == "" or s == "/" then return "?" end

    if not s:find("[%g%s]") then return "?" end

    if #s > 512 then s = s:sub(1, 512) end

    -- TRUOC moi nhanh browser: mot UA mang token tu dong KHONG duoc chia ro
    -- voi browser that, du token do nam o duoi va khong trong `(compatible;)`.
    --
    -- Dat o day chu khong sau `bot_in_compat` co y: cac nhanh `Edg/`,
    -- `CriOS/`, `Chrome/`, `Version/...Mobile` deu `return` ngay khi khop, nen
    -- mot nhanh bot dat SAU chung se khong bao gio chay voi UA ghep duoi.
    --
    -- Chi doi hoi token; KHONG doi `+http`/`+mailto` vi `facebookexternalhit`
    -- co dang `/1.1 (+http://...)` con `Facebot`/`Twitterbot/1.0` thi khong.
    local lower = s:lower()
    local bot_token = bot_token_in_ua(lower)
    if bot_token then
        -- Giu ten san pham khi doc duoc de log con phan biet duoc tung
        -- scraper; neu khong thi gop theo token. Ca hai deu nam ngoai ro
        -- browser, va do la tinh chat duy nhat can thiet.
        local product = lower:match("([%a][%w%-_.]*" .. bot_token .. "[%w%-_.]*)")
        return "bot:" .. (product and product:sub(1, 32) or bot_token)
    end

    local v = s:match("Edg/(%d+)")
    if v then return "Edge/" .. v end

    v = s:match("SamsungBrowser/(%d+)")
    if v then return "Samsung/" .. v end

    v = s:match("CriOS/(%d+)")
    if v then return "CriOS/" .. v end

    v = s:match("FxiOS/(%d+)")
    if v then return "FxiOS/" .. v end

    -- Bots dùng Chromium UA (Googlebot Mobile, Bingbot, AdsBot-Google Mobile…).
    -- UA chứa "Chrome/N" cho render fidelity nhưng token định danh thật nằm
    -- trong "compatible; BotName[;/]". Các dạng gặp:
    --   (compatible; Googlebot/2.1; +...)             — có /version
    --   (compatible; bingbot/2.0; +...)               — có /version
    --   (compatible; AdsBot-Google; +...)             — không có /version
    --   (compatible; AdsBot-Google-Mobile; +...)      — không có /version
    --   (KHTML, like Gecko; compatible; bingbot/2.0)  — "compatible;" giữa "("
    -- Pattern chỉ đòi identifier sau "compatible;"; dừng ở space/;/.
    -- Phải detect bot trước Chrome/ để không bị Chrome ăn → tránh identity
    -- collision với user thật.
    local bot_in_compat = s:match("compatible;%s*([%a][%w%-_]+)")
    if bot_in_compat and #bot_in_compat >= 3 and #bot_in_compat <= 32 then
        local bl = bot_in_compat:lower()
        if bl:find("bot", 1, true) or bl:find("spider", 1, true)
        or bl:find("crawler", 1, true) or bl == "mediapartners-google"
        or bl == "bingpreview" then
            return "bot:" .. bot_in_compat
        end
    end

    -- Chromium forks — tách bucket riêng để tránh identity collision với
    -- Chrome gốc (CGNAT VN: nhiều user cùng IP, bot giả Chrome → collision
    -- → ban lan sang user thật). Các fork gửi UA đầy đủ Chrome/ + token
    -- riêng; match token riêng trước để không bị Chrome/ ăn.
    v = s:match("coc_coc_browser/(%d+)")
    if v then return "CocCoc/" .. v end

    v = s:match("OPR/(%d+)")
    if v then return "Opera/" .. v end

    v = s:match("YaBrowser/(%d+)")
    if v then return "Yandex/" .. v end

    v = s:match("Vivaldi/(%d+)")
    if v then return "Vivaldi/" .. v end

    v = s:match("Whale/(%d+)")
    if v then return "Whale/" .. v end

    v = s:match("DuckDuckGo/(%d+)")
    if v then return "DDG/" .. v end

    v = s:match("Chrome/(%d+)")
    if v then return "Chrome/" .. v end

    v = s:match("Firefox/(%d+)")
    if v then return "Firefox/" .. v end

    v = s:match("Version/(%d+)[%d.]*%s+Mobile")
    if v then return "MobileSafari/" .. v end

    v = s:match("Version/(%d+)[%d.]*%s+Safari")
    if v then return "Safari/" .. v end

    if s:sub(1, 7) == "Dalvik/" then return "Dalvik" end

    local bot = s:match("compatible;%s*([%a][%w%-_]-[%w])/[%d]")
    if bot and #bot >= 3 and #bot <= 20 then
        return "bot:" .. bot
    end

    local slash_pos = s:find("/", 1, true)
    if slash_pos and slash_pos > 1 then
        local token = s:sub(1, slash_pos - 1)
        if token ~= "Mozilla" and #token >= 2 and not token:find("%s") then
            return token:sub(1, 32)
        end
    end

    return "?"
end

local function _compute(ip, ua_norm)
    local raw = VERSION .. "|" .. (ip or "") .. "|" .. ua_norm
    return ngx.md5(raw)
end

function _M.build(ctx)
    local ip = (ctx.ip and ctx.ip ~= "") and ctx.ip or ""

    local ua_norm = normalize_ua(ctx.ua)

    local id = _compute(ip, ua_norm)

    ctx.identity    = id
    ctx.network_id  = id
    ctx.ua_norm     = ua_norm

    return id
end

function _M.build_from(ip, ua_raw)
    local ua_norm = normalize_ua(ua_raw)
    return _compute(ip, ua_norm)
end

_M._normalize_ua = normalize_ua

return _M
