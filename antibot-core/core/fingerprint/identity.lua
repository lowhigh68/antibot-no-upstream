local _M = {}

local VERSION = "v1"

local function normalize_ua(ua)
    if ua == nil then return "?" end

    if type(ua) ~= "string" then return "?" end

    local s = ua:match("^%s*(.-)%s*$")
    if s == "" or s == "/" then return "?" end

    if not s:find("[%g%s]") then return "?" end

    if #s > 512 then s = s:sub(1, 512) end

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
    ctx.ua_norm     = ua_norm

    return id
end

function _M.build_from(ip, ua_raw)
    local ua_norm = normalize_ua(ua_raw)
    return _compute(ip, ua_norm)
end

_M._normalize_ua = normalize_ua

return _M
