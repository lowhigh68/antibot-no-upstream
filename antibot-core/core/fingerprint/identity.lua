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
