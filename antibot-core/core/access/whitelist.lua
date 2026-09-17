local _M   = {}
local pool = require "antibot.core.redis_pool"
local identity_mod = require "antibot.core.fingerprint.identity"
local cfg  = require "antibot.core.config"
local ip_scope = require "antibot.core.ip_scope"
local ua_claim = require "antibot.detection.bot.ua_claim"

local ANTIBOT_PATHS = {
    "/antibot/verify",
    "/antibot/beacon",
    "/antibot/debug",
    "/antibot/restore",
    "/antibot-admin",
}

local BYPASS_PATHS = {
    "/fpc/",
    "/ajaxcart/",
}

-- Phep kiem dai noi bo da chuyen sang `core/ip_scope.lua` — xem chu thich o do
-- ve ly do khong giu hai ban sao cua mot phep kiem an ninh.
--
-- Ly do an toan CU o day: "RFC1918 khong route qua public Internet; khong the
-- spoof tu ngoai. Request den voi src=RFC1918 = that su tu LAN/server."
--
-- Cau do chi dung chung nao `$remote_addr` con la dia chi TCP that. Voi
-- `real_ip_header` (vi du `CF-Connecting-IP`), `$remote_addr` tro thanh gia tri
-- sao chep tu mot header, va nginx KHONG kiem tra no co phai IP cong cong hay
-- khong. Luc do dac quyen o buoc 2 ben duoi mo ra cho bat ky ai gui dung mot
-- dong header.
--
-- Nen buoc 2 nay doc `ctx.ip_tcp` — dia chi TCP that, `ctx/init.lua` da tach
-- san — chu KHONG doc `ctx.ip`. Bat bien ma cau tren tuyen bo, nay duoc bao
-- dam bang dung thu no noi den.

-- Tầng 2: Device fingerprint dùng UA + canvas hash.
--
-- Kiến trúc no-stream: JA3 luôn partial/nil → không thể dùng JA3.
-- Canvas hash được lưu vào Redis bởi verify_token.lua sau khi user verify:
--   fp:canvas:{id}       — canvas hash của session đó
--   device_ua:{ua_hash}  — device_id tương ứng với UA này
--
-- Lookup flow khi cookie miss:
--   1. Tính ua_hash = md5(ua)
--   2. Lookup device_ua:{ua_hash} → device_id
--   3. Lookup verified:device:{device_id} → "1"
--   4. Match → bypass, set lại cookie
--
-- Không cần biết canvas hash khi check — chỉ cần ua_hash để lookup device_id.
-- Canvas hash chỉ cần khi grant (verify_token.lua).
-- Bind verify với IP /16 để chặn cross-network bypass.
-- /24: user mobile đổi cell tower thường đổi /24 → re-challenge mỗi lần (UX kém)
-- /16: cùng carrier mobile share /16 → user di chuyển trong VN cùng ISP vẫn pass
-- Bot phải compromise IP cùng /16 với user thật → khó hơn nhiều
local function get_ip16(ip)
    if not ip or ip == "" then return nil end
    return ip:match("^(%d+%.%d+)%.")
end

-- Self-declared crawler check — Googlebot/Bingbot/meta-externalagent/… identify
-- themselves in the UA. Such a UA must NEVER occupy the verified-HUMAN lane
-- (cookie / device / early-id), even after solving the canvas beacon — rendering
-- bots like meta-externalagent execute JS and pass the PoW. That lane
-- short-circuits at STEPS_COMMON → bypasses good-bot rate limiting AND scoring;
-- a bot-UA holding device_canvas_verified is how meta-externalagent leaked ~31k
-- req/day past the 60/min ceiling. Route them to the good-bot lane (DNS/ASN
-- verify + rate ceiling) instead. Same self-claim definition as l7/ban/ban_store.
local function lookup_device_by_ua(ua, ip, verified_ttl, ctx)
    if not ua or ua == "" then return nil end
    -- Gate the device_canvas_verified path (the observed leak).
    if ua_claim.claims_good_bot(ua) then return nil end
    local ip16 = get_ip16(ip)
    if not ip16 then return nil end

    local ua_hash = ngx.md5(ua)
    local key     = "device_ua:" .. ua_hash .. ":" .. ip16
    local device_id = pool.safe_get(key)
    if not device_id or device_id == "" then return nil end

    local dv = pool.safe_get("verified:device:" .. device_id)
    if dv ~= "1" then return nil end

    -- Renew TTL
    pool.safe_set("verified:device:" .. device_id, "1", verified_ttl)
    pool.safe_set(key, device_id, verified_ttl)

    -- Re-issue cookie
    local scheme = ngx.var.scheme or "http"
    local cookie_flags = "antibot_fp=" .. device_id
        .. "; Path=/; HttpOnly; SameSite=Lax; Max-Age="
        .. tostring(verified_ttl)
    if scheme == "https" then
        cookie_flags = cookie_flags .. "; Secure"
    end
    ngx.header["Set-Cookie"] = cookie_flags

    ctx.verified = true
    ctx.identity = device_id
    ctx.fp_light = device_id

    ngx.log(ngx.INFO, "[whitelist] device_canvas_verified id=",
            device_id:sub(1,8), " ip=", ctx.ip or "?")
    return device_id
end

local function extend_to_current_id(cookie, ip, ua, ttl)
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then return end
    local current_id = identity_mod.build_from(ip, ua)
    if not current_id or current_id == "" or current_id == cookie then return end
    local already = pool.safe_get("verified:" .. current_id)
    if already == "1" then return end
    pool.safe_set("verified:" .. current_id, "1", ttl)
    ngx.log(ngx.DEBUG,
        "[whitelist] ip_change_extend cookie=", cookie:sub(1,8),
        " new_id=", current_id:sub(1,8), " ip=", ip)
end

function _M.check(ctx)
    local uri = ngx.var.uri or "/"
    local ip  = ctx.ip or ""
    local ua  = ngx.var.http_user_agent or ""
    local verified_ttl = cfg.ttl.verified or 7200
    -- Self-declared crawlers never enter the verified-human lane. Gates the
    -- cookie (5) and early-id (7) paths below; device (6) is gated inside
    -- lookup_device_by_ua. Infra whitelists (1-4) and static bypass (8) still apply.
    local ua_is_bot = ua_claim.claims_good_bot(ua)

    -- 1. Internal antibot endpoints
    for _, p in ipairs(ANTIBOT_PATHS) do
        if uri:sub(1, #p) == p then return true, "antibot_internal" end
    end

    -- 2. Loopback + LAN (RFC1918, IPv6 private)
    -- Internal infrastructure: wp-cron, monitoring, DA hairpin, container bridge.
    -- KHÔNG count rate, không chạy scoring, không ghi session.
    --
    -- `ctx.ip_tcp`, KHONG phai `ctx.ip`: day la dac quyen manh nhat trong he
    -- thong (mien toan bo pipeline, thang ca tin hieu WAF), nen no phai gac
    -- tren dia chi TCP that, thu khong header nao dat duoc.
    if ip_scope.is_private(ctx.ip_tcp or ip) then return true, "lan_internal" end

    -- 3. IP whitelist
    local val = pool.safe_get("wl:" .. ip)
    if val == "1" then return true, "ip_whitelist" end

    -- 4. URL whitelist
    local url_list = pool.safe_get("wl:url_list")
    if url_list and url_list ~= "" then
        for prefix in url_list:gmatch("[^\n]+") do
            if prefix ~= "" and uri:sub(1, #prefix) == prefix then
                return true, "url_whitelist"
            end
        end
    end

    -- 5. Cookie-based verified session — PRIMARY, IP-independent.
    -- Sliding window TTL renewal.
    local cookie = ngx.var.cookie_antibot_fp
    if not ua_is_bot and cookie and cookie ~= "" then
        local verified = pool.safe_get("verified:" .. cookie)
        if verified == "1" then
            ctx.verified = true
            ctx.identity = cookie
            ctx.fp_light = cookie

            pool.safe_set("verified:" .. cookie, "1", verified_ttl)
            pool.safe_set("beacon:" .. cookie, "1", 600)
            pcall(extend_to_current_id, cookie, ip, ua, verified_ttl)

            ngx.log(ngx.DEBUG, "[whitelist] cookie_verified id=",
                    cookie:sub(1,8), " ip=", ip)
            return true, "cookie_verified"
        end
    end

    -- 6. Device fingerprint — SECONDARY, /16-bound (NOT IP-independent).
    -- Dùng (UA, IP /16) → device_id mapping. Trước đây IP-independent
    -- → bot rotate IP cross-country dùng UA phổ biến của user thật bypass
    -- được toàn bộ hệ thống. Bind /16 chặn cross-network leak nhưng vẫn
    -- handle: Safari ITP xóa cookie, đổi mạng cùng carrier (4G ↔ WiFi VN).
    local device_id = lookup_device_by_ua(ua, ip, verified_ttl, ctx)
    if device_id then
        return true, "device_canvas_verified"
    end

    -- 7. IP+UA early identity — TERTIARY, IP-dependent.
    -- Safety net: first request ngay sau verify trên cùng IP.
    if not ua_is_bot and (not cookie or cookie == "") then
        local early_id = identity_mod.build_from(ip, ua)
        local ev       = pool.safe_get("verified:" .. early_id)
        if ev == "1" then
            ctx.verified = true
            ctx.identity = early_id
            ctx.fp_light = early_id
            pool.safe_set("verified:" .. early_id, "1", verified_ttl)
            ngx.log(ngx.DEBUG, "[whitelist] earlyid_verified id=",
                    early_id:sub(1,8))
            return true, "earlyid_verified"
        end
    end

    -- 8. Static bypass paths
    for _, p in ipairs(BYPASS_PATHS) do
        if uri:sub(1, #p) == p then
            ngx.log(ngx.DEBUG, "[whitelist] bypass_path uri=", uri)
            return true, "bypass_path"
        end
    end

    return false, nil
end

_M.run = _M.check

return _M
