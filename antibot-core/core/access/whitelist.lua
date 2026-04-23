local _M   = {}
local pool = require "antibot.core.redis_pool"
local identity_mod = require "antibot.core.fingerprint.identity"
local cfg  = require "antibot.core.config"

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

-- Private/loopback ranges — internal infrastructure, bypass antibot.
-- Bao phủ:
--   127.0.0.0/8              — loopback
--   10.0.0.0/8               — RFC1918 class A
--   172.16.0.0/12            — RFC1918 class B
--   192.168.0.0/16           — RFC1918 class C
--   ::1                      — IPv6 loopback
--   fe80::/10                — IPv6 link-local
--   fc00::/7                 — IPv6 unique local (fc/fd prefix)
-- Lý do an toàn: RFC1918 không route qua public Internet; không thể
-- spoof từ ngoài. Request đến với src=RFC1918 = thật sự từ LAN/server.
local function is_private_lan(ip)
    if not ip or ip == "" then return false end
    if ip:find("^127%.", 1, false) then return true end
    if ip:find("^10%.", 1, false) then return true end
    if ip:find("^192%.168%.", 1, false) then return true end
    local b = ip:match("^172%.(%d+)%.")
    if b then
        local n = tonumber(b)
        if n and n >= 16 and n <= 31 then return true end
    end
    if ip == "::1" then return true end
    local p2 = ip:sub(1, 2):lower()
    if p2 == "fc" or p2 == "fd" then return true end
    if ip:sub(1, 4):lower() == "fe80" then return true end
    return false
end

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
local function lookup_device_by_ua(ua, verified_ttl, ctx)
    if not ua or ua == "" then return nil end
    local ua_hash  = ngx.md5(ua)
    local device_id = pool.safe_get("device_ua:" .. ua_hash)
    if not device_id or device_id == "" then return nil end

    local dv = pool.safe_get("verified:device:" .. device_id)
    if dv ~= "1" then return nil end

    -- Renew TTL
    pool.safe_set("verified:device:" .. device_id, "1", verified_ttl)
    pool.safe_set("device_ua:" .. ua_hash, device_id, verified_ttl)

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

    -- 1. Internal antibot endpoints
    for _, p in ipairs(ANTIBOT_PATHS) do
        if uri:sub(1, #p) == p then return true, "antibot_internal" end
    end

    -- 2. Loopback + LAN (RFC1918, IPv6 private)
    -- Internal infrastructure: wp-cron, monitoring, DA hairpin, container bridge.
    -- KHÔNG count rate, không chạy scoring, không ghi session.
    if is_private_lan(ip) then return true, "lan_internal" end

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
    if cookie and cookie ~= "" then
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

    -- 6. Device fingerprint — SECONDARY, IP-independent.
    -- Dùng UA → device_id mapping (canvas-based, lưu khi verify).
    -- Không cần JA3 — phù hợp kiến trúc no-stream.
    -- Handles: Safari ITP xóa cookie, cookie expire, đổi mạng.
    local device_id = lookup_device_by_ua(ua, verified_ttl, ctx)
    if device_id then
        return true, "device_canvas_verified"
    end

    -- 7. IP+UA early identity — TERTIARY, IP-dependent.
    -- Safety net: first request ngay sau verify trên cùng IP.
    if not cookie or cookie == "" then
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
