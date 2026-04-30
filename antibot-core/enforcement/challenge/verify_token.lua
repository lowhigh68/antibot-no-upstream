local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local identity_mod = require "antibot.core.fingerprint.identity"

local ffi = require "ffi"
local C   = ffi.C

pcall(function()
    ffi.cdef([[
        typedef struct sha256_ctx_st SHA256_CTX;
        unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
        unsigned char *HMAC(const void *evp_md,
                            const void *key, int key_len,
                            const unsigned char *data, size_t data_len,
                            unsigned char *md, unsigned int *md_len);
        const void *EVP_sha256(void);
    ]])
end)

local function sha256_hex(data)
    local md = ffi.new("unsigned char[32]")
    local ok = pcall(function() C.SHA256(data, #data, md) end)
    if not ok then return nil end
    local hex = {}
    for i = 0, 31 do hex[i+1] = string.format("%02x", md[i]) end
    return table.concat(hex)
end

local function hmac_sha256_hex(key, data)
    local md     = ffi.new("unsigned char[32]")
    local md_len = ffi.new("unsigned int[1]", 32)
    local ok, result = pcall(function()
        return C.HMAC(C.EVP_sha256(), key, #key, data, #data, md, md_len)
    end)
    if not ok or result == nil then return nil end
    local hex = {}
    for i = 0, 31 do hex[i+1] = string.format("%02x", md[i]) end
    return table.concat(hex)
end

local function check_canvas_consistency(red, id, ip, canvas_hash)
    if not canvas_hash or canvas_hash == "" or canvas_hash == "err" then return end
    local fp_key   = "fp:canvas:" .. id
    local existing = red:get(fp_key)
    if existing == ngx.null then existing = nil end
    if existing and existing ~= "" and existing ~= canvas_hash then
        red:incr("fp:canvas_change:" .. id)
        red:expire("fp:canvas_change:" .. id, 3600)
        ngx.log(ngx.INFO, "[verify] canvas_inconsistency id=", id:sub(1,8))
    else
        red:setex(fp_key, cfg.ttl.fp or 86400, canvas_hash)
    end
end

local function flag_fast_solve(red, id, solve_ms_str)
    local solve_ms = tonumber(solve_ms_str)
    if not solve_ms then return end
    if solve_ms < 50 then
        red:incr("fp:fast_solve:" .. id)
        red:expire("fp:fast_solve:" .. id, 3600)
    end
end

-- Build device_id từ UA + canvas hash — IP-independent và JA3-independent.
--
-- Tại sao canvas thay JA3:
--   Kiến trúc no-stream → JA3 luôn partial → build_device_id(ua, ja3) = nil
--   Canvas được capture bởi JS beacon, lưu vào beacon_data:{id}
--   Canvas ổn định theo GPU/driver — thay đổi khi đổi thiết bị/GPU
--   Phù hợp làm device identifier IP-independent
--
-- Tại sao không dùng JA3 nữa:
--   ja3=- với mọi request trong kiến trúc no-stream
--   → verified:device không bao giờ được set → tầng 2 vô hiệu
--
-- Canvas hash được đọc từ 2 nguồn theo thứ tự ưu tiên:
--   1. POST args.cv — có ngay khi verify (user vừa submit challenge)
--   2. Redis fp:canvas:{id} — từ verify lần trước (user quay lại)
local function build_device_id(ua, canvas_hash)
    if not ua or ua == "" then return nil end
    if not canvas_hash or canvas_hash == ""
       or canvas_hash == "err" or canvas_hash == "0" then
        return nil
    end
    return ngx.md5("device_canvas|" .. ua .. "|" .. canvas_hash)
end

-- Issue localStorage token để persistent restore qua sessions.
local function issue_ls_token(id)
    local secret = cfg.pow.challenge_secret
    local ts     = tostring(ngx.time())
    local data   = id .. "|" .. ts
    local sig    = hmac_sha256_hex(secret, data)
    if not sig then return nil end
    return id .. "|" .. ts .. "|" .. sig
end

local function grant_verified(ctx, id, verified_ttl, canvas_hash)
    -- Key 1: cookie key (primary)
    pool.safe_set("verified:" .. id, "1", verified_ttl)

    -- Key 2: early_id (ip+ua) — same-IP fallback
    local ua = ngx.var.http_user_agent or ""
    local early_id = identity_mod.build_from(ctx.ip, ua)
    if early_id and early_id ~= id then
        pool.safe_set("verified:" .. early_id, "1", verified_ttl)
    end

    -- Key 3: device fingerprint (ua+canvas) — IP-independent fallback.
    -- Thay JA3 bằng canvas vì kiến trúc no-stream không capture được JA3.
    -- Canvas ổn định theo GPU/driver, không phụ thuộc IP hay TLS stack.
    -- Handles: đổi mạng WiFi→4G, Safari ITP xóa cookie, cookie expire,
    --          iCloud Private Relay, DHCP reassign.
    local device_id = build_device_id(ua, canvas_hash)
    if device_id then
        pool.safe_set("verified:device:" .. device_id, "1", verified_ttl)
        -- Bind device_id với (UA, IP /16) để whitelist.lua lookup ANTI cross-
        -- network leak. Trước đây chỉ bind UA → bot rotate IP cross-country
        -- với UA phổ biến của user thật bypass toàn bộ verify chain.
        -- /16 vẫn cho phép user di chuyển trong cùng carrier (4G/WiFi VN).
        local ip = ctx.ip or ""
        local ip16 = ip:match("^(%d+%.%d+)%.")
        if ip16 then
            local ua_hash = ngx.md5(ua)
            local key     = "device_ua:" .. ua_hash .. ":" .. ip16
            pool.safe_set(key, device_id, verified_ttl)
            ngx.log(ngx.INFO, "[verify] device_canvas_id=", device_id:sub(1,8),
                    " canvas=", canvas_hash:sub(1,8),
                    " ip16=", ip16)
        else
            ngx.log(ngx.WARN, "[verify] cannot bind device — invalid IP format")
        end
    else
        ngx.log(ngx.DEBUG, "[verify] no device_id: canvas missing")
    end

    -- Cookie với Secure flag
    local scheme = ngx.var.scheme or "http"
    local cookie_flags = "antibot_fp=" .. id
        .. "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" .. tostring(verified_ttl)
    if scheme == "https" then
        cookie_flags = cookie_flags .. "; Secure"
    end
    ngx.header["Set-Cookie"] = cookie_flags

    -- Issue localStorage token cho persistent restore
    local ls_token = issue_ls_token(id)
    ctx.verified = true
    ngx.log(ngx.INFO, "[verify] passed id=", id:sub(1,8),
            " ip=", ctx.ip or "?",
            " device_id=", device_id and device_id:sub(1,8) or "nil")

    local referer = ngx.var.http_referer
    local dest    = (referer and referer ~= "") and referer or "/"

    if ls_token then
        ngx.status = 200
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
        ngx.header["Cache-Control"] = "no-store"
        ngx.say(string.format([[<!doctype html><html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="0;url=%s">
</head><body>
<script>
try{localStorage.setItem('ab_token',%q);}catch(e){}
window.location.replace(%q);
</script>
</body></html>]], dest, ls_token, dest))
        ngx.exit(200)
    else
        ngx.header["Location"] = dest
        ngx.exit(302)
    end
end

function _M.run(ctx)
    ngx.req.read_body()
    local args   = ngx.req.get_post_args()
    local token  = args and args.token
    local n_str  = args and args.n
    local fp_arg = args and args.fp

    if not token or not n_str then
        ctx.verified = false
        ngx.log(ngx.WARN, "[verify] missing token/n ip=", ctx.ip)
        ngx.exit(400)
        return false
    end

    local id = fp_arg or ngx.var.cookie_antibot_fp or nil
    if not id or id == "" then
        ctx.verified = false
        ngx.log(ngx.WARN, "[verify] missing identity ip=", ctx.ip)
        ngx.exit(400)
        return false
    end

    ctx.identity = id
    ctx.fp_light = id

    local difficulty = cfg.pow.difficulty
    local pow_hash   = sha256_hex(token .. n_str)

    if not pow_hash or pow_hash:sub(1, #difficulty) ~= difficulty then
        ngx.log(ngx.WARN, "[verify] PoW failed id=", id:sub(1,8))
        ctx.verified = false
        pool.safe_incr("viol:" .. id, cfg.ttl.violation)
        ngx.exit(403)
        return false
    end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[verify] redis unavailable: ", tostring(err))
        ctx.verified = false; ngx.exit(500); return false
    end

    local deleted = red:del("nonce:" .. id)

    if deleted == 0 then
        local already = red:get("verified:" .. id)
        if already == ngx.null then already = nil end

        if already == "1" then
            -- Safe retry — đọc canvas từ Redis (đã lưu lần verify trước)
            local canvas_raw = red:get("fp:canvas:" .. id)
            if canvas_raw == ngx.null then canvas_raw = nil end
            pool.put(red)
            ngx.log(ngx.INFO, "[verify] retry_already_verified id=", id:sub(1,8))
            grant_verified(ctx, id, cfg.ttl.verified or 7200, canvas_raw or "")
            return true
        end

        pool.put(red)
        ngx.log(ngx.WARN, "[verify] nonce not found (replay?) id=", id:sub(1,8))
        ctx.verified = false; ngx.exit(403); return false
    end

    local verified_ttl = cfg.ttl.verified or 7200
    local canvas_hash  = args and args.cv or ""
    local solve_ms     = args and args.sm or ""

    check_canvas_consistency(red, id, ctx.ip or "", canvas_hash)
    flag_fast_solve(red, id, solve_ms)
    pool.put(red)

    grant_verified(ctx, id, verified_ttl, canvas_hash)
    return true
end

function _M.handle()
    local ctx = ngx.ctx.antibot or {}
    ngx.ctx.antibot = ctx
    ctx.ip = ngx.var.remote_addr
    _M.run(ctx)
end

return _M
