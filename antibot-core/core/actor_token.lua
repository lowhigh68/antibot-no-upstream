-- Host-bound browser actor for durable quarantine state.
--
-- This token does NOT grant trust and is not a device fingerprint.  It only
-- gives a returning client an opaque, non-network subject so a future sentence
-- cannot spill across CGNAT, an office WAN, another tenant, or a proxy edge.
-- A SID issued in the current response never becomes `actor_presented`; the
-- client must return the signed cookie on a later request first.

local _M = {}

local cfg        = require "antibot.core.config"
local secrets    = require "antibot.core.secrets"
local site_scope = require "antibot.core.site_scope"

local ffi = require "ffi"
local C   = ffi.C
local bit = require "bit"

pcall(function()
    ffi.cdef([[
        unsigned char *HMAC(const void *evp_md,
                            const void *key, int key_len,
                            const unsigned char *data, size_t data_len,
                            unsigned char *md, unsigned int *md_len);
        const void *EVP_sha256(void);
    ]])
end)

local HMAC_LEN = 32
local secret_error_logged = false
local crypto_error_logged = false

local function hmac_sha256(key, data)
    local ok, value = pcall(function()
        local md     = ffi.new("unsigned char[?]", HMAC_LEN)
        local md_len = ffi.new("unsigned int[1]", HMAC_LEN)
        local result = C.HMAC(C.EVP_sha256(), key, #key,
                              data, #data, md, md_len)
        if result == nil or tonumber(md_len[0]) ~= HMAC_LEN then return nil end
        local out = {}
        for i = 0, HMAC_LEN - 1 do
            out[i + 1] = string.format("%02x", md[i])
        end
        return table.concat(out)
    end)
    if not ok then return nil end
    return value
end

local function constant_time_equal(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bit.bor(diff, bit.bxor(a:byte(i), b:byte(i)))
    end
    return diff == 0
end

local function token_data(host, nonce, issued_at)
    return "v1|" .. host .. "|" .. nonce .. "|" .. tostring(issued_at)
end

local function actor_id(host, nonce)
    return ngx.md5("actor-v1|" .. host .. "|" .. nonce)
end

local function cookie_value(name)
    local var = ngx.var or {}
    local direct = var["cookie_" .. name]
    if direct and direct ~= "" then return direct end
    local raw = var.http_cookie or ""
    local escaped = name:gsub("([^%w])", "%%%1")
    return (";" .. raw):match(";%s*" .. escaped .. "=([^;]+)")
end

local function append_set_cookie(value)
    local current = ngx.header["Set-Cookie"]
    if current == nil then
        ngx.header["Set-Cookie"] = value
    elseif type(current) == "table" then
        current[#current + 1] = value
        ngx.header["Set-Cookie"] = current
    else
        ngx.header["Set-Cookie"] = { current, value }
    end
end

local function random_nonce()
    local ok, random = pcall(require, "resty.random")
    if not ok or not random or type(random.bytes) ~= "function" then
        return nil, "secure_random_unavailable"
    end
    local good, raw = pcall(random.bytes, 16, true)
    if not good or type(raw) ~= "string" or #raw ~= 16 then
        return nil, "secure_random_failed"
    end
    return (raw:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function verify(raw, host, now)
    if type(raw) ~= "string" or #raw > 160 then return nil, "format" end
    local nonce, ts_text, mac = raw:match("^v1%.([0-9a-f]+)%.(%d+)%.([0-9a-f]+)$")
    if not nonce or #nonce ~= 32 or not mac or #mac ~= 64 then
        return nil, "format"
    end
    local issued_at = tonumber(ts_text)
    if not issued_at then return nil, "time" end

    local acfg = cfg.actor or {}
    local ttl = math.max(tonumber(acfg.ttl) or 2592000, 300)
    local skew = math.max(tonumber(acfg.future_skew) or 300, 0)
    if issued_at > now + skew then return nil, "future" end
    if issued_at < now - ttl then return nil, "expired" end

    local keys, key_err = secrets.actor_secrets()
    if not keys then return nil, key_err or "secret_unavailable" end
    local data = token_data(host, nonce, issued_at)
    local expected = hmac_sha256(keys.current, data)
    if expected and constant_time_equal(expected, mac) then
        return actor_id(host, nonce), "signed_current"
    end
    if keys.previous then
        expected = hmac_sha256(keys.previous, data)
        if expected and constant_time_equal(expected, mac) then
            return actor_id(host, nonce), "signed_previous"
        end
    end
    if not expected then return nil, "crypto_unavailable" end
    return nil, "signature"
end

function _M.resolve(ctx)
    local name = ((cfg.actor or {}).cookie_name or "antibot_sid")
    local raw = cookie_value(name)
    if not raw or raw == "" then return true, false end

    local host = site_scope.host(ctx)
    local id, kind_or_err = verify(raw, host, ngx.time())
    if not id then
        ctx.actor_invalid = kind_or_err
        ctx.actor_valid = false
        return true, false
    end

    ctx.actor_id        = id
    ctx.actor_kind      = kind_or_err
    ctx.actor_presented = true
    ctx.actor_valid     = true
    ctx.actor_invalid   = nil
    return true, false
end

function _M.issue(ctx)
    if ctx.actor_presented == true and ctx.actor_valid == true then return true end
    if ctx.actor_issued == true then return true end

    local keys, key_err = secrets.actor_secrets()
    if not keys then
        ctx.actor_issue_error = "secret_unavailable"
        if not secret_error_logged then
            secret_error_logged = true
            ngx.log(ngx.ERR, "[actor] signing secret unavailable: ",
                    tostring(key_err))
        end
        return nil, ctx.actor_issue_error
    end

    local nonce, random_err = random_nonce()
    if not nonce then
        ctx.actor_issue_error = random_err
        return nil, random_err
    end
    local host = site_scope.host(ctx)
    local issued_at = ngx.time()
    local mac = hmac_sha256(keys.current, token_data(host, nonce, issued_at))
    if not mac then
        ctx.actor_issue_error = "crypto_unavailable"
        if not crypto_error_logged then
            crypto_error_logged = true
            ngx.log(ngx.ERR, "[actor] HMAC-SHA256 unavailable; SID not issued")
        end
        return nil, ctx.actor_issue_error
    end

    local ttl = math.max(tonumber((cfg.actor or {}).ttl) or 2592000, 300)
    local name = ((cfg.actor or {}).cookie_name or "antibot_sid")
    local value = table.concat({"v1", nonce, tostring(issued_at), mac}, ".")
    local cookie = name .. "=" .. value
        .. "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" .. tostring(ttl)
    if (ngx.var.scheme or "http") == "https" then cookie = cookie .. "; Secure" end
    append_set_cookie(cookie)

    ctx.actor_issued = true
    ctx.actor_issue_error = nil
    ctx.actor_issued_id = actor_id(host, nonce) -- telemetry only; never a q2 subject
    return true
end

-- Test-only helpers keep contract tests deterministic without weakening the
-- production API or accepting caller-provided actor IDs.
_M._verify_for_test = verify
_M._hmac_for_test = hmac_sha256
_M._data_for_test = token_data

return _M
