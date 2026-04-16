local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local ffi = require "ffi"
local C   = ffi.C

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

local function hmac_sha256(key, data)
    local md     = ffi.new("unsigned char[?]", HMAC_LEN)
    local md_len = ffi.new("unsigned int[1]", HMAC_LEN)
    local result = C.HMAC(C.EVP_sha256(),
                          key, #key,
                          data, #data,
                          md, md_len)
    if result == nil then return nil end
    local hex = {}
    for i = 0, HMAC_LEN - 1 do
        hex[i+1] = string.format("%02x", md[i])
    end
    return table.concat(hex)
end

function _M.run(ctx)
    local id     = ctx.identity or ctx.fp_light or "unknown"
    local ts     = tostring(ngx.time())
    local nonce  = string.format("%06d", math.random(100000, 999999))
    local secret = cfg.pow.challenge_secret
    local data   = id .. "|" .. ts .. "|" .. nonce

    local token = hmac_sha256(secret, data)
    if not token then
        token = ngx.md5(data .. secret)
        ngx.log(ngx.WARN, "[challenge] HMAC-SHA256 unavailable, using MD5 fallback")
    end

    ctx.token    = token
    ctx.token_ts = ts

    ngx.log(ngx.DEBUG, "[challenge] token issued id=", id, " ts=", ts)
    return nonce
end

return _M
