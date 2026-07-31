local _M = {}

local bit = require "bit"

local function is_grease(val)
    if not val or val == 0 then return false end
    local lo = bit.band(val, 0xFF)
    local hi = bit.band(bit.rshift(val, 8), 0xFF)
    return lo == hi and bit.band(lo, 0x0F) == 0x0A
end

local function get_negotiated_info()
    local ok, ssl = pcall(require, "ngx.ssl")
    if not ok then
        return nil, "ngx.ssl not available"
    end

    local ver_str = ssl.get_tls1_version and ssl.get_tls1_version()
    local version = 0
    if ver_str then
        local VER_MAP = {
            ["SSLv3"]   = 0x0300,
            ["TLSv1"]   = 0x0301,
            ["TLSv1.1"] = 0x0302,
            ["TLSv1.2"] = 0x0303,
            ["TLSv1.3"] = 0x0304,
        }
        version = VER_MAP[ver_str] or 0
    end

    local cipher_name = ssl.get_cipher_name and ssl.get_cipher_name()
    local cipher_id   = 0

    if cipher_name then
        local CIPHER_MAP = {
            ["TLS_AES_128_GCM_SHA256"]              = 0x1301,
            ["TLS_AES_256_GCM_SHA384"]              = 0x1302,
            ["TLS_CHACHA20_POLY1305_SHA256"]         = 0x1303,
            ["ECDHE-ECDSA-AES128-GCM-SHA256"]       = 0xC02B,
            ["ECDHE-RSA-AES128-GCM-SHA256"]         = 0xC02F,
            ["ECDHE-ECDSA-AES256-GCM-SHA384"]       = 0xC02C,
            ["ECDHE-RSA-AES256-GCM-SHA384"]         = 0xC030,
            ["ECDHE-ECDSA-CHACHA20-POLY1305"]       = 0xCCA9,
            ["ECDHE-RSA-CHACHA20-POLY1305"]         = 0xCCA8,
            ["ECDHE-ECDSA-AES128-SHA256"]           = 0xC023,
            ["ECDHE-RSA-AES128-SHA256"]             = 0xC027,
            ["ECDHE-ECDSA-AES256-SHA384"]           = 0xC024,
            ["ECDHE-RSA-AES256-SHA384"]             = 0xC028,
            ["ECDHE-ECDSA-AES128-SHA"]              = 0xC009,
            ["ECDHE-RSA-AES128-SHA"]                = 0xC013,
            ["ECDHE-ECDSA-AES256-SHA"]              = 0xC00A,
            ["ECDHE-RSA-AES256-SHA"]                = 0xC014,
            ["AES128-GCM-SHA256"]                   = 0x009C,
            ["AES256-GCM-SHA384"]                   = 0x009D,
            ["AES128-SHA256"]                       = 0x003C,
            ["AES256-SHA256"]                       = 0x003D,
            ["AES128-SHA"]                          = 0x002F,
            ["AES256-SHA"]                          = 0x0035,
        }
        cipher_id = CIPHER_MAP[cipher_name] or 0
    end

    local extensions = {}

    if version == 0x0303 then
        extensions[#extensions + 1] = 0xFF01
    end

    if version == 0x0303 then
        extensions[#extensions + 1] = 0x0017
    end

    return {
        version    = version,
        cipher     = cipher_id,
        cipher_name= cipher_name,
        extensions = extensions,
    }
end

local function build_ja3s_str(info)
    local exts = {}
    for i, v in ipairs(info.extensions) do
        if not is_grease(v) then
            exts[i] = tostring(v)
        end
    end

    return string.format("%d,%d,%s",
        info.version,
        info.cipher,
        table.concat(exts, "-")
    )
end

-- PHÒNG VỆ BẮT BUỘC (cùng bài học 2026-04-22 với ja3.capture): mọi lỗi Lua
-- trong ssl_certificate_by_lua đều HUỶ BẮT TAY → sập HTTPS. Nuốt lỗi + log ERR.
function _M.capture()
    local ok, err = pcall(_M.capture_unsafe)
    if not ok then
        ngx.log(ngx.ERR, "[ja3s] capture ERROR (đã nuốt, handshake tiếp tục): ",
                tostring(err))
    end
end

function _M.capture_unsafe()
    -- Nhịp 2 của relay JA3: phase này là nơi ĐẦU TIÊN client_random được nạp
    -- (phase ClientHello trả toàn byte 0 — đo 2026-07-31), nên đây là nơi duy
    -- nhất đổi được khoá tạm (theo IP) sang khoá thật. Đặt ở đây thay vì thêm
    -- lệnh vào ssl_certificate_by_lua_block để khỏi phải sửa 99 per-domain conf.
    -- pcall riêng: hai fingerprint độc lập nhau, hỏng cái này không được kéo
    -- cái kia theo (cùng lý do phải bọc pcall toàn hàm — xem trên).
    local ok_r, err_r = pcall(function()
        require("antibot.transport.tls.ja3").relay()
    end)
    if not ok_r then
        ngx.log(ngx.ERR, "[ja3s] relay ERROR (đã nuốt): ", tostring(err_r))
    end

    local info, err = get_negotiated_info()
    if not info then
        ngx.log(ngx.ERR, "[ja3s] capture_miss err=", tostring(err))
        return
    end

    local ja3s_str  = build_ja3s_str(info)
    local ja3s_hash = ngx.md5(ja3s_str)

    ngx.ctx.tls_ja3s      = ja3s_hash
    ngx.ctx.tls_ja3s_raw  = ja3s_str
    ngx.ctx.tls_cipher    = info.cipher_name

    ngx.log(ngx.DEBUG, "[ja3s.capture] hash=", ja3s_hash,
            " cipher=", tostring(info.cipher_name),
            " ver=", info.version)
end

function _M.run(ctx)
    local ja3s = ngx.ctx.tls_ja3s
    if ja3s and ja3s ~= "" then
        ctx.ja3s       = ja3s
        ctx.ja3s_raw   = ngx.ctx.tls_ja3s_raw
        ctx.tls_cipher = ngx.ctx.tls_cipher
        ngx.log(ngx.DEBUG, "[ja3s.run] ja3s=", ja3s)
    end
end

return _M
