local _M = {}

-- ============================================================
-- Cross-phase bridge: ssl_client_hello_by_lua → access_by_lua
--
-- ngx.ctx KHÔNG persist giữa hai phase trên OpenResty 1.21+.
-- Dùng lua_shared_dict antibot_tls làm bridge.
--
-- RELAY 2 NHỊP (từ 2026-07-31). Vì sao không ghi thẳng md5(client_random) ở
-- phase ClientHello như trước: ĐO ĐƯỢC rằng OpenSSL chưa nạp client_random khi
-- callback ClientHello chạy — get_client_random(32) trả về 32 byte 0 trên MỌI
-- handshake ⇒ md5 = hằng số 70bc8f4b ⇒ cả dict chỉ có 1 entry, còn access phase
-- lại tính ra random THẬT nên không bao giờ khớp. Triệu chứng đánh lừa: ~20%
-- request "có ja3" (những request mà access phase cũng trả zero) đều mang CÙNG
-- một hash — không phải fingerprint của chúng, mà của handshake ghi sau cùng.
--
--   Nhịp 1 — ssl_client_hello_by_lua: parse được ClientHello (chỉ phase này có
--            ngx.ssl.clienthello.*) nhưng chưa có client_random → ghi tạm dưới
--            md5(raw_client_addr()), TTL ngắn.
--   Nhịp 2 — ssl_certificate_by_lua: client_random ĐÃ nạp (đo: zero=false) →
--            đọc entry tạm, ghi lại dưới md5(client_random), xoá entry tạm.
--            Gọi từ ja3s.capture() — không phải sửa 99 per-domain conf.
--   Đọc   — access_by_lua: md5(client_random), không đổi.
--
-- Cửa sổ va chạm của khoá tạm chỉ là khoảng cách giữa hai callback của CÙNG một
-- handshake (micro giây) → NAT chung IP không gây nhầm fingerprint.
-- ngx.var KHÔNG dùng được ở phase ClientHello (OpenResty 1.21+) nên
-- remote_addr:remote_port không phải lựa chọn.
--
-- Key format : "tls:<md5_of_client_random>"  /  tạm: "tlsq:<md5_of_client_addr>"
-- Value      : "tls13_flag|ext1-ext2|curve1-curve2|pt1-pt2"
-- TTL        : 300s (cover HTTP/2 long-lived + HTTP/1.1 keepalive)
-- HTTP/2     : nhiều request cùng handshake → cùng client_random → cùng key
-- ============================================================

local SHARED_DICT_NAME = "antibot_tls"
local TLS_KEY_PREFIX   = "tls:"
local TLS_KEY_TTL      = 300
local TMP_KEY_PREFIX   = "tlsq:"
local TMP_KEY_TTL      = 15

-- Bộ đếm rate-limit cho log chẩn đoán (per-worker, 1/200).
local _cap_n   = 0
local _relay_n = 0
local _diag_n  = 0

-- Khoá THẬT: md5(client_random) — unique per handshake.
-- Dùng ở ssl_certificate_by_lua* (nhịp 2) và access_by_lua* (đọc).
-- KHÔNG dùng được ở ssl_client_hello_by_lua*: ở đó random toàn byte 0.
-- Chuỗi toàn 0 bị TỪ CHỐI làm khoá — nếu chấp nhận, mọi client rơi vào tình
-- trạng đó sẽ dùng chung một ô và nhận fingerprint của nhau.
local function get_random_key()
    local ok, ssl_lib = pcall(require, "ngx.ssl")
    if not ok then
        return nil, "ngx.ssl module unavailable"
    end
    local random, err = ssl_lib.get_client_random(32)
    if not random or #random == 0 then
        return nil, err or "no client_random (plain HTTP?)"
    end
    if random:find("[^%z]") == nil then
        return nil, "zero client_random"
    end
    return ngx.md5(random)
end

-- Khoá TẠM: md5(raw_client_addr) — 4 byte (IPv4) / 16 byte (IPv6) nhị phân.
-- Là thứ duy nhất định danh được kết nối ở phase ClientHello (ngx.var bị disable).
local function get_addr_key()
    local ok, ssl_lib = pcall(require, "ngx.ssl")
    if not ok then
        return nil, "ngx.ssl module unavailable"
    end
    local ok2, addr, _, err = pcall(ssl_lib.raw_client_addr)
    if not ok2 then
        return nil, "raw_client_addr threw: " .. tostring(addr)
    end
    if not addr or #addr == 0 then
        return nil, err or "no client addr"
    end
    return ngx.md5(addr)
end

local function is_grease(val)
    if not val or val == 0 then return false end
    local lo = val % 256
    local hi = math.floor(val / 256) % 256
    return lo == hi and lo % 16 == 10
end

local function u16(s, pos)
    local a, b = s:byte(pos, pos + 1)
    if not a or not b then return nil, pos end
    return a * 256 + b, pos + 2
end

local function parse_supported_groups(ext_data)
    if not ext_data or #ext_data < 2 then return {} end
    local curves = {}
    local len, pos = u16(ext_data, 1)
    if not len then return {} end
    local bound = math.min(pos + len - 1, #ext_data)
    while pos + 1 <= bound do
        local g; g, pos = u16(ext_data, pos)
        if not g then break end
        if not is_grease(g) then curves[#curves + 1] = g end
    end
    return curves
end

local function parse_ec_point_formats(ext_data)
    if not ext_data or #ext_data < 1 then return {} end
    local fmts = {}
    local flen  = ext_data:byte(1)
    if not flen then return {} end
    local bound = math.min(1 + flen, #ext_data)
    for i = 2, bound do fmts[#fmts + 1] = ext_data:byte(i) end
    return fmts
end

local function build_ja3_str(ver, ciphers, exts, curves, pt_fmts)
    local function join(t)
        if not t or #t == 0 then return "" end
        local parts = {}
        for i, v in ipairs(t) do parts[i] = tostring(v) end
        return table.concat(parts, "-")
    end
    return ("%d,%s,%s,%s,%s"):format(
        ver, join(ciphers), join(exts), join(curves), join(pt_fmts))
end

local function serialize(is_tls13, extensions, curves, pt_fmts)
    local function join(t)
        if not t or #t == 0 then return "" end
        local parts = {}
        for i, v in ipairs(t) do parts[i] = tostring(v) end
        return table.concat(parts, "-")
    end
    return string.format("%s|%s|%s|%s",
        is_tls13 and "1" or "0",
        join(extensions),
        join(curves),
        join(pt_fmts))
end

local function deserialize(val)
    if not val then return nil end
    local parts = {}
    for segment in (val .. "|"):gmatch("([^|]*)|") do
        parts[#parts + 1] = segment
    end
    if #parts < 4 then return nil end

    local function split_nums(s)
        local t = {}
        if s and s ~= "" then
            for n in s:gmatch("[^-]+") do
                local num = tonumber(n)
                if num then t[#t + 1] = num end
            end
        end
        return t
    end

    return {
        is_tls13   = parts[1] == "1",
        extensions = split_nums(parts[2]),
        curves     = split_nums(parts[3]),
        pt_fmts    = split_nums(parts[4]),
    }
end

-- PHÒNG VỆ BẮT BUỘC: mọi lỗi Lua trong phase ssl_client_hello đều HUỶ BẮT TAY
-- → sập HTTPS diện rộng. Sự cố 2026-04-22: `ngx.var` bị vô hiệu ở phase này
-- ("API disabled in the current context") giết handshake, âm thầm 3 tháng.
-- capture_unsafe() có thể ném; wrapper NUỐT mọi lỗi — JA3 mất là chấp nhận được,
-- HTTPS sập thì không.
function _M.capture()
    local ok, err = pcall(_M.capture_unsafe)
    if not ok then
        ngx.log(ngx.ERR, "[ja3] capture ERROR (đã nuốt, handshake tiếp tục): ",
                tostring(err))
    end
end

function _M.capture_unsafe()
    local ok, ssl_clt = pcall(require, "ngx.ssl.clienthello")
    if not ok then
        ngx.log(ngx.ERR, "[ja3] require ngx.ssl.clienthello failed: ",
                tostring(ssl_clt))
        return
    end

    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then
        ngx.log(ngx.ERR, "[ja3] shared dict '", SHARED_DICT_NAME, "' not found")
        return
    end

    local addr_key, err = get_addr_key()
    if not addr_key then
        ngx.log(ngx.ERR, "[ja3] capture_miss reason=no_addr_key err=",
                tostring(err))
        return
    end

    local sv_data  = ssl_clt.get_client_hello_ext(0x002b)
    local is_tls13 = sv_data ~= nil and sv_data ~= ""

    local extensions = {}
    if type(ssl_clt.get_client_hello_ext_present) == "function" then
        local ok2, ext_present = pcall(ssl_clt.get_client_hello_ext_present)
        if ok2 and type(ext_present) == "table" then
            if ext_present[1] ~= nil then
                for _, etype in ipairs(ext_present) do
                    if type(etype) == "number" and not is_grease(etype) then
                        extensions[#extensions + 1] = etype
                    end
                end
            else
                ngx.log(ngx.WARN, "[ja3] ext_present is hash — order lost, ",
                        "upgrade lua-resty-core >= 0.1.25")
                for etype in pairs(ext_present) do
                    if type(etype) == "number" and not is_grease(etype) then
                        extensions[#extensions + 1] = etype
                    end
                end
            end
        elseif not ok2 then
            ngx.log(ngx.WARN, "[ja3] get_client_hello_ext_present error: ",
                    tostring(ext_present))
        end
    else
        ngx.log(ngx.WARN, "[ja3] get_client_hello_ext_present unavailable, ",
                "upgrade lua-resty-core >= 0.1.25")
    end

    local curves  = {}
    local sg_data = ssl_clt.get_client_hello_ext(0x000a)
    if sg_data then curves = parse_supported_groups(sg_data) end

    local pt_fmts = {}
    local pf_data = ssl_clt.get_client_hello_ext(0x000b)
    if pf_data then pt_fmts = parse_ec_point_formats(pf_data) end

    local val = serialize(is_tls13, extensions, curves, pt_fmts)
    local set_ok, set_err = shared:set(TMP_KEY_PREFIX .. addr_key, val,
                                       TMP_KEY_TTL)
    if not set_ok then
        ngx.log(ngx.ERR, "[ja3] capture_miss reason=set_failed err=",
                tostring(set_err))
        return
    end

    _cap_n = _cap_n + 1
    if _cap_n % 200 == 1 then
        ngx.log(ngx.ERR, "[ja3] capture_ok tmp=", addr_key:sub(1, 8),
                " n=", _cap_n, " tls13=", tostring(is_tls13),
                " #exts=", #extensions)
    end
end

-- ============================================================
-- Nhịp 2 — gọi từ ssl_certificate_by_lua* (qua ja3s.capture()).
-- Đổi khoá tạm (theo IP) sang khoá thật (theo client_random).
-- Caller ĐÃ bọc pcall; hàm này vẫn tự phòng vệ để lỗi không lan sang ja3s.
-- ============================================================
function _M.relay()
    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then return end

    local addr_key = get_addr_key()
    if not addr_key then return end

    local tmp_key = TMP_KEY_PREFIX .. addr_key
    local val = shared:get(tmp_key)
    if not val then
        -- Không có entry tạm: handshake nối lại phiên (ClientHello callback vẫn
        -- chạy nhưng entry đã hết TTL), hoặc capture() thoát sớm.
        _relay_n = _relay_n + 1
        if _relay_n % 200 == 1 then
            ngx.log(ngx.ERR, "[ja3] relay_miss reason=no_tmp tmp=",
                    addr_key:sub(1, 8), " n=", _relay_n)
        end
        return
    end

    local rand_key, err = get_random_key()
    if not rand_key then
        _relay_n = _relay_n + 1
        if _relay_n % 200 == 1 then
            ngx.log(ngx.ERR, "[ja3] relay_miss reason=no_random err=",
                    tostring(err), " n=", _relay_n)
        end
        return
    end

    shared:set(TLS_KEY_PREFIX .. rand_key, val, TLS_KEY_TTL)
    shared:delete(tmp_key)
end

-- Chẩn đoán vì sao run() không lấy được JA3.
-- Ba đường thoát dẫn tới ja3=nil trước đây đều return IM LẶNG (hoặc log DEBUG,
-- bị lọc) → một tính năng bảo mật chết 3 tháng mà error.log không một dấu vết.
-- Rate-limit 1/200 để không bloat log ở traffic cao (per-worker counter).
--
-- PHẢI là ngx.ERR, KHÔNG phải ngx.WARN: run() chạy ở access phase, tức trong
-- per-domain server block, mà da_to_openresty.sh ghi đè
-- `error_log /var/log/nginx/domains/<fqdn>.error.log;` KHÔNG kèm level →
-- mặc định `error` → mọi dòng WARN bị lọc sạch, không ghi ở đâu cả
-- (global error_log `warn` chỉ áp cho server không override — gần như không có).
-- Đã kiểm chứng 2026-07-31: WARN cho ra 0 dòng ở cả global/per-domain/antibot.log.
local function diag_miss(reason, extra)
    _diag_n = _diag_n + 1
    if _diag_n % 200 ~= 1 then return end
    ngx.log(ngx.ERR, "[ja3] run_miss reason=", reason,
            " n=", _diag_n, " ", extra or "")
end

function _M.run(ctx)
    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then
        diag_miss("no_shared_dict")
        ctx.ja3 = nil; ctx.ja3_raw = nil; ctx.ja3_partial = nil
        ctx.tls_version = nil; ctx.tls13 = nil
        return
    end

    local bridge_key, err = get_random_key()
    if not bridge_key then
        -- HTTP plain (err="no client_random"), hoặc access phase trả 32 byte 0
        -- (err="zero client_random"). Trường hợp sau THÀ MẤT JA3 còn hơn dùng:
        -- khoá zero là hằng số nên mọi client rơi vào đó sẽ đọc chung một ô và
        -- nhận fingerprint của nhau — chính là bug đã đo 2026-07-31.
        -- (KHÔNG dùng ctx.h2_is_h2: transport/init.lua chạy tls.run TRƯỚC
        --  http2.run nên trường đó luôn nil ở đây.)
        diag_miss("no_bridge_key", "err=" .. tostring(err)
                  .. " scheme=" .. tostring(ngx.var.scheme))
        ctx.ja3            = nil
        ctx.ja3_raw        = nil
        ctx.ja3_partial    = nil
        ctx.ja3_cipher_src = nil
        ctx.tls_version    = nil
        ctx.tls13          = nil
        return
    end

    local key = TLS_KEY_PREFIX .. bridge_key
    local val = shared:get(key)

    if not val then
        -- Khoá cầu nối tính được nhưng dict KHÔNG có entry. Ba nguyên nhân:
        --   a) capture() chưa từng chạy cho kết nối này (kết nối mở trước reload)
        --   b) entry HẾT HẠN — TLS_KEY_TTL=300s, mà kết nối H2 sống lâu hơn
        --   c) dict 10m ĐẦY → LRU evict (eviction KHÔNG báo lỗi ở set → im lặng)
        -- `free` phân biệt (c) với (a)/(b): free tụt gần 0 ⇒ dict quá nhỏ.
        -- Chỉ lấy mẫu khi thật sự sắp log (get_keys khoá dict — đắt). limit=4
        -- để vòng lặp dừng sớm. So khoá của ta với khoá đang có trong dict:
        --   dict rỗng            ⇒ capture() không ghi được
        --   toàn khoá lạ, đa dạng ⇒ hai phase thấy client_random khác nhau
        --   chỉ 1-2 khoá lặp lại  ⇒ client_random hằng ở phase ClientHello
        local sample = ""
        if (_diag_n + 1) % 200 == 1 then
            local ok_k, keys = pcall(shared.get_keys, shared, 4)
            if ok_k and type(keys) == "table" then
                local out = {}
                for i, k in ipairs(keys) do out[i] = k:sub(1, 12) end
                sample = " dict=[" .. table.concat(out, ",") .. "]"
            else
                sample = " dict=<get_keys failed>"
            end
        end
        diag_miss("dict_miss", "key=" .. bridge_key:sub(1, 8)
                  .. " free=" .. tostring(shared:free_space())
                  .. " cap=" .. tostring(shared:capacity())
                  .. sample)
        ctx.ja3            = nil
        ctx.ja3_raw        = nil
        ctx.ja3_partial    = nil
        ctx.ja3_cipher_src = nil
        ctx.tls_version    = nil
        ctx.tls13          = nil
        return
    end

    -- Không xóa key: HTTP/2 multiplexing nhiều request/connection
    -- Key tự expire sau TLS_KEY_TTL giây

    local data = deserialize(val)
    if not data then
        ngx.log(ngx.WARN, "[ja3] deserialize failed val=", tostring(val))
        ctx.ja3 = nil; ctx.tls13 = nil; ctx.ja3_partial = nil
        return
    end

    local client_ip   = ngx.var.remote_addr
    local client_port = ngx.var.remote_port

    local ciphers    = nil
    local cipher_src = "none"
    if client_ip and client_port then
        local ok2, stream_mod = pcall(require, "antibot.transport.tls.ja3_stream")
        if ok2 and stream_mod then
            ciphers = stream_mod.get_ciphers_for_request(client_ip, client_port)
            if ciphers then cipher_src = "stream_preread" end
        end
    end

    local is_partial = not ciphers or #ciphers == 0
    if is_partial then ciphers = {} end

    local tls_version = 0x0303
    local ja3_str  = build_ja3_str(tls_version, ciphers,
                                   data.extensions, data.curves, data.pt_fmts)
    local ja3_hash = ngx.md5(ja3_str)

    ctx.ja3            = ja3_hash
    ctx.ja3_raw        = ja3_str
    ctx.ja3_partial    = is_partial
    ctx.ja3_cipher_src = cipher_src
    ctx.tls_version    = tls_version
    ctx.tls13          = data.is_tls13

    if not is_partial then
        ngx.ctx.tls_ja3_hash = ja3_hash
    end

    ngx.log(ngx.DEBUG,
        "[ja3] run: key=", bridge_key:sub(1, 8),
        " hash=", ja3_hash,
        " tls13=", tostring(ctx.tls13),
        " partial=", tostring(is_partial),
        " #exts=", #data.extensions,
        " #curves=", #data.curves)
end

return _M
