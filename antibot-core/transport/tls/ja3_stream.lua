local _M = {}

local SHARED_DICT_NAME  = "antibot_tls"
local CIPHER_KEY_PREFIX = "ciphers:"
local CIPHER_KEY_TTL    = 10

local TLS_RECORD_HDR_LEN = 5
local MAX_RECORD_LEN     = 16383
local MIN_HELLO_BODY     = 41

local RECV_TIMEOUT_MS    = 5000

local function is_grease(val)
    if not val or val == 0 then return false end
    local lo = val % 256
    local hi = math.floor(val / 256) % 256
    return lo == hi and lo % 16 == 10
end

local function get_shared()
    local d = ngx.shared[SHARED_DICT_NAME]
    if not d then
        ngx.log(ngx.ERR,
            "[ja3_stream] shared dict '", SHARED_DICT_NAME, "' not found. ",
            "Add: lua_shared_dict ", SHARED_DICT_NAME, " 10m; ",
            "to BOTH stream{} and http{} blocks in nginx.conf")
    end
    return d
end

local function make_key(ip, port)
    return CIPHER_KEY_PREFIX .. ip .. ":" .. port
end

local function receive_exact(sock, n)
    local buf = {}
    local received = 0
    while received < n do
        local chunk, err, partial = sock:receive(n - received)
        if chunk then
            buf[#buf + 1] = chunk
            received = received + #chunk
        elseif partial and #partial > 0 then
            buf[#buf + 1] = partial
            received = received + #partial
            if err == "closed" then
                return nil, "connection closed after " .. received .. "/" .. n
            end
        else
            return nil, "receive error: " .. tostring(err)
        end
    end
    return table.concat(buf)
end

local function parse_cipher_suites(body)
    if not body then return nil, "nil_body" end
    local blen = #body
    if blen < MIN_HELLO_BODY then
        return nil, "too_short=" .. blen
    end

    local hs_type = body:byte(1)
    if hs_type ~= 0x01 then
        return nil, "not_client_hello hs_type=" .. tostring(hs_type)
    end

    local pos = 39

    if pos > blen then return nil, "oob_before_sid" end
    local sid_len = body:byte(pos)
    pos = pos + 1 + sid_len

    if pos + 1 > blen then return nil, "oob_before_cs" end

    local cs_hi = body:byte(pos)
    local cs_lo = body:byte(pos + 1)
    local cs_len = cs_hi * 256 + cs_lo
    pos = pos + 2

    if cs_len == 0 then
        return nil, "empty_cipher_list"
    end
    if cs_len % 2 ~= 0 then
        return nil, "odd_cs_len=" .. cs_len
    end
    if pos + cs_len - 1 > blen then
        return nil, "oob_ciphers need=" .. (pos + cs_len - 1) .. " have=" .. blen
    end

    local ciphers = {}
    local cs_end  = pos + cs_len
    while pos < cs_end do
        local hi = body:byte(pos)
        local lo = body:byte(pos + 1)
        pos = pos + 2
        if hi and lo then
            local c = hi * 256 + lo
            if not is_grease(c) then
                ciphers[#ciphers + 1] = c
            end
        end
    end

    if #ciphers == 0 then
        return nil, "all_grease_or_empty"
    end

    return ciphers
end

function _M.preread()
    local shared = get_shared()
    if not shared then return end

    local client_ip   = ngx.var.remote_addr
    local client_port = ngx.var.remote_port
    if not client_ip or not client_port then
        ngx.log(ngx.WARN, "[ja3_stream] no client addr info")
        return
    end

    local sock, err = ngx.req.socket()
    if not sock then
        ngx.log(ngx.WARN, "[ja3_stream] no socket: ", tostring(err))
        return
    end
    sock:settimeout(RECV_TIMEOUT_MS)

    local hdr, hdr_err = receive_exact(sock, TLS_RECORD_HDR_LEN)
    if not hdr then
        ngx.log(ngx.DEBUG, "[ja3_stream] header recv failed: ", hdr_err)
        return
    end

    local rec_type = hdr:byte(1)
    if rec_type ~= 0x16 then
        ngx.log(ngx.DEBUG,
            "[ja3_stream] not TLS handshake rec_type=0x",
            ("%02x"):format(rec_type))
        return
    end

    local rl_hi = hdr:byte(4)
    local rl_lo = hdr:byte(5)
    local record_len = rl_hi * 256 + rl_lo

    if record_len == 0 then
        ngx.log(ngx.DEBUG, "[ja3_stream] zero record_len")
        return
    end
    if record_len > MAX_RECORD_LEN then
        ngx.log(ngx.WARN,
            "[ja3_stream] record_len too large=", record_len,
            " (max ", MAX_RECORD_LEN, ")")
        return
    end
    if record_len < MIN_HELLO_BODY + 4 then
        ngx.log(ngx.DEBUG,
            "[ja3_stream] record too small for ClientHello: ", record_len)
        return
    end

    local body, body_err = receive_exact(sock, record_len)
    if not body then
        ngx.log(ngx.WARN,
            "[ja3_stream] body recv failed (record_len=", record_len,
            "): ", body_err)
        return
    end

    local ciphers, parse_err = parse_cipher_suites(body)
    if not ciphers then
        ngx.log(ngx.DEBUG,
            "[ja3_stream] parse failed: ", tostring(parse_err),
            " body_len=", #body)
        return
    end

    local key = make_key(client_ip, client_port)
    local val = table.concat(ciphers, ",")

    local ok, set_err, forcible = shared:set(key, val, CIPHER_KEY_TTL)
    if not ok then
        ngx.log(ngx.WARN,
            "[ja3_stream] shared dict set failed: ", tostring(set_err))
        return
    end
    if forcible then
        ngx.log(ngx.WARN, "[ja3_stream] shared dict forcibly evicted entries")
    end

    ngx.log(ngx.DEBUG,
        "[ja3_stream] stored ciphers key=", key,
        " count=", #ciphers,
        " record_len=", record_len)
end

function _M.get_ciphers_for_request(ip, port)
    if not ip or not port then return nil end
    local shared = get_shared()
    if not shared then return nil end

    local key = make_key(ip, port)
    local val = shared:get(key)
    if not val then return nil end

    shared:delete(key)

    local ciphers = {}
    for s in val:gmatch("[^,]+") do
        local n = tonumber(s)
        if n then ciphers[#ciphers + 1] = n end
    end

    return #ciphers > 0 and ciphers or nil
end

return _M
