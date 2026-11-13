-- Minimal IPv4/IPv6 parser used by the trusted-proxy boundary.
--
-- This module is deliberately pure Lua: proxy provenance is needed before any
-- Redis/network work and must also be testable outside a live nginx worker.

local _M = {}

local function trim(s)
    if type(s) ~= "string" then return nil end
    s = s:match("^%s*(.-)%s*$")
    if not s or s == "" then return nil end
    return s
end

local function parse_v4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local out = { tonumber(a), tonumber(b), tonumber(c), tonumber(d) }
    for i = 1, 4 do
        if not out[i] or out[i] < 0 or out[i] > 255 then return nil end
    end
    return { family = 4, words = out }
end

local function split_v6_side(side)
    local out = {}
    if side == "" then return out end
    if side:sub(1, 1) == ":" or side:sub(-1) == ":" then return nil end
    for word in side:gmatch("[^:]+") do
        if #word < 1 or #word > 4 or not word:match("^[%da-f]+$") then
            return nil
        end
        out[#out + 1] = tonumber(word, 16)
    end
    return out
end

local function parse_v6(s)
    s = s:lower()
    if not s:match("^[%da-f:%.]+$") then return nil end

    -- Convert an embedded IPv4 tail (::ffff:192.0.2.1) to two hextets first.
    local tail = s:match("([^:]+)$")
    if tail and tail:find(".", 1, true) then
        local v4 = parse_v4(tail)
        if not v4 then return nil end
        local w = v4.words
        local replacement = string.format("%x:%x", w[1] * 256 + w[2],
                                            w[3] * 256 + w[4])
        s = s:sub(1, #s - #tail) .. replacement
    end

    local ds, de = s:find("::", 1, true)
    if ds and s:find("::", de + 1, true) then return nil end

    local left, right
    if ds then
        left  = split_v6_side(s:sub(1, ds - 1))
        right = split_v6_side(s:sub(de + 1))
    else
        left  = split_v6_side(s)
        right = {}
    end
    if not left or not right then return nil end

    local used = #left + #right
    if (ds and used >= 8) or (not ds and used ~= 8) then return nil end

    local out = {}
    for i = 1, #left do out[#out + 1] = left[i] end
    if ds then
        for _ = 1, 8 - used do out[#out + 1] = 0 end
    end
    for i = 1, #right do out[#out + 1] = right[i] end
    if #out ~= 8 then return nil end
    return { family = 6, words = out }
end

function _M.parse(ip)
    ip = trim(ip)
    if not ip then return nil end
    -- Header values must be bare addresses, never host:port or [v6]:port.
    if ip:sub(1, 1) == "[" or ip:find("%%", 1, true) then return nil end
    if ip:find(".", 1, true) and not ip:find(":", 1, true) then
        return parse_v4(ip)
    end
    if ip:find(":", 1, true) then return parse_v6(ip) end
    return nil
end

local function mapped_v4(parsed)
    if not parsed or parsed.family ~= 6 then return nil end
    local w = parsed.words
    if w[1] ~= 0 or w[2] ~= 0 or w[3] ~= 0 or w[4] ~= 0
       or w[5] ~= 0 or w[6] ~= 0xffff then
        return nil
    end
    return { family = 4, words = {
        math.floor(w[7] / 256), w[7] % 256,
        math.floor(w[8] / 256), w[8] % 256,
    } }
end

function _M.normalize(ip)
    local parsed = type(ip) == "table" and ip or _M.parse(ip)
    if not parsed then return nil end
    parsed = mapped_v4(parsed) or parsed
    if parsed.family == 4 then
        return table.concat(parsed.words, ".")
    end
    local out = {}
    for i = 1, 8 do out[i] = string.format("%x", parsed.words[i]) end
    return table.concat(out, ":")
end

function _M.is_public(ip)
    local parsed = type(ip) == "table" and ip or _M.parse(ip)
    if not parsed then return false end
    parsed = mapped_v4(parsed) or parsed

    if parsed.family == 4 then
        local a, b, c, d = parsed.words[1], parsed.words[2],
                           parsed.words[3], parsed.words[4]
        if a == 0 or a == 10 or a == 127 or a >= 224 then return false end
        if a == 100 and b >= 64 and b <= 127 then return false end
        if a == 169 and b == 254 then return false end
        if a == 172 and b >= 16 and b <= 31 then return false end
        if a == 192 and b == 168 then return false end
        if a == 198 and (b == 18 or b == 19) then return false end
        -- Documentation/special-use nets cannot be an Internet client source.
        if a == 192 and b == 0 and (c == 0 or c == 2) then return false end
        if a == 198 and b == 51 and c == 100 then return false end
        if a == 203 and b == 0 and c == 113 then return false end
        if a == 255 and b == 255 and c == 255 and d == 255 then return false end
        return true
    end

    local w = parsed.words
    local all_zero = true
    for i = 1, 8 do if w[i] ~= 0 then all_zero = false; break end end
    if all_zero then return false end
    local loopback = true
    for i = 1, 7 do if w[i] ~= 0 then loopback = false; break end end
    if loopback and w[8] == 1 then return false end
    if w[1] >= 0xfc00 and w[1] <= 0xfdff then return false end -- ULA /7
    if w[1] >= 0xfe80 and w[1] <= 0xfebf then return false end -- link-local /10
    if w[1] >= 0xff00 then return false end                    -- multicast /8
    if w[1] == 0x2001 and w[2] == 0x0db8 then return false end -- documentation
    return true
end

function _M.compile(spec)
    spec = trim(spec)
    if not spec then return nil, "empty CIDR" end
    local addr, bits = spec:match("^([^/]+)/(%d+)$")
    if not addr then addr, bits = spec, nil end
    local parsed = _M.parse(addr)
    if not parsed then return nil, "invalid address" end
    local max = parsed.family == 4 and 32 or 128
    bits = bits and tonumber(bits) or max
    if not bits or bits < 0 or bits > max then return nil, "invalid prefix" end
    return { family = parsed.family, words = parsed.words,
             bits = bits, source = spec }
end

function _M.contains(compiled, ip)
    if not compiled then return false end
    local parsed = type(ip) == "table" and ip or _M.parse(ip)
    if not parsed or parsed.family ~= compiled.family then return false end
    local width = parsed.family == 4 and 8 or 16
    local full = math.floor(compiled.bits / width)
    local rem  = compiled.bits % width
    for i = 1, full do
        if parsed.words[i] ~= compiled.words[i] then return false end
    end
    if rem > 0 then
        local div = 2 ^ (width - rem)
        if math.floor(parsed.words[full + 1] / div)
           ~= math.floor(compiled.words[full + 1] / div) then
            return false
        end
    end
    return true
end

function _M.compile_list(list)
    local out, errors = {}, {}
    for i = 1, #(list or {}) do
        local item, err = _M.compile(list[i])
        if item then out[#out + 1] = item
        else errors[#errors + 1] = tostring(list[i]) .. ": " .. tostring(err) end
    end
    return out, errors
end

function _M.contains_any(compiled_list, ip)
    local parsed = type(ip) == "table" and ip or _M.parse(ip)
    if not parsed then return false end
    for i = 1, #(compiled_list or {}) do
        if _M.contains(compiled_list[i], parsed) then return true end
    end
    return false
end

return _M
