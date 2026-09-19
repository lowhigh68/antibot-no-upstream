-- proxy_origin — "request nay den qua mot reverse proxy cong cong khong".
--
-- VI SAO CAN MOT TANG RIENG. Tren dan may nay `$remote_addr` la dia chi client
-- that (khong co `upstream` block, khong `set_real_ip_from`). Voi domain dat sau
-- Cloudflare thi dieu do KHONG con dung: `ctx.ip` la dia chi EDGE, va moi tang
-- khoa theo IP dang gom hang tram khach that thanh MOT thuc the.
--
-- Do 19-09-2026 tren `in3mien.com` (cloud171-96): **431 IP edge phuc vu 456
-- identity**, trong do **218 luot co cookie that** (`rown` 0.65 va 0.80). Nhung
-- `rate:<ip>`, `ip_risk:<ip>`, `ext_rep`, `ip_tour` deu tinh ho nhu mot.
--
-- ┌─ DIEU TANG NAY KHONG LAM, VA KHONG BAO GIO DUOC LAM ─────────────────────┐
-- │ KHONG khoi phuc "IP that" tu header. KHONG doc GIA TRI cua                │
-- │ `CF-Connecting-IP` / `X-Forwarded-For` / `True-Client-IP`.                 │
-- │                                                                            │
-- │ Vi sao: `ctx.ip` la khoa cua ban / rate / reputation. Tin gia tri mot       │
-- │ header nghia la BAT KY AI cung tu khai duoc danh tinh cua minh — gui        │
-- │ `CF-Connecting-IP: 8.8.8.8` la day toan bo lich su xau sang mot dia chi     │
-- │ khac, hoac muon lai uy tin sach cua no. Ke tan cong thue mot CF Worker thi  │
-- │ ca dieu kien "ip thuoc dai CF" cung thoa. Fleet nay CO Y khong tich hop     │
-- │ Cloudflare; tang nay khong mo cua sau cho quyet dinh do.                    │
-- └────────────────────────────────────────────────────────────────────────────┘
--
-- BAT DOI XUNG AN TOAN — nguyen tac trung tam cua file nay:
--   Header CHI duoc phep lam request bi soi KY HON, khong bao gio nhe hon.
--   `ctx.behind_proxy` (duoc giam trong so) den TU DAI IP da xac minh, khong tu
--   header. Con header ma MAU THUAN voi dai IP thi thanh tin hieu XAU.
--
-- Vi tri: PHAI truoc `l7.ban.ip_ban_check` (buoc 6 cua STEPS_COMMON) de moi
-- tang khoa theo IP doc duoc co. Hau qua: o day KHONG CO tin hieu transport
-- (`ja3` / `tls13` / `h2` nam o buoc 11) — dung dua thiet ke nao vao chung.
-- Xem `memory/feedback_flag_read_before_write.md`.

local _M    = {}
local pool  = require "antibot.core.redis_pool"
local cache = ngx.shared.antibot_cache

-- Dai IP Cloudflare cong bo tai https://www.cloudflare.com/ips/
-- Kiem bang so nguyen 32-bit, KHONG bang tien to chuoi thap phan: mot khoi nhu
-- `104.16.0.0/13` trai dai `104.16`..`104.23` nen tien to chuoi vua bo sot vua
-- bat lan (`104.1[6-9]` khong phu `104.2x`). Chinh mot regex tien to kieu do da
-- lam toi doc sai mot phep do hom 19-09.
local CF_V4_CIDRS = {
    { "173.245.48.0",  20 }, { "103.21.244.0",  22 }, { "103.22.200.0", 22 },
    { "103.31.4.0",    22 }, { "141.101.64.0",  18 }, { "108.162.192.0",18 },
    { "190.93.240.0",  20 }, { "188.114.96.0",  20 }, { "197.234.240.0",22 },
    { "198.41.128.0",  17 }, { "162.158.0.0",   15 }, { "104.16.0.0",   13 },
    { "104.24.0.0",    14 }, { "172.64.0.0",    13 }, { "131.0.72.0",   22 },
}

local function ip_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- Dung luy thua thay vi `bit.band`: khong phu thuoc module `bit`, va
-- `2^(32-bits)` la so phan tu cua khoi. LuaJIT tra ve FLOAT o day, nhung moi gia
-- tri deu <= 2^32 nen so sanh voi so nguyen la chinh xac tuyet doi (float 64-bit
-- bieu dien dung moi so nguyen duoi 2^53). Khong lam tron, khong mat bit.
local CF_RANGES = nil
local function build_ranges()
    local t = {}
    for i = 1, #CF_V4_CIDRS do
        local base, bits = CF_V4_CIDRS[i][1], CF_V4_CIDRS[i][2]
        local n = ip_to_int(base)
        if n then
            local size = 2 ^ (32 - bits)
            t[#t + 1] = { lo = n, hi = n + size - 1 }
        end
    end
    return t
end

function _M.is_cloudflare(ip)
    if not ip or ip == "" then return false end
    if not CF_RANGES then CF_RANGES = build_ranges() end
    local n = ip_to_int(ip)
    if not n then return false end          -- IPv6: chua phu, tra false (fail-open)
    for i = 1, #CF_RANGES do
        local r = CF_RANGES[i]
        if n >= r.lo and n <= r.hi then return true end
    end
    return false
end

-- Header CHI de phat hien MAO DANH, khong bao gio de lay dia chi.
local PROXY_CLAIM_HEADERS = {
    "cf-connecting-ip", "true-client-ip", "x-forwarded-for", "x-real-ip",
}

-- Khai tay cho proxy KHONG phai Cloudflare (Fastly, Bunny, Sucuri, hoac proxy
-- noi bo cua khach). Ghi bang:
--     redis-cli SADD waf:proxyhosts example.com www.example.com
--
-- MOT KHOA TAP HOP, khong phai mot khoa moi host. Ly do la chi phi o duong nong:
-- module nay chay o BUOC 6 cho MOI request, va `antibot_cache` chi 5m dung chung
-- voi `waf:fimnew:`, dau `wp_paths`, v.v. Khi LRU duoi key thi mot so do
-- `waf:proxyhost:<host>` se cham Redis MOI REQUEST cho moi host chua cache — 74
-- domain nhan len thanh mot RTT them vao duong nong. Voi mot khoa tap hop thi
-- xau nhat cung chi la MOT lan doc moi 300s cho toan may.
--
-- Danh sach hien tai rong (0 host khai). Neu no rong thi phep kiem la mot phep
-- so sanh chuoi trong bo nho, khong cham Redis.
local HOSTS_TTL  = 300
local HOSTS_KEY  = "waf:proxyhosts"
local HOSTS_CK   = "proxyhosts:set"

-- Tra ve chuoi "|host1|host2|" (rong = "|") de kiem bang `find` plain-text.
local function declared_set()
    if cache then
        local v = cache:get(HOSTS_CK)
        if v then return v end
    end
    local joined = "|"
    local red = pool.get()
    if red then
        local members = red:smembers(HOSTS_KEY)
        pool.put(red)
        if type(members) == "table" then
            for i = 1, #members do
                joined = joined .. members[i] .. "|"
            end
        end
    end
    -- Cache CA khi rong: "khong co host nao khai" cung la mot cau tra loi, va no
    -- la cau tra loi thuong gap nhat. Thieu buoc nay thi SMEMBERS chay moi request.
    if cache then cache:set(HOSTS_CK, joined, HOSTS_TTL) end
    return joined
end

local function host_declared(host)
    if not host or host == "" then return false end
    local set = declared_set()
    if set == "|" then return false end          -- khong ai khai: thoat khong cham gi
    return set:find("|" .. host .. "|", 1, true) ~= nil
end

function _M.run(ctx)
    local ip   = ctx.ip
    local host = (ctx.req and ctx.req.host) or ngx.var.host

    local by_range = _M.is_cloudflare(ip)
    local by_host  = (not by_range) and host_declared(host) or false

    -- `behind_proxy` chi bat tu DAI IP da xac minh hoac khai bao cua operator.
    -- KHONG BAO GIO tu header.
    if by_range or by_host then
        ctx.behind_proxy = true
        ctx.proxy_vendor = by_range and "cloudflare" or "declared"
    end

    -- Header khai la proxy nhung dia chi KHONG thuoc dai nao da xac minh
    -- ⇒ MAO DANH. Do 19-09: 12 luot `msmobile.vn` + 2 luot `no1computer.vn`
    -- (hai site KHONG dung CF) co luu luong mang dau hieu nay.
    --
    -- Day la huong DUY NHAT header duoc phep anh huong diem: lam TANG.
    if not ctx.behind_proxy then
        local h = ngx.req.get_headers()
        for i = 1, #PROXY_CLAIM_HEADERS do
            local v = h[PROXY_CLAIM_HEADERS[i]]
            if v and v ~= "" then
                ctx.proxy_spoof = true
                ngx.log(ngx.WARN,
                    "[proxy_origin] header khai proxy ma ip ngoai dai da xac minh",
                    " ip=", tostring(ip), " host=", tostring(host),
                    " header=", PROXY_CLAIM_HEADERS[i])
                break
            end
        end
    end

    return true, false
end

return _M
