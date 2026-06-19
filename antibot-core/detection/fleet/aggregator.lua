local _M      = {}
local pool    = require "antibot.core.redis_pool"
local cfg     = require "antibot.core.config"
local trusted = require "antibot.detection.fleet.trusted"

-- Aggregator — per-request Redis writes for fleet detection.
--
-- For each non-trusted, non-IPv6 request, write 6 entries into a 1-minute
-- bucket scoped by the request's /24 (and the same for the parent /16):
--
--   fl:24:hit:<cidr_24>:<min>   INCR              total hits
--   fl:24:ips:<cidr_24>:<min>   PFADD <ip>        HLL distinct IPs
--   fl:24:fp:<cidr_24>:<min>    PFADD <fp_hash>   HLL distinct fingerprints
--   fl:24:path:<cidr_24>:<min>  ZINCRBY 1 <path>  for top-3 path share
--   fl:24:ver:<cidr_24>:<min>   INCR (verified only)
--   fl:24:ck:<cidr_24>:<min>    INCR (any cookie present)
--   fl:active:24:<min>          SADD <cidr_24>    analyzer scan-set
--
-- /16 mirror keys with prefix fl:16:* for roll-up evaluation (NO fingerprint
-- HLL at /16 because aggregating across multiple /24s in HLL is meaningless
-- — analyzer derives /16 confirm from /24 roll-up logic instead).
--
-- Bucket TTL = cfg.fleet_detection.timing.bucket_ttl (default 180s).
-- All writes go through a single Redis pipeline → 1 RTT per request.

-- 5-minute sliding bucket: rotation attacks spread requests thin per /24
-- (43.172/15 field test: 2-6 hits/min/24, 4-20 hits/min/16). A 1-minute
-- window left fp_poverty / path_convergence / cookie_vacuum noise-bound
-- — analyzer ran but every bucket skipped min_hits. 5-min accumulation
-- gives reliable statistics even under aggressive IP rotation.
local BUCKET_SECS = 300
local BUCKET_TTL  = (cfg.fleet_detection
    and cfg.fleet_detection.timing
    and cfg.fleet_detection.timing.bucket_ttl) or 900

local PATH_ZSET_CAP = 64  -- avoid unbounded path zset growth per /24

local function ip_to_cidr_24(ip)
    local a, b, c = ip:match("^(%d+)%.(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. "." .. c .. ".0/24"
end

local function ip_to_cidr_16(ip)
    local a, b = ip:match("^(%d+)%.(%d+)%.")
    if not a then return nil end
    return a .. "." .. b .. ".0.0/16"
end

-- Compact fingerprint hash: UA + accept-language + accept-encoding
-- ordering. Bot fleet rotating Chrome versions cycles only the UA tail
-- (Chrome/118 → 119 → …) but accept-* headers remain identical → still
-- collapses many "rotating" UAs into same fp_hash. This is precisely the
-- signature poverty we want to detect.
local function fp_hash(ua, accept_lang, accept_enc)
    local s = (ua or "") .. "|"
        .. (accept_lang or "") .. "|"
        .. (accept_enc or "")
    return ngx.md5(s):sub(1, 12)
end

local function path_hash(uri)
    if not uri or uri == "" then return "-" end
    -- Strip query string and normalize trailing slash.
    local p = uri:match("^([^?]*)") or uri
    if #p > 1 and p:sub(-1) == "/" then p = p:sub(1, -2) end
    return ngx.md5(p):sub(1, 10)
end

local function browser_ua(ua)
    if not ua or ua == "" then return false end
    -- Cheap signature: real browser UA must contain at least one of these
    -- engine tokens. Headless scrapers using "python-requests" / "curl" /
    -- "Go-http-client" do not — they get counted as non-browser, which
    -- alone is enough signal for the other layers; we don't double-count.
    return ua:find("Chrome/", 1, true)
        or ua:find("Firefox/", 1, true)
        or ua:find("Safari/", 1, true)
        or ua:find("Edg/", 1, true)
        or ua:find("OPR/", 1, true)
end

function _M.write(ctx)
    -- Trusted ASN bypass (performance — see trusted.lua)
    if trusted.is_trusted(ctx) then return end

    local ip = ctx.ip
    if not ip or ip == "" then return end
    if ip:find(":", 1, true) then return end  -- IPv6 skipped in v1
    if ip == "127.0.0.1" then return end

    local cidr_24 = ip_to_cidr_24(ip)
    if not cidr_24 then return end
    local cidr_16 = ip_to_cidr_16(ip)

    local bucket = math.floor(ngx.time() / BUCKET_SECS)
    local fp     = fp_hash(ctx.ua, ngx.var.http_accept_language, ngx.var.http_accept_encoding)
    local uri    = (ctx.req and ctx.req.uri) or ngx.var.uri or ""
    local ph     = path_hash(uri)
    local is_browser = browser_ua(ctx.ua) and true or false
    local is_verified = ctx.verified and true or false
    local has_cookie = (ngx.var.http_cookie ~= nil and ngx.var.http_cookie ~= "") and true or false

    local k_hit  = "fl:24:hit:"  .. cidr_24 .. ":" .. minute
    local k_ips  = "fl:24:ips:"  .. cidr_24 .. ":" .. minute
    local k_fp   = "fl:24:fp:"   .. cidr_24 .. ":" .. minute
    local k_path = "fl:24:path:" .. cidr_24 .. ":" .. minute
    local k_ver  = "fl:24:ver:"  .. cidr_24 .. ":" .. minute
    local k_ck   = "fl:24:ck:"   .. cidr_24 .. ":" .. minute
    local k_uab  = "fl:24:uab:"  .. cidr_24 .. ":" .. minute
    local k_act  = "fl:active:24:" .. minute

    local k16_hit  = "fl:16:hit:"  .. cidr_16 .. ":" .. minute
    local k16_ips  = "fl:16:ips:"  .. cidr_16 .. ":" .. minute
    local k16_fp   = "fl:16:fp:"   .. cidr_16 .. ":" .. minute
    local k16_path = "fl:16:path:" .. cidr_16 .. ":" .. minute
    local k16_ver  = "fl:16:ver:"  .. cidr_16 .. ":" .. minute
    local k16_ck   = "fl:16:ck:"   .. cidr_16 .. ":" .. minute
    local k16_uab  = "fl:16:uab:"  .. cidr_16 .. ":" .. minute
    local k16_act  = "fl:active:16:" .. minute

    local _, err = pool.pipeline(function(red)
        -- /24 counters
        red:incr(k_hit);  red:expire(k_hit,  BUCKET_TTL)
        red:pfadd(k_ips, ip);   red:expire(k_ips, BUCKET_TTL)
        red:pfadd(k_fp,  fp);   red:expire(k_fp,  BUCKET_TTL)
        red:zincrby(k_path, 1, ph); red:expire(k_path, BUCKET_TTL)
        red:zremrangebyrank(k_path, 0, -1 - PATH_ZSET_CAP)
        if is_verified then red:incr(k_ver); red:expire(k_ver, BUCKET_TTL) end
        if has_cookie  then red:incr(k_ck);  red:expire(k_ck,  BUCKET_TTL) end
        if is_browser  then red:incr(k_uab); red:expire(k_uab, BUCKET_TTL) end
        red:sadd(k_act, cidr_24); red:expire(k_act, BUCKET_TTL)

        -- /16 aggregation — full parallel set so analyzer can evaluate
        -- the parent prefix directly when rotation thins out per /24.
        red:incr(k16_hit);  red:expire(k16_hit, BUCKET_TTL)
        red:pfadd(k16_ips, ip);  red:expire(k16_ips, BUCKET_TTL)
        red:pfadd(k16_fp,  fp);  red:expire(k16_fp,  BUCKET_TTL)
        red:zincrby(k16_path, 1, ph); red:expire(k16_path, BUCKET_TTL)
        red:zremrangebyrank(k16_path, 0, -1 - PATH_ZSET_CAP)
        if is_verified then red:incr(k16_ver); red:expire(k16_ver, BUCKET_TTL) end
        if has_cookie  then red:incr(k16_ck);  red:expire(k16_ck,  BUCKET_TTL) end
        if is_browser  then red:incr(k16_uab); red:expire(k16_uab, BUCKET_TTL) end
        red:sadd(k16_act, cidr_16); red:expire(k16_act, BUCKET_TTL)
    end)

    if err then
        ngx.log(ngx.WARN, "[fleet.aggregator] pipeline err: ", tostring(err))
    end
end

-- Exposed for analyzer (avoid duplicating CIDR logic)
_M._ip_to_cidr_24 = ip_to_cidr_24
_M._ip_to_cidr_16 = ip_to_cidr_16

return _M
