local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Distributed crawl detection — subnet-based, không phụ thuộc URI cụ thể.
--
-- Nguyên tắc: distributed bot farm dùng nhiều IP trong cùng /24 subnet
-- để rotate, mỗi IP gửi ít request nhưng tổng subnet gửi rất nhiều.
-- User thật: 1 IP gửi nhiều request, subnet diversity thấp.
--
-- Detect bằng cách track:
--   1. Số request từ /24 subnet trong window 60s
--   2. Số URI khác nhau từ subnet đó (HyperLogLog)
-- → Subnet gửi nhiều request ĐẾN nhiều URI khác nhau → distributed crawl
-- → Không cần biết URI là gì — chỉ cần biết pattern diversity cao
--
-- Phân biệt với user thật CGNAT (nhiều người cùng IP):
--   CGNAT: cùng /24 nhưng URI diversity thấp (browse cùng vài trang)
--   Bot farm: /24 với URI diversity gần 1.0 (mỗi request 1 URI mới)

function _M.run(ctx)
    ctx.uri_cluster = 0

    local ip = ctx.ip or ""
    if ip == "" then return end

    -- Chỉ áp dụng cho navigation/unknown
    -- Resource request không phải crawl signal
    local class = ctx.req_class or "unknown"
    if class == "resource" or class == "api_callback" then return end

    -- Lấy /24 subnet — đơn vị tracking
    local subnet = ip:match("^(%d+%.%d+%.%d+)%.") or ip

    -- URI path (bỏ query string để tránh inflate diversity)
    local uri = (ctx.req and ctx.req.uri) or ngx.var.uri or "/"
    local uri_path = uri:match("^([^?]+)") or uri

    local red, err = pool.get()
    if not red then return end

    red:init_pipeline()
    -- 1. Request count cho subnet trong 60s
    red:incr("cluster:subnet_req:" .. subnet)
    red:expire("cluster:subnet_req:" .. subnet, 60)
    -- 2. URI diversity cho subnet (HyperLogLog — O(1) memory)
    red:pfadd("cluster:subnet_uri:" .. subnet, uri_path)
    red:expire("cluster:subnet_uri:" .. subnet, 60)
    -- 3. Đọc diversity count
    red:pfcount("cluster:subnet_uri:" .. subnet)

    local res, perr = red:commit_pipeline()
    pool.put(red)

    if not res then return end

    local req_count = tonumber(res[1]) or 0
    local uri_count = (type(res[5]) == "number") and res[5] or 0

    -- Distributed crawl signal:
    -- Subnet gửi > 30 request/60s VÀ > 15 URI khác nhau
    -- → không phải 1 user browse mà là nhiều bot rotate IP
    -- Threshold thấp hơn swarm_detect để detect sớm hơn
    local req_high = req_count > 30
    local uri_high = uri_count > 15

    if not (req_high and uri_high) then return end

    -- diversity_ratio: tỷ lệ URI unique / tổng request
    -- Bot:  ~1.0 (mỗi request URI mới)
    -- User CGNAT: ~0.1-0.3 (nhiều người cùng browse ít trang)
    local diversity_ratio = (req_count > 0) and (uri_count / req_count) or 0

    -- Normalize về 0-100 cho cluster_score.lua
    -- uri_count_normalize_max = 100 (từ config)
    local raw = math.min(100, req_count * diversity_ratio)
    ctx.uri_cluster = math.floor(raw)

    ngx.log(ngx.INFO,
        "[uri_cluster] distributed_crawl",
        " subnet=", subnet,
        " req=", req_count,
        " uri_uniq=", uri_count,
        " diversity=", string.format("%.2f", diversity_ratio),
        " uri_cluster=", ctx.uri_cluster)
end

return _M
