local _M = {}

-- Swarm detection — kết hợp uri_cluster (subnet-based) và ip_cluster.
--
-- Distributed crawl (bot farm rotate IP):
--   uri_cluster cao (nhiều bot cùng /24 → nhiều URI)
--   ip_cluster thấp (mỗi IP chỉ vài request)
--   → Chỉ cần uri_high là đủ để flag swarm
--
-- Single-IP aggressive crawl:
--   uri_cluster thấp (1 IP, 1 subnet)
--   ip_cluster cao (1 IP gửi nhiều request)
--   → ip_high là đủ
--
-- Thiết kế ban đầu yêu cầu CẢ HAI → miss distributed crawl hoàn toàn
-- Thiết kế mới: OR thay vì AND

function _M.run(ctx)
    local uri_high = (ctx.uri_cluster or 0) > 50   -- distributed crawl
    local ip_high  = (ctx.ip_cluster  or 0) > 30   -- single-IP crawl

    -- OR: phát hiện được cả 2 loại crawl
    ctx.swarm = uri_high or ip_high

    if ctx.swarm then
        ngx.log(ngx.INFO,
            "[swarm] detected",
            " uri_cluster=", ctx.uri_cluster or 0,
            " ip_cluster=", ctx.ip_cluster or 0,
            " uri_high=", tostring(uri_high),
            " ip_high=", tostring(ip_high))
    end
end

return _M
