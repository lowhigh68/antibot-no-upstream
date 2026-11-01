-- Canonical SITE/VHOST scope shared by every per-site state key.
--
-- This is intentionally NOT the literal Host header.  In nginx,
-- `$server_name` is the first name declared by the matched server block, so
-- aliases which share one vhost/docroot also share one state bucket.  Besides
-- matching network_quarantine's established contract, this prevents a client
-- from escaping state merely by switching between www/apex/other aliases.

local _M = {}

function _M.host(ctx)
    local var = (ngx and ngx.var) or {}
    local host = var.server_name
    if not host or host == "" then
        host = (ctx and ctx.req and ctx.req.host) or var.host or "unknown"
    end

    host = tostring(host):lower():gsub("%.$", "")
    host = host:gsub("[^%w%.%-_]", "_")
    if host == "" then host = "unknown" end

    if #host > 96 then
        host = ngx and ngx.md5 and ngx.md5(host):sub(1, 32)
            or host:sub(1, 96)
    end
    return host
end

return _M
