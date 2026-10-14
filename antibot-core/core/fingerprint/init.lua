local _M = {}

-- `geoip.lua` và `ip_classify.lua` ĐÃ BỊ XOÁ (2026-09-06).
--   geoip       → thân hàm chỉ có `ctx.geo = nil`. Không phải "chưa làm xong":
--                 không nơi nào đọc `ctx.geo`.
--   ip_classify → `ctx.ip_net_type` không nơi nào đọc. Trục `ctx.ip_score`
--                 cũng đã được gỡ end-to-end vì producer luôn đặt 0; các trục
--                 còn sống là `ip_rep`, `ip_risk` và `ext_rep`, với provenance
--                 độc lập.
local asn         = require "antibot.core.fingerprint.asn"
local collect_req = require "antibot.core.fingerprint.collect_request"
local build_light = require "antibot.core.fingerprint.build_light"
local session_load = require "antibot.detection.session.session_load"

function _M.run(ctx)
    collect_req.run(ctx)

    asn.run(ctx)

    local ok, err = build_light.run(ctx)
    if not ok then
        ngx.log(ngx.CRIT, "[fingerprint] build_light failed: ", err)
        return false, false
    end

    session_load.run(ctx)

    return true, false
end

return _M
