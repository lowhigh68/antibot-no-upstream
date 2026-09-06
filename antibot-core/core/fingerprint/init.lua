local _M = {}

-- `geoip.lua` và `ip_classify.lua` ĐÃ BỊ XOÁ (2026-09-06).
--   geoip       → thân hàm chỉ có `ctx.geo = nil`. Không phải "chưa làm xong":
--                 không nơi nào đọc `ctx.geo`.
--   ip_classify → `ctx.ip_net_type` không nơi nào đọc (chỉ còn trong chú thích
--                 và admin/CLAUDE.md), còn `ctx.ip_score = 0.0` thì
--                 `core/ctx/init.lua` đã đặt sẵn. Đổi lại nó tra Redis
--                 `asn:type:<n>` — có cache 300s trong shared dict nên rẻ,
--                 nhưng vẫn là I/O cho một nhãn không ai dùng.
--   `ctx.ip_score` VẪN CÓ NGƯỜI ĐỌC (compute weight 25, cross_layer_rules,
--   l7/rate/adaptive_limit) — nay `core/ctx/init.lua` là nơi DUY NHẤT đặt nó,
--   và vẫn giữ 0.0 theo đúng quyết định vận hành cũ.
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
