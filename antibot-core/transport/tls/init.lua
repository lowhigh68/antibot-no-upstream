local _M = {}

local ja3 = require "antibot.transport.tls.ja3"

-- `ja3s.run(ctx)` ĐÃ GỠ (2026-09-06): nó chỉ chép `ngx.ctx.tls_ja3s` sang
-- `ctx.ja3s`, mà giá trị đó là một HẰNG SỐ và không module nào đọc nó.
-- `ja3s.capture()` thì GIỮ NGUYÊN — nó là nhịp 2 của cầu JA3, được gọi từ
-- `ssl_certificate_by_lua_block` trong 99 per-domain conf. Xem `tls/ja3s.lua`.
function _M.run(ctx)
    ja3.run(ctx)
end

return _M
