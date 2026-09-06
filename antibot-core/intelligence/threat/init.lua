local _M = {}

local ip_rep      = require "antibot.intelligence.threat.ip_reputation"
local asn_rep     = require "antibot.intelligence.threat.asn_reputation"
-- `ja3_db.lua` ĐÃ BỊ XOÁ (2026-09-06). Nó đọc `rep:ja3:<hash>` để đặt
-- `ctx.ja3_rep`. Chết ba lần:
--   1. `rep:ja3:` KHÔNG NƠI NÀO GHI trong cả cây nguồn ⇒ luôn trả nil ⇒ 0.0
--   2. `ja3_rep` KHÔNG có trong `DEFAULT_WEIGHTS` ⇒ không cộng điểm cho ai
--   3. Hai nơi duy nhất đọc `ja3_rep` là `signal_merge`/`context_vector` —
--      mà đầu ra của chúng cũng không ai đọc (xem `scoring/init.lua`)
-- Nó còn gác `ja3_partial` nên hôm nay chưa từng chạy tới lượt Redis; nhưng
-- lên nấc `ja3_cipher = "on"` thì đó là một `GET` mỗi request cho một giá trị
-- không ai đọc.
--
-- `http2_db.lua` ĐÃ BỊ XOÁ (2026-09-06), cùng lý do nhưng TỆ HƠN vì nó KHÔNG
-- có cổng gác nào: nó chạy `pool.safe_get("rep:h2:" .. ctx.h2_sig)` trên MỌI
-- request có chữ ký H2, tức một Redis GET thật đang diễn ra hôm nay.
--   1. `rep:h2:` KHÔNG NƠI NÀO GHI ⇒ luôn nil ⇒ `ctx.h2_rep = 0.0`
--   2. `h2_rep` KHÔNG có trong `DEFAULT_WEIGHTS`, KHÔNG có trong logger
--   3. Nơi duy nhất đọc `ctx.h2_rep` là chính nó (dòng log DEBUG của mình)
local ja3_allow   = require "antibot.intelligence.threat.ja3_allowlist"

function _M.run(ctx)
    ip_rep.run(ctx)
    asn_rep.run(ctx)
    ja3_allow.run(ctx)
end

return _M
