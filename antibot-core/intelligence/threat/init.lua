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
local h2_db       = require "antibot.intelligence.threat.http2_db"
local ja3_allow   = require "antibot.intelligence.threat.ja3_allowlist"

function _M.run(ctx)
    ip_rep.run(ctx)
    asn_rep.run(ctx)
    h2_db.run(ctx)
    ja3_allow.run(ctx)
end

return _M
