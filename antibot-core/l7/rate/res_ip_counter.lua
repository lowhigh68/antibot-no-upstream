-- IP-level resource hit counter — feeds session/session_store.lua
-- resource_starved gating.
--
-- Lý do tồn tại:
--   resource class skip fingerprint → ctx.identity=nil → counter.lua
--   không chạy → res_count per identity LUÔN = 0 cho mọi browser
--   session vì CSS/JS/font fetch không bao giờ link được identity.
--   → session_store fire resource_starved oan cho browser thật.
--
--   Module này track resource hit theo IP (no identity needed) trong
--   cùng window TTL với rate counter. session_store đọc res_ip:<ip>
--   để verify IP có resource activity thật trước khi fire signal.
--
-- Tại sao tách module riêng:
--   - counter.lua chạy trong l7_layer, l7 SKIP cho resource class.
--   - res_ip_counter chạy trong STEPS_RESOURCE (lightweight, 1 INCR).
--   - Không trộn concern với bot_lite_verify (đang chạy đầu STEPS_RESOURCE).

local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local TTL = cfg.ttl.rate   -- 60s — cùng window rate counter

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then return true, false end

    -- INCR + EXPIRE atomic via safe_incr (đã có sẵn pipeline).
    local _, err = pool.safe_incr("res_ip:" .. ip, TTL)
    if err then
        ngx.log(ngx.WARN, "[res_ip_counter] incr err: ", err)
    end

    return true, false
end

return _M
