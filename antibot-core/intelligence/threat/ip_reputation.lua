local _M   = {}
local pool = require "antibot.core.redis_pool"

-- IP reputation — kết hợp ip_rep (threat feed) và ip_risk (runtime).
-- ip_rep: từ threat feed (IPsum, Spamhaus), cập nhật mỗi ngày.
-- ip_risk: từ runtime behavior trong session hiện tại (Attack 1 fix).

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" then
        ctx.ip_rep  = 0.0
        ctx.ip_risk = 0.0
        return
    end

    -- Threat feed reputation
    local rep_val = pool.safe_get("rep:" .. ip)
    ctx.ip_rep = tonumber(rep_val) or 0.0

    -- Runtime IP risk (Attack 1: UA switching detection)
    local risk_val = pool.safe_get("ip_risk:" .. ip)
    ctx.ip_risk = tonumber(risk_val) or 0.0

    if ctx.ip_risk > 0.3 then
        ngx.log(ngx.DEBUG,
            "[ip_rep] ip_risk elevated ip=", ip,
            " risk=", string.format("%.3f", ctx.ip_risk))
    end
end

return _M
