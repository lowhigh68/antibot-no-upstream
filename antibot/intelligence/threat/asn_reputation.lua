local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    ctx.asn_rep = 0.0

    if not ctx.asn or not ctx.asn.asn_number then
        return
    end

    local val = pool.safe_get("rep:asn:" .. ctx.asn.asn_number)
    if val then
        local rep = tonumber(val)
        if rep then
            ctx.asn_rep = rep
            ngx.log(ngx.DEBUG,
                "[asn_rep] redis asn=", ctx.asn.asn_number,
                " rep=", rep,
                " ip=", ctx.ip or "?")
        end
    end
end

return _M
