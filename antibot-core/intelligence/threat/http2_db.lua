local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    if not ctx.h2_sig or ctx.h2_sig == "" then
        ctx.h2_rep = 0.0
        return
    end

    local val = pool.safe_get("rep:h2:" .. ctx.h2_sig)
    ctx.h2_rep = tonumber(val) or 0.0

    if ctx.h2_rep > 0 then
        ngx.log(ngx.DEBUG,
            "[h2_db] h2_sig=", ctx.h2_sig,
            " rep=", ctx.h2_rep)
    end
end

return _M
