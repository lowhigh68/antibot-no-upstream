local _M = {}
local cfg = require "antibot.core.config"

function _M.run(ctx)
    ctx.burst_flag = (ctx.burst or 0) > cfg.rate.burst_threshold
    if ctx.burst_flag then
        ngx.log(ngx.INFO, "[burst] violation count=", ctx.burst,
                " ip=", ctx.ip)
    end
end

return _M
