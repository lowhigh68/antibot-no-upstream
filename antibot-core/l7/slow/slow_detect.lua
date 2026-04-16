local _M = {}
local cfg = require "antibot.core.config"

function _M.run(ctx)
    local rt = tonumber(ngx.var.request_time) or 0
    ctx.slow = rt > cfg.rate.slow_threshold_s
    if ctx.slow then
        ngx.log(ngx.INFO, "[slow] attack request_time=", rt, " ip=", ctx.ip)
    end
end

return _M
