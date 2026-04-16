local _M = {}

local whitelist = require "antibot.core.access.whitelist"

function _M.run(ctx)
    local hit, reason = whitelist.check(ctx)

    if hit then
        ctx.whitelisted   = true
        ctx.action        = "allow"
        ctx.action_reason = reason
        ngx.log(ngx.DEBUG, "[access] whitelisted ip=", ctx.ip,
                " reason=", reason)
        return true, true
    end

    return true, false
end

return _M
