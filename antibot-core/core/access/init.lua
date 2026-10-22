local _M = {}

local whitelist = require "antibot.core.access.whitelist"
local decision  = require "antibot.core.decision"

function _M.run(ctx)
    local hit, reason = whitelist.check(ctx)

    if hit then
        ctx.whitelisted   = true
        ctx.action        = "allow"
        ctx.action_reason = reason
        decision.set(ctx, {
            kind = "policy", source = "access", rule = reason,
            mode = "enforce", scope = "request",
        })
        ngx.log(ngx.DEBUG, "[access] whitelisted ip=", ctx.ip,
                " reason=", reason)
        return true, true
    end

    return true, false
end

return _M
