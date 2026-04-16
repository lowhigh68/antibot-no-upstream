local _M = {}

function _M.run(ctx)

    ctx.ip_score = ctx.ip_risk or 0.0
end

return _M
