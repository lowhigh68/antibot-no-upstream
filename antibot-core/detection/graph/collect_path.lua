local _M = {}

function _M.run(ctx)
    ctx.path = ctx.session or {}
end

return _M
