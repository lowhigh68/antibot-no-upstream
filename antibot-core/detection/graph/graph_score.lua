local _M = {}
function _M.run(ctx)
    ctx.graph_score = ctx.graph_score or 0.0
    ctx.graph_flag  = ctx.graph_flag  or 0.0
    return true, false
end
return _M
