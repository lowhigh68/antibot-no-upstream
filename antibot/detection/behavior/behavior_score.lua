local _M = {}

function _M.run(ctx)
    local timing  = ctx.rate_pattern  or 0.0
    local session = ctx.session_flag  or 0.0
    ctx.behavior_score = math.min(1.0,
        timing  * 0.6 +
        session * 0.4)
    return true, false
end
return _M
