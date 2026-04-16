local _M = {}

function _M.run(ctx)
    local delta = ctx.timing and ctx.timing.delta
    if not delta then ctx.pattern = 0.0; return end

    if delta < 0.05 then
        ctx.pattern = 0.8
    elseif delta < 0.2 then
        ctx.pattern = 0.4
    else
        ctx.pattern = 0.0
    end
end

return _M
