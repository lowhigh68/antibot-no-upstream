local _M = {}

function _M.run(ctx)
    if not ctx.browser then
        ctx.entropy = 1.0
        return
    end

    local raw = ctx.browser.ent
    if not raw or type(raw) ~= "number" then
        ctx.entropy = 0.1
        return
    end

    if raw < 1 then
        ctx.entropy = 0.05
    elseif raw < 50 then
        ctx.entropy = 0.3
    elseif raw < 100 then
        ctx.entropy = 0.6
    else
        ctx.entropy = 1.0
    end
end

return _M
