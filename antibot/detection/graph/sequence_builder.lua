local _M = {}

function _M.run(ctx)
    local s = ctx.session or {}
    local n = #s
    if n == 0 then ctx.seq = {}; return end

    ctx.seq = {}
    local start = math.max(1, n - 9)
    for i = start, n do
        ctx.seq[#ctx.seq + 1] = s[i]
    end
end

return _M
