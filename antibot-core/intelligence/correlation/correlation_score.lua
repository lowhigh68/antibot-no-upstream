local _M = {}

function _M.run(ctx)
    local rules = ctx.corr_rules or {}
    local total = 0.0
    for _, r in ipairs(rules) do
        total = total + (r.score or 0)
    end
    ctx.corr_score = math.min(1.0, total)
end

return _M
