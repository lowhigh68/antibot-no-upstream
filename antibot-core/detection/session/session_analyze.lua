local _M = {}

function _M.run(ctx)
    local session = ctx.session
    if not session or #session == 0 then
        ctx.session_flag = 0.0
        return
    end

    local score   = 0.0
    local n       = #session
    local seen    = {}
    local repeats = 0

    for _, uri in ipairs(session) do
        if seen[uri] then
            repeats = repeats + 1
        end
        seen[uri] = true
    end

    local repeat_ratio = repeats / n
    if repeat_ratio > 0.7 then
        score = score + 0.6
    elseif repeat_ratio > 0.4 then
        score = score + 0.3
    end

    local unique = 0
    for _ in pairs(seen) do unique = unique + 1 end
    if unique == 1 and n >= 3 then
        score = score + 0.4
    end

    ctx.session_flag = math.min(1.0, score)
end

return _M
