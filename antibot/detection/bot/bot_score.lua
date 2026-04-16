local _M = {}

function _M.run(ctx)
    if ctx.good_bot_verified == true then
        ctx.bot_score = 0.0
        return true, false
    end

    local score = ctx.bot_score or 0.0

    if ctx.good_bot_claimed then
        if ctx.dns_rev_timeout then
            ctx.bot_score = score
            return true, false
        end

        if ctx.dns_fwd_timeout then
            ctx.bot_score = math.min(score, 0.05)
            return true, false
        end
    end

    if ctx.ua_flag and ctx.ua_flag > score then
        score = math.max(score, ctx.ua_flag * 0.8)
    end

    ctx.bot_score = math.min(1.0, score)
    return true, false
end

return _M
