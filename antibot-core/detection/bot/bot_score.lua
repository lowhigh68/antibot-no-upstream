local _M = {}

function _M.run(ctx)
    -- S4/S3 verified good bot OR S2.5 contact/analyzer attest → bot_score=0.
    -- S2.5 must also force 0 (without it ua_flag at line below could re-raise
    -- bot_score for compliant bots like Pinterestbot whose ua_flag fires
    -- because the UA contains "bot" token).
    -- bot_score=0 also auto-breaks the ip_risk EMA loop via the existing
    -- guard in async/risk_update.lua (bot_score > 0.3 required to raise).
    if ctx.good_bot_verified == true
       or ctx.bot_identity_tier == "S2.5" then
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
