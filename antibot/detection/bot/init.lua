local _M        = {}
local ua_check  = require "antibot.detection.bot.ua_check"
local dns_rev   = require "antibot.detection.bot.dns_reverse"
local dns_fwd   = require "antibot.detection.bot.dns_forward"
local bot_score = require "antibot.detection.bot.bot_score"

function _M.run(ctx)
    ua_check.run(ctx)

    if ctx.good_bot_claimed then
        dns_rev.run(ctx)

        if ctx.dns_rev_valid == true then
            dns_fwd.run(ctx)
        elseif ctx.dns_rev_valid == false then
            ctx.bot_ua            = "fake_good_bot"
            ctx.bot_score         = 0.85
            ctx.good_bot_verified = false
        end
    end

    bot_score.run(ctx)

    return true, false
end

return _M
