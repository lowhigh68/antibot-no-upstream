local _M        = {}
local ua_check  = require "antibot.detection.bot.ua_check"
local dns_rev   = require "antibot.detection.bot.dns_reverse"
local dns_fwd   = require "antibot.detection.bot.dns_forward"
local bot_score = require "antibot.detection.bot.bot_score"

-- ASN fallback verify: dùng khi PTR/A verification fail nhưng bot UA + ASN
-- owner thật khớp với registry → tin được. Sở hữu ASN từ RIR (RIPE/ARIN/APNIC)
-- yêu cầu pháp nhân + IP block delegation — attack difficulty tương đương
-- spoof PTR.
--
-- Áp dụng cho mọi bot có ctx.good_bot_asns (không gated vào ptr_only).
-- ptr_only chỉ điều khiển: có skip forward DNS hay không.
local function asn_fallback_verify(ctx)
    local expected = ctx.good_bot_asns
    if not expected or #expected == 0 then return false end
    local actual = ctx.asn and ctx.asn.asn_number
    if not actual then return false end
    for _, asn in ipairs(expected) do
        if asn == actual then
            ngx.log(ngx.INFO,
                "[bot] VERIFIED asn_fallback bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?", " asn=AS", actual)
            return true
        end
    end
    ngx.log(ngx.INFO,
        "[bot] asn_fallback miss bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?", " actual=AS", actual,
        " expected=AS", table.concat(expected, ",AS"))
    return false
end

function _M.run(ctx)
    ua_check.run(ctx)

    if ctx.good_bot_claimed then
        dns_rev.run(ctx)

        if ctx.dns_rev_valid == true then
            dns_fwd.run(ctx)
        elseif ctx.dns_rev_valid == false then
            -- PTR resolved nhưng không match suffix HOẶC NXDOMAIN.
            -- Cho ptr_only bot (Meta family): fallback sang ASN verification.
            -- Reverse DNS không đáng tin với rotating pool / no-PTR IP blocks.
            if asn_fallback_verify(ctx) then
                ctx.good_bot_verified = true
                ctx.bot_score         = 0.0
                ctx.bot_ua            = "good_bot_asn_verified"
            else
                ctx.bot_ua            = "fake_good_bot"
                ctx.bot_score         = 0.85
                ctx.good_bot_verified = false
            end
        elseif ctx.dns_rev_valid == nil and ctx.dns_rev_timeout then
            -- DNS timeout (resolver không response). Cho ptr_only bot có ASN
            -- list, fallback ASN. Không thì giữ behavior cũ (bot_score.lua sẽ
            -- bảo toàn score=0 để không penalize timeout transient).
            if asn_fallback_verify(ctx) then
                ctx.good_bot_verified = true
                ctx.bot_score         = 0.0
                ctx.bot_ua            = "good_bot_asn_verified"
            end
        end
    end

    bot_score.run(ctx)

    return true, false
end

return _M
