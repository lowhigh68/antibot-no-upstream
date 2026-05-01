local _M = {}

local ua_check = require "antibot.detection.bot.ua_check"
local asn_mod  = require "antibot.core.fingerprint.asn"

-- Lite bot verification cho resource class (image, font, css, …).
--
-- Pipeline đầy đủ (fingerprint + detection) bị skip cho resource để giảm
-- overhead — kết quả là good bot fetching .png/.jpg không được verify →
-- ip_rep + h2_bot_confidence + mismatch dồn lên đủ để kill_block (raw≥80
-- → eff=85 → block). Bingbot/Googlebot fetch image bị FP.
--
-- Lite mode: chỉ chạy ua_check (UA pattern → bot_name + good_bot_asns)
-- + asn lookup (mmdb local, cached) + ASN match — KHÔNG chạy DNS reverse
-- (đắt). ASN match là đủ vì RIR delegation tương đương trust với PTR
-- delegation (cùng yêu cầu IP block ownership).
--
-- Chỉ activate khi UA self-identified và có ctx.good_bot_asns expected.
function _M.run(ctx)
    -- Đảm bảo asn được populate (fingerprint layer skip cho resource)
    if not ctx.asn or not ctx.asn.asn_number then
        asn_mod.run(ctx)
    end

    -- Chạy ua_check để extract bot_name + good_bot_asns + good_bot_ptr_only
    ua_check.run(ctx)

    -- Nếu không phải good_bot_claimed → không có gì để verify
    if not ctx.good_bot_claimed then
        return true, false
    end

    -- Cần ASN list expected để match
    local expected = ctx.good_bot_asns
    if not expected or #expected == 0 then
        return true, false
    end

    local actual = ctx.asn and ctx.asn.asn_number
    if not actual then
        return true, false
    end

    for _, asn in ipairs(expected) do
        if asn == actual then
            ctx.good_bot_verified = true
            ctx.bot_score         = 0.0
            ctx.bot_ua            = "good_bot_asn_verified"
            ngx.log(ngx.INFO,
                "[bot_lite] VERIFIED bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?", " asn=AS", actual,
                " uri=", ngx.var.uri or "?")
            return true, false
        end
    end

    -- ASN không match: UA là good bot nhưng IP không thuộc owner thật.
    -- Đây là fake_good_bot (UA spoof). Bot_score sẽ được set qua scoring
    -- bình thường. KHÔNG set good_bot_verified=true ở đây — kill_block
    -- sẽ catch attempt scrape giả Googlebot từ datacenter vô danh.
    ngx.log(ngx.INFO,
        "[bot_lite] asn_mismatch bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?", " actual=AS", actual,
        " expected=AS", table.concat(expected, ",AS"))

    return true, false
end

return _M
