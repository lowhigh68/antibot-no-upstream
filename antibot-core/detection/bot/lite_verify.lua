local _M = {}

local ua_check = require "antibot.detection.bot.ua_check"
local asn_mod  = require "antibot.core.fingerprint.asn"
local pool     = require "antibot.core.redis_pool"

local CRAWLER_PREFIX = "crawler:"
local CRAWLER_TTL    = 3600

local function require_full(ctx, reason)
    ctx.bot_lite_needs_full = true
    ctx.bot_ua              = reason
    -- Khong giu so 0 ma ua_check vua cap cho mot CLAIM chua duoc chung minh.
    -- Full bot lane co the ha lai ve 0 neu DNS/ASN xac minh thanh cong.
    ctx.bot_score = math.max(ctx.bot_score or 0, 0.85)
    return true, false
end

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
        return require_full(ctx, "good_bot_lite_no_registry")
    end

    local actual = ctx.asn and ctx.asn.asn_number
    if not actual then
        return require_full(ctx, "good_bot_lite_no_asn")
    end

    for _, asn in ipairs(expected) do
        if asn == actual then
            ctx.good_bot_verified = true
            ctx.bot_score         = 0.0
            ctx.bot_ua            = "good_bot_asn_verified"
            -- Distinct reason để antibot.log grep được — engine.run sẽ giữ
            -- nguyên (đã sửa thành action_reason or "good_bot_verified").
            ctx.action_reason     = "good_bot_asn_lite"
            if ctx.ip and ctx.ip ~= "" then
                pool.safe_set(CRAWLER_PREFIX .. ctx.ip, "1", CRAWLER_TTL)
            end
            -- WARN để xuất hiện trong default error log (INFO bị filter).
            ngx.log(ngx.WARN,
                "[bot_lite] VERIFIED bot=", ctx.good_bot_name or "?",
                " ip=", ctx.ip or "?", " asn=AS", actual,
                " uri=", ngx.var.uri or "?")
            return true, false
        end
    end

    -- ASN khong match: khong duoc roi thang vao resource scoring voi
    -- bot_score=0. Chuyen sang full lane de DNS co co hoi cuu crawler that;
    -- neu cung that bai, bot/init + engine se seal fake_good_bot.
    ngx.log(ngx.WARN,
        "[bot_lite] asn_mismatch bot=", ctx.good_bot_name or "?",
        " ip=", ctx.ip or "?", " actual=AS", actual,
        " expected=AS", table.concat(expected, ",AS"))

    return require_full(ctx, "good_bot_lite_asn_mismatch")
end

return _M
