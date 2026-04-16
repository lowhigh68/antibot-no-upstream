local _M = {}

local function build_h2_sig_str(ctx)
    local parts = {}

    parts[#parts+1] = ctx.h2_is_h2 and "h2" or "h1"

    parts[#parts+1] = ctx.h2_order or "?"

    parts[#parts+1] = ctx.h2_header_fp or "?"

    if ctx.h2_behavior_profile then
        parts[#parts+1] = ctx.h2_behavior_profile.navigation or "?"
    else
        parts[#parts+1] = "?"
    end

    if ctx.h2_request_anomaly then
        parts[#parts+1] = ctx.h2_request_anomaly
    end

    if ctx.h2_bot_pattern then
        parts[#parts+1] = "bot"
    end

    return table.concat(parts, "|")
end

local function h2_bot_confidence(ctx)
    local score = 0.0

    if not ctx.h2_is_h2 then
        local ua = ctx.ua or ""
        if ua:find("Chrome/", 1, true) or ua:find("Firefox/", 1, true) then
            score = score + 0.15
        end
        return score
    end

    if ctx.h2_bot_pattern then score = score + 0.4 end

    if ctx.h2_tls_mismatch then score = score + 0.25 end

    if ctx.h2_header_profile then
        local sf = ctx.h2_header_profile.sec_fetch
        local ch = ctx.h2_header_profile.client_hints
        local ua = ctx.ua or ""
        if ua:find("Chrome/", 1, true) then
            if not sf or not sf.present then
                score = score + 0.3
            end
            if ch and not ch.has_ch_ua then
                score = score + 0.2
            end
        end
    end

    if ctx.h2_order == nil then score = score + 0.1 end

    if ctx.h2_request_anomaly then score = score + 0.2 end

    return math.min(1.0, score)
end

function _M.run(ctx)
    local sig_str = build_h2_sig_str(ctx)

    if ctx.h2_is_h2 then
        ctx.h2_sig = ngx.md5(sig_str)
    else
        ctx.h2_sig = nil
    end

    ctx.h2_sig_raw        = sig_str
    ctx.h2_sig_method     = "inferred"
    ctx.h2_bot_confidence = h2_bot_confidence(ctx)

    if ctx.h2_bot_confidence > 0 then
        ctx.signals = ctx.signals or {}
        ctx.signals["h2_bot_confidence"] = ctx.h2_bot_confidence
    end

    ngx.log(ngx.DEBUG,
        "[h2_sig] sig=", ctx.h2_sig or "nil",
        " bot_confidence=", string.format("%.2f", ctx.h2_bot_confidence),
        " raw=", sig_str)
end

return _M
