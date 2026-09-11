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

    -- Không có H2 thì tầng H2 KHÔNG quan sát được gì → confidence = 0.
    -- Mâu thuẫn "UA khai trình duyệt mà không có H2" là mâu thuẫn giữa các tầng,
    -- thuộc về `mismatch` (intelligence/correlation/consistency_check.lua) và đã
    -- được tính ở đó. Trước 2026-08-01 nhánh này cộng 0.15 → cùng một sự kiện bị
    -- tính tiền ở CẢ HAI signal, mà hai signal cùng weight 55.
    if not ctx.h2_is_h2 then
        return 0.0
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

    -- ĐỌC CHO ĐÚNG: đây KHÔNG phải quan sát tầng vận chuyển. `h2_order` do
    -- `pseudo_header.infer_from_ua()` suy ra từ **User-Agent** — một chuỗi do
    -- client tự chọn — chứ không đọc từ dây (repo ghi sẵn ở `build_light.lua`:
    -- "`h2_order` CHƯA ĐƯỢC ĐO"). Nên `h2_order == nil` nghĩa là **"UA không
    -- nằm trong bảng mẫu"**, không phải "không đọc được thứ tự header".
    --
    -- GIỮ LẠI, có số liệu: đo 2026-09-11, 5 máy, 3,7 giờ, 107.256 request H2 —
    -- nhóm `nil` còn 9,8% và gần như toàn bộ là crawler TỰ KHAI TÊN (AhrefsBot,
    -- ClaudeBot, Baiduspider, facebookexternalhit, Wget, ChatGPT-User, GPTBot,
    -- YandexBot, TurnitinBot…). Với chúng, 0,1 là đúng.
    -- Nhóm `richness >= 0.5` lọt vào đây còn 470, và phần lớn là WebView iOS —
    -- đã xử bằng mẫu `AppleWebKit/605` trong `pseudo_header.lua`.
    --
    -- Trước khi sửa: 19% và 17.988 phiên đăng nhập. Cả hai con số đó là ẢO,
    -- do cột `ua=` bị cắt ở 120 ký tự (xem `aca6bef`). Ai định chỉnh nhánh này
    -- thì đo lại trước — đừng lấy số cũ.
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

    ctx.h2_bot_confidence = h2_bot_confidence(ctx)

    -- Ghi vào `ctx.signals` ĐÃ GỠ (2026-09-06): bảng đó do `signal_merge.lua`
    -- dựng ra và **không nơi nào đọc**; module ấy đã bị xoá. `compute.lua` lấy
    -- `h2_bot_confidence` thẳng từ `ctx.h2_bot_confidence` qua `get_signal()`.

    ngx.log(ngx.DEBUG,
        "[h2_sig] sig=", ctx.h2_sig or "nil",
        " bot_confidence=", string.format("%.2f", ctx.h2_bot_confidence),
        " raw=", sig_str)
end

return _M
