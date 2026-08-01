local _M = {}

-- Attack 2 — HTTP/1.1 downgrade:
-- Bot force HTTP/1.1 để tránh H2 fingerprinting.
-- Thêm compound rule: Chrome UA + no H2 + no Sec-Fetch → penalty mạnh hơn.
-- api_callback class được loại trừ (server callback hợp lệ không có H2).

local function ua_is_chrome(ua)
    return ua and ua:find("Chrome/", 1, true) ~= nil
              and ua:find("Edg/",    1, true) == nil
end
local function ua_is_firefox(ua)
    return ua and ua:find("Firefox/", 1, true) ~= nil
end
local function ua_is_modern_browser(ua)
    return ua_is_chrome(ua) or ua_is_firefox(ua)
        or (ua and ua:find("Safari/", 1, true) ~= nil
                and ua:find("Chrome/", 1, true) == nil)
end

function _M.run(ctx)
    local score = 0.0
    local ua    = ctx.ua or ""
    local class = ctx.req_class or "navigation"
    local req   = ctx.req or {}

    -- Ghi lại NHÁNH NÀO bắn, để hiệu chỉnh được. Trước đây 4 nhánh log bằng
    -- ngx.DEBUG — chạy ở access phase nên per-domain error_log (mức mặc định
    -- `error`) lọc sạch ⇒ không có cách nào biết nhánh nào đang cộng điểm.
    -- Xuất qua ctx.mm_rules → async/logger.lua ghi vào antibot.log (` mm=`).
    --
    -- Vì sao đo BÂY GIỜ: sửa JA3 xong (2026-07-31) đã kích hoạt hai nhánh
    -- CHẾT SUỐT 3 THÁNG — `chrome_no_h2` gác bởi `ctx.ja3 ~= nil` (ja3 luôn nil)
    -- và `tls12` gác bởi `ctx.tls13 == false` (tls13 nil, mà trong Lua
    -- `nil == false` là FALSE). Cộng lại tối đa +0.60 = 33 điểm (weight 55)
    -- vừa xuất hiện trong production mà chưa hiệu chỉnh trên dữ liệu thật.
    local hit = {}

    -- Attack 2: skip H2 downgrade penalty cho api_callback
    -- (payment IPN, webhook, server callback hợp lệ không dùng H2)
    local skip_h2_check = (class == "api_callback")

    -- PHÂN BẬC, KHÔNG CỘNG DỒN. Hai luật dưới đây đứng trên CÙNG một tiền đề
    -- "không có H2"; luật mạnh chỉ thêm bằng chứng phụ (thiếu Sec-Fetch). Trước
    -- đây cả hai cùng cộng → "không có H2" bị tính tiền HAI LẦN (0.25+0.35=0.60).
    -- Đo 2026-08-01: 12603/15358 (82%) lần `chrome_no_h2` bắn là bắn KÈM
    -- `no_h2_no_secfetch`. Nhóm chồng lấn nhận 0.60 trong khi nhóm chỉ có luật
    -- mạnh nhận 0.35 — cùng bằng chứng, chênh 13,75 điểm không tương ứng với
    -- thông tin nào. Nay luật mạnh THAY THẾ luật yếu.
    --
    -- KHÔNG xoá luật yếu: 2755 request (18%) chỉ dính mình nó — Chrome, không
    -- H2, nhưng CÓ Sec-Fetch (bot sao chép được header nhưng không làm được H2).
    --
    -- Ảnh hưởng đo trước khi sửa: 12644 request mất 13,75 điểm; trong 113 ca
    -- đang bị block chỉ 27 tụt xuống challenge, và 175/179 ca biên ở
    -- richness=0.00 với bot_score chiếm 34% điểm — chứng cứ độc lập với H2 vẫn
    -- còn, nên chúng rơi vào PoW chứ không thoát.
    local no_h2 = (not skip_h2_check) and ctx.h2_is_h2 == false
    local no_secfetch =
            (req.sec_fetch_mode == nil or req.sec_fetch_mode == "")
        and (req.sec_fetch_site == nil or req.sec_fetch_site == "")

    -- Mạnh: trình duyệt thật trên HTTPS luôn có CẢ H2 lẫn Sec-Fetch.
    -- Thiếu cả hai = thư viện HTTP giả mạo UA.
    if no_h2 and ua_is_modern_browser(ua) and no_secfetch then
        score = score + 0.35
        hit[#hit + 1] = "no_h2_no_secfetch"

    -- Yếu: chỉ thiếu H2. Gác bởi ja3 ~= nil nên nhánh này CHẾT suốt 3 tháng,
    -- sống lại từ 2026-07-31 khi JA3 được sửa.
    elseif no_h2 and ua_is_chrome(ua) and ctx.ja3 ~= nil then
        score = score + 0.25
        hit[#hit + 1] = "chrome_no_h2"
    end

    -- Chrome UA + TLS 1.2 (Chrome 100+ luôn dùng TLS 1.3)
    -- NGHI FP: middlebox kiểm tra TLS của doanh nghiệp hạ xuống TLS 1.2 →
    -- cả văn phòng ăn 19 điểm. Nhánh này KHÔNG có guard theo class.
    if ua_is_chrome(ua) and ctx.tls13 == false then
        score = score + 0.35
        hit[#hit + 1] = "tls12"          -- nhánh MỚI SỐNG sau khi sửa ja3
    end

    -- Browser UA + entropy thấp (headless không che hoàn toàn)
    local ent = ctx.entropy
    if ent and ent < 0.2 and ua_is_modern_browser(ua) then
        score = score + 0.45
        hit[#hit + 1] = "headless_ent"
    end

    if ctx.h2_tls_mismatch then
        score = score + 0.25
        hit[#hit + 1] = "h2_tls_mm"
    end

    if ctx.h2_header_profile then
        local ch = ctx.h2_header_profile.client_hints
        if ch and ch.has_ch_ua and not ua_is_chrome(ua) then
            score = score + 0.3
            hit[#hit + 1] = "ch_ua"
        end
    end

    if ctx.h2_bot_pattern then
        score = score + 0.3
        hit[#hit + 1] = "h2_bot_pat"
    end

    -- CHẶN TRẦN Ở 1.0: tổng 7 nhánh = 2.25, nên chỉ cần ~3 nhánh là BÃO HOÀ.
    -- Bão hoà = mismatch luôn 55 điểm phẳng, mất hết khả năng phân biệt "hơi
    -- nghi" với "chắc chắn bot". mm_raw giữ giá trị TRƯỚC khi chặn trần để đo
    -- mức bão hoà thật (>1.0 bao nhiêu) — không dùng để chấm điểm.
    ctx.mm_raw   = score
    ctx.mm_rules = table.concat(hit, ",")
    ctx.mismatch = math.min(1.0, score)
end

return _M
