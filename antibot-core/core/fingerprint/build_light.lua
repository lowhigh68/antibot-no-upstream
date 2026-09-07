local _M = {}

local identity_mod = require "antibot.core.fingerprint.identity"

local SENTINEL = {
    ja3    = "NO_JA3",
    h2_sig = "NO_H2",
    asn    = "NO_ASN",
}

local FP_QUALITY_THRESHOLD = 0.55

-- ── `h2_sig` BỊ LOẠI KHỎI BĂM, NHƯNG GIỮ TRONG `components` ───────────────
--
-- Đo 2026-09-07 trên cả 5 máy, TRONG PHẠM VI TỪNG KẾT NỐI TLS (cùng `conn`
-- thì chắc chắn cùng client, nên không dính bẫy CGNAT hay identity dùng
-- chung): **1228 kết nối HTTP/2 có `fp_light` đổi giữa hai request, 1213
-- (98,8%) là những kết nối có `h2_sig` đổi.** cloud186-126 khớp tuyệt đối
-- 377/377. Trên H1 — nơi `h2_sig` luôn là sentinel — con số tương ứng là 0.
--
-- Nguyên nhân đọc thẳng từ `transport/http2/signature.lua:3`: 3 trong 6 thành
-- phần của `h2_sig` là thuộc tính của REQUEST, không phải của client —
-- `h2_behavior_profile.navigation` lật giữa điều hướng và request con, còn
-- `h2_request_anomaly` với `h2_bot_pattern` được nối thêm CÓ ĐIỀU KIỆN nên
-- đến độ dài chuỗi cũng đổi. Một trình duyệt mở một kết nối rồi tải 1 trang +
-- N tài nguyên sẽ nhận N+1 `fp_light` khác nhau.
--
-- Giá phải trả: `sess:<fp_light>` bị cắt vụn nên `sess_len` không lớn lên
-- được, mà đó là thứ `cfg.trust` đòi >= 5. Đau nhất đúng chỗ cần nhất —
-- `auth_endpoint` churn 92,9% (cloud171-96) và 52,7% (cloud28-246),
-- `interaction` 28-51%: admin đã đăng nhập đang làm XHR. Cùng hình dạng ca FP
-- đã ghi ở `enforcement/CLAUDE.md` 2026-07-06.
--
-- VÌ SAO KHÔNG GỠ LUÔN KHỎI `components`: `fp_quality = real / #components`.
-- Rút mẫu số 5 → 4 sẽ đẩy client H2 thiếu CẢ `ja3` lẫn `asn` từ 3/5 = 0,60
-- xuống 2/4 = 0,50, tức xuống dưới ngưỡng 0,55 ⇒ **+5 điểm `fp_degraded`**.
-- Trên cloud171-96, nơi 92% request không có JA3, đó là hàng chục nghìn
-- request bị phạt oan. Giữ nguyên `components` thì `fp_quality` không đổi một
-- chút nào; chỉ cái băm đổi.
--
-- VÌ SAO KHÔNG THAY BẰNG `{h2_is_h2, h2_order}`: `h2_order` CHƯA ĐƯỢC ĐO là
-- có ổn định trong một kết nối hay không. Đưa nó vào là lặp lại đúng giả
-- định vừa bị dữ liệu bác bỏ, chỉ ở quy mô nhỏ hơn. Muốn thêm thì đo trước.
--
-- LỢI ÍCH KÈM THEO: cùng một client chuyển H1 ↔ H2 (Chrome connection
-- coalescing) nay giữ NGUYÊN `fp_light` thay vì tách đôi — đúng cái FP đã
-- hoãn ở `antibot-core/CLAUDE.md` 2026-05-23 mục "Defer C'".
--
-- KIỂM CHỨNG SAU KHI DEPLOY — con số CỤ THỂ, không phải "giảm là được". Sau
-- khi bỏ `h2_sig` khỏi băm, một kết nối chỉ còn churn nếu `ja3` HOẶC `ua`
-- đổi; đếm thẳng từ bảng chữ ký trước fix ra dự đoán từng máy:
--   cloud186-126  43,2% → 1,2%   (11/902)
--   cloud171-96   18,3% → 3,1%   (18/579)
--   cloud168-101  12,0% → 3,1%   (42/1350)
--   cloud28-246   25,3% → 4,1%   (39/948)
--   cloud183-139  26,6% → 8,1%   (107/1322)
-- Lệch nhiều so với các số này = giả thuyết sai ở đâu đó, phải đo lại.
--
-- Phần dư ĐÚNG, đừng sửa tiếp: 98,5% churn H1 (576/585) là do `ua` đổi giữa
-- các request trên cùng kết nối keep-alive — bot xoay UA. Một UA khác là một
-- tuyên bố danh tính khác, `fp_light` đổi theo là đúng.
local HASH_PARTS = 4

function _M.run(ctx)
    identity_mod.build(ctx)

    local components = {
        ctx.ip or "",
        ctx.ua or "",
        (ctx.asn and ctx.asn.asn_number and tostring(ctx.asn.asn_number))
            or SENTINEL.asn,
        ctx.ja3    or SENTINEL.ja3,
        ctx.h2_sig or SENTINEL.h2_sig,
    }

    if components[1] == "" then
        return false, "ip_empty"
    end

    local real = 0
    local sentinel_values = {}
    for _, v in pairs(SENTINEL) do sentinel_values[v] = true end

    for _, v in ipairs(components) do
        if v ~= "" and not sentinel_values[v] then
            real = real + 1
        end
    end

    -- `real / #components` VẪN đếm đủ 5 — xem khối chú thích ở đầu file.
    ctx.fp_quality  = real / #components
    ctx.fp_degraded = (ctx.fp_quality < FP_QUALITY_THRESHOLD)
    -- Băm CHỈ từ 4 thành phần đầu: ip | ua | asn | ja3.
    ctx.fp_light    = ngx.md5(table.concat(components, "|", 1, HASH_PARTS))

    if ctx.fp_degraded then
        ngx.log(ngx.WARN,
            "[build_light] degraded fp_quality=",
            string.format("%.2f", ctx.fp_quality),
            " ip=", ctx.ip,
            " ja3=", components[4],
            " h2=", components[5])
    end

    return true
end

return _M
