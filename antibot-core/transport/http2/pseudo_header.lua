local _M = {}

-- MỘT THỨ TỰ KHÔNG ÁNH XẠ DUY NHẤT TỚI MỘT CLIENT.
--
-- Bảng cũ khai báo khoá `mpsa` **BỐN LẦN**. Lua chỉ giữ bản cuối, nên
-- `mpsa` = `{curl_h2, tls13=false}` và ba bản trước — trong đó có **Firefox**
-- — bị nuốt sạch.
--
-- Hậu quả không phải "bảng thiếu chính xác", mà là một FP XÁC ĐỊNH:
--   `infer_from_ua` trả `"mpsa"` cho Firefox → `KNOWN_PATTERNS.mpsa.tls13`
--   là `false` → Firefox trên TLS 1.3 có `ctx.tls13_offered = true` → lệch →
--   `h2_tls_mismatch = true` → `http2/signature.lua:43` cộng **+0,25** vào
--   `h2_bot_confidence` (trọng số 55) = **+13,75 điểm** cho MỌI người dùng
--   Firefox đi HTTP/2 mà JA3 bắt được. Cả một họ trình duyệt, mọi request.
--
-- Sửa đúng không phải là khôi phục bốn dòng — `mpsa` vẫn chỉ nhận được một
-- giá trị. Sự thật là: Firefox (TLS 1.3) và curl/python/java/node dùng CHUNG
-- thứ tự `mpsa`, nên từ thứ tự đó **không suy ra được** phiên bản TLS phải là
-- gì. `tls13 = nil` ghi thẳng điều đó, và nhánh kiểm bên dưới bỏ qua.
--
-- Nói cách khác: tín hiệu này chưa bao giờ phân biệt được `mpsa`; bản cũ chỉ
-- che điều đó bằng cách chọn bừa một client rồi bắn nhầm vào Firefox.
local KNOWN_PATTERNS = {
    masp = { clients = "chrome,edge",                   tls13 = true  },
    mspa = { clients = "safari",                        tls13 = true  },
    -- `tls13 = nil`, KHONG phai `false`. Go bat TLS 1.3 MAC DINH tu Go 1.13
    -- (2019), nen moi client Go hien dai co `ctx.tls13_offered = true` va bang cu ban
    -- `h2_tls_mismatch` cho TAT CA. Dung y con bug Firefox ngay tren: mot ky
    -- vong phien ban duoc ghim cung roi client di truoc no.
    --
    -- Khac Firefox o MUC DO chu khong o BAN CHAT: nan nhan la webhook/IPN/
    -- uptime-monitor viet bang Go — tich hop that cua khach, an +0,25 vao
    -- `h2_bot_confidence` (trong so 55) = +13,75 diem, dung bang gia Firefox
    -- vua tra.
    --
    -- Vi sao la `nil` chu khong phai `true`: Go cho phep dat MaxVersion, con
    -- co ban Go cu; tu thu tu pseudo-header KHONG suy ra duoc phien ban TLS,
-- `find(s, 1, true)` là PLAIN find: đối số thứ ba `true` tắt hẳn bộ so khớp
-- mẫu, nên `%` trong chuỗi KHÔNG còn là ký tự thoát mà là một ký tự `%` thật.
--
-- Ba dòng dưới đây từng viết `Go%-http%-client/`, `Apache%-HttpClient` và
-- `node%-fetch` — cú pháp thoát của Lua pattern, đặt vào một phép tìm plain.
-- Kết quả: chúng đi tìm chuỗi có ký tự `%` bên trong, thứ không UA nào có, nên
-- **ba nhánh này chưa bao giờ khớp**.
--
-- Hệ quả đo được (do_after.sh 2026-09-06, cloud168-101): mọi client Go rơi
-- xuống `return nil, "ua_unknown"` ⇒ `ctx.h2_order = nil` ⇒ `signature.lua`
-- cộng +0.1. Cột `h2bc=` trên dòng UA Go chỉ có 0.10 và 0.50 (= 0.4 bot_pattern
-- + 0.1 order-nil) — KHÔNG có số hạng 0.25 nào.
--
-- Nên `d5e5e18` (sửa `amps.tls13` = nil) KHÔNG hề đổi hành vi production như
-- tôi đã tuyên bố: nhánh `amps` chưa từng với tới được. Nó là điều kiện CẦN
-- cho lần sửa này chứ không phải một bản vá độc lập — nếu sửa `find` mà chưa
-- sửa bảng thì mọi client Go lập tức ăn +0,25 × 55 = 13,75 điểm, tức BẬT một
-- FP thay vì tắt.
--
-- Đúng hình dạng con bug lặp đi lặp lại trong repo này: một giá trị đi qua ranh
-- giới mà hai bên hiểu khác nhau về nghĩa của nó.
local function infer_from_ua(ua)
    if not ua or ua == "" then return nil, "no_ua" end

    if ua:find("Chrome/", 1, true) and not ua:find("Edg/", 1, true) then
        return "masp", "ua_chrome"
    end
    end
    if ua:find("Edg/", 1, true) then
        return "masp", "ua_edge"
    end
    if ua:find("Firefox/", 1, true) then
        return "mpsa", "ua_firefox"
    end
    if ua:find("Safari/", 1, true) and not ua:find("Chrome/", 1, true) then
        return "mspa", "ua_safari"
    end
    if ua:find("Go-http-client/", 1, true) then
        return "amps", "ua_go"
    end
    if ua:find("curl/", 1, true) then
        return "mpsa", "ua_curl"
    end
    if ua:find("python", 1, true) or ua:find("httpx", 1, true)
    or ua:find("requests/", 1, true) then
        return "mpsa", "ua_python"
    end
    if ua:find("Java/", 1, true) or ua:find("okhttp/", 1, true)
    or ua:find("Apache-HttpClient", 1, true) then
        return "mpsa", "ua_java"
    end
    if ua:find("node-fetch", 1, true) or ua:find("axios/", 1, true) then
        return "mpsa", "ua_node"
    end

    return nil, "ua_unknown"
end

function _M.run(ctx)
    local proto = ngx.var.server_protocol or ""
    local is_h2 = proto:find("HTTP/2", 1, true) ~= nil

    if not is_h2 then
        ctx.h2_order        = nil
        ctx.h2_is_h2        = false
        return
    end

    ctx.h2_is_h2 = true

    -- NHÁNH "TRUSTED HEADER" ĐÃ BỊ GỠ (2026-09-06).
    --
    -- Nó đọc `ngx.var.http_x_h2_pseudo_order`, tức header **`X-H2-Pseudo-Order`
    -- của REQUEST** — thứ bất kỳ ai trên Internet cũng gửi được. Không một chỗ
    -- nào trong repo đặt header này (`grep -rn -i 'h2.pseudo.order' *.sh *.conf`
    -- → rỗng), nên nó chưa từng có nguồn hợp lệ.
    --
    -- Và nó không chỉ cho phép tự khai thứ tự: nhánh đó **`return` sớm**, nên
    -- một header duy nhất bỏ qua luôn cả phép kiểm `h2_tls_mismatch` bên dưới.
    -- Gửi `X-H2-Pseudo-Order: masp` là vừa nhận thứ tự của Chrome vừa tắt phép
    -- đối chiếu. Một dòng, một bypass.
    --
    -- Gỡ đi không tạo FP: không có client hợp lệ nào đang dùng đường này.
    -- Nếu sau này thật sự đặt một proxy nội bộ phía trước, thì điều kiện phải
    -- là "IP nguồn nằm trong danh sách tin cậy VÀ edge đã ghi đè header",
    -- không phải "header có mặt".
    local ua = ctx.ua or ngx.var.http_user_agent or ""
    local order, source = infer_from_ua(ua)

    ctx.h2_order         = order
    -- `h2_pseudo_method`, `h2_pseudo_source` va `h2_header_obs` DA BI GO
    -- (2026-09-06): ca ba chi-ghi. Rieng `observe_headers()` doc BAY bien
    -- `ngx.var` roi noi chuoi tren MOI request HTTP/2 — cong viec that cho mot
    -- gia tri chi xuat hien lai trong dong log DEBUG cua chinh no.

    if order and ctx.tls13_offered ~= nil then
        local pattern_info = KNOWN_PATTERNS[order]
        -- `tls13 == nil` = thứ tự này dùng chung bởi nhiều client khác họ ⇒
        -- KHÔNG kết luận gì. Thiếu phép kiểm này thì `nil ~= true` là đúng và
        -- mọi thứ tự mơ hồ lại bắn mismatch — chính là lỗi vừa sửa ở trên.
        if pattern_info and pattern_info.tls13 ~= nil
           and pattern_info.tls13 ~= ctx.tls13_offered then
            ctx.h2_tls_mismatch = true
            ngx.log(ngx.DEBUG,
                "[h2_pseudo] tls_version mismatch: order=", order,
                " expects_tls13=", tostring(pattern_info.tls13),
                " actual_tls13=", tostring(ctx.tls13_offered))
        end
    end

    ngx.log(ngx.DEBUG,
        "[h2_pseudo] order=", tostring(order),
        " source=", source)
end

return _M
