local _M = {}

-- `observe_stream_id()` VÀ `ctx.h2_request_profile` ĐÃ BỊ XOÁ (2026-09-06).
--
-- `observe_stream_id` đọc `ngx.var.http2_stream_id`. Biến đó KHÔNG có trong
-- tài liệu module HTTP/2 của nginx — bản chính thức chỉ công bố `$http2`.
-- `ngx.var` của một biến không tồn tại trả nil, `tonumber(nil)` = nil, nên hàm
-- luôn trả nil và mọi trường dẫn xuất (`is_fresh_conn`, `is_reused`,
-- `request_count`) chưa bao giờ có giá trị.
--
-- `ctx.h2_request_profile` thì dựng ba bảng lồng nhau cộng một `string.format`
-- trên MỌI request HTTP/2 rồi không nơi nào đọc. Đây là thứ đắt nhất trong
-- đám field chỉ-ghi vì nó cấp phát, không chỉ là một phép gán.
--
-- `classify_request_size()` Ở LẠI: `ctx.h2_request_anomaly` CÓ người đọc —
-- `transport/http2/signature.lua:61` cộng 0.2 vào `h2_bot_confidence`.
local function classify_request_size()
    local method = ngx.var.request_method or "GET"
    local cl     = tonumber(ngx.var.http_content_length)
    local te     = ngx.var.http_transfer_encoding

    if method == "GET" and cl ~= nil and cl > 0 then
        return "get_with_body"
    elseif method == "POST" and cl == 0 then
        return "post_empty_body"
    end
    return nil
end

function _M.run(ctx)
    if not ctx.h2_is_h2 then return end

    local anomaly = classify_request_size()
    if anomaly then
        ctx.h2_request_anomaly = anomaly
        ngx.log(ngx.INFO, "[h2_window] request anomaly: ", anomaly)
    end
end

return _M
