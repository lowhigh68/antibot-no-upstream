local _M = {}

-- File RIÊNG, không nhập vào antibot.log.
--
-- Lý do: WAF là hạng mục sinh nhiều FP và phải soi log thường xuyên, trong khi
-- antibot.log ghi MỌI request. Trộn vào nhau thì mỗi lần dò một FP phải lọc qua
-- hàng trăm nghìn dòng không liên quan. Và `write_log_line` bên logger.lua
-- `io.open`/write/`close` cho TỪNG request — nối thêm chi tiết WAF vào đó là
-- bắt 99% lưu lượng không dính luật nào trả giá cho 1% dính.
--
-- Nối ngược về antibot.log bằng cặp `id=` + `ts=`. Cùng mô hình tách
-- error-log/audit-log của ModSecurity.
local WAF_LOG = "/var/log/antibot/waf.log"

-- `matched=` là dữ liệu KẺ TẤN CÔNG ĐIỀU KHIỂN HOÀN TOÀN đi vào file log.
-- Một ký tự xuống dòng trong payload là giả mạo trọn một dòng log và đầu độc
-- mọi phép đo về sau. Lọc về ASCII in được TRƯỚC, rồi mới cắt độ dài — làm
-- ngược thứ tự thì vẫn có thể cắt giữa một chuỗi nhiều byte và để lại rác.
-- (Đã gặp thật: gawk báo `Invalid multibyte data` khi đọc antibot.log vì có UA
-- chứa byte UTF-8 hỏng lọt qua bộ khử chỉ xử lý khoảng trắng.)
local function scrub(s, max)
    if not s or s == "" then return "-" end
    s = tostring(s)
    s = s:gsub("[^\032-\126]", "_")
    s = s:gsub("[%s\"]", "_")
    if #s > max then s = s:sub(1, max) .. "~" end
    return s
end

-- Tạo sẵn file rỗng lúc khởi động worker.
--
-- Khác `antibot.log` ở một điểm quyết định: `logger.run()` chạy cho MỌI request
-- nên antibot.log tái sinh trong vài mili giây sau khi bị xoá — vắng mặt nó là
-- một chẩn đoán rõ ràng. `waf_logger.run()` thoát sớm khi không luật nào bắn,
-- nên nếu không có hàm này thì sau khi deploy `waf.log` KHÔNG TỒN TẠI, và
-- `tail` nó trả "No such file or directory". Người vận hành không phân biệt
-- được "chưa có tấn công nào" với "module hỏng / sai quyền thư mục".
--
-- Chạy được thẳng trong `init_worker_by_lua`: đây là file I/O thường, không
-- phải cosocket, nên không vướng lệnh cấm đã buộc `goodbot_seed` phải defer
-- qua `ngx.timer.at`.
function _M.ensure()
    local fh, err = io.open(WAF_LOG, "a")
    if not fh then
        ngx.log(ngx.ERR, "[waf] KHONG TAO DUOC ", WAF_LOG, ": ", tostring(err),
                " — moi luat WAF se ban ma khong ghi duoc gi. Kiem thu muc",
                " /var/log/antibot va quyen cua user `nginx`.")
        return false
    end
    fh:close()
    return true
end

function _M.run(ctx)
    if not ctx then return end
    local hits = ctx.waf_hits
    if not hits or #hits == 0 then return end

    local fh, err = io.open(WAF_LOG, "a")
    if not fh then
        -- ngx.ERR chứ không WARN. `da_to_openresty.sh` sinh `error_log <path>;`
        -- KHÔNG kèm mức ⇒ nginx lấy mặc định `error` ⇒ WARN bị lọc sạch trong
        -- mọi server block per-domain. Ghi ở WARN nghĩa là hỏng trong im lặng.
        ngx.log(ngx.ERR, "[waf] khong mo duoc ", WAF_LOG, ": ", tostring(err))
        return
    end

    local now    = ngx.time()
    local stamp  = os.date("%Y-%m-%d %H:%M:%S")
    local domain = (ctx.req and ctx.req.host) or ngx.var.host or "-"
    local id     = ctx.identity or ctx.fp_light or "-"
    local class  = ctx.req_class or "-"

    -- richness chỉ có với luật `signal` (request đi hết pipeline). Luật `block`
    -- thoát ở access phase trước khi `session_richness` kịp chạy, và không gọi
    -- nó ở đó vì hàm ấy có một lượt Redis và cần `ctx.identity` chưa tồn tại.
    local richness = ctx.session_richness and
        string.format("%.2f", ctx.session_richness) or "-"

    -- Bù cho chỗ richness khuyết, và với riêng bốn luật WordPress này thì đây
    -- còn là chỉ dấu FP TRỰC TIẾP hơn: có cookie đăng nhập WP nghĩa là người
    -- gửi rất có thể là chính chủ website. Chỉ là một lượt tìm chuỗi, không I/O.
    -- Hardcode tên cookie ở đây KHÔNG phá nguyên tắc generic của
    -- `session_richness` — module này đã là WordPress-specific theo định nghĩa.
    local wpauth = (ngx.var.http_cookie or ""):find("wordpress_logged_in_", 1, true)
        and 1 or 0

    for i = 1, #hits do
        local h = hits[i]
        fh:write(string.format(
            "[%s] [waf] ts=%d id=%s domain=%s ip=%s rule=%s target=%s"
            .. " sev=%s pl=%d matched=%s score=%.2f action=%s class=%s"
            .. " richness=%s wpauth=%d\n",
            stamp,
            now,
            scrub(id, 64),
            scrub(domain, 80),
            scrub(ctx.ip or ngx.var.remote_addr, 45),
            h.rule or "-",
            h.target or "-",
            h.action == "block" and "critical" or "notice",
            0,                       -- paranoia level: 0 = luật gốc, chưa phải CRS
            scrub(h.matched, 160),
            h.score or 0,
            h.action or "-",
            class,
            richness,
            wpauth))
    end

    fh:close()
end

return _M
