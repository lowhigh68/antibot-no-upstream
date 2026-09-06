local _M = {}

-- ── FILE NÀY KHÔNG CÒN TÍNH JA3S. NÓ LÀ NHỊP 2 CỦA CẦU JA3. ─────────────
--
-- Phần JA3S cũ đã bị gỡ (2026-09-06) vì nó sinh **một hằng số**:
-- `d8eada1de0f744e8f2d11cc5ea02451d` = MD5 của chuỗi `"0,0,"`, giống nhau trên
-- mọi kết nối. Hai lỗi API, cả hai xác nhận bằng bộ dò trên 5 máy production:
--
--   `ssl.get_tls1_version()` trả về **số** (0x0303/0x0304), nhưng code tra
--   `VER_MAP` bằng khoá **chuỗi** ("TLSv1.2") ⇒ `version = 0`. Tên biến trong
--   bản cũ là `ver_str` — ý định ban đầu là `get_tls1_version_str()`, và hàm
--   đó CÓ tồn tại.
--
--   `ngx.ssl.get_cipher_name` **KHÔNG TỒN TẠI** (đo trên cả 5 máy) ⇒
--   `cipher_id = 0`. Muốn lấy cipher đã thoả thuận thì dùng `ngx.var.ssl_cipher`
--   ở access phase.
--
-- Và kể cả sửa hai lỗi đó, nó vẫn không phải JA3S chuẩn: danh sách extension
-- được **bịa ra** (tự thêm 0xFF01 và 0x0017 cho mọi TLS 1.2, để rỗng cho TLS
-- 1.3), chứ không đọc từ ServerHello thật. OpenResty không cho đọc ServerHello.
-- Nên hash đó không đối chiếu được với pcap/Zeek/database nào.
--
-- Tại sao gỡ được mà không mất gì: **không một module nào tiêu thụ `ctx.ja3s`**
-- — không scoring, không reputation, không correlation, không enforcement. Đó
-- cũng chính là lý do một hằng số sống được lâu đến thế.
--
-- ⚠️ NHƯNG KHÔNG ĐƯỢC XOÁ FILE NÀY.
--
-- `_M.capture()` được gọi từ `ssl_certificate_by_lua_block` trong **99
-- per-domain conf** do `nginx/da_to_openresty.sh` sinh ra, và nó là **nơi duy
-- nhất** gọi được `ja3.relay()` — nhịp 2 của cầu JA3, phase đầu tiên mà
-- OpenSSL đã nạp `client_random`. Xoá file này là **JA3 chết theo**, và phải
-- sửa 99 conf mới dựng lại được. Giữ nguyên tên module và tên hàm.
--
-- Nếu sau này thật sự cần profile TLS đã thoả thuận, lấy ở **access phase**
-- bằng `ngx.ssl.get_tls1_version()` (giữ kiểu số) + `ngx.var.ssl_cipher`, và
-- đặt tên đúng bản chất — `tls_negotiated`, không phải JA3S.

-- PHÒNG VỆ BẮT BUỘC (cùng bài học 2026-04-22 với ja3.capture): mọi lỗi Lua
-- trong ssl_certificate_by_lua đều HUỶ BẮT TAY → sập HTTPS. Nuốt lỗi + log ERR.
function _M.capture()
    local ok, err = pcall(function()
        require("antibot.transport.tls.ja3").relay()
    end)
    if not ok then
        ngx.log(ngx.ERR, "[ja3s] relay ERROR (đã nuốt, handshake tiếp tục): ",
                tostring(err))
    end
end

return _M
