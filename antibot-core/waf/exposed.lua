local _M = {}

-- Luật phơi bày file — KHÔNG phụ thuộc WordPress.
--
-- Khác `wp_paths.lua` ở phạm vi: những luật này áp cho MỌI site trên máy, kể cả
-- site code tự viết mà bảy luật WordPress cố tình không đụng tới. Cũng vì vậy
-- chúng không đi qua cổng `is_wp_host`.
--
-- Đo 2026-09-02: quét toàn bộ `nginx/da_to_openresty.sh` chỉ thấy bốn dòng chứa
-- `.well-known`, đều là location CHO PHÉP. Không có `location ~ /\.` deny ở bất
-- kỳ đâu. Apache mặc định chặn `.ht*` nhưng KHÔNG chặn `.env` và KHÔNG chặn
-- `.git/`. Nghĩa là trên mọi domain của máy này, hai thứ đó nhiều khả năng đang
-- được phục vụ bình thường.

-- ── Dotfile ──────────────────────────────────────────────────────────
-- Chặn theo NGUYÊN TẮC (bất kỳ thành phần đường dẫn nào bắt đầu bằng dấu chấm)
-- chứ không theo danh sách tên. `.env` rò credential database cùng API key,
-- `.git/` cho tải về toàn bộ mã nguồn kèm lịch sử — và một danh sách tên sẽ
-- luôn chậm hơn cái tiếp theo.
--
-- ĐÚNG MỘT ngoại lệ, và nó bắt buộc: `/.well-known/`. Chặn nhầm chỗ này là mọi
-- domain trên máy KHÔNG GIA HẠN ĐƯỢC chứng chỉ ACME, và nó hỏng lặng lẽ cho tới
-- đúng ngày hết hạn.
--
-- `[^/.]` sau dấu chấm loại luôn `..` — nginx đã chuẩn hoá `..` đi trước khi tới
-- đây, nhưng để vậy thì luật không phụ thuộc vào giả định đó.
local RX_DOTFILE = "(?:^|/)\\.[^/.]"
local WELL_KNOWN = "/.well-known/"

-- ── File dump / backup ───────────────────────────────────────────────
-- Chỉ những đuôi KHÔNG BAO GIỜ là nội dung web hợp lệ. Một `.sql` rò ra là mất
-- trọn database — nặng hơn webshell, vì webshell còn phải chạy được mới gây hại.
--
-- CỐ Ý KHÔNG có `.zip` / `.gz` / `.tar.gz`: chúng được phục vụ hợp lệ (file tải
-- về trong uploads) và không phân biệt được với bản sao lưu chỉ bằng đường dẫn.
--
-- CŨNG ĐÃ LOẠI cách tiếp cận theo thư mục ("mọi thứ dưới /wp-content/<dir>/ lạ
-- đều chặn"). Nghe generic hơn nhưng sai: thư mục cache ĐƯỢC phục vụ thật —
-- W3TC `/wp-content/cache/minify/`, Autoptimize `/wp-content/cache/autoptimize/`,
-- Divi `/wp-content/et-cache/` — nên nó quay về đúng bài toán liệt kê tên thư
-- mục mà kế hoạch đã bác bỏ, chỉ khác là lần này liệt kê phía cho phép.
local RX_DUMP = [[\.(?:sql|wpress|bak|old|orig|save|swp|swo)(?:\.(?:gz|bz2|xz))?$]]

local RULES = {
    dotfile_exposed = { action = "block", score = 0,
        why = "Dotfile (.env / .git/ / .htpasswd) khong bao gio duoc phuc vu" },
    dump_exposed    = { action = "block", score = 0,
        why = "Dump/backup (.sql .wpress .bak) — ro ra la mat tron database" },
}
_M.RULES = RULES

-- Trả về rule_id hoặc nil. Không nhận `host`: các luật này không có cổng host.
--
-- Thứ tự: dump trước dotfile. Một `/.env.bak` khớp cả hai, và `dump_exposed` là
-- nhãn đúng hơn cho việc đọc log về sau.
function _M.check(uri)
    if not uri or uri == "" then return nil end
    local low = uri:lower()

    if ngx.re.find(low, RX_DUMP, "jo") then return "dump_exposed" end

    if low:sub(1, #WELL_KNOWN) == WELL_KNOWN then return nil end
    if ngx.re.find(low, RX_DOTFILE, "jo") then return "dotfile_exposed" end

    return nil
end

return _M
