local _M = {}

-- Luật phơi bày file — KHÔNG phụ thuộc WordPress.
--
-- Khác `wordpress/paths.lua` ở phạm vi: những luật này áp cho MỌI site trên máy, kể cả
-- site code tự viết mà bảy luật WordPress cố tình không đụng tới. Cũng vì vậy
-- chúng không đi qua cổng `is_wp_root`.
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

-- Đuôi thực thi PHP. BẢN SAO CÓ Ý của `RX_PHP_EXEC` trong `wordpress/paths.lua`:
-- `exposed.lua` cố tình không phụ thuộc module WordPress (nó chạy TRƯỚC, không có
-- cổng host, và phải dùng được trên máy không có CMS nào — 183-139 là code tay).
-- Hai bản phải giống nhau; sửa một thì sửa cả hai.
--
-- `(?=[/;.\]|$)` bắt cả PATH_INFO (`/x.php/y`) và `;` của một số server.
local RX_PHP_EXEC = [[\.(?:php[0-9]?|phtml|phar|pht|phps)(?=[/;.\\]|$)]]

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
    wellknown_exec  = { action = "block", score = 0,
        why = "PHP trong /.well-known/ — RFC 8615 chi chua metadata tinh" },
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

    -- `/.well-known/` được miễn `dotfile_exposed` — nhưng CHỈ cho nội dung tĩnh.
    --
    -- Ngoại lệ ACME là bắt buộc (mất nó = không gia hạn được chứng chỉ, hỏng
    -- lặng lẽ tới đúng ngày hết hạn), nhưng nó đã QUÁ RỘNG: miễn cả cây nghĩa là
    -- miễn luôn mọi `.php` đặt trong đó.
    --
    -- Đo 25-09 trên SÁU máy, và cấu trúc giống nhau ở cả sáu:
    --   TRÊN ĐĨA, toàn bộ nội dung `/.well-known/` thật của cả fleet là 23 file:
    --     19 `.txt` (token ACME + security.txt), 2 không đuôi, 1 `.json`, 1 `.html`
    --     `.php`: **0 file** trên 6/6 máy.
    --   TRONG LOG, hàng nghìn request `.php` mỗi máy:
    --     `gecko-litespeed.php` 2636/2026/1996/113/84/50
    --     `about.php` 4985/4218/4970/488 · `admin.php` 1190/1182/1081/126
    --     `index.php` 1924/1741/1845/206 · `wp-conflg.php`, `caches.php`,
    --     `classwithtostring.php`, `radio.php`, `content.php`, `file.php`
    --   Và BÊN TRONG `acme-challenge/`, nơi đáng lẽ chỉ có token:
    --     `/.well-known/acme-challenge/index.php` 1911/317/321/209
    --     `/.well-known/acme-challenge/xmrlpc.php?p=` 21
    --     `/adminfuns.php/.well-known/acme-challenge/file.php` trên CẢ SÁU máy,
    --       cùng một hình dạng — một bộ công cụ ghép ba thủ đoạn: tên webshell,
    --       PATH_INFO, và đường miễn trừ này.
    --
    -- ACME thật KHÔNG BAO GIỜ yêu cầu `.php`: token Let's Encrypt là chuỗi
    -- base64url không đuôi. Mọi `.php` trong `acme-challenge/` là dò, 100%.
    --
    -- Bất biến (RFC 8615): `/.well-known/` chứa METADATA TĨNH — `.json`, `.txt`,
    -- token không đuôi. Không có URI `/.well-known/` chuẩn nào thực thi PHP. Đây
    -- là bất biến về giao thức, KHÔNG phải danh sách tên file cần bảo trì.
    --
    -- KHÔNG thu hẹp ngoại lệ thành `/.well-known/acme-challenge/`: đo cho thấy
    -- `security.txt`, `assetlinks.json`, `apple-app-site-association`,
    -- `traffic-advice`, `passkey-endpoints`, `openid-configuration`, `gpc.json`,
    -- `tdmrep.json`, `change-password`, `jwks.json` đều có lưu lượng THẬT trên
    -- fleet. Chặn theo đuôi thực thi thì không cần biết tên nào hợp lệ — đó là lý
    -- do nó không quay về bài toán liệt kê mà kế hoạch đã bác.
    --
    -- `/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200`
    -- (82 + 16 lần) là phép tự kiểm soft-404 của Chrome. Không đuôi `.php` nên
    -- luật này không chạm tới nó.
    if low:sub(1, #WELL_KNOWN) == WELL_KNOWN then
        if ngx.re.find(low, RX_PHP_EXEC, "jo") then return "wellknown_exec" end
        return nil
    end
    if ngx.re.find(low, RX_DOTFILE, "jo") then return "dotfile_exposed" end

    return nil
end

return _M
