local _M = {}
local pool = require "antibot.core.redis_pool"

-- P0 — hardening WordPress theo ĐƯỜNG DẪN, không theo CVE.
--
-- Vì sao generic thay vì virtual patching từng CVE: hàng trăm người dùng, bộ
-- plugin không biết trước và thay đổi hằng ngày. Luật per-CVE là liệt kê một
-- danh sách ta không kiểm soát được — luôn chậm hơn kẻ tấn công, và chặn oan
-- người dùng cài plugin hợp lệ. Bốn luật dưới đây không cần biết plugin nào,
-- phiên bản nào, CVE nào.
--
-- TỰ GIỚI HẠN PHẠM VI: `/wp-content/` và `/wp-admin/` là đường dẫn riêng của
-- WordPress. Site không phải WP không có chúng, nên không cần cấu hình
-- "domain này là WP" cho ba luật đầu — chính đường dẫn đã là bộ lọc.
-- Riêng luật 3 (file PHP ở web root) KHÔNG tự giới hạn được, xem chú thích
-- tại `is_wp_host`.

-- ── Đuôi thực thi PHP ────────────────────────────────────────────────
-- KHÔNG neo vào cuối chuỗi. Trên Apache cấu hình bằng
-- `AddHandler application/x-httpd-php .php` (mặc định của DirectAdmin/cPanel),
-- handler khớp theo TỪNG đuôi trong tên file chứ không chỉ đuôi cuối — nên
-- `shell.php.jpg` VẪN chạy như PHP. Đó chính là lối vòng "đuôi kép" kinh điển.
-- Lookahead cho phép `.` để bắt cả dạng đó, và cho phép `/` để bắt PATH_INFO
-- (`/shell.php/x.jpg`).
--
-- `ngx.var.uri` là path đã chuẩn hoá và giải mã, không kèm query string, nên
-- không phải lo `?`. nginx tự trả 400 cho null byte trong URI. Chuẩn hoá cũng
-- có nghĩa `..` đã bị gỡ trước khi tới đây, nên `uploads/../../shell.php` đến
-- nơi dưới dạng `/shell.php` và rơi vào luật web root — đúng như mong muốn.
--
-- RIÊNG TRÊN STACK NÀY, đuôi kép có hai số phận khác nhau (xem
-- `nginx/da_to_openresty.sh`, khối `static_fastpath`):
--   `shell.php.jpg` → khớp location regex tĩnh `\.(js|css|png|jpg|…)$` ⇒ nginx
--      `try_files` phục vụ nguyên văn, KHÔNG proxy sang Apache ⇒ không chạy PHP.
--      Hit ở đây là dò tìm hoặc file đặt tên xấu, không phải khai thác thành công.
--   `shell.php.bak` → đuôi không nằm trong danh sách tĩnh ⇒ rơi xuống
--      `location /` ⇒ proxy sang Apache ⇒ AddHandler VẪN chạy nó như PHP.
-- Vì trường hợp thứ hai còn nguy hiểm nên vẫn bắt cả hai; đọc waf.log thì nhớ
-- phân biệt để khỏi đánh giá quá mức mức độ nghiêm trọng.
local RX_PHP_EXEC = [[\.(?:php[0-9]?|phtml|phar|pht|phps)(?=[/;.\\]|$)]]

-- Thư mục con của /wp-content/ mà PHP nằm ở đó là HỢP LỆ.
-- `mu-plugins` là must-use plugin của WordPress core — bỏ sót là chặn oan.
local WP_CONTENT_OK = {
    themes        = true,
    plugins       = true,
    ["mu-plugins"] = true,
}

-- File PHP hợp lệ ở web root của WordPress. Danh sách này ổn định qua nhiều
-- phiên bản; thiếu một cái thì hậu quả là tín hiệu thừa chứ không phải chặn oan
-- (luật 3 chỉ chấm điểm, không chặn).
local WP_ROOT_OK = {
    ["index.php"]             = true,
    ["wp-login.php"]          = true,
    ["wp-cron.php"]           = true,
    ["xmlrpc.php"]            = true,
    ["wp-config.php"]         = true,
    ["wp-settings.php"]       = true,
    ["wp-load.php"]           = true,
    ["wp-blog-header.php"]    = true,
    ["wp-links-opml.php"]     = true,
    ["wp-mail.php"]           = true,
    ["wp-signup.php"]         = true,
    ["wp-activate.php"]       = true,
    ["wp-trackback.php"]      = true,
    ["wp-comments-post.php"]  = true,
}

-- action: "block" = chặn ngay, near-zero FP.
--         "signal" = chỉ góp điểm, để engine.lua quyết cùng các tầng tin cậy.
-- score:  giá trị [0,1] đổ vào signal `waf_wp_path` (trọng số trong compute.lua).
--
-- Chưa làm cấu hình bật/tắt per-rule ở đây: F3 (chính sách theo domain) mới là
-- chỗ của việc đó, làm hai lần là hai nguồn sự thật.
local RULES = {
    wp_upload_exec   = { action = "block",  score = 0,
        why = "WordPress khong bao gio phuc vu PHP hop le tu /wp-content/uploads/" },
    wp_content_exec  = { action = "block",  score = 0,
        why = "PHP duoi /wp-content/ ngoai themes|plugins|mu-plugins" },
    wp_root_unknown  = { action = "signal", score = 0.50,
        why = "PHP la o web root cua mot host da xac nhan la WordPress" },
    wp_plugin_direct = { action = "signal", score = 0.25,
        why = "Goi thang file PHP trong /wp-content/plugins/" },
}
_M.RULES = RULES

-- ── Host này có phải WordPress không ──────────────────────────────────
-- Luật 3 nhắm "file PHP lạ ở web root". Trên hosting chia sẻ có cả site code
-- tự viết (đo được: cloud183-139, 366k request/ngày), root PHP tuỳ ý là chuyện
-- BÌNH THƯỜNG — bắn tín hiệu cho mọi request như vậy là chế ra một cỗ máy FP.
-- Luật này chỉ có nghĩa khi web root có danh sách file cố định, tức là WordPress.
--
-- Cách nhận biết không cần khai báo: thấy bất kỳ đường dẫn riêng của WP nào
-- trên host đó thì đánh dấu. Tự học, không cấu hình, không danh sách domain.
local WP_HOST_TTL_REDIS  = 2592000   -- 30 ngày, làm mới mỗi lần thấy
local WP_HOST_TTL_SHARED = 300       -- cùng mức với ip_classify.lua
local shared_cache = ngx.shared.antibot_cache

local function mark_wp_host(host)
    if not host or host == "" then return end
    if shared_cache then
        -- Đã ghi trong 300s gần đây thì khỏi chạm Redis lần nữa.
        if shared_cache:get("wphost:" .. host) == 1 then return end
        shared_cache:set("wphost:" .. host, 1, WP_HOST_TTL_SHARED)
    end
    pool.safe_set("waf:wphost:" .. host, "1", WP_HOST_TTL_REDIS)
end

local function is_wp_host(host)
    if not host or host == "" then return false end
    if shared_cache then
        local v = shared_cache:get("wphost:" .. host)
        if v ~= nil then return v == 1 end
    end
    local hit = pool.safe_get("waf:wphost:" .. host) == "1"
    if shared_cache then
        shared_cache:set("wphost:" .. host, hit and 1 or 0, WP_HOST_TTL_SHARED)
    end
    return hit
end

-- ── Khớp luật ────────────────────────────────────────────────────────
-- Trả về rule_id hoặc nil. Một request khớp nhiều nhất một luật: thứ tự dưới
-- đây đi từ hẹp tới rộng để luật cụ thể hơn thắng.
function _M.check(uri, host)
    if not uri or uri == "" then return nil end
    local low = uri:lower()

    local wc = low:find("/wp-content/", 1, true)

    -- Đánh dấu host là WordPress ngay cả khi request không phải PHP: ảnh và CSS
    -- dưới /wp-content/ là bằng chứng chắc chắn nhất, và cũng là loại request
    -- nhiều nhất trên site WP.
    if wc or low:find("/wp-admin/", 1, true) or low:find("/wp-includes/", 1, true) then
        mark_wp_host(host)
    end

    -- Không trỏ tới file PHP thì cả bốn luật đều không áp dụng. Đây là lối ra
    -- của tuyệt đại đa số request, và nó chỉ tốn một lượt regex.
    if not ngx.re.find(low, RX_PHP_EXEC, "jo") then return nil end

    if wc then
        local rest = low:sub(wc + 12)             -- 12 = #"/wp-content/"
        local sub  = rest:match("^([^/]+)/")
        if sub == "uploads" then return "wp_upload_exec" end
        if sub and not WP_CONTENT_OK[sub] then return "wp_content_exec" end
        -- PHP nằm ngay tại /wp-content/x.php (không có thư mục con):
        -- drop-in như advanced-cache.php chỉ được PHP `include`, không bao giờ
        -- được gọi thẳng qua HTTP. Gọi thẳng là dấu hiệu.
        if not sub then return "wp_content_exec" end
        if sub == "plugins" then return "wp_plugin_direct" end
        return nil                                 -- themes/, mu-plugins/
    end

    local file = low:match("^/([^/]+)$")
    if file and not WP_ROOT_OK[file] and is_wp_host(host) then
        return "wp_root_unknown"
    end

    return nil
end

return _M
