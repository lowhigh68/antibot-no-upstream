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
-- tại `is_wp_root`.

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
--
-- Khôi phục 2026-09-02 sau khi bị xoá ngoài phiên làm việc: phân biệt này vừa
-- chứng minh là có tải trọng thật — `/wp-config.php.bak` trả 200 trên
-- chungkhoanplus.com, và câu "nó được chạy như PHP hay phục vụ nguyên văn kèm
-- credential MySQL" trả lời được chính nhờ hai nhánh ghi ở trên.
local RX_PHP_EXEC = [[\.(?:php[0-9]?|phtml|phar|pht|phps)(?=[/;.\\]|$)]]

-- Thư mục con của /wp-content/ mà PHP nằm ở đó là HỢP LỆ.
-- `mu-plugins` là must-use plugin của WordPress core — bỏ sót là chặn oan.
local WP_CONTENT_OK = {
    themes        = true,
    plugins       = true,
    ["mu-plugins"] = true,
}

-- File duy nhất dưới `/wp-includes/` được fetch thẳng qua HTTP một cách hợp lệ.
-- Đường dẫn tính từ sau `/wp-includes/`. Mọi thứ còn lại ở đó là thư viện core,
-- file nào cũng mở đầu bằng guard ABSPATH và chỉ được `require` từ trong PHP.
-- Đây cũng là chỗ thả webshell kinh điển, chính vì hiếm ai nhìn vào.
local WP_INCLUDES_OK = {
    ["js/tinymce/wp-tinymce.php"] = true,   -- bộ nạp JS động, trình duyệt gọi thật
    ["ms-files.php"]              = true,   -- multisite phục vụ file qua PHP
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
    -- 0.50 chu khong phai 0.25 nhu plugins: mu-plugin HOP LE khong bao gio bi
    -- fetch qua HTTP ca — WordPress tu `include` moi file .php o day tren MOI
    -- request, khong can kich hoat. Nen mot request truc tiep dang ngo hon han
    -- so voi plugins, noi ma khong it plugin cu van tu goi PHP cua chinh no.
    wp_muplugin_direct = { action = "signal", score = 0.50,
        why = "Goi thang PHP trong /wp-content/mu-plugins/" },
    -- Van 0.25 va van signal: timthumb.php cung ca mot the he theme cu that su
    -- goi thang PHP cua chinh chung. Block o day la FP hang loat.
    wp_theme_direct  = { action = "signal", score = 0.25,
        why = "Goi thang PHP trong /wp-content/themes/" },
    wp_includes_exec = { action = "block",  score = 0,
        why = "PHP duoi /wp-includes/ ngoai 2 file trong allowlist" },
    wp_admin_includes_exec = { action = "block", score = 0,
        why = "PHP duoi /wp-admin/includes/ — thu vien thuan, chi duoc require" },
}
_M.RULES = RULES

-- ── (host, tiền tố) này có phải một GỐC WordPress không ───────────────
-- Luật 3 nhắm "file PHP lạ ở web root". Trên hosting chia sẻ có cả site code
-- tự viết (đo được: cloud183-139, 366k request/ngày), root PHP tuỳ ý là chuyện
-- BÌNH THƯỜNG — bắn tín hiệu cho mọi request như vậy là chế ra một cỗ máy FP.
-- Luật này chỉ có nghĩa khi web root có danh sách file cố định, tức là WordPress.
--
-- "Gốc WordPress" là một CẶP (host, tiền tố), không phải chỉ host. Đo trên
-- cloud168-101 (2026-09-02): 5 bản WordPress nằm một cấp dưới docroot, tất cả
-- đều là bản cài trong thư mục con (`/en` ×4, `/id` ×1), không cái nào là
-- subdomain. Một host có thể có hai gốc: `""` và `"/en"`, và hai câu hỏi đó
-- phải độc lập — biết `/en` là WordPress KHÔNG cho phép kết luận gì về gốc
-- domain, và ngược lại.
--
-- Cách nhận biết không cần khai báo: thấy bất kỳ đường dẫn riêng của WP nào
-- trên host đó thì đánh dấu. Tự học, không cấu hình, không danh sách domain.
local WP_HOST_TTL_REDIS  = 2592000   -- 30 ngày, làm mới mỗi lần thấy
local WP_HOST_TTL_SHARED = 300
local shared_cache = ngx.shared.antibot_cache

-- ĐÁNH DẤU CHẠY Ở LOG PHASE, KHÔNG PHẢI ACCESS PHASE.
--
-- Bản đầu đánh dấu ngay trong `check()`, dựa hoàn toàn vào URI do client gõ:
-- một `GET /wp-admin/` là cờ WordPress sống 30 ngày, trên host bất kỳ. Ba hậu quả:
--   1. Đầu độc — một request đủ để mọi PHP ở web root của một site code tự viết
--      bắn `wp_root_unknown`, đúng cỗ máy FP mà cổng này sinh ra để tránh.
--   2. `host` lấy từ `ngx.var.host` nên Host header bịa cũng tạo được key Redis
--      TTL 30 ngày ⇒ nguyên thủy ghi không giới hạn, giá một request.
--   3. Key rác chèn vào shdict `antibot_cache` (dùng chung toàn hệ)
--      ⇒ đẩy LRU, bán kính nổ vượt ra ngoài WAF.
--
-- Cổng mới: chỉ đánh dấu khi đường dẫn WordPress đó là thứ CÓ THẬT trên đĩa.
-- Host không phải WP không có thư mục `/wp-admin/`; Host header bịa rơi vào
-- default_server cũng vậy. Kẻ tấn công không tạo được file trên đĩa của người
-- khác nên không giả được bằng chứng này.
--
-- Đã cân nhắc và LOẠI: gác theo mã trạng thái phản hồi. Trên WordPress,
-- `.htaccess` chuẩn rewrite mọi đường dẫn không phải file thật về `index.php`,
-- và nhiều theme trả 200 cho chính trang 404 đó — nên 200 là phản hồi MẶC ĐỊNH
-- cho đường dẫn không tồn tại, đúng trên nền tảng mà luật này nhắm tới.
-- Đo trên lưu lượng thật 2026-09-02: 7/7 đường dẫn nghi vấn trả 200 nhưng
-- KHÔNG file nào tồn tại.

-- Có cần chạm đĩa để quyết định đánh dấu không. Rẻ: một lượt shdict + tối đa ba
-- phép tìm chuỗi. Trả false cho gần hết lưu lượng, nên phép chạm đĩa của người
-- gọi chỉ xảy ra một lần mỗi 300s cho mỗi host.
-- WordPress không chỉ nằm ở gốc domain. Đo trên cloud168-101 (2026-09-02):
-- 5/5 thư mục có WordPress nằm một cấp dưới docroot đều là bản cài THẬT trong
-- thư mục con — `/en` trên 4 site, `/id` trên 1 — không cái nào là subdomain.
--
-- Nên "gốc WordPress" là một cặp (host, tiền tố), không phải chỉ host. Cùng một
-- host có thể có hai gốc: `""` và `"/en"`.
--
-- CHẶN Ở ĐỘ SÂU 1. `/a/b/wp-admin/` không được học. Không phải để tiết kiệm mà
-- để chặn phình: tiền tố do người gửi request đặt, nên độ sâu tuỳ ý nghĩa là
-- không gian khoá tuỳ ý. Đúng loại lỗ đã phải vá một lần khi việc đánh dấu còn
-- chạy ở access phase.
local WP_MARKERS = { "/wp-content/", "/wp-admin/", "/wp-includes/" }

local function wp_prefix(low)
    for i = 1, #WP_MARKERS do
        local p = low:find(WP_MARKERS[i], 1, true)
        if p then
            local prefix = low:sub(1, p - 1)   -- "" khi ở gốc domain
            if prefix == "" then return "" end
            if prefix:match("^/[^/]+$") then return prefix end
            return nil                          -- sâu hơn 1 cấp: không học
        end
    end
    return nil
end
_M.wp_prefix = wp_prefix

-- ── KHOÁ NHẬN DIỆN: DOCROOT, KHÔNG PHẢI HOST HEADER ──────────────────
--
-- Câu hỏi mà `is_wp_root` trả lời là một câu hỏi về FILESYSTEM: "thư mục đang
-- phục vụ request này có phải gốc WordPress không". Host header không phải danh
-- tính của thư mục — nó là thứ kẻ gửi chọn.
--
-- VÌ SAO ĐỔI, đo trên fleet 27-09 (đọc từ chính vhost đang chạy, không suy từ
-- `da_to_openresty.sh`):
--
--             docroot   host    tỷ số
--   171-96       79      243     3,1×
--   28-246       46       86     1,9×
--
-- Khoá theo host thì không gian khoá là tập Host — do kẻ gửi chọn, không có chặn
-- trên. `is_wp_root` cache cả kết quả ÂM (300s) và KHÔNG đòi bằng chứng đĩa nào,
-- nên mỗi Host mới đi vào một đường có marker WP là một khoá rác trong
-- `antibot_cache` (5m, dùng CHUNG với whitelist/TLS/stats/risk). Cổng overlay
-- thêm ở bản trước làm đường đó chạy trên MỌI request `/wp-content/`,
-- `/wp-admin/`, `/wp-includes/` — trước đó chỉ `wp_root_unknown` đi qua.
--
-- Đường GHI đã được bịt từ `d3bfd04` (chỉ `mark` khi file WP có thật trên đĩa),
-- nên đây KHÔNG phải lỗ ghi Redis. Nó là đuổi LRU trong dict dùng chung — đúng
-- "bán kính nổ vượt ra ngoài WAF" mà khối chú thích trên `needs_mark` đã lường
-- cho đường ghi, nhưng đường ĐỌC không thừa hưởng phép chặn đó.
--
-- Khoá theo docroot thì không gian khoá bị chặn trên bởi SỐ THƯ MỤC trên máy
-- (~79), và nó hợp nhất alias đúng ngữ nghĩa: `da_to_openresty.sh:646-649` dựng
-- `server_name = domain + www.domain + pointers + www.pointers` cho MỘT khối
-- `server` có MỘT `root`. Đo được trên 171-96: `phuson.vn` có BỐN domain thật
-- (`phuson.vn`, `demo.phuson.vn`, `phusonglasstech.com`, `sunglass.com.vn`) dùng
-- chung một docroot. Chúng dùng chung ĐĨA nên "có WordPress không" là CÙNG một
-- câu hỏi — học một alias là biết cả nhóm. DirectAdmin đã coi chúng là chung;
-- đây chỉ là dùng lại danh tính đã có, không phát minh cách hợp nhất.
--
-- ĐÃ CÂN NHẮC VÀ LOẠI: `$server_name`. `ngx.var.server_name` trả tên ĐẦU của
-- khối `server`, không phải tên khớp — đã gây 642 lượt `ckn=false` oan cho khách
-- trên domain alias. Nó cũng vẫn là danh tính theo tên chứ không theo đĩa, nên
-- không trả lời đúng câu đang hỏi.
--
-- `document_root` KHÔNG phải hằng số trong một request: khối
-- `location ^~ /.well-known/acme-challenge/` đặt `root /var/www/html`
-- (`da_to_openresty.sh:206-212`, có trong CẢ HTTP và HTTPS của MỌI domain). Vô
-- hại ở đây vì đường đó không chứa marker WP nào nên `wp_prefix` trả nil trước
-- khi tới khoá. Nhưng nghĩa đúng của biến là "thư mục phục vụ request NÀY", chứ
-- KHÔNG phải "thư mục của host này" — đừng dùng nó làm khoá cho thứ theo host.
--
-- Giá trị thật trên fleet luôn là `.../public_html` hoặc `.../public_html/<sub>`,
-- KHÔNG có `/` cuối (đo 27-09), nên `<docroot><prefix>` ghép đúng: `prefix` mang
-- `/` đầu, `""` cho gốc. Cùng cách `fim.sh` ghép `root .. path` và `wpinv` ghi
-- `<docroot>` — ba chỗ đồng ý một cách ghép.
local function root_id(docroot, prefix)
    if not docroot or docroot == "" then return nil end
    -- Bỏ `/` cuối nếu có: một máy cấu hình tay có thể ghi `root /a/b/;` và khi đó
    -- `/a/b/` với `/a/b` là HAI khoá cho CÙNG một thư mục. Chuẩn hoá một chỗ.
    if docroot:sub(-1) == "/" then docroot = docroot:sub(1, -2) end
    return docroot .. prefix
end

-- Khoá: giữ NGUYÊN tên tiền tố `wphost:`/`wproot:` cho không gian khoá CŨ (theo
-- host) và dùng tên MỚI cho không gian khoá theo docroot. Hai tên khác nhau là
-- cố ý — chúng phải cùng sống một chu kỳ 30 ngày để không có cửa sổ trống, xem
-- `is_wp_root`.
local function cache_key(host, prefix)
    if prefix == "" then return "wphost:" .. host end
    return "wproot:" .. host .. ":" .. prefix
end

local function redis_key(host, prefix)
    if prefix == "" then return "waf:wphost:" .. host end
    return "waf:wproot:" .. host .. ":" .. prefix
end

-- Không gian khoá MỚI. Một khoá duy nhất cho cả `prefix == ""` và `prefix ~= ""`
-- vì `root_id` đã gộp tiền tố vào đường dẫn — `/home/u/domains/d/public_html` và
-- `/home/u/domains/d/public_html/en` là hai thư mục khác nhau, không cần hai
-- dạng tên khoá để phân biệt.
local function cache_key_root(rid)  return "wpdir:" .. rid end
local function redis_key_root(rid)  return "waf:wpdir:" .. rid end

-- Trả về TIỀN TỐ cần đánh dấu (chuỗi, có thể rỗng), hoặc nil.
-- Trả tiền tố chứ không phải boolean vì người gọi cần chính nó để `mark`.
function _M.needs_mark(uri, host, docroot)
    if not uri or not host or host == "" then return nil end
    local prefix = wp_prefix(uri:lower())
    if not prefix then return nil end
    -- Đã đánh dấu trong 300s gần đây thì thôi. Giá trị 0 (âm, do `is_wp_root`
    -- cache lại) KHÔNG chặn ở đây — nhờ vậy một host mới cài WordPress vẫn tự
    -- được nhận ra thay vì kẹt ở kết quả âm cũ.
    if shared_cache then
        local rid = root_id(docroot, prefix)
        if rid and shared_cache:get(cache_key_root(rid)) == 1 then return nil end
        if shared_cache:get(cache_key(host, prefix)) == 1 then return nil end
    end
    return prefix
end

-- Cat PATH_INFO: `/shell.php/x` -> `/shell.php`. Tra nguyen URI neu khong co
-- duoi PHP nao.
--
-- Vi sao can. Hai cho ghep chuoi `document_root .. uri` de hoi ve mot FILE THAT,
-- va ca hai deu sai voi PATH_INFO:
--   `waf/init.lua`  tra khoa `waf:fimnew:<root><uri>` — FIM ghi duong dan file
--                   that `/…/shell.php`, tra bang `/…/shell.php/x` la LECH KHOA,
--                   nen file FIM vua danh dau lai KHONG duoc nang tin hieu.
--   `target_exists` `io.open("/…/shell.php/x")` tra false du `shell.php` co that
--                   ⇒ cot `exists=` bao 0 cho mot file DANG NAM TREN DIA. Do la
--                   cot duy nhat phan biet "dang do tim" voi "da co san", nen
--                   sai o day lam hong dung phep do quan trong nhat.
--
-- Khong phai gia thuyet: `/wp-content/plugins/us.php/` da xuat hien trong
-- waf.log that — ke tan cong tren may nay biet dung PATH_INFO.
--
-- `ngx.re.find` tra vi tri KET THUC cua phan khop; lookahead `(?=[/;.\\]|$)`
-- rong nen `to` dung o ky tu cuoi cua `.php`. Cat tai do la duoc duong dan
-- script that. `/index.php/2020/01/bai/` -> `/index.php` (permalink PATHINFO),
-- `/a.php/b.php` -> `/a.php` (script that su chay la cai dau).
function _M.script_path(uri)
    if not uri or uri == "" then return uri end
    local _, to = ngx.re.find(uri, RX_PHP_EXEC, "jo")
    if not to then return uri end

    -- Cắt tại dấu `/` ĐẦU TIÊN nằm SAU đuôi PHP. Không có `/` nào thì giữ
    -- nguyên toàn bộ.
    --
    -- Một dòng này xử lý đúng cả hai ca mà hai bản trước đều làm sai một nửa:
    --   `/shell.php/x`            → `/shell.php`         (PATH_INFO)
    --   `/wp-config.php.txt`      → `/wp-config.php.txt` (đuôi kép, giữ nguyên)
    --   `/shell.php.jpg/path`     → `/shell.php.jpg`     (đuôi kép RỒI PATH_INFO)
    --
    -- Bản đầu cắt ngay tại `to`, nên `/wp-config.php.txt` thành `/wp-config.php`
    -- — một file LUÔN tồn tại trên mọi WordPress. Đo 2026-09-03 trên
    -- alumicastore.com: báo `exists=1` cho một file không hề có. Báo động giả ở
    -- đúng chỗ nguy hiểm nhất, vì `wp-config.php.txt` lộ ra là toàn bộ mật khẩu
    -- database.
    --
    -- Bản thứ hai chỉ cắt khi ký tự ngay sau là `/`, nên `/shell.php.jpg/path`
    -- giữ nguyên toàn bộ — trong khi `.php.jpg` chính là dạng `RX_PHP_EXEC` sinh
    -- ra để bắt (AddHandler khớp `.php` ở GIỮA tên). Luật bảo "đây là file có
    -- thể thực thi", `script_path` bảo "đây không phải tên file": hai câu mâu
    -- thuẫn trong cùng một module, và test còn ghi nhận hành vi sai đó như thể
    -- nó đúng.
    local slash = uri:find("/", to + 1, true)
    if not slash then return uri end
    return uri:sub(1, slash - 1)
end

-- Ngắn, để bọc cửa sổ giữa lúc lên lịch timer và lúc timer ghi xong. Không phải
-- TTL thật của việc đánh dấu — nó chỉ ngăn 20 request asset của cùng một trang
-- cùng tạo 20 timer. Timer nào ghi Redis thành công sẽ nâng lên
-- `WP_HOST_TTL_SHARED`.
local WP_HOST_TTL_INFLIGHT = 10

-- ĐÁNH DẤU PHẢI ĐI QUA `ngx.timer.at`, VÀ ĐÂY LÀ MỘT LỖI ĐÃ CHẠY THẬT.
--
-- `mark` được gọi từ `waf.run_log`, tức LOG PHASE — nơi OpenResty **cấm
-- cosocket**. `pool.safe_set` dùng `resty.redis`, tức cosocket, nên nó KHÔNG THỂ
-- thành công ở đó. Và vì là `safe_*` nên nó nuốt lỗi: hỏng hoàn toàn im lặng.
--
-- Đo trên aramex.vn 2026-09-03 00:12: một request `/en/wp-includes/js/...` cho
-- `wp=/en shd=1` mà `redis-cli --scan 'waf:wproot:*'` trống. shdict ghi được
-- (bộ nhớ chia sẻ, không phải cosocket), Redis thì không. Đó là toàn bộ lý do
-- WordPress cài trong thư mục con không bao giờ được học.
--
-- VÌ SAO KHÔNG AI THẤY TRONG BỐN THÁNG: `d3bfd04` chuyển việc đánh dấu từ access
-- phase sang log phase để có quyền chạm đĩa, và mang theo phép ghi Redis không
-- chạy được ở đó. Nhưng `waf:wphost:*` có TTL 30 NGÀY và đã được ghi từ TRƯỚC
-- lần chuyển đó — khoá cũ còn sống nên cơ chế trông vẫn chạy trong khi đã chết.
-- Một bộ đệm sống lâu hơn thứ sinh ra nó thì che được đúng cái chết của nó.
--
-- THỨ TỰ GHI ĐẢO LẠI. Bản cũ ghi shdict TRƯỚC rồi mới ghi Redis, nên bộ đệm
-- tuyên bố "xong rồi" trước khi biết việc có xong không — mỗi lần hỏng là 300
-- giây không thử lại. Nay Redis trước, và shdict chỉ được ghi khi Redis đã
-- nhận. Bộ đệm chỉ được phép nhớ một sự thật ĐÃ xảy ra.
function _M.mark(host, prefix, docroot)
    if not host or host == "" or not prefix then return end

    local ck = cache_key(host, prefix)
    local rk = redis_key(host, prefix)
    local rid = root_id(docroot, prefix)
    local rkr = rid and redis_key_root(rid) or nil
    local ckr = rid and cache_key_root(rid) or nil

    -- Chốt tạm: nếu không có nó, mỗi asset của một trang lại lên lịch một timer
    -- cho tới khi cái đầu tiên ghi xong. `lua_max_running_timers` mặc định 256.
    if shared_cache then
        shared_cache:set(ck, 1, WP_HOST_TTL_INFLIGHT)
        if ckr then shared_cache:set(ckr, 1, WP_HOST_TTL_INFLIGHT) end
    end

    local ok, err = ngx.timer.at(0, function()
        if rkr and pool.safe_set(rkr, "1", WP_HOST_TTL_REDIS) and shared_cache then
            shared_cache:set(ckr, 1, WP_HOST_TTL_SHARED)
        end
        if pool.safe_set(rk, "1", WP_HOST_TTL_REDIS) and shared_cache then
            shared_cache:set(ck, 1, WP_HOST_TTL_SHARED)
        end
    end)

    -- Lên lịch thất bại thì gỡ chốt tạm ngay, đừng để nó chặn 10 giây cho một
    -- việc chắc chắn không xảy ra.
    if not ok then
        if shared_cache then
            shared_cache:delete(ck)
            if ckr then shared_cache:delete(ckr) end
        end
        ngx.log(ngx.ERR, "[waf] khong len lich duoc mark ", rk, ": ", tostring(err))
    end
end

-- DI TRÚ HAI KHÔNG GIAN KHOÁ, KHÔNG CÓ CỬA SỔ TRỐNG.
--
-- Đổi khoá là đổi không gian khoá, nên mọi khoá đang có trên fleet không đọc được
-- nữa: 52 khoá `wpinv` vừa ghi trên 28-246, cộng số `mark()` đã học (79 `wphost`
-- thật trong Redis). Nếu chỉ đọc khoá mới thì ba luật HARD-BLOCK im lặng cho tới
-- khi học lại — đúng cửa sổ cold-start mà `wpinv` vừa đóng hôm nay.
--
-- Nên: đọc khoá MỚI trước; trượt thì đọc khoá CŨ theo host, và nếu khoá cũ có
-- thì GHI SANG dạng mới. Hai dạng cùng sống một chu kỳ 30 ngày rồi khoá cũ tự
-- hết hạn. Không có lệnh di trú nào phải chạy tay, và không có thời điểm nào cả
-- hai đều trống trong khi trước đó một cái có.
--
-- `docroot` có thể nil (người gọi không có runtime, hoặc biến rỗng). Khi đó chỉ
-- còn đường khoá cũ — suy giảm về hành vi bản trước chứ không phải mất cổng.
--
-- Ghi sang dạng mới phải qua TIMER: hàm này chạy ở access phase (được), nhưng
-- `check()` cũng được gọi ở đó và `pool.safe_set` là cosocket — ở access phase
-- cosocket chạy được, nên KHÔNG cần timer. Khác `mark()` (log phase, cosocket bị
-- CẤM). Đây là lý do một phép ghi ở đây an toàn mà phép ghi trong `mark` thì
-- không, và lẫn hai thứ đó đã giết `wp_paths.mark()` bốn tháng.
-- ── LOI REDIS KHAC "KHONG CO KHOA", va truoc ban nay chung GIONG NHAU ──
--
-- `pool.safe_get` tra `(val, err)`. Ban truoc so `== "1"` roi BO gia tri thu hai,
-- nen Redis chet va khoa khong ton tai cho cung mot ket qua am — roi ket qua am
-- do duoc cache 300 giay. Hai hau qua nguoc nhau, ca hai deu xau:
--
--   Redis chet    -> moi cong tra am -> ba luat HARD-BLOCK im lang toan fleet
--                    trong 300s, va khong bao gi. Day la fail-open.
--   Khoa that su
--   khong co      -> dung la am, va cache am la dung.
--
-- Nay phan biet: loi thi tra `nil` (KHONG KET LUAN) va KHONG cache. Nguoi goi
-- doi `nil` thanh "khong bat luat" — giong `false` ve hanh vi chan, nhung KHAC o
-- cho no khong dong bang mot cau tra loi sai trong 300 giay.
--
-- Day la mot dang TRAN, khong phai diem am: "khong co bang chung thi khong bat
-- luat chan", thay vi "khong co bang chung thi coi nhu am". Giu bat bien 2 trong
-- so (chi ket luan khi DA CHUNG MINH).
local function redis_says_yes(key)
    local v, err = pool.safe_get(key)
    if v == "1" then return true end
    if err then return nil end          -- KHONG KET LUAN
    return false
end

local function is_wp_root(host, prefix, docroot)
    if not prefix then return false end

    local rid = root_id(docroot, prefix)

    -- ── Đường khoá MỚI: theo thư mục ──────────────────────────────────
    if rid then
        local ckr = cache_key_root(rid)
        if shared_cache then
            local v = shared_cache:get(ckr)
            if v ~= nil then return v == 1 end
        end
        local yes = redis_says_yes(redis_key_root(rid))
        if yes == true then
            if shared_cache then
                shared_cache:set(ckr, 1, WP_HOST_TTL_SHARED)
            end
            return true
        end
        -- Redis loi: KHONG hoi khoa cu (cung mot Redis, cung se loi), KHONG cache.
        if yes == nil then return nil end
        -- CHƯA cache kết quả âm ở đây: còn phải hỏi khoá cũ, và cache âm trước
        -- khi hỏi xong là tự tạo ra 300 giây trả lời sai trong lúc di trú.
    end

    -- ── Đường khoá CŨ: theo host. Chỉ trong thời gian di trú ───────────
    if not host or host == "" then
        if rid and shared_cache then
            shared_cache:set(cache_key_root(rid), 0, WP_HOST_TTL_SHARED)
        end
        return false
    end

    -- CHI DOC khong gian khoa cu, KHONG BAO GIO GHI vao no.
    --
    -- Ban dau cua toi cache ket qua cu vao `cache_key(host, ...)`, va bo test bat
    -- ngay: mot khoa `wphost:bot1.evil.test` van xuat hien trong `antibot_cache`.
    -- Tuc duong toi dang GO BO lai tu ghi them khoa mang ten Host — dung cai thu
    -- ma ca thay doi nay sinh ra de loai. No bi chan tren o MOT khoa cho moi thu
    -- muc (vi khoa am theo thu muc ngan mach ngay sau do), nhung "chi ro ri mot
    -- it" khong phai ly do de ro ri.
    --
    -- Bo cache shdict o day khong lam tang chi phi: khi khoa cu CO, ta nang ngay
    -- sang khoa moi va moi request sau di duong moi; khi khong co, khoa AM theo
    -- thu muc ngan mach. Ca hai huong deu chi tra gia mot lan cho moi thu muc.
    local hit = redis_says_yes(redis_key(host, prefix))
    if hit == nil then return nil end   -- loi: khong ket luan, khong cache

    -- Khoá cũ có thật ⇒ nâng sang dạng mới. Một lần cho mỗi thư mục, rồi mọi
    -- request sau đi đường mới.
    if hit and rid then
        pool.safe_set(redis_key_root(rid), "1", WP_HOST_TTL_REDIS)
        if shared_cache then
            shared_cache:set(cache_key_root(rid), 1, WP_HOST_TTL_SHARED)
        end
    elseif rid and shared_cache then
        -- Âm ở CẢ HAI không gian: giờ mới được cache âm, và cache theo THƯ MỤC.
        -- Đây là chỗ khoá rác theo Host biến mất: 243 Host trên 171-96 đi vào 79
        -- thư mục, nên số khoá âm bị chặn trên bởi 79 bất kể ai gửi Host gì.
        shared_cache:set(cache_key_root(rid), 0, WP_HOST_TTL_SHARED)
    end

    return hit
end

-- Export cho lớp khác: `waf/routes.lua` (roadmap mục 5) cần đúng cổng nhận CMS
-- này — "host này đã được chứng minh là WordPress bằng một file THẬT trên đĩa".
-- Hợp đồng endpoint của WordPress không được áp cho site không phải WordPress:
-- một site tự viết có quyền dùng `/wp-login.php` cho mục đích riêng.
--
-- Không viết lại phép kiểm đó ở `routes.lua`: nó có cache hai tầng (shared dict +
-- Redis) và nó chỉ được ghi ở log phase trên file thật — nhân đôi là mở đường cho
-- hai định nghĩa "là WordPress" lệch nhau.
_M.is_wp_root = is_wp_root

-- ── Khớp luật ────────────────────────────────────────────────────────
-- Trả về rule_id hoặc nil. Một request khớp nhiều nhất một luật: thứ tự dưới
-- đây đi từ hẹp tới rộng để luật cụ thể hơn thắng.
function _M.check(uri, host, docroot)
    if not uri or uri == "" then return nil end
    local low = uri:lower()

    -- ── CONG OVERLAY: mọi luật ở đây đòi host ĐÃ được chứng minh là WordPress ──
    --
    -- Trước bản này chỉ `wp_root_unknown` đi qua `is_wp_root`; ba luật HARD-BLOCK
    -- (`wp_upload_exec`, `wp_content_exec`, `wp_includes_exec`,
    -- `wp_admin_includes_exec`) thì không. Metadata `profile = "wordpress"` KHÔNG
    -- chứng minh gì — `config.lua` bật profile đó mặc định trên MỌI domain, nên nó
    -- chỉ là một công tắc tính năng.
    --
    -- Đây là bất đối xứng thật, và nó nằm sai hướng: chính ba luật CHẶN lại là
    -- những luật không cần bằng chứng, còn luật `signal` thì cần.
    --
    -- Tiền tố lấy từ `wp_prefix` (cùng hàm `needs_mark` dùng), nên `/en/wp-admin/`
    -- tra khoá `(host, "/en")` còn `/wp-admin/` tra `(host, "")`. Hai không gian
    -- khoá riêng — một `/en` có WordPress không mở cổng cho `/vi`.
    --
    -- ── CỬA SỔ COLD-START, và cách đóng nó ────────────────────────────────
    --
    -- `is_wp_root` học TỪ LƯU LƯỢNG (`mark` ở log phase, chỉ khi thấy file WP thật
    -- trên đĩa). Nên ngay sau khi gate, một host chưa có khoá thì ba luật block IM
    -- LẶNG cho tới request WordPress hợp lệ đầu tiên. `fim.sh wpinv` dựng sẵn danh
    -- sách đó TỪ ĐĨA (DirectAdmin `domains.list` + `.pointers` + `.subdomains`),
    -- và nó PHẢI được chạy trước khi bản này lên production.
    -- ── VÌ SAO GATE THEO NHÁNH, KHÔNG PHẢI MỘT LẦN Ở ĐẦU ──────────────────
    --
    -- Bản đầu của tôi đặt `wp_prefix(low)` ngay đây rồi `return nil` khi không có
    -- tiền tố. Sai, và bộ test bắt ngay 7 ca: `wp_prefix` chỉ học tiền tố từ ba
    -- marker (`/wp-content/`, `/wp-admin/`, `/wp-includes/`), nên `/shell.php` ở
    -- web root — chính ca của `wp_root_unknown` — không có marker nào và bị chặn ở
    -- cổng, tức MẤT HẲN một luật đang chạy thật.
    --
    -- Nên tiền tố suy theo NHÁNH: nhánh marker dùng `wp_prefix`, còn nhánh web
    -- root tự tách tiền tố của nó (nó đã làm việc đó và đã gọi `is_wp_root`).
    local function wp_gate()
        local prefix = wp_prefix(low)
        return prefix ~= nil and is_wp_root(host, prefix, docroot)
    end

    local wc = low:find("/wp-content/", 1, true)

    -- Không đánh dấu host ở đây nữa — `check()` chạy ở access phase và giờ CHỈ
    -- ĐỌC. Việc ghi chuyển sang `needs_mark`/`mark`, gọi từ `waf.run_log` ở log
    -- phase, nơi có thể chạm đĩa để xác minh. Lý do đầy đủ ở khối trên `needs_mark`.

    -- Không trỏ tới file PHP thì cả bốn luật đều không áp dụng. Đây là lối ra
    -- của tuyệt đại đa số request, và nó chỉ tốn một lượt regex.
    if not ngx.re.find(low, RX_PHP_EXEC, "jo") then return nil end

    -- Ba nhánh marker dưới đây đòi cổng overlay. `wp_root_unknown` ở cuối hàm có
    -- cổng RIÊNG của nó (nó tự tách tiền tố từ segment đầu), nên không gọi ở đây.
    if wc and not wp_gate() then return nil end
    if wc then
        local rest = low:sub(wc + 12)             -- 12 = #"/wp-content/"
        local sub  = rest:match("^([^/]+)/")

        if sub == "uploads" then return "wp_upload_exec" end
        if sub and not WP_CONTENT_OK[sub] then return "wp_content_exec" end
        -- PHP nằm ngay tại /wp-content/x.php (không có thư mục con):
        -- drop-in như advanced-cache.php chỉ được PHP `include`, không bao giờ
        -- được gọi thẳng qua HTTP. Gọi thẳng là dấu hiệu.
        if not sub then
            -- TRỪ index.php. WordPress core tự đặt một file rỗng
            -- `<?php // Silence is golden.` ở đây để chặn liệt kê thư mục, nên
            -- nó có trên MỌI cài đặt WP. Chặn nó vô hại về chức năng (file vốn
            -- trả rỗng) — cái mất là nó ĐẦU ĐỘC kênh cảnh báo `exists=1`, thứ
            -- chỉ có giá trị khi sạch. Đo 2026-09-02, ngày đầu có cột đó:
            -- 3 trong 4 dòng `exists=1` của luật này chính là file này
            -- (achauled.com, vietnampost.online).
            -- `/wp-content/index.php/x` vẫn bị bắt: khi đó `sub` không nil nên
            -- nhánh này không chạy tới.
            if rest == "index.php" then return nil end
            return "wp_content_exec"
        end

        -- Tới đây `sub` chắc chắn là themes|plugins|mu-plugins — mọi nhánh còn
        -- lại đều là luật `signal`. `index.php` ở các thư mục đó cũng là chốt
        -- chặn liệt kê thư mục của WordPress core, giống hệt cái ở wp-content.
        --
        -- Đo 2026-09-02: `/wp-content/themes/index.php` chiếm 17 trong 20 dòng
        -- `wp_theme_direct` có `exists=1`, trải trên 9 domain. Lần trước tôi vá
        -- đúng MỘT TÊN mà quên rằng WordPress rải file này vào mọi thư mục con.
        --
        -- ĐẶT SAU nhánh `uploads` là cố ý, không phải tiện tay: ở đó luật là
        -- `block` và `uploads/index.php` VẪN phải bị chặn. Miễn trừ nó là mở một
        -- lối vòng có sẵn tên gọi — kẻ tấn công chỉ cần đặt webshell tên
        -- `index.php`. Nhiễu ở nhánh block đáng trả giá; ở nhánh signal thì
        -- không. Đó là ranh giới, không phải thứ tự ngẫu nhiên.
        --
        -- CHỈ một cấp: `themes/twentytwentyone/index.php` là template của theme,
        -- gọi thẳng nó vẫn là dò tìm nên vẫn bắt.
        if rest == sub .. "/index.php" then return nil end

        if sub == "plugins"    then return "wp_plugin_direct"   end
        if sub == "mu-plugins" then return "wp_muplugin_direct" end
        if sub == "themes"     then return "wp_theme_direct"    end
        -- Không tới được với WP_CONTENT_OK hiện tại, nhưng giữ làm lối thoát an
        -- toàn nếu bảng đó được mở rộng mà quên thêm luật tương ứng.
        return nil
    end

    -- /wp-includes/ — thư viện core. Xem chú thích tại WP_INCLUDES_OK.
    local wi = low:find("/wp-includes/", 1, true)
    if wi then
        if not wp_gate() then return nil end
        local rest = low:sub(wi + 13)              -- 13 = #"/wp-includes/"
        if WP_INCLUDES_OK[rest] then return nil end
        return "wp_includes_exec"
    end

    -- /wp-admin/includes/ — cũng là thư viện thuần, chỉ được `require`.
    --
    -- CHỈ `includes/`, KHÔNG chặn cả `/wp-admin/*.php`. Danh sách endpoint hợp
    -- lệ ở đó dài và còn dài thêm (admin-ajax, admin-post, async-upload,
    -- load-scripts, load-styles, customize, media-upload, nav-menus…) — liệt kê
    -- nó là quay lại đúng cái bẫy mà đầu file này bác bỏ.
    if low:find("/wp-admin/includes/", 1, true) then
        if not wp_gate() then return nil end
        return "wp_admin_includes_exec"
    end

    -- Segment ĐẦU, không neo `$`. Bản cũ dùng `^/([^/]+)$` nên `/shell.php/x`
    -- ra nil và lọt sạch — đúng cái PATH_INFO mà lookahead `/` trong
    -- RX_PHP_EXEC dựng ra để bắt, rồi bị cái neo này vứt đi. Không phải giả
    -- thuyết: `/wp-content/plugins/us.php/` đã xuất hiện trong waf.log thật, nên
    -- kẻ tấn công trên máy này biết dùng PATH_INFO.
    --
    -- Phải kiểm đuôi PHP trên CHÍNH segment đó: guard phía trên chỉ bảo đảm URI
    -- có đuôi PHP ở đâu đó, nên `/foo/bar.php` vẫn phải ra nil (bar.php không ở
    -- web root). Và `/index.php/2020/01/bai-viet/` giữ nguyên hành vi cũ —
    -- permalink dạng PATHINFO của WordPress — vì index.php nằm trong WP_ROOT_OK.
    -- Tìm segment ĐẦU TIÊN có đuôi PHP. Phần đứng trước nó là tiền tố.
    --
    -- KHÔNG dùng `script_path` ở đây, dù nó cũng cắt PATH_INFO. Đã thử và đó là
    -- một lỗi hồi quy: `script_path("/wp-config.php.bak")` ra `/wp-config.php`,
    -- mà chuỗi đó NẰM TRONG `WP_ROOT_OK` ⇒ luật ngừng bắn cho đúng một mẫu dò
    -- lộ mật khẩu database. Hai phép cắt trông giống nhau nhưng khác bản chất:
    --   PATH_INFO  là ranh giới `/`      — phải cắt
    --   đuôi kép   nằm TRONG một segment — không được cắt
    -- `script_path` không phân biệt được, nên nó chỉ dùng cho việc TRA FILE TRÊN
    -- ĐĨA (khoá FIM, `target_exists`), không dùng cho việc KHỚP LUẬT.
    --
    -- Chỉ xét hai segment. Cận trên độ sâu không phải để tiết kiệm mà để chặn
    -- phình: tiền tố do người gửi request đặt, độ sâu tuỳ ý nghĩa là không gian
    -- khoá tuỳ ý. Ở đây nó rơi ra tự nhiên — không có nhánh nào cho segment 3.
    local seg1, rest = low:match("^/([^/]+)(.*)$")
    if not seg1 then return nil end

    local file, prefix
    if ngx.re.find(seg1, RX_PHP_EXEC, "jo") then
        -- `/shell.php` và `/shell.php/x` — gốc domain. `rest` bỏ qua, đó chính
        -- là cách PATH_INFO được xử lý đúng.
        file, prefix = seg1, ""
    else
        -- `/en/shell.php` — WordPress cài trong THƯ MỤC CON. Đo trên
        -- cloud168-101 (2026-09-02): 5 bản cài như vậy (`/en` ×4, `/id` ×1),
        -- không cái nào là subdomain. Trước thay đổi này chúng không sinh luật
        -- nào ⇒ `init.lua` không tra `waf:fimnew:` ⇒ FIM đã biết file vừa xuất
        -- hiện mà WAF không bao giờ hỏi. Nối lại đường dây đã có sẵn hai đầu.
        --
        -- `rest:match("^/([^/]+)")` KHÔNG neo `$` — nếu neo thì `/en/shell.php/x`
        -- trượt, tức mở lại lỗ PATH_INFO ở đúng tầng vừa thêm.
        local seg2 = rest:match("^/([^/]+)")
        if not seg2 or not ngx.re.find(seg2, RX_PHP_EXEC, "jo") then return nil end
        file, prefix = seg2, "/" .. seg1
    end

    if not WP_ROOT_OK[file] and is_wp_root(host, prefix, docroot) then
        return "wp_root_unknown"
    end

    return nil
end

return _M
