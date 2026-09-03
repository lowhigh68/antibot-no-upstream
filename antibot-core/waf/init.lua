local _M = {}
local wp_paths = require "antibot.waf.wp_paths"
local exposed  = require "antibot.waf.exposed"
local args     = require "antibot.waf.args"
local body     = require "antibot.waf.body"
local pool     = require "antibot.core.redis_pool"

-- Ghi mot lan cham luat vao ctx. Tach ra vi tu 2026-09-03 co HAI nguon doc lap:
-- luat duong dan (`uri`) va luat tham so (`args`).
local function add_hit(ctx, rule_id, rule, target, matched)
    ctx.waf_hits = ctx.waf_hits or {}
    ctx.waf_hits[#ctx.waf_hits + 1] = {
        rule    = rule_id,
        target  = target,
        matched = matched,
        action  = rule.action,
        score   = rule.score,
    }
end

-- Ghi mot lan cham luat THAM SO. Dung chung cho ARGS va BODY: cung bang luat,
-- cung tin hieu `ctx.waf_arg`, chi khac `target` va chuoi `matched`.
-- `rule_id` co the la nil (khong khop) — nhan luon o day cho hai noi goi gon.
local function record_arg_hit(ctx, rule_id, target, matched)
    if not rule_id then return end
    local rule = args.RULES[rule_id]
    if not rule then return end
    add_hit(ctx, rule_id, rule, target, matched)

    -- HAI tín hiệu riêng, không phải một. Query string và thân request có bản
    -- chất FP khác hẳn nhau (thân chứa nội dung người dùng soạn), nên phải hiệu
    -- chỉnh trọng số độc lập — cùng lý do đã tách `waf_arg` khỏi `waf_wp_path`.
    local field = (target == "BODY") and "waf_body_arg" or "waf_arg"
    if (ctx[field] or 0) < rule.score then
        ctx[field] = rule.score
    end
end

-- Tầng WAF. Khác mọi tầng khác ở MỘT điểm quyết định: nó chạy TRƯỚC các cửa
-- thoát tin cậy trong `init.lua`, không phải sau.
--
-- Vì sao. `init.lua:_M.run()` mở đầu bằng:
--
--     if check_verified_cookie(ctx) then return end        -- trước cả STEPS_COMMON
--     ...
--     if ctx.verified or ctx.whitelisted then return end
--
-- Cookie `antibot_fp` sống `cfg.ttl.verified` = 7200s. Với quản lý bot đó là
-- thiết kế đúng: giải PoW rồi thì đừng bắt giải lại. Với WAF thì đó là lỗ —
-- giải PoW một lần (`cfg.pow.difficulty = "000"`, trình duyệt xong trong vài
-- chục ms) là có HAI GIỜ upload webshell không bị soi một byte nào.
--
-- Antibot chấm điểm AI gửi request. WAF soi CÁI GÌ nằm trong request đó. Danh
-- tính đã xác minh không nói gì về nội dung, nên trần tin cậy không được phép
-- che tầng này. Đây là lý do `run_pre` tồn tại tách khỏi `STEPS_*`.
--
-- VỊ TRÍ THÔI CHƯA ĐỦ — và bản đầu của khối chú thích này đã nói quá. Đứng
-- trước cửa tin cậy chỉ cứu được nhánh BLOCK, nơi `run_pre` trả true rồi
-- `ngx.exit`. Luật `signal` trả FALSE, nên hai cửa thoát trong `antibot/init.lua`
-- nuốt luôn `ctx.waf_wp_path` trước khi `compute.lua` kịp đọc: tín hiệu vào
-- waf.log mà không tác động gì. Vì vậy hai cửa đó nay có thêm điều kiện
-- `not ctx.waf_wp_path`.
--
-- Đo 2026-09-02 TRƯỚC khi vá: 8.323 lượt signal, 0 lượt thật sự thoát qua
-- fast-path (chữ ký là `final=-` trong waf.log). Lỗ có thật trong mã nhưng chưa
-- ai đi qua. Vá vì nó rẻ và vì hợp đồng ghi ở đoạn trên phải đúng — không phải
-- vì đang chảy máu.
--
-- Đổi lại, tầng này phải RẺ và phải TỰ LO ctx: nó chạy trước `ctx_layer.init`
-- nên không có gì trong `ctx` ngoài những thứ tự nó điền.

function _M.run_pre(ctx)
    local uri = ngx.var.uri
    if not uri or uri == "" then return false end

    -- KHÔNG miễn loopback. Miễn trừ cũ không mua được gì: lưu lượng 127.0.0.1
    -- thật sự chỉ có wp-cron gọi `/wp-cron.php` (đã nằm trong WP_ROOT_OK nên
    -- không luật nào bắn) và health check gọi `/` (không phải PHP). Đổi lại nó
    -- mở đúng một đường: SSRF, hoặc PHP của tài khoản khác trên hosting chia sẻ
    -- curl về localhost — cả hai tới đây với `$remote_addr` = 127.0.0.1.
    --
    -- Giới hạn phải nói rõ: `curl 127.0.0.1:8080` đi THẲNG vào Apache, không
    -- qua OpenResty, nên tầng này không nhìn thấy. Bịt chỗ đó là việc của cấu
    -- hình Apache + open_basedir, không phải của Lua.
    local ip   = ngx.var.remote_addr or ""
    local host = ngx.var.host or "-"

    -- `exposed` chạy trước `wp_paths`: nó rộng hơn (mọi site, không cổng host)
    -- và rẻ hơn (không chạm Redis/shdict). Thứ tự này cũng cho kết quả TỐT HƠN
    -- ở chỗ chồng lấn: `/wp-config.php.bak` khớp cả `dump_exposed` (block) lẫn
    -- `wp_root_unknown` (signal 0.50) — nhãn đúng là cái chặn.
    local rule_id, rules = exposed.check(uri), exposed.RULES
    if not rule_id then
        rule_id, rules = wp_paths.check(uri, host), wp_paths.RULES
    end

    local rule = rule_id and rules[rule_id]

    -- BO DO BODY (giai doan 1 — chi quan sat, khong luat nao ban).
    --
    -- Chay cho MOI request co the soi duoc, TRU nhanh `block`: request do sap
    -- `ngx.exit(403)` o duoi nen doc body cua no la tra gia cho thu sap bi vut
    -- di, va no cung la nhanh ma scanner bam vao nhieu nhat.
    --
    -- Phai chay ca khi KHONG luat nao khop — do moi la ~99% luu luong, tuc la
    -- dung phan bo can do. Neu chi chay khi co luat khop thi bo do chi thay
    -- duoc lat cat da bi loc, va moi ket luan rut ra tu no deu lech.
    --
    -- `probe` tu gac lay: GET/HEAD thoat ngay o phep kiem method dau tien.
    if not (rule and rule.action == "block") then
        body.probe(ctx)

        -- LUAT THAM SO — doc lap voi luat duong dan, KHONG phai nhanh else.
        --
        -- Hai nguon bang chung ve HAI PHAN khac nhau cua cung mot request:
        -- `/index.php?f=../../wp-config.php` co duong dan hoan toan binh thuong
        -- va tai trong nam tron trong query string. Gop chung vao mot chuoi
        -- "khop nhieu nhat mot luat" se lam cai thu hai bien mat moi khi cai
        -- thu nhat da ban — ma mot request mang CA HAI thi dang ngo hon han.
        --
        -- `ngx.var.args` la nil voi gan het luu luong (request khong co query
        -- string), nen `args.check` thoat ngay o phep kiem dau. Khong I/O.
        -- `args.describe(qs)` CHỨ KHÔNG phải `qs`.
        --
        -- Query string chứa được credential sống: WordPress đặt lại mật khẩu là
        -- `/wp-login.php?action=rp&key=<token>&login=<user>`, cộng OAuth code,
        -- API key trong tích hợp cũ, signed URL, email. Ghi nguyên văn vào
        -- waf.log — file text, giữ 30 ngày — là làm rò chúng ra.
        --
        -- Lập luận cũ của tôi là "mật khẩu không đi qua URL". Đúng với mật khẩu,
        -- sai với token. Tôi che thân request rồi để ngỏ đúng chỗ tương đương.
        local qs = ngx.var.args
        if qs and qs ~= "" then
            record_arg_hit(ctx, args.check(qs), "ARGS", args.describe(qs))
        end

        -- Cùng ba luật đó, áp lên THÂN REQUEST. `body.probe` đã chạy ở trên và
        -- để kết quả trong `ctx.waf_body.arg_rule`.
        --
        -- `matched=` TUYỆT ĐỐI KHÔNG ĐƯỢC là nội dung thân request.
        --
        -- Một POST tới `/wp-login.php` chứa `pwd=<mật khẩu người dùng>`. Ghi
        -- thân request vào `matched=` là ghi mật khẩu của khách hàng ra
        -- `/var/log/antibot/waf.log` — một file text, quyền đọc rộng, giữ 30
        -- ngày. Với query string thì rủi ro đó không tồn tại (mật khẩu không đi
        -- qua URL), nên khác biệt này chỉ có ở đây và phải xử lý ngay tại đây.
        --
        -- Ghi một mô tả thay thế: kiểu nội dung + độ dài. Đủ để đối chiếu với
        -- dòng `[waf-body]` cùng `id=`+`ts=`, không lộ một byte nào.
        local b = ctx.waf_body
        if b and b.arg_rule then
            record_arg_hit(ctx, b.arg_rule, "BODY",
                           "<" .. b.family .. ":" .. b.len .. ">")
        end
    end

    if not rule then return false end

    add_hit(ctx, rule_id, rule, "URI", uri)

    if rule.action ~= "block" then
        local score = rule.score

        -- FIM xác nhận: đúng file này MỚI XUẤT HIỆN trên đĩa.
        --
        -- Đây là thứ ba luật `signal` đang thiếu, và là thứ duy nhất phân biệt
        -- được hai vật thể mà chúng đang gộp làm một:
        --   /wp-content/plugins/elementor-pro/elementor-pro.php  — plugin thật
        --   /wp-content/plugins/xx/shell.php                     — webshell
        -- Cùng luật, cùng 12,5 điểm. FIM biết cái nào vừa xuất hiện, WAF không.
        --
        -- NÂNG TÍN HIỆU chứ KHÔNG chặn. Đúng nguyên tắc đã ghi ở dưới: luật WAF
        -- đóng góp tín hiệu, `engine.lua` quyết cùng ba tầng tin cậy. Điều đó
        -- làm nó an toàn FP THEO CẤU TRÚC — chuyện quan trọng trên hosting chia
        -- sẻ, nơi khách hàng CÓ upload file PHP mới một cách hợp lệ: quản trị
        -- viên đăng nhập thật vẫn được `auth_session_cap` giữ ở monitor, còn
        -- scanner ẩn danh thì lên block. Không cần luật miễn trừ nào.
        --
        -- MỨC TIN CẬY THEO BẬC, không phải cờ bật/tắt. FIM ghi sẵn giá trị:
        --   1.0   file mới ở web root / mu-plugins, đến một mình
        --   0.75  plugin/theme mới đến một mình, hoặc mu-plugins trong một đợt
        --   0.35  plugin/theme trong một đợt cài hàng loạt
        -- Ngay cả 1.0 × trọng số 50 = 50 điểm vẫn dưới CHALLENGE(55) và
        -- BLOCK(80), nên FIM không bao giờ tự mình phán quyết được.
        --
        -- KHOÁ LÀ ĐƯỜNG DẪN FILE THẬT, không phải `<host>:<uri>`.
        -- `da_to_openresty.sh:271` cho subdomain một webroot dạng
        -- `<public_html>/<sub_name>`, nên `document_root .. uri` LUÔN bằng đúng
        -- đường dẫn trên đĩa — cho domain chính, subdomain, lẫn WordPress cài
        -- trong thư mục con. Domain pointer/alias cũng tự đúng vì chúng dùng
        -- chung docroot, không phải liệt kê ra.
        --
        -- Một lượt Redis GET cho mỗi lần luật bắn (~4.300/ngày), KHÔNG phải mỗi
        -- request. Cùng khuôn với `is_wp_root`.
        -- `script_path` cat PATH_INFO truoc khi ghep khoa. Thieu no thi
        -- `/shell.php/x` tra khoa `waf:fimnew:<root>/shell.php/x` trong khi FIM
        -- ghi `<root>/shell.php` — lech khoa, nen dung file FIM vua danh dau la
        -- MOI lai khong duoc nang tin hieu. Ly do day du o `wp_paths.script_path`.
        local root = ngx.var.document_root
        if root and root ~= "" then
            local b = tonumber(pool.safe_get(
                "waf:fimnew:" .. root .. wp_paths.script_path(uri)))
            if b and b > score then
                score = b
                ctx.waf_fim_new = b
            end
        end

        if (ctx.waf_wp_path or 0) < score then
            ctx.waf_wp_path = score
        end
        return false
    end

    -- `log_by_lua` chạy sau `ngx.exit`, nên phải đặt action/action_reason ở đây,
    -- nếu không antibot.log ra `reason=-`.
    ctx.action        = "block"
    ctx.action_reason = rule_id
    ctx.ip            = ctx.ip or ip
    ctx.req           = ctx.req or { uri = uri, host = host }

    -- ngx.ERR chứ không WARN: access phase, error_log per-domain ép mức `error`
    -- nên WARN bị lọc câm. Cùng lý do đã ghi trong wp_hardening.lua.
    ngx.log(ngx.ERR, "[waf] block rule=", rule_id,
            " ip=", ip, " host=", host, " uri=", uri:sub(1, 160))

    ngx.exit(403)
    return true
end

-- Đường dẫn được yêu cầu có phải thứ CÓ THẬT trên đĩa không.
--
-- Đây là cột duy nhất phân biệt được "đang dò tìm" với "đã có sẵn", sau khi hai
-- ứng viên trước đều hỏng khi đối chiếu lưu lượng thật (đo 2026-09-02):
--   `status` — trang PoW của chính antibot trả 200 (`challenge/init.lua:14`), và
--      WordPress rewrite mọi thứ về index.php nên soft-404 cũng 200. Đo được:
--      7/7 đường dẫn nghi vấn trả 200, 0/7 file tồn tại.
--   `bytes`  — soft-404 render nguyên theme, to hơn output của phần lớn webshell.
--
-- CHỈ gọi ở log phase. `io.open` là I/O chặn: ở access phase nó nằm trên đường
-- đi của mọi request, ở log phase nó chạy sau khi client đã nhận xong phản hồi.
-- Người gọi phải tự lọc để nó không chạy cho mọi request.
--
-- Quyền không phải trở ngại: nginx vốn đã đọc thẳng những thư mục này để phục vụ
-- file tĩnh (khối `static_fastpath` trong `da_to_openresty.sh`).
--
-- ĐÍNH CHÍNH (2026-09-02): trước đây khối này ghi PATH_INFO là "giới hạn đã
-- biết, chấp nhận". Sai — nó không phải giới hạn có thể chấp nhận, nó làm hỏng
-- đúng cột mà cả hàm này sinh ra để phục vụ. `/shell.php/x` trả `exists=0`
-- trong khi `shell.php` ĐANG NẰM TRÊN ĐĨA, tức đọc log sẽ kết luận "chỉ đang dò
-- tìm" cho một máy đã bị đặt webshell. Và `/wp-content/plugins/us.php/` đã xuất
-- hiện trong waf.log thật, nên đây là kỹ thuật đang được dùng chứ không phải
-- tình huống giả định. Nay cắt bằng `wp_paths.script_path`.
--
-- Một giới hạn CÒN LẠI, và cái này thì thật sự chấp nhận được:
--   Thư mục trả true (`fopen` thành công với thư mục trên glibc). Với cổng đánh
--   dấu WordPress thì đó lại đúng: `/wp-admin/` tồn tại nghĩa là host này là WP.
local function target_exists()
    local root = ngx.var.document_root
    local uri  = ngx.var.uri
    if not root or root == "" or not uri or uri == "" then return nil end

    -- `ngx.var.uri` đã được nginx chuẩn hoá và giải mã, `..` bị gỡ trước khi tới
    -- đây, nên phép nối chuỗi này không mở đường thoát thư mục.
    local fh = io.open(root .. wp_paths.script_path(uri), "r")
    if not fh then return false end
    fh:close()
    return true
end

-- Nửa log-phase của tầng WAF. Gọi TRƯỚC `waf_logger.run` trong `_M.log()`.
--
-- Gộp hai việc vào một hàm vì cả hai cần đúng một phép chạm đĩa: điền
-- `ctx.waf_target_exists` cho waf.log, và quyết định có đánh dấu host là
-- WordPress hay không.
function _M.run_log(ctx)
    if not ctx then return end

    -- CHỈ đếm lượt chạm luật ĐƯỜNG DẪN. Từ `9890ad6`, `ctx.waf_hits` còn chứa
    -- luật tham số (`target=ARGS`/`BODY`), mà với chúng thì `target_exists()`
    -- trả lời về đường dẫn — không phải mục tiêu của luật, và luôn `1` vì
    -- `io.open` trên thư mục `/` thành công trên glibc.
    --
    -- Nên đếm `#ctx.waf_hits > 0` là chạm đĩa cho một câu hỏi không ai hỏi, rồi
    -- ghi ra một con số sai. Bỏ cả hai.
    local uri_hit = false
    if ctx.waf_hits then
        for i = 1, #ctx.waf_hits do
            if ctx.waf_hits[i].target == "URI" then
                uri_hit = true
                break
            end
        end
    end

    local host = ngx.var.host
    -- `needs_mark` trả về TIỀN TỐ cần đánh dấu (chuỗi, có thể RỖNG) hoặc nil.
    -- Rỗng là gốc domain, `"/en"` là WordPress cài trong thư mục con. Vì chuỗi
    -- rỗng vẫn truthy trong Lua, `if wp` ở đây là đúng — nhưng phải so `~= nil`
    -- khi ý là "có giá trị", đừng đổi thành `wp ~= ""`.
    local wp   = wp_paths.needs_mark(ngx.var.uri, host)

    -- Lối ra của gần hết lưu lượng: không luật nào bắn, VÀ tiền tố này đã được
    -- đánh dấu (hoặc đường dẫn không phải của WordPress). Không chạm đĩa.
    if not uri_hit and wp == nil then return end

    local ex = target_exists()
    if uri_hit then ctx.waf_target_exists = ex end
    if wp ~= nil and ex == true then wp_paths.mark(host, wp) end
end

return _M
