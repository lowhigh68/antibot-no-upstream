local _M = {}

-- File RIÊNG, không nhập vào antibot.log.
--
-- Lý do: WAF là hạng mục sinh nhiều FP và phải soi log thường xuyên, trong khi
-- antibot.log ghi MỌI request. Trộn vào nhau thì mỗi lần dò một FP phải lọc qua
-- hàng trăm nghìn dòng không liên quan. Và `write_log_line` bên logger.lua
-- `io.open`/write/`close` cho TỪNG request — nối thêm chi tiết WAF vào đó là
-- bắt 99% lưu lượng không dính luật nào trả giá cho 1% dính.
--
-- Ghép dòng: dùng `rid=` (`$request_id` của nginx, 32 hex, duy nhất từng
-- request). Nó ghép chính xác `[waf]` với `[waf-body]`.
--
-- ĐÍNH CHÍNH: khối này trước đây bảo ghép bằng cặp `id=`+`ts=`. Cặp đó KHÔNG
-- duy nhất — `id` là `ctx.identity`, mà mọi request thoát sớm (block ở access
-- phase, cookie fast-path, ban ở cửa) đều có `id=-`, còn `ts` chỉ tới giây.
-- Trên máy 43 domain thì hàng chục request cùng mang `id=- ts=<cùng giây>`.
--
-- Nối ngược về `antibot.log` thì VẪN phải dùng `id=`+`ts=` vì file đó chưa có
-- `rid=`. Giới hạn đã biết, chưa sửa — thêm `rid` vào `logger.lua` là đổi định
-- dạng dòng mà mọi lệnh awk dùng suốt quá trình đo đều dựa vào.
--
-- Cùng mô hình tách error-log/audit-log của ModSecurity.
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

-- Dong DO BODY — nhan `[waf-body]`, KHAC nhan `[waf]` cua dong luat.
--
-- Tach nhan chu khong them cot vao dong luat, vi hai ly do:
--   1. Dong luat co 19 cot va moi lenh awk da dung suot qua trinh do dac deu
--      dua vao do. Them cot la lam hong chung mot cach im lang.
--   2. Dong nay ban cho MOI POST, dong kia chi ban khi co luat khop. Tron hai
--      dan so khac han nhau vao mot dinh dang la tu tao ra ket luan sai — dung
--      cai bay `status=` da mat mot buoi de go.
--
-- Loc rieng: `grep -F '[waf-body]' waf.log`
-- Định danh DUY NHẤT cho một request, để ghép dòng `[waf]` với `[waf-body]`.
--
-- Cặp `id=`+`ts=` KHÔNG đủ, và đó là lỗi trong chính hướng dẫn tôi viết ở đầu
-- file này: `id` là `ctx.identity`, mà mọi request thoát sớm (block ở access
-- phase, cookie fast-path, ban ở cửa) đều có `id=-`; còn `ts` chỉ tới giây.
-- Trên một máy 43 domain thì hàng chục request cùng mang `id=- ts=<cùng giây>`
-- — ghép theo cặp đó là ghép bừa.
--
-- `$request_id` của nginx là 32 ký tự hex sinh riêng cho từng request (có từ
-- nginx 1.11). Rẻ: một lượt đọc biến, không tính toán.
local function req_id()
    local rid = ngx.var.request_id
    if not rid or rid == "" then return "-" end
    return rid
end

-- Đếm per-worker để LẤY MẪU những dòng không có gì đáng chú ý. Không cần chính
-- xác tuyệt đối, không cần chia sẻ giữa worker — chỉ cần giảm đều.
local body_seen = 0
local BODY_SAMPLE = 20

function _M.run_body(ctx)
    if not ctx then return end
    local b = ctx.waf_body
    if not b then return end

    -- LẤY MẪU. `run_body` bắn cho MỌI POST/PUT/PATCH/DELETE có Content-Type, và
    -- mỗi lần là một bộ ba syscall `io.open`/write/`close`. Trên site
    -- WooCommerce hay REST API thì đó là lượng I/O thật, cho một bộ đo TẠM.
    --
    -- Nhưng KHÔNG lấy mẫu cái đáng chú ý: `php`, `arg_rule`, `spill` đều hiếm và
    -- đều là thứ ta dựng bộ đo này để đếm. Chỉ lấy mẫu phần còn lại — tức phần
    -- chỉ đóng góp vào PHÂN BỐ (`blen`), mà phân bố thì lấy mẫu không làm méo.
    --
    -- Bỏ mẫu ở đây an toàn vì mọi lượt CHẠM LUẬT đã có dòng `[waf]` riêng với
    -- `target=BODY`; dòng `[waf-body]` không phải nguồn duy nhất của chúng.
    local notable = b.php or b.arg_rule or b.spill
    if not notable then
        body_seen = body_seen + 1
        if body_seen % BODY_SAMPLE ~= 0 then return end
    end

    local fh = io.open(WAF_LOG, "a")
    if not fh then return end   -- `run` da bao ERR neu mo that bai, khong lap lai

    fh:write(string.format(
        "[%s] [waf-body] ts=%d rid=%s id=%s domain=%s ip=%s method=%s uri=%s"
        .. " ct=%s cl=%s blen=%d spill=%d php=%s nargs=%s class=%s richness=%s"
        .. " argrule=%s fnm=%s smp=%d\n",
        os.date("%Y-%m-%d %H:%M:%S"),
        ngx.time(),
        req_id(),
        scrub(ctx.identity or ctx.fp_light, 64),
        scrub((ctx.req and ctx.req.host) or ngx.var.host, 80),
        scrub(ctx.ip or ngx.var.remote_addr, 45),
        scrub(ngx.req.get_method(), 10),
        scrub(ngx.var.uri, 120),
        b.family,
        -- Content-Length CUA HEADER, khong phai do dai doc duoc. `-` = chunked
        -- (khong co header nay).
        --
        -- Cot nay ton tai de tra loi DUNG MOT cau, va la cau dang chan viec dat
        -- `client_body_buffer_size`: spill co tuong quan voi chunked khong.
        --
        -- Do 2026-09-05 khong khop voi mo hinh: spill 12,5% nhung co 12 body
        -- LON HON 64 KB (toi 80.649 byte) van doc duoc vao bo nho. Voi buffer
        -- mac dinh 16k thi nhom sau phai roi ra file tam het.
        --
        -- Gia thuyet CHUA KIEM: `ngx.req.read_body()` dat
        -- `r->request_body_in_single_buf`, nen voi request CO Content-Length
        -- nginx cap mot buffer vua co body va bo qua directive; chi request
        -- CHUNKED moi roi ve buffer do va moi spill. Neu dung thi
        -- `spill=1` phai gan nhu luon di kem `cl=-`.
        --
        -- Doc bang: dem chao (spill, cl co/khong) tren vai ngay. Dung suy luan
        -- tu ma nguon nginx — dung kieu do da bi bac bo sau lan trong du an nay.
        ngx.var.http_content_length or "-",
        b.len,
        b.spill and 1 or 0,
        -- `-` chứ không phải `0` khi không đọc được body. "Chưa soi" khác hẳn
        -- "đã soi, sạch"; ghi `0` là biến một khoảng trống thành một âm tính,
        -- và mọi phép đếm về sau sẽ lệch mà log trông vẫn bình thường.
        (b.php == nil) and "-" or (b.php and "1" or "0"),
        b.nargs and tostring(b.nargs) or "-",
        ctx.req_class or "-",
        ctx.session_richness and string.format("%.2f", ctx.session_richness) or "-",
        -- Luat tham so nao khop trong THAN request. Doi chieu voi dong `[waf]`
        -- cung `rid=` de biet cai do la than hay query string — dong `[waf]`
        -- phan biet bang cot `target=` (ARGS / BODY).
        b.arg_rule or "-",
        -- Lan khop nam trong `filename=` cua multipart (1) hay o noi dung khac
        -- (0); `-` khi khong ap dung — khong phai multipart, hoac khong luat
        -- nao ban. Cot PHAN TANG de doc phan bo, khong tac dong gi toi phan
        -- quyet. Doc cung `family=` va `richness=`: ten file la tan cong, noi
        -- dung bai viet la FP, va hai cai do phai tach duoc TRUOC khi tinh
        -- chuyen `waf_body_arg` len khoi trong so 0.
        (b.fnm == nil) and "-" or (b.fnm and "1" or "0"),
        -- HỆ SỐ NHÂN, không phải cờ. `smp=1` = dòng này luôn được ghi;
        -- `smp=20` = nó đại diện cho 20 request cùng loại.
        --
        -- Bắt buộc phải có: lấy mẫu mà không ghi tỉ lệ ra là làm cho mọi phép
        -- đếm về sau thấp đi 20 lần trong khi log trông vẫn bình thường — đúng
        -- kiểu lệch âm thầm đã mất một buổi để gỡ với cột `status=`.
        notable and 1 or BODY_SAMPLE))

    fh:close()
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

    -- Mã trạng thái phản hồi. ĐÍNH CHÍNH: khi thêm cột này tôi ghi rằng 200
    -- nghĩa là site đã bị chiếm. Sai, và sai hai lần — đo trên lưu lượng thật
    -- 2026-09-02, 7 đường dẫn nghi vấn trả 200 mà KHÔNG file nào tồn tại:
    --   · 3/7 là trang PoW của chính antibot (`challenge/init.lua:14` đặt 200).
    --   · 4/7 là WordPress: `.htaccess` chuẩn rewrite mọi đường dẫn không phải
    --     file thật về index.php, và theme trả 200 cho trang 404 đó. Nên trên
    --     WordPress, 200 là phản hồi MẶC ĐỊNH cho đường dẫn KHÔNG tồn tại.
    -- Giữ lại vì rẻ và vẫn hữu ích khi đọc cùng `final=`, nhưng thứ thật sự trả
    -- lời câu hỏi "dò tìm hay đã có sẵn" là `exists=`.
    local status = ngx.status or 0

    -- File đích có thật trên đĩa không, do `waf.run_log` điền. Đây mới là cột
    -- quyết định: `/wp-content/plugins/shell/about.php` với exists=1 nghĩa là
    -- file ĐANG NẰM ĐÓ, không phụ thuộc site trả mã gì.
    local ex     = ctx.waf_target_exists
    local exists = (ex == true and "1") or (ex == false and "0") or "-"

    -- CHỈ có nghĩa với luật ĐƯỜNG DẪN. `target_exists()` kiểm
    -- `document_root .. uri`, nên với một luật tham số (`target=ARGS`/`BODY`)
    -- nó trả lời về đường dẫn — thứ KHÔNG phải mục tiêu của luật đó.
    --
    -- Và nó trả lời SAI theo hướng tệ nhất: `/?f=../../wp-config.php` có
    -- `uri = "/"`, mà `io.open` trên một thư mục THÀNH CÔNG trên glibc ⇒ mọi
    -- lượt `arg_traversal` đều báo `exists=1`. Đọc log sẽ tưởng có file thật.
    --
    -- Cùng lỗi đã làm `/wp-config.php.txt` báo `exists=1` sáng 2026-09-03: một
    -- cột trả lời về một thứ khác với thứ đang được hỏi. Ghi `-` thay vì một
    -- con số sai — không biết thì nói không biết.
    local function exists_for(target)
        if target == "URI" then return exists end
        return "-"
    end

    -- Phán quyết THẬT của engine, khác với `action=` vốn chỉ là hành động mà
    -- LUẬT muốn (hằng số "signal"/"block" theo rule_id, không mang thông tin).
    -- Thiếu cột này thì không đọc được 200 kia là origin hay là trang challenge
    -- — đúng chỗ đã làm lạc hướng cả một buổi điều tra.
    local final  = ctx.action or "-"

    -- Muc tin cay FIM da nang tin hieu len, 0 = khong danh dau. `waf/scripts/
    -- fim.sh` ghi `waf:fimnew:<duong-dan-file-that>`, `waf/init.lua` doc bang
    -- `ngx.var.document_root .. uri`.
    --   1.00  file moi o web root / mu-plugins, den mot minh
    --   0.75  plugin/theme moi den mot minh
    --   0.35  plugin/theme trong mot dot cai hang loat
    -- Doc cung `exists=`: exists noi file CO tren dia, fim noi no MOI CO va
    -- CHAC bao nhieu — ba cau khac nhau.
    local fim = ctx.waf_fim_new and string.format("%.2f", ctx.waf_fim_new) or "0"

    for i = 1, #hits do
        local h = hits[i]
        fh:write(string.format(
            "[%s] [waf] ts=%d rid=%s id=%s domain=%s ip=%s rule=%s target=%s"
            .. " sev=%s pl=%d matched=%s score=%.2f action=%s class=%s"
            .. " richness=%s wpauth=%d status=%d exists=%s final=%s fim=%s\n",
            stamp,
            now,
            req_id(),
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
            wpauth,
            status,
            exists_for(h.target),
            final,
            fim))
    end

    fh:close()
end

return _M
