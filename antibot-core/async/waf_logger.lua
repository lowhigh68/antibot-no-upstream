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
    -- Bỏ mẫu ở đây an toàn với `arg_rule` vì mọi lượt CHẠM LUẬT đã có dòng
    -- `[waf]` riêng với `target=BODY`; dòng `[waf-body]` không phải nguồn duy
    -- nhất của chúng.
    --
    -- `fn_rule` thì KHÔNG như vậy, và đây là chỗ dễ hụt nhất: nó KHÔNG sinh
    -- dòng `[waf]` (nó là telemetry, không tạo `waf_hits`), nên dòng
    -- `[waf-body]` là nguồn DUY NHẤT của nó. Quên nó ở đây là vứt 19/20 lượt
    -- tấn công tên file — đúng kiểu lệch âm thầm mà cột `smp=` sinh ra để chặn.
    -- `fn_trunc` cung la notable: mot lan quet KHONG HOAN TAT la thong tin,
    -- va lay mau no di thi ty le "khong soi het" trong so lieu thap di 20 lan.
    local notable = b.php or b.arg_rule or b.fn_rule or b.fn_trunc or b.spill
    if not notable then
        body_seen = body_seen + 1
        if body_seen % BODY_SAMPLE ~= 0 then return end
    end

    local fh = io.open(WAF_LOG, "a")
    if not fh then return end   -- `run` da bao ERR neu mo that bai, khong lap lai

    fh:write(string.format(
        "[%s] [waf-body] ts=%d rid=%s id=%s domain=%s ip=%s method=%s uri=%s"
        .. " ct=%s cl=%s te=%s proto=%s blen=%d spill=%d php=%s nargs=%s"
        .. " class=%s richness=%s vfy=%d argrule=%s fnm=%s fnrule=%s fntr=%s smp=%d\n",
        os.date("%Y-%m-%d %H:%M:%S"),
        ngx.time(),
        req_id(),
        scrub(ctx.identity or ctx.fp_light, 64),
        scrub((ctx.req and ctx.req.host) or ngx.var.host, 80),
        scrub(ctx.ip or ngx.var.remote_addr, 45),
        scrub(ngx.req.get_method(), 10),
        scrub(ngx.var.uri, 120),
        b.family,
        -- BA COT NAY DI VOI NHAU. Mot minh khong cot nao tra loi duoc cau hoi
        -- dang chan viec dat `client_body_buffer_size`.
        --
        -- `cl=`  gia tri header Content-Length. `-` nghia la KHONG CO HEADER DO
        --        — chi vay thoi. DINH CHINH: ban truoc toi ghi `cl=- = chunked`.
        --        Sai, va sai theo huong lam hong chinh phep do: header nay con
        --        vang trong HTTP/2 (body di bang DATA frame), HTTP/3, request
        --        khong co body, va vai client khong gui. Dan may nay bat H2 va
        --        co han mot tang van tay H2 — neu phan lon POST la h2 khong kem
        --        Content-Length thi phep cheo "spill x cl" khong noi len gi.
        -- `te=`  co header `Transfer-Encoding: chunked` hay khong. Day moi la
        --        chunked THAT.
        -- `proto=` 1.1 / 2.0 / 3.0. Quyet dinh nginx doc body bang duong nao.
        --
        -- Cau hoi: nginx co BIET TRUOC do dai body khong. Biet thi no cap dung
        -- co va bo qua directive; khong biet thi roi ve buffer va spill.
        --   HTTP/1.1 + Content-Length      -> biet
        --   HTTP/1.1 + Transfer-Encoding   -> khong biet
        --   HTTP/2                         -> tuy client co gui Content-Length
        --
        -- Doc bang phep cheo o muc 8 cua `wafstat.sh`. Dung suy luan tu ma nguon
        -- nginx — kieu suy luan do da bi bac bo sau lan trong du an nay.
        ngx.var.http_content_length or "-",
        -- Header do CLIENT dat, co the chua khoang trang ("chunked, gzip") — phai
        -- scrub, neu khong mot dong log bi tach truong sai.
        scrub(ngx.var.http_transfer_encoding, 24),
        ((ngx.var.server_protocol or "-"):gsub("^HTTP/", "")),
        b.len,
        b.spill and 1 or 0,
        -- `-` chứ không phải `0` khi không đọc được body. "Chưa soi" khác hẳn
        -- "đã soi, sạch"; ghi `0` là biến một khoảng trống thành một âm tính,
        -- và mọi phép đếm về sau sẽ lệch mà log trông vẫn bình thường.
        (b.php == nil) and "-" or (b.php and "1" or "0"),
        b.nargs and tostring(b.nargs) or "-",
        ctx.req_class or "-",
        ctx.session_richness and string.format("%.2f", ctx.session_richness) or "-",
        -- Cung ly do voi cot `vfy=` ben dong `[waf]`: danh dau DONG THIEU DU
        -- LIEU. Mot POST co `php=1` nhung khong luat nao ban chi sinh dong
        -- `[waf-body]`, khong sinh dong `[waf]`. Neu client do co cookie
        -- verified thi no thoat truoc classifier va `session_richness`, nen
        -- `class=- richness=-` — trong y het truong hop khac. Thieu cot nay thi
        -- rieng nhom body khong biet vi sao khong co du lieu.
        ctx.verified and 1 or 0,
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
        -- Luat khop khi soi RIENG gia tri ten file, doc lap voi than.
        --
        -- KHAC `fnm` va tra loi mot cau khac han:
        --   `fnm`     vi tri cua lan khop TOAN THAN duoc chon. Le thuoc thu tu
        --             uu tien, nen KHONG dung de dem tan cong ten file.
        --   `fnrule`  ket qua chay luat len CHINH gia tri ten file. Day moi la
        --             con so dem duoc.
        -- `filename*=` duoc giai ma rieng (RFC 5987 dinh nghia la
        -- percent-encoding); `filename=` thi khong.
        b.fn_rule or "-",
        -- LY DO quet ten file khong hoan tat. Doc kem `fnrule=`:
        --     fntr=-     khong ap dung — request khong phai multipart
        --     fntr=0     da soi het MOI ten file, khong luat nao ban
        --     fntr=spill multipart nhung body ra file tam -> KHONG soi gi ca
        --     fntr=rx   mau khong bien dich duoc -> loi luc deploy, sua ngay
        --     fntr=len  mot ten file > 512 byte  -> hiem, tu no da dang ngo
        --     fntr=n    hon 32 phan              -> thuong la upload that
        --     fntr=stop dung lai vi DA TIM THAY  -> binh thuong, kem `fnrule=`
        -- `stop` ton tai de `fntr=0` chi con MOT nghia. Ham thoat ngay o luat
        -- dau tien, nen khong co no thi `fnrule=X fntr=0` doc thanh "da soi
        -- het" trong khi that ra cac ten file phia sau chua he duoc soi — va
        -- moi phep dem "bao nhieu lan quet hoan tat" deu lech.
        -- Ba gia tri rx/len/n deu la KHONG BIET, khong phai sach — gop lai la
        -- bien mot khoang trong thanh mot am tinh (cung nguyen tac da dung cho
        -- `php=-` va `exists=-`). Nhung chung doi ba viec khac han nhau, nen ghi
        -- co la dung nghia ma khong doc duoc. Nhoi 32 chuoi `filename=` gia vao
        -- noi dung file la mot duong ne tranh THAT, va cot nay lam no hien ra.
        (b.fn_trunc == nil) and "-" or (b.fn_trunc or "0"),
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
            .. " richness=%s wpauth=%d vfy=%d status=%d exists=%s final=%s fim=%s\n",
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
            -- Client co cookie `verified` con han hay khong.
            --
            -- Cot nay danh dau DONG THIEU DU LIEU, khong phai them mot dac
            -- diem. Tu `f69b896`, tin hieu WAF trong so 0 khong con pha
            -- fast-path — dung y do — nen mot client verified cham luat se
            -- THOAT NGAY sau `check_verified_cookie`, truoc ca classifier va
            -- `session_richness`. Dong log cua no ra `class=- richness=- final=-`.
            --
            -- Ba dau `-` do trong y het truong hop "khong biet vi ly do khac"
            -- (block o access phase, ban o cua). Gop chung lai thi so lieu bong
            -- cua nhom verified khong dung de mo phong "neu bat trong so thi
            -- chuyen gi xay ra" — ma do la muc dich duy nhat cua che do bong.
            --
            -- `vfy=1` + ba dau `-` = thieu vi thoat fast-path, DEM RIENG.
            -- `vfy=0` + ba dau `-` = thieu vi ly do khac.
            -- Khong bia ra gia tri, chi noi ro vi sao khong co.
            ctx.verified and 1 or 0,
            status,
            exists_for(h.target),
            final,
            fim))
    end

    fh:close()
end

return _M
