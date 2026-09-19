# waf/

Tầng WAF. **Soi CÁI GÌ nằm trong request**, khác với phần còn lại của antibot vốn chấm điểm **AI gửi request**.

Đó không phải cách nói cho hay — nó quyết định vị trí của tầng này trong pipeline, và là lý do tồn tại của mọi thứ dưới đây.

## Vì sao chạy TRƯỚC các cửa thoát tin cậy

`antibot/init.lua:_M.run()` mở đầu bằng cookie fast-path: `verified:<cookie> == "1"` → `return` ngay, trước cả `STEPS_COMMON`. Cookie sống `cfg.ttl.verified` = 7200s.

Với quản lý bot đó là thiết kế đúng — giải PoW rồi thì đừng bắt giải lại. Với WAF thì đó là lỗ: giải PoW **một lần** (`cfg.pow.difficulty = "000"`, trình duyệt xong trong vài chục ms) là có **hai giờ upload webshell không bị soi một byte nào**.

Danh tính đã xác minh không nói gì về nội dung. Nên `waf.run_pre` chạy ở **bước 0**, tách khỏi `STEPS_*`, trước mọi thứ.

**Vị trí thôi chưa đủ — bản đầu của chú thích này đã nói quá.** Đứng trước cửa tin cậy chỉ cứu được nhánh **block**, nơi `run_pre` trả `true` rồi `ngx.exit`. Luật `signal` trả **false**, nên hai cửa thoát trong `antibot/init.lua` nuốt luôn `ctx.waf_wp_path` trước khi `compute.lua` kịp đọc — tín hiệu vào `waf.log` mà không tác động gì. Vì vậy hai cửa đó nay mang thêm điều kiện `not ctx.waf_wp_path`:

```lua
if waf_layer.run_pre(ctx) then return end
local verified = check_verified_cookie(ctx)
if verified and not ctx.waf_wp_path then return end
...
if ctx.whitelisted then return end          -- KHÔNG có điều kiện waf
if ctx.verified and not ctx.waf_wp_path then return end
```

Tín hiệu WAF phá được `verified`, **không phá được `whitelisted`** — whitelist là quyết định tường minh của người vận hành, không phải suy đoán của máy.

Đo 2026-09-02 **trước** khi vá: 8.323 lượt signal, **0** lượt thật sự thoát qua fast-path (chữ ký là `final=-` trong waf.log). Lỗ có thật trong mã nhưng chưa ai đi qua. Vá vì nó rẻ và vì hợp đồng phải đúng — không phải vì đang chảy máu.

Đổi lại, tầng này phải **rẻ** và phải **tự lo ctx**: nó chạy trước `ctx_layer.init` nên trong `ctx` không có gì ngoài những thứ tự nó điền.

## Module

| File | Vai trò | Phase |
|---|---|---|
| `init.lua` | Điều phối. `run_pre` (access, chỉ đọc) → `run_log` (log, sở hữu `io.open` duy nhất và phép ghi WP-host duy nhất) | access + log |
| `exposed.lua` | 2 luật, cả hai `block`, **không riêng WordPress**: `dotfile_exposed`, `dump_exposed` | access |
| `wp_paths.lua` | 8 luật riêng WordPress: 4 `block`, 4 `signal`. Giữ luôn cổng `is_wp_host` | access + log |
| `args.lua` | 3 luật `signal` soi **query string**: `arg_traversal`, `arg_php_wrapper`, `arg_null_byte` | access |
| `upload.lua` | **P1** — 3 luật `signal` soi **TÊN FILE** upload: `upload_exec_ext`, `upload_exec_double`, `upload_config`. Lua thuần (chạy trong worker thread) | access |
| `body.lua` | **Giai đoạn 1 — chỉ quan sát, KHÔNG luật nào bắn.** Đọc body an toàn, điền `ctx.waf_body` | access |
| `scripts/fim.sh` | **Nửa ngoài-request của tầng này.** Cron, giám sát toàn vẹn file | ngoài request |
| `scripts/wp_paths_test.lua` + `run.sh` | 72 assertion. `deploy.sh` bước `[3b]` gác trên nó | build |
| `async/waf_logger.lua` *(ở `async/`)* | Ghi `/var/log/antibot/waf.log`. **Không** nối vào `antibot.log` | log |

### Thứ tự dispatch trong `init.lua`

`exposed` **trước** `wp_paths`. Nó rộng hơn (mọi site, không cổng host) và rẻ hơn (không chạm Redis/shdict). Thứ tự này còn cho kết quả **đúng hơn** ở chỗ chồng lấn: `/wp-config.php.bak` khớp cả `dump_exposed` (block) lẫn `wp_root_unknown` (signal 0.50) — nhãn đúng là cái chặn.

Một request khớp **nhiều nhất một luật**.

## Luật

### `exposed.lua` — 2 luật, đều `block`

| rule_id | Bắt gì | Ngoại lệ |
|---|---|---|
| `dotfile_exposed` | Bất kỳ thành phần đường dẫn nào bắt đầu bằng `.` (`.env`, `.git/`, `.htpasswd`) | **Bắt buộc** miễn `/.well-known/` — thiếu là gãy gia hạn ACME toàn dàn |
| `dump_exposed` | `.sql .wpress .bak .old .orig .save .swp .swo`, tuỳ chọn `.gz/.bz2/.xz` | Cố ý **không** bắt `.zip`/`.gz` đứng một mình — được phục vụ hợp lệ từ uploads |

`RX_DOTFILE = "(?:^|/)\\.[^/.]"` viết bằng chuỗi có nháy chứ **không** phải `[[...]]`: `[^/.]]]` sẽ đóng long bracket sớm.

### `wp_paths.lua` — 8 luật

| rule_id | action | score | Ghi chú |
|---|---|---|---|
| `wp_upload_exec` | block | — | PHP dưới `/wp-content/uploads/` |
| `wp_content_exec` | block | — | PHP dưới `/wp-content/` ngoài `themes\|plugins\|mu-plugins` |
| `wp_includes_exec` | block | — | Allowlist 2 mục: `js/tinymce/wp-tinymce.php`, `ms-files.php` |
| `wp_admin_includes_exec` | block | — | `/wp-admin/includes/` |
| `wp_root_unknown` | signal | 0.50 | **Cần host đã biết là WordPress** |
| `wp_muplugin_direct` | signal | 0.50 | 0.50 chứ không 0.25 như plugins: mu-plugin hợp lệ **không bao giờ** bị fetch qua HTTP |
| `wp_plugin_direct` | signal | 0.25 | Không ít plugin cũ vẫn tự gọi PHP của chính nó |
| `wp_theme_direct` | signal | 0.25 | |

**Thứ tự nhánh `wc` là chịu lực, đừng sắp lại.** Miễn `index.php` đặt **sau** các nhánh block, cố ý:

```lua
if sub == "uploads" then return "wp_upload_exec" end
if sub and not WP_CONTENT_OK[sub] then return "wp_content_exec" end
...
if rest == sub .. "/index.php" then return nil end   -- SAU, không phải trước
```

Miễn nó dưới `uploads/` là mở một đường thoát có tên: kẻ tấn công chỉ cần đặt tên webshell là `index.php`.

Đo được vì sao phải miễn: 17/20 lượt `wp_theme_direct exists=1` là `/wp-content/themes/index.php` — chốt chặn liệt kê thư mục mà WordPress đặt ở **mọi** thư mục con, không chỉ một.

### `args.lua` — 3 luật, soi THAM SỐ

Cho tới 2026-09-03, tầng này chỉ đọc `ngx.var.uri`. Mười luật, tất cả đều là luật đường dẫn. **Query string, thân request, header, cookie — không có gì cả.**

Đó là lỗ hổng lõi, vì trên WordPress hosting chia sẻ việc chiếm quyền thật sự hầu như luôn đi qua một **lỗ hổng plugin khai thác bằng tham số**. Đường dẫn của những request đó hoàn toàn bình thường — `/index.php`, `/wp-admin/admin-ajax.php` — tải trọng nằm trong query string.

| rule_id | score | Bắt gì |
|---|---|---|
| `arg_traversal` | 0.75 | `..` theo sau bằng `/` hoặc `\` — LFI / đọc file tuỳ ý |
| `arg_php_wrapper` | 1.00 | `php:// data:// expect:// phar:// zip:// file:// compress.*://` |
| `arg_null_byte` | 1.00 | `%00` hoặc byte NUL thật — cắt chuỗi để vượt kiểm đuôi file |

**Ba luật, không phải ba trăm.** Đây không phải CRS thu nhỏ. Ba mẫu này được chọn vì chúng gần như không có bản sao hợp lệ trong lưu lượng thật. Luật SQLi/XSS của CRS thì ngược lại — nổi tiếng bắn oan nội dung bài viết và ô tìm kiếm trên chính WordPress, và đó là thứ phải tránh trên dàn máy có hàng trăm khách hàng.

Ba chi tiết mẫu là chịu lực:

- `\.\.[/\\]` — **không** bắt `..` trần. `bao-cao..pdf`, `range=10..20`, `v=1.2..1.3` đều hợp lệ.
- Wrapper **bắt buộc có `://`**. Thiếu nó thì `data:image/png;base64,…` (dạng HTML hợp lệ) bị bắt oan. Và `?file=https://x` **không** khớp vì `file` phải dính liền `://`.
- Giải mã tối đa **3 mức** (gốc + 2 lần). `%2e%2e%2f` cần một lần, `%252e%252e%252f` cần hai. Bộ lọc chỉ nhìn chuỗi thô trượt cả hai; bộ lọc giải mã đúng một lần trượt cái thứ hai.

### `args.check(s, decode, binary)` — hai trục, không phải một

| Nguồn | `decode` | `binary` | Luật NUL |
|---|---|---|---|
| Query string | ✔ | ✘ | chạy |
| Body `urlencoded` | ✔ | ✘ | chạy |
| Body `json` / `xml` / `text` | ✘ | ✘ | chạy |
| Body `multipart` / `other` | ✘ | **✔** | **bỏ** |

`decode` trả lời *"chuỗi này có phải percent-encoding không"*; `binary` trả lời *"chuỗi này có phải byte nhị phân không"*. Hai câu độc lập, nên hai tham số.

**Chỉ mẫu BYTE THÔ bị tắt.** `RX_NUL_RAW` là `\x00` — một **byte**, mà mọi định dạng nhị phân chứa nó theo đúng đặc tả. `RX_NUL_ENC` là `%00` — **ba ký tự**, tức một mẫu **văn bản**: percent-encoding chỉ tồn tại ở chỗ có người gõ ra (query string, tên file trong header multipart, trường form dạng text). Nó **không** bị tắt, kể cả với thân nhị phân.

Bản đầu gộp hai mẫu làm một rồi tắt cả cụm. Rộng quá: `filename="shell.php%00.jpg"` là mẫu văn bản nằm ở **dòng header**, không phải trong nội dung file, và nó bị tắt theo. Xác suất ba byte `%`,`0`,`0` xuất hiện ngẫu nhiên trong 47 KB nhị phân là ~0,003 lần/file — cùng bậc với `../`, tức đo được chứ không phải nguồn nhiễu.
**`binary` sinh ra từ số liệu, không phải phỏng đoán.** Đo 2026-09-05 trên hai máy, ~10 giờ: **67/67** lượt `arg_null_byte` nằm trong **nội dung file upload** — cột `fnm` cho thấy **0/61** lượt multipart nằm trong `filename=`. Cụm kích thước 7,3 KB / 47 KB / 80 KB lặp lại trên 13 domain không liên quan: đó là ảnh và tài liệu của khách.

Lý do cấu trúc: lập luận gốc của luật NUL là *"byte NUL không bao giờ hợp lệ trong **tham số**"*. Đúng với query string và trường form. Với thân multipart thì sai hoàn toàn — một phần của thân **chính là nội dung file**, và mọi định dạng nhị phân (PNG, JPEG, PDF, ZIP) chứa byte NUL theo đúng đặc tả của nó. Luật không phát hiện tấn công; nó phát hiện *"vừa có người upload file"*. Ở trọng số 50 thì mỗi ảnh sản phẩm đều +50 điểm.

`arg_traversal` và `arg_php_wrapper` **vẫn chạy cho nhị phân**. Chúng là mẫu **văn bản**, không phải đặc điểm của định dạng nhị phân: xác suất `../` xuất hiện ngẫu nhiên trong 47 KB nhị phân là ~0,003 lần/file — dưới một lượt mỗi vài ngày trên dàn máy này. Đo được, không phải nguồn nhiễu.

> **Cảnh báo khi đọc số liệu cũ.** `check()` trả về **một** rule_id theo thứ tự NUL → wrapper → traversal. Nên con số *"0 lượt traversal/wrapper trên body"* đo được **trước** thay đổi này **không** chứng minh chúng sạch — chúng đang bị NUL che khuất. Phải đo lại body vài ngày rồi mới kết luận về hai luật kia.

**Bắn ĐỘC LẬP với luật đường dẫn**, không phải nhánh `else`. Hai nguồn bằng chứng về hai phần khác nhau của cùng một request; gộp vào chuỗi "khớp nhiều nhất một luật" sẽ làm cái thứ hai biến mất mỗi khi cái thứ nhất đã bắn. Một request mang **cả hai** thì hai tín hiệu cộng lại và mới vượt ngưỡng — đó chính là lý do phải tách.

Tín hiệu riêng `waf_arg`, **không** dùng chung `waf_wp_path`: hai họ luật có bản chất FP khác hẳn nhau (đường dẫn PHP lạ là chuyện site tự viết vẫn làm; `php://` trong tham số thì không), nên phải hiệu chỉnh riêng được. Thân request tách tiếp thành `waf_body_arg` — nó chứa **nội dung người dùng soạn**, dân số FP khác hẳn query string.

**Cả hai đang ở trọng số 0 — chế độ quan sát.** Và "quan sát" ở đây có nghĩa hẹp hơn nó nghe: tín hiệu trọng số 0 **không được có mặt trong `waf_signal()`** ở `antibot/init.lua`.

Vì sao ranh giới nằm đúng ở đó. `waf_signal()` quyết định tín hiệu nào đủ sức vô hiệu cookie fast-path. Bản `3a99bdc` để `waf_arg` trong danh sách đó, nên một client có cookie verified gửi `?f=../x` mất fast-path, chạy hết pipeline, rồi có thể bị một tín hiệu **khác** đưa lên challenge. `waf.log` ghi `rule=arg_traversal … final=challenge` và người đọc kết luận luật gây FP — trong khi nó cộng 0 điểm. Nhưng cũng không vô can: không có luật thì request đã `allow`. Luật đổi phán quyết qua đường **đổi luồng**, không qua điểm số — lệch âm thầm đúng trên cột `final=` vốn thêm vào để chống lệch.

`waf/scripts/contract_test.lua` kiểm **hai chiều** theo trọng số, nên danh sách trong `init.lua` không còn phải nhớ bằng tay:

| Trọng số trong `DEFAULT_WEIGHTS` | Bắt buộc |
|---|---|
| `> 0` | **PHẢI** có trong `waf_signal()` — thiếu là tín hiệu bị nuốt im lặng với mọi client đã giải PoW |
| `== 0` | **KHÔNG ĐƯỢC** có trong `waf_signal()` — thừa là chế độ quan sát đang đổi luồng request |

Ngày nâng `waf_arg` lên khỏi 0: sửa `compute.lua`, chạy `[3b]`, cổng sẽ nói phải thêm gì vào `waf_signal()`.

Cả ba là `signal`. Ngay cả 1.00 × 50 = 50 điểm vẫn dưới CHALLENGE(55) — **không luật nào tự mình phán quyết được**. Nâng lên `block` hay không là việc của số liệu sau vài ngày đọc `waf.log`, không phải của trực giác.

### Giới hạn đã biết của luật tham số — đo được, KHÔNG vá bằng thêm mẫu

Ghi ra để không ai tưởng tầng này phủ nhiều hơn thực tế:

| Lọt gì | Vì sao không đuổi theo |
|---|---|
| JSON escape `<?php` | Mỗi lược đồ mã hoá là một bộ giải mã mới. Đó là con đường dẫn thẳng tới bộ luật CRS mà tầng này **cố ý** không đi |
| Body nén (`Content-Encoding: gzip`) | Phải giải nén trong access phase — CPU và bộ nhớ do người gửi điều khiển |
| Body vượt `client_body_buffer_size` | Ghi ra file tạm, đọc là I/O chặn. Ghi nhận `spill=1` chứ không đoán |
| Header, cookie | Chưa có số liệu nào về nội dung header trên dàn máy này. `../` trong `Referer` có thể hợp lệ — cần bộ ràng buộc khác, không chuyển thẳng ba mẫu này sang được |

**Nguyên tắc đằng sau bảng này:** một tầng bắt được payload ngây thơ mà **không bắn oan** có giá trị hơn một tầng cố phủ 100% rồi chặn khách hàng thật. Phần còn lại là việc của `fim.sh` (thấy file sau khi đáp xuống) và các tầng chấm điểm.

### `decode` — và vì sao nó là chuyện đúng/sai, không phải chuyện nhanh/chậm

`args.check(s, decode)` giải mã tối đa 3 mức, nhưng **chỉ với nội dung percent-encoded**. Query string luôn bật; thân request chỉ bật khi `family == "urlencoded"`.

Multipart là byte thô kèm boundary, JSON dùng `\uXXXX`. Giải mã chúng là **diễn giải sai bản chất dữ liệu**, và nó **tự tạo dương tính giả**: một file `.txt` được upload có chứa đúng chuỗi ký tự `%2e%2e%2f` sẽ biến thành `../` sau một lần unescape rồi bắn — một FP không hề có trong dữ liệu gốc.

Tiện thể: giảm từ tối đa 9 lượt regex + 2 lần cấp phát chuỗi 64k xuống 3 lượt regex + 0 cấp phát cho nhóm multipart/json/binary.

### Cổng `is_wp_host`

`wp_root_unknown` chỉ có nghĩa khi web root có danh sách file cố định — tức WordPress. Trên hosting chia sẻ có cả site tự viết (đo: cloud183-139, 366k request/ngày), PHP tuỳ ý ở root là **bình thường**; bắn tín hiệu cho mọi request như vậy là chế ra một cỗ máy FP.

Đánh dấu chạy ở **log phase** (`waf.run_log`) và **chỉ khi** đường dẫn WP là **file có thật trên đĩa**.

Bản đầu đánh dấu theo URI ở access phase và **đầu độc được**: một `GET /wp-admin/` đặt cờ 30 ngày cho bất kỳ host nào, kể cả qua `Host` header giả — ghi Redis không giới hạn + đẩy LRU trên `antibot_cache` dùng chung.

| Khoá | Nơi | TTL |
|---|---|---|
| `wphost:<host>` | shdict `antibot_cache` | 300s (cả dương lẫn âm) |
| `waf:wphost:<host>` | Redis | 30 ngày, làm mới mỗi lần thấy |

Giá trị **âm** được cache nhưng `needs_mark` **không** chặn trên nó — nhờ vậy host mới cài WordPress vẫn tự được nhận ra thay vì kẹt ở kết quả âm cũ.

## Log phase CẤM cosocket — và điều đó đã giết việc đánh dấu trong 4 tháng

`waf.run_log` chạy ở `log_by_lua`, nơi OpenResty **cấm cosocket**. `pool.safe_set` dùng `resty.redis`, tức cosocket, nên **mọi phép ghi Redis trực tiếp trong `run_log` đều thất bại** — và vì là `safe_*` nên thất bại **hoàn toàn im lặng**.

**Đo trên aramex.vn 2026-09-03 00:12**, một request `/en/wp-includes/js/jquery/jquery.min.js`:

```
[wafdbg] uri=/en/wp-includes/js/... host=aramex.vn wp=/en hit=nil shd=1
redis-cli --scan 'waf:wproot:*'   →  TRỐNG
```

`shd=1` chứng minh `mark()` chạy tới nơi và shdict ghi được (bộ nhớ chia sẻ, không phải cosocket). Redis thì không nhận gì.

**Vì sao không ai thấy trong bốn tháng.** `d3bfd04` chuyển việc đánh dấu từ access phase sang log phase để có quyền chạm đĩa, và mang theo một phép ghi Redis không chạy được ở đó. Nhưng `waf:wphost:*` có TTL **30 ngày** và đã được ghi từ **trước** lần chuyển đó — khoá cũ còn sống nên cơ chế trông vẫn chạy trong khi đã chết hẳn.

> Một bộ đệm sống lâu hơn thứ sinh ra nó thì che được đúng cái chết của nó.

**Quy tắc rút ra, áp cho mọi thứ viết thêm vào `run_log`:** bất kỳ phép chạm Redis nào ở log phase **phải** đi qua `ngx.timer.at(0, …)` — cùng khuôn `async/risk_update.lua` đã dùng. `io.open` thì ngược lại, chạy thẳng được; đó là lý do `target_exists()` không cần timer.

**Và thứ tự ghi phải là Redis trước, bộ đệm sau.** Bản cũ ghi shdict trước rồi mới ghi Redis, nên bộ đệm tuyên bố "xong rồi" trước khi biết việc có xong không — mỗi lần hỏng là 300 giây không thử lại. Nay chỉ ghi shdict TTL đầy đủ **bên trong** callback, sau khi `safe_set` trả `true`. Một chốt tạm 10 giây ghi ngay để 20 asset của cùng một trang không cùng tạo 20 timer (`lua_max_running_timers` mặc định 256).

Bộ đệm chỉ được phép nhớ một sự thật **đã** xảy ra.

## `run_log` — nửa log-phase

Gộp hai việc vào một hàm vì cả hai cần **đúng một** phép chạm đĩa: điền `ctx.waf_target_exists` cho waf.log, và quyết định có đánh dấu host là WordPress không.

```lua
if not hit and not wp then return end     -- lối ra của gần hết lưu lượng
local ex = target_exists()
if hit then ctx.waf_target_exists = ex end
if wp and ex == true then wp_paths.mark(host) end
```

`target_exists()` = `io.open(ngx.var.document_root .. ngx.var.uri)`. **Chỉ gọi ở log phase** — `io.open` là I/O chặn; ở access phase nó nằm trên đường đi của mọi request.

Hai giới hạn đã biết, **chấp nhận** thay vì viết thêm mã:
- PATH_INFO `/shell.php/x` trả `false` dù `shell.php` có thật.
- Thư mục trả `true` (`fopen` thành công với thư mục trên glibc). Với cổng đánh dấu WordPress thì đó lại **đúng**: `/wp-admin/` tồn tại nghĩa là host này là WP.

## FIM — nửa ngoài-request

`scripts/fim.sh` tồn tại vì một WAF theo URI **không thể** nhìn thấy ba đường vào phổ biến nhất:

1. **mu-plugins tự chạy** — WordPress `include` **mọi** `.php` ở đó trên **mọi** request. Không có request nào để chặn.
2. **LFI / `include()`** — đường dẫn không xuất hiện trong URI.
3. **cron / CLI / gõ thẳng `127.0.0.1:8080`** — không đi qua OpenResty.

Cộng thêm một cái thứ tư mà chỉ FIM thấy: **dòng chèn vào file core có sẵn**. Backdoor thật hiếm khi là file mới — nó sửa `wp-includes/functions.php`, rồi chạy trên mọi request mà không có URI nào để chặn.

### Hai tầng, và tiêu chí chọn

Tiêu chí **không phải** là rẻ, mà là: **WAF có thấy được không.**

| Tầng | Phạm vi | Đo trên cloud168-101 (2026-09-02) | Cron |
|---|---|---|---|
| nóng (`--hot`) | Chạy được **không cần một HTTP request nào** | 15.770 file / **0,474s** | `*/5` |
| đầy | Tất cả | 317.343 file / **27s** | `17 3 * * *` |

Tầng nóng gồm: web root, `wp-content/` độ sâu 1 (drop-in: `advanced-cache.php`, `object-cache.php`, `db.php`, `sunrise.php`), `mu-plugins/`, WordPress trong thư mục con — **và**, do glob `$ROOTS/*`, cả `wp-includes/` + `wp-admin/` độ sâu 1, chiếm **93,7%** số file.

**Đừng cắt `$ROOTS/*` dù nó trông như nhiễu.** Lý do giữ y hệt lý do mu-plugins có mặt: `wp-includes/*.php` độ sâu 1 là những file core `require` lúc khởi động. Luật `wp_includes_exec` chặn việc **gõ thẳng** `/wp-includes/xxx.php` — chuyện khác hẳn. Chính người viết dòng này đã suýt cắt nhầm ở lần review đầu.

`uploads/` **cố ý** không ở tầng nóng: webshell trong đó phải có HTTP request mới chạy, và `wp_upload_exec` chặn thẳng. Tầng đầy vẫn phủ.

**Giới hạn đã biết:** `-maxdepth 1` nên file core độ sâu 2+ (`wp-includes/rest-api/`, `blocks/`) không ở tầng nóng dù cũng được require — tầng đầy phủ, một ngày một lần.

### Đường phản hồi vào WAF

FIM **nâng tín hiệu, không chặn**:

```
fim.sh → SETEX waf:fimnew:<đường-dẫn-file-thật> 604800 <boost>
       → waf/init.lua đọc bằng ngx.var.document_root .. uri
       → nâng score của luật signal 0.25/0.50 lên tới boost
```

| boost | Trường hợp |
|---|---|
| 1.00 | File mới ở web root / mu-plugins, đến **một mình** |
| 0.75 | plugin/theme mới đến một mình, hoặc mu-plugins trong một đợt |
| 0.35 | plugin/theme trong một **đợt cài hàng loạt** (gom theo slug) |
| 0.50 | còn lại, trong đợt |

Ngay cả 1.00 × trọng số 50 = **50 điểm**, vẫn dưới CHALLENGE(55) và BLOCK(80). **FIM không bao giờ tự mình phán quyết được** — đúng nguyên tắc: luật WAF đóng góp tín hiệu, `engine.lua` quyết cùng ba tầng tin cậy. Điều đó làm nó **an toàn FP theo cấu trúc** trên hosting chia sẻ, nơi khách hàng **có** upload PHP mới một cách hợp lệ: quản trị viên đăng nhập thật vẫn được `auth_session_cap` giữ ở monitor, còn scanner ẩn danh thì lên block. Không cần luật miễn trừ nào.

**Khoá là đường dẫn file thật, không phải `<host>:<uri>`.** `da_to_openresty.sh:271` cho subdomain một webroot dạng `<public_html>/<sub_name>`, nên `document_root .. uri` **luôn** bằng đúng đường dẫn trên đĩa — cho domain chính, subdomain, lẫn WordPress cài trong thư mục con. Domain pointer/alias tự đúng vì dùng chung docroot, không phải liệt kê ra. Cũng bỏ luôn được biến thể `www.`.

Gom theo **slug plugin/theme**, không theo thư mục cha: `GROUP_MAX` là ngưỡng **công khai**, gom theo thư mục thì kẻ tấn công chỉ cần thả 6 file rải vào các thư mục con là thoát sạch.

Một lượt Redis GET **cho mỗi lần luật bắn** (~4.300/ngày), không phải mỗi request.

### Vận hành FIM

```bash
fim.sh baseline [--hot]                 # manifest đầu tiên, không báo cáo gì
fim.sh check    [--hot] [--dry] [-v]
```

- Manifest **riêng cho từng tier** (`manifest.hot.txt` / `manifest.full.txt`). Bắt buộc: đối chiếu tập con với manifest đầy sẽ báo mọi file không được phủ là DEL, biến manifest đầy thành rác và nuốt mọi thay đổi về sau.
- Manifest ở `/var/lib/antibot/fim/`, **ngoài cây deploy** — `./deploy.sh` không đụng tới, không cần dựng lại baseline sau mỗi lần deploy.
- Im lặng khi không có gì (cron gửi mail theo **bất kỳ** dòng stdout nào). `-v` để ép in.
- Mã thoát 1 = có CRITICAL.

**Bốn cái bẫy đã cắn, ghi lại để không lặp** (chi tiết trong chú thích `fim.sh`):

1. `if ! flock -n 9` **không phân biệt** "khoá đang bị giữ" (exit 1) với "không có lệnh flock" (exit 127) — trên máy thiếu util-linux, FIM **không làm gì cả** và báo thành công, mãi mãi. Phải `command -v flock` riêng.
2. `$ROOTS` không nháy → glob không khớp thì bash để **nguyên chuỗi mẫu** → `find` trả 1 → `set -o pipefail` giết cả pipeline. Mọi `find` phải có `|| :`. **Không** dùng `shopt -s nullglob` thay thế: glob rỗng làm `find` chạy không tham số, tức quét **thư mục hiện tại**.
3. Vì (2) gỡ mất chỗ chặn tình cờ của `pipefail`, phải có **chốt an toàn tường minh**: quét ra 0 file → `baseline` từ chối ghi manifest, `check` từ chối coi là xoá hàng loạt. Thiếu nó: quét rỗng → awk in DEL cho cả 317k đường dẫn → `cp` ghi đè manifest rỗng → lần sau 317k NEW → **đẩy mọi file PHP trên máy thành khoá `waf:fimnew:`**. Chỉ chặn trường hợp **0** — xoá một domain thật có thể làm biến mất hàng nghìn file, nên ngưỡng theo tỷ lệ sẽ chặn cả thao tác hợp lệ.
4. Vòng xác minh Redis so với **giá trị đã ghi** (`$4` của chính dòng SETEX), không phải hằng số `"1"`. Bản `a253016` ghi literal `1` nên `!= "1"` từng đúng; đổi sang boost theo bậc mà quên sửa phép so sánh thì cảnh báo **luôn sáng** — mà một cảnh báo luôn sáng là một cảnh báo dạy người vận hành bỏ qua nó.

**Không** dùng vòng `while read` gọi `classify`/`dirname` cho từng dòng: một bản cập nhật core 2.000 file sẽ sinh 4.000 tiến trình con. Đã trả giá một lần (script khảo sát chạy 11 phút 21 giây). Một lượt awk.

## `body.lua` — bộ đo body (giai đoạn 1)

**Không luật nào bắn.** Module này chỉ ghi lại **cái gì có trong body** rồi thôi.

Lý do là kỷ luật, không phải sự thận trọng suông: trong phiên xây tầng này, **sáu giả thuyết liên tiếp bị số liệu thật bác bỏ** — file mu-plugins "backdoor" hoá ra là bản vá của agency SEO, "`status=200` nghĩa là đã bị chiếm" sai hai lần, "công cụ quản trị WP tập trung" bị chính output bác bỏ. Viết luật body khi chưa biết body trên dàn máy này chứa gì là lặp lại đúng sai lầm đó, chỉ khác là hậu quả rơi vào 43 domain thật.

### Cái giá thực sự bằng KHÔNG

`ngx.req.read_body()` nghe thì đắt, thực tế không thêm gì: **`proxy_request_buffering` không được đặt trong repo ⇒ mặc định `on` ⇒ nginx vốn đã đọc và đệm trọn body trước khi gửi lên Apache.** Đọc nó ở access phase chỉ là nhìn vào thứ đã nằm sẵn trong bộ nhớ.

`proxy_buffering off` trong `da_to_openresty.sh` là đệm **phản hồi** — directive khác, đọc nhầm thì kết luận ngược.

### Cổng lọc

```
method ∈ {POST, PUT, PATCH, DELETE}   ← GET/HEAD thoát ngay, không I/O
        AND có Content-Type
```

**Cổng là `Content-Type`, tuyệt đối không phải `Content-Length`.** Đo 2026-09-02: **387 POST multipart trong 24h báo `cl=0`** — chunked transfer-encoding thì không có Content-Length. Gác bằng `cl > 0` sẽ bỏ qua đúng nhóm đáng quan tâm nhất (upload file), và bỏ qua **trong im lặng**.

Gọi từ `run_pre` **sau** phép khớp luật đường dẫn và **bỏ qua nhánh `block`** — request đó sắp `ngx.exit(403)`, đọc body của nó là trả giá cho thứ sắp bị vứt đi. Nhưng vẫn chạy khi **không luật nào khớp**, vì đó mới là ~99% lưu lượng, tức đúng phân bố cần đo.

### `ctx.waf_body`

| Trường | Nghĩa |
|---|---|
| `family` | `urlencoded` / `multipart` / `json` / `xml` / `text` / `other` |
| `len` | Số byte, hoặc **`-1`** nếu spill |
| `spill` | Body vượt `client_body_buffer_size` → nginx ghi ra file tạm, `get_body_data()` trả `nil` |
| `php` | Có thẻ mở PHP không (`<?php` / `<?=`, không phân biệt hoa thường) |
| `nargs` | Số tham số, **chỉ với `urlencoded`**; `nil` cho phần còn lại |

**Không đọc file tạm ở access phase.** `io.open` là I/O chặn nằm trên đường đi của mọi request — đúng điều luật repo cấm. Ghi nhận `spill` rồi đi tiếp; chính con số đó quyết định `client_body_buffer_size` nên đặt bao nhiêu, **không cần viết thêm mã**.

**Đếm `&` chứ không gọi `get_post_args()`** — cùng ba lý do đã ghi ở `async/logger.lua:414`: hàm đó **cắt ở 100 và không báo gì** (mà 500 tham số mới là trường hợp đáng ngờ nhất), nó cấp phát một bảng Lua mỗi request, và đây là access phase.

**`<?xml` KHÔNG tính là PHP.** Bắt `<?` trần sẽ biến mọi upload SVG, mọi feed RSS, mọi SOAP envelope thành dương tính — chế ra một cỗ máy FP đúng lúc đang cố đo xem FP nằm ở đâu.

### `client_body_buffer_size 64k`

Mặc định nginx là 8k/16k, nghĩa là **hôm nay** body 16k–64k đã bị ghi ra đĩa rồi mới đọc lại. Nâng lên 64k **giảm** một vòng ghi-đọc đĩa cho nhóm đó, kể cả khi không ai soi. Bộ đệm cấp cho **từng request có body và chỉ trong lúc đọc**, không cấp trước theo `worker_connections`.

**ĐÃ CÓ SỐ, 09-09.** `wafstat.sh` mục 8 trên 5 máy (23,5 giờ, ~100.000 POST): **mọi** lượt spill đều có `Content-Length`, và **368 request chunked không spill lần nào**. Giả thuyết ghi trong `nginx.conf` — "chỉ request KHÔNG có Content-Length mới rơi về buffer" — **ngược hẳn**. Ngưỡng thật là **8K**, không phải 16k: trên cloud186-126 và cloud183-139 số spill khớp chính xác tổng ba nhóm ≥8K (101 = 18+38+45 và 14 = 2+10+2). Directive đã bật lại; nó xử lý dải 8k–64k = **1.115/1.215 lượt spill mỗi ngày** toàn đàn máy. Phần >64k (239 lượt) vẫn spill và đó là đúng — body lớn nhất đọc được là 3,5 MB.

## waf.log

File **riêng**, không nhập vào `antibot.log`. Nối ngược bằng cặp `id=` + `ts=`.

Lý do: WAF sinh nhiều FP và phải soi log thường xuyên, trong khi `antibot.log` ghi **mọi** request — trộn vào nhau thì mỗi lần dò một FP phải lọc qua hàng trăm nghìn dòng không liên quan. Và `write_log_line` bên `logger.lua` `io.open`/write/`close` cho **từng** request; nối thêm chi tiết WAF vào đó là bắt 99% lưu lượng không dính luật nào trả giá cho 1% dính. Cùng mô hình tách error-log/audit-log của ModSecurity.

`waf_logger.ensure()` tạo sẵn file rỗng lúc `init_worker`. Khác `antibot.log` ở một điểm quyết định: `logger.run()` chạy cho mọi request nên `antibot.log` tái sinh sau vài ms — vắng mặt nó là chẩn đoán rõ ràng. `waf_logger.run()` thoát sớm khi không luật nào bắn, nên thiếu `ensure()` thì sau deploy `waf.log` **không tồn tại**, và người vận hành không phân biệt được "chưa có tấn công nào" với "module hỏng / sai quyền thư mục".

Hai loại dòng, **nhãn khác nhau**:

| Nhãn | Bắn khi | Dân số |
|---|---|---|
| `[waf]` | Có luật khớp | ~4.300/ngày |
| `[waf-body]` | Mọi POST soi được | mọi POST |

Tách nhãn chứ **không** thêm cột vào dòng luật: dòng `[waf]` có 19 cột và mọi lệnh awk dùng suốt quá trình đo đều dựa vào đó — thêm cột là làm hỏng chúng trong im lặng. Và trộn hai dân số khác hẳn nhau vào một định dạng là tự tạo ra kết luận sai, đúng cái bẫy `status=` đã mất một buổi để gỡ.

```bash
grep -F '[waf-body]' /var/log/antibot/waf.log
```

**`[waf-body]` được LẤY MẪU.** Dòng "đáng chú ý" (`php`, `argrule`, `spill`) luôn ghi; phần còn lại chỉ ghi 1/20. Cột `smp=` là **hệ số nhân** (1 hoặc 20) — nhân lên trước khi kết luận bất cứ điều gì về số lượng. Hệ quả cho người vận hành: **một POST bình thường gửi thử có 95% khả năng không xuất hiện**, nên phép thử khói phải dùng body *đáng chú ý*:

```bash
curl -s -X POST -d 'x=<?php' https://<host>/ -o /dev/null   # ép một dòng [waf-body]
curl -s 'https://<host>/?f=../x' -o /dev/null               # ép một dòng [waf] target=ARGS
```

**`fnm=` là cột phân tầng, không phải luật.** Trên thân multipart, `argrule` đang gộp hai dân số ngược nhau: `../` trong **tên file** (gần như chắc chắn là tấn công) và `../` trong **nội dung** file/bài viết (gần như chắc chắn là FP). `fnm=1` nghĩa là chỗ khớp nằm cùng dòng với một `filename=` hoặc `filename*=`; `fnm=0` là nằm chỗ khác; `fnm=-` là không áp dụng.

> **Đính chính 2026-09-05 — đọc trước khi dùng con số này.** `fnm` mô tả **vị trí của lần khớp được chọn**, không phải *"request này có tấn công ở tên file hay không"*. `args.check` trả về **một** rule_id theo thứ tự NUL → wrapper → traversal rồi dừng. Một request vừa có `php://` trong **nội dung** file vừa có `../../shell.php` trong **tên file** sẽ cho wrapper thắng, `fnm=0`, dù tấn công ở tên file là có thật.
>
> Nên `fnm=0` đọc đúng là *"lần khớp được chọn nằm ngoài tên file"*. Tôi đã nói quá điều này khi báo cáo số liệu 05-09: đúng là **0/61 lần khớp được chọn** nằm trong tên file, còn *"không có tấn công tên file nào"* thì chưa bao giờ được chứng minh.

### `fn_rule` — soi RIÊNG tên file, độc lập với thân

`fnm` tái sử dụng **vị trí** của luật toàn thân, nên nó kéo theo hai khuyết tật của cách làm đó:

1. **Lệ thuộc thứ tự ưu tiên.** Một request vừa có `php://` trong nội dung file vừa có `../../shell.php` trong tên file sẽ cho wrapper thắng, `fnm=0`. Nên `fnm` **không** dùng để đếm tấn công tên file.
2. **Không soi được `filename*=`.** Thân multipart chạy `decode=false` (đúng — giải mã nội dung nhị phân tự tạo ra FP), nhưng giá trị `filename*=` theo RFC 5987 **là** percent-encoding. `filename*=UTF-8''..%2F..%2Fshell.php` lọt sạch.

`fn_rule` chạy `args.check` lên **chính giá trị tên file**, ghi ra cột `fnrule=`. Không dùng chung với `arg_rule`, không đặt tín hiệu nào trong ctx — vẫn là telemetry ở trọng số 0.

**Giải mã có phân biệt, và đây là chỗ chịu lực:**

| Dạng | Là gì | `decode` |
|---|---|---|
| `filename*=` | RFC 5987 định nghĩa **là** percent-encoding | **true** |
| `filename=` | Giá trị thô (UTF-8 hoặc RFC 2047) | **false** |

Giải mã bừa cả hai thì một file khách đặt tên `a..%2Fb.pdf` biến thành `a../b.pdf` và bắn — đúng dạng FP cả tầng này tránh. Cặp đối chứng đó là một test.

**Mẫu, và từng mảnh của nó là một ca đã bị bắt hụt:**

```
(?:^|[;\s])filename(\*?)\s*=\s*(?:"((?:[^"\]|\.)*)"|([^;"\r\n]*))
```

| Mảnh | Bịt gì |
|---|---|
| `(?:^\|[;\s])` | Thiếu nó thì `myfilename="../x"` — **bất kỳ** chuỗi nào kết thúc bằng `filename` — cũng khớp |
| `\s*=\s*` | `filename = "../x.php"` — không chuẩn nhưng parser bên dưới chấp nhận, nên đó là một đường né tránh |
| `"((?:[^"\]\|\.)*)"` | Nháy thoát. Bản trước dùng `[^"]*` và tôi ghi rằng *"quét mọi lần xuất hiện nên vẫn bắt được ở lần sau"* — **sai**: với `filename="abc\"../../x.php"` chỉ có **một** lần xuất hiện, `[^"]*` dừng ở dấu nháy đã thoát, và toàn bộ tải trọng phía sau không được kiểm |

**Giải mã `filename*=` đúng MỘT lần**, rồi gọi luật với `decode=false`. RFC 5987 định nghĩa ext-value là percent-encoding **một lớp**; giải thêm lớp nữa tạo FP thật:

```
filename*=UTF-8''a..%252Fb.txt
  giải 1 lần → a..%2Fb.txt     ← tên file hợp lệ chứa ký tự `%`
  giải 2 lần → a../b.txt       ← bắn
```

Bản trước truyền `decode = (m[1] == "*")` nên rơi vào vòng 3 mức của `args.check` — đúng cái bẫy mà cả khối chú thích này viết ra để tránh.

**`fn_trunc` — hết ngân sách khác với đã soi hết.** Chặn 32 phần và 512 byte mỗi tên file là cần, nhưng chạm trần rồi trả `nil` im lặng là biến một khoảng trống thành một âm tính. Và đó là một đường né tránh **thật**: nhồi 32 chuỗi `filename=` giả vào nội dung file thì bộ quét dừng trước header thật.

| Cột | Nghĩa |
|---|---|
| `fntr=-` | Không áp dụng — request không phải multipart |
| `fntr=0` | Đã soi hết **mọi** vùng header, không luật nào bắn |
| `fntr=stop` | Dừng lại vì **đã tìm thấy** → bình thường, luôn đi kèm một `fnrule=` |
| `fntr=len` | Một tên file > 512 byte. **Không phải vùng mù** — giá trị vẫn được kiểm trọn; đây là tín hiệu "dài bất thường" |
| `fntr=empty` | POST multipart không có thân → bình thường |
| `fntr=nb` | Content-Type không có `boundary` đọc được → không cắt được phần nào |
| `fntr=bd` | Có boundary nhưng thân không chứa dấu phân cách nào |
| `fntr=bdup` | Content-Type có **nhiều** boundary khác nhau → đã quét mọi candidate, nhưng không biết parser hạ nguồn chọn cái nào |
| `fntr=bval` | Giá trị boundary không dùng được |
| `fntr=disp` | `Content-Disposition` dạng sai |
| `fntr=ending` | Không thấy dấu đóng kết thúc |
| `fntr=hdr` | Một vùng header > 2 KB → chỉ soi 2 KB đầu |
| `fntr=n` | Hơn 64 phần → thường là upload thư viện ảnh thật, cách xử lý là nâng trần |
| `fntr=nothread` | Thân tràn ra file tạm và `thread_pool` chưa bật → **không soi được gì cả** |

**Là lý do, không phải cờ.** Bản trước trả `true` cho mọi nguyên nhân: đúng nghĩa "không soi hết" nhưng không đọc được, vì chúng đòi những việc khác hẳn nhau — đọc `fntr=47` sau ba ngày thì không biết làm gì với nó. Khi chạm nhiều trần, giữ lại cái **đòi hành động lớn nhất** (`STATUS_RANK` trong `body_core.lua`), không phải cái xảy ra trước.

**`len` là ngoại lệ và đây là chỗ dễ đọc nhầm nhất.** Giá trị tên file vẫn được kiểm **trọn vẹn**, không cắt. Cắt ở 512 rồi mới kiểm — cái bản trước làm — chính là để kẻ tấn công độn 512 byte cho traversal nằm ra ngoài tầm nhìn. Nên `len` báo "tên file dài bất thường", **không** báo "có chỗ chưa soi". Đừng đếm nó vào vùng mù.

**`stop` tồn tại để `fntr=0` chỉ còn một nghĩa.** Hàm thoát ngay ở luật đầu tiên, nên khi `fnrule` bắn thì các tên file phía sau **chưa hề được soi**. Không có `stop` thì `fnrule=X fntr=0` đọc thành "đã soi hết" và mọi phép đếm "bao nhiêu lần quét hoàn tất" đều lệch. Đây là một **giá trị** thay cho một quy ước phải nhớ — quy ước là thứ bị quên đúng lúc đọc số liệu. `len` cũng thắng `stop`: chạm trần độ dài trước khi tìm thấy thì vẫn còn vùng mù.

**Mẫu hỏng cũng vào cột này, có chủ ý.** `ngx.re.gmatch` trả `nil` khi *mẫu không biên dịch được*, và chỗ đó ban đầu nuốt luôn — một mẫu hỏng hiện ra thành `fnrule=- fntr=-` trên **mọi** multipart, trông y hệt một tầng đang chạy và không thấy gì. `RX_FILENAME` là hằng số nên đó là lỗi lúc deploy chứ không phải lỗi của request; vì vậy `ngx.ERR` chỉ kêu **một lần mỗi worker**, còn đường báo được đọc thật là `fntr=rx` chạy liên tục trong `wafstat` mục 7. Xem nhật ký 2026-09-05.

**Quoted-pair: soi CẢ HAI dạng, không thay thế.** Mẫu học **cú pháp** quoted-pair — nhánh `\\.` chính là lý do nó khớp được `filename="abc\"..."` — nhưng giá trị bắt ra vẫn còn nguyên dấu `\`, còn parser hạ nguồn thì bỏ nó. Cú pháp được phân tích mà ngữ nghĩa thì không:

| Gửi lên | Dạng thô (luật nhìn thấy) | Sau khi bỏ quoted-pair | Ai bắt |
|---|---|---|---|
| `filename=".\./shell.php"` | `.\./shell.php` — không có `..` | `../shell.php` | chỉ dạng đã bỏ escape |
| `filename="p\hp://input"` | `p\hp://input` — không có `php://` | `php://input` | chỉ dạng đã bỏ escape |
| `filename="..\..\shell.php"` | `..\..\shell.php` — **khớp** `\.\.[/\\]` | `...shell.php` — không khớp | chỉ **dạng thô** |

Dòng thứ ba là lý do không bỏ escape một cách phá huỷ: `..\..\` là traversal Windows **thật**, và bỏ dấu `\` làm nó biến mất. Đổi một lỗ hổng lấy một lỗ hổng. Ta không biết parser hạ nguồn đọc kiểu nào — PHP, Python, Node mỗi thứ một kiểu — nên chạy luật trên cả hai cách đọc. Giá: một `find` byte thô, và chỉ khi dạng thô **đã sạch**; tên file bình thường không có dấu `\` nên đường này không chạy. Bỏ escape **đúng một lần** (`.\\./` ra `.\./`, sạch — lặp thêm mới ra `../`), ghim bằng test đối chứng cùng kiểu `%2500`.

**Đã tính đến:** nhiều phần (quét hết, tấn công thường ở phần cuối); ba dạng cú pháp; không phân biệt hoa thường; dùng cờ `i` của `ngx.re` thay vì `body:lower()` để khỏi cấp phát thêm 80 KB mỗi POST; nhóm không tham gia của `ngx.re` trả `false` chứ không phải `nil`; đường dẫn Windows đầy đủ (`C:\Users\me\anh.jpg`) sạch ở **cả hai** dạng.

**Một ngoại lệ có chủ ý ở `filename*=`.** `filename*=UTF-8''x%2500.jpg` giải đúng một lần ra `x%00.jpg` — tên file thật chứa ba **ký tự** `%`, `0`, `0`. `args.check(v, false)` không giải mã thêm, nhưng `RX_NUL_ENC` vẫn bắn vì nó khớp `%00` dạng **văn bản**. Vậy riêng luật NUL **có** đọc thêm một lớp, và câu "giải mã đúng một lần" không còn thuần tuý — nói ra để không ai đọc nó như một bảo đảm. Giữ vậy: app hạ nguồn giải mã lại tên file là chuyện phổ biến và làm sai, `x%00.jpg` giải thêm lần nữa thành `x<NUL>.jpg` — đúng cái cắt chuỗi mà luật NUL sinh ra để bắt. Cùng một lựa chọn đã làm cho thân nhị phân. Ghim bằng cặp test đối chứng `%2500` (`filename*=` bắn / `filename=` im).

**Ba điều kiện chặn — phải xử lý TRƯỚC khi nâng `fn_rule` lên trọng số > 0.** Cả ba đều vô hại ở chế độ quan sát và đều thành lỗi thật khi chặn, nên chúng được in ra ngay trong output `wafstat` mục 7, chỗ số liệu được đọc:

1. ~~Quét toàn bộ thân~~ — **đã xử lý 05-09**, nay cắt part theo boundary và chỉ soi vùng header. Vùng mù còn lại: **multipart lồng nhau** (`multipart/mixed` trong một phần) — header của phần con nằm trong *thân* phần cha nên không được soi. Hiếm trong form web, và PHP cũng không đưa chúng vào `$_FILES`.
2. **`rx`, `len`, `n` đều không phải sạch** (`stop` thì bình thường). Tải trọng ở tên file thứ 33 hoặc sau byte 512 không được nhìn thấy. Enforcement đọc chúng như "đã soi, không thấy" là biến vùng mù thành giấy thông hành — hoặc nâng trần cho đường chặn, hoặc coi chính việc chạm trần là một tín hiệu riêng.
3. **`fn_rule` chỉ tính trên multipart còn trong bộ nhớ** (`fntr=spill`). Upload lớn spill nhiều hơn, nên **đừng suy rộng tỉ lệ này ra toàn bộ lưu lượng upload** — `wafstat` mục 7 in thẳng tỉ lệ đó ra. Và nó **không đóng được bằng `client_body_buffer_size`**: buffer 64 KB thì kẻ tấn công độn 65 KB, buffer 256 KB thì độn 257 KB. Đây là địa hạt của `fim.sh` (`scan_full` không có `-maxdepth` nên phủ cả `uploads/`) cộng với `wp_upload_exec` chặn thẳng việc *thực thi* — không phải bài toán tinh chỉnh buffer.

**`fn_rule` được miễn lấy mẫu** trong `waf_logger.run_body`. Bắt buộc: nó **không** sinh dòng `[waf]` (không tạo `waf_hits`), nên dòng `[waf-body]` là nguồn duy nhất của nó — quên là vứt 19/20 lượt. `fn_trunc` cũng được miễn — lấy mẫu nó đi thì tỉ lệ "không soi hết" trong số liệu thấp đi 20 lần.

**`%00` trong thân nhị phân vẫn có FP nhỏ.** Giữ `%00` là đúng hơn tắt cả cụm, nhưng `args.check` quét **toàn bộ** thân chứ không riêng header — một file PDF/text upload chứa đúng ba ký tự `%00` vẫn bắn. Xác suất thấp (~0,003 lần/47 KB) nhưng khác 0. Nên khi tính chuyện bật enforcement, **chỉ coi `%00` + `fnm=1` là bằng chứng mạnh**, còn `%00` + `fnm=0` thì tiếp tục đếm chứ chưa dùng để quyết.

**`vfy=` đánh dấu dòng THIẾU dữ liệu, không phải thêm một đặc điểm.** Từ `f69b896`, tín hiệu WAF trọng số 0 không còn phá fast-path — đúng ý đồ — nên một client verified chạm luật thoát ngay sau `check_verified_cookie`, trước cả classifier và `session_richness`. Dòng log của nó ra `class=- richness=- final=-`, trông y hệt trường hợp *"không biết vì lý do khác"* (block ở access phase, ban ở cửa).

| | Nghĩa |
|---|---|
| `vfy=1` + ba dấu `-` | Thiếu vì thoát fast-path — **đếm riêng** |
| `vfy=0` + ba dấu `-` | Thiếu vì lý do khác |

Gộp chung thì số liệu bóng của nhóm verified không dùng để mô phỏng *"nếu bật trọng số thì chuyện gì xảy ra"* — mà đó là mục đích duy nhất của chế độ bóng. `wafstat.sh` mục 2 tách hàng `thoat-fastpath` ra riêng.



**`cl=` `te=` `proto=` đi với nhau — một mình không cột nào trả lời được.**

| Cột | Là gì |
|---|---|
| `cl=` | Giá trị header `Content-Length`. `-` = **không có header đó**, chỉ vậy thôi |
| `te=` | `Transfer-Encoding` — đây mới là chunked **thật** |
| `proto=` | `1.1` / `2.0` / `3.0` |

> **Đính chính 2026-09-05.** Bản đầu tôi ghi `cl=- = chunked`. Sai, và sai theo hướng làm hỏng chính phép đo: header này còn vắng trong HTTP/2 (body đi bằng DATA frame), HTTP/3, request không có body, và vài client không gửi. Dàn máy này bật H2 và có hẳn một tầng vân tay H2 — nếu phần lớn POST là h2 không kèm Content-Length thì phép chéo "spill × cl" không nói lên gì.

Câu hỏi thật là **nginx có biết trước độ dài body không**: biết thì nó cấp buffer đúng cỡ và bỏ qua `client_body_buffer_size`; không biết thì rơi về buffer đó và spill.

| | nginx biết trước? |
|---|---|
| HTTP/1.1 + `Content-Length` | có |
| HTTP/1.1 + `Transfer-Encoding: chunked` | không |
| HTTP/2 | tuỳ client có gửi `Content-Length` |

`wafstat.sh` mục 8 chéo `spill` với ba cột này. `client_body_buffer_size` trong `nginx/nginx.conf` đang bị **chú thích lại** cho tới khi bảng đó có số.

### Ba cột phải đọc cùng nhau

| Cột | Trả lời câu gì |
|---|---|
| `exists=` | File **có** trên đĩa không |
| `fim=` | Nó **mới có** không, và chắc bao nhiêu |
| `final=` | Engine **kết luận** gì (`ctx.action`) |

`status=` **mơ hồ, đừng dùng nó để kết luận.** Đo 2026-09-02: 7/7 đường dẫn nghi vấn trả 200, **0/7** file tồn tại — 3/7 là trang PoW của chính antibot (`challenge/init.lua:14` đặt 200), 4/7 là WordPress rewrite mọi đường dẫn không phải file thật về `index.php` rồi theme trả 200 cho trang 404 đó. **Trên WordPress, 200 là phản hồi mặc định cho đường dẫn KHÔNG tồn tại.**

`action=` cũng không mang thông tin — nó là hằng số của **luật** (`signal`/`block`), không phải phán quyết. Phán quyết là `final=`.

`matched=` là dữ liệu **kẻ tấn công điều khiển hoàn toàn** đi vào file log. Lọc về ASCII in được **trước**, rồi mới cắt độ dài — làm ngược thứ tự thì vẫn có thể cắt giữa một chuỗi nhiều byte và để lại rác. (Đã gặp thật: gawk báo `Invalid multibyte data` khi đọc `antibot.log`.)

## ctx

**Ghi:** `waf_hits` (mảng), `waf_wp_path` (số, → `compute.lua`), `waf_fim_new`, `waf_target_exists`, `action`, `action_reason`

**Đọc:** `ngx.var.uri`, `ngx.var.host`, `ngx.var.document_root`, `ngx.var.remote_addr`

## Quy tắc

- **Mọi `ngx.exit` phải đặt `ctx.action` + `ctx.action_reason` trước.** `log_by_lua` chạy **sau** `ngx.exit`, nếu không `antibot.log` ra `reason=-`. Sáu `action_reason` của tầng này: `wp_upload_exec`, `wp_content_exec`, `wp_includes_exec`, `wp_admin_includes_exec`, `dotfile_exposed`, `dump_exposed`.
- **`ngx.ERR` chứ không `ngx.WARN`.** `da_to_openresty.sh` sinh `error_log <path>;` **không kèm mức** ⇒ nginx lấy mặc định `error` ⇒ WARN bị lọc sạch trong mọi server block per-domain. Ghi ở WARN nghĩa là hỏng trong im lặng.
- **`run_pre` chỉ đọc.** Mọi phép ghi (đĩa, Redis WP-host) thuộc `run_log`.
- **Không miễn loopback.** Miễn trừ cũ không mua được gì: lưu lượng 127.0.0.1 thật sự chỉ có wp-cron gọi `/wp-cron.php` (đã trong `WP_ROOT_OK`) và health check gọi `/`. Đổi lại nó mở đúng một đường: SSRF, hoặc PHP của tài khoản khác trên hosting chia sẻ curl về localhost.
- **Test bắt buộc chạy dưới `resty`, không phải `luajit`.** Luật quyết định bằng `ngx.re.find` với lookahead PCRE `(?=[/;.\\]|$)` — Lua pattern không diễn đạt được. `deploy.sh` bước `[3b]` gác; `SKIP_TEST=1` để vượt.
- **Thêm luật mới:** thêm mục vào `RULES` + nhánh trong `check()` + assertion trong `wp_paths_test.lua`. Luật `signal` phải có score trong `[0,1]`; trọng số nằm ở `compute.lua` (`waf_wp_path = 50`).

## Giới hạn — đo được, không vá bằng Lua

Một WAF theo URI **không** nhìn thấy:

- `include()` / LFI — đường dẫn không ở trong URI
- cron / WP-CLI
- `curl 127.0.0.1:8080` đi **thẳng** vào Apache, không qua OpenResty
- mu-plugins tự chạy — không có request để chặn

Ba cái đầu cần `open_basedir` + cấu hình Apache. Cái thứ tư là lý do `fim.sh` tồn tại.

## Liên quan

- **Trên:** `antibot/init.lua` (gọi `run_pre` bước 0, `run_log` trong `_M.log()`)
- **Dưới:** `intelligence/scoring/compute.lua` (`waf_wp_path` trọng số 50), `enforcement/decision/engine.lua` (ba tầng tin cậy quyết định thật)
- **Bên cạnh:** `async/waf_logger.lua`

## `upload.lua` — P1: soi TEN FILE upload

**Câu hỏi khác hẳn phần còn lại của tầng.** `args.lua` hỏi *"giá trị này có chứa
mẫu tấn công không"*. `upload.lua` hỏi *"file này, nếu đáp xuống đĩa và có ai gọi
URL của nó, thì **server** có chạy nó không"*. Câu thứ hai không nhìn mẫu nào —
nó nhìn **phần mở rộng** và cách Apache/PHP-FPM ánh xạ đuôi sang handler.

### Vì sao P1 KHÔNG phải "đi từ 0 lên có"

`body_core.scan` đã có `php` = thân chứa `<?php`/`<?=`, và nó **đã** là tín hiệu
trọng số 50 (`waf_body_php`). Việc của P1 là bịt các đường mà `<?php` **không**
xuất hiện:

| Đường lọt | `waf_body_php` bắt? | P1 |
|---|---|---|
| `shell.php` chứa `<?php` | **có** (50đ) | cộng thêm "đuôi chạy được" |
| `shell.phtml` / `.php5` / `.phar` | **có** | cộng thêm |
| `x.php.jpg` (đuôi kép) | tuỳ nội dung | **bắt được tên** |
| `.htaccess` với `AddType … .jpg` | **KHÔNG** — không có `<?php` | **chỉ P1** |
| Polyglot `GIF89a` + PHP | **có** | — |

Hai dòng cuối là lý do P1 tồn tại. Không phải "thêm mẫu cho chắc".

### Ba luật

| rule_id | Bắt gì |
|---|---|
| `upload_exec_ext` | Đuôi chạy được ở **vị trí cuối** — `shell.php` |
| `upload_exec_double` | Đuôi chạy được **không** ở cuối — `x.php.jpg` |
| `upload_config` | `.htaccess` `.htpasswd` `.user.ini` `php.ini` `web.config` |

**`upload_exec_double` không phải hoang tưởng.** Apache với `AddHandler` (không
phải `SetHandler`) ánh xạ theo **bất kỳ** đuôi trong tên, không chỉ đuôi cuối —
`x.php.jpg` chạy như PHP trên cấu hình mặc định của nhiều bản. Đây là một trong
những đường upload webshell phổ biến nhất và **không** đòi hỏi lỗi nào khác.

### Ba lớp chuẩn hoá, mỗi lớp đóng một đường né đã biết

```
basename()    lấy thành phần cuối — CẢ `/` lẫn `\`, vì PHP trên Linux coi `\`
              là ký tự tên file bình thường nên `a\b.php` LÀ đuôi `.php`
strip_tail()  cắt `::$DATA` (NTFS ADS), byte NUL, khoảng trắng/dấu chấm cuối —
              Apache vẫn ánh xạ `shell.php.` và `shell.php ` sang PHP
extensions()  duyệt PHẢI→TRÁI, tối đa 6 đuôi
```

Bỏ `strip_tail` thì **4** đường né mở ra cùng lúc (đã thử phá, test đỏ 4 dòng).

### Bảng đuôi HẸP có chủ ý — và hai đuôi cố ý KHÔNG có

`.inc` **CÓ** trong bảng, và bản đầu của mục này ghi ngược. Đo trên fleet 19-09:
cả ba dòng `AddHandler` liệt kê `.inc` ngay cạnh `.php`, nên trên dàn máy này nó
là mã chạy được. Bỏ ra là một lỗ thật. `.html`/`.htm` không chạy trên
server. `.svg` — xem mục riêng dưới.

**`contract_test` [28] gác chính ba cái này**, vì thêm một dòng vào bảng Lua thì
rất dễ, và người thêm sẽ không đọc file này trước.

### Trọng số 0 — chế độ quan sát

Cùng khuôn `waf_arg`/`waf_body_arg`, và là lý do `arg_null_byte` không phá 43
domain: luật chạy, ghi log, **không cộng điểm** cho tới khi có số liệu.

Chưa có **một** số đo nào từ dàn máy này về tên file upload. `.php` "gần như
không có bản sao hợp lệ" là một **phỏng đoán** — đúng loại phỏng đoán đã sai 6
lần trong phiên xây tầng body. Dân số chạy qua luật này là kho ảnh và tài liệu
của khách.

**Cổng vào để nâng khỏi 0:** đọc `uprule=` trong `waf.log` vài ngày.

### `up_rule` là KÊNH RIÊNG, không tranh chỗ `return` với `arg_rule`

`filename="shell.php"` **không** khớp mẫu nào của `check_args` — không `..`,
không `php://`, không `%00`. Gộp hai kết quả vào một đường `return` làm P1 biến
mất ở đúng nhóm nó sinh ra để bắt. Ngược lại `filename="../../x.php"` khớp **cả
hai**, và lúc đó ta muốn cả hai số đếm.

**`up_rule` đi qua 4 chặng, mỗi chặng có nhiều `return` sớm:**

```
scan_disposition_headers → scan_one_boundary → filename_rule → scan
```

Bỏ sót **một** `return` thì tín hiệu mất **trong im lặng** ở đúng nhóm đó — ví dụ
tràn `MAX_PARTS`: một upload 70 phần có `shell.php` ở phần thứ 3 thoát qua nhánh
`n` và báo cáo "không có gì". **`contract_test` [27a]** đòi mọi `return` trong
`scan_one_boundary` có đúng 3 giá trị.

### `pack`/`unpack` — V2 → V3, và vì sao phải nâng phiên bản

`unpack` gác bằng `#f ~= <số trường>`. Thêm một trường mà quên nâng phiên bản
thì một bản `pack` mới gặp `unpack` cũ trả `bad_payload` — **trong im lặng**, và
**chỉ** với thân **đã spill**, tức đúng nhóm upload lớn, nhóm đáng quan tâm nhất.
Đổi phiên bản làm sự không khớp đó **có tên**. **`contract_test` [27c]** so cả
phiên bản lẫn số trường.

### `uprule=` trong waf.log

Ghi **rule_id**, tuyệt đối **không** ghi tên file — tên file do kẻ gửi điều khiển
và thực tế có mang token, email, đường dẫn nội bộ; `waf.log` là file text giữ 30
ngày. Cùng lý do đã không ghi thân request vào `matched=`.

`up_rule` cũng vào cổng `notable` của `waf_logger`: nó **không** sinh dòng
`[waf]` (kênh riêng, không tạo `waf_hits`), nên `BODY_SAMPLE` sẽ vứt 19/20 lượt
— phép đo sẽ nói "không có gì" về đúng thứ nó được sinh ra để đếm.

**Đọc kèm `fntr=`:** `uprule=- fntr=spill` nghĩa là **chưa soi**, không phải
sạch. Gộp hai cái lại là đúng lỗi đã cắt 4 tháng ở `wp_paths.mark()`.

### `upload.lua` — P1: soi TÊN FILE upload

**Câu hỏi khác hẳn `args.lua`.** `args.lua` hỏi *"giá trị này có chứa mẫu tấn công không"*. `upload.lua` hỏi *"file này, nếu đáp xuống đĩa và có ai gọi URL của nó, thì **server có chạy** nó không"*. Câu thứ hai không nhìn mẫu nào — nó nhìn **phần mở rộng** và cách Apache/PHP-FPM ánh xạ đuôi sang handler.

**P1 KHÔNG đi từ 0 lên có.** `body_core.scan` đã có `php` = thân chứa `<?php`/`<?=`, và nó **đã** là tín hiệu trọng số 50 (`waf_body_php`). Việc của P1 là bịt các đường mà `<?php` **không** xuất hiện:

| Đường lọt | `waf_body_php` bắt? | P1 |
|---|---|---|
| `shell.php` chứa `<?php` | **có** (50đ) | cộng thêm "đuôi chạy được" |
| `shell.phtml` / `.php5` / `.phar` | **có** | cộng thêm |
| Đuôi kép `x.php.jpg` | tuỳ nội dung | **bắt được tên** |
| `.htaccess` (`AddType … .jpg`) | **MÙ** — không có `<?php` | **chỉ P1** |
| Webshell mã hoá không thẻ mở | **MÙ** | chưa — xem giới hạn |

Hai dòng cuối là lý do P1 tồn tại. Không phải "thêm mẫu cho chắc".

**Sáu nhãn, không phải hai — và đó là quyết định về phép ĐO, không phải chia nhỏ cho vui.** Gộp lại thì không trả lời được câu quyết định trọng số: *"tín hiệu này đến từ `.htaccess` (đổi handler của mọi file trong thư mục) hay từ `web.config` (trên stack Linux/Apache gần như vô hại)"*. Một nhãn gộp là một con số không dùng được.

| rule_id | Bắt gì | Mức |
|---|---|---|
| `upload_apache_config` | `.htaccess` — đổi **handler** của các file khác. `AddType application/x-httpd-php .jpg` biến mọi JPEG thành mã chạy được, và **không** chứa `<?php` nên `waf_body_php` mù hoàn toàn | mạnh nhất |
| `upload_php_config` | `.user.ini` `php.ini` — `auto_prepend_file` là một đường chạy mã | mạnh |
| `upload_foreign_config` | `web.config` (IIS, stack này gần như vô hại) `.htpasswd` (không đổi handler) — dấu hiệu scanner, đếm **riêng** | yếu |
| `upload_php_ext` | Đuôi **đã xác minh trên fleet** ở vị trí cuối — `.php .php5 .phtml .inc` | mạnh |
| `upload_php_double` | Cùng tập đó **không** ở cuối — `x.php.jpg`, vì `AddHandler` (khác `SetHandler`) khớp **bất kỳ** đuôi trong tên | mạnh |
| `upload_php_legacy_ext` | `.php3 .php4 .php6 .php7 .php8 .pht .phtm .phps .phar` — **không thấy** trong `AddHandler` nào trên fleet. Vẫn soi (máy mới cài, hoặc `.htaccess` của khách bật), nhưng đếm **riêng** | chưa rõ |

**Bảng đuôi đã ĐO trên fleet 19-09, và số liệu bác bỏ bản đầu của tôi:**

```
httpd-hostname.conf:4       AddHandler ...php74/sockets/webapps.sock  .inc .php .phtml
httpd-php-handlers.conf:5   AddHandler application/x-httpd-lsphp     .inc .php .php5 .phtml
httpd-php-handlers.conf:12  AddHandler application/x-httpd-lsphp     .inc .php .php5 .phtml
```

Hai kết luận ngược chiều nhau:

1. **`.inc` LÀ mã chạy được** trên dàn máy này — đứng ngay cạnh `.php` trong cả ba dòng. Bản đầu tôi ghi ngược ("`.inc` không được ánh xạ theo mặc định") và còn **cài phỏng đoán đó vào `contract_test` [28] như một bất biến**. Bỏ `.inc` ra là một lỗ **thật**: webshell tên `x.inc` chạy bình thường.
2. **`.php3 .php4 .php6 .php7 .php8 .pht .phtm .phps .phar` không có trong bất kỳ dòng nào.** Bảng cũ rộng gấp ba lần thực tế — chỉ tốn một dòng log ở trọng số 0, nhưng nó làm **bẩn phép đo**: đếm `upload_exec_ext` mà không biết bao nhiêu lượt là đuôi thật sự chạy được thì không dùng con số đó quyết định trọng số được.

Do đó [28] nay gác **hai chiều**: `svg`/`html`/`htm` **không được** có trong `PHP_EXT` (quyết định FP), còn `php`/`inc`/`php5`/`phtml` **phải** có (đo trên fleet). Nhánh [28b] chính là cái bắt lại lỗi của tôi nếu ai lặp nó.

**Ba bước chuẩn hoá, mỗi bước bịt một đường né đã biết:**

- `basename()` — chỉ lấy thành phần cuối. Cả `/` **và** `\`: PHP trên Linux coi `\` là ký tự tên file bình thường, nên `a\b.php` là **một** tên file đuôi `.php`.
- `strip_tail()` — cắt `::$DATA` (NTFS ADS), byte NUL (`shell.php\0.jpg` → server thấy `shell.php`), dấu cách/tab/dấu chấm cuối (`shell.php.` vẫn được Apache ánh xạ trên một số cấu hình).
- `extensions()` — duyệt **mọi** đuôi từ phải sang, tối đa 6. Trần 6 để kẻ gửi không bắt ta duyệt một tên 512 byte đầy dấu chấm.

**Trọng số 0 lúc chào đời** — cùng khuôn `waf_arg`/`waf_body_arg`, và là lý do `arg_null_byte` không phá 43 domain. Nên `waf_upload` **không** được có mặt trong `waf_signal()`; `contract_test` [1] gác hai chiều đó.

**Cố ý KHÔNG có:** luật "không có đuôi" hay "đuôi lạ". Khách upload file không đuôi và đuôi lạ thật (`.dwg`, `.ai`, `.sketch`, `.psd`). `.inc` thì **có** trong bảng — đo trên fleet, xem bảng rule_id ở trên.

**ĐÃ kiểm trên fleet 19-09** (mục này trước đó ghi "chưa kiểm" — nay có số liệu). Lệnh, để kiểm lại khi thêm máy hoặc đổi PHP handler:

```bash
grep -rniE 'AddHandler|AddType' /usr/local/apache2/conf/ | grep -i php
```

**Đường đi của `up_rule` là chỗ dễ hỏng âm thầm nhất.** Nó qua bốn chặng — `scan_disposition_headers` → `scan_one_boundary` → `filename_rule` → `scan` — và mỗi chặng có nhiều lối `return` sớm. Bỏ sót **một** thì tín hiệu mất **trong im lặng** ở đúng nhóm đó: ví dụ tràn `MAX_PARTS`, một upload 70 phần có `shell.php` ở phần thứ 3 sẽ thoát qua nhánh `n` và báo cáo "không có gì". Đúng khuôn lỗi đã cắt 4 tháng của `wp_paths.mark()`. `contract_test` [27a] đòi **mọi** `return` trong `scan_one_boundary` trả về đúng 3 giá trị.

**`pack`/`unpack` nâng V2 → V3.** `unpack` gác bằng `#f ~= 11`, nên một bản `pack` mới gặp `unpack` cũ trả `bad_payload` — im lặng, và **chỉ** với thân đã spill, tức đúng nhóm upload lớn. [27c] kiểm cả phiên bản lẫn **số trường**, vì khớp phiên bản một mình không bắt được lệch trường.

**`uprule=` trong `waf.log` ghi RULE_ID, tuyệt đối không ghi tên file** — tên file do kẻ gửi điều khiển và thực tế có mang token/email/đường dẫn nội bộ; `waf.log` là file text giữ 30 ngày. Cùng lý do đã không ghi thân request vào `matched=`. Đọc **kèm** `fntr=`: `uprule=- fntr=spill` nghĩa là **chưa soi**, không phải sạch.

**Giới hạn còn lại, đo được:** webshell mã hoá (`eval(base64_decode(…))` không thẻ mở) vẫn lọt — nó cần luật **nội dung**, thuộc P2/F2. Và MIME lệch đuôi chưa soi: `Content-Type: image/jpeg` kèm `filename="x.php"` hiện chỉ bắn vì đuôi, chưa bắn vì **lệch**.

### Vùng không quan sát của multipart — đo trước, KHÔNG vá bằng ngưỡng

`MAX_PARTS = 64` và `MAX_HDR_LEN = 2048` làm parser trả trạng thái truncated (`fntr=n`, `fntr=hdr`). Điều đó **đúng** — nó không im lặng coi là đã quét đầy đủ, và đó là cả điểm của cột `fntr=`.

Nhưng **trạng thái đó hiện chỉ đi vào `waf.log`, không vào `ctx`.** Đã grep: `fn_trunc` không xuất hiện trong `init.lua` lẫn `compute.lua`. Nghĩa là một upload 70 part với `shell.php` ở part 65 **lọt sạch và không sinh tín hiệu nào** — ta biết mình không quét hết, rồi không làm gì với thông tin đó.

**Không block theo số part.** Upload nhiều part là chuyện hợp lệ thường xuyên (gallery sản phẩm, import CSV kèm ảnh), nên một ngưỡng toàn cục là cỗ máy FP. `MAX_PARTS` cũng **không** nên nâng: nó là trần chi phí do kẻ gửi điều khiển.

**Hướng đúng là tín hiệu theo NGỮ CẢNH**, và nó chỉ có nghĩa khi **bốn** điều kiện cùng đúng:

| Điều kiện | Vì sao cần |
|---|---|
| endpoint upload (`async-upload.php`, `media-new.php`, `admin-ajax.php?action=upload*`) | loại trừ form nhiều trường thông thường |
| có `filename=` trong thân | loại trừ form không kèm file |
| body scan **incomplete** (`fntr ∈ {n, hdr, spill}`) | đây là vùng mù thật, không phải scan sạch |
| **chưa xác thực** (`session_richness < 0.5`) | admin đăng nhập upload 70 ảnh là việc bình thường — đúng dân số `auth_session_cap` che |

Bốn điều kiện cùng lúc thì mới là *"có người nhồi part để đẩy file ra ngoài vùng quét"*; thiếu điều kiện thứ tư là chặn đúng quản trị viên thật.

**Chưa implement, và cổng vào là số đo:** cần biết `fntr=n` và `fntr=hdr` xuất hiện bao nhiêu lần trên `waf.log` của 5 máy, và trong đó bao nhiêu lượt có `rown < 0.5`. Nếu con số là 0 thì đây là hạng mục **gác vĩnh viễn** như `expensive_filter` throttle — viết luật cho một dân số bằng 0 là cái giá đã trả một lần.

```bash
grep -c 'fntr=n\b'   /var/log/antibot/waf.log
grep -c 'fntr=hdr'   /var/log/antibot/waf.log
grep -E 'fntr=(n|hdr)' /var/log/antibot/waf.log | tr ' ' '\n' | grep '^rown=' | sort | uniq -c | sort -rn | head
```

### `.svg` — tách khỏi P1 có chủ ý, và vì sao WAF không phải chỗ chữa

`.svg` **không** nằm trong bảng đuôi của P1. Không phải vì nó vô hại — ngược lại
— mà vì nó là loại nguy hiểm **khác**, nên cả ngưỡng FP lẫn chỗ chữa đều khác.

| | Webshell `.php` | `.svg` |
|---|---|---|
| Chạy ở đâu | **server**, trong tiến trình PHP | **trình duyệt** nạn nhân |
| Là gì | RCE | XSS khi phục vụ trực tiếp |
| Bản sao hợp lệ trong upload của khách | gần như không có | **logo, icon — có thật, nhiều** |
| Chữa bằng WAF được không | được, chặn lúc upload | **không** — xem dưới |

SVG là XML nên mang được `<script>`, `on*=`, `<foreignObject>`,
`<use href="data:…">`, `xlink:href="javascript:…"`, `<style>` kèm `@import`.
Blocklist thẻ/thuộc tính **luôn thua**; phải allowlist (bản làm đúng: SVG
Sanitizer của DOMPurify).

**Bốn lớp phòng vệ, xếp theo sức mạnh thật — không theo thứ tự hay được nhắc:**

1. **Sanitize lúc upload** — biện pháp gốc, xử lý nguyên nhân.
2. **Phục vụ từ origin KHÔNG dùng chung cookie** — mạnh nhất trong các lớp
   *không* cần sửa file, vì nó vô hiệu hoá **hậu quả** thay vì đoán trước
   payload: script có chạy cũng không đọc được cookie phiên, không gọi được API
   dưới danh nghĩa nạn nhân. Cùng nguyên lý `googleusercontent.com` tồn tại.
3. **Chỉ nhúng bằng `<img>`** — trong `<img>` thì script trong SVG **không chạy**
   (chế độ non-animated/non-interactive của spec). Nhưng nó **chỉ bảo vệ trang
   nhúng**; mở thẳng `/wp-content/uploads/x.svg` thì vô tác dụng, mà WordPress
   cho mở thẳng.
4. **CSP** — **yếu nhất, và hay bị tưởng là mạnh nhất.** Lý do không phải CSP
   dở, mà là nó **không áp dụng được vào đúng ca đáng lo**: `Content-Security-Policy`
   là response header của **tài liệu**, còn khi nạn nhân mở thẳng URL thì tài
   liệu **chính là file SVG** — WordPress/Apache không gắn CSP cho nó. CSP chỉ có
   tác dụng nếu gắn lên **chính response phục vụ file upload**, tức việc của
   nginx.

**Rẻ hơn cả ba lớp trên, và chưa ai nhắc: `Content-Disposition: attachment`.**
Mở thẳng URL thì tải về chứ không render; `<img>` vẫn nhúng bình thường. Trên
dàn 74 domain đây là tỉ lệ phòng-vệ/chi-phí tốt nhất vì **không cần sửa gì trong
WordPress của khách**:

```nginx
location ~* /wp-content/uploads/.*\.svg$ {
    add_header Content-Disposition "attachment" always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'" always;
    add_header X-Content-Type-Options nosniff always;
}
```

**Vì sao đây KHÔNG phải việc của tầng WAF.** Cả bốn lớp đều là **cấu hình phục
vụ file**, không phải luật soi request. Một luật WAF chặn upload `.svg` sẽ chặn
đúng thứ khách hàng làm hợp lệ hàng ngày (logo, icon) để đổi lấy việc **không**
bảo vệ được các file SVG **đã nằm trên đĩa từ trước** — tức trả giá FP cao nhất
cho vùng phủ nhỏ nhất. Đó là hình dạng của một luật sai chỗ.

**Trạng thái: hạng mục riêng, chưa làm, không thuộc P1.** Cổng vào là số đo —
bao nhiêu `.svg` thật đang được upload và phục vụ trên dàn máy, để biết đặt
`Content-Disposition` có phá giao diện site nào không.

### `.svg` — tách khỏi P1 có chủ ý, và vì sao WAF không phải chỗ chữa

`.svg` **không** nằm trong bảng đuôi của P1. Không phải vì nó vô hại — ngược lại
— mà vì nó là loại nguy hiểm **khác**, nên cả ngưỡng FP lẫn chỗ chữa đều khác.

| | Webshell `.php` | `.svg` |
|---|---|---|
| Chạy ở đâu | **server**, trong tiến trình PHP | **trình duyệt** nạn nhân |
| Là gì | RCE | XSS khi phục vụ trực tiếp |
| Bản sao hợp lệ trong upload của khách | gần như không có | **logo, icon — có thật, nhiều** |
| Chữa bằng WAF được không | được, chặn lúc upload | **không** — xem dưới |

SVG là XML nên mang được `<script>`, `on*=`, `<foreignObject>`,
`<use href="data:…">`, `xlink:href="javascript:…"`, `<style>` kèm `@import`.
Blocklist thẻ/thuộc tính **luôn thua**; phải allowlist (bản làm đúng: SVG
Sanitizer của DOMPurify).

**Bốn lớp phòng vệ, xếp theo sức mạnh thật — không theo thứ tự hay được nhắc:**

1. **Sanitize lúc upload** — biện pháp gốc, xử lý nguyên nhân.
2. **Phục vụ từ origin KHÔNG dùng chung cookie** — mạnh nhất trong các lớp
   *không* cần sửa file, vì nó vô hiệu hoá **hậu quả** thay vì đoán trước
   payload: script có chạy cũng không đọc được cookie phiên, không gọi được API
   dưới danh nghĩa nạn nhân. Cùng nguyên lý `googleusercontent.com` tồn tại.
3. **Chỉ nhúng bằng `<img>`** — trong `<img>` thì script trong SVG **không chạy**
   (chế độ non-animated/non-interactive của spec). Nhưng nó **chỉ bảo vệ trang
   nhúng**; mở thẳng `/wp-content/uploads/x.svg` thì vô tác dụng, mà WordPress
   cho mở thẳng.
4. **CSP** — **yếu nhất, và hay bị tưởng là mạnh nhất.** Lý do không phải CSP
   dở, mà là nó **không áp dụng được vào đúng ca đáng lo**: `Content-Security-Policy`
   là response header của **tài liệu**, còn khi nạn nhân mở thẳng URL thì tài
   liệu **chính là file SVG** — WordPress/Apache không gắn CSP cho nó. CSP chỉ có
   tác dụng nếu gắn lên **chính response phục vụ file upload**, tức việc của
   nginx.

**Rẻ hơn cả ba lớp trên, và chưa ai nhắc: `Content-Disposition: attachment`.**
Mở thẳng URL thì tải về chứ không render; `<img>` vẫn nhúng bình thường. Trên
dàn 74 domain đây là tỉ lệ phòng-vệ/chi-phí tốt nhất vì **không cần sửa gì trong
WordPress của khách**:

```nginx
location ~* /wp-content/uploads/.*\.svg$ {
    add_header Content-Disposition "attachment" always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'" always;
    add_header X-Content-Type-Options nosniff always;
}
```

**Vì sao đây KHÔNG phải việc của tầng WAF.** Cả bốn lớp đều là **cấu hình phục
vụ file**, không phải luật soi request. Một luật WAF chặn upload `.svg` sẽ chặn
đúng thứ khách hàng làm hợp lệ hàng ngày (logo, icon) để đổi lấy việc **không**
bảo vệ được các file SVG **đã nằm trên đĩa từ trước** — tức trả giá FP cao nhất
cho vùng phủ nhỏ nhất. Đó là hình dạng của một luật sai chỗ.

**Trạng thái: hạng mục riêng, chưa làm, không thuộc P1.** Cổng vào là số đo —
bao nhiêu `.svg` thật đang được upload và phục vụ trên dàn máy, để biết đặt
`Content-Disposition` có phá giao diện site nào không.

## Trạng thái tầng WAF — đo bằng code, không đọc bảng kế hoạch

**Bảng này đo lại được. Đừng tin nó, chạy lại lệnh ở cột cuối.**

Lý do nó tồn tại: bản lộ trình đăng ngày 18-09 khai `F1a` (đọc body) và `F1b` (soi
thân) là **chưa làm**, trong khi 801 dòng của chúng đã chạy trên cả 5 máy từ
05-09. Tôi đọc hết 1.504 dòng lộ trình rồi tin **bảng trạng thái trong đó** thay
vì `grep` mã nguồn. Đó là lần thứ năm cùng một họ lỗi trong dàn này: *"không đọc
được" bị thu thành "đã đọc và câu trả lời là X"* — xem `l7/CLAUDE.md` và
`async/logger.lua`.

| Mục | Trạng thái | Bằng chứng trong mã |
|---|---|---|
| P0 — luật đường dẫn | **xong** | `exposed.lua` 68 + `wp_paths.lua` 469 |
| F1a — đọc body an toàn | **xong** | `body.lua` 149 gọi từ `init.lua:111` trong `run_pre` |
| F1b — soi thân request | **xong** | `init.lua:137` áp `args.check` lên `ctx.waf_body`; spill đi qua `body_core.lua` 596 + `body_worker.lua` 56 trên thread pool `antibot_waf_io` |
| T — test | **một phần** | `scripts/*.lua` 3.502 dòng test / 2.173 dòng mã. Cổng `deploy.sh [3b]` |
| P2/F2 — luật payload | **một phần** | **3 luật** tham số trong `body_core.lua:143-150`. Không có SQLi/XSS/RCE — `grep -niE 'union\|select.*from\|<script\|eval\('` trên `waf/*.lua` trả về **0** dòng mã |
| P1 — chặn upload webshell | **một phần** | `upload.lua` — **6 nhãn**, trọng số 0. Đuôi đã xác minh trên fleet (`.php .php5 .phtml .inc`), đuôi kép, tầng legacy đếm riêng, ba nhãn config tách theo sức mạnh thật. Chặn theo *nội dung* file (chữ ký webshell mã hoá, entropy, polyglot) **chưa** làm |
| F3 — chính sách theo domain | **chưa** | `proxy_origin.lua` mới có **một** khoá tập toàn cục `waf:proxyhosts` |
| A — admin UI cho WAF | **chưa** | `admin/init.lua` chưa có trang nào của tầng này |

Lệnh đo lại, chạy từ `antibot-core/`:

```bash
cat waf/args.lua waf/body.lua waf/body_core.lua waf/body_worker.lua \
    waf/exposed.lua waf/init.lua waf/wp_paths.lua waf/upload.lua | wc -l   # mã: 2173
cat waf/scripts/*.lua | wc -l                                # test: 3502
grep -o 'return "arg_[a-z_]*' waf/body_core.lua | sort -u   # 3 rule_id tham so
grep -o 'return "upload_[a-z_]*' waf/upload.lua | sort -u   # 6 rule_id ten file
grep -nE '^ *waf_[a-z_]+ *=' intelligence/scoring/compute.lua # 5 tín hiệu
```

**Ba rule_id, bốn lệnh `return`.** `arg_null_byte` trả về từ **hai** nhánh —
byte NUL thô và mẫu văn bản `%00` — vì đó đúng là chỗ trục `binary` tách ra
(xem mục `args.check` ở trên). Nên đếm `grep -c 'return "arg_'` ra **4** mà số
luật vẫn là **3**. Lệnh trong khối trên `sort -u` chính vì vậy; bản đầu của
chính mục này đếm lệnh `return` rồi suýt ghi sai số luật.

**Năm tín hiệu WAF.** `waf_wp_path = 50`, `waf_body_php = 50`, `waf_arg = 0`,
`waf_body_arg = 0`, `waf_upload = 0` (P1, 19-09). `waf_body_php` **đã** được nâng
khỏi 0 — đếm "ba luật `args` nên ba tín hiệu trọng số 0" là trộn hai thứ khác
nhau: số *luật* không bằng số *tín hiệu*. Con số này đổi mỗi lần thêm tín hiệu,
nên **đọc bằng lệnh ở trên**, đừng đọc câu này.

**Việc kế tiếp là P1, rồi F3.** P1 trước vì nền đã có sẵn trong `body_core` nên
phần còn lại là luật, không phải hạ tầng. F3 sau vì nó là **công cụ chữa FP**:
6 host sau reverse proxy cần chính sách khác 68 host còn lại, và P2/F2 — mục duy
nhất có rủi ro FP cao — phải xếp sau khi đã có F3 để gỡ.

## Update log
- 2026-09-19 (6) — **Cong `[2]` chan ban P1: escape sequence sai. Nguyen nhan la ONG DAN, khong phai Lua — va `luacheck` co lop thu ba vi vay.**
  - **Loi:** `upload_test.lua:82: invalid escape sequence near '"..'`. Toi viet `"..\..\shell.php"` trong mot **heredoc bash**, bash an mot lop `\`, nen file nhan `"..\..\shell.php"` — va `\.` khong phai escape hop le trong Lua. Hai dong bi: 82 (`\.`) va 143 (`a\b\c.php`, `\c` khong hop le).
  - **Vi sao hai lop kiem cu deu MU:** `luabal.pl` dem khoi; `luacheck` lop [1] cung dem khoi, va no chay tren code **da bo chuoi** boi `strip()`. Ca hai deu lam viec ben NGOAI chuoi, nen khong lop nao nhin vao ben TRONG chuoi. **Do la vung mu co cau truc, khong phai sot ngau nhien** — va no giai thich vi sao mot ban "131/131 xanh" van bi luajit tu choi nap.
  - **Sua ma khong phu thuoc lop escape nao:** `string.char(92)` cho dau backslash thay vi viet `\` trong heredoc. Ba dong (82, 126, 143). Dai hon nhung khong co lop nao an duoc.
  - **`luacheck.pl` them lop [3] — escape sequence.** Thu pha: tai tao dung dong 82 => **do**, chi ra dung ky tu; code da sua => xanh.
  - **VA LOP [3] BAO SAI NGAY LAN CHAY DAU — 5 bao dong, 3 tren code DANG CHAY production.** `exposed.lua` va `wp_paths.lua` chua `[[\.(?:sql|wpress|bak)$]]` — long-bracket string **KHONG xu ly escape**, nen `\.` la HAI ky tu literal va la **dung y** (PCRE can `\.`). `strip()` gop long-string va chuoi thuong vao cung mot mang nen lop moi khong phan biet duoc.
  - **Suyt lap dung loi da got ba lop kiem hom qua.** Neu toi tin bao dong do va "sua" `exposed.lua`, toi da pha regex cua hai luat dang chan webshell that. Da tach `@longs` khoi `@strs`; thu pha ba huong: escape sai trong nhay doi => do; **cung chuoi do trong long-bracket => xanh**; nhay don => do. Phan biet dung ca ba.
  - **Chu thich dau `luacheck.pl` da sai va da sua:** no khai "BON LOP KIEM" va liet ke hai lop **da bi go hom qua** nhu dang chay. Dung loai chu thich sai co he thong ma repo nay da ghi nhan — mot cong cu kiem tinh ma tu mo ta sai chinh no thi khong con la thuoc do. Nay: BA lop, kem muc "HAI LOP DA GO" ghi ro vi sao.
  - **Bai hoc, va no khac lan truoc:** hom qua bai hoc la "test chua thu pha thi chua biet no lam gi". Hom nay them mot nua: **mot lop kiem MOI phai chay tren toan bo cay TRUOC khi tin no** — vi cai nó bao sai dau tien la code dang chay production, khong phai code moi viet. Lop [3] gan bi tat trong 5 phut dau doi.
- 2026-09-19 (5) — **So lieu `AddHandler` tu fleet BAC BO bang duoi cua toi, va bon gop y cua nguoi van hanh vao code.**
  - **Loi te nhat trong ngay, va no la loi cua rieng toi:** `upload.lua` ban dau ghi ".inc KHONG duoc anh xa sang PHP handler theo mac dinh" — roi toi **cai chinh phong doan do vao `contract_test` [28] nhu mot BAT BIEN**. Do that tren fleet: ca **ba** dong `AddHandler` (`httpd-hostname.conf:4`, `httpd-php-handlers.conf:5,12`) liet ke `.inc` **ngay canh** `.php`. Tren dan may nay `.inc` la ma chay duoc; bo no ra la mot lo THAT, webshell ten `x.inc` chay binh thuong.
  - **Bai hoc phuong phap, khac han cac lan truoc:** cac lan truoc la "doan sai roi do lai". Lan nay toi lay mot phong doan chua do va **khoa cung no bang mot test**. Test khong lam phong doan thanh su that — no chi lam nguoi sua DUNG ve sau bi bao do. **Mot bat bien chi duoc dat vao test khi no den tu phep do hoac tu quyet dinh tuong minh.** [28] nay gac HAI chieu: `svg`/`html`/`htm` KHONG duoc co trong `PHP_EXT`, `php`/`inc`/`php5`/`phtml` PHAI co — nhanh [28b] chinh la cai bat lai loi cua toi neu ai lap.
  - **Chieu nguoc lai cung sai:** `.php3 .php4 .php6 .php7 .php8 .pht .phtm .phps .phar` **khong co trong bat ky dong nao**. Bang cu rong gap ba lan thuc te. Huong nay chi ton mot dong log o trong so 0, nhung no lam **ban phep do** — dem `upload_exec_ext` ma khong biet bao nhieu luot la duoi that su chay duoc thi khong dung con so do quyet dinh trong so duoc.
  - **HAI nhan -> SAU nhan, theo gop y, va giai quyet ca hai diem 1+2 bang mot co che.** `upload_apache_config` (`.htaccess` — doi handler cua moi file trong thu muc, manh nhat) · `upload_php_config` (`.user.ini`/`php.ini` — `auto_prepend_file`) · `upload_foreign_config` (`web.config` tren stack Linux gan nhu vo hai, `.htpasswd` khong doi handler — dem RIENG de khong lam con so `.htaccess` phong len bang luu luong scanner) · `upload_php_ext` (duoi DA XAC MINH tren fleet) · `upload_php_double` (cung tap, khong o cuoi) · `upload_php_legacy_ext` (phu thuoc cau hinh, dem rieng). Cat bang la mat kha nang phat hien; gop nhan la mat kha nang DO. Tach tang giu ca hai.
  - **Diem 3 — thu tu chuan hoa: `canonical_views` kiem BA goc nhin thay vi mot chuoi da normalize.** `shell.php\0/benign.jpg`: `basename` don thuan chon `benign.jpg` (dau `/` cuoi cung nam SAU NUL), nhung mot thanh phan ha nguon dung chuoi kieu C thay `shell.php` — **chuoi dung o dung cho ta khong nhin**. Ba goc nhin: cat NUL/ADS **truoc** roi basename (goc nhin C-string, dung dau vi nguy hiem nhat) · basename truoc roi cat (tang hien dai) · chuoi tho chi cat duoi. **Thu pha: quay ve mot goc nhin => hai ca `shell.php\0/...` do, dung ca ban neu.** Gia: ba `find` tren chuoi < 512 byte, va chi tra khi request THAT SU co `filename=`.
  - **Diem 4 — vung mu sau part 64: GHI RA, chua vá, va co ly do.** Da grep: `fn_trunc` **khong xuat hien** trong `init.lua` lan `compute.lua` — trang thai truncated chi di vao `waf.log`. Mot upload 70 part co `shell.php` o part 65 lot sach va khong sinh tin hieu nao. Dung nhu ban noi: **khong block theo so part** (gallery san pham, import CSV kem anh — FP ngay), va `MAX_PARTS` cung khong nen nang (no la tran chi phi do ke gui dieu khien). Huong dung la tin hieu theo ngu canh voi **BON** dieu kien cung luc: endpoint upload · co `filename=` · scan incomplete (`fntr ∈ {n,hdr,spill}`) · **chua xac thuc** (`richness < 0.5`). Thieu dieu kien thu tu la chan dung quan tri vien that upload 70 anh. **Cong vao la so do**, khong phai truc giac: neu `fntr=n`/`fntr=hdr` = 0 tren waf.log cua 5 may thi gac vinh vien nhu `expensive_filter` throttle — viet luat cho mot dan so bang 0 la cai gia da tra mot lan.
  - **Test: 62 assertion (tu 55) + 12 ca dau-cuoi -> 19.** Them `.inc` (do tren fleet), tang legacy dem rieng, ba nhan config, bon ca NUL, `.htpasswd`. `[28]` ba nhanh, **thu pha ca ba, ca ba do dung cho**.
  - **Mot cho trong bo test phai sua ky vong, va ghi ro vi sao lan nay la DUNG:** dau muc [1] cua `upload_test.lua` viet "neu dong nao trong nhom nay do, KHONG duoc sua test cho khop". Ca `include.inc` -> `nil` nam dung o do. Lan nay sua **la dung**, vi cai bi bac bo la GIA DINH cua toi, khong phai hanh vi dung cua code — do luong tu may that thang mot gia dinh chua kiem la ly do hop le duy nhat de doi ky vong. "Test do nen toi ha ky vong" thi khong.
  - **So do: ma 2.069 -> 2.173 dong, test 3.398 -> 3.502, nhan 3 -> 6.**
- 2026-09-19 (4) — **P1 khoi dong: `upload.lua` — soi TEN FILE upload. Trong so 0.**
  - **Vi sao no KHONG phai "them mau cho chac":** `waf_body_php` (trong so 50, da chay tu 05-09) **da** bat webshell PHP thuan trong than multipart. P1 chi bit cac duong ma `<?php` KHONG xuat hien, va do luong duong do rat hep: `.htaccess` chua `AddType application/x-httpd-php .jpg` (khong co the mo PHP nao — `waf_body_php` **mu hoan toan**) va duoi kep `x.php.jpg` khop `AddHandler`. Hai ca do la ly do file nay ton tai; phan con lai la cong them bang chung cho thu da bat duoc.
  - **Ba luat:** `upload_exec_ext` (duoi chay duoc o cuoi), `upload_exec_double` (duoi chay duoc KHONG o cuoi — `AddHandler` khac `SetHandler`, no khop bat ky duoi nao trong ten), `upload_config` (`.htaccess`/`.user.ini`/`php.ini`/`web.config`).
  - **Ba buoc chuan hoa, moi buoc bit mot duong ne DA BIET:** `basename` (ca `/` va `\` — PHP tren Linux coi `\` la ky tu ten file binh thuong nen `a\b.php` la MOT ten file duoi `.php`); `strip_tail` (`::$DATA` NTFS ADS, byte NUL cat chuoi, dau cach/tab/cham cuoi); `extensions` duyet MOI duoi tu phai sang, tran 6.
  - **Co y KHONG co luat "duoi la" hay "khong duoi".** Khach upload `.dwg`/`.ai`/`.sketch`/`.psd` va file khong duoi THAT. `.inc` cung khong vao bang — no khong duoc anh xa sang PHP handler mac dinh, chi nguy hiem qua LFI, ma LFI la duong `args.lua` gac. **Thu pha: them `.svg`/`.inc` vao bang => nhom "phai im" do 2 ca.**
  - **`.svg` tach RIENG, khong o P1 — va day la quyet dinh ve FP, khong phai ve muc do nguy hiem.** SVG nguy hiem o TRINH DUYET nan nhan (XSS), khong o server (RCE), va khach upload logo/icon SVG **that, hang ngay**. Mot luat chan `.svg` luc upload se chan dung viec do de doi lay viec KHONG bao ve duoc cac file SVG **da nam tren dia tu truoc** — tra gia FP cao nhat cho vung phu nho nhat. Bon lop phong ve that (sanitize / origin khong dung chung cookie / chi nhung `<img>` / CSP + `Content-Disposition: attachment`) deu la **cau hinh phuc vu file**, khong phai luat soi request — nen chung khong thuoc tang WAF. **Dinh chinh mot cho hay bi hieu sai:** CSP la lop YEU NHAT trong bon, khong phai manh nhat — `Content-Security-Policy` la header cua TAI LIEU, ma khi nan nhan mo thang `/uploads/x.svg` thi tai lieu CHINH LA file SVG do, va WordPress/Apache khong gan CSP cho no. Gac bang `contract_test` [28] chu khong chi bang chu thich: mot dong trong bang Lua thi de them, va nguoi them se khong doc CLAUDE.md truoc.
  - **`pack`/`unpack` nang V2 -> V3.** `unpack` gac bang `#f ~= 11`, nen mot ban `pack` moi gap `unpack` cu tra `bad_payload` — IM LANG, va **chi** voi than da spill, tuc dung nhom upload lon. [27c] kiem ca phien ban LAN so truong, vi khop phien ban mot minh khong bat duoc lech truong (thu pha: them mot `enc()` vao `pack` => do).
  - **Hai cho hong am tham da chan TRUOC khi deploy, khong phai sau:**
    - **`notable` trong `waf_logger`.** Cong nay quyet dinh dong `[waf-body]` co duoc ghi hay khong. Thieu `up_rule` o day thi mot upload `shell.php` khong kem bang chung nao khac se **khong sinh dong log nao** — va con so dung de quyet dinh nang trong so khoi 0 se thap di 20 lan, tuc phep do noi "khong co gi" ve dung thu no sinh ra de dem.
    - **`preload` trong hai bo test cu.** `body_core` gio `require "antibot.waf.upload"`, ma `args_test.lua` va `body_test.lua` chi preload `body_core`. Thieu cai thu hai thi `require` di tim theo `package.path` cua `resty` va hong ngay tu dong nap — truoc khi chay mot assertion nao.
  - **Test: `upload_test.lua` (55 assertion) + `body_test.lua` them 12 ca dau-cuoi + `contract_test` [27][28].** So assertion "PHAI IM" **nhieu hon** "phai ban", co y: dan so chay qua luat nay la kho anh va tai lieu cua khach. **Nam phep thu pha, nam lan do dung cho:** bo `strip_tail` => 4 duong ne do; bo vong duoi kep => 3 do; bo `basename` => `../.htaccess` do; them `.svg`/`.inc` => 2 do; lech truong `pack` => [27c] do. Tren code that: xanh.
  - **`upload_test.lua` co lap KHONG du, va do la ly do them 12 ca vao `body_test.lua`:** bo kia kiem `check_filename` tren mot chuoi, khong kiem gia tri co song qua BON chang `scan_disposition_headers -> scan_one_boundary -> filename_rule -> scan` voi mot than multipart THAT hay khong. Mot `return` danh roi `up_rule` se **xanh** o bo co lap va do o bo dau-cuoi.
  - **CHUA KIEM tren dan may nay:** bang `EXEC_EXT` dung tu tai lieu chung, khong tu `/usr/local/apache2/conf` cua 5 may. Lenh kiem nam trong chu thich `upload.lua` va trong muc nay — phai chay **truoc** khi nang trong so khoi 0.
  - **Con lai cho P2/F2:** webshell ma hoa (`eval(base64_decode(...))` khong the mo) can luat NOI DUNG. Va MIME lech duoi (`Content-Type: image/jpeg` kem `filename="x.php"`) hien chi ban vi duoi, chua ban vi **lech**.
- 2026-09-19 (4) — **P1 khởi động: `upload.lua` — soi TÊN FILE upload. Trọng số 0.**
  - **Vì sao P1 KHÔNG phải "đi từ 0 lên có", và đây là điều đáng ghi nhất:** `body_core.scan` đã có `php` (thân chứa `<?php`/`<?=`) và nó **đã** là tín hiệu **trọng số 50** (`waf_body_php`). Nên webshell PHP thuần **đã** bị bắt từ 05-09. Việc của P1 là bịt các đường mà `<?php` **không** xuất hiện: `.htaccess` với `AddType … .jpg` (không có thẻ mở PHP, `waf_body_php` mù hoàn toàn), và đuôi kép `x.php.jpg`. Hai đường đó là lý do P1 tồn tại — không phải "thêm mẫu cho chắc".
  - **Ba luật:** `upload_exec_ext` (đuôi chạy được ở cuối), `upload_exec_double` (đuôi chạy được **không** ở cuối — Apache `AddHandler` ánh xạ theo **bất kỳ** đuôi trong tên, nên `x.php.jpg` chạy như PHP trên cấu hình mặc định của nhiều bản), `upload_config` (`.htaccess` `.user.ini` `php.ini` `web.config`).
  - **Ba lớp chuẩn hoá, mỗi lớp đóng một đường né đã biết:** `basename` (cả `/` lẫn `\` — PHP trên Linux coi `\` là ký tự tên file bình thường nên `a\b.php` **là** đuôi `.php`), `strip_tail` (`::$DATA` NTFS ADS, byte NUL, khoảng trắng/dấu chấm cuối — Apache vẫn ánh xạ `shell.php.` sang PHP), `extensions` phải→trái tối đa 6. **Thử phá: bỏ `strip_tail` ⇒ 4 đường né mở cùng lúc, test đỏ đúng 4 dòng.**
  - **Bảng đuôi HẸP có chủ ý.** *(Đính chính cùng ngày — xem mục 19-09 (5): câu "`.inc` không được ánh xạ sang PHP handler mặc định" ở đây SAI. Số liệu `AddHandler` trên fleet cho thấy `.inc` đứng ngay cạnh `.php` trong cả ba dòng. Giữ nguyên câu sai ở đây, có dấu, vì xoá nó đi thì mục 19-09 (5) mất đối tượng.)* `.html`/`.htm` không chạy trên server. `.svg` xử lý riêng.
  - **`.svg` tách khỏi P1 — quyết định, không phải bỏ sót.** Nó là loại nguy hiểm **khác**: chạy ở trình duyệt nạn nhân (XSS), không ở server (RCE). Và khác ở chỗ đắt nhất: **khách upload logo/icon SVG thật, hàng ngày**. Một luật chặn `.svg` lúc upload sẽ chặn đúng việc đó, để đổi lấy việc **không** bảo vệ được các file SVG đã nằm trên đĩa từ trước — trả giá FP cao nhất cho vùng phủ nhỏ nhất. Bốn lớp phòng vệ xếp theo sức mạnh thật đã ghi trong mục riêng; **một đính chính đáng chú ý: CSP là lớp YẾU nhất**, không vì nó dở mà vì `Content-Security-Policy` là header của **tài liệu**, còn khi nạn nhân mở thẳng `/uploads/x.svg` thì tài liệu **chính là file SVG** — WordPress/Apache không gắn CSP cho nó. Muốn CSP có tác dụng phải gắn lên **chính response phục vụ file upload**, tức việc của nginx. Rẻ hơn cả ba lớp trên và chưa ai nhắc: `Content-Disposition: attachment`.
  - **`up_rule` là KÊNH RIÊNG, không tranh chỗ `return` với `arg_rule`.** `filename="shell.php"` **không** khớp mẫu nào của `check_args` — không `..`, không `php://`, không `%00` — nên gộp hai kết quả vào một `return` làm P1 biến mất ở đúng nhóm nó sinh ra để bắt. Ngược lại `filename="../../x.php"` khớp **cả hai** và lúc đó muốn cả hai số đếm.
  - **Chỗ hỏng-trong-im-lặng phải gác, và đã gác: `up_rule` đi qua 4 chặng** (`scan_disposition_headers` → `scan_one_boundary` → `filename_rule` → `scan`), mỗi chặng nhiều `return` sớm. Bỏ sót **một** cái thì tín hiệu mất im lặng ở đúng nhóm đó — tràn `MAX_PARTS` là ví dụ cụ thể: upload 70 phần có `shell.php` ở phần 3 thoát qua nhánh `n` và báo "không có gì". Đúng khuôn lỗi đã cắt 4 tháng của `wp_paths.mark()`. **`contract_test` [27a]** đòi mọi `return` trong `scan_one_boundary` có đúng 3 giá trị.
  - **`pack`/`unpack` nâng V2 → V3.** `unpack` gác bằng `#f ~= <số trường>`, nên thêm trường mà quên nâng phiên bản thì `pack` mới gặp `unpack` cũ trả `bad_payload` **im lặng**, và **chỉ** với thân **đã spill** — tức đúng nhóm upload lớn. Đổi phiên bản làm sự không khớp đó **có tên**. **[27c]** so cả phiên bản lẫn số trường (đếm `enc(` trong `pack`).
  - **`up_rule` vào cổng `notable` của `waf_logger`** — nó **không** sinh dòng `[waf]` (kênh riêng, không tạo `waf_hits`), nên thiếu bước này thì `BODY_SAMPLE` vứt 19/20 lượt và phép đo sẽ nói "không có gì" về đúng thứ nó sinh ra để đếm. Cùng lý do đã ghi cho `fn_rule`.
  - **Cột `uprule=` ghi RULE_ID, tuyệt đối không ghi tên file** — tên file do kẻ gửi điều khiển và thực tế mang token, email, đường dẫn nội bộ; `waf.log` là file text giữ 30 ngày. Cùng lý do đã không ghi thân request vào `matched=`. Đọc kèm `fntr=`: `uprule=- fntr=spill` là **chưa soi**, không phải sạch.
  - **Trọng số 0, và lần này nói rõ vì sao không đặt 50 ngay.** `.php` "gần như không có bản sao hợp lệ" là một **phỏng đoán** — đúng loại đã sai 6 lần trong phiên xây tầng body. Dân số chạy qua luật này là **kho ảnh và tài liệu của khách**. Chưa có một số đo nào từ dàn máy này về tên file upload. Cổng vào: đọc `uprule=` vài ngày.
  - **Hai bộ test preload thiếu module là lỗi sẽ chặn deploy — đã vá trước khi đẩy.** `body_core` nay `require "antibot.waf.upload"`, nên `body_test.lua` và `args_test.lua` (cả hai preload `body_core` bằng `dofile`) sẽ hỏng **ngay từ lúc nạp**, trước một assertion nào. Đúng họ lỗi đã chặn bản 19-09 ở cổng `[3b]`.
  - **`contract_test` [28] gác bảng đuôi:** `svg`/`inc`/`html`/`htm` **không được** nằm trong `EXEC_EXT`. Thêm một dòng vào bảng Lua thì rất dễ, và người thêm sẽ không đọc `CLAUDE.md` trước.
  - **Thử phá — 4 phép, 4 lần đỏ đúng chỗ:** (a) bỏ `up_rule` ở `return` của nhánh `MAX_PARTS` ⇒ [27a] đỏ; (b) `pack` V3 + `unpack` V2 ⇒ [27c] đỏ; (c) thêm trường vào `pack` mà quên sửa `#f` ⇒ [27c] đỏ với số trường cụ thể; (d) nhét `svg` vào `EXEC_EXT` ⇒ [28] đỏ. Thêm 5 phép phá trên chính `upload.lua` (bỏ `strip_tail`/`basename`/vòng đuôi kép, mở rộng bảng quá mức) ⇒ đều đỏ. **Bộ test 55 assertion mô phỏng chạy được tại chỗ bằng perl** vì máy dev không có Lua.
  - **Chưa chạy trên `resty`.** `luacheck.pl` 131/131 và `luabal.pl` 131/131 đều 0 lỗi, nhưng đó là kiểm **tĩnh**. Cổng thật là `deploy.sh [3b]` trên máy có OpenResty.
  - **Một chú thích sai tự bắt được lúc viết:** bản đầu của `upload.lua` ghi "đã kiểm `AddHandler` trên `/usr/local/apache2/conf` của dàn máy này" — **chưa hề**. Đã thay bằng lời thừa nhận chưa kiểm + lệnh `grep` cụ thể để kiểm trước khi nâng trọng số. Chú thích khẳng định một phép đo chưa làm là đúng loại câu làm người đọc sau tin sai.
- 2026-09-19 (3) — **Trạng thái tầng WAF ghi lại theo số đo của mã, vì bảng kế hoạch đã sai về chính mình.**
  - **Lỗi được sửa:** bản lộ trình khai `F1a`/`F1b` là *chưa làm*. Chúng đã chạy từ 05-09: `body.lua` 149 dòng gọi từ `init.lua:111`, luật áp lên thân ở `init.lua:137`, spill qua `body_core.lua` 596 + `body_worker.lua` 56 trên thread pool `antibot_waf_io`. **801 dòng đang chạy trên 5 máy** bị khai là chưa tồn tại.
  - **Nguyên nhân, và vì sao nó không phải chuyện bất cẩn:** tôi đọc hết 1.504 dòng lộ trình rồi tin **bảng trạng thái bên trong nó** thay vì `grep` mã nguồn. Cùng một họ lỗi với `ctx.xf_over`, `h2=`/`tls13=`, `ctx.ip_shared`, `ja3=` — *"không đọc được" bị thu thành "đã đọc và câu trả lời là X"*. Lần này nguồn không phải một cột log mà là một tài liệu; cơ chế y hệt. **Lần thứ năm.**
  - **Phòng vệ đặt vào chỗ đúng:** trạng thái nay nằm trong `waf/CLAUDE.md` — file nằm **cạnh mã**, kèm bốn lệnh `wc -l`/`grep` để đo lại — chứ không nằm trong một tài liệu ngoài cây nguồn, vốn không ai `grep` và không có gì buộc nó trung thực.
  - **Số đo 19-09:** mã tầng WAF **1.823 dòng**, test **3.059 dòng**. `waf/scripts/*.lua` nhiều hơn mã 1,68 lần.
  - **Và một đính chính ngay trong lúc viết mục này: bốn tín hiệu WAF, không phải ba.** Tôi định ghi "ba luật `args` = ba tín hiệu trọng số 0"; `grep` ra `waf_wp_path = 50`, `waf_body_php = 50`, `waf_arg = 0`, `waf_body_arg = 0`. `waf_body_php` **đã** rời mức 0 và tôi đếm sót. Số *luật* không bằng số *tín hiệu* — `args.lua` có 3 luật nhưng đổ vào **hai** tín hiệu khác nhau tuỳ nguồn (query string hay thân).
  - **Và một cái bẫy đếm nữa, bắt được lúc tự kiểm lệnh mình vừa viết:** lệnh xác minh tôi đặt vào tài liệu trả về **4** trong khi tài liệu ghi **3 luật**. Không phải cái nào sai cũng bỏ qua được — `arg_null_byte` `return` từ **hai** nhánh (byte NUL thô / mẫu văn bản `%00`), đúng chỗ trục `binary` tách ra. Ba rule_id, bốn `return`. Lệnh đã sửa thành `grep -o ... | sort -u`. Một lệnh xác minh sai còn tệ hơn không có lệnh nào — cùng lập luận đã gỡ ba lớp kiểm hôm qua.
  - **P2/F2 vẫn chỉ có 3 luật tham số**, không SQLi/XSS/RCE: `grep -niE 'union|select.*from|<script|eval\('` trên `waf/*.lua` trả về **0** dòng mã (một lượt duy nhất nằm trong chú thích giải thích vì sao **không** đi đường CRS).
  - **Thứ tự việc còn lại: P1 → F3 → P2/F2 → A.** P1 trước vì `body_core` đã parse multipart (header phần theo boundary, chuẩn hoá `filename`, `fn_rule`) nên phần thiếu là luật chứ không phải hạ tầng. F3 xếp trước P2/F2 vì nó là **công cụ gỡ FP**, mà P2/F2 là mục duy nhất còn lại có rủi ro FP cao — thêm luật payload trước khi có đường gỡ theo domain là làm ngược.
- 2026-09-19 (2) — **Hai công cụ đo/kiểm vào git: `measure.sh` và `luacheck.pl`. Và ba lớp kiểm bị GỠ vì báo sai — ghi lại để không ai dựng lại.**
  - **`waf/scripts/measure.sh` — bốn nhóm đo, chỉ đọc.** `cf` (lưu lượng qua reverse proxy + `proxy_spoof`), `ban` (phân bố TTL `ban:<id>`/`ban:<ip>`), `fleet` (chặn theo dải), `fp` (ứng viên false-positive). Nhận mốc thời gian dạng file hoặc chuỗi. **Vì sao vào git:** mỗi vòng đo trước là 30–40 dòng dán qua chat, và **ba lần** trong phiên lệnh SAI mà không ai thấy ngay — `grep -o 'ip=[0-9.]*'` trả rỗng, `grep 'ua="..."'` không bao giờ khớp (logger khử dấu nháy + khoảng trắng), `awk -v t=""` khớp MỌI dòng khi mốc rỗng rồi báo là "sau mốc". Trong git thì lệnh được review một lần, dùng nhiều lần, sửa một chỗ. Hai cảnh báo đọc kết quả in ngay ở đầu file: cột transport ghi `-` vì **tầng chưa chạy**, và `rown > 0` **không** chứng minh người thật (hằng số trên nhiều IP là dấu hiệu bot mang cookie cố định).
  - **`waf/scripts/luacheck.pl` — hai lớp kiểm tĩnh, đã thử phá cả hai.** Máy dev không có luajit/lua/node/python nên cổng cú pháp duy nhất là `deploy.sh` bước [2] trên máy thật; file này cắt ngắn vòng lặp "đẩy lên rồi mới phát hiện". **[1] cân bằng khối** — tách chuỗi/comment trước khi tokenize, long-bracket mọi mức `=`, `repeat...until` đóng bằng `until`. Thử phá: bỏ một `end` ⇒ ĐỎ, in ra khối còn treo; bỏ một `return` ⇒ vẫn xanh (đúng). **[2] gọi hàm của module đã `require`** — `local m = require "antibot.x.y"` rồi gọi `m.foo()` thì `x/y.lua` phải xuất `foo`. Thử phá: đổi `claims_good_bot` thành `claims_good_bot_TYPO` ⇒ ĐỎ với tên file và tên hàm. Bỏ qua module dùng `setmetatable`. **Kết quả: 129/129 file, 0 lỗi.**
  - **BA LỚP KIỂM ĐÃ GỠ, và cả ba đều do tôi viết rồi tự bắt được khi thử phá:**
    - **`luacheck` lớp [3] bản 1 — "file trong chuỗi phải tồn tại".** BÁO XANH cho đúng lỗi nó sinh ra để bắt: chạy từ gốc repo thì `antibot-core/x/y.lua` **tồn tại**, nên nó bỏ qua. Lỗi thật không phải "file không tồn tại" mà là "đường dẫn tương đối phụ thuộc `cwd`".
    - **`luacheck` lớp [3] bản 2 — "chuỗi phải được ghép với biểu thức neo".** 18 false positive: `contract_test.lua` giữ đường dẫn trong **bảng dữ liệu** rồi mới ghép `SRC .. $f` lúc dùng. Theo vết biến qua bảng và vòng lặp là việc của parser, không phải regex. **Gỡ hẳn** — một lớp hay báo sai sẽ bị tắt đi, và lúc đó còn tệ hơn không có.
    - **`contract_test` [25] mục 4 — "`logger.lua` phải nhắc chữ `transport` ở chú thích".** Ý kiến phong cách đội lốt bất biến; nó đỏ vì thiếu chú thích và **đã chặn một bản deploy hợp lệ**. Gỡ, kiến thức chuyển vào khối chú thích đầu `async/logger.lua`.
  - **Bất biến đó vẫn được gác, ở phạm vi hẹp hơn: `contract_test` [26].** Mọi `slurp(` trong **chính file test** phải neo vào `SRC`. Hẹp nhưng đúng file duy nhất đã mắc lỗi này, và **không báo sai** — đã bỏ comment trước khi quét (bản đầu khớp cả chuỗi ví dụ trong chú thích của chính nó, đúng lỗi mục [23] đã mắc cùng ngày). Thử phá: tái tạo lỗi 19-09 ⇒ đỏ đúng 1 lỗi; hiện tại ⇒ 0.
  - **Bài học phương pháp, ghi rõ vì nó lặp bốn lần trong một phiên:** một test/công cụ kiểm **chưa được thử phá thì chưa biết nó có tác dụng gì**. Ba trong bốn lớp ở trên "chạy xanh" trên code đúng — và hai trong số đó cũng xanh trên code **sai**. Phép thử duy nhất có nghĩa là: tái tạo đúng lỗi thật, xem nó có đỏ không.
  - **Vòng đo đầu bằng `measure.sh` phơi ra hai thiếu sót của chính nó — đã sửa.** Nhóm `fp` báo `UA/identity = 8` trên năm identity, mâu thuẫn với phép đo sáng cùng ngày (`= 1`). Truy ra: (a) mục [3] **cắt UA ở 60 ký tự**, mà phần phân biệt (`Chrome/120.0.6099.109` vs `.110`) nằm ngay sau chỗ bị cắt — tôi cắt dữ liệu trước khi đọc nó, **lần thứ tư trong phiên với cùng nguyên nhân**; (b) không có mục nào hỏi "`rown` có phải hằng số không", mà đó chính là dấu hiệu phân biệt bot mang cookie cố định với khách quay lại.
  - **Thêm mục [0] vào nhóm `fp`: đếm số IP và số domain trên giá trị `rown` phổ biến nhất.** Đo 19-09 trên cloud171-96: **`rown=0.12` trên 1.219/1.251 lượt `banned_ip` có cookie**, xuất hiện trên **ba dải IP và ba domain khác nhau** (`137.23.3.14`/`smartcarvn.com`, `84.8.253.11`/`baoduongmercedes.com`, `84.13.142.21`/`phutunglandrover.com`). Người thật không cho ra một hằng số trên nhiều IP/domain như vậy — đây là **một đàn bot mang cookie cố định**, và hai trong ba IP đó chính là các IP đã xác định sáng cùng ngày là bot xoay UA (50 UA / 1 domain / 12–13 identity). **Không phải FP.** Mục [5] mới in UA **đầy đủ, không cắt** của identity đông nhất, kèm IP+domain, để phân biệt "một máy đổi minor version" với "collapse thật".
  - **`rown >= 0.5` bị chặn = 0** trên toàn bộ log sau mốc ⇒ `auth_session_cap` đang làm đúng việc, không phiên đăng nhập thật nào bị chặn.
- 2026-09-19 — **Mục T khởi động: `contract_test.lua` [25] (bất biến thứ tự cờ) + `luabal.pl` (kiểm cân bằng khối không cần luajit).**
  - **Vì sao [25] tồn tại:** bốn ca "cờ đọc ở bước chạy TRƯỚC bước ghi" trong một phiên, **không ca nào** bị `luajit -b` hay `nginx -t` bắt (cú pháp đúng, ngữ nghĩa sai): `ctx.xf_over` (gán ở nhánh fall-through ⇒ 100% dòng bị chặn ghi `false`), `h2=`/`tls13=` (transport là bước cuối), `ctx.ip_shared`, `ja3=` (tôi đề xuất dùng nó tách client trên đúng tập `banned_id` — nơi nó **không thể** tồn tại). Mục [22][23][24] chặn ba ca **cụ thể**; [25] chặn **tính chất**, nên bắt được ca thứ năm chưa ai biết.
  - **Cách làm:** trích map `biến → file` từ các dòng `local X = require "antibot.a.b"`, trích thứ tự từ các bảng `STEPS_*` trong `init.lua`, rồi với mỗi cờ trong danh sách canh gác, so vị trí bước ghi với bước đọc. **Danh sách tường minh, KHÔNG tự quét mọi `ctx.*`** — một cờ có thể được ghi ở log phase hoặc bởi timer, và một test tự động sẽ báo đỏ hàng loạt rồi bị tắt đi, tệ hơn là không có test.
  - **NƠI ĐỌC PHẢI KHAI BẰNG FILE + BƯỚC, KHÔNG bằng biến layer — và chính lỗi này đã suýt lọt.** Bản đầu tôi khai nơi đọc là biến layer, và test **báo xanh cho một lỗi đang tồn tại**: `ip_shared` được đọc trong `l7/ban/ban_store.lua` nhưng tôi khai `ip_ban_check` — hai **file khác nhau** cùng nằm trong `l7/ban/`, và `ip_ban_check.lua` không chứa chuỗi `ctx.ip_shared` nên phép kiểm trả nil rồi bỏ qua. **Test luôn xanh còn tệ hơn không có test.** Nay mỗi nơi đọc khai `{ file, bước }`, và **fail-closed**: file không còn đọc cờ ⇒ ĐỎ (danh sách lạc hậu), không im lặng bỏ qua.
  - **ĐÍNH CHÍNH — chạy [25] đã bắt được chính tôi.** Tôi đã commit ở `d83758d` rằng "Fix B trong `ban_store.lua` là code chết vì cờ ghi ở bước 10 mà đọc ở bước 6". **Sai.** `ip_ban_check.lua` (bước 6) chỉ đọc `ban:<ip>` và **không gọi** `ban_store`; `ban_store.run` do `l7/init.lua` gọi, tức chạy theo `l7_layer` — **bước 15**, sau `ip_tour` (bước 11). **Thứ tự ĐÚNG.** Nguyên nhân đọc sai: hai file cùng thư mục `l7/ban/` nên tôi gán vị trí của file này cho file kia mà không truy đường gọi. Và `PFCOUNT iptour:ua:<ip>` = 0 cũng không chứng minh gì — khoá đó TTL **90 giây**, phép đo chạy nhiều giờ sau cửa sổ log. Đã sửa chú thích tại chỗ trong `ban_store.lua`.
  - **`luabal.pl` — kiểm cân bằng khối Lua không cần luajit.** Máy dev không có luajit/lua/node/python, nên trước khi đẩy code lên chỉ có `deploy.sh` bước [3] làm cổng cú pháp. Bộ đếm từ khoá bằng grep/awk đã cho kết quả **SAI ba lần** trong phiên: `elseif` chứa chữ `if` ⇒ đếm thừa; `for x in y do` có cả `for` lẫn `do` ⇒ thừa một; chữ `end`/`if` nằm trong chuỗi hoặc comment ⇒ lung tung. Cùng một file ra `+2` rồi `-2` tuỳ cách xử lý `elseif` — một bộ kiểm lắc như vậy tệ hơn không có, vì nó tạo niềm tin sai. Bộ mới tách chuỗi/comment **trước** khi tokenize, xử lý `do` theo ngữ cảnh, long-bracket mọi mức `=` (`[=[ ]=]` — `admin/init.lua` và `challenge/init.lua` nhúng cả trang HTML+JS vào đó), và `repeat...until` (đóng bằng `until`, không bằng `end`). **Kết quả: 129/129 file `antibot-core/` cân bằng.** Đã thử phá: bỏ một `return` ⇒ vẫn xanh (đúng, không đổi khối); bỏ một `end` ⇒ ĐỎ, exit 1, in ra khối còn treo.
  - **Giới hạn phải biết:** `luabal.pl` **chỉ** kiểm cân bằng khối. Không phải parser — không bắt được sai kiểu, sai tên biến, hay logic sai. `deploy.sh` bước [3] vẫn là cổng cú pháp thật.
  - **BẢN VÁ [25] ĐẦU TIÊN CHẶN DEPLOY — hai lỗi, cả hai của tôi.** Deploy 19-09 huỷ ở cổng `[3b]` với `175 qua, 5 hong`:
    - **Bốn lỗi "thiếu file" — đường dẫn tương đối.** Mục [20]–[23] của tôi viết `slurp("antibot-core/detection/...")` thay vì `slurp(SRC .. "detection/...")`. Trên máy dev tôi chạy thử bằng perl **từ gốc repo** nên đường dẫn đúng; `run.sh` chạy với `cwd` khác nên nó vỡ, và `slurp` trả nil ⇒ test báo "thiếu file" cho file đang tồn tại. Mọi mục cũ trong file đều dùng `SRC ..` — tôi đã không theo. **Bài học phương pháp: thử test bằng một runtime khác, từ một thư mục khác, thì chưa chứng minh gì về runtime thật.**
    - **Lỗi thứ năm là LỖI THIẾT KẾ TEST, không phải lỗi code.** Assertion "`logger.lua` phải nhắc chữ `transport` ở chú thích" là **ý kiến phong cách đội lốt bất biến** — nó đỏ vì thiếu chú thích, buộc người khác sửa **văn bản** mới deploy được, và nó đã chặn đúng một bản deploy hợp lệ. **Đã gỡ.** Nguyên tắc rút ra: test hợp đồng chỉ gác thứ **kiểm chứng được** — "một cờ đọc trước khi ghi" là sai khách quan; "một dòng chú thích thiếu" thì không. Kiến thức đó chuyển vào đúng chỗ: khối chú thích mới ở đầu `async/logger.lua` (cột transport `-` nghĩa là "chưa đo", không phải "đo rồi, âm"), kèm bốn ca đã đọc sai.
  - **Bộ chạy 5.050 ca CRS: ĐO XONG, CHƯA VIẾT — và lý do là thứ tự phụ thuộc.** Corpus có thật: 322 file YAML, **5.050 test case**, trong đó **1.000 test ÂM** (`no_expect_ids`) và 2.905 có body. Nhưng `expect_ids` trỏ tới **rule ID của CRS** mà ta **chưa nhập luật nào** (`IMP`/`P2` là giai đoạn 3): chạy bây giờ thì 4.050 ca dương đỏ hết — không vì code sai mà vì chưa có gì để bắn, còn 1.000 ca âm xanh hết cũng không nói gì. **Bộ chạy đầy đủ chỉ có nghĩa SAU `F2 + IMP + P2`.** Viết bây giờ là viết một thước đo cho thứ chưa tồn tại.
- 2026-09-13 — **`fim.sh`: `umask 077` + sua quyen file da ton tai.** Script truoc khong dat umask nen quyen phu thuoc umask cua root tung may — do 13-09: bon may 0640, rieng cloud183-139 0644. Tren shared hosting `manifest.full.txt` la danh muc DAY DU duong dan va kich thuoc file cua MOI khach hang tren may (13.636 dong tren 183-139); de 0644 thi PHP cua bat ky khach nao cung doc duoc ban do file cua tat ca khach con lai. Dat umask trong script chu khong chmod tay, vi may moi dung se lai sinh sai quyen; kem hai dong `chmod` vi umask khong dong toi file DA TON TAI.

- 2026-09-12 — **Giai đoạn 1 đóng: nối `waf_body_php` trọng số 50, bỏ hai cái còn lại.** Tầng thân request có **ba** bộ dò độc lập, và chỉ bộ dở nhất được nối vào điểm. Đo trên 5 máy, toàn bộ `waf.log` còn giữ:
  - `argrule` — 269 lượt, `arg_traversal fnm=0` là **24/24** có trạng thái phiên. FP thuần. **Giữ trọng số 0.**
  - `fnrule` — **6 lượt trên cả đàn máy** (riêng cloud28-246 quét 309.838 thân). Tín hiệu chết. **Không nối.** Ghi lại để không ai đo lại: `fnm` bị khoá sau `arg_rule` (`legacy_fnm` trả `nil` khi không có `at`), còn `fn_rule` chạy độc lập — và nó vẫn không bắt được gì.
  - `php` — **2.495 lượt**, và dân số hợp lệ nằm ở **đúng một** đường dẫn: `/wp-admin/async-upload.php`. Mọi thứ khác là đích scanner **không tồn tại** trên các site này: `/cgi-bin/php-cgi`, `/php-cgi/php-cgi.exe` (CVE-2024-4577), `/jquery-file-upload/server/php/`, `/module/ueditor/php/action_upload.php`, `/eoffice10/…/OfficeServer.php`. **Nối, trọng số 50.**
  - **Trọng số 50 có tiền lệ, không chọn bừa:** bằng `waf_wp_path` và bằng đúng mức FIM nâng tín hiệu lên (1.0 = 50 điểm) — **dưới CHALLENGE 55**, nên nó không bao giờ tự quyết một mình. Dân số FP duy nhất (quản trị viên upload media) đã được `auth_session_cap` che.
  - **`richness >= 0.5` KHÔNG phải "đã đăng nhập".** Đợt đo này bắt quả tang: một trình dò `/cgi-bin/php5` vẫn đạt ngưỡng đó. `session_richness` đo "có trạng thái" — bốn cookie rác cộng 500 byte là 0.80. Mọi phép lọc FP về sau phải căn cứ **đường dẫn**, không phải cột này.
  - **`waf_signal()` phải nối thêm**, nếu không client đã giải PoW cứ thế POST mã PHP mà cả tầng WAF không thấy gì. Chú thích cũ ngay dòng đó ghi *"KHÔNG gộp `ctx.waf_body` vào đây: đó là telemetry thuần"* — đúng ngày nó được viết, sai từ lúc tín hiệu có trọng số.
  - **Mục kiểm mới trong `contract_test.lua`: tín hiệu có trọng số phải có nơi GÁN.** Phép kiểm hai chiều cũ đối chiếu `compute.lua` với `init.lua` nên mù với ca tệ nhất — tên có trong cả hai, hợp đồng báo xanh, mà không dòng mã nào gán `ctx.<tên>`, tín hiệu vĩnh viễn bằng 0. Đó đúng là cách `wp_paths.mark()` chết im lặng bốn tháng.

- 2026-09-11 — **Bước `[7]` báo "OK" sai, và đó tệ hơn không có bước kiểm nào.** Nó đếm gộp mọi dòng cron chứa `fim.sh`, nên một máy **chỉ** đặt lịch tầng đầy, **mỗi ngày một lần**, vẫn được báo OK. Đó là ca có thật: `fim.log` trên một máy từ 09-06 đến 09-11 có sáu lần chạy `[full]` lúc 03:17 và **không một dòng `[hot]` nào**. Tầng đầy chạy thưa không thay thế được tầng nóng — WordPress `include` **mọi** `.php` trong `mu-plugins` trên **mọi** request, nên ở đó không có request nào để WAF chặn và FIM là phòng tuyến duy nhất. Nay đếm **theo từng tầng** (`--hot` / `check` không `--hot`), in thẳng các dòng cron khớp để thấy cả lịch, và cảnh báo riêng khi cron chứa **`baseline`** — thứ nguy hiểm nhất có thể đặt ở đó, vì nó công nhận mọi file hiện có là đáng tin, tức mỗi webshell vừa thả vào đều được hợp thức hoá ở lần chạy kế tiếp và FIM im lặng y hệt lúc nó khoẻ mạnh.

- 2026-09-11 — **FIM: cơ chế chống nhiễu thứ hai, theo THỜI GIAN.** Lượt chạy thật đầu tiên sau khi bật cron trên cả 5 máy đã lộ ngay nguồn nhiễu: `wp-content/wflogs/{attack-data,config-livewaf,config-transient,ips}.php` — file trạng thái của **Wordfence**, nó tự ghi liên tục — báo `HIGH` mỗi 30 phút, vĩnh viễn. `GROUP_MAX` không đỡ được vì nó gom theo **bề rộng** (4 < 5 nên mỗi file được liệt kê riêng như thể đến một mình). Thêm `$PREVCHG`: một đường dẫn `CHG` ở **hai lần quét liên tiếp** là file trạng thái ứng dụng, hạ xuống bậc `STATE` (không vào số "đáng chú ý", không vào mail cron, vẫn nằm đủ trong `$LOG`). **Không dùng danh sách tên thư mục** — danh sách tên sai cả hai chiều: nó không biết plugin cache thứ 50 tên gì, còn kẻ tấn công đọc được danh sách thì biết chính xác chỗ nào được miễn. Hai ràng buộc giữ cho nó không che việc thật: lần đổi **đầu tiên** luôn báo bậc đầy đủ, và **`NEW` không bao giờ bị hạ bậc** — đã chạy thử: `shell.php` thả vào đúng `wflogs/` vẫn ra `HIGH` và vẫn sinh key `waf:fimnew:`. Giới hạn đã biết, ghi thẳng trong mã: file đổi cách quãng không bao giờ bị hạ, và lần sửa **thứ hai** lên một file đang ồn ào sẽ rơi xuống `STATE` — kể cả `wp-config.php`.

- 2026-09-11 — **`vendor/` — xét rồi BÁC, không thêm luật.** Đo 6.371 lượt chạm `vendor/*.php` (chủ yếu CVE-2017-9841, PHPUnit `eval-stdin.php` `eval()` thân request). Hai lý do bác: (1) **5.132 lượt đã là 403** — tầng khác chặn rồi, luật mới chỉ đổi nhãn cho việc đã xong, đổi lấy rủi ro FP trên đàn máy trăm domain khách; (2) `uri:find("vendor/")` là **danh sách tên**, thấp hơn hẳn chuẩn của ba luật đang có — `dotfile_exposed` bắt theo **hình dạng**, `dump_exposed` theo **lớp hiện vật**, `wp_upload_exec` theo **bất biến cấu trúc**. Danh sách tên sai cả hai chiều: nó mù với `/libs/`, `/third_party/`, còn `/wp-includes/js/dist/vendor/about.php` ngay trong số liệu thì **có chữ `vendor` mà chẳng phải thư mục Composer nào** — đó là chỗ thả webshell. 119 lượt `200` **không** nghĩa là file có thật: `achaubook.com` trả 200 cho cả `/laravel/`, `/yii/`, `/zend/`, `/www/` lẫn đường dẫn scanner gõ sai thiếu một cấp `phpunit`, và `vantaiachau.vn` trả 200 cho tên ngẫu nhiên `z0d2hccc.php` — WordPress rewrite về `index.php`, đúng cái mơ hồ mà cột `exists=` sinh ra để khử. Việc của lớp này là FIM, không phải luật URI.

- 2026-09-05 (vòng 13) — **`thread_pool` bật. Vùng mù spill đóng thật, không còn là "đã viết nhưng chưa chạy".**
  - `nginx -V` trên cloud168-101 có `--with-threads` → bỏ dấu `#`. Đây là **thay đổi chức năng đầu tiên của `nginx.conf` kể từ 24-05** (`2784a93`); mọi lần đụng file này giữa hai mốc đó đều là chú thích.
  - **Cổng `[2b]` mới, chặn TRƯỚC rsync.** Điều kiện này khác mọi cổng khác ở chỗ nó phụ thuộc **bản build của từng máy**, không phải nội dung repo. Để `nginx -t` ở `[4d]` bắt thì cây `antibot-core` **đã** sync xong, nginx.conf bị khôi phục, script `exit 1` và không reload — máy đó chạy code cũ với cây mới trên đĩa, một trạng thái nửa vời. Chặn sớm thì không động gì cả.
  - Máy nào build thiếu: thêm dấu `#` vào dòng đó trong repo. Code tự báo `scan=nothread`, không hỏng gì.
  - Kiểm sau vài giờ: `grep -o 'scan=[^ ]*' /var/log/antibot/waf.log | sort | uniq -c` — `nothread` phải về 0.

- 2026-09-05 (vòng 12) — **Tách lõi Lua thuần, đọc được thân đã tràn ra file tạm, và bỏ bản cài đặt trùng.** Ba file: `body_core.lua` (lõi, không `ngx`), `body_worker.lua` (chạy trong thread), `body.lua` (lớp truy cập `ngx`).
  - **Vùng mù spill đã đóng.** `ngx.run_worker_thread` chạy Lua trong thread pool thật nên `io.open` + đọc trọn file không chặn event loop. Tôi đã nói "đừng xây" ở vòng 10 với lý do I/O chặn và log phase — cơ chế này đi vòng qua cả hai. Đây là vùng mù mà `client_body_buffer_size` **không bao giờ** đóng được (buffer 64K thì độn 65K).
  - **Ràng buộc kéo theo:** thread VM không có API `ngx`, nên lõi phải là Lua thuần — hết `ngx.re`. Giá: `body:lower()` cấp một bản sao trọn thân (50 MiB → 100 MiB cho một lần đọc). Đó là lý do `threads=2`.
  - **`thread_pool` để COMMENT trong `nginx.conf`.** Directive này chỉ tồn tại nếu OpenResty build với `--with-threads`; thiếu nó thì `nginx -t` hỏng → bước `[4d]` huỷ cả lần deploy. Không đánh cược với 43 domain để đổi lấy một tính năng đang ở trọng số 0. Cột `scan=nothread` nói chính xác bao nhiêu request đang thiếu; bước `[4e]` nhắc khi build có hỗ trợ.
  - **Cột `scan=` mới.** `php=-`/`argrule=-` nói "chưa soi" nhưng không nói *vì sao*, và với request không phải multipart thì `fntr` không mang được. Được miễn lấy mẫu.
  - **Parser thật thay regex.** `parse_parameters` xử lý quoted-string, quoted-pair, header folding, và giới hạn đúng vào tham số của `Content-Disposition`. Bắt được ba lớp regex không bắt: `name="x; filename=../../y"` (dấu `;` trong nháy không phải cú pháp), `X-Debug: filename=...` (header khác), và **nhiều `boundary`** trong một Content-Type — hợp lệ về cú pháp, parser khác nhau chọn khác nhau, nên quét mọi candidate và vẫn báo `bdup`.
  - **Sửa hai lỗi của vòng 11:** (a) đúng 64 phần + dấu đóng bị gắn `n` vì `--B--` cũng khớp `find(delim)` và cũng đứng đầu dòng — nay kiểm `close` trước trần; (b) POST multipart **thân rỗng** bị gắn `fntr=spill` vì nhánh đó gộp cả spill lẫn rỗng nhưng nhãn cứng là `"spill"` — nay `empty`.
  - **`len` không còn cắt.** Kiểm trọn giá trị, chỉ gắn cờ. Bản trước cắt ở 512 rồi mới kiểm — độn 512 byte là che được traversal.
  - **Một bản cài đặt, không phải hai.** `args.check` nay uỷ quyền xuống `body_core.check_args`. Hai bản đã lệch **thật**: bản `ngx.re` không `lower()` lại sau mỗi vòng giải mã, nên `%50hp%3A%2F%2Finput` giải ra `Php://input` và trượt mẫu chữ thường — một bypass hoàn chỉnh của `arg_php_wrapper` trên đường query string. Chiều uỷ quyền là ngược trực giác (`args` gọi `body_core`) vì bản Lua thuần là bản chạy được ở **cả hai** nơi. `contract_test` mục 4 chặn việc viết lại.
  - **Vùng mù mới, ghi ra chứ không giấu:** multipart **lồng nhau** — header phần con nằm trong thân phần cha. Và một **quyết định** cần biết mình đang chọn: `--Bxyz` không được coi là dấu phân cách (đúng RFC, chặn nội dung file tự chế ra phần); nếu có parser hạ nguồn khớp boundary theo tiền tố thì ta cắt *ít* hơn nó. Chưa kiểm được PHP xử lý ra sao.

- 2026-09-05 (vòng 11) — **Cắt part theo boundary. Trần 32 trước đây bị chính kẻ tấn công tiêu hộ.**
  - **Không phải chuyện nhiễu.** Quét toàn thân làm trần `MAX_FILENAMES` **vô nghĩa**: nhồi 32 chuỗi `filename="x.jpg"` vào *nội dung* phần 1, header thật ở phần 2 không bao giờ được soi. `fn_trunc="n"` làm nó **hiện ra** nhưng không làm nó **bị bắt**, và nâng trần không cứu được vì số lượng do kẻ tấn công quyết. Đây là **âm tính giả**, kích hoạt bằng cách sắp thứ tự field trong form.
  - **Đánh đổi, và hướng đánh đổi là có chủ ý.** Quét toàn thân có một ưu điểm thật: **không phụ thuộc parser**. Cắt theo boundary đẻ ra rủi ro lệch parser — đòi `\r\n` mà PHP chấp `\n` thì kẻ tấn công dùng `\n` và ta thấy một phần khổng lồ trong khi PHP thấy hai. Nguyên tắc: **bộ quét phải là tập cha của parser** — chỗ nào không chắc thì cắt *nhiều* hơn. Nên dấu phân cách nhận `\n--B` (chấp cả `\r\n--B` lẫn `\n--B` trần) và dòng trống nhận cả `\r\n\r\n` lẫn `\n\n`.
  - **Rẻ hơn chứ không đắt hơn** — đính chính điều tôi viết ở vòng 4. Một `find` chuỗi thuần cho boundary, rồi PCRE chỉ chạy trên vài trăm byte header thay vì trên toàn bộ 40 MB.
  - **Ba trần, ba nghĩa khác nhau** thay cho một `MAX_FILENAMES` vừa đếm vừa chặn chi phí: `MAX_PARTS=64`, `MAX_HDR_LEN=2048`, `MAX_FN_LEN=512`. Hai giá trị `fntr` mới: `nb` (không đọc được boundary — **báo ra chứ không lùi về quét toàn thân**, vì chạy âm thầm một thuật toán khác đúng là cái bẫy cả module này tránh) và `hdr`.
  - **Ưu tiên khi chạm nhiều trần** gom vào một hàm `worse()` xếp `len > hdr > n > stop` — bản cũ rải `if trunc ~= "..."` khắp nơi, chỉ so được với **một** giá trị và đã bỏ sót.
  - **Dấu đóng kết thúc `--B--` phải loại riêng.** Coi nó là một phần thì không tìm thấy dòng trống nào sau nó và `hdr` bắn trên **mọi** thân multipart lành — một báo động 100% giả.
  - **Vòng sau tìm từ đầu vùng header, không từ cuối.** Nhảy tới cuối nhanh hơn nhưng sai khi vùng header bị cắt 2 KB: cái cắt đó có thể nằm *vượt qua* dấu phân cách kế tiếp và thế là mất hẳn một phần — tức cắt **ít** hơn parser, đúng điều cả hàm đặt ra để tránh.
  - **Bộ test viết lại bằng thân multipart THẬT.** Bản cũ truyền một mảnh header trần không có dấu phân cách nào — nó chạy được chỉ vì bộ quét cũ quét toàn thân, tức bộ test không hề kiểm cái cấu trúc mà nó đang khẳng định.

- 2026-09-05 (vòng 10) — **`fntr=spill`: vùng mù bị giấu trong một nhãn vô can.**
  - Multipart đã spill trả `fn_trunc=nil` → in ra `fntr=-` = "không áp dụng", **giống hệt** một request không phải multipart. Nhưng trong body đó **có** tên file thật, ta chỉ không đọc được. Đếm "quét hoàn tất" = `count(fntr=0)` và "vùng mù" = `count(rx|len|n)` thì multipart đã spill **không rơi vào ô nào** — tổng hai ô không bằng tổng multipart, và cái thiếu đi đúng là cái bị bỏ qua. Lần thứ tư của cùng một dạng lỗi (`php = false`, `fntr` kiểu cờ, `fntr=0` hai nghĩa).
  - `wafstat` mục 7 in thẳng **tỉ lệ multipart không hề được soi**, kèm câu không đóng được bằng buffer.
  - **Không xây đọc file tạm.** Access phase là I/O chặn; log phase thì `io.open` được phép nhưng *file tạm còn tồn tại ở log phase hay không là chưa kiểm* — đúng loại giả định đã giết `wp_paths.mark()`. Và kể cả làm được thì không đáng: lỗ này thuộc `fim.sh` + `wp_upload_exec`, không phải của bộ đọc body.

- 2026-09-05 (vòng 9) — **Nháy không đóng ăn xuyên dòng, và `fntr=0` mang hai nghĩa.**
  - **Bỏ sót tự báo cáo là hoàn tất.** `[^"\\]` cho qua cả `\r` và `\n`, nên một `filename="` không đóng nuốt sang dòng dưới tới dấu nháy **mở** của header thật rồi đóng lại ở đó:
    ```
    ; filename="
    Content-Disposition: form-data; name=f; filename="../../shell.php"
    ```
    Giá trị bắt ra là một đoạn header vô hại, `filename=` thật **đã bị tiêu thụ** nên `gmatch` không còn thấy, và hàm trả `nil, false` — tức báo là **đã soi sạch**. Dạng lỗi nặng nhất trong module này: không phải một lần bỏ sót, mà một lần bỏ sót tự nhận là hoàn tất.
  - **Sửa:** `[^"\\\r\n]` và `\\[^\r\n]`. Dùng `[^\r\n]` chứ không phải `.` vì trong PCRE không có cờ `s`, dấu `.` vẫn khớp `\r`. Tên file thật không thể chứa CR/LF — header multipart kết thúc ở CRLF theo định nghĩa — nên loại chúng không mất gì. **Chưa dứt điểm:** một nội dung file có cả `filename="..."` trên *một* dòng vẫn đếm; đó là điều kiện chặn số 1.
  - **`fntr=0` mang hai nghĩa.** Hàm thoát ngay ở luật đầu tiên, nên `fnrule=X fntr=0` thật ra là "dừng lại vì tìm thấy", không phải "đã soi hết". Thêm giá trị `stop` thay vì một quy ước phải nhớ — quy ước là thứ bị quên đúng lúc đọc số liệu. `len` thắng `stop`.
  - Sáu test mới: ăn xuyên dòng (cả `fn_rule` lẫn `fn_trunc`), quoted-pair không thoát được xuống dòng, `stop`, và `len` thắng `stop`.

- 2026-09-05 (vòng 8) — **`fn_trunc` từ cờ thành lý do.**
  - `true` gộp ba nguyên nhân: mẫu hỏng, hơn 32 phần, tên file > 512 byte. Đúng nghĩa "không soi hết" nhưng **không đọc được** — ba ngày nữa nhìn `fntr=47` thì không biết làm gì, trong khi ba nguyên nhân đòi ba việc khác hẳn: `rx` sửa ngay, `len` tự nó đáng ngờ, `n` chỉ cần nâng trần.
  - Cột `fntr=` nay là `-` | `0` | `rx` | `len` | `n`. Chạm cả `len` lẫn `n` thì **`len` thắng** — nó là cái bất thường hơn, `n` một mình gần như luôn là lưu lượng lành.
  - `wafstat` mục 7 đếm riêng từng nguyên nhân kèm việc phải làm, thay cho một con số gộp.
  - Đổi được vì `fn_rule` **chưa từng chạy** trên production (mẫu không biên dịch từ `8dfafd2` tới `996c0d6`) — không có dữ liệu `fntr` cũ nào để giữ tương thích.
  - Ba giới hạn còn lại (quét toàn thân, spill không soi, `%2500` bảo thủ hơn RFC) giữ nguyên: đã ghi thành điều kiện chặn ở vòng 6, và cái cuối cố ý để đo trước.

- 2026-09-05 (vòng 7) — **Quoted-pair: cú pháp được phân tích, ngữ nghĩa thì không.**
  - Mẫu ở vòng 4 học nhánh `\\.` để khớp được `filename="abc\"..."`, nhưng giá trị bắt ra vẫn còn nguyên dấu `\` và đi thẳng vào `args.check`. Parser hạ nguồn bỏ dấu đó, nên `filename=".\./shell.php"` thành `../shell.php` và `filename="p\hp://input"` thành `php://input` — cả hai lọt vì dạng thô không có `..` liền nhau, không có `php://`.
  - Test `filename="abc\"../../x.php"` ở vòng 4 **không chứng minh được gì** cho lớp này: nó có sẵn `../` ở dạng thô nên bắn dù có bỏ escape hay không.
  - **Soi cả hai dạng, không thay thế.** Bỏ escape một cách phá huỷ đổi một lỗ hổng lấy một lỗ hổng: `..\..\shell.php` là traversal Windows thật khớp `\.\.[/\\]` ở dạng thô, và thành `...shell.php` — không khớp — sau khi bỏ dấu `\`. Không biết parser hạ nguồn đọc kiểu nào thì chạy luật trên cả hai cách đọc.
  - Giá bằng gần 0: một `find` byte thô, chỉ chạy khi dạng thô đã sạch **và** tên file có dấu `\`.
  - Sáu test mới: dấu chấm/gạch chéo/chữ đã thoát (chỉ bắn sau khi bỏ escape), Windows-style (chỉ bắn ở dạng thô), bỏ escape đúng một lần, và đường dẫn Windows hợp lệ phải im ở cả hai dạng.

- 2026-09-05 (vòng 6) — **Ghim mép `%2500`, và biến hai giới hạn đã biết thành điều kiện chặn.**
  - **Mép NUL:** `filename*=UTF-8''x%2500.jpg` giải một lần ra `x%00.jpg`, rồi `RX_NUL_ENC` vẫn bắn vì nó khớp `%00` dạng văn bản — tức riêng luật NUL đọc thêm một lớp và câu "giải mã đúng một lần" không thuần tuý. **Giữ hành vi, ghim bằng cặp test đối chứng** (`filename*=` bắn `arg_null_byte` / `filename=` im, vì `%2500` không chứa `%00`) để nó là quyết định chứ không phải tình cờ.
  - **Điều kiện chặn:** quét-toàn-thân và `fn_trunc` từ "giới hạn đã biết" nâng thành **ba điều kiện phải xử lý trước khi nâng trọng số**, và in thẳng vào output `wafstat` mục 7 — chỗ số liệu được đọc là chỗ chúng dễ bị quên nhất.
  - Điểm "không nuốt lỗi regex" đã làm ở vòng 5.

- 2026-09-05 (vòng 5) — **`RX_FILENAME` ở vòng 4 không biên dịch được. Cả `fn_rule` chết câm.**
  - Long string `[[...]]` của Lua **không xử lý chuỗi thoát**: cái gõ ra là cái PCRE nhận. Vòng 4 ghi `[^"\]` với **một** dấu `\` thay vì hai. Trong lớp ký tự, `\]` là dấu `]` **đã thoát** nên lớp không đóng, nó nuốt tiếp tới dấu `]` sau (trong `[^;"\r\n]`) và bỏ lại một `(?:` không đóng ⇒ **lỗi cú pháp toàn mẫu**.
  - Hậu quả: `ngx.re.gmatch` trả `nil`, code nuốt `err`, `fn_rule` trả `nil` cho **mọi** multipart. Cột hiện ra `fnrule=- fntr=-` — không phải "sạch", mà là "không có tầng nào chạy". Chính con đường bypass mà vòng 4 sinh ra để đóng thì vẫn mở nguyên.
  - **Sửa:** `[^"\\]|\\.` (nhân đôi dấu `\`); không nuốt `err` nữa — `ngx.ERR` một lần mỗi worker **và** trả `fn_trunc=true` để cột `fntr` mang tín hiệu liên tục.
  - **Test:** thêm một dòng ở **đầu** nhóm `fn_rule` kiểm *mẫu có biên dịch được không*. Mẫu hỏng làm cả mười dòng dưới đỏ cùng lúc và không dòng nào nói được nguyên nhân; dòng này nói.
  - **Cổng đã có sẵn và sẽ bắt được:** `deploy.sh [3b]` chạy `run.sh` bằng `resty` **trước** rsync. Máy dev không có Lua nên lỗi lọt được vào git, nhưng không lọt được lên server. Đây là lý do `[3b]` chặn trước rsync chứ không phải sau.

- 2026-09-05 (vòng 4) — **Bốn lỗ trong chính `fn_rule` vừa thêm.**
  - **FP thật:** `filename*=` đi qua vòng giải mã 3 mức của `args.check` trong khi RFC 5987 là percent-encoding **một lớp**. `a..%252Fb.txt` → giải 1 lần ra `a..%2Fb.txt` (tên file hợp lệ) → giải lần 2 thành `a../b.txt` và bắn. Nay giải đúng một lần rồi gọi luật với `decode=false`.
  - **Ba đường né tránh trong mẫu:** thiếu dấu phân cách trước `filename` (`myfilename="../x"` cũng khớp); không nhận khoảng trắng quanh `=`; `[^"]*` dừng ở nháy đã thoát nên `filename="abc\"../../x.php"` không được kiểm — và mitigation tôi ghi trong chú thích ("quét mọi lần xuất hiện") **sai**, vì ca đó chỉ có một lần xuất hiện.
  - **`fn_trunc`:** chạm trần 32 phần hoặc 512 byte nay báo ra thay vì im lặng trả `nil`. Nhồi 32 `filename=` giả vào nội dung file là đường né tránh thật.
  - **Ghi rõ `fn_rule` không bao gồm body spill** — upload lớn spill nhiều hơn nên tỉ lệ này không suy rộng được.

- 2026-09-05 (vòng 3) — **`fn_rule`: soi riêng tên file, độc lập với thân.**
  - Đóng đúng một bypass có thật: `filename*=UTF-8''..%2F..%2Fshell.php` lọt sạch vì thân multipart chạy `decode=false` trong khi giá trị RFC 5987 **là** percent-encoding.
  - Và tách `fnm` khỏi vai trò nó không làm được: `fnm` mô tả vị trí của lần khớp **được chọn**, nên lệ thuộc thứ tự NUL → wrapper → traversal. `fn_rule` chạy luật lên **chính giá trị tên file** nên đếm được.
  - **Giải mã có phân biệt:** `filename*=` giải mã, `filename=` không. Bừa cả hai thì `a..%2Fb.pdf` — tên file hợp lệ — biến thành `a../b.pdf` và bắn.
  - Vẫn là telemetry, trọng số 0, không đặt tín hiệu ctx. Nâng lên tín hiệu thật là quyết định sau, khi có số đếm.
  - **Miễn lấy mẫu** trong `run_body` — `fn_rule` không sinh dòng `[waf]` nên `[waf-body]` là nguồn duy nhất.

- 2026-09-05 (vòng review thứ hai) — **`cl=-` không đồng nghĩa chunked; `vfy=` cho cả dòng body.**
  - **Đính chính quan trọng nhất:** tôi đặt tên cột `cl=` là "chunked". Sai. Nó chỉ có nghĩa *"không có header Content-Length"* — cũng vắng trong HTTP/2, HTTP/3, request không body. Dàn máy này bật H2 và có hẳn một tầng vân tay H2, nên nếu phần lớn POST là h2 không kèm Content-Length thì phép chéo `spill × cl` **không trả lời được gì**. Thêm `te=` (Transfer-Encoding, chunked thật) và `proto=`; `wafstat.sh` mục 8 chéo cả ba.
  - **`vfy=` cũng vào dòng `[waf-body]`.** Một POST có `php=1` mà không luật nào bắn chỉ sinh dòng `[waf-body]`, không sinh `[waf]` — nên riêng nhóm body không biết `class=- richness=-` là do thoát fast-path hay lý do khác.
  - **Nói lại cho đúng về `filename*=`:** mới chỉ **nhận diện** (gắn `fnm=1` đúng khi trên dòng đó đã có một lần khớp thô), **chưa soi**. `filename*=UTF-8''..%2F..%2Fshell.php` vẫn lọt vì thân multipart chạy `decode=false`.
  - **`%00` trong thân nhị phân còn FP nhỏ:** `args.check` quét toàn bộ thân chứ không riêng header. Khi tính chuyện enforcement, chỉ coi `%00` + `fnm=1` là bằng chứng mạnh.

- 2026-09-05 — **`arg_null_byte` tắt cho thân nhị phân. Số liệu ngày đầu tiên từ hai máy.**
  - **Đo được:** 67/67 lượt `arg_null_byte` là byte NUL trong **nội dung file upload**, `fnm=0` cho cả 61 lượt multipart đo được. Cụm 7,3 KB / 47 KB / 80 KB lặp trên 13 domain không liên quan. Luật không phát hiện tấn công — nó phát hiện *"vừa có người upload file"*. Ở trọng số 50 thì mỗi ảnh sản phẩm đều +50 điểm. Cột `fnm` (thêm hôm 09-04) là thứ duy nhất phân biệt được điều này; không có nó thì chỉ thấy "65 lượt" và không có cách nào biết chúng là gì.
  - **Sửa:** `args.check(s, decode, binary)`. `binary` bỏ luật NUL, bật cho `multipart`/`other`. Hai luật kia giữ nguyên cho mọi family.
  - **Query string: 0 lượt** trên cả hai máy trong ~10 giờ, 43+ domain. 0 FP nhưng cũng 0 bằng chứng — `waf_arg` giữ trọng số **0** thêm một tuần. Đổi trọng số trên 43 domain vì một mẫu 10 giờ là loại quyết định cả tầng này được viết ra để tránh.
  - **Đánh dấu WordPress đã sống:** `waf:wphost:*` = 51, `waf:wproot:*` = 3 trên máy WordPress; 0/0 trên máy code tay (đúng — không có WP host nào). Đây là xác nhận cho lỗi cosocket-ở-log-phase đã chết câm 4 tháng.
  - **Máy code tay có giá trị đo khác hẳn:** `wp_root_unknown` = 0 (không host WP nào được đánh dấu) nhưng `dotfile_exposed` = 88/96 tổng số lượt. Bốn luật `wp_*_exec` **không** có cổng host nên scanner dò đường dẫn WordPress trên site không-WordPress vẫn làm chúng bắn — chỉ `wp_root_unknown` mới cần `is_wp_root`.
  - **Ba thứ hỏng mà đợt đo này lộ ra**, không thuộc tầng WAF nhưng ghi lại vì cùng một gốc *"thứ nằm trong repo không tự nó tới máy chủ"*: `nginx.conf` không nằm trong đường deploy (nên `client_body_buffer_size 64k` chưa bao giờ tới máy nào); `fim.sh` thiếu bit thực thi nên cron sẽ chết câm; `/var/log/antibot` để `drwxr-xr-x` và log do `io.open` tạo ra là `-rw-rw-rw-` — 8,9 GB `antibot.log` world-writable trên hosting chia sẻ. Hai cái sau đã vá (`44edc62`, `20b2263`).

- 2026-09-04 — **Chế độ quan sát trở thành quan sát thật + bốn lỗi telemetry từ bản review.**
  - **`waf_signal()` chỉ còn `waf_wp_path`.** Tín hiệu trọng số 0 (`waf_arg`, `waf_body_arg`) không còn vô hiệu cookie fast-path. Trước đó chúng đổi **luồng đi** của request mà không đổi điểm — client verified gửi `?f=../x` chạy hết pipeline rồi có thể bị tín hiệu khác đưa lên challenge, và `waf.log` ghi `rule=arg_traversal … final=challenge` như thể luật gây ra. `contract_test.lua` nay kiểm **hai chiều** theo trọng số nên hợp đồng tự bảo trì.
  - **`body.lua`: `len = spilled and -1 or 0`.** `-1` chỉ đúng cho spill (độ dài có thật, không đọc). Với "không có body / body rỗng" thì độ dài **đã biết** và bằng 0 — ghi `-1` ở đó là gộp "không biết" vào một giá trị, đúng lỗi đã sửa với `php = false`, và nó thổi phồng chính con số dùng để chọn `client_body_buffer_size`.
  - **`describe()`: marker `,+` sai ở đúng 9 tham số.** Hàm hỏi "phía sau còn `&` không" thay vì "có phải dừng vì chạm trần không": vòng thứ 8 đẩy `pos` tới tham số **cuối**, không còn `&`, nên 9 tham số hiện ra y hệt 8. Thay bằng cờ `truncated`, thêm test neo cả hai mép (7/8/9/10 + dấu `&` thừa).
  - **`describe()`: tham số key-only làm rò chính thứ hàm này sinh ra để che.** `?<token>` không có `=` thì cả chuỗi thành "tên" và bị ghi 32 ký tự đầu; whitelist ký tự **không** cứu được vì token base64 toàn `[A-Za-z0-9]`. Nay ghi `?`. Tên có `=` thì ép về `[A-Za-z0-9_.-]` (thay `_`, **không** băm — băm làm log mất tính đọc được ngay).
  - **Cột `fnm=` mới trên `[waf-body]`** — phân tầng, không phải luật. Tách "khớp trong `filename=`" (tấn công) khỏi "khớp trong nội dung" (FP) trên thân multipart, bằng phép kiểm *cùng dòng* chứ không phải cửa sổ nhìn-lui. Chỉ chạy khi `arg_rule` đã bắn ⇒ chi phí trên lưu lượng thường bằng 0. Đây là dữ liệu phải có **trước** khi nâng `waf_body_arg` khỏi 0 — thu hẹp luật trước khi đo là ra kết luận rồi mới tìm dữ liệu ủng hộ.
  - **`contract_test.lua` ghi rõ tính bất đối xứng của nó:** nó tìm chuỗi trong mã nguồn, không phân tích cú pháp Lua. **Báo đỏ ⇒ chắc chắn có lỗi. Báo xanh ⇒ không chứng minh được gì.** Một `name == "waf_arg"` nằm trong chú thích vẫn làm phép kiểm qua.

- 2026-09-02 (`0e27ae0`) — Ghi lại vì sao 94% tầng nóng là `wp-includes`/`wp-admin`. Chỉ chú thích. Chú thích cũ khai tầng nóng gồm "mu-plugins, web root, wp-content drop-in" — tức **nói dối về 94% thứ mình đang làm**, và người đọc sau sẽ cắt nhầm.
- 2026-09-02 (`822fb41`) — 4 lỗi làm tầng nóng chết ngay từ baseline. Glob không khớp → `find` trả 1 → `pipefail` giết pipeline; `scan_full` có y hệt lỗ đó; chốt an toàn tường minh thay chỗ chặn tình cờ của `pipefail`; vòng xác minh Redis so với hằng số `"1"` trong khi giá trị ghi là `1.0` → **báo hỏng ở mọi lần chạy dù Redis khoẻ** (lỗi do chính `99947ac` gây ra).
- 2026-09-02 (`99947ac`) — 3 thay đổi từ bản phản biện: khoá Redis theo **đường dẫn file thật** (giải quyết pointer/alias + subdomain + WP thư mục con cùng lúc), tầng nóng phủ WordPress trong thư mục con, **boost theo bậc gom theo slug** thay cờ bật/tắt.
- 2026-09-02 (`ceb6e40`) — Miễn `index.php` ở **mọi** thư mục con của `wp-content`, không chỉ một. Đo: 17/20 lượt `wp_theme_direct exists=1` là `themes/index.php`. Đặt **sau** nhánh block, nếu không webshell tên `index.php` dưới `uploads/` là đường thoát có tên.
- 2026-09-02 (`cccabf7`) — Gom mọi thành phần của tầng WAF về `antibot-core/waf/` (kể cả `fim.sh`, trước ở `nginx/scripts/`).
- 2026-09-02 (`d3bfd04`) — 4 P0: bỏ miễn trừ loopback, đóng bypass PATH_INFO ở luật root, chuyển đánh dấu WP-host sang log phase + gác trên file có thật, thêm cột `exists=`/`final=`.
- 2026-09-02 (`a253016`) — FIM báo tín hiệu sang WAF: **nâng, không chặn**.
- 2026-09-02 (`1fe98d9`) — Hai tầng FIM: đóng cửa sổ mù 24 giờ mà không trả giá 27 giây mỗi lần.
- 2026-09-02 (`728dcd6`) — `fim.sh`: thứ duy nhất thấy được 3 lỗ mà luật URI mù.
