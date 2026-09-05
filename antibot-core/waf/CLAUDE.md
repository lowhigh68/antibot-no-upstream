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

64k là **mốc khởi đầu, không phải kết luận**. Cột `blen=`/`spill=` sẽ cho phân bố thật để chỉnh lại có căn cứ.

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

**Đã tính đến:** nhiều phần (quét hết, tấn công thường ở phần cuối); ba dạng cú pháp (`filename="x"`, `filename=x`, `filename*=`); không phân biệt hoa thường; nháy thoát `\"` (quét mọi lần xuất hiện nên vẫn bắt được ở lần sau); chặn số lượng 16 và độ dài 512; dùng cờ `i` của `ngx.re` thay vì `body:lower()` để khỏi cấp phát thêm 80 KB mỗi POST; nhóm không tham gia của `ngx.re` trả `false` chứ không phải `nil`.

**Giới hạn đã biết:** quét toàn bộ thân chứ không riêng dòng `Content-Disposition`, nên một file văn bản có **nội dung** chứa chuỗi `filename="../x"` (file log, chính bộ luật WAF) sẽ bị đếm. Hiếm, và đo được — để nguyên rồi đọc số liệu, đừng thu hẹp trước khi biết nó có thật hay không.

**`fn_rule` được miễn lấy mẫu** trong `waf_logger.run_body`. Bắt buộc: nó **không** sinh dòng `[waf]` (không tạo `waf_hits`), nên dòng `[waf-body]` là nguồn duy nhất của nó — quên là vứt 19/20 lượt.

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

## Update log

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
