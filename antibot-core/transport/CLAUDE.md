# transport/

TLS + HTTP/2 fingerprint capture. Runs at access phase (NOT during handshake — that's `ssl_*_by_lua_block`).

## Purpose
Compute JA3/JA3S/H2 fingerprints from data captured during SSL handshake (stored in shared dict bridge), populate `ctx.ja3*`, `ctx.tls13`, `ctx.h2_*`.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `tls.run(ctx)` → `http2.run(ctx)` |
| `tls/init.lua` | Calls `ja3.run(ctx)` + `ja3s.run(ctx)` |
| `tls/ja3.lua` | `capture()` runs in `ssl_client_hello_by_lua_block` — parses ClientHello extensions, stores in `lua_shared_dict antibot_tls` keyed by md5(client_random). `run(ctx)` reads from dict at access phase, computes JA3 hash, sets `ctx.ja3`, `ctx.ja3_raw`, `ctx.ja3_partial` (true when no cipher list — constant in no-stream arch), `ctx.tls13` |
| `tls/ja3s.lua` | `capture()` runs in `ssl_certificate_by_lua_block` — captures negotiated cipher + version. `run(ctx)` sets `ctx.ja3s`, `ctx.ja3s_raw`, `ctx.tls_cipher` |
| ~~`tls/ja3_stream.lua`~~ | **ĐÃ XOÁ 2026-09-06.** Đọc ClientHello ở tầng `stream{}` preread, mà repo này không có `stream{}` (`grep -rn 'preread\|^stream' nginx/` → rỗng) ⇒ luôn trả nil. Giữ lại chỉ tạo cảm giác cipher list "có đường lấy" |
| `http2/init.lua` | Inspects HTTP/2 settings/headers → `ctx.h2_sig`, `ctx.h2_order`, `ctx.h2_bot_confidence` |

## Cross-phase bridge — RELAY 2 NHỊP

> **MÂU THUẪN CHƯA GIẢI, ghi 2026-09-06.** Câu "`ngx.ctx` does NOT persist" bên
> dưới **mâu thuẫn với chính code trong thư mục này**: `ja3s.capture()` ghi
> `ngx.ctx.tls_ja3s` ở `ssl_certificate_by_lua`, rồi `ja3s.run(ctx)` đọc lại nó ở
> access phase ([`tls/ja3s.lua`](tls/ja3s.lua)). Một trong hai điều phải sai:
> hoặc `ngx.ctx` CÓ đi xuyên phase (⇒ câu này sai, và cầu shared-dict theo IP là
> phức tạp thừa), hoặc nó KHÔNG (⇒ `ja3s` chết từ đầu). **Không ai phát hiện được
> vì không module nào tiêu thụ `ctx.ja3s`** — xem mục Update log.
> Lưu ý riêng cho HTTP/2: một kết nối TLS chở NHIỀU request, mà `ngx.ctx` là
> per-REQUEST; nên kể cả khi nó đi xuyên phase, chưa chắc đã tới được request
> thứ hai trở đi. Phải đo bằng request thật, không suy luận.

`ssl_client_hello_by_lua` → `ssl_certificate_by_lua` → `access_by_lua` are SEPARATE Lua VMs. `ngx.ctx` does NOT persist. Bridge = `lua_shared_dict antibot_tls`.

**`get_client_random()` trả 32 byte 0 ở phase ClientHello** (đo 2026-07-31) — OpenSSL chưa nạp. Không dùng nó làm khoá ở phase đó được. `ngx.var` cũng bị disable ở phase đó. Nên:

| Nhịp | Phase | Khoá | Việc |
|---|---|---|---|
| 1 | `ssl_client_hello` | `tlsq:<md5(raw_client_addr())>` TTL 15s | parse ClientHello (chỉ phase này có `ngx.ssl.clienthello.*`), ghi tạm |
| 2 | `ssl_certificate` | → `tls:<md5(client_random)>` TTL 300s | `ja3.relay()` gọi từ `ja3s.capture_unsafe()`; `client_random` đã nạp (`zero=false`) → re-key + xoá entry tạm |
| đọc | `access` | `tls:<md5(client_random)>` | `ja3.run()` |

Khoá tạm theo IP chỉ sống giữa hai callback của **cùng một handshake** (micro giây) → NAT chung IP không nhầm fingerprint. `get_random_key()` **từ chối** chuỗi toàn 0: thà mất JA3 còn hơn để mọi client zero-random đọc chung một ô.

`relay()` đặt trong `ja3s.capture_unsafe()` để **không phải sửa 99 per-domain conf** — đổi lại: `ja3s.lua` giờ là dependency của đường JA3.

## ctx fields written
`ja3`, `ja3_raw`, `ja3_partial`, `ja3_cipher_src`, `tls_version`, `tls13`, `ja3s`, `ja3s_raw`, `tls_cipher`, `h2_sig`, `h2_order`, `h2_bot_confidence`

## ctx fields read
`ip`, `port` (for ja3_stream lookup), `ua`

## Flow
1. `ssl_client_hello_by_lua_block` (in **default server only** — hostname.conf) → `ja3.capture()` writes to shared dict
2. `ssl_certificate_by_lua_block` (per-domain conf) → `ja3s.capture()` writes to ngx.ctx (per-handshake)
3. `access_by_lua_block` → `transport.run(ctx)` → reads dict + ngx.ctx → populates ctx.ja3*

## Related
- Upstream: nginx SSL handshake phases write to dict
- Downstream consumers: `intelligence/scoring/compute.lua` (signals `ja3_*`, `h2_*`), `detection/cluster/`, `detection/anomaly/`

## Important rules
- **`ssl_client_hello_by_lua_block` phải có ở MỌI server 443 — hoặc không server nào.** Callback vũ trang qua SSL_CTX của **default server**; nhưng khi chạy, OpenResty phân giải SNI TRƯỚC rồi tìm directive trong **chính server khớp SNI** → thiếu = `[alert] no ssl_client_hello_by_lua* defined in server <name>` = **huỷ bắt tay TLS**. Nửa vời ⇒ sập HTTPS đúng những domain thiếu. **KHÔNG đặt được ở `http{}`** (kế thừa xuống server port-80 → `[emerg] no ssl configured for the server`). Pre-flight bắt buộc: `nginx -T | grep -c '^[[:space:]]*ssl_certificate_key'` phải BẰNG `nginx -T | grep -c '^[[:space:]]*ssl_client_hello_by_lua_block'` (tiền tố `^[[:space:]]*` để không đếm nhầm dòng comment). Xem `memory/feedback_default_server.md`
- `ssl_certificate_by_lua_block` for `ja3s.capture()` is OK in non-default per-domain confs
- `JA3_PARTIAL_PENALTY = 0` in engine.lua — no-stream arch never captures cipher list, ja3_partial is architectural constant not a bot signal
- Modules MUST export both `_M.capture` and `_M.run` — replacing with no-op breaks transport pipeline (`attempt to call nil`)

## Update log
- 2026-09-08 — **Cửa thứ tư của cùng một con bug: RANH GIỚI API.**
  - Ba cửa trước đều nằm trong parser (`"?"` giải mã thành `false`, thân 0 byte, thân khai độ dài 0). Cửa này nằm **ngoài** parser: `get_client_hello_ext` trả `nil` khi extension **vắng** và `nil, err` khi **đọc lỗi**, mà cả bốn chỗ gọi đều chỉ nhận giá trị đầu. Lỗi API biến thành "extension không tồn tại".
  - Giá từng chỗ khác nhau, và hai chỗ giữa mới là chỗ đắt: `0x002b` → `tls13=false` → nhánh `tls12` → **19,25 điểm oan**; `0x000a`/`0x000b` → `nil` rơi qua `if ... then` mà **không chạm `ext_ok`** ⇒ công bố một JA3 **thiếu extension** là **đầy đủ**, tức chính điều kiện đang chờ để lật nấc cipher sang `"on"`.
  - Hai nhánh `pcall` mất giá trị thứ ba (`pcall` trả `true, nil, err`). Hành vi vẫn an toàn — `ext_ok` giữ `false`, cipher giữ `partial` — nhưng **hỏng im lặng**: không dòng nào nói vì sao danh sách rỗng. `shape="api_err"` tách khỏi `shape="nil"` để 7 ca đo được trên cloud28-246 hôm 07-09 có nghĩa.
  - **Chỉ coi giá trị thứ hai là lỗi khi giá trị đầu là `nil`.** Nhờ vậy đúng dù hợp đồng lua-resty-core có khớp tài liệu hay không: API không bao giờ trả err thì các nhánh mới chết, chứ không đọc nhầm một giá trị phụ thành lỗi.
  - `contract_test` mục 14 gác cả bảy chỗ. Là kiểm **nguồn** chứ không phải kiểm hành vi — hai nhánh này cần `ngx.ssl` thật, `resty` trần không dựng được — nên nó chỉ chặn việc quay lại kiểu viết cũ, **không** chứng minh hành vi đúng.
- 2026-09-06 — **Đo JA3 trên 5 máy. Xoá `ja3_stream.lua`. Sửa cột `ja3p=` đang nói dối.**
  - **Cột `ja3p=` KHÔNG đọc được như xưa nay vẫn đọc.** `async/logger.lua` viết `tostring(ctx.ja3_partial or false)`, mà `ja3.lua` đặt `ja3_partial = nil` ở **cả bốn** nhánh không tính được JA3 ⇒ `nil` sập thành `false` ⇒ **`ja3p=false` trông như "JA3 đầy đủ" nhưng thật ra là "chưa từng có JA3"**. Vì `is_partial` luôn true khi tính được, **số JA3 đầy đủ trên toàn đàn máy đúng bằng 0** — trong khi log hiển thị 26–99% "false". Nay ba trạng thái tách bạch: `true` = thiếu cipher, `false` = đầy đủ, `-` = không có JA3. Cùng con `false`-vs-`nil` đã cắn ở `waf/body.lua` (`php = false`).
  - **`ja3_stream.lua` ĐÃ XOÁ.** Không có `stream{}` / `preread` ở đâu trong repo, và file tự CLAUDE.md của nó đã ghi "always returns nil". Giữ lại chỉ tạo cảm giác cipher list có đường lấy. `is_partial = true` viết thẳng, hành vi **không đổi**.
  - **`get_client_hello_ciphers()` CÓ trên cả 5 máy** (OpenResty 1.29.2.3 / 1.31.1.1, lua-resty-core 0.1.33 / 0.1.34). Nghĩa là lấy được cipher NGAY trong `ssl_client_hello_by_lua`, **không đụng tới mô hình OpenResty→Apache**. Đánh đổi "no-stream" là thật và có chủ ý, nhưng nó **không còn buộc** JA3 phải partial.
    - **CHƯA BẬT — bật là thay đổi chính sách, không phải sửa lỗi.** `ja3_db.lua` và `ja3_allowlist.lua` đều gác `ja3_partial`, nên chúng **chưa từng chạy một lần nào**. Có cipher ⇒ `is_partial=false` ⇒ **cả hai bật cùng lúc trên toàn đàn máy**, mà `ja3_allowlist_miss` nặng **50**. Thêm nữa hash JA3 đổi ⇒ `fp_light` đổi một lượt ⇒ `sess:` mồ côi, `ban:` hết khớp, counter reset (đã cảnh báo ở `antibot-core/CLAUDE.md` 2026-07-31). Cần đo phân phối trên người dùng đã verified trước, và bật ở chế độ quan sát.
  - **`lua-resty-core >= 0.1.25` trên cả 5 máy** ⇒ `get_client_hello_ext_present` trả **mảng**, thứ tự extension được giữ. Nhánh cảnh báo "ext_present is hash — order lost" trong `ja3.lua` **không hoạt động** (và nó ghi ở `ngx.WARN` nên vô hình dưới `error_log` mức `error`).
  - **JA3 chũn KHÔNG phải vấn đề của đàn máy này** — giả thuyết "Chromium randomize thứ tự extension làm `fp_light` chũn" **bị dữ liệu bác bỏ**:

    | Máy | 1 JA3 duy nhất | ≥5 JA3 | TB/client | max |
    |---|---|---|---|---|
    | cloud171-96 | 97,9% | 0,0% | 1,03 | 15 |
    | cloud183-139 | 96,5% | 0,2% | 1,06 | 125 |
    | cloud168-101 | 96,8% | 0,9% | 1,14 | 160 |
    | cloud28-246 | 95,7% | 1,2% | 1,26 | 457 |
    | cloud186-126 | 89,8% | 4,5% | **1,68** | 374 |

    Cùng client + cùng phút mà vẫn nhiều JA3: 0,7–3,0%. `max` hàng trăm gần như chắc chắn là **artefact của hàm định danh**, không phải JA3 bất ổn: `id = md5(ip+ua)` nên sau CGNAT, hàng trăm điện thoại cùng UA Chrome bị gộp thành **một** `id`, mỗi máy một JA3. cloud186-126 cao gấp rưỡi phần còn lại — nếu muốn đụng tới đây thì đo riêng máy đó trước.
  - **`ja3s` sinh hằng số `d8eada1de0f744e8f2d11cc5ea02451d` = MD5("0,0,")** (đã tự tính lại để xác nhận). Hai lỗi API, cả hai xác nhận bằng bộ dò trên máy thật:
    - `ssl.get_tls1_version()` trả **số** `0x0303`, mà `VER_MAP` tra bằng khoá **chuỗi** `"TLSv1.2"` ⇒ `version = 0`. Tên biến là `ver_str` — ý định ban đầu là `get_tls1_version_str()`, và hàm đó **có tồn tại**.
    - `ngx.ssl.get_cipher_name` **KHÔNG TỒN TẠI** (bộ dò xác nhận trên cả 5 máy) ⇒ `cipher_id = 0`. Phải dùng `ngx.var.ssl_cipher`.
    - **Tác động hôm nay bằng 0 vì không module nào tiêu thụ `ctx.ja3s`.** Đó cũng chính là lý do nó sống được lâu như vậy — cùng loại với `canvas_change` (xem `memory/project_dead_signals.md`).
  - **CẢNH BÁO cho ai định dọn `ja3s`:** `ja3s.capture()` là **nơi chở `ja3.relay()`** — nhịp 2 của cầu JA3, đặt ở đó có chủ ý để khỏi sửa 99 per-domain conf. **Xoá `ja3s` là JA3 chết theo.** Một bản review bên ngoài đã đề xuất "dừng dùng JA3S" làm bước ĐẦU TIÊN của lộ trình; làm đúng thế là mất JA3 toàn đàn máy.
- 2026-08-01 — **`http2/signature.lua`: nhánh "không có H2" trả 0 thay vì +0.15.** Không có H2 thì tầng H2 **không quan sát được gì** → `h2_bot_confidence = 0`. Mâu thuẫn "UA khai trình duyệt mà không có H2" là mâu thuẫn **giữa các tầng**, thuộc `intelligence/correlation/consistency_check.lua` và đã tính ở đó — trước đây cộng cả hai nơi mà hai signal cùng weight 55. Cùng đợt còn gỡ `h2_bot_pattern`/`h2_tls_mismatch` khỏi `mismatch` (chúng là quan sát thô của tầng H2, `signature.lua` đã tính +0.40/+0.25). **Ranh giới sở hữu:** `h2_bot_confidence` = quan sát của tầng H2; `mismatch` = mâu thuẫn UA↔tầng. Đo trước khi sửa: `block → challenge` 54/171, `block → allow` **0**. Chi tiết ở `intelligence/CLAUDE.md` 2026-08-01 (3).
- 2026-07-31 (4) — **Đường cứu cho handshake NỐI LẠI PHIÊN (promote ở access phase).**
  - Sau relay 2 nhịp, JA3 đã per-client thật (phân bố hàng chục hash, hash phổ biến nhất chỉ 16%) nhưng phủ chỉ ~14%. Phân rã miss: **`dict_miss` 143/173**, `no_bridge_key` 30 mà **27 là `scheme=http`** (cổng 80, không có TLS — đúng thiết kế), `zero client_random` = **0**.
  - **Nguyên nhân:** `keepalive_timeout 65` → kết nối rảnh 65s bị đóng → client tái kết nối liên tục; per-domain conf có `ssl_session_cache shared:SSL:10m` → phần lớn lần tái kết nối là **nối lại phiên**; nối lại phiên **không gửi certificate** → certificate callback không chạy → **nhịp 2 không chạy**. Đây là **điểm mù của `relay_miss`**: nó chỉ log khi relay *có chạy* mà thiếu entry tạm — relay không được gọi thì không có dòng nào (`relay_miss no_tmp` chỉ 2).
  - Vì sao KHÔNG phải TTL: để `TLS_KEY_TTL=300s` gây miss thì request phải đến sau 300s kể từ handshake, trong khi kết nối rảnh 65s đã đóng — tức phải duyệt liên tục >5 phút. Có, nhưng không thể chiếm 83%. **Nâng TTL là sửa nhầm chỗ.**
  - **Fix:** `run()` khi trượt khoá thật thì đọc entry tạm `tlsq:<md5(binary_remote_addr)>` (callback ClientHello **vẫn chạy** khi nối lại phiên) rồi thăng cấp sang khoá thật. `TMP_KEY_TTL` 15s → **5s** để thu hẹp cửa sổ va chạm NAT — đó là cái giá phải trả: hai client sau cùng một NAT cùng nối lại phiên trong 5s có thể nhận fingerprint của nhau. Nhịp 2 vẫn xoá entry tạm cho mọi handshake mới nên phần dư nhỏ.
  - **KẾT QUẢ (đo cửa sổ 5 phút):** `capture_ok` 6 / `relay_ok` 5 / `promote` 5 / `run_miss` 1. `promote` **ngang** `relay_ok` ⇒ khoảng **một nửa handshake không chạy certificate callback** ⇒ **giả thuyết nối lại phiên được xác nhận**, và **đường promote đang gánh một nửa lượng JA3 — không được gỡ.** Phủ sóng `ja3=-` 2570/3000 → 1255/3000.
  - **Phần `ja3=-` còn lại là ĐÚNG THIẾT KẾ**, không phải miss: `banned_ip`/`banned_id` thoát ở `init.lua` `ip_ban_check`, `ip_whitelist` ở `access_layer`, `fleet_dyn_block_24` ở `fleet_check_block`, `device_canvas_verified` ở fast-path cookie — **tất cả đều đứng TRƯỚC `transport_layer` trong `STEPS_COMMON`**. Phần còn lại (`reason=score=NN`) là traffic **cổng 80**, không có TLS.
  - **BẪY ĐO ĐẾM (đã sập 2 lần trong cùng phiên):** các counter chẩn đoán là **per-worker** và mỗi worker đều log ở `n=1`. **`max_n` qua nhiều worker KHÔNG phải tổng** — đọc kiểu đó cho ra "promote ≤200 lần, bỏ đi được", ngược hẳn sự thật. Cũng không so được `capture_ok` với `relay_ok` bằng `max_n` khi hai counter bắt đầu ở hai lần deploy khác nhau. **Luôn đếm số DÒNG LOG trong CÙNG một cửa sổ thời gian** (`awk -v t="$(date '+%Y/%m/%d %H:%M' -d '-5 min')" '$0 >= t'`), vì mọi counter dùng chung rate-limit 1/200 nên số dòng so tương đối được.
- 2026-07-31 (3) — **RELAY 2 NHỊP: JA3 lần đầu thực sự per-client.**
  - **Bug gốc, đo được:** `capture_ok len=32 zero=true hex=00000000` trên **mọi** handshake ⇒ `md5(32 byte 0)` = hằng số `70bc8f4b` ⇒ cả dict 10MB chỉ có **1 entry** (`dict=[tls:70bc8f4b]`, `sort -u | wc -l` = 1). Access phase tính ra random THẬT nên không bao giờ khớp.
  - **Điều nguy hiểm hơn con số miss:** ~20% request "có ja3" là những request mà access phase **cũng** trả zero → chúng đọc trúng ô hằng đó và nhận fingerprint của **một handshake bất kỳ**. Dấu hiệu nhận ra: mọi log đều cùng một hash `a28e27c779593eee5cfe3f9001e50945`. **Một hash JA3 giống hệt nhau trên nhiều client khác nhau = khoá cầu nối hỏng, không phải "JA3 đã chạy".**
  - **Tác hại lan xuống:** `detection/cluster/tls_cluster.lua` đếm `cluster:tls:<ja3>` → ja3 hằng làm counter chạm trần `tls_count_normalize_max` → `cluster_score` bị cộng thuế cố định cho đúng nhóm ~20% đó.
  - **Fix:** relay 2 nhịp (xem bảng ở mục Cross-phase bridge). `ja3s.capture()` được bọc `pcall` — trước giờ **chưa có**, dù chạy trong `ssl_certificate_by_lua` của mọi per-domain conf: cùng loại mìn đã nổ 2026-04-22.
  - **Còn phải đo:** handshake **nối lại phiên** (session resumption) có thể không gọi certificate callback → không có nhịp 2 → mất JA3. Theo dõi `relay_miss reason=no_tmp`. Nếu tỷ lệ cao, phương án dự phòng là promote khoá tạm ngay ở access phase (`ngx.var.binary_remote_addr`), đánh đổi bằng rủi ro va chạm NAT.
- 2026-07-31 — **`tls/ja3.lua`: `pcall` phòng vệ + instrument 3 đường thoát im lặng**.
  - **`capture()` → wrapper `pcall(_M.capture_unsafe)`**. Bắt buộc: mọi lỗi Lua trong phase `ssl_client_hello` **huỷ bắt tay TLS** ⇒ sập HTTPS diện rộng. Đã xảy ra 2026-04-22: `ngx.var` bị vô hiệu ở phase này (`API disabled in the current context`, traceback qua `resty/core/var.lua:__index`) giết handshake và **âm thầm 3 tháng**. Nay lỗi bị nuốt + log `ngx.ERR` → mất JA3 chấp nhận được, sập HTTPS thì không.
  - **`diag_miss()` (rate-limit 1/200)** cho 3 đường trong `run()` trước đây return im lặng: `no_shared_dict`, `no_bridge_key` (kèm `err`, `h2`), `dict_miss` (kèm `key`, `h2`, `free_space`, `capacity`).
  - **`diag_miss` PHẢI dùng `ngx.ERR`, không phải `ngx.WARN`** (sửa cùng ngày sau khi bản WARN cho ra **0 dòng**). `run()` chạy ở access phase ⇒ trong per-domain server block, mà `da_to_openresty.sh` ghi `error_log /var/log/nginx/domains/<fqdn>.error.log;` **không kèm level** → mặc định `error` → WARN bị lọc sạch. `error_log ... warn` ở `nginx.conf` chỉ áp cho server không override (thực tế gần như không có). **Quy tắc chung: mọi log chẩn đoán chạy ở access/log phase phải ở mức `ngx.ERR` mới thấy được** — `ngx.WARN`/`ngx.DEBUG` = im lặng. Log của `antibot.log` là đường HOÀN TOÀN KHÁC (`async/logger.lua` ghi bằng `io.open`), `ngx.log` không bao giờ tới đó.
  - **Bài toán đang đo:** sau khi bật JA3 (xem `antibot-core/CLAUDE.md` 2026-07-31), bảng chéo cho thấy chỉ **58/269 = 21.6%** request HTTP/2 lấy được JA3 — `capture()` chạy đúng (có hash thật) nhưng `run()` **tra dict trượt 78%**. Ba nghi phạm phân biệt bằng log trên: (a) `get_client_random()` không dùng được ở access phase → phải đổi khoá cầu nối sang `remote_addr:remote_port`; (b) `TLS_KEY_TTL=300s` < đời kết nối H2 → nâng TTL; (c) dict 10m đầy → LRU evict (eviction **không** báo lỗi ở `set`) → nâng `lua_shared_dict antibot_tls`.
  - **Quy trình bắt buộc khi sửa file này:** máy dev không có Lua → syntax-check trên server bằng `/usr/local/openresty/luajit/bin/luajit -b <file> /dev/null` **TRƯỚC** `nginx -t`/reload. Lỗi cú pháp ⇒ `require` fail ⇒ sập HTTPS toàn bộ.
- `72f0415` (2026-05-03) — no changes
