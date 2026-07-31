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
| `tls/ja3_stream.lua` | Stream preread cipher capture — only works if `stream{}` block configured (this project does NOT use stream → always returns nil → ja3_partial = true) |
| `http2/init.lua` | Inspects HTTP/2 settings/headers → `ctx.h2_sig`, `ctx.h2_order`, `ctx.h2_bot_confidence` |

## Cross-phase bridge — RELAY 2 NHỊP
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
- 2026-07-31 (4) — **Đường cứu cho handshake NỐI LẠI PHIÊN (promote ở access phase).**
  - Sau relay 2 nhịp, JA3 đã per-client thật (phân bố hàng chục hash, hash phổ biến nhất chỉ 16%) nhưng phủ chỉ ~14%. Phân rã miss: **`dict_miss` 143/173**, `no_bridge_key` 30 mà **27 là `scheme=http`** (cổng 80, không có TLS — đúng thiết kế), `zero client_random` = **0**.
  - **Nguyên nhân:** `keepalive_timeout 65` → kết nối rảnh 65s bị đóng → client tái kết nối liên tục; per-domain conf có `ssl_session_cache shared:SSL:10m` → phần lớn lần tái kết nối là **nối lại phiên**; nối lại phiên **không gửi certificate** → certificate callback không chạy → **nhịp 2 không chạy**. Đây là **điểm mù của `relay_miss`**: nó chỉ log khi relay *có chạy* mà thiếu entry tạm — relay không được gọi thì không có dòng nào (`relay_miss no_tmp` chỉ 2).
  - Vì sao KHÔNG phải TTL: để `TLS_KEY_TTL=300s` gây miss thì request phải đến sau 300s kể từ handshake, trong khi kết nối rảnh 65s đã đóng — tức phải duyệt liên tục >5 phút. Có, nhưng không thể chiếm 83%. **Nâng TTL là sửa nhầm chỗ.**
  - **Fix:** `run()` khi trượt khoá thật thì đọc entry tạm `tlsq:<md5(binary_remote_addr)>` (callback ClientHello **vẫn chạy** khi nối lại phiên) rồi thăng cấp sang khoá thật. `TMP_KEY_TTL` 15s → **5s** để thu hẹp cửa sổ va chạm NAT — đó là cái giá phải trả: hai client sau cùng một NAT cùng nối lại phiên trong 5s có thể nhận fingerprint của nhau. Nhịp 2 vẫn xoá entry tạm cho mọi handshake mới nên phần dư nhỏ.
  - **Đo hiệu quả:** so `relay_ok n` với `capture_ok n` cùng worker/cửa sổ (xấp xỉ ⇒ cert callback chạy đủ; thấp hơn hẳn ⇒ nối lại phiên chiếm phần chênh), và `promote n` cho biết đường cứu gánh bao nhiêu.
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
