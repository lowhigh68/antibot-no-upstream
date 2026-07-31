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

## Cross-phase bridge
`ssl_client_hello_by_lua` → `ssl_certificate_by_lua` → `access_by_lua` are SEPARATE Lua VMs in nginx. `ngx.ctx` does NOT persist. Bridge via `lua_shared_dict antibot_tls` keyed by `md5(ngx.ssl.get_client_random(32))` — accessible from all 3 phases. TTL 300s covers HTTP/2 multi-stream + HTTP/1.1 keepalive.

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
- 2026-07-31 — **`tls/ja3.lua`: `pcall` phòng vệ + instrument 3 đường thoát im lặng**.
  - **`capture()` → wrapper `pcall(_M.capture_unsafe)`**. Bắt buộc: mọi lỗi Lua trong phase `ssl_client_hello` **huỷ bắt tay TLS** ⇒ sập HTTPS diện rộng. Đã xảy ra 2026-04-22: `ngx.var` bị vô hiệu ở phase này (`API disabled in the current context`, traceback qua `resty/core/var.lua:__index`) giết handshake và **âm thầm 3 tháng**. Nay lỗi bị nuốt + log `ngx.ERR` → mất JA3 chấp nhận được, sập HTTPS thì không.
  - **`diag_miss()` (rate-limit 1/200)** cho 3 đường trong `run()` trước đây return im lặng: `no_shared_dict`, `no_bridge_key` (kèm `err`, `h2`), `dict_miss` (kèm `key`, `h2`, `free_space`, `capacity`).
  - **`diag_miss` PHẢI dùng `ngx.ERR`, không phải `ngx.WARN`** (sửa cùng ngày sau khi bản WARN cho ra **0 dòng**). `run()` chạy ở access phase ⇒ trong per-domain server block, mà `da_to_openresty.sh` ghi `error_log /var/log/nginx/domains/<fqdn>.error.log;` **không kèm level** → mặc định `error` → WARN bị lọc sạch. `error_log ... warn` ở `nginx.conf` chỉ áp cho server không override (thực tế gần như không có). **Quy tắc chung: mọi log chẩn đoán chạy ở access/log phase phải ở mức `ngx.ERR` mới thấy được** — `ngx.WARN`/`ngx.DEBUG` = im lặng. Log của `antibot.log` là đường HOÀN TOÀN KHÁC (`async/logger.lua` ghi bằng `io.open`), `ngx.log` không bao giờ tới đó.
  - **Bài toán đang đo:** sau khi bật JA3 (xem `antibot-core/CLAUDE.md` 2026-07-31), bảng chéo cho thấy chỉ **58/269 = 21.6%** request HTTP/2 lấy được JA3 — `capture()` chạy đúng (có hash thật) nhưng `run()` **tra dict trượt 78%**. Ba nghi phạm phân biệt bằng log trên: (a) `get_client_random()` không dùng được ở access phase → phải đổi khoá cầu nối sang `remote_addr:remote_port`; (b) `TLS_KEY_TTL=300s` < đời kết nối H2 → nâng TTL; (c) dict 10m đầy → LRU evict (eviction **không** báo lỗi ở `set`) → nâng `lua_shared_dict antibot_tls`.
  - **Quy trình bắt buộc khi sửa file này:** máy dev không có Lua → syntax-check trên server bằng `/usr/local/openresty/luajit/bin/luajit -b <file> /dev/null` **TRƯỚC** `nginx -t`/reload. Lỗi cú pháp ⇒ `require` fail ⇒ sập HTTPS toàn bộ.
- `72f0415` (2026-05-03) — no changes
