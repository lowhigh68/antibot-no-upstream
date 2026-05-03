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
- `ssl_client_hello_by_lua_block` MUST be in default_server (hostname.conf) — non-default placement causes SNI cert selection bug (see `memory/feedback_default_server.md`)
- `ssl_certificate_by_lua_block` for `ja3s.capture()` is OK in non-default per-domain confs
- `JA3_PARTIAL_PENALTY = 0` in engine.lua — no-stream arch never captures cipher list, ja3_partial is architectural constant not a bot signal
- Modules MUST export both `_M.capture` and `_M.run` — replacing with no-op breaks transport pipeline (`attempt to call nil`)

## Update log
- `72f0415` (2026-05-03) — no changes
