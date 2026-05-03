# antibot-core/

Pipeline root. `init.lua` is the single entry point invoked from per-domain nginx server blocks via `access_by_lua_block { require("antibot").run() }`.

## Per-module overview (read these for any module-specific work)

| Module | What it does | When it runs |
|---|---|---|
| [`core/`](core/CLAUDE.md) | Config, Redis pool, ctx init, request classifier, fingerprint primitives, good-bot seed | First (`STEPS_COMMON`) |
| [`transport/`](transport/CLAUDE.md) | TLS (JA3/JA3S) + HTTP/2 fingerprints, cross-phase shared dict bridge | After ctx, before l7 |
| [`l7/`](l7/CLAUDE.md) | Rate limit, burst, slow-loris, IP/identity ban (read+write) | Early — before detection |
| [`detection/`](detection/CLAUDE.md) | Bot verify (4-path), anomaly, behavior, session, cluster, graph, browser beacon | After l7. Skipped for resource class except bot/lite_verify |
| [`intelligence/`](intelligence/CLAUDE.md) | Score aggregation from all signals → ctx.score + top_signals | After detection |
| [`enforcement/`](enforcement/CLAUDE.md) | Decision engine, PoW challenge, ban write | Last in pipeline |
| [`async/`](async/CLAUDE.md) | risk_update, adaptive_weight, logger, memory_guard | log_by_lua phase (off-request) |
| [`admin/`](admin/CLAUDE.md) | Web UI + JSON API | Mounted only in hostname.conf |

## Pipeline at a glance (`init.lua`)

```
access_by_lua_block { antibot.run() }
  ↓
1. cookie fast-path: if verified:<cookie>=1 → set ctx.verified, RETURN
2. classifier.run(ctx) → ctx.req_class + score_multiplier + rate_weight + skip_layers
3. STEPS_COMMON (always):
     ctx.init → ip_ban_check → device_classifier → access (whitelist) → transport
4. if ctx.verified or ctx.whitelisted → RETURN (no l7 counter, no detection)
5. dispatch by class:
     resource     → STEPS_RESOURCE       = bot.lite_verify → intelligence → enforcement
     interaction  → STEPS_INTERACTION    = fingerprint → l7 → detection → intelligence → enforcement
     others       → STEPS_FULL_DETECTION = same as interaction
6. enforcement.engine sets ctx.action; challenge.serve or ban_store_write may fire
log_by_lua_block { antibot.log() }
  ↓
async/risk_update + adaptive_weight (skip resource), logger
```

## Cross-cutting rules

| Rule | Why | Where enforced |
|---|---|---|
| Use `core.redis_pool` only — never `resty.redis` directly | Connection leak prevention, error normalization | All |
| New signal: register in `DEFAULT_WEIGHTS` AND `get_signal()` | Otherwise silent zero contribution | intelligence/scoring/compute.lua |
| New layer: check `ctx.skip_layers` via `should_run` | Allow per-class skip | detection/init.lua pattern |
| Set `ctx.action` + `ctx.action_reason` BEFORE every `ngx.exit(...)` | log_by_lua produces `reason=-` otherwise | l7/ban/*, enforcement/* |
| New `lua_shared_dict` → declare in `nginx/nginx.conf:49-53` only | Single source for memory budgeting | nginx.conf |
| Never block in `log_by_lua` — use `ngx.timer.at(0, fn)` | Latency added to every request otherwise | async/* |
| `init_worker_by_lua_block` cosocket DISABLED — defer Redis via `ngx.timer.at(0, fn)` | OpenResty constraint | core/goodbot_seed invocation |
| `ssl_client_hello_by_lua_block` ONLY in default_server (hostname.conf) | Non-default placement breaks SNI cert selection | nginx config |

## Identity hash discipline

| Key | Hash source | Stable across |
|---|---|---|
| `ctx.identity` | `md5(ip + ua_norm)` | UA + IP |
| `ctx.fp_light` | `md5(ip + ua + asn + ja3 + h2)` | Same TLS profile + IP |
| `ctx.fp_full` | composite | Per-handshake |
| Cookie `antibot_fp` | matches `ctx.identity` after first verify | Browser session |

`l7/ban/ban_store.lua` (read) and `enforcement/ban/ban_store_write.lua` (write) MUST use SAME id source order. Mismatch → ban exists in Redis but never matched → bot loops.

## Bot verification (detection/bot)
4 paths — see [`memory/project_bot_verification.md`](../memory/project_bot_verification.md):
1. **Full DNS** — PTR suffix + forward A contains source IP → `good_bot_verified`
2. **PTR-only** (Meta family) — PTR suffix only, skip forward → `good_bot_verified`
3. **ASN fallback** — DNS NXDOMAIN/timeout, match `ctx.asn.asn_number` against expected → `good_bot_asn_verified`
4. **Lite** (resource class) — ua_check + ASN match (no DNS) → `good_bot_asn_lite`

Hardcoded ASNs: `AS15169` Google, `AS8075` Bing, `AS32934` Meta, `AS714/6185/2709` Apple, `AS135905` CocCoc.

## SNI cert selection gotcha
See [`memory/feedback_default_server.md`](../memory/feedback_default_server.md). Symptom "wrong cert per-domain" → check `default_server` flag FIRST. Antibot/Lua are NOT the cause in 100% of cases observed so far. Fix: add `default.conf` with `default_server` on both 80 + 443.

## Update log
- 2026-05-04 (v2) — `engine.lua` good_bot_throttle REWRITE to **hybrid scoring** (general, no hardcoded names):
  - HARD: `qs_len ≥ 200` OR `params ≥ 8` → throttle
  - SOFT: weighted sum (qs_len + params + comma + search) ≥ 0.7 → throttle
  - RPM gate: 8 expensive req/min/bot_name (after detection)
  - Catches WooCommerce filter, WP search, sort, faceted nav cross-site without naming any param
  - Vietnamese natively handled (UTF-8 inflates qs_len bytes)
  - Action `throttled` (status 429 + Retry-After 120). Reason `good_bot_throttled`
  - `async/risk_update.lua` skip ip_rep penalty when `action=throttled`
- 2026-05-04 (v1) — `enforcement/decision/engine.lua` good_bot_throttle initial (specific patterns): hardcoded `filter_*=`, `min/max_price=`, `orderby=` at 8/min/bot_name. Replaced by v2 same-day.
- `72f0415` (2026-05-03) — l7 Phase 1 client-network FP fixes:
  - slow_detect device-aware threshold (mobile×2.5, trusted×1.5)
  - rate counter retry-aware (0.3× weight for same URI within 3s)
  - ban escalation 5-minute grace via `ban:age:<id>`
  - **Net effect**: real users on flaky 3G/4G/captive portals no longer cascade through false slow → false burst → false ban → permanent ban escalation
- `7bfcb0f` (2026-05-01) — bot_lite verification observable in antibot.log (WARN level)
- `2848f8b` (2026-05-01) — lite_verify for resource class added to STEPS_RESOURCE
- `2646a44` (2026-05-01) — registered missing Google/Bing crawler variants
- `08959fd`, `c48af76`, `d7a5875`, `34b9fff`, `52ccef2`, `7a5a126`, `f1d6df9` (2026-04-30) — bot verification overhaul (4-path arch, ASN fallback, PTR-only for Meta, hardcoded registry)

## How to use these CLAUDE.md files

Each subdirectory CLAUDE.md is the orientation map for that module. Read it BEFORE diving into individual `.lua` files when:
- Investigating a flag's source
- Adding a new signal/layer
- Tracing why a request was blocked
- Auditing FP/FN

The files document data flow (ctx fields read/written), Redis keys, position in pipeline, related modules — enough to plan changes without re-reading code line by line.

Update the relevant CLAUDE.md whenever you commit a meaningful change to that module. Append to the "Update log" section at the bottom with commit hash + date + 1-line summary.
