# detection/

Signal families that observe HOW request behaves vs HOW request looks (l7 = volume, transport = TLS shape, detection = behavioral/structural). Most expensive layer — skipped for `resource` class.

## Purpose
Compute behavioral/structural anomaly scores into ctx flags consumed by `intelligence/scoring/compute.lua`.

## Subdirectories

| Dir | Purpose | Output ctx fields |
|---|---|---|
| `bot/` | Good-bot identification (4-path verify), UA bot pattern check | `bot_score`, `bot_ua`, `good_bot_verified`, `good_bot_claimed`, `good_bot_asns`, `good_bot_ptr_only` |
| `anomaly/` | UA structure, header consistency, protocol oddity | `header_flag`, `ua_flag`, `proto_flag`, `anomaly_score`, `ua_identity_uncertain` |
| `browser/` | Beacon JS injection (2-phase), beacon handler endpoint | `inject_candidate`, `browser_needed` |
| `behavior/` | Click/scroll/timing patterns from beacon data | `behavior_score` |
| `session/` | Session path, repeat ratio, resource_starved (Attack 4) | `sess_len`, `session_flag`, `nav_count`, `res_count`, `resource_starved` |
| `cluster/` | UA/IP/URI/TLS clustering across identities | `ua_cluster`, `ip_cluster`, `uri_cluster`, `tls_cluster`, `cluster_score` |
| `graph/` | Graph correlation between identities | `graph_flag`, `graph_score`, `subnet_diversity` |

## Top-level files

| File | Role |
|---|---|
| `init.lua` | Orchestrator. Each sub-init.lua calls `should_run(ctx)` checking `ctx.skip_layers` |
| `distributed_swarm.lua` | Cross-identity attack pattern detection → `ctx.swarm` |
| `wp_hardening.lua` | WordPress-specific path/payload checks |

## bot/ submodule (4-path verification)
See [`memory/project_bot_verification.md`](../../memory/project_bot_verification.md).
- `init.lua` orchestrate ua_check → dns_reverse → dns_forward → asn_fallback
- `ua_check.lua` regex match UA against good-bot patterns, hardcoded `PTR_ONLY_BOTS` table (also stores ASN list)
- `dns_reverse.lua` PTR lookup, suffix match against `goodbot:dns:<name>` (Redis)
- `dns_forward.lua` A record check IP membership; **early return if `good_bot_ptr_only`** (Meta family)
- `lite_verify.lua` resource-class only: ua_check + asn lookup + ASN match (no DNS)
- Reasons emitted: `good_bot_verified` (full DNS or PTR-only), `good_bot_asn_verified` (ASN fallback), `good_bot_asn_lite` (resource)

## ctx fields written
See per-subdir column above.

## ctx fields read
`ip`, `ua`, `req.{uri,method,host,referer,accept,accept_lang,accept_enc,sec_fetch_*}`, `device_type`, `device_is_mobile`, `device_sec_fetch_expected`, `device_ch_ua_mobile_expected`, `req_class`, `sess_len`, `fp_light`, `asn`, `tls13`, `ja3`

## Flow
```
COMMON  → ip_ban_check + access (whitelist) + transport (fp)
            ↓
class dispatch
            ↓
detection.run(ctx)
   ├─ bot.run         → may set good_bot_verified=true → engine bypass scoring
   ├─ anomaly.run     → header_flag, ua_flag, proto_flag
   ├─ session.run     → load + analyze + store; sets sess_len, session_flag, resource_starved
   ├─ behavior.run    → behavior_score (beacon-driven)
   ├─ browser.trigger → ctx.inject_candidate (decided by Accept header)
   ├─ cluster.run     → cluster_score
   ├─ graph.run       → graph_flag, graph_score
   └─ distributed_swarm.run → ctx.swarm
```

For `resource` class: `STEPS_RESOURCE` skips this entire layer except `bot/lite_verify.lua` (called directly from init.lua).

## Related
- Upstream: `core/ctx`, `core/fingerprint/*`, `transport/*`
- Downstream: `intelligence/scoring/compute.lua` reads ALL output flags as signals; `enforcement/decision/engine.lua` short-circuits on `good_bot_verified`
- Beacon two-phase: `browser/trigger.lua` (access) sets candidate; `header_filter_by_lua_block` confirms via Content-Type; `browser/inject.lua` (body_filter) emits JS

## Important rules
- New module MUST check `ctx.skip_layers[<name>]` via `should_run()` helper
- `good_bot_verified=true` → engine.lua immediate allow, bypass scoring (write only after PROVEN identity, not on UA claim alone)
- session_store has separate sess_age key for grace period — newly-arrived users won't trigger resource_starved
- Beacon injection NEVER short-circuits — CSS/JS/image responses must NEVER have Content-Length cleared (header_filter checks Content-Type)

## Update log
- `72f0415` (2026-05-03) — no changes here, Phase 1 only touched l7/
- 2026-05-04 — `distributed_swarm.lua` class-aware thresholds (Option C):
  - navigation `25/45` (relax — VN popular product flash crowd OK)
  - auth_endpoint `8/15` (tighten — credential stuffing protection)
  - api_callback `12/25`, feed_or_meta `45/90`, interaction `20/35`
  - inapp_browser `20/35`, unknown `15/30` (legacy default)
  - Weight `swarm_attack = 120` GIỮ NGUYÊN — không thay đổi scoring math
  - Logs include `class=` + threshold values for tuning per-class
  - Fix: VN e-commerce popular product page bị block khi 30 /24 cùng UA Chrome browse simultaneously (organic flash crowd ≠ swarm bot)
