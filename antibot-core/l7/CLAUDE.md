# l7/

Layer 7 traffic shaping: rate limit, burst, slow-loris, IP/identity ban. Runs early in pipeline (`STEPS_COMMON` for ban_check, `STEPS_FULL_DETECTION` for rate/burst/slow).

## Purpose
Catch volumetric/protocol attacks BEFORE expensive detection layers. Reject banned identities immediately.

## Files

| File | Role | Phase |
|---|---|---|
| `init.lua` | Orchestrator: `ip_ban_check` (in COMMON) + `ban_store` (per-class), `rate.counter`, `burst.burst_counter`, `burst.burst_decision`, `slow.slow_detect` |
| `ban/ip_ban_check.lua` | Read `banned:ip:<ip>` from Redis. Hit → set `ctx.action="block"`, `ctx.action_reason="banned_ip"`, `ngx.exit(403)` |
| `ban/ban_store.lua` | Read `ban:<identity>`. Hit → escalate viol (rate-limited 1/60s, after grace 5min), extend ban TTL via `cfg.ttl.ban_steps`. Sets `action_reason="banned_id"`, exits 403. Defers when UA claims good bot (DNS verify in detection/bot decides) |
| `rate/counter.lua` | `rl:<ip>` and `rl:<id>` incr by `rate_weight` (class-dependent). Sets `ctx.rate`, `ctx.ip_rate`, `ctx.burst` (rate/TTL > burst_threshold/60). **Retry-aware**: same URI from same identity within 3s gets 0.3× weight. Also SADD `rate:ids:<ip>` per request (TTL = `cfg.ttl.rate`) for adaptive_limit's distinct-identity check |
| `rate/res_ip_counter.lua` | INCR `res_ip:<ip>` (TTL = `cfg.ttl.rate` = 60s) for resource class only. Runs in `STEPS_RESOURCE` (NOT in `l7_layer.run` because resource class skips l7). Feeds `detection/session/session_store.lua` resource_starved gating — IP-level browser activity check |
| `rate/adaptive_limit.lua` | Hybrid ip_surge: Tier 1 sets `ctx.ip_surge` signal when `ip_rate > cfg.rate.ip_surge_threshold` (1500/60s ≈ 25 req/s) → scoring decides. Tier 2 hard-bans IP only when `ip_rate > cfg.rate.ip_surge_extreme` (5000/60s ≈ 83 req/s) AND distinct identities `< cfg.rate.ip_surge_distinct_min` (3). Short TTL `cfg.rate.ip_surge_ban_ttl` (300s). Also increments `viol:<id>` async when per-identity rate exceeds adaptive threshold |
| `burst/burst_counter.lua` | `burst:<id>` incr. Sets `ctx.burst`. Grace: trusted session (sess_len ≥ 5, sess_flag < 0.4) → burst=0 |
| `burst/burst_decision.lua` | `ctx.burst_flag = ctx.burst > cfg.rate.burst_threshold` |
| `slow/slow_detect.lua` | `ctx.slow = request_time > effective_threshold`. **Device-aware**: mobile×2.5, trusted×1.5 |

## Identity hash discipline
`ban_store.lua` and `ban_store_write.lua` MUST read/write key with same `id` source (`ctx.identity || ctx.fp_light`). Order matters — identity = md5(ip+ua_norm), fp_light = md5(ip+ua+asn+ja3+h2). If write key X read key Y → ban exists in Redis but never matched → bot loops forever.

## ctx fields written
`banned`, `rate`, `ip_rate`, `burst`, `burst_flag`, `slow`, `is_retry`, `ip_surge`, `rate_flag` (also `action`, `action_reason` before `ngx.exit`)

## ctx fields read
`ip`, `identity`, `fp_light`, `ua`, `req.uri`, `req_class`, `rate_weight`, `score_multiplier`, `sess_len`, `session_flag`, `device_is_mobile`, `device_type`, `skip_layers`, `skip_rate`

## Flow
```
COMMON  → ip_ban_check          → exit 403 if IP banned
            ↓
class dispatch
            ↓
FULL/INT → ban_store             → exit 403 if identity banned (defer if good_bot UA)
         → rate.counter          → ctx.rate, ctx.ip_rate, ctx.burst (with retry discount)
         → burst.burst_counter   → ctx.burst (per-id)
         → burst.burst_decision  → ctx.burst_flag
         → slow.slow_detect      → ctx.slow (device-aware)
```

## Related
- Upstream: `core/ctx`, `core/req_classifier`, `core/fingerprint/identity`, `core/redis_pool`
- Downstream: `intelligence/scoring/compute.lua` reads `ip_rate`, `burst`, `slow`, `burst_flag`, `ip_surge`, `rate_flag` as signals
- Related ban writes: `enforcement/ban/ban_store_write.lua` writes `ban:<id>`. l7 only WRITES `ban:<ip>` via `adaptive_limit.lua` Tier 2 (hard-ban path, gated by extreme rate + low distinct identities)

## Important rules
- Any `ngx.exit(...)` MUST set `ctx.action` AND `ctx.action_reason` first — log_by_lua produces `reason=-` otherwise (already done in ban_store.lua banned_id, ip_ban_check.lua banned_ip)
- Defer ban for `ua_claims_good_bot()` UA — let detection/bot DNS verify decide
- Retry detection key `retry:<id>:<md5(uri)>` TTL 5s — short, no Redis pressure
- Ban grace `ban:age:<id>` TTL 24h — first-time ban hit doesn't escalate

## Update log
- 2026-05-23 — **`rate/res_ip_counter.lua` NEW** — track resource hit per IP (60s window) to feed `detection/session/session_store.lua` resource_starved IP-level gating. Wired into `STEPS_RESOURCE` (init.lua) because resource class bypasses `l7_layer.run`. Single `safe_incr("res_ip:<ip>", ttl.rate)` — lightweight, no pipeline. Solves FP: browser session loads CSS/JS but res_count per identity LUÔN = 0 (resource class skips fingerprint). With this counter, session_store can verify IP has actual resource activity before firing the signal. See `version.txt` 2026-05-23 + `detection/CLAUDE.md` for the gating logic.
- 2026-05-22 — **ip_surge hybrid model** (`rate/adaptive_limit.lua` rewrite + `rate/counter.lua` distinct-id SADD):
  - Old logic: `ip_rate > 1500/60s` → unilateral hard-ban IP for 1800s. Blind to identity diversity → false-positive on first-run browser-extension users (single identity bursts 1000-1500 in 60s during install/test), NAT/CGNAT, AI-agent navigation.
  - New Tier 1 (SIGNAL): `ip_rate > cfg.rate.ip_surge_threshold` (1500) → set `ctx.ip_surge=true`. Scoring layer adds weight 25 (registered in `intelligence/scoring/compute.lua DEFAULT_WEIGHTS + get_signal`). Alone reaches MONITOR (25), not CHALLENGE (55) — clean-fingerprint browser passes.
  - New Tier 2 (HARD BAN): `ip_rate > cfg.rate.ip_surge_extreme` (5000) **AND** `scard(rate:ids:<ip>) < cfg.rate.ip_surge_distinct_min` (3). Implausible rate AND single-source. TTL `cfg.rate.ip_surge_ban_ttl` (300s, was 1800).
  - `counter.lua`: SADD `rate:ids:<ip>` per request in same pipeline (TTL = `cfg.ttl.rate` = 60s).
  - `core/redis_pool.lua`: new helper `safe_scard(key)`.
  - Audit log: `[rate] HARD BAN ip_surge_extreme` (fired) or `[rate] ip_surge_extreme suppressed (NAT diversity)` (suppressed by distinct check) in error.log.
  - Incident: IP 118.70.131.98 banned 2026-05-21 when user installed/tested Claude Code Chrome extension on thbvietnam.com. Old logic fired Tier 1 hard-ban with TTL 1800s. Operator manually whitelisted IP as workaround.
- `72f0415` (2026-05-03) — Phase 1 mitigations:
  - `slow_detect.lua`: device-aware threshold (mobile×2.5, trusted×1.5) — fix 3G/4G FP
  - `rate/counter.lua`: retry-aware weight (0.3× for same URI within 3s) — fix browser auto-retry FP
  - `ban/ban_store.lua`: 5-min escalation grace via `ban:age:<id>` — fix permanent ban from network flap
