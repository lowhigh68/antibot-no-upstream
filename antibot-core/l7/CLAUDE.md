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
| `rate/counter.lua` | `rl:<ip>` and `rl:<id>` incr by `rate_weight` (class-dependent). Sets `ctx.rate`, `ctx.ip_rate`, `ctx.burst` (rate/TTL > burst_threshold/60). **Retry-aware**: same URI from same identity within 3s gets 0.3× weight |
| `rate/adaptive_limit.lua` | Per-domain dynamic threshold tuning (background) |
| `burst/burst_counter.lua` | `burst:<id>` incr. Sets `ctx.burst`. Grace: trusted session (sess_len ≥ 5, sess_flag < 0.4) → burst=0 |
| `burst/burst_decision.lua` | `ctx.burst_flag = ctx.burst > cfg.rate.burst_threshold` |
| `slow/slow_detect.lua` | `ctx.slow = request_time > effective_threshold`. **Device-aware**: mobile×2.5, trusted×1.5 |

## Identity hash discipline
`ban_store.lua` and `ban_store_write.lua` MUST read/write key with same `id` source (`ctx.identity || ctx.fp_light`). Order matters — identity = md5(ip+ua_norm), fp_light = md5(ip+ua+asn+ja3+h2). If write key X read key Y → ban exists in Redis but never matched → bot loops forever.

## ctx fields written
`banned`, `rate`, `ip_rate`, `burst`, `burst_flag`, `slow`, `is_retry` (also `action`, `action_reason` before `ngx.exit`)

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
- Downstream: `intelligence/scoring/compute.lua` reads `ip_rate`, `burst`, `slow`, `burst_flag` as signals
- Related ban writes: `enforcement/ban/ban_store_write.lua` writes `ban:<id>`. l7 only READS

## Important rules
- Any `ngx.exit(...)` MUST set `ctx.action` AND `ctx.action_reason` first — log_by_lua produces `reason=-` otherwise (already done in ban_store.lua banned_id, ip_ban_check.lua banned_ip)
- Defer ban for `ua_claims_good_bot()` UA — let detection/bot DNS verify decide
- Retry detection key `retry:<id>:<md5(uri)>` TTL 5s — short, no Redis pressure
- Ban grace `ban:age:<id>` TTL 24h — first-time ban hit doesn't escalate

## Update log
- `72f0415` (2026-05-03) — Phase 1 mitigations:
  - `slow_detect.lua`: device-aware threshold (mobile×2.5, trusted×1.5) — fix 3G/4G FP
  - `rate/counter.lua`: retry-aware weight (0.3× for same URI within 3s) — fix browser auto-retry FP
  - `ban/ban_store.lua`: 5-min escalation grace via `ban:age:<id>` — fix permanent ban from network flap
