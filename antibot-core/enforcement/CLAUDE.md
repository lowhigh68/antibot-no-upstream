# enforcement/

Decision + action. Last layer in pipeline. Maps `ctx.score` → action (allow/monitor/challenge/block), serves PoW challenge, writes ban entries.

## Purpose
Translate aggregated score into HTTP action. Apply class-based multipliers, kill-switches, IP-risk threshold lowering, trust caps. Short-circuit on whitelist + good_bot_verified.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `engine.run(ctx)` → if action=challenge: `challenge.serve(ctx)`. If action=block + new violation: `ban.ban_store_write.write(ctx)` |
| `decision/engine.lua` | Core: short-circuit (`whitelisted`, `good_bot_verified`), apply `score_multiplier × trust_multiplier + fp_penalty + resource_boost capped at 40`, kill-switches for resource (raw≥95→eff≥85 block, raw≥80→eff≥60 challenge), IP-risk threshold lowering (`ip_risk≥0.4` → challenge cap 40), trust cap (trusted→action_cap=monitor). Sets `ctx.action`, `ctx.action_reason`, `ctx.effective_score`, `ctx.kill_reason`. Sets debug `X-Bot-*` response headers when `$antibot_debug=1` |
| `challenge/init.lua` | When action=challenge: serve PoW HTML page |
| `challenge/serve.lua` | Generate challenge HTML with PoW token (HMAC-signed, difficulty `cfg.pow.difficulty="000"`) |
| `challenge/verify_token.lua` | `/antibot/verify` endpoint handler — verify PoW solution, on success set Redis `verified:<cookie>=1` (TTL ≈ session lifetime) |
| `ban/ban_store_write.lua` | Write `ban:<id>` to Redis when action=block AND not already banned. Order MUST match `l7/ban/ban_store.lua` read (identity OR fp_light) |
| `explain.lua` | Build human-readable reason string from `ctx.top_signals` + `ctx.kill_reason` + `ctx.trust_reason` (used by antibot.log + admin) |

## Constants in engine.lua
- Thresholds: `MONITOR=25, CHALLENGE=55, BLOCK=80`
- `RESOURCE_MAX_SCORE=40`, `RESOURCE_BOOST_MAX=15`
- Resource kill: `KILL_BLOCK_RAW=95→EFF=85`, `KILL_CHALLENGE_RAW=80→EFF=60`
- FP penalty: `FP_DEGRADED=5`, `FP_QUALITY=3` (threshold 0.5), **`JA3_PARTIAL_PENALTY=0`** (no-stream architecture constant)
- Attack 1 IP-risk: `THRESHOLD_LOWER=0.4` → CHALLENGE cap 40 (skip for api_callback)

## ctx fields written
`action`, `action_reason`, `effective_score`, `kill_reason`, `trust_reason`, `monitor_flag`, `ip_risk_lowered`

## ctx fields read
`whitelisted`, `good_bot_verified`, `score`, `score_multiplier`, `req_class`, `sess_len`, `session_flag`, `ip_risk`, `fp_degraded`, `fp_quality`, `ja3_partial`, `ip` plus all signals (for debug headers)

## Decision flow (engine.lua)
```
ctx.whitelisted=true → action=allow, reason=whitelisted, RETURN
ctx.good_bot_verified=true → action=allow, reason=good_bot_verified|good_bot_asn_verified|good_bot_asn_lite (preserved), RETURN

raw_score = ctx.score
multiplier = score_multiplier × trust_multiplier (trust if sess_len≥session_min, sess_flag<flag_max)
effective_score = raw × multiplier + fp_penalty + resource_boost (resource only)
              capped at RESOURCE_MAX_SCORE for resource

if resource: kill switches override (raw≥95 → eff≥85 block; raw≥80 → eff≥60 challenge)

challenge_threshold = CHALLENGE (55)
if ip_risk ≥ 0.4 and class ≠ api_callback: challenge_threshold = 40

action by effective_score:
  ≥ BLOCK (80)              → block
  ≥ challenge_threshold     → challenge
  ≥ MONITOR (25)            → monitor (silent)
  else                      → allow

if trust_reason and action=challenge: action = cfg.trust.action_cap (default monitor)
```

## Flow
```
intelligence.run(ctx) → ctx.score, ctx.top_signals
            ↓
enforcement.run(ctx)
   engine.run         → ctx.action, ctx.action_reason, ctx.effective_score
   if challenge:
      challenge.serve → respond 403 + HTML challenge page
   if block + new viol:
      ban_store_write → Redis ban:<id> with TTL from cfg.ttl.ban_steps[viol]
            ↓
log_by_lua → async/logger writes /var/log/antibot/antibot.log
```

## Related
- Upstream: `intelligence/scoring/compute` (provides ctx.score), all detection layers (provide signal flags)
- Downstream: `async/risk_update` reads `ctx.action` to update `ip_risk:<ip>` async
- PoW verify cycle: challenge.serve → browser solves → POST `/antibot/verify` → verify_token → Redis `verified:<cookie>` → next request hits cookie fast-path in init.lua

## Important rules
- Thresholds duplicated in `core/config.lua` AND `engine.lua` — change one → reconcile other
- Engine MUST `return` immediately on whitelisted/good_bot_verified — debug headers set later in function won't fire (intentional, cookie/whitelist short-circuit is by design)
- `cfg.pow.difficulty="000"` — affects user solve latency, don't change without explicit request
- `JA3_PARTIAL_PENALTY=0` — no-stream arch never captures cipher list. Penalty would fire on EVERY HTTPS request → useless signal. Don't restore
- ban_store_write MUST use SAME id source order as l7/ban/ban_store.lua read

## Update log
- `72f0415` (2026-05-03) — no direct changes. l7 Phase 1 mitigations indirectly lower `ctx.slow`, `ctx.burst` for unstable network users → `ctx.score` lower → action more lenient → fewer false challenges/blocks
- 2026-05-04 (v1) — `engine.lua` good_bot_throttle initial: verified bots hitting hardcoded patterns (filter_/min_price/max_price/orderby) get rate-limited at 8/min/bot_name with `429 Retry-After: 120`. Reason `good_bot_throttled`
- 2026-05-04 (v2) — `engine.lua` good_bot_throttle REWRITE to **hybrid scoring** (general, no hardcoded names):
  - **HARD**: `qs_len ≥ 200` OR `params ≥ 8` → trigger immediately (count toward RPM)
  - **SOFT**: weighted sum of 4 sub-signals ≥ `0.7` → compound subtle expensive
    - qs_len graduated 0.15/0.35/0.50 at 40/80/120 chars
    - param_count graduated 0.20/0.40 at 3/5 params
    - comma density graduated 0.10/0.25/0.40 at 1/2/4 commas (raw `,` + `%2C`)
    - search_term 0.15 if `+` or `%20` present (lenient — single Việt search pass)
  - **RPM**: `gb_throttle:<bot>:<minute>` TTL 65s; throttle khi count > 8
  - Catches WooCommerce filter, WP search, sort, faceted nav cross-site without naming params
  - Vietnamese URL handled natively (UTF-8 bytes inflate qs_len)
  - Logs include `trigger` (hard_qs_len|hard_param_count|soft_score) + `score` for tuning
  - Sets `ctx.expensive_score`, `ctx.expensive_trigger` even when allowed (debugging)
  - Pair with `async/risk_update.lua` skip when `action="throttled"` (no ip_rep penalty for legit verified bot)
