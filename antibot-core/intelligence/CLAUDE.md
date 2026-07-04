# intelligence/

Score aggregation. Reads ctx flags from detection+l7+transport+core, computes `ctx.score`, identifies top contributing signals.

## Purpose
Convert dozens of individual signals (each [0,1]) into a single weighted score [0,100+] that enforcement/engine consumes. Track contribution % for explainability.

## Files

| File | Role |
|---|---|
| `init.lua` | Orchestrator: `compute.run(ctx)` → `signal_merge.run(ctx)` → `context_vector.run(ctx)` → `threat/*.run(ctx)` |
| `scoring/compute.lua` | Walks `DEFAULT_WEIGHTS` table, calls `get_signal(name, ctx)` per signal, sums weighted contributions into `ctx.score`. Records `ctx.top_signals` (3 highest with contribution_pct) |
| `scoring/signal_merge.lua` | Normalizes signal sources into common shape `{name, field, type}` for compute |
| `scoring/context_vector.lua` | Build per-context dampening (resource gets lower base on every signal) |
| `threat/*.lua` | Specialized threat assessments (compound rules, attack-chain detection) — emit `ctx.corr_score`, `ctx.corr_rules`, `ctx.mismatch` |

## DEFAULT_WEIGHTS (compute.lua excerpt)
| Signal | Weight | Source |
|---|---|---|
| `ip_rep` | 45 | Redis `ip_risk:<ip>` |
| `ip_score` | 25 | core/fingerprint/ip_classify (datacenter/vpn/etc) |
| `bot_score` | varies | detection/bot |
| `header_flag` | varies | detection/anomaly/header_anomaly |
| `ua_flag` | varies | detection/anomaly/ua_anomaly |
| `proto_flag` | varies | detection/anomaly/protocol_anomaly |
| `cluster_score` | varies | detection/cluster |
| `graph_score` | varies | detection/graph |
| `behavior_score` | varies | detection/behavior |
| `session_flag` | varies | detection/session |
| `h2_bot_confidence` | varies | transport/http2 |
| `mismatch` | varies | threat correlation |
| `burst` | varies | l7/burst |
| `slow` | varies | l7/slow (boolean → multiplied) |
| `ip_surge` | 25 | l7/rate/adaptive_limit (boolean → 1.0/0.0) |

## ctx fields written
`score`, `top_signals` (array of `{signal, contribution_pct, value, weight}`), `corr_score`, `corr_rules`, `mismatch`

## ctx fields read
ALL signal fields from upstream layers. Plus `req_class` for class-based dampening.

## Flow
```
[detection.run + l7.run + transport.run all complete]
            ↓
intelligence.run(ctx)
   compute.run            → walk weights, get_signal(), sum → ctx.score
   signal_merge.run       → normalize signal table
   context_vector.run     → resource class dampening
   threat/correlate.run   → ctx.corr_score, ctx.mismatch, ctx.corr_rules
            ↓
enforcement.engine.run    → compute effective_score, decide action
```

## Related
- Reads from: every other layer (it's the aggregator)
- Writes to: `enforcement/decision/engine.lua`
- Async update: `async/risk_update.lua` writes `ip_risk:<ip>` based on action outcome (next request reads via ip_rep)

## Important rules
- New signal: register in BOTH `DEFAULT_WEIGHTS` AND `get_signal()` switch in compute.lua. Forgetting one → silent zero contribution
- Keep signals in `[0, 1]` range — compute multiplies by weight, summing >1 values would exceed score budget
- Don't add weight without removing/reducing another — total score budget should stay consistent (currently roughly 100 max for typical bot)
- `top_signals` array: keep at 3 entries, used by explain.lua + antibot.log

## Update log
- 2026-07-04 — **`ip_tour` signal registered** (`scoring/compute.lua`): `DEFAULT_WEIGHTS.ip_tour = 25` + `get_signal` branch returns `ctx.ip_tour and 1.0 or 0.0`. Source `ctx.ip_tour` set by `detection/ip_tour.lua` (cross-domain tour). Weight 25 = MONITOR-level for aggregation/explainability; the deterministic `challenge` comes from the ip_tour floor in `engine.lua` (challenge-first), not from this weight. Combined with other bot signals can still reach BLOCK naturally.
- 2026-05-23 — **`session_richness` NEGATIVE signal** registered (`scoring/compute.lua`): `DEFAULT_WEIGHTS.session_richness = -30` + `get_signal` branch returns `ctx.session_richness or 0`. Trust proxy — richness 0.8 trừ 24 pts khỏi total. compute loop refactor: track `pos_total` (sum positive contributions) riêng với `total` (gồm negative) để `contribution_pct` của top_signals không bị méo bởi trust signal. pts âm KHÔNG vào top_signals (filter `pts > 0.5`). Source `ctx.session_richness` set by `core/session_richness.lua` ở STEPS_COMMON. Cũng helps `fp_degraded_pen` và `corr_rule_weight` chỉ counted vào pos_total nếu > 0 (correctness fix for negative-aware percentage).
- 2026-05-22 — **ip_surge signal registered** (`scoring/compute.lua`): added `ip_surge = 25` to `DEFAULT_WEIGHTS` + `if name == "ip_surge"` branch in `get_signal()`. Reads `ctx.ip_surge` (boolean set by `l7/rate/adaptive_limit.lua` Tier 1 when `ip_rate > cfg.rate.ip_surge_threshold`). Weight tuned so signal alone reaches MONITOR (25) but not CHALLENGE (55) — clean-fingerprint browser bursting briefly stays in monitor; aggregate with other bot signals (ua_flag, header_flag, cluster_score) is what escalates to block. See `antibot-core/l7/CLAUDE.md` 2026-05-22 entry for the design rationale and incident that motivated the rewrite.
- 2026-05-19 — `threat/asn_reputation.lua` — S2.5 waiver: if `ctx.bot_identity_tier=="S2.5"` (Path 1 contact attest or Path 2 analyzer attest from `detection/bot/init.lua`), set `ctx.asn_rep=0` after threat feed load. Rationale: PTR attest already proves IP belongs to declared operator; the datacenter prior baked into `rep:asn:<asn>` is the wrong signal — Pinterestbot on AWS, PageSpeed on GCP are intentionally on datacenter ASNs. Removing this ~15pt contribution is required to push S2.5 steady-state score under MONITOR threshold.
- `72f0415` (2026-05-03) — no changes here. l7 mitigations may indirectly lower input signal values (ctx.slow, ctx.burst) for legit users, reducing computed score for FP cases
- 2026-05-04 — no direct change here. `swarm_attack` weight=120 stays. Logic moved into `detection/distributed_swarm.lua` per-class threshold lookup. Sensitivity adjusted at SOURCE (signal value range) not at WEIGHT (multiplier) — preserves contribution ranking in `top_signals`
