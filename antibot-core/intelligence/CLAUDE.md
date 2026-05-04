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
- `72f0415` (2026-05-03) — no changes here. l7 mitigations may indirectly lower input signal values (ctx.slow, ctx.burst) for legit users, reducing computed score for FP cases
- 2026-05-04 — no direct change here. `swarm_attack` weight=120 stays. Logic moved into `detection/distributed_swarm.lua` per-class threshold lookup. Sensitivity adjusted at SOURCE (signal value range) not at WEIGHT (multiplier) — preserves contribution ranking in `top_signals`
