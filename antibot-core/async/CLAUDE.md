# async/

Background tasks run via `ngx.timer.at(0, fn)` from `log_by_lua_block` (after response sent). Never block request path.

## Purpose
Persist learning state, write logs, manage memory pressure — all OFF the request critical path.

## Files

| File | Role | Trigger |
|---|---|---|
| `risk_update.lua` | Update `ip_risk:<ip>` based on `ctx.action` outcome (block/challenge → increment, allow → decay). Skip for `req_class=resource` to avoid per-asset noise | `log_by_lua` |
| `adaptive_weight.lua` | Tune `DEFAULT_WEIGHTS` based on observed FP/FN ratio (slow learning) | `log_by_lua` |
| `logger.lua` | Format ctx → write `/var/log/antibot/antibot.log` line via `ngx.log(ngx.WARN, ...)` (default error log filtered by INFO so use WARN level for visibility) | `log_by_lua` |
| `memory_guard.lua` | Periodic shared dict eviction when memory pressure high. Started from `init_worker_by_lua_block` | timer loop |

## ctx fields read
`action`, `action_reason`, `score`, `effective_score`, `ip`, `identity`, `req_class`, `top_signals`, `mismatch`, `kill_reason` plus all signal flags

## ctx fields written
None (read-only consumer of ctx state)

## Redis keys written
- `ip_risk:<ip>` (risk_update — TTL via cfg.ttl)
- `weights:<signal>` (adaptive_weight — slow Bayesian update)

## Flow
```
[response sent to client]
            ↓
log_by_lua_block { antibot.log() }
   if class ≠ resource AND ctx.identity:
       ngx.timer.at(0, risk_update.run)
       ngx.timer.at(0, adaptive_weight.run)
   logger.run(ctx)         → write antibot.log line (synchronous to log phase)
```

`init_worker_by_lua_block`:
- `memory_guard.start()` — long-running timer
- `goodbot_seed.run` (in core/) — one-time seed via deferred timer (cosocket disabled in init_worker)

## Related
- Upstream: `enforcement/decision/engine.lua` writes `ctx.action`/`ctx.action_reason`
- `intelligence/scoring/compute.lua` reads `ip_rep` (from `ip_risk:<ip>` updated here) on next request
- `core/goodbot_seed.lua` runs from init_worker similarly

## Important rules
- NEVER block in log phase — `ngx.timer.at(0, fn)` defers off-request
- `risk_update` + `adaptive_weight` skip `req_class=resource` (noise reduction for asset fetches)
- Use `ngx.WARN` (not INFO) so logs appear in default OpenResty error log when antibot.log path missing
- Cosocket (Redis) is DISABLED in `init_worker_by_lua` — defer Redis work via `ngx.timer.at(0, fn)`. See `core/goodbot_seed.lua` invocation pattern in init.lua
- New async task → register in `init.lua:_M.log()`, gate by class to avoid resource noise

## Update log
- `72f0415` (2026-05-03) — no changes
- 2026-05-04 — `risk_update.lua`: treat `action="throttled"` like `allow`/`monitor` for both identity_risk and ip_risk decay paths. Verified good bot bị rate-limit hợp pháp KHÔNG bị penalty rep — bot identity đã verify qua DNS/ASN, throttle chỉ là backend protection
