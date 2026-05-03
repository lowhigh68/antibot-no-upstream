# core/

Foundational primitives. Loaded by every other module. No business logic — pure utilities.

## Purpose
Config, Redis pool, ctx lifecycle, request classification, fingerprint primitives, good-bot registry seed.

## Files

| File | Role |
|---|---|
| `config.lua` | Thresholds (rate, burst, slow, trust), TTL, PoW difficulty, weights |
| `redis_pool.lua` | `safe_get/safe_set/safe_incr/pipeline/get/put` — only Redis interface allowed |
| `req_classifier.lua` | Sets `ctx.req_class` ∈ `{resource, navigation, interaction, api_callback, auth_endpoint, feed_or_meta, inapp_browser, unknown}`, plus `score_multiplier`, `rate_weight`, `skip_layers` |
| `ctx/init.lua` | `init(ctx)` — populate `ctx.ip`, `ctx.ua`, `ctx.req` from nginx vars; reset all flags. `finalize(ctx)` — fallback identity if missing |
| `fingerprint/identity.lua` | `build_from(ip, ua)` → md5 — coarse identity (used by rate counter when no full fp yet) |
| `fingerprint/asn.lua` | mmdb lookup → `ctx.asn = {asn_number, asn_org}` |
| `fingerprint/ip_classify.lua` | `ctx.ip_type` (datacenter/vpn/residential), `ctx.ip_score` (0..1) |
| `fingerprint/device_classifier.lua` | UA → `ctx.device_type`, `ctx.device_is_mobile`, `device_sec_fetch_expected`, `device_ch_ua_mobile_expected` |
| `fingerprint/collect_request.lua` | Aggregates fp_full from all fp parts |
| `fingerprint/init.lua` | Orchestrate fp collection |
| `goodbot_seed.lua` | Worker 0 seed `core/data/goodbot.json` → Redis `goodbot:dns:*`, `goodbot:asn:*`, `goodbot:ptr_only:*` (deferred via `ngx.timer.at` because cosocket disabled in init_worker_by_lua) |
| `data/goodbot.json` | DNS suffix + ASN + ptr_only registry for Google/Bing/Meta/Apple/CocCoc |

## ctx fields written (mostly init+populate)
`ip`, `port`, `ua`, `req.{uri,method,host,scheme,accept,referer,proto,…}`, `device_*`, `asn`, `ip_type`, `ip_score`, `req_class`, `score_multiplier`, `rate_weight`, `skip_layers`. **All flags reset to defaults**.

## ctx fields read
None at init phase — first module to run.

## Flow
`access_by_lua` first call → `ctx_layer.init(ctx)` from `STEPS_COMMON[0]` → all later modules consume `ctx.ip/ua/req/device_type/req_class`.

## Related
- Consumed by: every layer
- Reads: `nginx.var.*` only
- Writes Redis: `goodbot_seed.lua` only (one-time, worker 0)

## Important rules
- Never instantiate `resty.redis` directly — always `redis_pool.safe_*`
- New `lua_shared_dict` → declare in `nginx/nginx.conf:49-53` only
- Adding a class in `req_classifier.lua` ripples into score_multiplier + rate_weight + skip_layers — must reconcile with `intelligence/scoring/compute.lua`
- Adding good bot → extend `goodbot.json` + `PTR_ONLY_BOTS` in `detection/bot/ua_check.lua`

## Update log
- `72f0415` (2026-05-03) — no changes here, Phase 1 only touched l7/
