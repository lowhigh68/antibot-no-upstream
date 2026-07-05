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
| `distributed_swarm.lua` | Cross-identity attack pattern detection → `ctx.swarm_attack` (0.3–1.0, =1.0 at HARD threshold; many /24 → ONE domain). NOTE: sets `ctx.swarm_attack`, NOT the boolean `ctx.swarm` (that's `cluster/swarm_detect.lua`, a different signal) |
| `ip_tour.lua` | Cross-domain tour detection → `ctx.ip_tour` (ONE ip → many domains). Runs in `STEPS_COMMON` (after access_layer), NOT here. HLL `iptour:dom/ua:<ip>`, NAT-gated by distinct-UA, richness-exempt, strike→direct-ban |
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
   └─ distributed_swarm.run → ctx.swarm_attack (NOT ctx.swarm — see top-level files note)
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
- 2026-07-04 — **`ip_tour.lua` NEW — cross-domain shared-hosting tour detector**. Targets operator-confirmed attack: a few bot IPs "tour" across many tenant domains on the shared host, each domain at MODERATE req/s (occasionally hitting wp-admin/login), so per-IP `ip_surge` and per-(IP,domain) `burst` are both blind while aggregate PHP-FPM+MySQL load spikes. Antibot's structural advantage: all tenant domains funnel through one OpenResty+Redis → a single IP's distinct-domain count is visible here, which no per-site WAF can see.
  - **Signal, not hard block**: sets `ctx.ip_tour`. Enforcement decided in `enforcement/decision/engine.lua` AFTER `good_bot_verified` short-circuit → verified crawlers (Googlebot/Bingbot legitimately crawl every domain) exempt automatically, no per-bot config. Engine floors `ip_tour` → `challenge` (challenge-first) before trust cap.
  - **Discriminators (all must hold)**: `distinct_domains ≥ cfg.ip_tour.distinct_domains` (touring) AND `distinct_ua < distinct_ua_max` (single-source — NAT gate: office/CGNAT hitting many domains ALSO carries many UAs; identity not available this early so distinct-UA is the proxy) AND `session_richness < richness_max` (logged-in multi-site admin exempt). distinct-domain is a CARDINALITY not a request count → a real user on ONE site for hours stays at 1 → zero FP on long sessions.
  - **Ban-if-repeat**: each flagged request increments `iptour:strike:<ip>`. Real user solves PoW → verified cookie → cookie fast-path → never re-enters → strikes stop. Bot can't solve → strikes cross `strike_ban` → direct `ban:<ip>` (sealed at door by `l7/ban/ip_ban_check` on every domain). Direct-ban gated on NOT `ua_claims_good_bot` (claimers go through DNS-verify/scoring, never hard-banned here). TTL escalates via `iptour:age:<ip>` (300s first → 3600s repeat).
  - **Storage** (Redis HLL, same primitive as `distributed_swarm`): `iptour:dom:<ip>` PFADD host, `iptour:ua:<ip>` PFADD md5(ua), `iptour:strike:<ip>`, `iptour:age:<ip>`. One pipeline/request (6 ops, 1 RTT), fail-open. Config `cfg.ip_tour` (core/config.lua). Signal registered in `intelligence/scoring/compute.lua` (`ip_tour=25`). Complements `distributed_swarm` (orthogonal axis) + `fleet` (per-/24) — none previously counted distinct-domain-per-IP.
- 2026-05-23 — **`session/session_store.lua` IP-level resource_starved gating** — before setting `ctx.resource_starved=true`, read `res_ip:<ip>` (populated by new `l7/rate/res_ip_counter.lua` running in `STEPS_RESOURCE`). If `res_ip >= 5` → suppress signal (IP đang load resource thật, signal sai semantic). Threshold 5 chọn để 1 stray hit từ user khác trên NAT không giải vây cho bot — giảm FN risk shared-NAT khi mix bot+human traffic. Root cause cũ: resource class skip fingerprint → res_count tracked per identity LUÔN = 0 cho mọi browser → signal fire oan. Fix FP cho WordPress admin install (Flatsome theme, tuart.xuongweb.com). New log markers: `resource_starved suppressed (ip has res activity)` (gating thắng), `resource_starved ... res_ip=X` (fire thật). See `version.txt` 2026-05-23 + `l7/CLAUDE.md`.
- 2026-05-24 (v4.4.7) — `bot/ua_check.lua` — **unregistered_bot path: thêm `ctx.good_bot_asns = get_bot_asns(bot_name)`**.
  - Root cause: khi Redis không có `goodbot:dns:<name>` (seed chưa chạy / transient flush), code rơi vào `unregistered_bot` branch. Branch này set `ctx.good_bot_suffixes={}` nhưng KHÔNG set `ctx.good_bot_asns`. `asn_fallback_verify()` trong `bot/init.lua` check `ctx.good_bot_asns` → nil → return false → bot bị classify là fake. Mất fallback path dù AS15169 đã hardcode trong PTR_ONLY_BOTS.
  - Fix: gọi `get_bot_asns(bot_name)` (đọc từ PTR_ONLY_BOTS trước, Redis sau) và gán vào `ctx.good_bot_asns` trong cả hai branch.
- 2026-05-19 (v2) — `bot/init.lua:contact_attest` Path 1b — fall back to cloud-PTR check when PTR doesn't match contact URL eTLD+1 (Pingdom-on-AWS case). Same S2.5 reward but new reason `contact_cloud_attested`. Single function edit.
- 2026-05-19 — **S2.5 attest tier** in `bot/init.lua`:
  - 2 new helpers `contact_attest()` (Path 1) + `analyzer_attest()` (Path 2) — both grant `ctx.bot_identity_tier="S2.5"` and set `ctx.skip_layers.cluster/graph = true` (cascade prevention)
  - `ua_check.lua` populates `bot_ua_compliant`, `bot_contact_host`, `browser_ua_pattern`, `analyzer_marker` up-front before headless/bot-claim branches
  - `bot_score.lua` honors `ctx.bot_identity_tier=="S2.5"` (returns bot_score=0, skips ua_flag escalation that would re-raise it)
  - `dns_reverse.lua:lookup_ptr(ip)` exported for Path 2 (called when good_bot_claimed=false)
  - `cloud_suffixes.lua` (new) — hardcoded `CLOUD_PTR_SUFFIXES` + `BROWSER_STANDARD_TOKENS` blacklist for marker regex
- `72f0415` (2026-05-03) — no changes here, Phase 1 only touched l7/
- 2026-05-04 — `distributed_swarm.lua` class-aware thresholds (Option C):
  - navigation `25/45` (relax — VN popular product flash crowd OK)
  - auth_endpoint `8/15` (tighten — credential stuffing protection)
  - api_callback `12/25`, feed_or_meta `45/90`, interaction `20/35`
  - inapp_browser `20/35`, unknown `15/30` (legacy default)
  - Weight `swarm_attack = 120` GIỮ NGUYÊN — không thay đổi scoring math
  - Logs include `class=` + threshold values for tuning per-class
  - Fix: VN e-commerce popular product page bị block khi 30 /24 cùng UA Chrome browse simultaneously (organic flash crowd ≠ swarm bot)
