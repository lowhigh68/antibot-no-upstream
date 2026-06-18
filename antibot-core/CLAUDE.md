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
- 2026-06-18 — **Cookie anti-sharing defense** (`init.lua` + `core/config.lua`). Defends against PoW-bypass-via-cookie-sharing attack observed from `43.172.0.0/15` subnet (35+ IPs reusing same `antibot_fp` cookie across multiple domains: vantaibienquocte.com, dichtiengphap.net, vanchuyenmyviet.net, vantaiachau.vn, thailandtranslation.net, vietship.net; ~80 load avg, PHP-FPM pool saturation).
  - **Attack pattern**: bot framework solves PoW once on 1 IP → captures `antibot_fp` cookie + `verified:<id>=1` in Redis → replicates cookie to 35+ IPs in `/15` subnet → each request hits cookie fast-path → `ctx.verified=true` → bypass ALL detection (L7, scoring, bot rate limit, score engine). Antibot.log shows `score=0.0 eff=0.0 action=allow reason=device_canvas_verified` for every scraper request. Same `id=...` observed from multiple distinct IPs (proof of cookie reuse).
  - **Defense**: In `check_verified_cookie` (init.lua), after confirming `verified:<cookie>=1`, track distinct source IPs via Redis SET `cookie_ips:<cookie>` (TTL 86400s = 24h sliding window). Atomic pipeline `SADD ip` + `EXPIRE ttl` + `SCARD` = 1 RTT. If `SCARD > cfg.cookie.max_ips_per_cookie` (default 3) → revoke via `DEL verified:<cookie>` + `DEL cookie_ips:<cookie>`, return false → request falls through to normal pipeline → re-challenge. Real users (1-3 IPs/day from home wifi + mobile + occasional public wifi) stay under threshold. Bot fleet must now re-solve PoW per IP — defeats the bypass.
  - **Config**: `cfg.cookie.max_ips_per_cookie = 3`, `cfg.cookie.ip_tracking_ttl = 86400` (core/config.lua). Tunable: 2 too tight (FP mobile 4G/wifi switch), 5 too lax (bot has budget).
  - **Cost**: +1 Redis RTT per verified-cookie request (pipeline batch). Acceptable trade-off for closing critical bypass.
  - **Log**: `[antibot] cookie revoked: shared across N IPs cookie=<first16> ip=<source>` at WARN level.
  - **Edge cases**: mobile user 4G↔wifi switch in same day: 1-2 IPs, OK. Cross-country roaming: rare, accept 1 re-challenge. VPN switch: accept re-challenge. CGNAT: client-reported IP usually stable.
- 2026-06-18 — **Generic verified-bot rate ceiling + adaptive class promotion** (`enforcement/decision/engine.lua` + `core/config.lua` + `async/logger.lua`). REPLACES Meta-specific `throttle_meta_asn`. 3-class table (polite/moderate/aggressive/default) with per-bot map. Adaptive promotion via `gb_aggression:<bot>` TTL 600s self-decay. See `enforcement/CLAUDE.md` update log for details.
- 2026-05-24 (v3-hybrid) — **auth_endpoint body semantic fallback** (`core/req_classifier.lua`). v2 keyword detection vẫn miss Magento `loginpost` + custom obfuscated paths. v3 thêm slow path: `ngx.req.read_body()` + scan `AUTH_BODY_MARKERS` (password=, passwd=, pwd=, "password", client_secret=, grant_type=password, otp=, totp=...). Body cap 8KB, chỉ POST trigger. Fast path catches 95% (zero body read), slow path catches obfuscated. Defense-in-depth. `AUTH_LEGACY_PATHS` giảm 2 → 1 (chỉ xmlrpc.php — XML body không có literal password=).
- 2026-05-24 (v2) — **Refactor auth_endpoint: framework enumeration → semantic vocabulary** (`core/req_classifier.lua`). v1 (commit 32bed76) hardcode ~30 CMS-specific patterns = anti-pattern (cùng problem cookie list ở session_richness). v2: `AUTH_KEYWORDS` table 15 từ semantic auth chuẩn (login/signin/register/auth/password/token/...). `has_auth_keyword_in_path` split URI theo "/", check word boundary `[-_.]` trong từng component. Single keyword "login" catches ALL frameworks `/wp-login.php`, `/user/login`, `/customer/account/login`, `/login`, `/strapi/admin/auth/login`. Zero maintenance. `AUTH_LEGACY_PATHS` exception list 2 entries cho paths không có semantic keyword (xmlrpc.php, wp-admin/admin-ajax.php). Order fix giữ nguyên: auth check trước interaction JSON. Trade-off: Magento `loginpost` (không separator) miss — acceptable.
- 2026-05-24 — **Generic auth_endpoint detection + classify order fix v1** (`core/req_classifier.lua`). Enumeration approach (hardcoded CMS patterns) — RỜI BỎ. Order fix giữ. Xem v2 phía trên.
- 2026-05-23 (v3) — **Generic kill-switch cho dampened class non-resource** (`enforcement/decision/engine.lua`). Bù gap do Fix A' (commit 649031e) tạo ra: `unknown` mult 0.5 + raw 140 = eff 70 → challenge mãi không lên block. Incident 20.9.70.139 (Azure UA-empty bot, ASN=AS8075 Microsoft, ua=, multiple bot signals fire). Kill thresholds: `raw≥150→floor 85% raw`, `raw≥110→floor 65% raw`. Áp dụng cho mọi class có `score_multiplier<1.0` TRỪ resource (đã có kill riêng raw 80/95). Defense-in-depth: dampening giảm FP cho normal, KILL escalate cho pure-threat storm. Threshold cao (110) đảm bảo logged-in admin user (sau khi trừ session_richness -24 pts) không trigger nhầm.
- 2026-05-23 (v2) — **Generic burst handling: session_richness + class_burst_factor** — orthogonal lift cho burst/rate threshold:
  - **`core/session_richness.lua` (NEW)** — generic trust proxy. Measure BẰNG CHỨNG VẬT LÝ client có state: cookie payload bytes + count + Authorization/CSRF header. `ctx.session_richness ∈ [0,1]`. Không hardcode tên cookie → cover MỌI CMS hiện tại + tương lai. Run trong STEPS_COMMON sau ctx_layer.init.
  - **`core/config.lua rate.class_burst_factor`** — multiplier per req_class: navigation 0.67 (20/s, tighten), interaction 1.5 (45/s, SPA AJAX), api_callback 2.0 (webhook retry), auth_endpoint 0.8 (anti credential-stuffing), feed_or_meta 0.5 (crawler 1-shot).
  - **`l7/burst/burst_decision.lua`** — rewrite: `effective = base × class_factor × (1 + richness×2)`. Orthogonal 2-dim threshold.
  - **`l7/rate/adaptive_limit.lua`** — per-ID rate cũng hưởng richness lift. KHÔNG apply vào ip_surge (per-IP, NAT có nhiều session).
  - **`intelligence/scoring/compute.lua`** — `session_richness` = NEGATIVE signal (weight -30). richness 0.8 trừ 24 pts khỏi total. Fix `contribution_pct` calc dùng `pos_total` riêng để trust signal không méo % của threat signals.
  - **`async/logger.lua`** — append `richness=X.XX` vào antibot.log mỗi request (volume control qua daily rotate).
  - Effective thresholds: WP admin AJAX = 117/s, anonymous SPA = 58/s, bot scrape = 45/s, multi-tab user (nav) = 20/s, login bot = 24/s.
  - Threat coverage: bot fake cookie 500 byte random vẫn bị anomaly + h2_bot + ip_score + rate_flag bắt. Mất ~65/100+ pts → defense-in-depth OK.
- 2026-05-23 — **Generic FP fixes: unknown-class dampening + res_ip gating** (`core/req_classifier.lua` + new `l7/rate/res_ip_counter.lua` + `init.lua` + `detection/session/session_store.lua`):
  - **Fix A'** — `unknown` class `score_multiplier` 1.0 → 0.5, `rate_weight` 1.0 → 0.5. Nguyên tắc bayesian: uncertainty GIẢM penalty (không tăng). Request không classify được thường là CMS admin lạ (Joomla/Drupal/Magento/custom), không phải bot — bot imitate browser pattern → đã vào class cụ thể. Signal anomaly/h2_bot/cluster vẫn fire độc lập đủ bắt nếu thực sự bot.
  - **Fix B'** — `resource_starved` IP-level gating. Root cause: resource class skip fingerprint → `ctx.identity=nil` → `res_count` per identity LUÔN = 0 cho mọi browser session. Browser thật load CSS/JS hàng chục lần mà signal vẫn fire. Fix: NEW `l7/rate/res_ip_counter.lua` runs in `STEPS_RESOURCE` (init.lua) → INCR `res_ip:<ip>` (TTL 60s). `session_store.lua` đọc trước khi fire — nếu `res_ip >= 5` thì suppress. Threshold 5 để stray hit từ NAT peer không giải vây cho bot.
  - **Defer C'** — h2_bot_confidence warm-up grace (Chrome H1→H2 connection coalescing FP) — observe log sau khi deploy A'+B' để xác định còn cần không.
  - Incident: WordPress admin install + Flatsome theme trên tuart.xuongweb.com, IP 14.232.154.94 (FTTH VN resident, Chrome 148) bị block 13:15:22 — score 37→83 trong 1 giây do `resource_starved=44%` + `class=unknown mult=1` + `mismatch` (H2 coalescing). Sau fix: score ước tính ~27 → monitor (thay vì block).
  - Operator action: `redis-cli DEL "ban:9d24102d4ea42f791bee1c9699ec9a31" "ban:hit:9d24102d4ea42f791bee1c9699ec9a31" "viol:9d24102d4ea42f791bee1c9699ec9a31" "ban:14.232.154.94" "ip_risk:14.232.154.94"` sau deploy.
- 2026-05-22 — **ip_surge hybrid model** in `l7/rate/adaptive_limit.lua` (rewrite) + `l7/rate/counter.lua` (distinct-id SADD) + `intelligence/scoring/compute.lua` (signal registration) + `core/config.lua` (new `ip_surge_extreme`, `ip_surge_distinct_min`, `ip_surge_ban_ttl`) + `core/redis_pool.lua` (`safe_scard` helper).
  - Old: `ip_rate > 1500/60s` → unilateral hard-ban IP 1800s. False-positive on first-run extension users (Claude Code observed), CGNAT, AI-agent browsing, multi-tab e-commerce.
  - New Tier 1 (signal): `ip_rate > ip_surge_threshold` (1500) → `ctx.ip_surge=true` → scoring layer decides via aggregate. Clean-fingerprint browser passes (reaches MONITOR only).
  - New Tier 2 (hard ban): `ip_rate > ip_surge_extreme` (5000) **AND** `distinct identities < ip_surge_distinct_min` (3) → ban with `ip_surge_ban_ttl` (300s). Extreme rate gated by NAT diversity check.
  - Operator note: clear stale ban with `redis-cli DEL ban:<ip> ban:hit:<ip>` after deploy if you whitelisted any IPs as workaround.
- 2026-05-19 (v2) — `bot/init.lua:contact_attest` Path 1b cloud fallback. When good_bot_claimed + compliant UA + PTR resolved but PTR does NOT suffix-match contact URL eTLD+1, accept PTR ending in cloud provider suffix (`cloud_suffixes.lua`) as sufficient for S2.5. Fixes Pingdom screenshot fleet on AWS (UA `(pingbot/2.0; +http://www.pingdom.com/)`, PTR `ec2-*.amazonaws.com` — Pingdom doesn't setup their domain reverse DNS for cloud-rented IPs). Reason `contact_cloud_attested`. Threat trade-off: attacker can spin up cloud VM + register domain + compliant UA → S2.5 cap monitor; mitigated by anomaly/behavior signals still scoring under cap.
- 2026-05-19 — **S2.5 attest tier** (Phase 1) — generic mechanism for legitimate bots/tools not in hardcoded registry:
  - **Path 1 contact attest** (`bot/init.lua:contact_attest`): UA RFC-compliant `(compatible; *; +http://host)` + PTR suffix-matches eTLD+1 of contact URL → S2.5
  - **Path 2 analyzer attest** (`bot/init.lua:analyzer_attest`): browser-pattern UA + tool marker tail (`Chrome-Lighthouse`, `GTmetrix`, …) + PTR ends in cloud provider suffix → S2.5
  - S2.5 reward: `bot_score=0` (auto-breaks `ip_risk` EMA loop via existing `bot_score>0.3` guard), `asn_rep=0` waive (PTR attest covers datacenter prior), skip cluster+graph (cascade prevention), engine **caps action at monitor** (Q17=b — bot SDKs don't solve PoW so challenge=block-effective)
  - New file `detection/bot/cloud_suffixes.lua` — universal cloud PTR suffix list + browser standard token blacklist. NOT a bot list.
  - `dns_reverse.lua:lookup_ptr(ip)` exported helper for Path 2 (good_bot_claimed=false branch).
  - Fixes: Pinterestbot (Path 1, PTR `crawl-*.pinterest.com`), UptimeRobot/Pingdom (Path 1), PageSpeed Lighthouse (Path 2, GCP PTR), GTmetrix (Path 2)
  - Phase 2 deferred: behavioral signals (rate/path-breadth/header convergence → downgrade), lite_attest before l7 (vấn đề O1)
- 2026-05-04 — `detection/distributed_swarm.lua` class-aware thresholds (Option C): navigation `25/45`, auth_endpoint `8/15`, feed_or_meta `45/90`, api_callback `12/25`, interaction `20/35`, inapp_browser `20/35`, unknown `15/30` (legacy). Weight `swarm_attack = 120` GIỮ NGUYÊN. Fix VN flash crowd FP (popular product page 30 /24 cùng UA Chrome bị block oan). Compute.lua scoring math không thay đổi — sensitivity adjusted at signal SOURCE per req_class.
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
