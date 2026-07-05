# core/

Foundational primitives. Loaded by every other module. No business logic — pure utilities.

## Purpose
Config, Redis pool, ctx lifecycle, request classification, fingerprint primitives, good-bot registry seed.

## Files

| File | Role |
|---|---|
| `config.lua` | Thresholds (rate, burst, slow, trust), TTL, PoW difficulty, weights |
| `redis_pool.lua` | `safe_get/safe_set/safe_incr/safe_scard/pipeline/get/put` — only Redis interface allowed |
| `req_classifier.lua` | Sets `ctx.req_class` ∈ `{resource, navigation, interaction, api_callback, auth_endpoint, feed_or_meta, inapp_browser, unknown}`, plus `score_multiplier`, `rate_weight`, `skip_layers` |
| `ctx/init.lua` | `init(ctx)` — populate `ctx.ip`, `ctx.ua`, `ctx.req` from nginx vars; reset all flags. `finalize(ctx)` — fallback identity if missing |
| `fingerprint/identity.lua` | `build_from(ip, ua)` → md5 — coarse identity (used by rate counter when no full fp yet) |
| `fingerprint/asn.lua` | mmdb lookup → `ctx.asn = {asn_number, asn_org}` |
| `fingerprint/ip_classify.lua` | Coarse network-type LABEL only → `ctx.ip_net_type` (residential/datacenter/…) for logging/admin. **IP-type scoring DISABLED** (`ctx.ip_score=0` at source) — DC egress = real users (Private Relay/corp), caused FP. Shared-IP detection is behavioural (`ctx.ip_shared` via ip_tour), NOT ASN |
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
- 2026-07-05 — `fingerprint/device_classifier.lua` — **added `crawler` + `http_client` structural device types** (before the browser tree). `crawler` = self-declared bot (bot-suffix `bot/`;`)` space, `spider`/`crawler`, or `(+http` contact URL — meta-external etc.); `http_client` = no `Mozilla/` AND no engine token (curl/python-requests/Go-http/Java/okhttp). Drains the old catch-all `unknown` (which was ~#1) into meaningful buckets. Enforcement-neutral (device_type isn't scored). Paired with `async/logger.lua` DEVICE_GROUP (`crawler`→"crawler", `http_client`→"tool") and intent rename `good_bot`→`goodbot` / `ambiguous`→`watch` (goodbot removes the only underscore in intent names → fixes admin `%w+` stat-parse that silently dropped good_bot). Admin "Device Distribution" → "Client Distribution". See `admin/CLAUDE.md` 2026-07-05.
- 2026-07-04 — `fingerprint/asn.lua` — **made idempotent + moved earlier**. `asn.run` now returns immediately if `ctx.asn.asn_number` already set. Wired into `init.lua` STEPS_COMMON (right after `ctx_layer.init`, before the fleet aggregator) so `ctx.asn` exists when `detection/fleet/trusted.is_good_crawler` runs — previously asn only resolved in the fingerprint layer (after class dispatch), so fleet's ASN-based bypass silently never fired (`ctx.asn=nil` → always false). The later fingerprint-layer `asn.run` now no-ops. Net: no extra mmdb lookups (moved, not added). Root cause of legit crawler ranges being at risk of fleet /16-dyn-block (Meta actively blocked in prod; Google/Bing preventive). See `antibot-core/CLAUDE.md` 2026-07-04 fleet entry.
- 2026-07-04 — `config.lua` — **`_M.ip_tour` block added** for cross-domain shared-hosting tour detector (`detection/ip_tour.lua`). Keys: `window=90`, `distinct_domains=5`, `distinct_ua_max=3` (NAT gate), `richness_max=0.5` (multi-site admin exempt), `strike_ban=12`, `ban_ttl=300`/`ban_ttl_repeat=3600`. See `detection/CLAUDE.md` 2026-07-04.
- 2026-06-19 (later) — `config.lua` — **`_M.subnet_block` REMOVED** + `_M.fleet_detection` ADDED. `cfg.subnet_block` + `core/access/subnet_block.lua` deleted (was just slow iptables — wasted antibot's request-stream visibility). Replaced by active 3-axis subnet aggregator (`detection/fleet/`). `_M.fleet_detection` holds thresholds/weights/modes/trusted_asn — see `antibot-core/CLAUDE.md` 2026-06-19 (replace operator-driven CIDR list) entry.
- 2026-06-19 — `config.lua` — **`_M.subnet_block` list** added then removed same day (see entry above). Initial design was operator-curated CIDR block; superseded by active fleet detection.
- 2026-06-19 — `config.lua` — **reverted threshold-based anti-sharing tables** (`_M.cookie` / `_M.verified_share`). Methodology was thin; operator empirical test proved subnet-level block is correct layer. See `antibot-core/CLAUDE.md` update log.
- 2026-06-18 — `config.lua` — **`_M.rate.good_bot_rate` table** for generic verified-bot rate ceiling (replaces ad-hoc Meta ASN limit). 3 classes polite/moderate/aggressive/default + bot_name→class map. Adaptive promotion via `gb_aggression:<bot>` TTL self-decay. See `enforcement/CLAUDE.md`.
- 2026-05-24 (v4.4.10) — `req_classifier.lua` — **AUTH_LEGACY_PATHS multi-CMS expansion**: thêm `^/wp-json/wp/v2/users`, `^/admin/` (Drupal/Magento/OpenCart/NukeViet/MyBB), `^/typo3/`, `^/ghost/`, `^/adm/` (phpBB), `^/admin%.php$` (XenForo), `^/admincp/` (vBulletin). File upload xác nhận không ảnh hưởng: multipart blocked bởi CT guard (Fix A) và /wp-admin/ caught bởi FAST PATH 2 trước slow path.
- 2026-05-24 (v4.4.9) — `req_classifier.lua` — **Fix A: body scan CT guard + Fix B: AUTH_LEGACY_PATHS expansion**.
  - Fix A: `body_contains_auth_marker(ct)` — gate trên `application/x-www-form-urlencoded` trước `read_body()`. REST/JSON/multipart → return false ngay, zero read_body overhead. `AUTH_BODY_MARKERS` giảm 19 → 11 entries (loại bỏ JSON/multipart markers — orphaned bởi Fix A).
  - Fix B: `AUTH_LEGACY_PATHS` mở rộng: `^/wp-admin/admin-ajax.php` → `^/wp-admin/` (all WP admin POST); thêm `^/administrator/` (Joomla), `^/filament/` (Laravel Filament), `^/nova/` (Laravel Nova). Mục tiêu: rate_weight=1.5 throttle admin AJAX burst trên multi-CMS server.
- 2026-05-24 (v4.4.7) — `req_classifier.lua` — **inapp_browser FP fix: bot-exclusion guard**.
  - `compute_inapp_likeness()`: thêm guard đầu hàm — nếu `ua` chứa `bot`/`spider`/`crawler` → return 0.0. Bots tự identify tên mình trong UA (RFC 9309); Signal 2 (non-canonical Safari tail) fire oan vì chúng gắn contact URL sau `Safari/X.Y`. In-app browser KHÔNG bao giờ self-identify là bot.
  - Incident: Googlebot smartphone UA `...Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://...)` → inapp_likeness=0.45 → blocked 13 lần trên www.hoanmy.vn (IPs 66.249.66.40, 66.249.71.132 = AS15169). Xác nhận từ log thực tế.
- 2026-05-24 — `req_classifier.lua` — **inapp_browser: generic structural detection, xoá brand-token enumeration**:
  - Xoá `INAPP_UA_TOKENS` (FBAN, ZALO, INSTAPP, ...) và `is_inapp_browser()`. Same anti-pattern: app mới → thêm token = dead-end maintenance.
  - Thay bằng `compute_inapp_likeness(ua, xrw, sec_ch_ua)` → Signal 1 (X-Requested-With reverse-domain `0.6`), Signal 2 (non-canonical Safari tail `0.3`), Signal 3 (Chrome 90+ thiếu Sec-Ch-Ua `0.15`), OS-engine safety net (`0.3` — HarmonyOS, TBS/, KaiOS). Output: `ctx.inapp_likeness ∈ [0,1]`. Threshold 0.4 → class=`inapp_browser`.
  - Mọi Android WebView app hiện tại + tương lai auto-covered qua Signal 1. iOS in-app via Signal 2. Zero code change khi app mới ra.
  - `classify()` updated: call `detect_inapp(ua)` → set `ctx.inapp_likeness` + return class. DEBUG log thêm `inapp=X.XX`.
  - `async/logger.lua`: thêm `inapp=%.2f` vào log format.
- 2026-05-24 (v3-hybrid) — `req_classifier.lua` — **auth_endpoint thêm body semantic fallback**:
  - v2 keyword path detection vẫn assume framework dùng semantic naming. Gap với Magento `loginpost` (no separator), custom obfuscated paths.
  - v3 thêm SLOW PATH: `ngx.req.read_body()` + scan body cho `AUTH_BODY_MARKERS` (password=, passwd=, pwd=, "password", name="password", client_secret=, grant_type=password, otp=, totp=, mfa_code=, verification_code=, ...). Body cap 8KB, chỉ POST mới đến nhánh này. Fast path keyword catches 95% requests → slow path chỉ trigger minority POST.
  - Defense-in-depth: attacker phải bypass cả URI keyword AND body marker (đổi tên password field phá UX).
  - `AUTH_LEGACY_PATHS` giảm 2 → 1 entry (chỉ `/xmlrpc.php` — XML body không có literal `password=`). `/wp-admin/admin-ajax.php` removed vì body detection catch action=login qua marker pwd=.
  - Performance: fast path zero overhead (chỉ 95% requests); slow path ~10-50µs per POST trigger → site 100 req/s với 10% POST → 0.1ms aggregate latency.
- 2026-05-24 (v2) — `req_classifier.lua` — **refactor auth_endpoint từ enumeration → semantic vocabulary**:
  - v1 (commit 32bed76) hardcode ~30 CMS-specific patterns — anti-pattern (cùng vấn đề cookie list trước đây ở session_richness).
  - v2 refactor: `AUTH_KEYWORDS` table 15 từ semantic vocabulary (login, signin, register, auth, oauth, password, token, session, 2fa, mfa, credentials...). `has_auth_keyword_in_path` split URI theo "/", check mỗi component match keyword với word boundary `[-_.]` (tránh FP "author" matching "auth"). Cùng keyword "login" catches /wp-login.php, /user/login, /customer/account/login, /login, /strapi/admin/auth/login bất kể CMS. Generic, zero maintenance khi CMS mới ra.
  - `AUTH_LEGACY_PATHS` exception list nhỏ (2 entries) cho paths bruteforce không có semantic keyword (xmlrpc.php, wp-admin/admin-ajax.php). Mỗi entry có justification rõ ràng.
  - Order fix giữ nguyên từ v1: auth_endpoint check trước interaction JSON (bug POST /wp-json/wp/v2/users với CT application/json bị classify nhầm).
  - Trade-off: Magento `loginpost` (component không có separator giữa login+post) miss — acceptable 95%+ framework dùng semantic naming chuẩn.
- 2026-05-23 (v2) — `session_richness.lua` (NEW) — generic trust proxy for "client has state with server". Measures cookie payload bytes + count + Authorization/CSRF header presence. Output `ctx.session_richness ∈ [0,1]`. Wired in `STEPS_COMMON` (init.lua) after ctx_layer.init. Consumed by `l7/rate/adaptive_limit.lua`, `l7/burst/burst_decision.lua` (threshold lift), `intelligence/scoring/compute.lua` (negative signal weight -30), `async/logger.lua` (richness field in antibot.log). KHÔNG hardcode tên cookie CMS — generic cho WP/Joomla/Drupal/Magento/SPA/JWT/future. Calibration constants (SIZE_SATURATION=500, COUNT_SATURATION=4, AUTH_BONUS=0.3, CSRF_BONUS=0.2) tunable trong file. `config.lua rate.class_burst_factor` table mới: per-class burst threshold multiplier (navigation 0.67, interaction 1.5, api_callback 2.0, auth_endpoint 0.8, feed_or_meta 0.5).
- 2026-05-23 — `req_classifier.lua` — `unknown` class `score_multiplier` 1.0 → 0.5, `rate_weight` 1.0 → 0.5. Nguyên tắc: uncertainty class nên GIẢM penalty, không tăng. Trước đây path không match rule nào (CMS admin lạ: Joomla `/administrator`, Drupal `/?q=admin`, Magento `/admin/dashboard`, custom paths) bị áp full score×1.0 → escalate sớm. Bot thật imitate navigation/interaction pattern (đã rơi class cụ thể). Signal khác (anomaly/h2_bot/cluster) vẫn fire độc lập, đủ bắt nếu thực sự bot. Fix FP cho tuart.xuongweb.com WP admin install — xem `version.txt` 2026-05-23.
- 2026-05-22 — supporting changes for l7 ip_surge hybrid (see `l7/CLAUDE.md`):
  - `config.lua` — new keys in `_M.rate`: `ip_surge_extreme=5000`, `ip_surge_distinct_min=3`, `ip_surge_ban_ttl=300`. Existing `ip_surge_threshold=1500` now means "signal trigger" not "hard-ban trigger".
  - `redis_pool.lua` — new `safe_scard(key)` helper used by `l7/rate/adaptive_limit.lua` to read distinct-identity count from `rate:ids:<ip>` set.
- `72f0415` (2026-05-03) — no changes here, Phase 1 only touched l7/
