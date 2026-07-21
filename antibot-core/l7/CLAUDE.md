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
| `expensive_filter_guard.lua` | **RESOURCE-keyed** combinatorial-filter-crawl guard. Runs in `STEPS_COMMON` (after `ip_tour`, before short-circuit → sees every caller incl. verified). Detects faceted-filter signature generically (≥`min_values` comma/dot-separated values in one path-segment OR query-param — no param-name enumeration), keys on `base` listing path (strip query + comma-segments), meters DISTINCT combos per base via HLL `xf:combos:<host>:<base>:<bucket>`. `mode=shadow` appends `xf_base/xf_combos/xf_hits/xf_over` to the antibot.log line (via `async/logger.lua`, correlate with richness/class/ip); `enforce` → 429 `action_reason=expensive_filter` when combos > `combos_threshold`. Config `cfg.expensive_filter` |

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
- 2026-07-21 — **`ban_store.lua` — shared-identity FP guard (cả văn phòng bị `banned_id`)** (Fix A + Fix B). `ban:<id>` khóa NGUYÊN văn phòng thay vì 1 máy.
  - **Chữ ký nhận dạng:** nhiều người / cả văn phòng cùng bị "Access denied", antibot.log `reason=banned_id`, **cùng một `id=<hash>`**, cùng `ip=` (IP NAT), `score=0.0`, `richness` cao (0.6-0.8, UA browser thật). Các request `class=resource` vẫn `action=allow` (resource không set identity), chỉ `navigation` dính.
  - **Gốc rễ:** `ctx.identity = md5(ip + ua_norm)` và `normalize_ua` gộp Chrome về **`"Chrome/<major>"`** (bỏ minor/build/**OS**) — `core/fingerprint/identity.lua:72-73`. Văn phòng = chung IP NAT + cùng major browser → **collapse về MỘT identity hash** → `ban:<id>` = ban cả cụm (IP, browser-major), không per-device. Escalation (`viol++` mỗi F5) kéo tới permanent. Vì sao lá chắn cũ trượt: `ip_shared` cần distinct-**raw**-UA≥6 (có thể fire) nhưng thiết kế vẫn cố tình `ban:<id>` per-identity (giả định id=device — SAI khi collapse); `auth_session_cap` nằm trong ENGINE, chạy SAU khi `ban_store.lua` `ngx.exit(403)` seal ở cửa → không cứu được.
  - **Fix A (richness gate):** `ban:<id>` khớp + `session_richness ≥ SHARED_ID_RICHNESS(0.5)` → bỏ seal + KHÔNG escalate, trả về pipeline cho scoring phán live (score~0 → allow). richness tính PER-REQUEST (cookie/auth của chính request) → phân biệt từng người trong cùng identity. Đặt TRƯỚC khối escalation. Cứu nhân viên **đã đăng nhập**.
  - **Fix B (shared-IP challenge):** `ban:<id>` khớp + `ctx.ip_shared` + `Accept: text/html` → serve PoW (`enforcement.challenge.run`) thay vì 403, KHÔNG escalate. Người thật giải 1 lần → `verified:<cookie>` → bypass ở cookie fast-path (init.lua) cho mọi request sau; bot không giải nổi → chặn hiệu quả. Cứu nhân viên **duyệt ẩn danh**. `action_reason=banned_id_shared_challenge`. Request non-HTML (XHR/static) rơi xuống seal cứng — nhưng navigation đầu đã verify nên request sau được tha.
  - **Còn lại:** văn phòng monoculture cực đoan (mọi máy CÙNG raw-UA y hệt → distinct raw-UA<6 → `ip_shared` không fire) thì user ẩn danh vẫn bị; Fix A vẫn cứu user login. Fix gốc sâu hơn (identity mịn per-device) để sau. `SHARED_ID_RICHNESS` giữ đồng bộ với `engine.AUTH_SESSION_RICHNESS`.
- 2026-07-10 — **`expensive_filter_guard.lua` — BAN 24h theo bằng chứng PER-IP** (`+ core/config.lua _M.expensive_filter.ban_* + async/logger.lua xf_ipcombos`). Trước đây guard chỉ 429; giờ ban `ban:<ip>` TTL 24h cho crawler TẬP TRUNG.
  - **Cái bẫy FP tránh được:** 429 fire theo `over = combos > combos_threshold` = chỉ số của TÀI NGUYÊN (gộp mọi caller). Ban theo điều kiện đó = gánh tội tập thể → user thật ẩn danh (richness thấp) lỡ ghé listing đang bị botnet cào sẽ bị ban oan. Nên ban TÁCH RỜI khỏi `over`, chỉ dựa **per-IP distinct-combo**: HLL riêng `xf:ipc:<host>:<base>:<ip>:<bucket>` (PFADD cùng pipeline, res[7]). Ban khi `ip_combos >= cfg…ban_ip_combos(20)` — MỘT IP tự nó cào ≥20 tổ hợp filter nặng/window = crawler bất khả chối (người thật 1-3). Metering chạy TRƯỚC nhánh 429 nên request bị 429 vẫn cộng vào per-IP HLL → crawler leo dần tới 20 rồi ban; user thật 1-2 combo không bao giờ tới ngưỡng.
  - **Giới hạn bản chất (đã thống nhất với operator):** distributed 1-req/IP swarm (vd ca 372 IP × 1 req) có ~1 combo/IP → KHÔNG chạm ngưỡng → **không ban được theo IP** (đúng — 1 IP/1 req không phân biệt với người thật; ép ban = FP hàng loạt). Ca đó GIỮ NGUYÊN nguyên tắc cũ = 429 resource-throttle. Ban chỉ giải quyết crawler tập trung trên ít IP.
  - **Exempt (nhất quán hệ thống):** good bot + whitelist (return sớm), `ctx.ip_shared_verified` (Tier-2 office/CGNAT nhiều user cookie thật — 1 IP không ban nuke cả nhà; cờ có sẵn vì guard chạy sau `ip_tour`), `session_richness >= exempt_richness(0.5)` (phiên đã login). Loopback bỏ qua.
  - **Admin hiện đúng:** `write_ip_ban` mirror `enforcement/ban/ban_store_write` — viết `ban:<ip>` + `ban:hit:<ip>` (ACTIVE) + `ban_ctx:<ip>` (score=ip_combos, reason=expensive_filter_ban). Guard exit 403 tại STEPS_COMMON nên ban_store_write không chạy → phải tự viết. `l7/ban/ip_ban_check` (chạy trước guard) seal request kế ở cửa.
  - **Recognition signature:** antibot.log `reason=expensive_filter_ban` + `xf_ipcombos>=20`; error.log `[xf] BAN ip=… ip_combos=…`. IP hiện tab BAN TTL ~24h. Tuning: `grep xf_ipcombos antibot.log` xem phân bố per-IP; hạ/nâng `ban_ip_combos`. Tắt ban (về nguyên tắc cũ chỉ 429) = `cfg.expensive_filter.ban_enabled=false`.
- 2026-07-08 — **`expensive_filter_guard.lua` calibrated → ENFORCE**. Shadow 24h (thbvietnam.com): real users 1-3 distinct combos/base/window, good bots (Googlebot/Bing/Meta) ~28-109, attack botnet 320-543. Refinements before enabling: (1) **skip `req_class=="resource"`** (versioned asset queries like `js.cookie.min.js?ver=` false-triggered the dot-detector, harmless combos=1 but noise); (2) **`ua_claims_good_bot` excluded from BOTH meter and enforce** — good bots go the DNS/ASN registry lane + are limited by the good_bot rate ceiling; excluding them from PFADD stops their legit crawl (Googlebot alone drove a base to 109) from inflating the counter and collaterally 429-ing later real users; (3) **`session_richness >= exempt_richness(0.5)` exempt from 429 but STILL metered** (protects logged-in power-users doing multi-facet filters; keeps visibility if a bot games cookies to reach 0.5). `mode=enforce`, `combos_threshold=60` (20× margin over human max). Revert = `cfg.expensive_filter.mode="shadow"`. NOTE: good-bot exclusion + richness exemption ARE caller-keyed, but only on attributes not gameable here (DNS/ASN good-bot is infra-verified; current botnet is richness=0) — the resource-keyed COUNTER remains the primary defense.
- 2026-07-07 — **`expensive_filter_guard.lua` NEW — RESOURCE-keyed combinatorial-filter-crawl guard** (shadow mode). Third metering axis after `ip_tour` (per-IP) and `distributed_swarm` (per-/24): the first keyed PURELY on the target resource (base listing path), immune to IP/UA/verified rotation.
  - **Problem it solves:** two attacks hit the same faceted-filter endpoint but leak through different caller-keyed defenses — (a) verified bot (Meta) crawling PATH filters `/loc-a,b,c.html` bypasses via the good-bot/verified lane; (b) distributed botnet crawling QUERY filters `?filter_attr=a.b.c` evades per-IP scoring + `distributed_swarm` (UA-fragmented). Common invariant = the base listing page (uncacheable combinatorial DB query). Attacker rotates IP/UA/canvas-verified to fragment every per-caller counter; a per-base-path counter can't be fragmented (1000 IPs → 1000 contributions to ONE counter → trips faster as attack scales).
  - **Mechanism:** generic faceted-filter detection (≥`min_values` comma/dot separators in ONE path-segment or query-param value — structural, no param-name list) → `base` = uri with query + comma-segments stripped → `PFADD xf:combos:<host>:<base>:<bucket>` md5(combo) → PFCOUNT = distinct combos. DISTINCT-combo (not rate) is the human/crawler discriminator: humans reuse a few combos, crawlers enumerate hundreds; flash-crowd = high rate + low distinct → safe. **NOT exempt by verified/richness** (verification can be gamed — see the Meta `device_canvas_verified` leak, `core/CLAUDE.md` 2026-07-07); the metric itself is the FP protection.
  - **Placement:** `STEPS_COMMON` after `ip_tour`, before the post-COMMON good_bot/verified short-circuit → meters EVERY caller. `mode=shadow` (default) appends `xf_base/xf_combos/xf_hits/xf_over` to the **antibot.log** per-request line (via `async/logger.lua`) — NOT error.log; calibration greps antibot.log where full context (richness/class/ip/reason) lives on the same line. Flip `cfg.expensive_filter.mode=enforce` → 429 `action_reason=expensive_filter` when `combos > combos_threshold`. Redis HLL O(1)/base, self-expiring, fail-open. Only the `enforce` 429 event logs to error.log (escalated action, consistent with ban_write/rate-exceeded).
- 2026-05-23 (v2) — **burst/rate threshold lift hai chiều**:
  - `burst/burst_decision.lua` rewrite: `effective = burst_threshold × class_burst_factor[class] × (1 + ctx.session_richness × 2)`. Hai dimension orthogonal × multiplicative.
  - `rate/adaptive_limit.lua` per-ID `thresh = base × (1 - ip_score×risk_factor) × (1 + richness×2)`. KHÔNG apply richness vào ip_surge/extreme (per-IP có NAT mixed traffic).
  - Effective thresholds: WP admin AJAX 117/s, anonymous SPA 58/s, bot 45/s, multi-tab nav 20/s, login bot 24/s.
  - `class_burst_factor` config ở `core/config.lua rate.class_burst_factor`. `session_richness` compute ở `core/session_richness.lua` (STEPS_COMMON).
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
