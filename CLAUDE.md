# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

## Project: AntiBot v4.x (OpenResty/Lua — DirectAdmin shared hosting)

**Stack:** OpenResty terminates TLS → `proxy_pass` to Apache on `127.0.0.1:8080/8081`. `$remote_addr` = real client IP (no upstream block). Source in `antibot-core/` deploys to `/usr/local/openresty/nginx/conf/antibot/`.

**Reload loop:**
```bash
/usr/local/openresty/nginx/sbin/nginx -t && /usr/local/openresty/nginx/sbin/nginx -s reload
```

## Pipeline: `antibot.run()`

1. **Cookie fast-path** — `verified:<cookie> == "1"` → set `ctx.verified`, return immediately.
2. **Classifier** (`core/req_classifier.lua`) — tags as `resource | navigation | interaction | api_callback | auth_endpoint | feed_or_meta | inapp_browser | unknown`. Sets `score_multiplier`, `rate_weight`, `skip_layers`. Changes here ripple into every layer.
3. **`STEPS_COMMON`** — always runs: ctx init → `l7.ban.ip_ban_check` → `device_classifier` → `access` (whitelist) → `transport` (TLS + HTTP/2 fingerprint).
4. **Short-circuit after COMMON** — if `ctx.verified` OR `ctx.whitelisted` → return immediately (avoids l7 counters running on LAN/admin/loopback whitelist hits).
5. **Class-dispatched** —
   - `resource` → `STEPS_RESOURCE`: `bot_lite_verify` → intelligence → enforcement (no fingerprint/l7/detection — kept lightweight).
   - `interaction` → `STEPS_INTERACTION`: full stack.
   - others → `STEPS_FULL_DETECTION`: `fingerprint` → `l7` → `detection` → `intelligence` → `enforcement`.
6. Each step returns `(ok, exit)`. `exit==true` stops pipeline. `ok==false` + `fatal==true` → 500. Only `fingerprint_layer` is fatal.

**`action_reason` discipline:** any module that calls `ngx.exit(...)` MUST set `ctx.action` and `ctx.action_reason` first — `log_by_lua` runs after exit and produces `reason=-` otherwise. Pattern in `l7/ban/ban_store.lua` (`banned_id`), `l7/ban/ip_ban_check.lua` (`banned_ip`), and `engine.lua` (`whitelisted`, `good_bot_verified`, `good_bot_asn_lite`).

**Beacon injection** is two-phase: `trigger.lua` sets `ctx.inject_candidate` from `Accept` header; `header_filter_by_lua` confirms via actual response `Content-Type`. Both must agree. Never short-circuit — CSS/JS/image responses must never have `Content-Length` cleared.

## Bot Verification (7 paths, see `memory/project_bot_verification.md`)

Pipeline `detection/bot/init.lua:run` (full classes) and `detection/bot/lite_verify.lua:run` (resource class). UA self-claim → `ctx.good_bot_claimed=true` + populates `ctx.good_bot_asns` and `ctx.good_bot_ptr_only` from hardcoded `PTR_ONLY_BOTS` registry in `ua_check.lua` (Redis override: `goodbot:asn:<name>`, `goodbot:ptr_only:<name>`).

| Path | Trigger | Modules | `action_reason` | Result |
|---|---|---|---|---|
| Full DNS verify (S4) | non-resource good bot, normal infra | `dns_reverse` (PTR suffix) → `dns_forward` (A contains source IP) | `good_bot_verified` | bypass scoring, allow |
| PTR-only (S4) | Meta family — rotating IPs break forward A | `dns_reverse` only; `dns_forward` returns early when `ctx.good_bot_ptr_only` | `good_bot_verified` | bypass scoring, allow |
| ASN fallback (S3) | DNS NXDOMAIN/timeout/bad-suffix but UA claims good bot | `bot/init.lua:asn_fallback_verify` matches `ctx.asn.asn_number` against `good_bot_asns` | `good_bot_asn_verified` | bypass scoring, allow |
| Lite verify (S3) | resource class (skips fingerprint+detection) | `STEPS_RESOURCE[1]` runs `lite_verify.lua` (ua_check + asn lookup + match, no DNS) | `good_bot_asn_lite` | bypass scoring, allow |
| **Contact attest — PTR (S2.5)** | UA RFC-compliant `(compatible; *; +http://host)` + PTR suffix-matches contact URL eTLD+1 | `bot/init.lua:contact_attest` 1a after `dns_reverse` returns `dns_rev_valid=false` | `contact_ptr_match` | scored, **cap monitor**, waive `bot_score` + `asn_rep`, skip cluster+graph |
| **Contact attest — cloud (S2.5)** | UA compliant + PTR ends in known cloud provider suffix (operator runs on cloud, no domain reverse-DNS setup — e.g. Pingdom screenshot from AWS) | `bot/init.lua:contact_attest` 1b cloud fallback | `contact_cloud_attested` | scored, **cap monitor**, waive `bot_score` + `asn_rep`, skip cluster+graph |
| **Analyzer attest (S2.5)** | Browser-pattern UA + tool marker tail (e.g. `Chrome-Lighthouse`) + PTR ends in cloud provider suffix | `bot/init.lua:analyzer_attest` runs when `good_bot_claimed=false` | `analyzer_attested` | scored, **cap monitor**, waive `bot_score` + `asn_rep`, skip cluster+graph |

Hardcoded ASNs: `AS15169` Google, `AS8075` Bing, `AS32934` Meta, `AS714/6185/2709` Apple, `AS135905` CocCoc. Default registry seeded into Redis from `core/data/goodbot.json` by `core/goodbot_seed.lua` on worker 0 (deferred via `ngx.timer.at` because cosocket is disabled in `init_worker_by_lua`).

Cloud PTR suffix list (for S2.5 Path 2) hardcoded in `detection/bot/cloud_suffixes.lua` — universal infrastructure, NOT a bot list. Browser tail token blacklist in same file excludes `Mobile/Safari/Edge/...` so they never match analyzer marker regex.

S2.5 difference vs S3/S4: does NOT set `good_bot_verified` → engine still computes score, but caps action at `monitor` (never `challenge`/`block`). bot_score=0 also auto-breaks the `ip_risk:<ip>` EMA loop (guard in `async/risk_update.lua` requires `bot_score>0.3` to raise). Designed for bots whose operator setup PTR+contact-URL but aren't in the hardcoded registry — generic mechanism, no per-bot config needed.

`lite_verify` logs at `ngx.WARN` so verify path appears in `/var/log/antibot/antibot.log` (INFO is filtered). To add a new good bot: extend `goodbot.json` + `PTR_ONLY_BOTS` table — OR rely on Path 1/2 generic attest with no file changes.

## Module Map

| Layer | Path | Role |
|---|---|---|
| core | `core/config.lua`, `redis_pool.lua`, `req_classifier.lua`, `goodbot_seed.lua`, `data/goodbot.json` | Thresholds, Redis pool, classification, good-bot registry seed |
| transport | `transport/tls/`, `transport/http2/` | JA3/JA3S, H2 fingerprints |
| l7 | `l7/` | Rate limiting, burst, slow-loris, IP ban (`ban_store`/`ip_ban_check` set `action_reason` before exit) |
| detection | `detection/bot/{init,ua_check,dns_reverse,dns_forward,lite_verify}.lua`, `anomaly/`, `browser/`, `cluster/`, `graph/` | Signal families; each `init.lua` checks `ctx.skip_layers`. `bot/` houses the 4-path verification |
| intelligence | `intelligence/scoring/compute.lua`, `threat/` | Aggregates `ctx.score`; add new signals to `DEFAULT_WEIGHTS` + `get_signal()` |
| enforcement | `enforcement/decision/engine.lua`, `challenge/`, `ban/`, `explain.lua` | Decision + PoW + ban writes. Engine short-circuits on `whitelisted` and `good_bot_verified` |
| async | `async/` | `risk_update`, `adaptive_weight`, `logger`, `memory_guard` (timer-based) |
| admin | `admin/init.lua` | HTTP UI + JSON API, Basic-auth. HTML/JS embedded as Lua long-string. |

## Scoring Model

- `compute.lua` walks `DEFAULT_WEIGHTS`, pulls signals via `get_signal(name, ctx)` (value `[0,1]`), sums into `ctx.score`.
- `engine.lua` short-circuits on `ctx.whitelisted` then on `ctx.good_bot_verified` (any of the 4 paths) — both bypass scoring entirely.
- Otherwise applies: `score_multiplier` (classifier) × `trust_multiplier` + `fp_penalty` + resource-class boost capped at `RESOURCE_MAX_SCORE = 40`.
- **`fp_penalty`:** `JA3_PARTIAL_PENALTY = 0` (no-stream architecture never captures cipher list → ja3_partial is constant, not a bot signal). Only `fp_degraded` (5) and `fp_quality<0.5` (3) contribute, scaled 0.5× for `interaction`/`api_callback`.
- **Kill-switches for `resource`:** raw ≥95 → effective ≥85 (block); raw ≥80 → effective ≥60 (challenge). These bypass class multiplier dampening — must be paired with `lite_verify` short-circuit to avoid FP on Googlebot/Bingbot fetching images.
- **IP-risk lowering (Attack 1):** `ctx.ip_risk >= 0.4` drops challenge threshold 55→40 to catch UA-switching from same IP (disabled for `api_callback`). Sets `ctx.ip_risk_lowered=true`.
- **Trust cap:** trusted/active session caps challenge → `cfg.trust.action_cap` (default `monitor`).
- **`auth_session_cap` (session_verified tier):** `session_richness ≥ 0.5` (authenticated logged-in session) caps block/challenge → `monitor`. Third trust tier alongside `good_bot_verified`/`ip_shared_verified`. Recognition: a real logged-in admin (richness≈0.80) hard-blocked at `/wp-admin` then `banned_id` cascade, driven by identity-correlation signals (`session_flag`/`graph_flag`/`mismatch`/`cluster_score`/`risk`) amplified by `auth_endpoint ×1.5`, with a self-reinforcing `risk:<id>` loop. Monitor (not challenge — admin-ajax is XHR) also decays the loop. See `enforcement/CLAUDE.md` 2026-07-06.
- Class multipliers (`req_classifier.lua`): `resource=0.2`, `navigation=1.0`, `interaction`/`api_callback` exist with own values, `auth_endpoint=1.5` (POST to `/wp-login.php`, `/xmlrpc.php`, `wp-admin/admin-ajax.php`, `wp-json/wp/v2/users`), `feed_or_meta=0.4` (`/robots.txt`, `/feed/`, `/sitemap*.xml` — also skips graph/cluster/browser/anomaly/behavior/session).
- Thresholds exist in **both** `config.lua` (external consumers) and `engine.lua` (actual decisions). Change one → reconcile the other.

## Key Rules

- **Redis:** always use `core.redis_pool` helpers (`safe_get/safe_set/safe_incr/pipeline`). Never instantiate `resty.redis` directly.
- **New signal:** register in `DEFAULT_WEIGHTS` AND `get_signal()` in `compute.lua`.
- **New layer:** must check `ctx.skip_layers` via `should_run` helper (follow `detection/init.lua` pattern).
- **New good bot:** add UA pattern to `ua_check.lua` regex chain (use `ua_lower:match(...)` for case-insensitive non-`bot`/`spider`/`crawler` names), add entry to `PTR_ONLY_BOTS` table, add suffix list to `core/data/goodbot.json` (and `ptr_only` array if rotating IPs). No other file changes needed.
- **New `ngx.exit` site:** set `ctx.action` and `ctx.action_reason` before exiting, otherwise antibot.log shows `reason=-`. Do not depend on enforcement layer to label the action.
- **`lua_shared_dict`** names (`antibot_tls`, `whitelist_cache`, `antibot_stats`, `antibot_ua_cache`, `antibot_cache`) declared in `nginx/nginx.conf:49-53` — add new dicts there only.
- **Secrets** hardcoded in `admin/init.lua` (`AUTH_USER`/`AUTH_PASS`) and `config.lua` (`pow.challenge_secret`). Don't log or rotate casually.
- **`cfg.pow.difficulty = "000"`** — tuning impacts user latency, don't change without explicit request.
- `log_by_lua`: `risk_update` and `adaptive_weight` run via `ngx.timer.at(0,…)` and skip `req_class=="resource"`. Never block in log phase.
- **Init-worker cosocket:** disabled in `init_worker_by_lua*`. Defer Redis/DNS work via `ngx.timer.at(0, fn)` (see `goodbot_seed` invocation in `init.lua:init_worker`).

