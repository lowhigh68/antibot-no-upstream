# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An OpenResty / Lua antibot module that runs inline on a DirectAdmin shared-hosting box. OpenResty terminates TLS on `0.0.0.0:80/443` and `proxy_pass`es cleartext traffic to Apache on `127.0.0.1:8080` (HTTP) and `127.0.0.1:8081` (HTTPS). Apache is addressed by literal IP, not via an `upstream {}` block — see [nginx/nginx.conf](nginx/nginx.conf) and the header of [nginx/da_to_openresty.sh](nginx/da_to_openresty.sh) for the reasoning (keeping `$remote_addr` as the real client IP, avoiding `Content-Length` breakage when `body_filter_by_lua` injects the beacon JS).

Source comments and user-facing strings are bilingual (Vietnamese + English). Preserve the language of surrounding text when editing.

## Deployment layout

Source under `antibot-core/` deploys to `/usr/local/openresty/nginx/conf/antibot/` on the server. `nginx.conf` sets:

```
lua_package_path "/usr/local/openresty/nginx/conf/?.lua;/usr/local/openresty/nginx/conf/?/init.lua;...";
```

so `require "antibot.detection.bot.ua_check"` resolves to `conf/antibot/detection/bot/ua_check.lua`. When adding a new module, the `require` path mirrors the directory structure under `antibot-core/`.

There is no build step, no test runner, no linter in the repo. Iteration loop on the server:

```bash
/usr/local/openresty/nginx/sbin/nginx -t      # syntax check
/usr/local/openresty/nginx/sbin/nginx -s reload
```

`da_to_openresty.sh` regenerates per-domain configs from DirectAdmin data and runs the test/reload itself (see [nginx/da_to_openresty.sh:666](nginx/da_to_openresty.sh#L666)). Invocations:

```bash
sudo bash da_to_openresty.sh                  # full rebuild
sudo bash da_to_openresty.sh --user U         # one user
sudo bash da_to_openresty.sh --domain D
sudo bash da_to_openresty.sh --dry-run
sudo bash da_to_openresty.sh --install-hooks
sudo bash da_to_openresty.sh --user U --domain D --remove
```

Bad-bot UA list is refreshed by parsing `globalblacklist.conf` with [ua_parse.py](ua_parse.py) (stdout = JSON array) and pushed into Redis by `scripts/ua_sync.sh` (not in this repo); the admin UI has an `ua_sync` button that shells out to that script.

## Request lifecycle

The per-domain server blocks emitted by `da_to_openresty.sh` wire Lua phases like this (see [nginx/da_to_openresty.sh:261-357](nginx/da_to_openresty.sh#L261-L357)):

| Phase | Handler |
|---|---|
| `ssl_client_hello_by_lua` | `antibot.transport.tls.ja3.capture` (HTTPS only) |
| `ssl_certificate_by_lua` | `antibot.transport.tls.ja3s.capture` (HTTPS only) |
| `access_by_lua` | `require("antibot").run()` |
| `header_filter_by_lua` | confirms `text/html` response, sets `ctx.browser_needed`, clears `Content-Length` |
| `body_filter_by_lua` | `antibot.detection.browser.inject.filter` (beacon injection) |
| `log_by_lua` | `require("antibot").log()` |
| `init_worker_by_lua` | `require("antibot").init_worker()` (memory_guard timer) |

`location = /antibot/verify`, `/antibot/beacon`, `/antibot/debug` are injected into every server block (see `antibot_locations()` in the generator). The admin dashboard in [antibot-core/admin/init.lua](antibot-core/admin/init.lua) exposes `/antibot-admin`, `/antibot-admin/data`, `/antibot-admin/wl` — it's referenced from generated configs but wired separately; if you rename routes, grep for them there.

Beacon injection uses a **two-phase design** — the request-side `trigger.lua` sets `ctx.inject_candidate` from the `Accept` header, and `header_filter_by_lua` only confirms by reading the **actual** response `Content-Type`. Both must agree before the body filter rewrites anything. Never short-circuit this: CSS/JS/image responses must never have their `Content-Length` cleared.

## Pipeline inside `antibot.run()`

[antibot-core/init.lua](antibot-core/init.lua) is the only entry point. Flow:

1. **Cookie fast-path** — if `cookie_antibot_fp` exists and Redis key `verified:<cookie>` is `"1"`, set `ctx.verified` and return. Nothing else runs.
2. **Classifier** — [core/req_classifier.lua](antibot-core/core/req_classifier.lua) tags the request as one of `resource | navigation | interaction | api_callback | inapp_browser | unknown`, each with its own `score_multiplier`, `rate_weight`, and `skip_layers` map (defined in `CLASS_CONFIG`). **Changes to classification logic ripple into every layer** that reads `ctx.skip_layers` — expect the scoring, detection, and cluster layers to all consult it.
3. **`STEPS_COMMON`** always runs: `ctx` init → `l7.ban.ip_ban_check` → `device_classifier` → `access` (whitelist) → `transport` (TLS + HTTP/2 fingerprint).
4. **Class-dispatched steps** — `resource` runs only `intelligence + enforcement`; `interaction`, `inapp_browser`, and everything else run the full stack: `fingerprint` (fatal on failure) → `l7` → `detection` → `intelligence` → `enforcement`.
5. Each step returns `(ok, exit)`. `exit == true` stops the pipeline (used when ban/challenge already served a response). `ok == false` with `fatal = true` → 500.

In `_M.log()` (log phase), `risk_update` and `adaptive_weight` are scheduled via `ngx.timer.at(0, …)` and `logger.run(ctx)` is called inline — so never block in these.

## Module layers (what lives where)

- **`core/`** — platform primitives. `config.lua` (single source of truth for thresholds, weights, TTLs, endpoint sensitivity), `redis_pool.lua` (connection pool + `safe_get/safe_set/safe_incr/pipeline` helpers — always use these, never instantiate `resty.redis` directly), `ctx/`, `req_classifier.lua`, `access/` (whitelist), `fingerprint/` (identity, device, geoip, asn, collect_request).
- **`transport/`** — L4/L5: `tls/ja3.lua`, `tls/ja3s.lua`, `tls/ja3_stream.lua`, `http2/*` (frame/hpack/pseudo-header/window signatures).
- **`l7/`** — rate limiting, burst, slow-loris, IP ban check. `l7/ban/ban_store.lua` early-exits the pipeline; `l7/init.lua` is the orchestrator.
- **`detection/`** — scoring modules, one subdir per signal family: `bot/` (UA check, DNS forward/reverse), `anomaly/` (header/protocol/UA), `behavior/`, `session/`, `cluster/` (UA/URI/IP/TLS swarms), `graph/` (sequence patterns), `browser/` (JS beacon: `trigger` → `inject` → `beacon_handler` → `collect` → `canvas`/`webgl`/`entropy` → `store`). Each subdir has an `init.lua` that respects `ctx.skip_layers`.
- **`intelligence/`** — cross-request correlation and final scoring. `threat/` holds IP/ASN/JA3/H2 reputation DBs and allow/block lists. `scoring/compute.lua` aggregates ctx signals into `ctx.score`, using per-signal weights and `ctx.skip_layers` (via `SIGNAL_SOURCE`). **If you add a new signal, register it in both `DEFAULT_WEIGHTS` and `get_signal()` there.**
- **`enforcement/`** — `decision/engine.lua` converts `ctx.score` + multipliers + trust + `ip_risk` into `allow | monitor | challenge | block`. `challenge/` handles PoW token issue + verify + nonce store. `ban/` writes ban state with escalating TTLs (`cfg.ttl.ban_steps`). `explain.lua` emits human-readable decision context.
- **`async/`** — timer-scheduled work: `risk_update`, `adaptive_weight` (weight learning), `logger`, `memory_guard`.
- **`admin/init.lua`** — self-contained HTTP admin UI + JSON API, Basic-auth gated. The HTML/JS is embedded as a Lua long-string — editing the dashboard means editing that string.

## Scoring model (read before changing weights)

- `intelligence.scoring.compute` walks `DEFAULT_WEIGHTS`, pulls each signal via `get_signal(name, ctx)` (value in `[0,1]`), multiplies by weight, sums into `ctx.score`. Top 5 contributors are stored in `ctx.top_signals`.
- `enforcement.decision.engine` then applies: `score_multiplier` (from classifier), `trust_multiplier` (from session length + `session_flag`), `fp_penalty` (degraded fingerprint / low `fp_quality` / partial JA3), and a `resource`-class boost that caps at `RESOURCE_MAX_SCORE = 40`.
- **Kill-switches** for `resource` class: if `raw_score >= 95`, effective score is forced to ≥85 (block); `raw_score >= 80` forces ≥60 (challenge). This prevents static-file bypass when all signals are screaming.
- **IP-risk threshold lowering**: if `ctx.ip_risk >= 0.4`, the challenge threshold drops from 55 to 40 for that request (Attack 1 defense against UA-switching from the same IP). Disabled for `api_callback`.
- Thresholds in `config.lua` (`allow/monitor/challenge/block = 0/25/80/100`) and in `engine.lua` (`MONITOR/CHALLENGE/BLOCK = 25/55/80`) are **both live** — `config.lua` seeds external consumers, `engine.lua` is what actually decides. If you change one, reconcile with the other.

## Redis key conventions

Everything goes through `core.redis_pool`. Common key prefixes (non-exhaustive, grep before inventing a new one):

- `ban:<ip>` / `ban:<identity>` — active bans, TTL from `cfg.ttl.ban_steps`
- `ban_ctx:<id>` — JSON blob captured at ban time (ua, device, bot_score, ip)
- `rep:<ip>` — IP reputation score
- `risk:<identity>` — rolling risk score
- `ip_risk:<ip>` — IP-level risk aggregate
- `viol:<id>` — violation counter
- `verified:<cookie>` — `"1"` ⇒ fast-path allow
- `wl:<ip>`, `wl:url_set`, `wl:url_list` — whitelist
- `rl:<key>` — rate-limit counters
- `nonce:<id>` — challenge nonce (short TTL from `cfg.ttl.nonce`)
- `badbot:ua_patterns`, `badbot:ua_custom_set`, `badbot:ua_count`, `badbot:ua_sync_time`
- `goodbot:dns:<name>`, `asn:type:<asn>`
- `ja3:allow:<hash>`, `ja3:block:<hash>`
- `stat:<host>:<action>:<YYYYMMDD>` — daily counters used by the dashboard
- `threat:last_sync`, `threat:stats` — threat-intel sync state

Admin UI `wl` endpoint actions ([antibot-core/admin/init.lua:47](antibot-core/admin/init.lua#L47)) are the authoritative list of supported mutations.

## Things to know before editing

- **Secrets are currently hardcoded** in `admin/init.lua` (`AUTH_USER`/`AUTH_PASS`) and `core/config.lua` (`pow.challenge_secret`). Treat them as production secrets — don't regenerate casually, don't log them, and flag it if the user asks for a change that would rotate them.
- **`cfg.pow.difficulty = "000"`** means PoW hashes need 3 hex zeros — tuning this impacts user latency; don't change without being asked.
- **`ctx.skip_layers`** is the mechanism for "don't run this layer on this class". New layers MUST check it via their own `should_run` helper, following the pattern in [detection/init.lua](antibot-core/detection/init.lua).
- **Fatal vs non-fatal steps**: only `fingerprint_layer` is marked fatal. Other layer errors are logged and the pipeline continues. Don't change this without thinking about what happens when e.g. Redis is down.
- **Beacon injection** assumes Apache sends uncompressed HTML. If you introduce gzip on the upstream side, the body filter won't match and injection silently fails.
- `lua_shared_dict` names in use: `antibot_tls`, `whitelist_cache`, `antibot_stats`, `antibot_ua_cache`, `antibot_cache` — declared in [nginx/nginx.conf:49-53](nginx/nginx.conf#L49-L53). Add new dicts there, not in per-domain configs.
