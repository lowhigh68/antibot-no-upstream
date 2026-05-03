# admin/

Web UI + JSON API for runtime introspection. Mounted at `/antibot-admin` in hostname.conf only (Basic-auth + IP allowlist).

## Purpose
Operator visibility: ban list, ip_risk top, signal weights, recent decisions, manual override (unban, set goodbot, change weight).

## Files

| File | Role |
|---|---|
| `init.lua` | Single-file router. HTML/JS embedded as Lua long-string (`[[ ... ]]`). Routes: `/` (dashboard), `/api/stats`, `/api/bans`, `/api/unban`, `/api/goodbot`, `/api/weights`, `/api/recent` |

## Auth
Hardcoded in `init.lua`:
- `AUTH_USER`, `AUTH_PASS` — Basic-auth
- IP allowlist enforced in nginx server block before `content_by_lua_block`:
```nginx
location ^~ /antibot-admin {
    access_by_lua_block {
        local allowed = { ["192.168.168.114"]=true, ["14.191.162.213"]=true, ["127.0.0.1"]=true }
        if not allowed[ngx.var.remote_addr] then ngx.exit(403) end
    }
    content_by_lua_block { require("antibot.admin").router() }
}
```

## ctx fields read
None (admin endpoint, separate from request pipeline)

## Redis keys read/written
Reads: `ban:*`, `ip_risk:*`, `viol:*`, `goodbot:*`, `weights:*`, `verified:*`, recent decisions
Writes: same (manual override)

## Flow
```
Operator browser → https://<hostname>/antibot-admin/
  ↓ Basic-auth + IP check
content_by_lua → admin.router()
  ↓ dispatch URI to handler
respond JSON or HTML
```

## Important rules
- AUTH_USER/AUTH_PASS hardcoded — DON'T log or rotate casually
- IP allowlist hardcoded in nginx conf — update when admin IP changes
- Endpoint NOT mounted on per-domain confs — only hostname.conf (so attacker can't probe via random vhost)
- Modifications via API mirror Redis writes — same TTL/key conventions as core code

## Update log
- `72f0415` (2026-05-03) — no changes
