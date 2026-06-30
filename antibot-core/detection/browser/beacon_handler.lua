local _M   = {}
local pool = require "antibot.core.redis_pool"

-- Accept beacons within ±60s of server time.
-- Wider than typical replay windows to accommodate client clock drift.
local REPLAY_WINDOW_MS = 60000

function _M.handle()
    if ngx.var.request_method ~= "POST" then
        ngx.exit(405); return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then ngx.exit(400); return end

    local ok, data = pcall(require("cjson").decode, body)
    if not ok or not data then ngx.exit(400); return end

    -- Map obfuscated field names back to canonical names.
    -- New JS sends: p=fp, a=cv, b=wgl, c=nav, d=ent, e=hd, f=beh, t=timestamp_ms
    -- Old JS sends clear names (fp, cv, wgl, nav, ent) — accepted for compatibility.
    local fp  = data.p or data.fp
    local cv  = data.a or data.cv
    local wgl = data.b or data.wgl
    local nav = data.c or data.nav
    local ent = data.d or data.ent
    local hd  = data.e or data.hd
    local beh = data.f or data.beh
    local ts  = data.t

    if not fp or #fp ~= 32 then ngx.exit(400); return end

    -- Replay guard: reject if beacon timestamp is outside ±60s window.
    -- Legitimate browsers fire the beacon 2s after page load → always recent.
    if ts then
        local diff = math.abs(ngx.now() * 1000 - ts)
        if diff > REPLAY_WINDOW_MS then
            ngx.exit(400); return
        end
    end

    local fp_exists = pool.safe_get("fp:" .. fp)
    if not fp_exists then ngx.exit(403); return end

    local payload = {
        cv  = cv,
        wgl = wgl,
        nav = nav,
        ent = ent,
        hd  = hd,
        beh = beh,
        ts  = ngx.time(),
    }

    local store_ok, json = pcall(require("cjson").encode, payload)
    if store_ok then
        pool.safe_set("beacon_data:" .. fp, json, 600)
        pool.safe_set("beacon:" .. fp, "1", 600)
    end

    ngx.status = 204
    ngx.exit(204)
end

return _M
