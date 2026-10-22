local _M   = {}
local pool = require "antibot.core.redis_pool"
local admission = require "antibot.l7.admission"
local decision = require "antibot.core.decision"

-- Accept beacons within ±60s of server time.
-- Wider than typical replay windows to accommodate client clock drift.
local REPLAY_WINDOW_MS = 60000

local function finish(ctx, status, kind, reason)
    ctx.action = status == 204 and "allow" or "block"
    ctx.action_reason = reason
    decision.set(ctx, {
        kind = kind or "policy", source = "browser_beacon", rule = reason,
        mode = "enforce", scope = "request", upstream = false,
    })
    ngx.status = status
    ngx.exit(status)
end

function _M.handle()
    local _, limited = admission.run_endpoint("beacon")
    if limited then return end
    local ctx = (ngx.ctx and ngx.ctx.antibot) or {}
    if ngx.ctx then ngx.ctx.antibot = ctx end

    if ngx.var.request_method ~= "POST" then
        finish(ctx, 405, "policy", "beacon_method"); return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then finish(ctx, 400, "policy", "beacon_body_missing"); return end

    local ok, data = pcall(require("cjson").decode, body)
    if not ok or type(data) ~= "table" then
        finish(ctx, 400, "policy", "beacon_json_invalid"); return
    end

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

    if type(fp) ~= "string" or #fp ~= 32
       or fp:match("^[0-9A-Fa-f]+$") == nil then
        finish(ctx, 400, "policy", "beacon_fp_invalid"); return
    end

    -- Replay guard: reject if beacon timestamp is outside ±60s window.
    -- Legitimate browsers fire the beacon 2s after page load → always recent.
    if ts then
        ts = tonumber(ts)
        if not ts then
            finish(ctx, 400, "policy", "beacon_ts_invalid"); return
        end
        local diff = math.abs(ngx.now() * 1000 - ts)
        if diff > REPLAY_WINDOW_MS then
            finish(ctx, 400, "security", "beacon_replay"); return
        end
    end

    local fp_exists = pool.safe_get("fp:" .. fp)
    if not fp_exists then
        finish(ctx, 403, "security", "beacon_unknown_fp"); return
    end

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

    finish(ctx, 204, "policy", "beacon_stored")
end

return _M
