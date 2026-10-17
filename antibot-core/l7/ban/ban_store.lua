local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local ua_claim = require "antibot.detection.bot.ua_claim"
local quarantine = require "antibot.core.network_quarantine"

-- A session established by this host may pass a coarse network-UA seal. This
-- is not a whitelist: the request continues through the live pipeline.
local SHARED_ID_RICHNESS = 0.5

-- Keep these in sync with detection/bot/init.lua. A previously proved crawler
-- is allowed to re-enter verification unless a fresh contradicted verdict is
-- present for the same network-UA subject.
local FAKE_VERDICT_PREFIX = "botverdict:fake:"
local CRAWLER_PREFIX      = "crawler:"

local function selected_seal(results, host_keys, global_keys, legacy_keys, legacy_read)
    if results and results[2] == "1" then return global_keys, false end
    if results and results[3] == "1" then return host_keys, false end
    if legacy_read and results and results[4] == "1" then
        return legacy_keys, true
    end
    return nil, false
end

function _M.run(ctx)
    local qcfg = cfg.network_quarantine or {}
    if qcfg.enabled == false then
        ctx.banned = false
        return false, false
    end

    local id = quarantine.network_id(ctx)
    if not id or id == "" then
        ctx.banned = false
        return false, false
    end

    local host_keys   = quarantine.keys(ctx, "host")
    local global_keys = quarantine.keys(ctx, "global")
    local legacy_keys = quarantine.legacy_keys(ctx)

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_store] redis unavailable: ", err)
        ctx.banned = false
        return false, false
    end

    -- One round trip. New host/global namespaces are authoritative. The old
    -- ban:<id> namespace is read-only during migration and expires naturally.
    red:init_pipeline()
    red:get("wl:id:" .. id)
    red:get(global_keys.ban)
    red:get(host_keys.ban)
    if qcfg.legacy_read ~= false then red:get(legacy_keys.ban) end
    local res = red:commit_pipeline()
    pool.put(red)

    if res and res[1] == "1" then
        ctx.whitelisted   = true
        ctx.action_reason = "id_whitelist"
        ctx.banned        = false
        ngx.log(ngx.INFO, "[ban_store] id_whitelist bypass id=", id:sub(1, 8))
        return false, false
    end

    local keys, legacy = selected_seal(
        res, host_keys, global_keys, legacy_keys, qcfg.legacy_read ~= false)
    if not keys then
        ctx.banned = false
        return false, false
    end

    ctx.ban_id        = id
    ctx.ban_id_kind   = "network_ua"
    ctx.ban_scope     = keys.scope
    ctx.ban_host      = keys.host
    ctx.ban_key       = keys.ban
    ctx.ban_legacy    = legacy

    local ua = ctx.ua or ngx.var.http_user_agent or ""
    if ua_claim.claims_good_bot(ua)
       and ctx.ip and pool.safe_get(CRAWLER_PREFIX .. ctx.ip) == "1"
       and pool.safe_get(FAKE_VERDICT_PREFIX .. id) ~= "1" then
        ngx.log(ngx.INFO,
            "[ban_store] defer good_bot_claim id=", id:sub(1, 8),
            " scope=", keys.scope, " ua=", ua:sub(1, 60))
        ctx.banned          = false
        ctx.ban_deferred_gb = true
        return false, false
    end

    local richness = ctx.session_richness_own or 0
    if richness >= SHARED_ID_RICHNESS
       and ctx.session_cookie_known == true then
        ngx.log(ngx.INFO,
            "[ban_store] richness_bypass id=", id:sub(1, 8),
            " scope=", keys.scope,
            " r=", string.format("%.2f", richness))
        ctx.banned = false
        return false, false
    end

    local accept = (ctx.req and ctx.req.accept) or ngx.var.http_accept or ""
    local html_navigation = accept:find("text/html", 1, true) ~= nil

    -- Host quarantine is deliberately recoverable for every browser
    -- navigation, not only after the separate distinct-UA detector calls the IP
    -- shared. A managed office can have many cloned machines with exactly the
    -- same normalized UA, so distinct-UA evidence may remain one forever.
    -- Legacy seals retain the narrower old shared-IP recovery rule.
    if html_navigation
       and (keys.scope == "host" or (keys.scope == "legacy" and ctx.ip_shared)) then
        pool.safe_set(keys.hit, tostring(ngx.time()), 300)
        ctx.action        = "challenge"
        ctx.action_reason = keys.scope == "host"
            and "network_quarantine_challenge"
            or "banned_id_shared_challenge"
        ctx.banned = false
        ngx.log(ngx.INFO,
            "[ban_store] recovery_challenge id=", id:sub(1, 8),
            " scope=", keys.scope,
            " host=", keys.host,
            " ip=", ctx.ip or "?",
            " r=", string.format("%.2f", richness))
        require("antibot.enforcement.challenge").run(ctx)
        return true, true
    end

    -- A seal hit is not new evidence. Record activity only; never increment a
    -- violation counter and never refresh or lengthen the sentence here.
    pool.safe_set(keys.hit, tostring(ngx.time()), 300)
    ctx.banned = true
    ctx.action = "block"
    if keys.scope == "global" then
        ctx.action_reason = "global_identity_ban"
    elseif keys.scope == "host" then
        ctx.action_reason = "network_quarantine"
    else
        ctx.action_reason = "banned_id"
    end

    ngx.log(ngx.INFO,
        "[ban_store] blocked id=", id:sub(1, 8),
        " scope=", keys.scope,
        " host=", keys.host,
        " legacy=", tostring(legacy))
    ngx.status = 403
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Access denied.")
    ngx.exit(403)
    return true, true
end

return _M
