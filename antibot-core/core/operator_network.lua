-- Published operator-network evidence for automation clients.
--
-- `nginx/scripts/monitor_ip_sync.sh` writes
-- `mon:<ip> = <policy>@<operator-domain>`.
-- A network match alone is NOT a whitelist and NOT a good-bot verification.
-- This module promotes only a matching self-identified automation client to
-- the separate `operator` tier.  Detection/scoring still run; the final engine
-- may cap block/challenge at monitor, and the L7 automation governor still
-- meters aggressive traffic.

local _M = {}

local pool = require "antibot.core.redis_pool"

local POS_TTL = 300
local NEG_TTL = 60
local MISS = "-"

local function normalize_record(value)
    if value == nil then return nil, nil end
    value = tostring(value):lower():gsub("%.$", "")
    if value == "1" or value == "legacy@legacy" then
        return "legacy", "legacy"
    end
    local mode, owner = value:match("^(claim)@([%w%.%-]+)$")
    if not mode then mode, owner = value:match("^(ipcap)@([%w%.%-]+)$") end
    -- Seven-day/partial-deploy compatibility: a plain owner written by the
    -- first v2 draft is interpreted as claim-bound, never as an IP-only cap.
    if not mode and value:match("^[%w%.%-]+$") then
        mode, owner = "claim", value
    end
    if not mode or owner == "" then return nil, nil end
    return mode, owner
end

local function suffix_match(host, owner)
    if not host or not owner or owner == "legacy" then return false end
    host = tostring(host):lower():gsub("%.$", "")
    return host == owner
        or (#host > #owner and host:sub(-#owner - 1) == "." .. owner)
end

-- Bind source network to the claimant without an AI-bot product allowlist.
-- Contact-domain equality is strongest.  Opaque products such as
-- `anthropic-ai` can bind to the first label of `anthropic.com`; this is still
-- only operator-tier evidence and never grants the good-bot bypass.
local function owner_matches_claim(ctx, owner)
    if owner == "legacy" then return nil end
    local claim = ctx.automation_inspect or {}
    if suffix_match(claim.contact_domain, owner) then return "contact" end

    if claim.machine_claimed == true then
        local stem = owner:match("^([^.]+)")
        local principal = tostring(ctx.automation_principal or ""):lower()
        if stem and #stem >= 4 and principal:find(stem, 1, true) then
            return "stem"
        end
    end
    return nil
end

function _M.lookup(ip)
    local dict = ngx.shared and ngx.shared.antibot_cache
    local ckey = "opnet:" .. ip
    if dict then
        local cached = dict:get(ckey)
        if cached ~= nil then
            if cached == MISS then return nil, nil end
            return normalize_record(cached)
        end
    end

    local raw = pool.safe_get("mon:" .. ip)
    local mode, owner = normalize_record(raw)
    if dict then
        dict:set(ckey, mode and (mode .. "@" .. owner) or MISS,
            mode and POS_TTL or NEG_TTL)
    end
    return mode, owner
end

function _M.resolve(ctx)
    if not ctx or not ctx.automation_meter_claimed then return false end
    local ip = tostring(ctx.ip or "")
    if ip == "" then return false end

    local mode, owner = _M.lookup(ip)
    local bind = owner and owner_matches_claim(ctx, owner) or nil
    if not bind then return false end

    ctx.operator_network_verified = true
    ctx.operator_network_name = owner
    ctx.operator_network_mode = mode
    -- Keep the evidence strength visible: contact is a domain-bound claim;
    -- stem is the weaker generic inference used for opaque product tokens.
    ctx.operator_network_bind = bind
    ctx.automation_claimed = true
    ctx.automation_meter_claimed = true
    ctx.automation_tier = "operator"
    ctx.automation_proof = "published_ip"
    return true
end

function _M.run(ctx)
    _M.resolve(ctx)
    return true, false
end

return _M
