local _M  = {}
local bit = require "bit"
local cfg = require "antibot.core.config"

-- Subnet-level deterministic block list.
--
-- Operator-managed CIDR blocklist for subnets EMPIRICALLY confirmed as
-- pure bot infrastructure. Each entry has a label (operator-defined
-- category) that propagates into action_reason and admin dashboard for
-- audit/grouping. See `cfg.subnet_block` comment in core/config.lua for
-- entry format and validation protocol.
--
-- Hit telemetry: each match INCRs `subnet_hit:<cidr>:<YYYYMMDD>` (TTL 8d)
-- so admin dashboard can show per-subnet daily hit counts. Cheap (1 INCR
-- per block) and lets operator detect which subnets still active vs
-- candidates for review.

local PARSED = {}  -- { {base_masked, mask, prefix, cidr_str, label, note}, ... }
local INITIALIZED = false

local function ip_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local ai, bi, ci, di = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not (ai and bi and ci and di) then return nil end
    if ai > 255 or bi > 255 or ci > 255 or di > 255 then return nil end
    return bit.bor(
        bit.lshift(ai, 24),
        bit.lshift(bi, 16),
        bit.lshift(ci, 8),
        di
    )
end

local function parse_cidr(cidr)
    local base_str, prefix_str = cidr:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    if not base_str then return nil end
    local prefix = tonumber(prefix_str)
    if not prefix or prefix < 0 or prefix > 32 then return nil end

    local base_int = ip_to_int(base_str)
    if not base_int then return nil end

    -- Refuse 0.0.0.0/0 as misconfiguration safety
    if prefix == 0 then return nil end

    local mask = bit.lshift(0xFFFFFFFF, 32 - prefix)
    local base_masked = bit.band(base_int, mask)
    return base_masked, mask, prefix
end

-- Normalize entry into {cidr, label, note}. Accepts both string and table
-- forms for backward compatibility with older config style.
local function normalize_entry(entry)
    if type(entry) == "string" then
        return { cidr = entry, label = "default", note = "" }
    elseif type(entry) == "table" and entry.cidr then
        return {
            cidr  = entry.cidr,
            label = entry.label or "default",
            note  = entry.note  or "",
        }
    end
    return nil
end

local function init()
    if INITIALIZED then return end
    local list = cfg.subnet_block or {}
    for _, raw in ipairs(list) do
        local e = normalize_entry(raw)
        if not e then
            ngx.log(ngx.ERR, "[subnet_block] invalid entry ignored")
        else
            local base_masked, mask, prefix = parse_cidr(e.cidr)
            if base_masked then
                PARSED[#PARSED + 1] = {
                    base_masked, mask, prefix, e.cidr, e.label, e.note
                }
            else
                ngx.log(ngx.ERR, "[subnet_block] invalid CIDR ignored: ", e.cidr)
            end
        end
    end
    INITIALIZED = true
    if #PARSED > 0 then
        ngx.log(ngx.INFO, "[subnet_block] loaded ", #PARSED, " block rules")
    end
end

-- Returns matched rule table {cidr, label, note} if IP is in any blocked
-- subnet, else nil. Used by admin to expose rule list with labels.
local function lookup_rule(ip)
    if not INITIALIZED then init() end
    if #PARSED == 0 then return nil end

    local ip_int = ip_to_int(ip)
    if not ip_int then return nil end

    for i = 1, #PARSED do
        local rule = PARSED[i]
        if bit.band(ip_int, rule[2]) == rule[1] then
            return { cidr = rule[4], label = rule[5], note = rule[6] }
        end
    end
    return nil
end

-- Expose parsed rule list to admin for dashboard rendering.
function _M.list_rules()
    if not INITIALIZED then init() end
    local out = {}
    for i = 1, #PARSED do
        local r = PARSED[i]
        out[i] = { cidr = r[4], label = r[5], note = r[6], prefix = r[3] }
    end
    return out
end

_M.lookup_rule = lookup_rule

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    -- IPv6 not handled in this v1 (no IPv6 subnets confirmed-bot yet).
    if ip:find(":", 1, true) then
        return true, false
    end

    local matched = lookup_rule(ip)
    if not matched then
        return true, false
    end

    -- Hit telemetry: INCR per (cidr, day). 8-day TTL gives 7-day window
    -- for admin dashboard + 1-day safety margin. ngx.timer.at defers to
    -- log phase context — never block request path.
    ngx.timer.at(0, function(premature)
        if premature then return end
        local ok, pool = pcall(require, "antibot.core.redis_pool")
        if not ok then return end
        local key = "subnet_hit:" .. matched.cidr .. ":" .. os.date("%Y%m%d")
        pool.safe_incr(key, 8 * 86400)
    end)

    ctx.action        = "block"
    ctx.action_reason = "banned_subnet:" .. matched.label
    ctx.banned_subnet = matched.cidr
    ctx.banned_subnet_label = matched.label

    ngx.log(ngx.WARN, "[subnet_block] blocked ip=", ip,
            " subnet=", matched.cidr,
            " label=", matched.label)

    ngx.status = 403
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Access denied.")
    ngx.exit(403)
    return true, true
end

return _M
