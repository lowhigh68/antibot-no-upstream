local _M  = {}
local bit = require "bit"
local cfg = require "antibot.core.config"

-- Subnet-level deterministic block list.
--
-- Operator-managed CIDR blocklist for subnets EMPIRICALLY confirmed as
-- pure bot infrastructure (no legitimate users mixed in). Equivalent to
-- iptables block but at antibot/nginx layer — same effect, reload via
-- nginx -s reload (no firewall restart), git-versioned, log-integrated.
--
-- Use case: empirically validate a subnet is 100% bot by temporarily
-- blocking it at firewall — if site load drops to baseline and stays
-- normal, subnet has no legitimate users. Add to cfg.subnet_block and
-- remove firewall rule.
--
-- Incident driver (2026-06-19, `43.172.0.0/15`):
--   - 44+ distinct IPs in 2-min window from /15
--   - 16+ Chrome versions cycled (including ancient 103/104/105) — bot UA pool
--   - 100% Windows Chrome — zero real-user platform diversity (Mobile/Mac/Firefox)
--   - 20+ expensive endpoints hit in parallel
--   - Zero verified cookie hits (no historical real users)
--   - HTTP 500 cascade — PHP-FPM saturating
--   - Firewall block on /15 → load returns to baseline immediately
--   - Firewall unblock → server dies in minutes
-- Empirical proof: this /15 has no legitimate users. Deterministic block.

local PARSED = {}  -- { {base_masked, mask, prefix, cidr_str}, ... }
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

    -- Build mask: top `prefix` bits set, rest zero.
    -- prefix=0  → mask=0          (matches everything — refuse to load)
    -- prefix=32 → mask=0xFFFFFFFF (single IP)
    -- prefix=15 → mask=0xFFFE0000
    local mask
    if prefix == 0 then
        return nil  -- refuse to allow "block 0.0.0.0/0" as misconfiguration safety
    else
        mask = bit.lshift(0xFFFFFFFF, 32 - prefix)
    end
    local base_masked = bit.band(base_int, mask)
    return base_masked, mask, prefix
end

local function init()
    if INITIALIZED then return end
    local list = cfg.subnet_block or {}
    for _, cidr in ipairs(list) do
        local base_masked, mask, prefix = parse_cidr(cidr)
        if base_masked then
            PARSED[#PARSED + 1] = { base_masked, mask, prefix, cidr }
        else
            ngx.log(ngx.ERR, "[subnet_block] invalid CIDR ignored: ", cidr)
        end
    end
    INITIALIZED = true
    if #PARSED > 0 then
        ngx.log(ngx.INFO, "[subnet_block] loaded ", #PARSED, " block rules")
    end
end

-- Returns matched CIDR string if IP is in any blocked subnet, else nil.
local function ip_in_blocked_subnet(ip)
    if not INITIALIZED then init() end
    if #PARSED == 0 then return nil end

    local ip_int = ip_to_int(ip)
    if not ip_int then return nil end

    for i = 1, #PARSED do
        local rule = PARSED[i]
        if bit.band(ip_int, rule[2]) == rule[1] then
            return rule[4]
        end
    end
    return nil
end

_M.ip_in_blocked_subnet = ip_in_blocked_subnet

function _M.run(ctx)
    local ip = ctx.ip
    if not ip or ip == "" or ip == "127.0.0.1" or ip == "::1" then
        return true, false
    end

    -- IPv6 not handled in this v1 (no IPv6 subnets confirmed-bot yet).
    -- Skip IPv6 by structural check (contains colon).
    if ip:find(":", 1, true) then
        return true, false
    end

    local matched = ip_in_blocked_subnet(ip)
    if not matched then
        return true, false
    end

    ctx.action        = "block"
    ctx.action_reason = "banned_subnet"
    ctx.banned_subnet = matched

    ngx.log(ngx.WARN, "[subnet_block] blocked ip=", ip,
            " subnet=", matched)

    ngx.status = 403
    ngx.header["Content-Type"] = "text/plain"
    ngx.say("Access denied.")
    ngx.exit(403)
    return true, true
end

return _M
