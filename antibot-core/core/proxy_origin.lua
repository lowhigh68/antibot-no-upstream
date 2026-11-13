-- Trusted reverse-proxy boundary.
--
-- A proxy range is transport provenance, never an allow verdict.  Only after
-- the unforgeable TCP peer matches a configured CIDR may a rule provide the
-- end-client IP from one named header.  The restored client then traverses the
-- normal AntiBot/WAF pipeline exactly like a direct client.

local _M = {}

local cfg       = require "antibot.core.config"
local ip_scope  = require "antibot.core.ip_scope"
local ip_cidr   = require "antibot.core.ip_cidr"
local cf_cidrs  = require "antibot.core.data.cloudflare_cidrs"

local CLAIM_HEADERS = {
    "cf-connecting-ip", "cf-connecting-ipv6", "true-client-ip",
    "x-forwarded-for", "x-real-ip",
}
local ALLOWED_HEADERS = {
    ["cf-connecting-ip"] = true,
    ["cf-connecting-ipv6"] = true,
    ["true-client-ip"]   = true,
    ["x-forwarded-for"]  = true,
    ["x-real-ip"]        = true,
}

local function normalize_host(host)
    host = tostring(host or ""):lower():gsub("%.$", "")
    host = host:match("^([^:]+)") or host
    return host
end

local function host_matches(patterns, host)
    host = normalize_host(host)
    for i = 1, #(patterns or {}) do
        local p = normalize_host(patterns[i])
        if p == "*" or p == host then return true end
        if p:sub(1, 2) == "*." then
            local suffix = p:sub(2)
            if #host > #suffix and host:sub(-#suffix) == suffix then return true end
        end
    end
    return false
end

local function compile_rule(raw, fallback_name)
    if type(raw) ~= "table" then return nil end
    local header = tostring(raw.header or ""):lower()
    if not ALLOWED_HEADERS[header] then return nil end
    local ranges, errors = ip_cidr.compile_list(raw.cidrs)
    if #ranges == 0 then return nil end
    if #errors > 0 and ngx and ngx.log then
        ngx.log(ngx.ERR, "[proxy_origin] invalid CIDR rule=",
            tostring(raw.name or fallback_name), " errors=", table.concat(errors, ","))
    end
    return {
        name   = tostring(raw.name or fallback_name or "proxy"),
        header = header,
        fallback_header = ALLOWED_HEADERS[tostring(raw.fallback_header or ""):lower()]
            and tostring(raw.fallback_header):lower() or nil,
        hosts  = raw.hosts or {},
        ranges = ranges,
    }
end

local function build_rules()
    local out = {}
    local c = cfg.proxy_origin or {}
    if c.enabled == false then return out end

    local cf = c.cloudflare or {}
    if cf.enabled ~= false then
        local rule = compile_rule({
            name   = "cloudflare",
            header = cf.header or "cf-connecting-ip",
            fallback_header = "cf-connecting-ipv6",
            hosts  = cf.hosts or { "*" },
            cidrs  = cf_cidrs,
        }, "cloudflare")
        if rule then out[#out + 1] = rule end
    end

    local generic = c.generic or {}
    for i = 1, #(generic.rules or {}) do
        local rule = compile_rule(generic.rules[i], "proxy_" .. tostring(i))
        if rule then out[#out + 1] = rule end
    end
    return out
end

-- Compiled once per worker/module load.  No DNS, Redis or file I/O occurs on
-- the request path; changing trust policy therefore deliberately needs reload.
local RULES = build_rules()

local function headers()
    local ok, h = pcall(ngx.req.get_headers)
    if not ok or type(h) ~= "table" then return {} end
    return h
end

local function header_value(h, name)
    local v = h[name]
    if type(v) == "table" then return nil, "duplicate" end
    if type(v) ~= "string" or v == "" then return nil, "missing" end
    return v, nil
end

local function applicable_rules(host)
    local out = {}
    for i = 1, #RULES do
        if host_matches(RULES[i].hosts, host) then out[#out + 1] = RULES[i] end
    end
    return out
end

local function trusted_by(rules, ip)
    for i = 1, #rules do
        if ip_cidr.contains_any(rules[i].ranges, ip) then return true end
    end
    return false
end

local function matching_rule(rules, peer)
    for i = 1, #rules do
        if ip_cidr.contains_any(rules[i].ranges, peer) then return rules[i] end
    end
    return nil
end

local function single_client(value)
    local parsed = ip_cidr.parse(value)
    if not parsed or not ip_cidr.is_public(parsed) then return nil, "invalid_client" end
    return ip_cidr.normalize(parsed), nil, 1
end

local function xff_client(value, trusted_rules)
    local chain = {}
    for item in tostring(value):gmatch("[^,]+") do
        if #chain >= 32 then return nil, "too_many_hops" end
        local parsed = ip_cidr.parse(item)
        if not parsed then return nil, "invalid_hop" end
        chain[#chain + 1] = parsed
    end
    if #chain == 0 then return nil, "empty_chain" end

    -- Proxies append the address they received to the right.  Walk back across
    -- known proxies and stop at the nearest untrusted hop.
    for i = #chain, 1, -1 do
        if not trusted_by(trusted_rules, chain[i]) then
            if not ip_cidr.is_public(chain[i]) then return nil, "private_client" end
            return ip_cidr.normalize(chain[i]), nil, #chain
        end
    end
    return nil, "all_hops_trusted"
end

local function extract_client(rule, h, trusted_rules)
    local value, err = header_value(h, rule.header)
    if value then
        local client, parse_err, hops
        if rule.header == "x-forwarded-for" then
            client, parse_err, hops = xff_client(value, trusted_rules)
        else
            client, parse_err, hops = single_client(value)
        end
        if client then return client, nil, hops, rule.header end
        err = parse_err
    end

    -- Cloudflare Pseudo IPv4 "Overwrite Headers" uses a Class-E pseudo value
    -- in CF-Connecting-IP and preserves the real visitor in this IPv6 header.
    if rule.fallback_header then
        local fallback = header_value(h, rule.fallback_header)
        if fallback then
            local client, fallback_err, hops = single_client(fallback)
            if client then
                return client, nil, hops, rule.fallback_header
            end
            err = fallback_err or err
        end
    end
    return nil, err
end

local function mark_claim_spoof(ctx, h, peer, host)
    for i = 1, #CLAIM_HEADERS do
        local v = h[CLAIM_HEADERS[i]]
        if v and v ~= "" then
            ctx.proxy_spoof = true
            ctx.proxy_spoof_header = CLAIM_HEADERS[i]
            ngx.log(ngx.WARN,
                "[proxy_origin] untrusted peer sent proxy header peer=",
                tostring(peer), " host=", tostring(host),
                " header=", CLAIM_HEADERS[i])
            return
        end
    end
end

function _M.is_cloudflare(ip)
    for i = 1, #RULES do
        if RULES[i].name == "cloudflare" then
            return ip_cidr.contains_any(RULES[i].ranges, ip)
        end
    end
    return false
end

function _M.run(ctx)
    ctx = ctx or {}
    local peer = ctx.ip_tcp
    if not peer or peer == "" then peer = ip_scope.tcp_peer() end
    peer = ip_cidr.normalize(peer) or tostring(peer or "")

    local host = normalize_host((ctx.req and ctx.req.host) or ngx.var.host)
    local current = ctx.ip or ngx.var.remote_addr or peer
    local current_normalized = ip_cidr.normalize(current) or tostring(current or "")
    local h = headers()
    local rules = applicable_rules(host)
    local rule = matching_rule(rules, peer)

    ctx.ip_tcp                   = peer
    ctx.proxy_verified           = false
    ctx.proxy_vendor             = nil
    ctx.proxy_rule               = nil
    ctx.proxy_edge_ip            = nil
    ctx.proxy_client_ip_verified = false
    ctx.proxy_header             = nil
    ctx.proxy_header_error       = nil
    ctx.proxy_hops               = nil
    ctx.proxy_degraded           = false
    ctx.proxy_spoof              = false
    ctx.proxy_spoof_header       = nil
    ctx.behind_proxy             = false
    ctx.ip_is_aggregate          = false
    ctx.client_ip_source         = "tcp"
    ctx.transport_scope          = "client"

    if not rule then
        -- If nginx RealIP was enabled independently but Lua has no matching
        -- trust rule, never retain a public address copied from that header.
        if peer ~= "" and current_normalized ~= peer then
            ctx.ip_spoofed = current_normalized
            current = peer
        else
            current = current_normalized
        end
        ctx.ip = ip_cidr.normalize(current) or tostring(current or "")
        mark_claim_spoof(ctx, h, peer, host)
        return true, false
    end

    ctx.proxy_verified  = true
    ctx.behind_proxy    = true
    ctx.proxy_vendor    = rule.name
    ctx.proxy_rule      = rule.name
    ctx.proxy_edge_ip   = peer
    ctx.proxy_header    = rule.header
    ctx.transport_scope = "proxy_edge"

    local client, err, hops, source = extract_client(rule, h, rules)
    if client then
        ctx.ip                       = client
        ctx.proxy_client_ip_verified = true
        ctx.client_ip_source         = source or rule.header
        ctx.proxy_header             = source or rule.header
        ctx.proxy_hops               = hops
        -- A value that is itself another trusted edge remains aggregate.  It
        -- may be a proxy-to-proxy/Worker request, not one end-user address.
        ctx.ip_is_aggregate = trusted_by(rules, client)
        -- Safe self-traffic recovery through a verified proxy.  The header
        -- cannot grant this unless the TCP peer already passed the CIDR gate.
        ctx.self_request = ip_scope.is_self_ip(client)
    else
        ctx.ip                       = peer
        ctx.proxy_client_ip_verified = false
        ctx.client_ip_source         = "proxy_edge"
        ctx.proxy_header_error       = err or "invalid"
        ctx.proxy_degraded           = true
        ctx.ip_is_aggregate          = true
    end

    return true, false
end

function _M.rules_for_test()
    return RULES
end

return _M
