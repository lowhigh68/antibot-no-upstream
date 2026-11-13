local pass, fail = 0, 0
local function ok(v, name)
    if v then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL proxy_origin: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end
-- The deployed directory is named `antibot`, while the repository directory
-- is `antibot-core`.  Resolve the namespace explicitly so this contract runs
-- in both places without creating a source-tree symlink.
table.insert(package.loaders, 1, function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    local f = loadfile(src .. rel .. ".lua")
    if f then return f end
    return loadfile(src .. rel .. "/init.lua")
end)

local current_headers = {}
local cache = {}
_G.ngx = {
    ERR = 3, WARN = 4,
    var = {
        remote_addr = "8.8.8.8", realip_remote_addr = "",
        server_addr = "198.51.100.10", host = "example.test",
    },
    req = { get_headers = function() return current_headers end },
    config = { prefix = function() return "/tmp/antibot-proxy-test/" end },
    shared = { antibot_cache = {
        get = function(_, k) return cache[k] end,
        set = function(_, k, v) cache[k] = v; return true end,
        add = function(_, k, v) if cache[k] then return nil end; cache[k] = v; return true end,
    } },
    log = function() end,
}

local cfg = require "antibot.core.config"
cfg.proxy_origin.generic.rules = {
    {
        name = "company_proxy",
        cidrs = { "45.32.0.0/16", "2001:4860:abcd::/48" },
        hosts = { "proxy.example", "*.proxy.example" },
        header = "x-forwarded-for",
    },
    {
        -- A local reverse proxy is a particularly important boundary: its
        -- RFC1918 peer must never grant LAN/self privileges to Internet users.
        name = "local_proxy",
        cidrs = { "10.20.0.0/16" },
        hosts = { "local-proxy.example" },
        header = "x-forwarded-for",
    },
}

package.loaded["antibot.core.proxy_origin"] = nil
package.loaded["antibot.core.ip_scope"] = nil
local proxy = require "antibot.core.proxy_origin"
local cidr  = require "antibot.core.ip_cidr"

local function request(peer, headers, host, opts)
    opts = opts or {}
    current_headers = headers or {}
    ngx.var.host = host or "example.test"
    ngx.var.remote_addr = opts.remote_addr or peer
    ngx.var.realip_remote_addr = opts.realip_remote_addr or ""
    local ctx = {
        ip = ngx.var.remote_addr,
        ip_tcp = opts.ctx_peer or (opts.realip_remote_addr ~= "" and opts.realip_remote_addr or peer),
        req = { host = ngx.var.host },
    }
    proxy.run(ctx)
    return ctx
end

do
    local c = request("8.8.8.8", {}, "plain.example")
    eq(c.ip, "8.8.8.8", "direct client unchanged")
    eq(c.proxy_verified, false, "direct client is not proxy")
    eq(c.ip_is_aggregate, false, "direct client is individual")
    eq(c.client_ip_source, "tcp", "direct provenance")
end

do
    local c = request("2001:4860:4860::8888", {}, "plain.example")
    eq(c.ip, "2001:4860:4860:0:0:0:0:8888", "direct IPv6 normalized")
    eq(c.ip_spoofed, nil, "IPv6 spelling is not treated as RealIP spoof")
end

do
    local c = request("8.8.8.8", { ["cf-connecting-ip"] = "1.1.1.1" })
    eq(c.ip, "8.8.8.8", "untrusted header cannot replace IP")
    eq(c.proxy_spoof, true, "untrusted proxy claim is observable")
end

do
    local c = request("173.245.48.10", { ["cf-connecting-ip"] = "8.8.4.4" })
    eq(c.ip, "8.8.4.4", "Cloudflare restores IPv4 client")
    eq(c.proxy_vendor, "cloudflare", "Cloudflare provider")
    eq(c.proxy_client_ip_verified, true, "Cloudflare client proof")
    eq(c.ip_is_aggregate, false, "restored client remains bannable")
    eq(c.transport_scope, "proxy_edge", "transport belongs to edge")
end

do
    local c = request("173.245.48.10", {})
    eq(c.ip, "173.245.48.10", "missing header retains edge")
    eq(c.proxy_degraded, true, "missing header is degraded")
    eq(c.proxy_header_error, "missing", "missing reason")
    eq(c.ip_is_aggregate, true, "unresolved edge is aggregate")
end

do
    local c = request("173.245.48.10", { ["cf-connecting-ip"] = "10.0.0.7" })
    eq(c.ip, "173.245.48.10", "private header cannot become client")
    eq(c.proxy_header_error, "invalid_client", "private client rejected")
    eq(c.ip_is_aggregate, true, "invalid client leaves collective edge")
end

do
    local c = request("2606:4700::1234", {
        ["cf-connecting-ip"] = "2001:4860:4860::8888",
    })
    eq(c.proxy_verified, true, "Cloudflare IPv6 edge recognized")
    eq(c.ip, "2001:4860:4860:0:0:0:0:8888", "IPv6 client normalized")
end

do
    local c = request("173.245.48.10", {
        ["cf-connecting-ip"] = "240.1.2.3",
        ["cf-connecting-ipv6"] = "2001:4860:4860::8844",
    })
    eq(c.ip, "2001:4860:4860:0:0:0:0:8844", "Pseudo IPv4 restores original IPv6")
    eq(c.client_ip_source, "cf-connecting-ipv6", "Pseudo IPv4 provenance")
end

do
    -- Coexists safely if nginx RealIP is enabled later: peer still comes from
    -- realip_remote_addr while current remote_addr is already the client.
    local c = request("173.245.48.10", { ["cf-connecting-ip"] = "8.8.4.4" },
        "example.test", {
            remote_addr = "8.8.4.4", realip_remote_addr = "173.245.48.10",
        })
    eq(c.ip, "8.8.4.4", "nginx RealIP and Lua agree")
    eq(c.ip_tcp, "173.245.48.10", "nginx RealIP preserves edge")
end

do
    local c = request("45.32.1.5", {
        ["x-forwarded-for"] = "8.8.8.8, 45.32.2.9",
    }, "shop.proxy.example")
    eq(c.proxy_vendor, "company_proxy", "generic provider matched")
    eq(c.ip, "8.8.8.8", "XFF walks right-to-left over trusted hop")
    eq(c.proxy_hops, 2, "XFF hop count")
end

do
    local c = request("45.32.1.5", {
        ["x-forwarded-for"] = "8.8.8.8",
    }, "wrong.example")
    eq(c.proxy_verified, false, "generic provider is host-scoped")
    eq(c.ip, "45.32.1.5", "host mismatch retains peer")
    eq(c.proxy_spoof, true, "host mismatch claim is spoof telemetry")
end

do
    local c = request("10.20.0.7", {
        ["x-forwarded-for"] = "8.8.8.8",
    }, "local-proxy.example")
    eq(c.proxy_verified, true, "private generic proxy is provenance-verified")
    eq(c.ip, "8.8.8.8", "private proxy restores public client")
    eq(require("antibot.core.ip_scope").is_self(c), false,
       "private proxy peer cannot grant self privilege")
end

do
    local c = request("10.20.0.7", {}, "local-proxy.example")
    eq(c.proxy_degraded, true, "private proxy missing header is degraded")
    eq(require("antibot.core.ip_scope").is_self(c), false,
       "degraded private proxy cannot grant self privilege")
end

-- LAN whitelist is valid only for a direct TCP client, not for a trusted
-- private proxy peer carrying an Internet client.
do
    package.loaded["antibot.core.redis_pool"] = {
        safe_get = function() return nil end,
        safe_set = function() return true end,
    }
    package.loaded["antibot.core.fingerprint.identity"] = {
        build_from = function() return "unused" end,
    }
    package.loaded["antibot.detection.bot.ua_claim"] = {
        is_browser_wrapped = function() return false end,
        claims_automation = function() return false end,
    }
    package.loaded["antibot.core.access.verified_human"] = {
        check_cookie = function() return false end,
    }
    package.loaded["antibot.core.access.whitelist"] = nil
    ngx.var.uri = "/shop"
    -- Empty UA keeps this test focused on the LAN boundary and avoids entering
    -- the unrelated device-cookie recovery path.
    ngx.var.http_user_agent = ""
    ngx.var.cookie_antibot_fp = nil
    ngx.var.scheme = "https"
    ngx.header = {}

    local whitelist = require "antibot.core.access.whitelist"
    local proxied = request("10.20.0.7", {
        ["x-forwarded-for"] = "8.8.8.8",
    }, "local-proxy.example")
    local allowed, reason = whitelist.check(proxied)
    eq(allowed, false, "private proxy does not enter LAN whitelist")
    eq(reason, nil, "private proxy has no LAN allow reason")

    local direct = request("10.30.0.7", {}, "plain.example")
    allowed, reason = whitelist.check(direct)
    eq(allowed, true, "direct private client retains LAN whitelist")
    eq(reason, "lan_internal", "direct private client LAN reason")
end

do
    local c = request("173.245.48.10", {
        ["cf-connecting-ip"] = { "8.8.8.8", "1.1.1.1" },
    })
    eq(c.proxy_header_error, "duplicate", "duplicate single-IP header rejected")
    eq(c.ip_is_aggregate, true, "duplicate header cannot sentence edge")
end

do
    local p29 = assert(cidr.compile("2a06:98c0::/29"))
    ok(cidr.contains(p29, "2a06:98c7:ffff::1"), "IPv6 /29 upper member")
    ok(not cidr.contains(p29, "2a06:98c8::1"), "IPv6 /29 boundary")
    local p13 = assert(cidr.compile("104.16.0.0/13"))
    ok(cidr.contains(p13, "104.23.255.255"), "IPv4 /13 upper member")
    ok(not cidr.contains(p13, "104.24.0.1"), "IPv4 /13 boundary")
end

-- Transport signals must not attribute the edge handshake to the client.
do
    local calls = { tls = 0, h2 = 0 }
    package.loaded["antibot.transport.tls"] = {
        run = function() calls.tls = calls.tls + 1 end,
    }
    package.loaded["antibot.transport.http2"] = {
        run = function() calls.h2 = calls.h2 + 1 end,
    }
    package.loaded["antibot.transport"] = nil
    local transport = assert(loadfile(src .. "transport/init.lua"))()
    local proxied = { proxy_verified = true, ja3 = "edge", h2_bot_confidence = 1 }
    transport.run(proxied)
    eq(calls.tls, 0, "proxy does not consume edge JA3")
    eq(calls.h2, 0, "proxy does not consume edge H2")
    eq(proxied.ja3, nil, "edge JA3 cleared")
    eq(proxied.h2_bot_confidence, 0.0, "edge H2 score cleared")
    transport.run({ proxy_verified = false })
    eq(calls.tls, 1, "direct transport still runs TLS")
    eq(calls.h2, 1, "direct transport still runs H2")
end

print(("proxy_origin_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
