local _M = {}

local tls   = require "antibot.transport.tls"
local http2 = require "antibot.transport.http2"

function _M.run(ctx)
    -- At the origin, TLS and HTTP/2 belong to the proxy-to-origin connection,
    -- not to the browser named by CF-Connecting-IP/XFF.  Reusing them as an
    -- end-user fingerprint would assign one edge signature to many clients.
    if ctx.proxy_verified == true then
        ctx.transport_scope       = "proxy_edge"
        ctx.ja3                   = nil
        ctx.ja3_raw               = nil
        ctx.ja3_partial           = nil
        ctx.ja3_cipher_n          = 0
        ctx.ja3_allowlist_miss    = 0.0
        ctx.tls13_offered         = nil
        ctx.h2_is_h2              = nil
        ctx.h2_order              = nil
        ctx.h2_bot_confidence     = 0.0
        return true, false
    end

    tls.run(ctx)

    http2.run(ctx)

    return true, false
end

return _M
