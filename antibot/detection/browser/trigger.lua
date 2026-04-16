local _M   = {}
local pool = require "antibot.core.redis_pool"

-- trigger.lua: REQUEST-phase decision only.
-- Sets ctx.inject_candidate = true when the client signals it expects HTML.
-- This is a TENTATIVE flag — it does NOT confirm injection will happen.
-- The confirmed decision (ctx.browser_needed) is made in header_filter_by_lua_block
-- after reading the actual response Content-Type from upstream.
--
-- Two-phase design:
--   access phase  → inject_candidate  (client wants HTML?)
--   header_filter → browser_needed    (server actually returned HTML?)

function _M.run(ctx)
    local accept = (ctx.req and ctx.req.accept) or ngx.var.http_accept or ""
    if not accept:find("text/html", 1, true) then
        ctx.inject_candidate = false
        return
    end

    local fp = ctx.fp_light
    if fp then
        local cached = pool.safe_get("beacon:" .. fp)
        if cached == "1" then
            ctx.inject_candidate = false
            return
        end
    end

    ctx.inject_candidate = true
end

return _M
