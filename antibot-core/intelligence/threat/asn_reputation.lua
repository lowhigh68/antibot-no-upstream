local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.run(ctx)
    ctx.asn_rep = 0.0

    if not ctx.asn or not ctx.asn.asn_number then
        return
    end

    local val = pool.safe_get("rep:asn:" .. ctx.asn.asn_number)
    if val then
        local rep = tonumber(val)
        if rep then
            ctx.asn_rep = rep
            ngx.log(ngx.DEBUG,
                "[asn_rep] redis asn=", ctx.asn.asn_number,
                " rep=", rep,
                " ip=", ctx.ip or "?")
        end
    end

    -- S2.5 waiver: PTR contact attest (Path 1) or analyzer attest (Path 2)
    -- has already proven the IP belongs to the operator who declared the bot.
    -- Datacenter prior (asn_rep) is the wrong signal for an attested operator
    -- — Pinterestbot on AWS, PageSpeed on Google Cloud, etc. all run from
    -- datacenter ASNs by design. Drop asn_rep to 0 to prevent ~15pt penalty
    -- per request which keeps eff_score above CHALLENGE threshold.
    if ctx.bot_identity_tier == "S2.5" then
        ctx.asn_rep = 0.0
    end
end

return _M
