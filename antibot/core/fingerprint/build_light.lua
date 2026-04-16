local _M = {}

local identity_mod = require "antibot.core.fingerprint.identity"

local SENTINEL = {
    ja3    = "NO_JA3",
    h2_sig = "NO_H2",
    asn    = "NO_ASN",
}

local FP_QUALITY_THRESHOLD = 0.55

function _M.run(ctx)
    identity_mod.build(ctx)

    local components = {
        ctx.ip or "",
        ctx.ua or "",
        (ctx.asn and ctx.asn.asn_number and tostring(ctx.asn.asn_number))
            or SENTINEL.asn,
        ctx.ja3    or SENTINEL.ja3,
        ctx.h2_sig or SENTINEL.h2_sig,
    }

    if components[1] == "" then
        return false, "ip_empty"
    end

    local real = 0
    local sentinel_values = {}
    for _, v in pairs(SENTINEL) do sentinel_values[v] = true end

    for _, v in ipairs(components) do
        if v ~= "" and not sentinel_values[v] then
            real = real + 1
        end
    end

    ctx.fp_quality  = real / #components
    ctx.fp_degraded = (ctx.fp_quality < FP_QUALITY_THRESHOLD)
    ctx.fp_light    = ngx.md5(table.concat(components, "|"))

    if ctx.fp_degraded then
        ngx.log(ngx.WARN,
            "[build_light] degraded fp_quality=",
            string.format("%.2f", ctx.fp_quality),
            " ip=", ctx.ip,
            " ja3=", components[4],
            " h2=", components[5])
    end

    return true
end

return _M
