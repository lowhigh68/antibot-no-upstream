local _M = {}

function _M.run(ctx)
    ctx.anomaly_score = math.min(1.0,
        (ctx.header_flag or 0) * 0.45 +
        (ctx.proto_flag  or 0) * 0.25 +
        (ctx.ua_flag     or 0) * 0.30)
end

return _M
