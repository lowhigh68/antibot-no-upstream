local _M = {}

function _M.run(ctx)
    local score = 0.0
    local req   = ctx.req or {}

    local proto = req.proto or ngx.var.server_protocol or ""
    if proto == "HTTP/1.0" then score = score + 0.3 end

    local method = req.method or ""
    local valid  = { GET=1, POST=1, PUT=1, DELETE=1,
                     HEAD=1, OPTIONS=1, PATCH=1 }
    if method ~= "" and not valid[method] then score = score + 0.5 end

    ctx.proto_flag = math.min(1.0, score)
end

return _M
