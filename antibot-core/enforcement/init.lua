local _M = {}

local engine    = require "antibot.enforcement.decision.engine"
local explain   = require "antibot.enforcement.decision.explain"
local challenge = require "antibot.enforcement.challenge"
local ban       = require "antibot.enforcement.ban"

function _M.run(ctx)
    local action = engine.run(ctx)

    local ok, err = pcall(explain.run, ctx)
    if not ok then
        ngx.log(ngx.ERR, "[enforcement] explain error: ", tostring(err))
    end

    if action == "block" then
        ban.run(ctx)
        -- Serve 403 NGAY cho request hiện tại, không chỉ ghi ban cho request sau.
        -- Trước đây chỉ ghi ban Redis rồi return → request hiện tại vẫn đi qua
        -- upstream Apache → mỗi attack pattern lãng phí 1 request damage trước
        -- khi defense kick in (consume DB/CPU 1-3s).
        ngx.status = 403
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("Access denied.")
        ngx.exit(403)
        return true, true

    elseif action == "challenge" then
        if ctx.is_static then
            ctx.action = "monitor"
            ngx.log(ngx.WARN,
                "[enforcement] unexpected challenge for resource",
                " ip=", ctx.ip or "?",
                " uri=", ngx.var.uri or "?")
            return true, false
        end
        challenge.run(ctx)
        return true, true

    else
        return true, false
    end
end

return _M
