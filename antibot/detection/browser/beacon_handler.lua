local _M   = {}
local pool = require "antibot.core.redis_pool"

function _M.handle()
    if ngx.var.request_method ~= "POST" then
        ngx.exit(405); return
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then ngx.exit(400); return end

    local ok, data = pcall(require("cjson").decode, body)
    if not ok or not data then ngx.exit(400); return end

    local fp = data.fp
    if not fp or #fp ~= 32 then ngx.exit(400); return end

    local fp_exists = pool.safe_get("fp:" .. fp)
    if not fp_exists then ngx.exit(403); return end

    local payload = {
        cv  = data.cv,
        wgl = data.wgl,
        nav = data.nav,
        ent = data.ent,
        ts  = ngx.time(),
    }

    local store_ok, json = pcall(require("cjson").encode, payload)
    if store_ok then
        pool.safe_set("beacon_data:" .. fp, json, 600)
        pool.safe_set("beacon:" .. fp, "1", 600)
    end

    ngx.status = 204
    ngx.exit(204)
end

return _M
