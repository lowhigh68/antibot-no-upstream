local _M = {}

local redis = require "resty.redis"

local function get_cfg()
    return require("antibot.core.config").intel
end

local function is_enabled()
    local c = get_cfg()
    return c and c.enabled and c.redis and c.redis.host and c.redis.host ~= ""
end

function _M.get()
    if not is_enabled() then return nil, "intel disabled" end
    local c  = get_cfg()
    local rc = c.redis

    local red = redis:new()
    red:set_timeout(rc.timeout)

    local ok, err = red:connect(rc.host, rc.port)
    if not ok then
        ngx.log(ngx.ERR, "[intel_pool] connect failed: ", err)
        return nil, err
    end

    if rc.password and rc.password ~= "" then
        local aok, aerr = red:auth(rc.password)
        if not aok then
            ngx.log(ngx.WARN, "[intel_pool] auth failed: ", aerr)
        end
    end

    if rc.db and rc.db > 0 then
        red:select(rc.db)
    end

    return red
end

function _M.put(red)
    if not red then return end
    local c  = get_cfg()
    local rc = c.redis
    local ok, err = red:set_keepalive(
        (rc.pool_idle_s or 30) * 1000,
        rc.pool_size or 5
    )
    if not ok then
        ngx.log(ngx.WARN, "[intel_pool] keepalive failed: ", err)
    end
end

function _M.safe_get(key)
    local red, err = _M.get()
    if not red then return nil, err end
    local val, rerr = red:get(key)
    _M.put(red)
    if val == ngx.null then return nil end
    return val, rerr
end

function _M.safe_set(key, val, ttl)
    local red, err = _M.get()
    if not red then return false, err end
    local ok, rerr
    if ttl and ttl > 0 then
        ok, rerr = red:setex(key, ttl, val)
    else
        ok, rerr = red:set(key, val)
    end
    _M.put(red)
    return ok == "OK", rerr
end

return _M
