local _M = {}

local redis  = require "resty.redis"
local config = require "antibot.core.config"

local CFG = config.redis

function _M.get()
    local red = redis:new()
    red:set_timeout(CFG.timeout_ms)

    local ok, err = red:connect(CFG.host, CFG.port)
    if not ok then
        ngx.log(ngx.ERR, "[redis_pool] connect failed: ", err)
        return nil, err
    end

    if CFG.db and CFG.db > 0 then
        local ok2, err2 = red:select(CFG.db)
        if not ok2 then
            ngx.log(ngx.WARN, "[redis_pool] SELECT failed: ", err2)
        end
    end

    return red
end

function _M.put(red)
    if not red then return end
    local ok, err = red:set_keepalive(
        CFG.pool_idle_s * 1000,
        CFG.pool_size
    )
    if not ok then
        ngx.log(ngx.WARN, "[redis_pool] keepalive failed: ", err)
    end
end

function _M.pipeline(fn)
    local red, err = _M.get()
    if not red then return nil, err end

    red:init_pipeline()
    local ok, fn_err = pcall(fn, red)
    if not ok then
        red:cancel_pipeline()
        _M.put(red)
        return nil, fn_err
    end

    local results, commit_err = red:commit_pipeline()
    _M.put(red)

    if not results then
        return nil, commit_err
    end
    return results
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

function _M.safe_incr(key, ttl)
    local red, err = _M.get()
    if not red then return nil, err end
    red:init_pipeline()
    red:incr(key)
    if ttl then red:expire(key, ttl) end
    local results, perr = red:commit_pipeline()
    _M.put(red)
    if not results then return nil, perr end
    return results[1]
end

return _M
