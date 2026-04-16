local _M   = {}
local pool = require "antibot.core.redis_pool"

local SCAN_COUNT = 100
local INTERVAL_S = 60

function _M.start()
    local ok, err = ngx.timer.every(INTERVAL_S, function()
        local red, e = pool.get()
        if not red then return end

        local cursor = "0"
        local deleted = 0

        repeat
            local res = red:scan(cursor,
                "MATCH", "sess:*",
                "COUNT", SCAN_COUNT)
            if not res then break end

            cursor = res[1]
            local keys = res[2] or {}

            for _, key in ipairs(keys) do
                local fp = key:sub(6)
                local active = red:exists("rl:" .. fp)
                if active == 0 then
                    red:del(key)
                    deleted = deleted + 1
                end
            end
        until cursor == "0"

        pool.put(red)
        if deleted > 0 then
            ngx.log(ngx.INFO, "[memory_guard] deleted ", deleted,
                    " orphaned session keys")
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[memory_guard] timer.every failed: ", err)
    end
end

return _M
