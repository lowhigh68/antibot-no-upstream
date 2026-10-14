local _M   = {}
local pool = require "antibot.core.redis_pool"

local SCAN_COUNT = 100
local INTERVAL_S = 60
local cursor = "0"
local cycle_deleted = 0

function _M.start()
    local ok, err = ngx.timer.every(INTERVAL_S, function(premature)
        if premature then return end
        local red, e = pool.get()
        if not red then return end

        local deleted = 0

        -- One SCAN page per tick. The old repeat-until walked the complete
        -- keyspace inside one timer callback; on a large Redis DB that could
        -- occupy an event-loop worker for an unbounded time.
        local res, scan_err = red:scan(cursor,
            "MATCH", "sess:*",
            "COUNT", SCAN_COUNT)
        if not res then
            cursor = "0"
            cycle_deleted = 0
            pool.put(red)
            ngx.log(ngx.WARN, "[memory_guard] scan failed: ",
                    tostring(scan_err or "unknown"))
            return
        end

        cursor = tostring(res[1] or "0")
        local scanned = res[2] or {}
        local keys = {}
        for _, key in ipairs(scanned) do
            -- `SCAN MATCH sess:*` also returns the shared-session HLL
            -- namespace `sess:ck:<fp>`.  Only `sess:<fp>` is the path list
            -- guarded by `rl:<fp>`; deleting the HLL here disables the
            -- shared-key FP guard in session_store.lua.
            if key:match("^sess:[^:]+$") then
                keys[#keys + 1] = key
            end
        end

        local active_results = {}
        if #keys > 0 then
            red:init_pipeline()
            for _, key in ipairs(keys) do
                red:exists("rl:" .. key:sub(6))
            end
            active_results = red:commit_pipeline() or {}
        end

        local orphaned = {}
        for i, key in ipairs(keys) do
            if tonumber(active_results[i]) == 0 then
                orphaned[#orphaned + 1] = key
            end
        end

        if #orphaned > 0 then
            red:init_pipeline()
            for _, key in ipairs(orphaned) do red:del(key) end
            local del_results = red:commit_pipeline()
            if del_results then
                for _, result in ipairs(del_results) do
                    deleted = deleted + (tonumber(result) or 0)
                end
            end
        end

        pool.put(red)
        cycle_deleted = cycle_deleted + deleted
        if cursor == "0" and cycle_deleted > 0 then
            ngx.log(ngx.INFO, "[memory_guard] cycle deleted ", cycle_deleted,
                    " orphaned session keys")
            cycle_deleted = 0
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[memory_guard] timer.every failed: ", err)
    end
end

return _M
