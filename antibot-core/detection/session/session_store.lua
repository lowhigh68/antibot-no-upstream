local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- Attack 4 — Slow crawl / residential proxy:
-- Track resource_count và navigate_count per identity.
-- Human browse: browser tự fetch CSS/JS/fonts/images sau page load.
-- Bot HTTP: chỉ fetch HTML → resource_count ≈ 0.
-- resource_ratio = resource_count / navigate_count
-- Threshold: ratio < 2 sau navigate_count > 5 → robotic pattern.

local RESOURCE_RATIO_MIN    = 1.0   -- hạ từ 2.0 → 1.0
                                    -- Vì sess_res được incr trong logger (async)
                                    -- có thể đến muộn hơn nav → cần threshold thấp hơn
local RESOURCE_COUNT_WINDOW = 300   -- TTL 5 phút

-- Gating cho resource_starved: trước khi fire signal, verify IP có resource
-- activity thật trong 60s window. Bypass FP cho browser session đang load
-- CSS/JS (resource class skip fingerprint → ctx.identity=nil → res_count per
-- identity LUÔN = 0, bất kể browser có load CSS/JS hay không).
--
-- Threshold 5: yêu cầu TỐI THIỂU 5 resource hit/60s từ IP để confident IP
-- thực sự là browser đang load. 1 stray hit từ user khác trên NAT không
-- đủ giải vây cho bot (giảm FN risk shared-NAT).
local RES_IP_MIN_HITS = 5

function _M.run(ctx)
    local fp  = ctx.fp_light
    local uri = (ctx.req and ctx.req.uri) or ngx.var.request_uri
    if not fp or not uri then return end

    local key   = "sess:" .. fp
    local limit = cfg.ttl.session_max_len
    local ttl   = cfg.ttl.session

    -- Track navigation vs resource count (Attack 4)
    local class = ctx.req_class or "unknown"
    local nav_key = "sess_nav:"  .. fp
    local res_key = "sess_res:"  .. fp

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.WARN, "[session_store] redis err: ", err)
        return
    end

    red:init_pipeline()

    -- Session path tracking (original)
    red:lpush(key, uri)
    red:ltrim(key, 0, limit - 1)
    red:expire(key, ttl)
    red:llen(key)

    -- Attack 4: navigation / resource counters
    if class == "navigation" or class == "unknown" then
        red:incr(nav_key)
        red:expire(nav_key, RESOURCE_COUNT_WINDOW)
    elseif class == "resource" then
        red:incr(res_key)
        red:expire(res_key, RESOURCE_COUNT_WINDOW)
    end

    local res, perr = red:commit_pipeline()
    pool.put(red)

    if res then
        ctx.sess_len = (type(res[4]) == "number") and res[4] or 0

        -- Compute resource ratio (Attack 4)
        local nav_count = 0
        local res_count = 0

        if class == "navigation" or class == "unknown" then
            nav_count = (type(res[5]) == "number") and res[5] or 0
            -- Read resource count separately (not in pipeline for simplicity)
            local rv = pool.safe_get(res_key)
            res_count = tonumber(rv) or 0
        elseif class == "resource" then
            res_count = (type(res[5]) == "number") and res[5] or 0
            local nv = pool.safe_get(nav_key)
            nav_count = tonumber(nv) or 0
        end

        ctx.nav_count = nav_count
        ctx.res_count = res_count

        -- Flag robotic pattern: nhiều navigations, ít/không có resource fetch.
        --
        -- Điều chỉnh threshold vì:
        -- 1. sess_res được incr trong logger (async) → có thể đến muộn hơn nav
        --    vài request → grace period cần cao hơn
        -- 2. Trang có thể cache → browser không fetch lại resource mỗi page
        -- 3. User đổi trình duyệt → fp mới → nav_count reset về 0,
        --    sess_res từ browser cũ không có → false positive
        --
        -- nav_count >= 10 (thay vì 5) để tránh flag session mới
        -- nav_count >= 15 (thay vì 8) để tính ratio
        local would_fire = false
        local fire_reason

        if nav_count >= 10 and res_count == 0 then
            would_fire = true
            fire_reason = "resource_starved"
        elseif nav_count >= 15 then
            local ratio = res_count / nav_count
            if ratio < RESOURCE_RATIO_MIN then
                would_fire = true
                fire_reason = "low_resource_ratio ratio=" ..
                              string.format("%.1f", ratio)
            end
        end

        if would_fire then
            -- IP-level gate: verify IP có resource activity thật trong window
            -- trước khi fire. Tránh FP với browser session vì resource class
            -- skip fingerprint → res_count per identity LUÔN = 0.
            local ip = ctx.ip
            local res_ip = 0
            if ip and ip ~= "" then
                local rv = pool.safe_get("res_ip:" .. ip)
                res_ip = tonumber(rv) or 0
            end

            if res_ip >= RES_IP_MIN_HITS then
                ngx.log(ngx.DEBUG,
                    "[session_store] resource_starved suppressed ",
                    "(ip has res activity) fp=", fp:sub(1,8),
                    " nav=", nav_count, " res_id=", res_count,
                    " res_ip=", res_ip)
            else
                ctx.resource_starved = true
                ngx.log(ngx.DEBUG,
                    "[session_store] ", fire_reason,
                    " fp=", fp:sub(1,8),
                    " nav=", nav_count, " res_id=", res_count,
                    " res_ip=", res_ip)
            end
        end
    end
end

return _M
