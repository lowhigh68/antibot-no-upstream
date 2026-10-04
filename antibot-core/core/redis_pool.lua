local _M = {}

local redis  = require "resty.redis"
local config = require "antibot.core.config"

local CFG = config.redis

-- ── AUTH TREN DUONG NONG ─────────────────────────────────────────────
--
-- Redis la CONTROL PLANE cua lop nay, khong phai cache: no giu `verified:*`,
-- whitelist, ban va khoa FIM. Mot tenant ghi duoc `verified:<cookie>` = tu cap cho
-- minh ve di qua toan bo lop cham diem. Vi vay `requirepass`/ACL tren server la
-- muc P0, va client PHAI biet AUTH truoc khi bat no -- bat o server ma client chua
-- biet thi MOI phep Redis that bai va WAF fail-open trong im lang.
--
-- `password = ""` = KHONG gui AUTH, tuc hanh vi y nguyen ban cu. Cho phep bat
-- server truoc hay sau deploy deu khong vo.
--
-- HAI diem khac `redis_intel_pool.lua`, va ca hai deu co chu y:
--
-- 1. CHI AUTH TREN KET NOI MOI. `set_keepalive` tra ket noi ve pool con NGUYEN
--    trang thai da xac thuc, nen AUTH lai tren ket noi tai dung la mot round-trip
--    THEM vao MOI request. `get_reused_times() > 0` = lay tu pool = da AUTH roi.
--
-- 2. AUTH LOI thi TRA NIL, khong tra ket noi. `intel_pool` chi `log(WARN)` roi tra
--    `red` ra ngoai, nen ben goi tuong minh co handle dung duoc trong khi moi lenh
--    sau do deu tra `NOAUTH`. Mot handle "co ve song" nguy hon mot `nil`: `nil` thi
--    ben goi da co nhanh xu ly (fail-open co y thuc), con handle chet thi khong.
--    Ket noi loi cung KHONG duoc dua vao pool -- dong thang bang `close()`.
function _M.get()
    local red = redis:new()
    red:set_timeout(CFG.timeout_ms)

    local ok, err = red:connect(CFG.host, CFG.port)
    if not ok then
        ngx.log(ngx.ERR, "[redis_pool] connect failed: ", err)
        return nil, err
    end

    local moi = true
    local n, nerr = red:get_reused_times()
    if n and n > 0 then moi = false end
    if not n then
        ngx.log(ngx.WARN, "[redis_pool] get_reused_times failed: ", nerr)
    end

    if moi and CFG.password and CFG.password ~= "" then
        local aok, aerr = red:auth(CFG.password)
        if not aok then
            ngx.log(ngx.ERR, "[redis_pool] AUTH failed: ", aerr)
            red:close()
            return nil, aerr
        end
    end

    if moi and CFG.db and CFG.db > 0 then
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

-- MGET: mot round-trip cho NHIEU khoa.
--
-- Can cho phep tra CHUOI TO TIEN cua mot thu muc (`.htaccess` ap cho ca thu muc con),
-- va do sau that la 0-7 tang — 8 `safe_get` la 8 round-trip tren hot path, con mot
-- `MGET` la mot. Tra ve mang cung THU TU khoa; phan tu khong ton tai la `ngx.null`.
--
-- `safe_*` chu khong `pipeline`: bo test stub `pool` theo tung ham `safe_*`, va mot
-- ham moi phai stub duoc — khong thi nhanh nay chay that trong test va no do voi
-- "attempt to call field 'pipeline'" (da xay ra 01-10).
function _M.safe_mget(keys, n)
    if not keys or n == nil or n < 1 then return nil end
    local red, err = _M.get()
    if not red then return nil, err end
    local res, merr = red:mget(unpack(keys, 1, n))
    _M.put(red)
    if not res then return nil, merr end
    return res
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

function _M.safe_scard(key)
    local red, err = _M.get()
    if not red then return nil, err end
    local n, rerr = red:scard(key)
    _M.put(red)
    if n == ngx.null then return 0 end
    return tonumber(n) or 0, rerr
end

return _M
