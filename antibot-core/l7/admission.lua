-- Local L7 admission control.
--
-- Day la phanh TAI NGUYEN, khong phai phan quyet BOT. Vuot budget chi tra
-- 429/503 ngan han; khong ghi ban, khong tang risk, khong ket toi identity.
-- Chay truoc verified/whitelist/resource fast-path va khong cham Redis.

local _M  = {}
local cfg = require "antibot.core.config"

local last_dict_error = 0

local function conf()
    return cfg.l7_admission or {}
end

local function now()
    return ngx.now and ngx.now() or ngx.time()
end

local function log_dict_error(name)
    local t = now()
    if t - last_dict_error >= 60 then
        last_dict_error = t
        ngx.log(ngx.ERR,
            "[l7_admission] lua_shared_dict missing/unavailable: ", name,
            " (check nginx.conf and reload)")
    end
end

local function dictionary()
    local shared = ngx.shared or {}
    local dict = shared.antibot_cache
    if not dict then log_dict_error("antibot_cache") end
    return dict
end

-- Fixed bucket: TTL CHI dat khi add khoa moi, khong refresh tren moi request.
-- `incr(key, 1, 0, ttl)` khong co tren mot so OpenResty cu; cap add+incr nay
-- giu tuong thich va van atomic khi hai worker tao khoa cung luc.
local function bucket_incr(dict, key, seconds, t)
    local bucket = math.floor(t / seconds)
    local bkey   = key .. ":" .. seconds .. ":" .. bucket

    local value, err = dict:incr(bkey, 1)
    if value then return value end
    if err ~= "not found" then return nil, err end

    local ok, add_err = dict:add(bkey, 1, seconds + 1)
    if ok then return 1 end
    if add_err == "exists" then
        return dict:incr(bkey, 1)
    end
    return nil, add_err
end

local function safe_component(s, fallback)
    s = tostring(s or "")
    if s == "" then return fallback end
    s = s:lower():gsub("[^%w%.%-_:]", "_")
    if #s > 96 then
        return (ngx.md5 and ngx.md5(s):sub(1, 16)) or s:sub(1, 96)
    end
    return s
end

local function server_host(ctx)
    -- server_name den tu config da chon, khong tao cardinality theo Host header.
    local host = ngx.var.server_name
    if not host or host == "" then
        host = ctx and ctx.req and ctx.req.host or ngx.var.host
    end
    return safe_component(host, "unknown")
end

local function client_ip(ctx)
    return safe_component((ctx and ctx.ip) or ngx.var.remote_addr, "unknown")
end

-- Static CANDIDATE vs static MISS.
--
-- VI SAO CAN TACH. `req_classifier` chi biet "GET/HEAD + duoi tinh", tuc static
-- CANDIDATE. Neu tep co that tren dia, Nginx phuc vu truc tiep va request do
-- that su re. Neu KHONG co, `try_files` chuyen sang `@static_backend` va no vao
-- Apache/PHP — voi WordPress thi `.htaccess` rewrite thanh `index.php`, tuc no
-- la tai DYNAMIC du duoi tep la `.jpg`.
--
-- Truoc ban nay ca hai dung CUNG ngan sach `resource`, von duoc dat cao vi gia
-- dinh "static thi re". Do duoc tren stub cung hinh dang (1 host, 2000 IP,
-- `.jpg` khong ton tai):
--
--   2000 IP x 10 req don 1 giay      -> 4.000 req/s den Apache
--   2000 IP x 10 req trai deu 10 giay -> 20.000/20.000 LOT, 2.000 req/s
--   2000 IP x 2 req/s, ben vung 60s  -> 3.200 req/s lien tuc, 80% lot
--
-- Cung luu luong do neu la `.php` thi chi 350 req/s lot. Khac 9 lan, va chenh
-- lech do khong phan anh chi phi thuc te nao.
--
-- Chu thich o `req_classifier.lua:431` tung khang dinh "static miss se bi
-- @static_backend admission guard dem lai" — guard do DA BI THU HOI o review 3
-- (rang buoc Lua-only), va `da_to_openresty.sh` dat `access_by_lua_block
-- { return; }` trong named location, tuc TAT han Lua o do. Chu thich mo ta code
-- khong ton tai.
--
-- CACH DO: `io.open` tren `document_root .. uri`, GIONG `waf/init.lua`
-- (`target_exists`). Khac mot diem quan trong: do nay chay o ACCESS phase chu
-- khong log phase, nen phai CACHE — mot `io.open` moi request resource la dung
-- cai review 1 da canh bao ("khong can stat() file trong Lua tren moi request").
--
-- Cache trong shared dict, khoa theo `docroot|uri`, TTL ngan (mac dinh 30s):
--   · tep that  -> cache "1", request sau khong stat lai
--   · tep thieu -> cache "0", va day la ca QUAN TRONG: mot flood 3.200 req/s
--     vao CUNG duong dan chi ton MOT `io.open` moi 30 giay.
-- TTL ngan de deploy/upload tep moi khong bi hieu sai qua lau.
--
-- FAIL-OPEN CO CHU DICH: khong doc duoc docroot, dict loi, hay `io.open` loi
-- vi ly do khac -> coi nhu static that (ngan sach resource). Mot phep do khong
-- chac chan khong duoc phep bien thanh 429 cho khach that. FP la uu tien mot.
local function static_target_exists(ctx, dict, uri)
    local root = ngx.var.document_root
    if not root or root == "" then return nil end
    if root:sub(-1) == "/" then root = root:sub(1, -2) end

    -- Query string khong anh huong duong dan tren dia; `ngx.var.uri` da
    -- normalize va KHONG chua query. Giu nguyen de khoa cache on dinh.
    local ckey = "adm:fx:" .. root .. "|" .. uri
    if dict then
        local cached = dict:get(ckey)
        if cached == 1 then return true end
        if cached == 0 then return false end
    end

    local fh = io.open(root .. uri, "r")
    local exists = false
    if fh then fh:close(); exists = true end

    if dict then
        local ttl = tonumber((conf().static_probe_ttl)) or 30
        dict:set(ckey, exists and 1 or 0, ttl)
    end
    return exists
end

-- `resource` chi giu ngan sach resource khi tep co THAT tren dia. Static miss
-- di vao ngan sach `dynamic` vi do dung la noi tai cua no den.
local function class_group(class, ctx, dict, uri)
    if class ~= "resource" then return "dynamic" end
    local c = conf()
    if c.static_probe == false then return "resource" end
    local exists = static_target_exists(ctx, dict, uri)
    if exists == false then
        if ctx then ctx.resource_actual = false end
        return "dynamic"
    end
    if ctx and exists == true then ctx.resource_actual = true end
    return "resource"
end

local function route_shard(uri, count)
    uri = uri or "/"
    local h
    if ngx.crc32_short then
        h = ngx.crc32_short(uri)
    elseif ngx.md5 then
        h = tonumber(ngx.md5(uri):sub(1, 8), 16)
    end
    h = tonumber(h) or 0
    return h % math.max(tonumber(count) or 64, 1)
end

local function mark_over(ctx, reason, value, limit, window)
    if not ctx then return end
    ctx.admission_limited = true
    ctx.admission_reason  = reason
    ctx.admission_count   = value
    ctx.admission_limit   = limit
    ctx.admission_window  = window
end

local function reject(ctx, reason, value, limit, window, status, retry_after)
    mark_over(ctx, reason, value, limit, window)
    if ctx then
        ctx.action        = "throttled"
        ctx.action_reason = "l7_admission:" .. reason
    end

    ngx.header["Retry-After"]      = tostring(retry_after or 2)
    ngx.header["Cache-Control"]    = "no-store"
    ngx.header["Content-Type"]     = "text/plain"
    ngx.header["X-Bot-Action"]     = "throttled"
    ngx.header["X-L7-Admission"]   = reason
    ngx.status = status or 429

    ngx.log(ngx.WARN,
        "[l7_admission] throttle reason=", reason,
        " count=", tostring(value),
        " limit=", tostring(limit),
        " window=", tostring(window),
        " ip=", client_ip(ctx),
        " host=", server_host(ctx),
        " uri=", (ngx.var.uri or "/"):sub(1, 160))

    ngx.say("Too many requests.")
    ngx.exit(status or 429)
    return true, true
end

local function count_limit(dict, prefix, spec, windows, t)
    if not spec then return nil end
    for _, name in ipairs({ "short", "long" }) do
        local seconds = tonumber(windows[name])
        local limit   = tonumber(spec[name])
        if seconds and seconds > 0 and limit and limit > 0 then
            local value, err = bucket_incr(dict, prefix, seconds, t)
            if not value then
                return {
                    reason = "dict_error", error = err,
                    value = 0, limit = limit, window = seconds,
                }
            end
            if value > limit then
                return {
                    value = value, limit = limit, window = seconds,
                }
            end
        end
    end
    return nil
end

local function apply_check(ctx, dict, prefix, spec, reason, c, t)
    local over = count_limit(dict, prefix, spec, c.windows or {}, t)
    if not over then return false, false end

    local final_reason = over.reason == "dict_error"
        and (reason .. "_dict_error") or reason
    mark_over(ctx, final_reason, over.value, over.limit, over.window)

    -- Shared-dict pressure khong duoc bien thanh outage. Core budgets khac van
    -- tiep tuc bao ve; error duoc log rate-limited de operator thay.
    if over.reason == "dict_error" then
        log_dict_error(final_reason .. ":" .. tostring(over.error))
        return false, false
    end

    if c.mode == "enforce" then
        return reject(ctx, final_reason, over.value, over.limit, over.window,
                      c.status, c.retry_after)
    end
    return false, false
end

function _M.run(ctx)
    local c = conf()
    if not c.enabled or c.mode == "off" then return true, false end

    -- Tai su dung shared dict da co de giu thay doi thuần Lua. Prefix `adm:`
    -- tach namespace; route shard co cardinality co dinh. Per-IP keys van co
    -- the tao LRU pressure khi IP churn, nen core checks luon chay truoc.
    local core = dictionary()
    if not core then return true, false end
    local clients = core

    local limits = c.limits or {}
    local class  = (ctx and ctx.req_class) or "unknown"
    local host   = server_host(ctx)
    local ip     = client_ip(ctx)
    local uri    = ngx.var.uri or (ctx and ctx.req and ctx.req.uri) or "/"
    -- `group` tinh SAU `uri` vi phep do static-miss can duong dan. Thu tu cu
    -- (`group` truoc `uri`) se truyen nil vao phep kiem tep.
    local group  = class_group(class, ctx, core, uri)
    local shard  = route_shard(uri, c.route_shards)
    local t      = now()

    if ctx then
        ctx.admission_group       = group
        ctx.admission_route_shard = shard
    end

    local checks = {
        { core, "adm:g", limits.global, "global" },
        { core, "adm:h:" .. host, limits.host, "host" },
        { core, "adm:hg:" .. host .. ":" .. group,
          limits.host_group and limits.host_group[group], "host_" .. group },
        { core, "adm:r:" .. host .. ":" .. group .. ":" .. shard,
          limits.route_group and limits.route_group[group], "route_" .. group },
    }

    for i = 1, #checks do
        local ignored, exit = apply_check(
            ctx, checks[i][1], checks[i][2], checks[i][3], checks[i][4], c, t)
        if exit then return true, true end
    end

    -- IP cua verified reverse proxy la edge tap the. Khong dung no de ket luan
    -- client, nhung host/global/route circuit breakers phia tren van bat buoc.
    if clients and not (ctx and ctx.behind_proxy) then
        local ip_spec = limits.ip and (limits.ip[class] or limits.ip.default)
        local ignored, exit = apply_check(ctx, clients,
            "adm:ip:" .. ip .. ":" .. class, ip_spec, "ip_" .. class, c, t)
        if exit then return true, true end
    end

    return true, false
end

-- /antibot/verify va /antibot/beacon override server access_by_lua. Content
-- handler Lua cua tung endpoint goi ham nay truc tiep, khong sua Nginx config.
function _M.run_endpoint(name)
    local c = conf()
    if not c.enabled or c.mode == "off" then return true, false end

    local core = dictionary()
    if not core then return true, false end
    local clients = core

    local ep = c.limits and c.limits.endpoints and c.limits.endpoints[name]
    if not ep then return true, false end

    local ctx  = (ngx.ctx and ngx.ctx.antibot) or {}
    if ngx.ctx then ngx.ctx.antibot = ctx end
    ctx.backend_class = "antibot_endpoint:" .. tostring(name)
    local host = server_host(ctx)
    local ip   = client_ip(ctx)
    local t    = now()

    local ignored, exit = apply_check(ctx, core,
        "adm:ep:h:" .. host .. ":" .. name, ep.host,
        "endpoint_" .. name .. "_host", c, t)
    if exit then return true, true end

    if clients then
        ignored, exit = apply_check(ctx, clients,
            "adm:ep:ip:" .. ip .. ":" .. name, ep.ip,
            "endpoint_" .. name .. "_ip", c, t)
        if exit then return true, true end
    end
    return true, false
end

return _M
