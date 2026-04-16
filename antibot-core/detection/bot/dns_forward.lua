local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local function do_forward_lookup(hostname)
    local ok, resolver = pcall(require, "resty.dns.resolver")
    if not ok then return nil, "dns_lib_unavailable" end

    local r, err = resolver:new({
        nameservers = { "8.8.8.8", "1.1.1.1" },
        retrans     = 2,
        timeout     = 1500,
    })
    if not r then return nil, tostring(err) end

    local ips = {}

    local ans_a, err_a = r:query(hostname, { qtype = r.TYPE_A })
    if ans_a and not ans_a.errcode then
        for _, ans in ipairs(ans_a) do
            if ans.type == r.TYPE_A and ans.address then
                ips[ans.address] = true
            end
        end
    end

    local ans_aaaa, err_aaaa = r:query(hostname, { qtype = r.TYPE_AAAA })
    if ans_aaaa and not ans_aaaa.errcode then
        for _, ans in ipairs(ans_aaaa) do
            if ans.type == r.TYPE_AAAA and ans.address then
                ips[ans.address:lower()] = true
            end
        end
    end

    if next(ips) == nil then
        local e = tostring(err_a or err_aaaa or "no_records")
        if e:find("timeout") then return nil, "timeout" end
        return nil, "no_records"
    end

    return ips, nil
end

local function normalize_ip(ip)
    if not ip:find(":", 1, true) then
        return ip
    end
    return ip:lower()
end

function _M.run(ctx)
    if ctx.dns_rev_valid ~= true then
        return true, false
    end

    local ptr = ctx.dns_rev
    local ip  = normalize_ip(ctx.ip or "")
    if not ptr or ip == "" then return true, false end

    local cache_key = "dns_fwd:" .. ptr
    local cached    = pool.safe_get(cache_key)
    local fwd_ips   = {}

    if cached then
        if cached ~= "FAIL" then
            for addr in cached:gmatch("[^,]+") do
                fwd_ips[addr] = true
            end
        end
    else
        local ips, err = do_forward_lookup(ptr)
        if ips then
            fwd_ips = ips
            local ip_list = {}
            for addr in pairs(ips) do ip_list[#ip_list+1] = addr end
            pool.safe_set(cache_key, table.concat(ip_list, ","),
                          cfg.ttl.dns or 300)
        else
            pool.safe_set(cache_key, "FAIL", cfg.ttl.dns or 300)
            if err and err:find("timeout") then
                ctx.dns_fwd_timeout = true
                return true, false
            end
        end
    end

    ctx.dns_fwd_valid = fwd_ips[ip] == true

    if ctx.dns_fwd_valid then
        ctx.good_bot_verified = true
        ctx.bot_score         = 0.0
        ngx.log(ngx.INFO,
            "[dns_fwd] VERIFIED bot=", ctx.good_bot_name or "?",
            " ip=", ctx.ip, " ptr=", ptr)
    else
        ctx.good_bot_verified = false
        ctx.bot_ua            = "fake_good_bot"
        ctx.bot_score         = 0.9
        ngx.log(ngx.WARN,
            "[dns_fwd] FAKE bot=", ctx.good_bot_name or "?",
            " ip=", ctx.ip, " ptr=", ptr)
    end

    return true, false
end

return _M
