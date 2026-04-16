local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local function expand_ipv6(ip)
    local left, right = ip:match("^(.*)::(.*)$")
    local left_parts, right_parts = {}, {}

    if left then
        for g in left:gmatch("[^:]+") do
            left_parts[#left_parts+1] = g
        end
        for g in (right ~= "" and right or ""):gmatch("[^:]+") do
            right_parts[#right_parts+1] = g
        end
        local missing = 8 - #left_parts - #right_parts
        local mid = {}
        for i = 1, missing do mid[i] = "0" end
        local all = {}
        for _, g in ipairs(left_parts)  do all[#all+1] = g end
        for _, g in ipairs(mid)         do all[#all+1] = g end
        for _, g in ipairs(right_parts) do all[#all+1] = g end
        left_parts = all
    else
        for g in ip:gmatch("[^:]+") do
            left_parts[#left_parts+1] = g
        end
    end

    local hex = ""
    for _, g in ipairs(left_parts) do
        hex = hex .. string.format("%04s", g):gsub(" ", "0")
    end
    return hex
end

local function ipv6_ptr_name(ip)
    local hex = expand_ipv6(ip)
    if not hex or #hex ~= 32 then return nil end
    local nibbles = {}
    for i = #hex, 1, -1 do
        nibbles[#nibbles+1] = hex:sub(i, i)
    end
    return table.concat(nibbles, ".") .. ".ip6.arpa"
end

local function ipv4_ptr_name(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return d .. "." .. c .. "." .. b .. "." .. a .. ".in-addr.arpa"
end

local function do_ptr_lookup(ip)
    local ok, resolver = pcall(require, "resty.dns.resolver")
    if not ok then return nil, "dns_lib_unavailable" end

    local r, err = resolver:new({
        nameservers = { "8.8.8.8", "1.1.1.1" },
        retrans     = 1,
        timeout     = 800,
    })
    if not r then return nil, "resolver_init: " .. tostring(err) end

    local ptr_name
    if ip:find(":", 1, true) then
        ptr_name = ipv6_ptr_name(ip)
        if not ptr_name then return nil, "ipv6_expand_failed" end
    else
        ptr_name = ipv4_ptr_name(ip)
        if not ptr_name then return nil, "ipv4_parse_failed" end
    end

    local answers, err2 = r:query(ptr_name, { qtype = r.TYPE_PTR })
    if not answers then
        if tostring(err2):find("timeout") then
            return nil, "timeout"
        end
        return nil, "query_failed: " .. tostring(err2)
    end
    if answers.errcode then
        if answers.errcode == 3 then
            return nil, "nxdomain"
        end
        return nil, "dns_err_" .. tostring(answers.errcode)
    end

    for _, ans in ipairs(answers) do
        if ans.type == r.TYPE_PTR and ans.ptrdname then
            return ans.ptrdname, nil
        end
    end
    return nil, "no_ptr_record"
end

function _M.run(ctx)
    if not ctx.good_bot_claimed then
        return true, false
    end

    local ip = ctx.ip or ""
    if ip == "" or ip == "127.0.0.1" or ip == "::1" then
        ctx.dns_rev_valid = false
        return true, false
    end

    local cache_key = "dns_ptr:" .. ip
    local cached    = pool.safe_get(cache_key)
    local ptr, err_type

    if cached then
        if cached == "TIMEOUT" or cached == "NXDOMAIN" or cached == "FAIL" then
            ptr      = nil
            err_type = cached
        else
            ptr = cached
        end
    else
        local p, e = do_ptr_lookup(ip)
        if p then
            ptr = p
            pool.safe_set(cache_key, ptr, cfg.ttl.dns or 300)
        else
            if e and e:find("timeout") then
                err_type = "TIMEOUT"
            elseif e == "nxdomain" or e == "no_ptr_record" then
                err_type = "NXDOMAIN"
            else
                err_type = "FAIL"
            end
            pool.safe_set(cache_key, err_type, cfg.ttl.dns or 300)
            ngx.log(ngx.DEBUG, "[dns_rev] ip=", ip, " err=", tostring(e))
        end
    end

    ctx.dns_rev = ptr

    if ptr then
        local ua_mod = require "antibot.detection.bot.ua_check"
        local suffixes = ctx.good_bot_suffixes or {}
        ctx.dns_rev_valid = ua_mod.is_valid_suffix(ptr, suffixes)
        if not ctx.dns_rev_valid then
            ngx.log(ngx.INFO,
                "[dns_rev] bad suffix ip=", ip,
                " ptr=", ptr,
                " bot=", ctx.good_bot_name or "?")
        end
    elseif err_type == "TIMEOUT" then
        ctx.dns_rev_timeout = true
        ctx.dns_rev_valid   = nil
    else
        ctx.dns_rev_valid   = false
        ctx.dns_rev_nxdomain= true
    end

    return true, false
end

return _M
