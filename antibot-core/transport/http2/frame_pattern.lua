local _M = {}

local function classify_cache_control()
    local cc = ngx.var.http_cache_control
    local pragma = ngx.var.http_pragma

    if not cc then
        if pragma == "no-cache" then return "pragma_only" end
        return "missing"
    end

    if cc:find("no-cache", 1, true) then return "no_cache" end
    if cc:find("max-age=0", 1, true) then return "max_age_0" end
    if cc == "max-age=0"             then return "force_refresh" end
    return "other"
end

local function classify_navigation()
    local referer  = ngx.var.http_referer
    local sf_site  = ngx.var.http_sec_fetch_site
    local sf_mode  = ngx.var.http_sec_fetch_mode
    local has_ref  = referer and referer ~= ""
    local has_sf   = sf_site ~= nil

    if has_sf then
        if sf_site == "none" and sf_mode == "navigate" then
            return "direct_nav_browser"
        end
        if sf_site == "same-origin" then return "internal_nav" end
        if sf_site == "cross-site"  then return "external_ref"  end
        if sf_site == "same-site"   then return "samesite_nav"  end
        return "browser_other"
    end

    if has_ref then return "ref_no_sf"   end
    return "no_context"
end

local function has_upgrade_insecure()
    return ngx.var.http_upgrade_insecure_requests == "1"
end

local function get_request_timing()
    local rt = tonumber(ngx.var.request_time)
    if not rt then return nil end
    return {
        request_time_ms = math.floor(rt * 1000),
        is_too_fast = rt < 0.005,
        is_too_slow = rt > 10,
    }
end

function _M.run(ctx)
    ctx.h2_frames = nil

    if not ctx.h2_is_h2 then return end

    local cache_class = classify_cache_control()
    local nav_class   = classify_navigation()
    local has_uir     = has_upgrade_insecure()
    local timing      = get_request_timing()

    ctx.h2_behavior_profile = {
        cache_control      = cache_class,
        navigation         = nav_class,
        upgrade_insecure   = has_uir,
        timing             = timing,
        signal = string.format("%s.%s.%s",
            cache_class,
            nav_class,
            has_uir and "uir" or "nuir")
    }

    if nav_class == "no_context"
    and cache_class == "missing"
    and not has_uir then
        ctx.h2_bot_pattern = true
        ngx.log(ngx.DEBUG, "[h2_frame] bot_pattern: no nav context, no cache, no UIR")
    end

    ngx.log(ngx.DEBUG,
        "[h2_frame] nav=", nav_class,
        " cache=", cache_class,
        " uir=", tostring(has_uir))
end

return _M
