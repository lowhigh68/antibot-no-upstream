local _M = {}

local function classify_cache_control()
    local cc = ngx.var.http_cache_control
    local pragma = ngx.var.http_pragma

    if not cc then
        if pragma == "no-cache" then return "pragma_only" end
        return "missing"
    end

    if cc:find("no-cache", 1, true) then return "no_cache" end
    -- Khớp CHÍNH XÁC phải đứng trước khớp CHỨA, nếu không nhánh dưới không bao
    -- giờ chạy được: `find("max-age=0")` nuốt luôn cả trường hợp bằng đúng.
    if cc == "max-age=0"             then return "force_refresh" end
    if cc:find("max-age=0", 1, true) then return "max_age_0" end
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

-- `get_request_timing()` DA BI XOA (2026-09-06). Chet HAI lan, y het
-- `l7/slow/slow_detect.lua` vua go:
--   1. `h2_behavior_profile.timing` khong noi nao doc
--   2. no doc `ngx.var.request_time` o ACCESS phase — luc do request chua xu
--      ly xong nen gia tri gan 0 => `is_too_fast` LUON true, `is_too_slow`
--      LUON false. Ke ca co nguoi doc thi hai co do van vo nghia.

function _M.run(ctx)
    if not ctx.h2_is_h2 then return end

    local cache_class = classify_cache_control()
    local nav_class   = classify_navigation()
    local has_uir     = has_upgrade_insecure()

    -- Bang nay TUNG co 5 truong; bon trong so do (`cache_control`,
    -- `upgrade_insecure`, `timing`, `signal`) khong noi nao doc. Ba bien cuc bo
    -- o tren VAN duoc dung — cho nhanh `h2_bot_pattern` ngay duoi — nen chung
    -- o lai; chi cai bang thi thu gon con dung truong co nguoi doc.
    ctx.h2_behavior_profile = { navigation = nav_class }

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
