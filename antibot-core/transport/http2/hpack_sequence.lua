local _M = {}

local function classify_accept_encoding(ae)
    if not ae or ae == "" then return "missing" end
    local has_br    = ae:find("br",    1, true) ~= nil
    local has_zstd  = ae:find("zstd",  1, true) ~= nil
    local has_gzip  = ae:find("gzip",  1, true) ~= nil
    local has_defl  = ae:find("deflate", 1, true) ~= nil

    if has_gzip and has_defl and has_br and has_zstd then return "full_zstd"   end
    if has_gzip and has_defl and has_br              then return "full_br"     end
    if has_gzip and has_defl                         then return "gzip_deflate" end
    if has_gzip and not has_defl and not has_br      then return "gzip_only"   end
    return "other"
end

local function classify_accept(ac)
    if not ac or ac == "" then return "missing" end
    if ac:find("text/html", 1, true) and ac:find("application/xhtml", 1, true) then
        return "browser_full"
    end
    if ac:find("application/json", 1, true) then return "json_api" end
    if ac == "*/*"                           then return "wildcard" end
    if ac:find("text/html", 1, true)         then return "html_basic" end
    return "other"
end

local function observe_sec_fetch()
    local site = ngx.var.http_sec_fetch_site
    local mode = ngx.var.http_sec_fetch_mode
    local dest = ngx.var.http_sec_fetch_dest
    if site and mode and dest then
        return {
            present = true,
            site    = site,
            mode    = mode,
            dest    = dest,
        }
    end
    return { present = false }
end

local function observe_client_hints()
    local ch_ua     = ngx.var.http_sec_ch_ua
    local ch_mobile = ngx.var.http_sec_ch_ua_mobile
    local ch_plat   = ngx.var.http_sec_ch_ua_platform
    return {
        has_ch_ua       = ch_ua ~= nil and ch_ua ~= "",
        has_ch_mobile   = ch_mobile ~= nil,
        has_ch_platform = ch_plat ~= nil and ch_plat ~= "",
        ch_ua_value     = ch_ua,
    }
end

local function observe_content_type()
    local ct = ngx.var.http_content_type
    if not ct then return nil end
    if ct == ct:lower() then return "lowercase" end
    return "mixed_case"
end

function _M.run(ctx)
    ctx.h2_hpack = nil

    if not ctx.h2_is_h2 then return end

    local ae = ngx.var.http_accept_encoding
    local ac = ngx.var.http_accept

    ctx.h2_header_profile = {
        accept_encoding  = classify_accept_encoding(ae),
        accept_type      = classify_accept(ac),
        sec_fetch        = observe_sec_fetch(),
        client_hints     = observe_client_hints(),
        content_type     = observe_content_type(),
        has_referer      = ngx.var.http_referer ~= nil and ngx.var.http_referer ~= "",
        has_origin       = ngx.var.http_origin  ~= nil and ngx.var.http_origin  ~= "",
        ua_len           = #(ctx.ua or ""),
    }

    local sf = ctx.h2_header_profile.sec_fetch.present
    local ch = ctx.h2_header_profile.client_hints.has_ch_ua
    ctx.h2_header_fp = string.format("%s.%s.%s.%s",
        ctx.h2_header_profile.accept_encoding,
        ctx.h2_header_profile.accept_type,
        sf and "sf" or "nsf",
        ch and "ch" or "nch")

    ngx.log(ngx.DEBUG,
        "[h2_hpack_obs] header_fp=", ctx.h2_header_fp,
        " ae=", ctx.h2_header_profile.accept_encoding)
end

return _M
