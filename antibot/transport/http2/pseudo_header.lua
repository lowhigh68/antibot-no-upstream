local _M = {}

local KNOWN_PATTERNS = {
    masp = { client = "chrome",   tls13 = true  },
    mpsa = { client = "firefox",  tls13 = true  },
    mspa = { client = "safari",   tls13 = true  },
    amps = { client = "go_http2", tls13 = false },
    mpsa = { client = "python_h2", tls13 = false },
    mpsa = { client = "java_h2",  tls13 = false },
    mpsa = { client = "curl_h2",  tls13 = false },
}

local function infer_from_ua(ua)
    if not ua or ua == "" then return nil, "no_ua" end

    if ua:find("Chrome/", 1, true) and not ua:find("Edg/", 1, true) then
        return "masp", "ua_chrome"
    end
    if ua:find("Edg/", 1, true) then
        return "masp", "ua_edge"
    end
    if ua:find("Firefox/", 1, true) then
        return "mpsa", "ua_firefox"
    end
    if ua:find("Safari/", 1, true) and not ua:find("Chrome/", 1, true) then
        return "mspa", "ua_safari"
    end
    if ua:find("Go%-http%-client/", 1, true) then
        return "amps", "ua_go"
    end
    if ua:find("curl/", 1, true) then
        return "mpsa", "ua_curl"
    end
    if ua:find("python", 1, true) or ua:find("httpx", 1, true)
    or ua:find("requests/", 1, true) then
        return "mpsa", "ua_python"
    end
    if ua:find("Java/", 1, true) or ua:find("okhttp/", 1, true)
    or ua:find("Apache%-HttpClient", 1, true) then
        return "mpsa", "ua_java"
    end
    if ua:find("node%-fetch", 1, true) or ua:find("axios/", 1, true) then
        return "mpsa", "ua_node"
    end

    return nil, "ua_unknown"
end

local function observe_headers()
    local present = {}

    if ngx.var.http_accept          and ngx.var.http_accept ~= ""
    then present[#present+1] = "ac" end
    if ngx.var.http_accept_language and ngx.var.http_accept_language ~= ""
    then present[#present+1] = "al" end
    if ngx.var.http_accept_encoding and ngx.var.http_accept_encoding ~= ""
    then present[#present+1] = "ae" end

    if ngx.var.http_sec_fetch_site  then present[#present+1] = "sf" end
    if ngx.var.http_sec_ch_ua       then present[#present+1] = "ch" end
    if ngx.var.http_sec_ch_ua_mobile then present[#present+1] = "cm" end

    if ngx.var.http_dnt == "1"      then present[#present+1] = "dn" end

    return table.concat(present, "")
end

function _M.run(ctx)
    local proto = ngx.var.server_protocol or ""
    local is_h2 = proto:find("HTTP/2", 1, true) ~= nil

    if not is_h2 then
        ctx.h2_order        = nil
        ctx.h2_is_h2        = false
        ctx.h2_pseudo_method = nil
        return
    end

    ctx.h2_is_h2 = true

    local trusted = ngx.var.http_x_h2_pseudo_order
    if trusted and trusted ~= "" then
        if #trusted == 4 and trusted:match("^[mpsa]+$") then
            ctx.h2_order         = trusted
            ctx.h2_pseudo_method = "upstream_header"
            ngx.log(ngx.DEBUG, "[h2_pseudo] trusted order=", trusted)
            ctx.h2_header_obs = observe_headers()
            return
        end
    end

    local ua = ctx.ua or ngx.var.http_user_agent or ""
    local order, source = infer_from_ua(ua)

    ctx.h2_order         = order
    ctx.h2_pseudo_method = "inferred"
    ctx.h2_pseudo_source = source

    ctx.h2_header_obs = observe_headers()

    if order and ctx.tls13 ~= nil then
        local pattern_info = KNOWN_PATTERNS[order]
        if pattern_info and pattern_info.tls13 ~= ctx.tls13 then
            ctx.h2_tls_mismatch = true
            ngx.log(ngx.DEBUG,
                "[h2_pseudo] tls_version mismatch: order=", order,
                " expects_tls13=", tostring(pattern_info.tls13),
                " actual_tls13=", tostring(ctx.tls13))
        end
    end

    ngx.log(ngx.DEBUG,
        "[h2_pseudo] order=", tostring(order),
        " source=", source,
        " header_obs=", tostring(ctx.h2_header_obs))
end

return _M
