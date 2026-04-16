local _M = {}

local function classify_request_size()
    local method = ngx.var.request_method or "GET"
    local cl     = tonumber(ngx.var.http_content_length)
    local req_len = tonumber(ngx.var.request_length) or 0
    local te      = ngx.var.http_transfer_encoding

    local profile = {
        method     = method,
        has_body   = cl ~= nil or (te ~= nil),
        body_size  = cl,
        is_chunked = te ~= nil and te:lower():find("chunked") ~= nil,
        req_bytes  = req_len,
    }

    if method == "GET" and cl ~= nil and cl > 0 then
        profile.anomaly = "get_with_body"
    elseif method == "POST" and cl == 0 then
        profile.anomaly = "post_empty_body"
    end

    return profile
end

local function observe_stream_id()
    local sid = tonumber(ngx.var.http2_stream_id)
    if not sid then return nil end
    local request_count = math.floor((sid + 1) / 2)
    return {
        stream_id     = sid,
        request_count = request_count,
        is_fresh_conn = (sid == 1),
        is_reused     = (sid > 3),
    }
end

function _M.run(ctx)
    ctx.h2_window = nil

    if not ctx.h2_is_h2 then return end

    local req_profile = classify_request_size()
    local stream_info = observe_stream_id()

    ctx.h2_request_profile = {
        request  = req_profile,
        stream   = stream_info,
        signal   = string.format("%s.%s.%s",
            (req_profile.method or "?"):lower(),
            req_profile.has_body and tostring(req_profile.body_size or "chunked") or "nobody",
            stream_info and (stream_info.is_fresh_conn and "fresh" or "reused") or "unknown"
        )
    }

    if req_profile.anomaly then
        ctx.h2_request_anomaly = req_profile.anomaly
        ngx.log(ngx.INFO, "[h2_window] request anomaly: ", req_profile.anomaly)
    end

    ngx.log(ngx.DEBUG,
        "[h2_window] stream=", stream_info and tostring(stream_info.stream_id) or "n/a",
        " req_bytes=", req_profile.req_bytes,
        " method=", req_profile.method)
end

return _M
