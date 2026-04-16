local _M = {}

local function calc_header_entropy()
    local headers = ngx.req.get_headers()
    local count = 0
    for _ in pairs(headers) do count = count + 1 end
    if count < 3 then return 0.1 end
    if count > 25 then return 0.9 end
    return 0.5
end

function _M.run(ctx)
    ctx.ip   = ngx.var.remote_addr or ""
    ctx.port = tonumber(ngx.var.remote_port) or 0

    ctx.ua = ngx.var.http_user_agent or ""

    ctx.req = ctx.req or {}
    ctx.req.uri     = ngx.var.request_uri or "/"
    ctx.req.method  = ngx.var.request_method or "GET"
    ctx.req.host    = ngx.var.host or ""
    ctx.req.scheme  = ngx.var.scheme or "http"
    ctx.req.accept  = ngx.var.http_accept or ""
    ctx.req.referer = ngx.var.http_referer or ""
    ctx.req.proto   = ngx.var.server_protocol or ""

    ctx.req.content_type = ngx.var.http_content_type or ""

    ctx.req.accept_lang = ngx.var.http_accept_language or ""

    ctx.req.accept_enc = ngx.var.http_accept_encoding or ""

    ctx.req.sec_fetch_site = ngx.var.http_sec_fetch_site or ""
    ctx.req.sec_fetch_mode = ngx.var.http_sec_fetch_mode or ""
    ctx.req.sec_fetch_dest = ngx.var.http_sec_fetch_dest or ""

    ctx.entropy = calc_header_entropy()

    ctx.req.connection = ngx.var.http_connection or ""

    ngx.log(ngx.DEBUG,
        "[collect_request] ip=", ctx.ip,
        " ua=", ctx.ua:sub(1, 40),
        " entropy=", ctx.entropy)

    return true, false
end

return _M
