local _M = {}

local FATAL_FIELDS = { "ip", "ua", "req" }

function _M.init(ctx)
    ctx.ip   = ngx.var.remote_addr or ""
    ctx.port = tonumber(ngx.var.remote_port) or 0
    ctx.ua   = ngx.var.http_user_agent or ""

    ctx.req = {
        uri            = ngx.var.request_uri        or "/",
        method         = ngx.var.request_method     or "GET",
        host           = ngx.var.host               or "",
        scheme         = ngx.var.scheme             or "http",
        accept         = ngx.var.http_accept        or "",
        referer        = ngx.var.http_referer       or "",
        proto          = ngx.var.server_protocol    or "",
        content_type   = ngx.var.http_content_type      or "",
        accept_lang    = ngx.var.http_accept_language   or "",
        accept_enc     = ngx.var.http_accept_encoding   or "",
        connection     = ngx.var.http_connection        or "",
        sec_fetch_site = ngx.var.http_sec_fetch_site    or "",
        sec_fetch_mode = ngx.var.http_sec_fetch_mode    or "",
        sec_fetch_dest = ngx.var.http_sec_fetch_dest    or "",
    }

    ctx.ja3            = nil
    ctx.ja3_raw        = nil
    ctx.ja3_partial    = nil
    ctx.ja3_cipher_src = nil
    ctx.tls_version    = nil
    ctx.ja3s           = nil
    ctx.tls_cipher     = nil

    ctx.h2_sig         = nil
    ctx.h2_order       = nil

    ctx.identity       = nil
    ctx.ua_norm        = nil
    ctx.fp_light       = nil
    ctx.fp_full        = nil
    ctx.fp_quality     = 0.25
    ctx.fp_degraded    = false

    ctx.asn            = nil
    ctx.ip_type        = { is_datacenter=false, is_vpn=false, is_tor=false, is_residential=true }
    ctx.ip_score       = 0.0

    ctx.ip_rep         = 0.0
    ctx.asn_rep        = 0.0
    ctx.ja3_rep        = 0.0
    ctx.h2_rep         = 0.0

    ctx.rate_flag      = false
    ctx.burst_flag     = false
    ctx.slow           = false
    ctx.rate           = 0
    ctx.burst          = 0

    ctx.session        = nil
    ctx.sess_len       = 0
    ctx.session_flag   = 0.0
    ctx.graph_flag     = 0.0
    ctx.graph_score    = 0.0
    ctx.ua_cluster     = 0
    ctx.ip_cluster     = 0
    ctx.uri_cluster    = 0
    ctx.tls_cluster    = 0
    ctx.swarm          = false
    ctx.anomaly_score  = 0.0
    ctx.bot_score      = 0.0
    ctx.behavior_score = 0.0
    ctx.baseline_ua    = false
    ctx.entropy        = 0.35
    ctx.subnet_diversity = 0
    ctx.geo            = nil

    ctx.whitelisted      = false
    ctx.good_bot_claimed = false
    ctx.banned           = false
    ctx.verified         = false
    ctx.score            = 0.0
    ctx.action           = "allow"
    ctx.action_reason    = nil
    ctx.top_signals      = {}
    ctx.monitor_flag     = false

    ctx.corr_score     = 0.0
    ctx.corr_rules     = {}
    ctx.mismatch       = 0.0

    return true, false
end

function _M.finalize(ctx)
    if not ctx.ip or ctx.ip == "" then
        return false, "FATAL: ctx.ip missing"
    end
    if not ctx.ua then
        ctx.ua = ""
    end
    if not ctx.req then
        return false, "FATAL: ctx.req missing"
    end

    if not ctx.identity then
        local identity_mod = require "antibot.core.fingerprint.identity"
        identity_mod.build(ctx)
        ctx.fp_degraded = true
        ngx.log(ngx.WARN,
            "[ctx.finalize] identity fallback ip=", ctx.ip,
            " id=", ctx.identity)
    end

    if not ctx.fp_light or ctx.fp_light == "" then
        ctx.fp_light = ctx.identity
    end

    return true, nil
end

return _M
