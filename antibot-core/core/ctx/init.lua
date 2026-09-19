local _M = {}

local ip_scope = require "antibot.core.ip_scope"

local FATAL_FIELDS = { "ip", "ua", "req" }

function _M.init(ctx)
    -- MOT HEADER KHONG BAO GIO DUOC PHEP KHAI MINH LA DIA CHI NOI BO.
    --
    -- `ngx.var.remote_addr` chi la dia chi TCP that CHUNG NAO khong co
    -- `real_ip_header`. Khi co (vi du `nginx/CF/cloudflare-realip.conf` dat
    -- `real_ip_header CF-Connecting-IP`), no la gia tri sao chep NGUYEN VAN tu
    -- mot header, va module realip cua nginx KHONG kiem tra dia chi thay the co
    -- phai IP cong cong hay khong — `127.0.0.1`, `10.x`, `192.168.x`, `::1`
    -- deu duoc nhan.
    --
    -- Chuoi hau qua neu khong chan o day: `ctx.ip = "127.0.0.1"` =>
    -- `access/whitelist.lua` tra `lan_internal` => `ctx.whitelisted = true` =>
    -- pipeline thoat ngay o buoc 4. Bo qua scoring, l7, ip_ban_check,
    -- detection, PoW. Va tin hieu WAF thang duoc `verified` nhung KHONG thang
    -- `whitelisted`, nen ca luat chan WP-path lan `dotfile_exposed` cung bi bo
    -- qua. Tuc mot header duy nhat go bo toan bo he thong.
    --
    -- Chan o TANG LUA chu khong chi o config, vi bat bien nay phai dung du ai
    -- them `set_real_ip_from` o dau, luc nao, cho domain nao.
    --
    -- CHI thay the khi dia chi bi ghi de LA dai noi bo. IP cong cong gia mao
    -- thi khong xu ly duoc o day — do la ban chat cua viec tin header cua mot
    -- proxy, va cach sua nam o cho gioi han `set_real_ip_from`, khong phai o
    -- day.
    local tcp_ip = ip_scope.tcp_peer()
    local ip     = ngx.var.remote_addr or ""

    if tcp_ip ~= "" and ip ~= tcp_ip and ip_scope.is_private(ip) then
        ngx.log(ngx.WARN,
            "[ctx] tu choi dia chi noi bo do header khai: ", ip,
            " — dung dia chi TCP that: ", tcp_ip,
            " host=", ngx.var.host or "?")
        ctx.ip_spoofed = ip
        ip = tcp_ip
    end

    ctx.ip     = ip
    ctx.ip_tcp = tcp_ip
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
    ctx.tls_version    = nil

    ctx.h2_sig         = nil
    ctx.h2_order       = nil

    ctx.identity       = nil
    ctx.ua_norm        = nil
    ctx.fp_light       = nil
    ctx.fp_full        = nil
    ctx.fp_quality     = 0.25
    ctx.fp_degraded    = false

    ctx.asn            = nil
    -- IP-type scoring bi VO HIEU CO CHU Y (DC egress = nguoi that: iCloud
    -- Private Relay, proxy bao mat doanh nghiep, cloud VPN). `ip_classify.lua`
    -- da bi xoa 2026-09-06 nen DAY LA NOI DUY NHAT dat gia tri; ba noi doc no
    -- (compute weight 25, cross_layer_rules, l7/rate/adaptive_limit) deu nhan 0.
    ctx.ip_score       = 0.0
    ctx.ip_shared      = false       -- Tier 1 (lenient): distinct-UA/IP high → dampen per-IP reputation
    ctx.ip_shared_verified = false   -- Tier 2 (strict): shared AND real cookied users → IP-ban immunity
    ctx.ip_real_users  = 0           -- distinct cookie-bearing identities on IP (ip_tour)
    ctx.ip_farm_suspect = false      -- Phase 2: shared IP with mobile-farm signature (many UAs, very low cookie-ratio)
    -- Dat boi core/proxy_origin.lua (buoc 6 cua STEPS_COMMON, TRUOC ip_ban_check).
    -- `behind_proxy` CHI bat tu dai IP da xac minh hoac khai bao operator, KHONG
    -- BAO GIO tu header. `proxy_spoof` = header khai proxy ma ip ngoai dai ⇒ xau.
    ctx.behind_proxy   = false       -- request den qua reverse proxy cong cong (ctx.ip la dia chi EDGE)
    ctx.proxy_vendor   = nil         -- "cloudflare" | "declared"
    ctx.proxy_spoof    = false       -- header khai proxy nhung dia chi khong thuoc dai nao da xac minh

    ctx.ip_rep         = 0.0
    ctx.asn_rep        = 0.0

    ctx.rate_flag      = false
    ctx.burst_flag     = false
    ctx.rate           = 0
    ctx.burst          = 0

    ctx.session        = nil
    ctx.sess_len       = 0
    ctx.session_flag   = 0.0
    ctx.graph_flag     = 0.0
    ctx.ua_cluster     = 0
    ctx.ip_cluster     = 0
    ctx.uri_cluster    = 0
    ctx.swarm          = false
    ctx.anomaly_score  = 0.0
    ctx.bot_score      = 0.0
    ctx.behavior_score = 0.0
    ctx.baseline_ua    = false
    ctx.entropy        = 0.35
    ctx.subnet_diversity = 0

    ctx.whitelisted      = false
    ctx.good_bot_claimed = false
    ctx.banned           = false
    ctx.verified         = false

    -- S2.5 attest fields (Phase 1).
    -- ua_check populates {bot_ua_compliant, bot_contact_host, browser_ua_pattern, analyzer_marker}.
    -- bot/init.lua sets bot_identity_tier="S2.5" when contact_attest or analyzer_attest fires.
    -- dns_rev populated by dns_reverse (existing field, kept for back-compat).
    ctx.bot_ua_compliant    = false
    ctx.bot_contact_host    = nil
    ctx.browser_ua_pattern  = false
    ctx.analyzer_marker     = nil
    ctx.bot_identity_tier   = nil
    ctx.score            = 0.0
    ctx.action           = "allow"
    ctx.action_reason    = nil
    ctx.top_signals      = {}
    ctx.monitor_flag     = false

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
