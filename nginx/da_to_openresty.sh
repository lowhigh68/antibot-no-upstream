#!/usr/bin/env bash
# ============================================================
# /usr/local/openresty/nginx/conf/scripts/da_to_openresty.sh
#
# Đọc cấu trúc dữ liệu DirectAdmin → sinh OpenResty antibot conf
#
# Kiến trúc proxy (no-upstream):
#   Client → 0.0.0.0:80/443 (OpenResty, terminate TLS)
#          → proxy_pass → Apache 127.0.0.1:8080 (HTTP)
#                       → Apache 127.0.0.1:8081 (HTTPS)
#
#   Dùng direct IP thay vì upstream block để:
#   - $remote_addr luôn là IP thật của client
#   - Không cần keepalive pool gây phức tạp với body_filter
#   - Tránh lỗi Content-Length khi body_filter inject JS
#
# Attack 3 — Beacon injection (two-phase design):
#   access phase    → ctx.inject_candidate  (client muốn HTML? — từ Accept header)
#   header_filter   → ctx.browser_needed    (server thực sự trả HTML? — từ Content-Type)
#   body_filter     → inject beacon JS      (chỉ khi browser_needed đã được xác nhận)
#
#   Nguyên tắc: không bao giờ xóa Content-Length của CSS/JS/image
#   vì quyết định inject chỉ được confirm khi biết Content-Type thực của response.
#
# Nguồn dữ liệu DirectAdmin:
#   ${DA_DATA_DIR}/${user}/user.conf
#   ${DA_DATA_DIR}/${user}/domains.list
#   ${DA_DATA_DIR}/${user}/domains/${domain}.conf
#   ${DA_DATA_DIR}/${user}/domains/${domain}.pointers
#     format: domainpointer=type=alias  → lấy phần trước = đầu tiên
#   ${DA_DATA_DIR}/${user}/domains/${domain}.subdomains
#     format: subdomain (prefix, không có domain)
#
# Output:
#   ${OR_USER_DIR}/${user}/domains/${domain}.conf       ← main domain
#   ${OR_USER_DIR}/${user}/domains/${fqdn}.conf         ← subdomain
#   Pointer domains: thêm vào server_name, không tạo file riêng
#
# Usage:
#   sudo bash da_to_openresty.sh
#   sudo bash da_to_openresty.sh --user USERNAME
#   sudo bash da_to_openresty.sh --domain DOMAIN
#   sudo bash da_to_openresty.sh --dry-run
#   sudo bash da_to_openresty.sh --install-hooks
#   sudo bash da_to_openresty.sh --user U --domain D --remove
# ============================================================

set -uo pipefail

DA_DATA_DIR="/usr/local/directadmin/data/users"
OR_CONF_DIR="/usr/local/openresty/nginx/conf"
OR_USER_DIR="${OR_CONF_DIR}/user"
OR_BIN="/usr/local/openresty/nginx/sbin/nginx"
SCRIPT_PATH="$(readlink -f "$0")"

APACHE_HTTP="127.0.0.1:8080"
APACHE_HTTPS="127.0.0.1:8081"

FILTER_USER=""
FILTER_DOMAIN=""
DRY_RUN=false
QUIET=false
INSTALL_HOOKS=false
DO_REMOVE=false
IMPORT_GOODBOTS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --user)          FILTER_USER="$2";   shift 2 ;;
        --domain)        FILTER_DOMAIN="$2"; shift 2 ;;
        --dry-run)       DRY_RUN=true;       shift   ;;
        --quiet)         QUIET=true;         shift   ;;
        --install-hooks) INSTALL_HOOKS=true; shift   ;;
        --import-goodbots) IMPORT_GOODBOTS=true; shift ;;
        --remove)        DO_REMOVE=true;     shift   ;;
        *) shift ;;
    esac
done

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
ok()   { $QUIET || echo -e "${G}[OK]${N}    $*"; }
fail() { echo -e "${R}[FAIL]${N}  $*" >&2; }
info() { $QUIET || echo -e "${B}[INFO]${N}  $*"; }
warn() { echo -e "${Y}[WARN]${N}  $*" >&2; }

[ -f "$OR_BIN" ]      || { fail "OpenResty binary not found: $OR_BIN"; exit 1; }
[ -d "$DA_DATA_DIR" ] || { fail "DA data dir not found: $DA_DATA_DIR"; exit 1; }

# ── DA helpers ────────────────────────────────────────────────

da_get() {
    local file="$1" key="$2" default="${3:-}"
    local val
    val=$(grep -m1 "^${key}=" "$file" 2>/dev/null | cut -d= -f2-)
    echo "${val:-$default}"
}

get_user_ip() {
    local user="$1"
    local user_conf="${DA_DATA_DIR}/${user}/user.conf"
    local ip
    ip=$(da_get "$user_conf" "ip" "")
    [ -z "$ip" ] && ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo "$ip"
}

has_ssl_cert() {
    local user="$1" domain="$2"
    [ -f "${DA_DATA_DIR}/${user}/domains/${domain}.cert.combined" ] && \
    [ -f "${DA_DATA_DIR}/${user}/domains/${domain}.key" ]
}

# Normalize ssl flag: DA dùng "1","on","ON","yes","YES" → true
is_ssl_on() {
    local val="${1,,}"
    [[ "$val" == "1" || "$val" == "on" || "$val" == "yes" ]]
}

# ── Read pointer domains từ ${domain}.pointers ───────────────
# Format mỗi dòng: domainpointer=type=alias
# → lấy phần trước dấu = đầu tiên
get_pointers() {
    local user="$1" domain="$2"
    local ptr_file="${DA_DATA_DIR}/${user}/domains/${domain}.pointers"
    [ -f "$ptr_file" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line// /}"
        [ -z "$line" ] && continue
        local ptr_domain="${line%%=*}"
        [ -z "$ptr_domain" ] && continue
        echo "$ptr_domain"
    done < "$ptr_file"
}

# ── Read subdomains từ ${domain}.subdomains ───────────────────
# Format mỗi dòng: subdomain prefix (không có domain)
get_subdomains() {
    local user="$1" domain="$2"
    local sub_file="${DA_DATA_DIR}/${user}/domains/${domain}.subdomains"
    [ -f "$sub_file" ] || return 0

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line// /}"
        [ -z "$line" ] && continue
        echo "$line"
    done < "$sub_file"
}

# ── Static file fast path (shared across HTTP and HTTPS) ─────
# File tồn tại trên disk → nginx serve + cache 7 ngày (không qua Apache).
# File không tồn tại      → 404 ở nginx ~1ms (không route qua WordPress 4s).
# Giải phóng PHP-FPM worker khỏi việc xử lý 404 static file qua .htaccess.
# Antibot vẫn chạy trong access_by_lua (ở server level) — detect bot quét asset.
#
# Deviation từ DA default (dùng @backend fallback): aggressive hơn vì:
#   - 99%+ plugin caching (WP Rocket, Autoptimize, Elementor, …) generate
#     file lên disk rồi reference → file tồn tại → serve bởi nginx, OK.
#   - Dynamic .css/.js qua PHP hiếm; nếu có plugin đặc biệt cần, add
#     exception riêng per-path với prefix `^~` ưu tiên hơn regex.
#   - Broken reference (theme thiếu file) → 404 nhanh thay vì WP 4s.
static_fastpath() {
    cat << 'LEOF'
    location ~* \.(js|css|png|jpg|jpeg|gif|svg|webp|woff2?|ttf|eot|otf|ico|map|mp4|webm|mp3|ogg|ogv|m4a|m4v|pdf|zip|7z|rar|tgz|gz|txt|xml|json|htc)$ {
        try_files $uri =404;
        expires 7d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
LEOF
}

# ── Antibot internal locations (shared across HTTP and HTTPS) ─
antibot_locations() {
    cat << 'LEOF'
    location = /antibot/verify {
        access_by_lua_block { return; }
        content_by_lua_block {
            local v = require "antibot.enforcement.challenge.verify_token"
            v.handle()
        }
    }
    location = /antibot/beacon {
        access_by_lua_block { return; }
        content_by_lua_block {
            require("antibot.detection.browser.beacon_handler").handle()
        }
    }
    location = /antibot/debug {
        access_by_lua_block {
            if ngx.var.remote_addr ~= "127.0.0.1" then
                ngx.exit(403); return
            end
        }
        content_by_lua_block {
            local e = require "antibot.enforcement.decision.engine"
            ngx.header["Content-Type"] = "application/json"
            local t = e.thresholds()
            ngx.say(string.format(
                '{"version":"4.3.5","monitor":%d,"challenge":%d,"block":%d}',
                t.monitor, t.challenge, t.block))
        }
    }
LEOF
}

# ── Generate conf cho 1 domain/subdomain ──────────────────────
# Args:
#   $1 user
#   $2 fqdn          — domain hoặc sub.domain
#   $3 parent_domain — rỗng nếu là main domain
#   $4 server_names  — space-separated list
#   $5 has_ssl       — "1" hoặc "0"
#   $6 cert_domain   — domain chứa cert (có thể = $2 hoặc parent)
#   $7 server_ip     — IP của user (từ DA user.conf)
generate_conf() {
    local user="$1"
    local fqdn="$2"
    local parent_domain="$3"
    local server_names="$4"
    local has_ssl="$5"
    local cert_domain="$6"
    local server_ip="$7"
    local is_sub=0
    [ -n "$parent_domain" ] && is_sub=1

    # Web root
    local webroot
    if [ "$is_sub" = "1" ]; then
        local sub_name="${fqdn%%.*}"
        if [ -d "/home/${user}/domains/${fqdn}/public_html" ]; then
            webroot="/home/${user}/domains/${fqdn}/public_html"
        else
            webroot="/home/${user}/domains/${parent_domain}/public_html/${sub_name}"
        fi
    else
        webroot="/home/${user}/domains/${fqdn}/public_html"
    fi

    local access_log="/var/log/nginx/domains/${fqdn}.log"
    local bytes_log="/var/log/nginx/domains/${fqdn}.bytes"
    local error_log="/var/log/nginx/domains/${fqdn}.error.log"

    local ssl_cert="${DA_DATA_DIR}/${user}/domains/${cert_domain}.cert.combined"
    local ssl_key="${DA_DATA_DIR}/${user}/domains/${cert_domain}.key"

    # Mail autoconfig: chỉ cho main domain
    local mail_loc=""
    if [ "$is_sub" = "0" ]; then
        mail_loc='
    location = "/.well-known/autoconfig/mail/config-v1.1.xml" {
        proxy_pass http://unix:/usr/local/directadmin/shared/internal.sock;
        proxy_set_header X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
    }
'
    fi

    cat << CONFEOF
# ============================================================
# AUTO-GENERATED by da_to_openresty.sh
# User     : ${user}
# Domain   : ${fqdn}$([ -n "$parent_domain" ] && echo " (subdomain of ${parent_domain})" || echo "")
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# DO NOT EDIT — regenerated on each DA event
# ============================================================

# ── HTTP ─────────────────────────────────────────────────────
server {
    listen 0.0.0.0:80;

    server_name ${server_names};

    access_log ${access_log} antibot_fmt;
    access_log ${bytes_log} bytes;
    error_log  ${error_log};

    root  "${webroot}";
    index index.php index.html index.htm;

    set \$antibot_debug "0";
    access_by_lua_block {
        require("antibot").run()
    }
    log_by_lua_block { require("antibot").log() }
    header_filter_by_lua_block {
        -- Attack 3 beacon injection — two-phase content-type isolation.
        -- Phase 1 (access): trigger.lua sets inject_candidate based on request Accept header.
        -- Phase 2 (here):   confirm using ACTUAL response Content-Type from Apache.
        -- Only when both conditions are true do we set browser_needed and clear Content-Length.
        -- This guarantees CSS/JS/image responses are NEVER modified.
        local ctx = ngx.ctx.antibot
        if not ctx or not ctx.inject_candidate then return end
        local ct = ngx.header["Content-Type"] or ""
        if not ct:find("text/html", 1, true) then return end
        ctx.browser_needed        = true
        ngx.header.content_length = nil
    }
    body_filter_by_lua_block {
        require("antibot.detection.browser.inject").filter()
    }

$(antibot_locations)
$(static_fastpath)
${mail_loc}
    location / {
        proxy_buffering off;
        proxy_pass      http://${APACHE_HTTP};
        proxy_set_header X-Client-IP       \$remote_addr;
        proxy_set_header X-Accel-Internal  /nginx_static_files;
        proxy_set_header Host              \$host;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host  \$host;
        proxy_hide_header Upgrade;
    }

    location ^~ /nginx_static_files/ {
        alias    "${webroot}/";
        internal;
    }

    include /etc/nginx/webapps.conf;
}
CONFEOF

    # HTTPS block — sinh khi ssl=1/on/yes VÀ cert tồn tại
    if is_ssl_on "$has_ssl" && has_ssl_cert "$user" "$cert_domain"; then
        cat << HTTPSEOF

# ── HTTPS ────────────────────────────────────────────────────
server {
    listen 0.0.0.0:443 ssl;
    http2  on;

    server_name ${server_names};

    ssl_certificate     ${ssl_cert};
    ssl_certificate_key ${ssl_key};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    access_log ${access_log} antibot_fmt;
    access_log ${bytes_log} bytes;
    error_log  ${error_log};

    root  "${webroot}";
    index index.php index.html index.htm;

    ssl_client_hello_by_lua_block {
        require("antibot.transport.tls.ja3").capture()
    }
    ssl_certificate_by_lua_block {
        require("antibot.transport.tls.ja3s").capture()
    }

    set \$antibot_debug "0";
    access_by_lua_block {
        require("antibot").run()
    }
    log_by_lua_block { require("antibot").log() }
    header_filter_by_lua_block {
        -- Attack 3 beacon injection — two-phase content-type isolation.
        -- Phase 1 (access): trigger.lua sets inject_candidate based on request Accept header.
        -- Phase 2 (here):   confirm using ACTUAL response Content-Type from Apache.
        -- Only when both conditions are true do we set browser_needed and clear Content-Length.
        -- This guarantees CSS/JS/image responses are NEVER modified.
        local ctx = ngx.ctx.antibot
        if not ctx or not ctx.inject_candidate then return end
        local ct = ngx.header["Content-Type"] or ""
        if not ct:find("text/html", 1, true) then return end
        ctx.browser_needed        = true
        ngx.header.content_length = nil
    }
    body_filter_by_lua_block {
        require("antibot.detection.browser.inject").filter()
    }

$(antibot_locations)
$(static_fastpath)
${mail_loc}
    location / {
        proxy_buffering       off;
        proxy_ssl_server_name on;
        proxy_ssl_name        \$host;
        proxy_ssl_verify      off;
        proxy_pass            https://${APACHE_HTTPS};
        proxy_set_header      X-Client-IP       \$remote_addr;
        proxy_set_header      X-Accel-Internal  /nginx_static_files;
        proxy_set_header      Host              \$host;
        proxy_set_header      X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto https;
        proxy_set_header      X-Forwarded-Host  \$host;
        proxy_hide_header     Upgrade;
    }

    location ^~ /nginx_static_files/ {
        alias    "${webroot}/";
        internal;
    }

    include /etc/nginx/webapps.ssl.conf;
}
HTTPSEOF
    elif is_ssl_on "$has_ssl"; then
        warn "  SSL flag set but cert not found: ${DA_DATA_DIR}/${user}/domains/${cert_domain}.cert.combined"
    fi
}


# ── Write file hoặc dry-run ───────────────────────────────────
write_conf() {
    local user="$1" filename="$2" content="$3"
    local out_dir="${OR_USER_DIR}/${user}/domains"
    local out_file="${out_dir}/${filename}.conf"

    if $DRY_RUN; then
        ok "  [dry] → ${out_file}"
        return 0
    fi

    mkdir -p "$out_dir"
    printf '%s\n' "$content" > "$out_file"
    ok "  → ${out_file}"
}

# ── Process 1 domain ──────────────────────────────────────────
process_domain() {
    local user="$1" domain="$2" server_ip="$3"

    local domain_conf="${DA_DATA_DIR}/${user}/domains/${domain}.conf"
    [ -f "$domain_conf" ] || { warn "  domain.conf not found: $domain_conf"; return 1; }

    local has_ssl
    has_ssl=$(da_get "$domain_conf" "ssl" "0")
    is_ssl_on "$has_ssl" && has_ssl="1" || has_ssl="0"

    # ── Pointers ──────────────────────────────────────────────
    local pointers=()
    while IFS= read -r p; do
        [ -n "$p" ] && pointers+=("$p")
    done < <(get_pointers "$user" "$domain")

    # server_name = domain + www.domain + pointers + www.pointers
    local server_names="${domain} www.${domain}"
    for ptr in "${pointers[@]}"; do
        server_names="${server_names} ${ptr} www.${ptr}"
    done

    info "  domain: ${domain} (ssl=${has_ssl})"
    [ ${#pointers[@]} -gt 0 ] && \
        info "    pointers (added to server_name): ${pointers[*]}"

    # ── Main domain conf ──────────────────────────────────────
    local content
    content=$(generate_conf "$user" "$domain" "" \
                             "$server_names" "$has_ssl" "$domain" "$server_ip")
    write_conf "$user" "$domain" "$content"

    # ── Subdomains ────────────────────────────────────────────
    while IFS= read -r sub; do
        [ -z "$sub" ] && continue

        local fqdn="${sub}.${domain}"

        if [ -n "$FILTER_DOMAIN" ] && \
           [ "$FILTER_DOMAIN" != "$fqdn" ] && \
           [ "$FILTER_DOMAIN" != "$domain" ]; then
            continue
        fi

        local sub_ssl="0"
        local sub_cert_domain="$domain"
        if [ "$has_ssl" = "1" ]; then
            sub_ssl="1"
            if has_ssl_cert "$user" "$fqdn"; then
                sub_cert_domain="$fqdn"
                info "    subdomain: ${fqdn} (ssl, cert riêng)"
            else
                info "    subdomain: ${fqdn} (ssl, cert từ ${domain})"
            fi
        else
            info "    subdomain: ${fqdn} (no ssl)"
        fi

        local sub_content
        sub_content=$(generate_conf "$user" "$fqdn" "$domain" \
                                    "$fqdn" "$sub_ssl" "$sub_cert_domain" "$server_ip")
        write_conf "$user" "$fqdn" "$sub_content"

    done < <(get_subdomains "$user" "$domain")
}

# ── Process 1 user ────────────────────────────────────────────
process_user() {
    local user="$1"
    local domains_list="${DA_DATA_DIR}/${user}/domains.list"
    [ -f "$domains_list" ] || { warn "  domains.list not found: $domains_list"; return 1; }

    local server_ip
    server_ip=$(get_user_ip "$user")
    info "User: ${user} (ip=${server_ip})"

    # Xóa conf cũ trước khi generate mới
    # Tránh conf domain đã xóa còn sót lại gây conflict
    if ! $DRY_RUN; then
        local clean_dir="${OR_USER_DIR}/${user}/domains"
        if [ -d "$clean_dir" ]; then
            rm -f "${clean_dir}"/*.conf
            info "  Cleaned old confs: ${clean_dir}/*.conf"
        fi
    fi

    while IFS= read -r domain || [ -n "$domain" ]; do
        domain="${domain// /}"
        [ -z "$domain" ] && continue

        if [ -n "$FILTER_DOMAIN" ] && \
           [ "$FILTER_DOMAIN" != "$domain" ] && \
           [[ "$FILTER_DOMAIN" != *".${domain}" ]]; then
            continue
        fi

        process_domain "$user" "$domain" "$server_ip"
    done < "$domains_list"
}

# ── Remove conf ───────────────────────────────────────────────
remove_conf() {
    local user="$1" domain="${2:-}"
    if [ -n "$domain" ]; then
        local base="${OR_USER_DIR}/${user}/domains"
        [ -f "${base}/${domain}.conf" ] && \
            rm -f "${base}/${domain}.conf" && ok "Removed: ${domain}.conf"
        for sf in "${base}/"*".${domain}.conf"; do
            [ -f "$sf" ] && rm -f "$sf" && ok "Removed: $(basename "$sf")"
        done
    else
        local d="${OR_USER_DIR}/${user}"
        [ -d "$d" ] && rm -rf "$d" && ok "Removed user dir: $d"
    fi
}

# ── Import known good bots vào Redis ─────────────────────────
import_goodbots() {
    local REDIS_CLI
    REDIS_CLI=$(command -v redis-cli) || { fail "redis-cli not found"; return 1; }

    info "Importing known good bots into Redis goodbot:dns:* ..."

    declare -A BOTS=(
        # Google
        ["googlebot"]="googlebot.com,google.com"
        ["googlebot-image"]="googlebot.com,google.com"
        ["googlebot-video"]="googlebot.com,google.com"
        ["googleother"]="googlebot.com,google.com"
        ["adsbot-google"]="google.com"
        ["adsbot-google-mobile"]="google.com"
        ["apis-google"]="google.com"
        ["google-agent"]="google.com"
        ["google-site-verifier"]="googleusercontent.com,google.com"
        # Microsoft Bing
        ["bingbot"]="search.msn.com"
        # Facebook / Meta
        ["facebookexternalhit"]="tfbnw.net,facebook.com"
        ["facebot"]="tfbnw.net,facebook.com"
        # Apple
        ["applebot"]="applebot.apple.com"
        ["applebot-extended"]="applebot.apple.com"
    )

    for bot in "${!BOTS[@]}"; do
        local suffixes="${BOTS[$bot]}"
        $REDIS_CLI SET "goodbot:dns:${bot}" "$suffixes" > /dev/null
        ok "  goodbot:dns:${bot} = ${suffixes}"
    done

    info "Done. Total: ${#BOTS[@]} bots imported."
}

# ── Install DA event hooks ────────────────────────────────────
install_hooks() {
    local hook_dir="/usr/local/directadmin/scripts/custom"
    mkdir -p "$hook_dir"

    local hooks=(
        "user_create_post.sh"
        "user_destroy_pre.sh"
        "domain_create_post.sh"
        "domain_destroy_pre.sh"
        "subdomain_create_post.sh"
        "subdomain_destroy_pre.sh"
    )

    for hook in "${hooks[@]}"; do
        local hook_file="${hook_dir}/${hook}"
        if [ -f "$hook_file" ]; then
            grep -q "da_to_openresty" "$hook_file" 2>/dev/null && {
                ok "Hook already installed: $hook_file"; continue
            }
        else
            echo '#!/usr/bin/env bash' > "$hook_file"
        fi

        cat >> "$hook_file" << HOOKEOF

# ── AntiBot OpenResty sync ───────────────────────────────────
_ANTIBOT_SCRIPT="${SCRIPT_PATH}"
_ANTIBOT_LOG="/var/log/antibot_sync.log"
_ts() { date '+%Y-%m-%d %H:%M:%S'; }
{
  echo "[\$(_ts)] Hook: ${hook} user=\${username:-} domain=\${domain:-}"
  case "${hook}" in
    user_destroy_pre.sh)
      bash "\$_ANTIBOT_SCRIPT" --user "\${username}" --remove --quiet
      ;;
    domain_destroy_pre.sh)
      bash "\$_ANTIBOT_SCRIPT" --user "\${username}" \
           --domain "\${domain}" --remove --quiet
      ;;
    subdomain_destroy_pre.sh)
      bash "\$_ANTIBOT_SCRIPT" --user "\${username}" \
           --domain "\${subdomain}.\${domain}" --remove --quiet
      ;;
    *)
      _ARGS="--quiet"
      [ -n "\${username:-}" ] && _ARGS="\$_ARGS --user \${username}"
      [ -n "\${domain:-}" ]   && _ARGS="\$_ARGS --domain \${domain}"
      bash "\$_ANTIBOT_SCRIPT" \$_ARGS
      ;;
  esac
  echo "[\$(_ts)] Hook done exit=\$?"
} >> "\$_ANTIBOT_LOG" 2>&1
HOOKEOF

        chmod +x "$hook_file"
        ok "Hook installed: $hook_file"
    done
}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

$DO_REMOVE && { remove_conf "${FILTER_USER}" "${FILTER_DOMAIN:-}"; exit 0; }
$INSTALL_HOOKS && { install_hooks; exit 0; }
$IMPORT_GOODBOTS && { import_goodbots; exit 0; }

$QUIET || {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  DA → OpenResty AntiBot Config Builder  [v4.3.5]"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ -n "$FILTER_USER" ]   && echo "  Filter user  : $FILTER_USER"
    [ -n "$FILTER_DOMAIN" ] && echo "  Filter domain: $FILTER_DOMAIN"
    $DRY_RUN && echo "  Mode: DRY RUN" || echo "  Mode: WRITE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

USERS_OK=0; ERRORS=0

for user_dir in "${DA_DATA_DIR}"/*/; do
    [ -d "$user_dir" ]             || continue
    user=$(basename "$user_dir")
    [ -f "${user_dir}/user.conf" ] || continue
    [ -n "$FILTER_USER" ] && \
    [ "$FILTER_USER" != "$user" ]  && continue

    if process_user "$user"; then
        USERS_OK=$((USERS_OK + 1))
    else
        ERRORS=$((ERRORS + 1))
    fi
done

$QUIET || {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "  Users OK: %-3d | Errors: %d\n" "$USERS_OK" "$ERRORS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

[ "$ERRORS" -gt 0 ] && { fail "Build errors — aborting"; exit 1; }
$DRY_RUN && { $QUIET || ok "Dry run complete"; exit 0; }

$QUIET || { echo ""; info "Testing OpenResty config syntax..."; echo ""; }

if "$OR_BIN" -t 2>&1; then
    $QUIET || {
        echo ""
        echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
        echo -e "${G}  ✓  Syntax OK${N}"
        echo -e "${G}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
        echo ""
    }
    "$OR_BIN" -s reload 2>/dev/null && \
        { $QUIET || ok "OpenResty reloaded"; } || \
        warn "Reload failed — may not be running yet"
    exit 0
else
    echo ""
    echo -e "${R}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "${R}  ✗  Syntax FAILED — NOT reloading${N}"
    echo -e "${R}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""
    echo "  Check: /usr/local/openresty/nginx/logs/error.log"
    echo ""
    exit 1
fi
