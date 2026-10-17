#!/usr/bin/env bash
# Synchronize operator-published IPv4 ranges to Redis `mon:<ip>`.
#
# Contract:
#   mon:<ip>                 TTL 48h  policy@operator-domain
#   mon:src:<source>         TTL 48h  expanded public IPv4 count
#   mon:srcsync:<source>     TTL 48h  last successful source timestamp
#   mon:last_sync            TTL 48h  last run with at least one good source
#
# Lua still runs all detection/scoring. A matching automation identity may be
# tagged as operator-network verified, and a final block/challenge is capped at
# monitor. Published network evidence never creates `wl:` or S4 goodbot trust.

set -uo pipefail
umask 077

REDIS_CLI="${REDIS_CLI:-/usr/local/bin/redis-cli}"
[ -x "$REDIS_CLI" ] || REDIS_CLI="$(command -v redis-cli 2>/dev/null || echo /usr/bin/redis-cli)"
REDIS_HOST="${MONITOR_REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${MONITOR_REDIS_PORT:-6379}"
REDIS_DB="${MONITOR_REDIS_DB:-0}"

LOG_FILE="${MONITOR_SYNC_LOG:-/var/log/antibot_monitor_sync.log}"
CACHE_DIR="${MONITOR_SYNC_CACHE:-/tmp/antibot_monitor_ips}"
LOCK_FILE="${MONITOR_SYNC_LOCK:-/tmp/antibot_monitor_sync.lock}"
SCRIPT_PATH="$(readlink -f "$0")"
TTL_MON="${MONITOR_TTL:-172800}"

# source | operator-domain | policy | format | min | max expanded IPv4 | URL
# Provider facts live here. Lua policy stays generic: it binds the contact
# domain (or opaque product stem) to the operator domain stored here. `claim`
# requires that binding before a verdict cap; `ipcap` preserves the existing
# uptime-monitor behavior for browser-shaped probes from a published network.
SOURCES=(
    "uptrends|uptrends.com|ipcap|plain_ipv4|10|2000|https://app.uptrends.com/Download/DownloadCheckpointServerIpv4"
    "openai-gptbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/gptbot.json"
    "openai-searchbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/searchbot.json"
    "openai-chatgpt-user|openai.com|claim|json_prefixes|1|65536|https://openai.com/chatgpt-user.json"
    "openai-adsbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/adsbot.json"
    "anthropic|anthropic.com|claim|json_prefixes|1|8192|https://claude.com/crawling/bots.json"
    "perplexitybot|perplexity.ai|claim|json_prefixes|1|8192|https://www.perplexity.com/perplexitybot.json"
    "perplexity-user|perplexity.ai|claim|json_prefixes|1|8192|https://www.perplexity.com/perplexity-user.json"
)

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
warn() { echo "[$(ts)] WARN: $*" | tee -a "$LOG_FILE" >&2; }

ip_to_int() {
    local ip="$1" a b c d extra n
    IFS=. read -r a b c d extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for n in "$a" "$b" "$c" "$d"; do
        [[ "$n" =~ ^[0-9]{1,3}$ ]] || return 1
        [ "$((10#$n))" -le 255 ] || return 1
    done
    printf '%u' "$(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))"
}

int_to_ip() {
    local n="$1"
    printf '%d.%d.%d.%d\n' \
        "$(( (n >> 24) & 255 ))" "$(( (n >> 16) & 255 ))" \
        "$(( (n >> 8) & 255 ))"  "$(( n & 255 ))"
}

# Global counter is reset by parse_source. The caller supplies a hard cap so a
# compromised feed cannot expand a huge CIDR into Redis keys.
PARSED_EXPANDED=0
expand_token() {
    local token="$1" out="$2" hard_max="$3"
    local base prefix n size network i
    if [[ "$token" == */* ]]; then
        base="${token%/*}"; prefix="${token##*/}"
    else
        base="$token"; prefix=32
    fi
    [[ "$prefix" =~ ^[0-9]{1,2}$ ]] || return 1
    [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ] || return 1
    n="$(ip_to_int "$base")" || return 1
    size=$(( 1 << (32 - prefix) ))
    network=$(( (n / size) * size ))
    # Reject malformed/non-canonical prefixes instead of silently normalizing.
    [ "$network" -eq "$n" ] || return 1
    [ $((PARSED_EXPANDED + size)) -le "$hard_max" ] || return 2
    PARSED_EXPANDED=$((PARSED_EXPANDED + size))
    for ((i=0; i<size; i++)); do int_to_ip $((network + i)); done >> "$out"
}

filter_public_ipv4() {
    awk -F. '
        NF != 4 { next }
        $1==0 || $1==10 || $1==127 || $1>=224 { next }
        $1==100 && $2>=64 && $2<=127 { next }
        $1==169 && $2==254 { next }
        $1==172 && $2>=16 && $2<=31 { next }
        $1==192 && $2==168 { next }
        $1==192 && $2==0 && $3==2 { next }
        $1==198 && ($2==18 || $2==19) { next }
        $1==198 && $2==51 && $3==100 { next }
        $1==203 && $2==0 && $3==113 { next }
        { print }
    '
}

parse_source() {
    local input="$1" format="$2" output="$3" hard_max="$4"
    local raw="${output}.raw.$$" token rc
    local -a tokens=()
    : > "$raw"
    PARSED_EXPANDED=0

    case "$format" in
        plain_ipv4)
            mapfile -t tokens < <(
                tr -d '\r' < "$input" \
                | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
                | sort -u || :
            )
            ;;
        json_prefixes)
            # Read only the documented field, not arbitrary IPv4-looking text
            # elsewhere in a JSON/HTML response.
            mapfile -t tokens < <(
                tr -d '\r\n' < "$input" \
                | grep -oE '"ipv4Prefix"[[:space:]]*:[[:space:]]*"([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?"' \
                | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
                | sort -u || :
            )
            ;;
        *) rm -f -- "$raw"; return 1 ;;
    esac

    [ "${#tokens[@]}" -gt 0 ] || { rm -f -- "$raw"; return 1; }
    for token in "${tokens[@]}"; do
        expand_token "$token" "$raw" "$hard_max"
        rc=$?
        if [ "$rc" -ne 0 ]; then rm -f -- "$raw"; return "$rc"; fi
    done
    filter_public_ipv4 < "$raw" | sort -u > "$output"
    rm -f -- "$raw"
    [ -s "$output" ]
}

self_test() {
    local td json out bad
    td="$(mktemp -d)" || return 1
    json="$td/feed.json"; out="$td/out"; bad="$td/bad.json"
    printf '%s\n' '{"prefixes":[{"ipv4Prefix":"8.8.8.0/30"},{"ipv4Prefix":"1.1.1.1/32"},{"ipv4Prefix":"10.0.0.0/24"}]}' > "$json"
    parse_source "$json" json_prefixes "$out" 300 || { rm -rf -- "$td"; return 1; }
    [ "$(wc -l < "$out")" -eq 5 ] || { rm -rf -- "$td"; return 1; }
    grep -qx '8.8.8.3' "$out" || { rm -rf -- "$td"; return 1; }
    ! grep -q '^10\.' "$out" || { rm -rf -- "$td"; return 1; }

    printf '%s\n' '{"prefixes":[{"ipv4Prefix":"8.8.8.1/24"}]}' > "$bad"
    ! parse_source "$bad" json_prefixes "$out" 300 \
        || { rm -rf -- "$td"; return 1; }
    printf '%s\n' '{"prefixes":[{"ipv4Prefix":"8.8.0.0/16"}]}' > "$bad"
    ! parse_source "$bad" json_prefixes "$out" 300 \
        || { rm -rf -- "$td"; return 1; }
    rm -rf -- "$td"
    echo "monitor_ip_sync self-test: OK"
}

integration_test() {
    command -v redis-server >/dev/null 2>&1 || {
        echo "monitor_ip_sync integration-test: SKIP (redis-server missing)" >&2
        return 2
    }
    local td port i oip uip keys oval uval ottl
    td="$(mktemp -d)" || return 1
    port=$((20000 + ($$ % 10000)))
    cleanup_integration() {
        redis-cli -p "$port" shutdown nosave >/dev/null 2>&1 || true
        rm -rf -- "$td"
    }
    trap cleanup_integration EXIT INT TERM

    redis-server --port "$port" --bind 127.0.0.1 --save "" \
        --appendonly no --daemonize yes --dir "$td" --pidfile "$td/redis.pid"
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ "$(redis-cli -p "$port" ping 2>/dev/null)" = "PONG" ] && break
        sleep 0.1
    done
    [ "$(redis-cli -p "$port" ping 2>/dev/null)" = "PONG" ] || return 1

    MONITOR_REDIS_PORT="$port" \
    MONITOR_SYNC_LOG="$td/sync.log" \
    MONITOR_SYNC_CACHE="$td/cache" \
    MONITOR_SYNC_LOCK="$td/lock" \
    REDIS_CLI="$(command -v redis-cli)" \
        bash "$SCRIPT_PATH"

    oip="$(head -1 "$td/cache/openai-chatgpt-user.ips")"
    uip="$(head -1 "$td/cache/uptrends.ips")"
    oval="$(redis-cli -p "$port" --raw get "mon:$oip")"
    uval="$(redis-cli -p "$port" --raw get "mon:$uip")"
    ottl="$(redis-cli -p "$port" ttl "mon:$oip")"
    keys="$(redis-cli -p "$port" --scan --pattern 'mon:*' | wc -l)"

    [ "$oval" = "claim@openai.com" ] || return 1
    [ "$uval" = "ipcap@uptrends.com" ] || return 1
    [ "$ottl" -gt 0 ] || return 1
    [ "$keys" -gt 40000 ] || return 1
    printf 'monitor_ip_sync integration-test: OK keys=%s openai=%s uptrends=%s ttl=%s\n' \
        "$keys" "$oval" "$uval" "$ottl"

    cleanup_integration
    trap - EXIT INT TERM
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
fi

if [ "${1:-}" = "--integration-test" ]; then
    integration_test
    exit $?
fi

if [ "${1:-}" = "--install-cron" ]; then
    cat > /etc/cron.d/antibot-monitor-ip <<EOF
# Refresh officially published operator IPv4 ranges; keys fail strict by TTL.
# The script already appends through log()/warn(); redirecting to the same file
# here would duplicate every line.
17 */12 * * * root bash ${SCRIPT_PATH} >/dev/null 2>&1
EOF
    chmod 0644 /etc/cron.d/antibot-monitor-ip
    log "installed /etc/cron.d/antibot-monitor-ip"
    exit 0
fi

VALIDATE_ONLY=0
[ "${1:-}" = "--validate-sources" ] && VALIDATE_ONLY=1

REDIS_PASS="${ANTIBOT_REDIS_PASS:-}"
if [ -z "$REDIS_PASS" ]; then
    _pwf="${ANTIBOT_REDIS_PASS_FILE:-/etc/antibot/redis.pass}"
    [ -r "$_pwf" ] && REDIS_PASS="$(head -1 "$_pwf" 2>/dev/null | tr -d '\r\n')"
fi
RAUTH=()
[ -n "$REDIS_PASS" ] && RAUTH=(--no-auth-warning -a "$REDIS_PASS")
RCLI()  { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" "${RAUTH[@]}" "$@"; }
RPIPE() { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" "${RAUTH[@]}" --pipe; }

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "already running; skip"; exit 0; }
mkdir -p "$CACHE_DIR"
log "monitor-ip sync start"

total_written=0
sources_ok=0
for entry in "${SOURCES[@]}"; do
    IFS='|' read -r name owner policy format min_ips max_ips url <<< "$entry"
    cache="${CACHE_DIR}/${name}.download"
    parsed="${CACHE_DIR}/${name}.ips"

    if ! curl -fsSL --proto '=https' --tlsv1.2 --max-redirs 3 \
        --connect-timeout 10 --max-time 30 -o "$cache" "$url" 2>/dev/null; then
        warn "[$name] download failed; old keys remain until TTL"
        continue
    fi
    if ! parse_source "$cache" "$format" "$parsed" "$max_ips"; then
        warn "[$name] invalid schema/CIDR or expansion exceeds $max_ips; no write"
        continue
    fi

    n="$(wc -l < "$parsed")"
    if [ "$n" -lt "$min_ips" ] || [ "$n" -gt "$max_ips" ]; then
        warn "[$name] $n IP outside safety range $min_ips..$max_ips; no write"
        continue
    fi

    if [ "$VALIDATE_ONLY" -eq 1 ]; then
        log "[$name] valid: $n public IPv4 policy=$policy owner=$owner"
        total_written=$((total_written + n))
        sources_ok=$((sources_ok + 1))
        continue
    fi

    pipe_out="$({
        while IFS= read -r ip; do
            printf 'SET mon:%s %s@%s EX %s\n' "$ip" "$policy" "$owner" "$TTL_MON"
        done < "$parsed"
        printf 'SET mon:src:%s %s EX %s\n' "$name" "$n" "$TTL_MON"
        printf 'SET mon:srcsync:%s %s EX %s\n' "$name" "$(date +%s)" "$TTL_MON"
    } | RPIPE 2>&1)"
    if [ $? -ne 0 ] || echo "$pipe_out" | grep -qE 'errors: [1-9]|NOAUTH|ERR '; then
        warn "[$name] Redis write failed; old keys remain until TTL"
        continue
    fi

    log "[$name] $n public IPv4 -> mon:<ip> policy=$policy owner=$owner TTL=${TTL_MON}s"
    total_written=$((total_written + n))
    sources_ok=$((sources_ok + 1))
done

if [ "$sources_ok" -eq 0 ]; then
    warn "no source succeeded; old keys expire after ${TTL_MON}s (fail strict)"
    exit 1
fi

if [ "$VALIDATE_ONLY" -eq 1 ]; then
    log "source validation done: $total_written IP from $sources_ok sources"
    exit 0
fi

if ! RCLI SET mon:last_sync "$(date +%s)" EX "$TTL_MON" >/dev/null 2>&1; then
    warn "could not update mon:last_sync"
    exit 1
fi
log "monitor-ip sync done: $total_written IP from $sources_ok sources"
