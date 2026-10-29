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
HEALTH_MAX_AGE="${MONITOR_HEALTH_MAX_AGE:-108000}" # 30h: cron 12h + one missed run

# source | operator-domain | policy | format | min | max expanded IPv4 | URL
# Provider facts live here. Lua policy stays generic: it binds the contact
# domain (or opaque product stem) to the operator domain stored here. `claim`
# requires that binding before a verdict cap; `ipcap` preserves the existing
# uptime-monitor behavior for browser-shaped probes from a published network.
SOURCES=(
    "uptrends|uptrends.com|ipcap|plain_ipv4|10|2000|https://app.uptrends.com/Download/DownloadCheckpointServerIpv4"
    "openai-gptbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/gptbot.json"
    "openai-searchbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/searchbot.json"
    # openai-chatgpt-user GO BO 2026-10-29 -- feed vuot tran, KHONG phai loi cap.
    #
    # Do duoc tren cloud168-105 (health FAIL tu 20-10): feed doi luc
    # creationTime 2026-10-20T17:07:39 va tu do chua sync lai lan nao. 234
    # prefix, tat ca canonical, phan bo `1 x /16 + 233 x /28` -> no ra 69.264
    # dia chi, tran la 65.536. Rieng mot `/16` da bang ca tran. `expand_token`
    # tra 2, `parse_source` bo het, khong ghi gi -- dung nhu thiet ke.
    #
    # VI SAO GO SOURCE chu khong nang tran: `ChatGPT-User` la fetch do NGUOI
    # dung bam trong ChatGPT, khong phai crawler theo lich. Mat dong nay thi
    # cac request do bi tinh diem nhu mot client thuong -- khong ai bi chan
    # oan, chi mat cai `claim` cap verdict. Nang tran thi vua nhan ngan sach
    # khoa Redis +69.264 (dang co 42.795), vua lam cam bien im sau khi no vua
    # bao dung; va neu feed no them lan nua thi lap lai y nguyen.
    #
    # Muon bat lai thi dieu kien la CHINH SACH DAI IP, khong phai con so:
    # chuyen `mon:<ip>` sang so khop DAI (CIDR) o phia Lua. Chi khi do mot
    # `/16` moi thanh 1 ban ghi thay vi 65.536 khoa.
    "openai-adsbot|openai.com|claim|json_prefixes|1|8192|https://openai.com/adsbot.json"
    "anthropic|anthropic.com|claim|json_prefixes|1|8192|https://claude.com/crawling/bots.json"
    "perplexitybot|perplexity.ai|claim|json_prefixes|1|8192|https://www.perplexity.com/perplexitybot.json"
    "perplexity-user|perplexity.ai|claim|json_prefixes|1|8192|https://www.perplexity.com/perplexity-user.json"
)

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log()  { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
warn() { echo "[$(ts)] WARN: $*" | tee -a "$LOG_FILE" >&2; }
alert() {
    warn "$*"
    if [ "${MONITOR_HEALTH_SYSLOG:-1}" = "1" ] && command -v logger >/dev/null 2>&1; then
        command logger -p daemon.err -t antibot-monitor-ip -- "$*" || true
    fi
}

# That bai cua MOT source trong lan sync THAT. Phai len syslog cung tag voi
# `health`, vi neu khong thi journalctl chi co TRIEU CHUNG ma khong bao gio co
# NGUYEN NHAN: `mon:srcsync:<name>` chi duoc ghi khi thanh cong tron ven (sau
# ba cong `continue` ben duoi), nen moi duong that bai deu giu khoa cu toi het
# TTL 48h roi mot/hai ngay sau mo ra duoi dang `health FAIL [...]: stale`.
#
# Do duoc 2026-10-29 (cloud168-105): bon dong `health FAIL [openai-chatgpt-user]
# stale age=128227s` trong journalctl, trong khi ly do thuc -- feed no 69.264
# dia chi vuot tran 65.536 -- chi nam trong /var/log/antibot_monitor_sync.log
# vi no di qua `warn()`. Chan doan mat mot vong do chi vi sai DUONG RA.
#
# IM khi `--validate-sources`: do la lenh chay TAY de kiem feed, va no di qua
# dung ba nhanh nay. Mot lan kiem tay khong duoc sinh `daemon.err` -- neu
# khong thi canh bao that bi lan trong tieng on do chinh operator tao ra.
sfail() {
    if [ "${VALIDATE_ONLY:-0}" -eq 1 ]; then
        warn "$*"
    else
        alert "$*"
    fi
}

ip_to_int() {
    local ip="$1" a b c d extra n
    IFS=. read -r a b c d extra <<< "$ip"
    [ -z "${extra:-}" ] || return 1
    for n in "$a" "$b" "$c" "$d"; do
        # Feed addresses are decimal dotted quads. Reject zero-padded octets
        # instead of silently treating an ambiguous/octal-looking token as
        # decimal (for example 01.02.03.04 -> 1.2.3.4).
        [[ "$n" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
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
    printf '%s\n' '{"prefixes":[{"ipv4Prefix":"01.2.3.4/32"}]}' > "$bad"
    ! parse_source "$bad" json_prefixes "$out" 300 \
        || { rm -rf -- "$td"; return 1; }
    rm -rf -- "$td"
    echo "monitor_ip_sync self-test: OK"
}

health_check() {
    local now failures checked entry name owner policy format min_ips max_ips url
    local sync count age last_sync last_age summary pong
    now="$(date +%s)"
    failures=0
    checked=0
    summary=""

    pong="$(RCLI --raw PING 2>/dev/null || :)"
    if [ "$pong" != "PONG" ]; then
        alert "health FAIL: Redis unavailable at ${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}"
        return 1
    fi

    if ! [[ "$HEALTH_MAX_AGE" =~ ^[0-9]+$ ]] || [ "$HEALTH_MAX_AGE" -lt 43200 ]; then
        alert "health FAIL: invalid MONITOR_HEALTH_MAX_AGE=${HEALTH_MAX_AGE}"
        return 1
    fi

    for entry in "${SOURCES[@]}"; do
        IFS='|' read -r name owner policy format min_ips max_ips url <<< "$entry"
        sync="$(RCLI --raw GET "mon:srcsync:${name}" 2>/dev/null || :)"
        count="$(RCLI --raw GET "mon:src:${name}" 2>/dev/null || :)"

        if ! [[ "$sync" =~ ^[0-9]+$ ]]; then
            alert "health FAIL [$name]: missing/invalid mon:srcsync"
            failures=$((failures + 1))
            continue
        fi
        if [ "$sync" -gt $((now + 300)) ]; then
            alert "health FAIL [$name]: source timestamp is in the future (${sync})"
            failures=$((failures + 1))
            continue
        fi
        age=$((now - sync))
        if [ "$age" -gt "$HEALTH_MAX_AGE" ]; then
            alert "health FAIL [$name]: stale age=${age}s limit=${HEALTH_MAX_AGE}s"
            failures=$((failures + 1))
            continue
        fi
        if ! [[ "$count" =~ ^[0-9]+$ ]] \
           || [ "$count" -lt "$min_ips" ] \
           || [ "$count" -gt "$max_ips" ]; then
            alert "health FAIL [$name]: count=${count:-missing} expected=${min_ips}..${max_ips}"
            failures=$((failures + 1))
            continue
        fi

        checked=$((checked + 1))
        summary="${summary}${name}:${count}/${age}s,"
    done

    last_sync="$(RCLI --raw GET mon:last_sync 2>/dev/null || :)"
    if ! [[ "$last_sync" =~ ^[0-9]+$ ]] \
       || [ "$last_sync" -gt $((now + 300)) ] \
       || [ $((now - last_sync)) -gt "$HEALTH_MAX_AGE" ]; then
        alert "health FAIL: mon:last_sync missing, future, or older than ${HEALTH_MAX_AGE}s"
        failures=$((failures + 1))
    else
        last_age=$((now - last_sync))
    fi

    if [ "$failures" -ne 0 ]; then
        alert "health FAIL: checked=${checked}/${#SOURCES[@]} failures=${failures}"
        return 1
    fi
    log "health OK: checked=${checked}/${#SOURCES[@]} last_age=${last_age}s sources=${summary%,}"
}

# Manual/deploy-time capacity report. This deliberately is not part of the
# six-hour health cron because SCAN walks the complete Redis keyspace. Keep
# exact-IP O(1) lookup until this evidence shows memory/key pressure.
stats_report() {
    local pong dbsize memory_info used used_human dataset scan_counts mon_keys mon_ip_keys
    local source_expanded entry name owner policy format min_ips max_ips url count
    pong="$(RCLI --raw PING 2>/dev/null || :)"
    if [ "$pong" != "PONG" ]; then
        warn "stats unavailable: Redis unavailable at ${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}"
        return 1
    fi

    dbsize="$(RCLI --raw DBSIZE 2>/dev/null || :)"
    memory_info="$(RCLI --raw INFO memory 2>/dev/null | tr -d '\r' || :)"
    used="$(awk -F: '$1=="used_memory" {print $2}' <<< "$memory_info")"
    used_human="$(awk -F: '$1=="used_memory_human" {print $2}' <<< "$memory_info")"
    dataset="$(awk -F: '$1=="used_memory_dataset" {print $2}' <<< "$memory_info")"
    scan_counts="$(RCLI --scan --pattern 'mon:*' 2>/dev/null \
        | awk '{all++} /^mon:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {ip++}
               END {printf "%d %d", all+0, ip+0}')"
    read -r mon_keys mon_ip_keys <<< "$scan_counts"
    source_expanded=0
    for entry in "${SOURCES[@]}"; do
        IFS='|' read -r name owner policy format min_ips max_ips url <<< "$entry"
        count="$(RCLI --raw GET "mon:src:${name}" 2>/dev/null || :)"
        [[ "$count" =~ ^[0-9]+$ ]] && source_expanded=$((source_expanded + count))
    done
    log "stats dbsize=${dbsize:-?} mon_keys=${mon_keys} mon_ip_keys=${mon_ip_keys} source_expanded=${source_expanded} used_memory=${used:-?} used_memory_human=${used_human:-?} used_memory_dataset=${dataset:-?}"
}

integration_test() {
    command -v redis-server >/dev/null 2>&1 || {
        echo "monitor_ip_sync integration-test: SKIP (redis-server missing)" >&2
        return 2
    }
    local td port i oip uip keys oval uval ottl stats_out
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

    run_nested() {
        MONITOR_REDIS_PORT="$port" \
        MONITOR_SYNC_LOG="$td/sync.log" \
        MONITOR_SYNC_CACHE="$td/cache" \
        MONITOR_SYNC_LOCK="$td/lock" \
        MONITOR_HEALTH_SYSLOG=0 \
        REDIS_CLI="$(command -v redis-cli)" \
            bash "$SCRIPT_PATH" "$@"
    }

    run_nested || return 1
    run_nested --health || return 1
    stats_out="$(run_nested --stats)" || return 1
    echo "$stats_out" | grep -q 'mon_ip_keys=' || return 1

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

    # A missing per-source heartbeat must make health fail even while all
    # exact IP keys are still alive under their independent TTL.
    redis-cli -p "$port" DEL mon:srcsync:anthropic >/dev/null
    if run_nested --health >/dev/null 2>&1; then return 1; fi

    # STALE heartbeat is a DIFFERENT branch from a missing one, and it is the
    # branch that matters in production: a feed that silently stops updating
    # leaves every key present, merely old. Deleting the key only exercises the
    # "missing/invalid" test above, so removing the age comparison entirely
    # left the whole suite green — verified by mutation 17-10. Restore the
    # heartbeat with a timestamp older than the limit and require a failure.
    redis-cli -p "$port" SET mon:srcsync:anthropic \
        "$(( $(date +%s) - 200000 ))" >/dev/null
    if run_nested --health >/dev/null 2>&1; then return 1; fi
    # And a fresh heartbeat must pass again, so the check above cannot be
    # satisfied by health failing for some unrelated permanent reason.
    redis-cli -p "$port" SET mon:srcsync:anthropic "$(date +%s)" >/dev/null
    run_nested --health >/dev/null 2>&1 || return 1
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
# Validate all source heartbeats independently between sync runs. Failures are
# written both to the sync log and syslog with tag antibot-monitor-ip.
47 */6 * * * root bash ${SCRIPT_PATH} --health >/dev/null 2>&1
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

if [ "${1:-}" = "--health" ]; then
    health_check
    exit $?
fi

if [ "${1:-}" = "--stats" ]; then
    stats_report
    exit $?
fi

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
        sfail "[$name] download failed; old keys remain until TTL"
        continue
    fi
    if ! parse_source "$cache" "$format" "$parsed" "$max_ips"; then
        sfail "[$name] invalid schema/CIDR or expansion exceeds $max_ips; no write"
        continue
    fi

    n="$(wc -l < "$parsed")"
    if [ "$n" -lt "$min_ips" ] || [ "$n" -gt "$max_ips" ]; then
        sfail "[$name] $n IP outside safety range $min_ips..$max_ips; no write"
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
        sfail "[$name] Redis write failed; old keys remain until TTL"
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
