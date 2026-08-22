#!/usr/bin/env bash
# ============================================================
# /usr/local/openresty/nginx/conf/scripts/monitor_ip_sync.sh
#
# Đồng bộ dải IP do NHÀ VẬN HÀNH CÔNG BỐ → Redis `mon:<ip>`
# Cron: 17 */12 * * * root bash .../monitor_ip_sync.sh
#       (cài bằng `--install-cron`, xem cuối file)
#
# ─── VÌ SAO CÓ FILE NÀY ─────────────────────────────────────
# Hệ đã có hai tầng danh tính, cả hai đều dựa vào UA TỰ KHAI:
#   S4   — registry + DNS hai chiều  → bỏ qua chấm điểm
#   S2.5 — contact/analyzer attest   → trần `monitor`
# Thiếu tầng thứ ba: nhà vận hành khai danh tính bằng cách
# **công bố danh sách IP**, không nhét gì vào UA. `detection/CLAUDE.md`
# (2026-08-07) đã ghi đây là "lỗ hổng lớn nhất còn lại", nêu đích danh
# OpenAI/Anthropic/Perplexity.
#
# Ca đầu tiên chạm vào nó: công cụ uptime đa điểm. Chúng bắn ~35 điểm
# kiểm tra ĐỒNG THỜI từ 35 subnet với cùng một UA trình duyệt trần —
# về cấu trúc KHÔNG phân biệt được với thăm dò có phối hợp, nên
# `distributed_swarm` (trọng số 120) chặn thẳng. Đo trên cloud28-246
# ngày 2026-08-22: 811 req/giờ = 13,5 req/phút, mà mốc cứng là 35 /24
# trong 60 GIÂY ⇒ lưu lượng tự nhiên không thể chạm; chỉ một chùm bắn
# đồng thời mới tạo ra được. Bộ dò làm đúng việc của nó.
#
# ─── VÌ SAO KHÔNG DÙNG `wl:<ip>` ────────────────────────────
# `core/access/whitelist.lua:161` → `ctx.whitelisted` → `init.lua:162`
# **return ngay**, bỏ qua l7 rate limit, toàn bộ detection, enforcement,
# và cả thống kê. Miễn trừ toàn phần, vĩnh viễn, vô hình.
# `mon:` chỉ đặt TRẦN ở bước cuối: mọi tầng vẫn chạy, vẫn ghi log, vẫn
# ban được nếu IP đó thực sự làm bậy.
#
# ─── VÌ SAO CÓ TTL ──────────────────────────────────────────
# Cron chết / vendor đổi URL / mạng hỏng ⇒ khoá tự hết hạn ⇒ miễn trừ
# biến mất ⇒ hệ về mặc định nghiêm ngặt. FAIL-CLOSED. `wl:` thì ngược
# lại: ghi một lần, sống mãi, và không ai nhớ ra để xoá.
#
# Redis key schema:
#   mon:<ip>          TTL 48h   "1"        (engine.lua đọc, chỉ ở nhánh chặn)
#   mon:src:<name>    TTL 48h   số IP      (để soi nguồn nào đóng bao nhiêu)
#   mon:last_sync     TTL 48h   timestamp
# ============================================================

set -uo pipefail

REDIS_CLI="${REDIS_CLI:-/usr/local/bin/redis-cli}"
[ -x "$REDIS_CLI" ] || REDIS_CLI="$(command -v redis-cli 2>/dev/null || echo /usr/bin/redis-cli)"
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
REDIS_DB="0"

LOG_FILE="/var/log/antibot_monitor_sync.log"
CACHE_DIR="/tmp/antibot_monitor_ips"
LOCK_FILE="/tmp/antibot_monitor_sync.lock"
SCRIPT_PATH="$(readlink -f "$0")"

# TTL 48h với cron 12h ⇒ biên 4 lần. Hụt 3 nhịp cron liên tiếp mới mất
# miễn trừ — đủ rộng để không rớt vì một lần mạng lỗi, đủ hẹp để không
# giữ IP đã rời tay vendor quá hai ngày.
TTL_MON="172800"

# ─── Chặn trên/dưới: cổng an toàn, KHÔNG phải tinh chỉnh ────
# Feed bị chiếm hoặc trả về rác thì không được phép miễn trừ diện rộng.
# Dưới ngưỡng ⇒ tải hỏng. Trên ngưỡng ⇒ nguồn đã đổi bản chất, dừng lại
# cho người xem, đừng tự động nuốt.
MIN_IPS_PER_SRC=10
MAX_IPS_PER_SRC=2000

# ─── Nguồn ──────────────────────────────────────────────────
# name|url   — thêm dòng là thêm vendor, không cần sửa gì khác.
# CHỈ nhận nguồn nào vendor công bố CHÍNH THỨC là "IP của chúng tôi".
# KHÔNG nhận danh sách bên thứ ba tổng hợp lại.
SOURCES=(
    "uptrends|https://app.uptrends.com/Download/DownloadCheckpointServerIpv4"
)
# Mở rộng sau (mỗi cái cần kiểm định dạng trả về trước khi bật):
#   gptbot      https://openai.com/gptbot.json           (JSON, CIDR — cần khai triển)
#   perplexity  https://www.perplexity.com/perplexitybot.json
#   claudebot   https://www.anthropic.com/claudebot.json
# LƯU Ý: ba nguồn trên trả CIDR, mà `engine.lua` khớp IP CHÍNH XÁC.
# Muốn dùng phải khai triển CIDR → IP (dải /24 = 256 khoá) hoặc đổi cách
# đọc bên Lua. Đừng bật cho tới khi giải quyết xong chuyện đó.

ts()    { date '+%Y-%m-%d %H:%M:%S'; }
RCLI()  { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" "$@"; }
RPIPE() { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" --pipe; }
log()   { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
warn()  { echo "[$(ts)] WARN: $*" | tee -a "$LOG_FILE" >&2; }

# ─── Cài cron (file cron nằm ngoài git nên script tự ghi) ───
if [ "${1:-}" = "--install-cron" ]; then
    cat > /etc/cron.d/antibot-monitor-ip <<EOF
# Đồng bộ dải IP nhà vận hành công bố → mon:<ip> (TTL 48h)
# Lệch 17 phút để không đụng giờ tròn của threat_feed_sync.
17 */12 * * * root bash ${SCRIPT_PATH} >> ${LOG_FILE} 2>&1
EOF
    chmod 644 /etc/cron.d/antibot-monitor-ip
    log "Đã cài /etc/cron.d/antibot-monitor-ip"
    exit 0
fi

exec 9>"$LOCK_FILE"
flock -n 9 || { warn "Đang chạy rồi, bỏ qua lượt này"; exit 0; }

mkdir -p "$CACHE_DIR"
log "════════ monitor-ip sync bắt đầu ════════"

total_written=0
sources_ok=0

for entry in "${SOURCES[@]}"; do
    name="${entry%%|*}"
    url="${entry#*|}"
    cache="${CACHE_DIR}/${name}.txt"

    if ! curl -sSf --max-time 30 -o "$cache" "$url" 2>/dev/null; then
        warn "[$name] tải thất bại — GIỮ NGUYÊN khoá cũ, chúng sẽ tự hết hạn"
        continue
    fi

    # Lọc phòng thủ: chỉ nhận IPv4 hợp lệ, loại mọi dải nội bộ/dành riêng.
    # Một feed bị chiếm mà trả về 10.0.0.0 hay 127.0.0.1 thì không được
    # phép biến hạ tầng nội bộ thành vùng miễn trừ.
    mapfile -t ips < <(
        tr -d '\r' < "$cache" \
        | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
        | awk -F. '
            $1>255||$2>255||$3>255||$4>255 { next }          # octet không hợp lệ
            $1==0 || $1==10 || $1==127 || $1>=224 { next }    # this/private/loopback/multicast+
            $1==172 && $2>=16 && $2<=31 { next }              # 172.16/12
            $1==192 && $2==168 { next }                       # 192.168/16
            $1==169 && $2==254 { next }                       # link-local
            $1==100 && $2>=64 && $2<=127 { next }             # CGNAT 100.64/10
            { print }' \
        | sort -u
    )

    n="${#ips[@]}"
    if [ "$n" -lt "$MIN_IPS_PER_SRC" ]; then
        warn "[$name] chỉ $n IP (< $MIN_IPS_PER_SRC) — coi như tải hỏng, KHÔNG ghi"
        continue
    fi
    if [ "$n" -gt "$MAX_IPS_PER_SRC" ]; then
        warn "[$name] tới $n IP (> $MAX_IPS_PER_SRC) — nguồn đã đổi bản chất, DỪNG để người xem"
        continue
    fi

    cmds=""
    for ip in "${ips[@]}"; do
        cmds+="SET mon:${ip} 1 EX ${TTL_MON}\n"
    done
    cmds+="SET mon:src:${name} ${n} EX ${TTL_MON}\n"
    printf "%b" "$cmds" | RPIPE >/dev/null 2>&1

    log "[$name] $n IP → mon:<ip> TTL ${TTL_MON}s"
    total_written=$((total_written + n))
    sources_ok=$((sources_ok + 1))
done

if [ "$sources_ok" -eq 0 ]; then
    warn "KHÔNG nguồn nào thành công — khoá cũ sẽ hết hạn sau ${TTL_MON}s và hệ về mặc định nghiêm ngặt"
    exit 1
fi

RCLI SET mon:last_sync "$(date +%s)" EX "$TTL_MON" >/dev/null 2>&1
log "════════ xong: $total_written IP từ $sources_ok nguồn ════════"
