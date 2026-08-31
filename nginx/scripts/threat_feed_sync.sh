#!/usr/bin/env bash
# ============================================================
# /usr/local/openresty/nginx/conf/scripts/threat_feed_sync.sh
#
# Unified threat intelligence feed sync → Redis
# Cron: 0 * * * * root bash /usr/local/openresty/nginx/conf/scripts/threat_feed_sync.sh
#
# THIẾT KẾ — generalization thay vì enumeration:
#   - IP reputation: 3 source (IPsum, Spamhaus, AbuseIPDB)
#   - ASN classification: 1 source feed (X4BNet) — ~900 ASNs
#     (jhassine gỡ 2026-08-31: file là danh sách CIDR, không phải ASN)
#   - ASN reputation: derive từ classification + threat history
#   - Manual override: chỉ cho local ISP cần exception (Vietnam carriers)
#
# Redis key schema:
#   rep:{ip}              TTL  6h    score 0.0–1.0    (IP reputation)
#   rep:asn:{number}      TTL 24h    score 0.0–1.0    (ASN reputation)
#   asn:type:{number}     TTL 25h    "datacenter|vpn|tor|residential|business"
#   spamhaus:drop         TTL 24h    SET of CIDRs
#   threat:last_sync      TTL 24h    timestamp
#   threat:stats          TTL 24h    JSON metrics
# ============================================================

set -uo pipefail

# ─── Config ───────────────────────────────────────────────────
REDIS_CLI="/usr/local/bin/redis-cli"
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
REDIS_DB="0"

LOG_FILE="/var/log/antibot_threat_sync.log"
CACHE_DIR="/tmp/antibot_feeds"
LOCK_FILE="/tmp/antibot_threat_sync.lock"

# Score (0.0 = trust, 1.0 = bad)
SCORE_IPSUM_L3="0.70"      # IPsum level 3+: confirmed malicious
SCORE_IPSUM_L4="0.85"      # IPsum level 4+: very high confidence
SCORE_ASN_HOST="0.45"      # Datacenter ASN: elevated suspicion
SCORE_ASN_BAD="0.75"       # Known abuse / VPN ASN

# AbuseIPDB optional API key
ABUSEIPDB_KEY="${ABUSEIPDB_KEY:-}"

# TTL
TTL_IP="21600"             # 6h
TTL_ASN="86400"            # 24h
TTL_ASN_TYPE="90000"       # 25h (margin > cron interval)

# Feed URLs
URL_IPSUM="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
URL_SPAMHAUS_DROP="https://www.spamhaus.org/drop/drop.txt"
URL_X4BNET_DC_ASN="https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt"
URL_X4BNET_VPN_ASN="https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/vpn/ASN.txt"
# URL_JHASSINE_DC gỡ 2026-08-31 — file là danh sách CIDR, không phải ASN

# ─── Manual override — VN consumer ISPs (force "residential") ─
# Generalization principle: chỉ override khi feed comprehensive
# CÓ THỂ liệt kê sai (vd Viettel có cloud arm bị tag datacenter
# nhưng phần lớn IP vẫn là residential mobile/FTTH).
#
# Coverage ~95% user VN consumer traffic (FTTH + mobile + cable).
# Mỗi ASN tag residential → ip_score 0.0 → không penalty user thật.
MANUAL_OVERRIDE_RESIDENTIAL=(
    # Top 4 ISPs (>90% market)
    24086    # Viettel Group (FTTH + corporate)
    45899    # VNPT (FTTH)
    18403    # FPT Telecom (FTTH)
    7552     # Viettel Mobile (4G/5G)
    # Tier 2 telco
    131429   # Mobifone (4G/5G)
    7643     # VNPT (legacy IPv4 block)
    24492    # CMC Telecom (consumer side; CMC Cloud có ASN riêng)
    137970   # Gtel Mobile (Gmobile / Beeline VN)
    133267   # Hanoi Telecom (Vietnamobile mobile)
    133741   # Hanoi Telecom (HTC FTTH)
    # Cable TV / regional broadband
    45903    # SCTV — Saigontourist Cable Television
    132167   # Hanoi Cable TV
    45543    # Saigontel
    # Smaller/legacy ISPs
    45494    # NetNam Corporation
    23899    # NETNAM (legacy block)
    132045   # CMC Saigon (consumer)
    134715   # Indochina Telecom
)

# ─── VN datacenter allowlist — KHÔNG override residential ─────
# Lý do tồn tại list này: feed (X4BNet/jhassine) tag đúng các
# datacenter này là "datacenter", nhưng nếu admin lỡ thêm nhầm
# ASN vào MANUAL_OVERRIDE_RESIDENTIAL → user thật bị tag dc và
# ngược lại. List này guard chống lẫn lộn 2 chiều:
#   1. Đảm bảo VN datacenter LUÔN có asn:type=datacenter
#      (kể cả khi feed bỏ sót)
#   2. Skip residential override nếu trùng với list này
VN_DATACENTER_ASNS=(
    38731    # Viettel IDC
    133571   # VNPT IDC (Net2E)
    45905    # Vietnix
    135905   # Bizfly Cloud (VCCorp)
    138388   # FPT Smart Cloud
    63956    # OdiCloud / Inet
)

# ─── Helpers ──────────────────────────────────────────────────
RC()    { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" "$@"; }
RPIPE() { "$REDIS_CLI" -h "$REDIS_HOST" -p "$REDIS_PORT" -n "$REDIS_DB" --pipe; }
ts()    { date '+%Y-%m-%d %H:%M:%S'; }
log()   { echo "[$(ts)] $*" | tee -a "$LOG_FILE"; }
warn()  { echo "[$(ts)] WARN $*" | tee -a "$LOG_FILE" >&2; }

# ─── Lock ─────────────────────────────────────────────────────
exec 9>"$LOCK_FILE"
flock -n 9 || { warn "Already running, skipping"; exit 0; }

mkdir -p "$CACHE_DIR"
log "════════ Threat feed sync started ════════"

TOTAL_IP=0; TOTAL_ASN_REP=0; TOTAL_ASN_TYPE=0

# ============================================================
# FEED 1: IPsum — IP-level reputation
# ============================================================
sync_ipsum() {
    log "→ Fetching IPsum..."
    local cache="${CACHE_DIR}/ipsum.txt"

    if ! curl -sSf --max-time 30 -o "$cache" "$URL_IPSUM" 2>/dev/null; then
        warn "IPsum fetch failed"
        return 1
    fi

    local count=0
    local pipeline_cmds=""

    while IFS=$'\t' read -r ip level; do
        [[ "$ip" =~ ^# ]] && continue
        [[ -z "$ip" ]] && continue
        level="${level:-0}"

        local score
        if [ "$level" -ge 4 ] 2>/dev/null; then
            score="$SCORE_IPSUM_L4"
        else
            score="$SCORE_IPSUM_L3"
        fi

        pipeline_cmds+="SET rep:${ip} ${score} EX ${TTL_IP}\n"
        count=$((count + 1))

        if [ $((count % 500)) -eq 0 ]; then
            printf "%b" "$pipeline_cmds" | RPIPE >/dev/null 2>&1
            pipeline_cmds=""
        fi
    done < <(grep -v '^#' "$cache")

    [ -n "$pipeline_cmds" ] && printf "%b" "$pipeline_cmds" | RPIPE >/dev/null 2>&1

    TOTAL_IP=$((TOTAL_IP + count))
    log "  IPsum: $count IPs"
}

# ============================================================
# FEED 2: Spamhaus DROP — bad CIDR ranges
# ============================================================
sync_spamhaus() {
    log "→ Fetching Spamhaus DROP..."
    local cache="${CACHE_DIR}/spamhaus_drop.txt"

    if ! curl -sSf --max-time 30 -o "$cache" "$URL_SPAMHAUS_DROP" 2>/dev/null; then
        warn "Spamhaus fetch failed"
        return 1
    fi

    RC DEL "spamhaus:drop" >/dev/null 2>&1
    local count=0

    while IFS= read -r line; do
        line="${line%%;*}"
        line="${line// /}"
        [[ -z "$line" ]] && continue
        RC SADD "spamhaus:drop" "$line" >/dev/null 2>&1
        count=$((count + 1))
    done < "$cache"

    RC EXPIRE "spamhaus:drop" "$TTL_ASN" >/dev/null 2>&1
    log "  Spamhaus: $count CIDRs"
}

# ============================================================
# FEED 3: ASN Classification (general approach)
#
# Source 1: X4BNet/lists_vpn — actively maintained
#   - datacenter Asn.list:  ~1500 ASN
#   - vpn Asn.list:         ~50 ASN
#
# (Source 2 jhassine ĐÃ GỠ — xem chú thích trong sync_asn_classification)
#
# Tổng: ~900 ASN được phân loại
# ============================================================
# Số ASN cao nhất IANA đã cấp phát (2026). Mọi giá trị ngoài [1, ASN_MAX] là
# rác parse, không phải ASN.
#
# 2026-08-31 — VÌ SAO CÓ HÀM NÀY. Nguồn jhassine `datacenters.csv` được nạp bằng
# `asn="${asn//[!0-9]/}"` (bóc mọi ký tự không phải số) dựa trên chú thích
# `Format: asn,name,domain,cidr_count`. Chú thích SAI: cột đầu là CIDR.
#     "1.178.1.0/24","1.178.1.0","1.178.1.255","AWS"  →  11781024
# 52.859 dòng ⇒ 52.859 khoá `rep:asn:` + `asn:type:` rác mỗi lần chạy sạch.
# Đo 2026-08-31: Redis có 53.761 khoá `rep:asn:`, **52.918 (98,4%) ngoài dải** —
# trong khi script tự báo `asn_rep=928`. Hai hậu quả:
#   1. `DBSIZE` phình ~105k ⇒ vượt trần SCAN của admin ⇒ ba máy cùng dữ liệu
#      hiện ba danh sách Good Bot khác nhau (18/17/15 trên tổng 41).
#   2. CIDR ngắn bóc ra vẫn LỌT dải hợp lệ ("1.0.4.0/22" → 104022) ⇒ gán
#      `rep:asn:=0.45` cho một ASN vô tội ⇒ +15,75 điểm thô oan, âm thầm.
# Nguồn jhassine đã gỡ (xem chỗ nó từng nằm). Hàm này là chốt chặn cho các
# nguồn CÒN LẠI: X4BNet hôm nay sạch, nhưng nó đổi định dạng lúc nào cũng được
# — đúng như jhassine đã đổi — và khi đó phải hỏng ỒN ÀO, không âm thầm.
ASN_MAX=401308
asn_valid() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le "$ASN_MAX" ]; }

sync_asn_classification() {
    log "→ Syncing ASN classification..."
    local count_dc=0
    local count_vpn=0
    local count_residential=0
    local count_bad=0          # dòng bị loại vì ngoài dải — PHẢI log ra
    local pipeline_cmds=""

    # ── X4BNet datacenter ASNs ──────────────────────────────
    local cache_dc="${CACHE_DIR}/x4bnet_dc_asn.txt"
    if curl -sSf --max-time 30 -o "$cache_dc" "$URL_X4BNET_DC_ASN" 2>/dev/null; then
        while IFS= read -r asn; do
            asn="${asn//[!0-9]/}"   # strip non-digit
            [[ -z "$asn" ]] && continue
            if ! asn_valid "$asn"; then count_bad=$((count_bad + 1)); continue; fi
            pipeline_cmds+="SET asn:type:${asn} datacenter EX ${TTL_ASN_TYPE}\n"
            pipeline_cmds+="SET rep:asn:${asn} ${SCORE_ASN_HOST} EX ${TTL_ASN}\n"
            count_dc=$((count_dc + 1))
        done < "$cache_dc"
        log "  X4BNet datacenter: $count_dc ASNs"
    else
        warn "X4BNet datacenter fetch failed"
    fi

    # ── X4BNet VPN ASNs ─────────────────────────────────────
    local cache_vpn="${CACHE_DIR}/x4bnet_vpn_asn.txt"
    if curl -sSf --max-time 30 -o "$cache_vpn" "$URL_X4BNET_VPN_ASN" 2>/dev/null; then
        while IFS= read -r asn; do
            asn="${asn//[!0-9]/}"
            [[ -z "$asn" ]] && continue
            if ! asn_valid "$asn"; then count_bad=$((count_bad + 1)); continue; fi
            pipeline_cmds+="SET asn:type:${asn} vpn EX ${TTL_ASN_TYPE}\n"
            pipeline_cmds+="SET rep:asn:${asn} ${SCORE_ASN_BAD} EX ${TTL_ASN}\n"
            count_vpn=$((count_vpn + 1))
        done < "$cache_vpn"
        log "  X4BNet VPN: $count_vpn ASNs"
    else
        warn "X4BNet VPN fetch failed"
    fi

    # ── nguồn jhassine ĐÃ GỠ (2026-08-31) — ĐỪNG THÊM LẠI ──
    # `server-ip-addresses/data/datacenters.csv` KHÔNG phải danh sách ASN. Chú
    # thích cũ ghi `Format: asn,name,domain,cidr_count`; định dạng thật là:
    #     "1.178.1.0/24","1.178.1.0","1.178.1.255","AWS"
    # Cột đầu là CIDR. Qua `${asn//[!0-9]/}` nó thành `11781024`. 52.859 dòng ⇒
    # 52.859 khoá rác mỗi lần chạy trên Redis sạch.
    #
    # Lọc dải KHÔNG cứu được nguồn này: mọi dòng đều là CIDR nên sau khi lọc nó
    # đóng góp ĐÚNG 0 ASN, chỉ khác là vẫn đốt 52.859 lệnh `GET` mỗi giờ. Đo
    # 2026-08-31 trên cloud168-117: riêng vòng lặp này **4 phút 19 giây** để rồi
    # báo "0 additional ASNs" — số 0 đó không phải nguồn cạn, mà là guard
    # `existing` gặp lại chính đám rác nó ghi ra lần trước.
    #
    # Muốn dùng dữ liệu này thì phải khớp theo DẢI IP, không phải theo ASN — tức
    # một cơ chế khác hẳn (`rep:ip:` hoặc CIDR match), không phải sửa vòng lặp.

    # ── VN datacenter allowlist — explicit datacenter tag ──
    # Force tag để feed-miss không làm Bizfly/FPT Cloud rơi vào
    # "unknown" → mặc định residential trong ip_classify.lua.
    declare -A VN_DC_SET=()
    local count_vn_dc=0
    for asn in "${VN_DATACENTER_ASNS[@]}"; do
        VN_DC_SET[$asn]=1
        pipeline_cmds+="SET asn:type:${asn} datacenter EX ${TTL_ASN_TYPE}\n"
        pipeline_cmds+="SET rep:asn:${asn} ${SCORE_ASN_HOST} EX ${TTL_ASN}\n"
        count_vn_dc=$((count_vn_dc + 1))
    done
    log "  VN datacenter allowlist: $count_vn_dc ASNs"

    # ── Manual override — VN consumer ISPs FORCE residential ─
    # Override AFTER feed sync để chắc chắn priority cao hơn.
    # Consumer ISPs có thể bị X4BNet/jhassine tag nhầm datacenter
    # vì có cloud arm, nhưng phần lớn IP vẫn là residential FTTH/mobile.
    # Guard: nếu ASN trùng VN_DATACENTER_ASNS (config sai) → skip.
    for asn in "${MANUAL_OVERRIDE_RESIDENTIAL[@]}"; do
        if [[ -n "${VN_DC_SET[$asn]:-}" ]]; then
            warn "ASN ${asn} in both residential and datacenter lists — keeping datacenter"
            continue
        fi
        pipeline_cmds+="SET asn:type:${asn} residential EX ${TTL_ASN_TYPE}\n"
        pipeline_cmds+="DEL rep:asn:${asn}\n"   # xóa rep score nếu có
        count_residential=$((count_residential + 1))
    done
    log "  Manual override residential: $count_residential ASNs (VN consumer ISPs)"

    # Flush pipeline
    printf "%b" "$pipeline_cmds" | RPIPE >/dev/null 2>&1

    TOTAL_ASN_REP=$((count_dc + count_vpn + count_vn_dc))
    TOTAL_ASN_TYPE=$((count_dc + count_vpn + count_vn_dc + count_residential))
    log "  ASN total: type=$TOTAL_ASN_TYPE rep=$TOTAL_ASN_REP  (loại ngoài dải: $count_bad)"
    [ "$count_bad" -gt 0 ] && warn "$count_bad dòng ngoài dải ASN — nguồn có thể đã đổi định dạng, KIỂM NGAY"
}

# ============================================================
# FEED 4: AbuseIPDB enrichment (optional, requires API key)
# ============================================================
sync_abuseipdb() {
    [ -z "$ABUSEIPDB_KEY" ] && return 0

    log "→ AbuseIPDB enrichment..."
    local log_dir="/var/log/nginx/domains"
    local count=0
    local limit=200

    [ ! -d "$log_dir" ] && return 0

    local recent_ips
    recent_ips=$(find "$log_dir" -name "*.log" -newer "${CACHE_DIR}/.last_abuseipdb" 2>/dev/null \
        | head -5 \
        | xargs grep -h "action=monitor\|action=challenge\|action=block" 2>/dev/null \
        | awk '{print $1}' | sort -u | head "$limit")

    touch "${CACHE_DIR}/.last_abuseipdb"

    while IFS= read -r ip; do
        [ -z "$ip" ] && continue
        local existing
        existing=$(RC TTL "rep:${ip}" 2>/dev/null)
        [ "${existing:-0}" -gt 10800 ] && continue

        local resp
        resp=$(curl -sSf --max-time 5 \
            -H "Key: ${ABUSEIPDB_KEY}" \
            -H "Accept: application/json" \
            "https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=30" \
            2>/dev/null)

        local abuse_score
        abuse_score=$(echo "$resp" | grep -oP '"abuseConfidenceScore":\K[0-9]+' || echo "0")

        if [ "${abuse_score:-0}" -ge 50 ]; then
            local redis_score
            redis_score=$(awk "BEGIN{printf \"%.2f\", 0.5 + ${abuse_score}/200}")
            RC SET "rep:${ip}" "$redis_score" EX "$TTL_IP" >/dev/null 2>&1
            count=$((count + 1))
        fi
    done <<< "$recent_ips"

    TOTAL_IP=$((TOTAL_IP + count))
    log "  AbuseIPDB: $count IPs enriched"
}

# ============================================================
# MAIN
# ============================================================

# Test Redis
if ! RC PING >/dev/null 2>&1; then
    log "ERROR: Cannot connect to Redis at ${REDIS_HOST}:${REDIS_PORT}"
    exit 1
fi

sync_ipsum
sync_spamhaus
sync_asn_classification
sync_abuseipdb

# Stats
RC SET "threat:last_sync" "$(ts)" EX 86400 >/dev/null 2>&1
RC SET "threat:stats" \
    "{\"ip\":${TOTAL_IP},\"asn_rep\":${TOTAL_ASN_REP},\"asn_type\":${TOTAL_ASN_TYPE},\"ts\":\"$(ts)\"}" \
    EX 86400 >/dev/null 2>&1

log "════════ Sync complete: ip=$TOTAL_IP asn_rep=$TOTAL_ASN_REP asn_type=$TOTAL_ASN_TYPE ════════"
