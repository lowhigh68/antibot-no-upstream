#!/bin/bash
# Read-only query-churn distribution report from current and rotated logs.
# ASCII-only on purpose: this file is deployed across mixed locales.

set -euo pipefail

LOGDIR=${1:-/var/log/antibot}
MARK=${2:-/etc/antibot/qch.deploy_ts}

die() {
    echo "QCHSTAT_ERROR $*" >&2
    exit 2
}

[ -d "$LOGDIR" ] || die "log directory not found: $LOGDIR"
[ -r "$MARK" ] || die "marker not readable: $MARK"

SINCE=$(tr -d '[:space:]' < "$MARK")
case "$SINCE" in
    ''|*[!0-9]*) die "marker is not an epoch: $SINCE" ;;
esac

UNTIL=$(date +%s)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/qchstat.XXXXXX")
DATA="$TMP/rows.tsv"
META="$TMP/meta"
trap 'rm -f -- "$DATA" "$META" "$TMP/page" "$TMP/application" "$TMP/actor" "$TMP/first_party" "$TMP/slow"; rmdir -- "$TMP" 2>/dev/null || true' EXIT HUP INT TERM

list_logs() {
    find "$LOGDIR" -maxdepth 1 -type f -name 'antibot.log*' \
        -newermt "@$SINCE" -print0 | sort -z
}

emit_logs() {
    local file
    while IFS= read -r -d '' file; do
        case "$file" in
            *.gz) gzip -cd -- "$file" ;;
            *)    cat -- "$file" ;;
        esac
    done < <(list_logs)
}

emit_logs | LC_ALL=C awk -v since="$SINCE" -v until="$UNTIL" \
    -v meta="$META" '
function getv(name) { return (name in field) ? field[name] : "-" }
{
    for (key in field) delete field[key]
    for (i = 1; i <= NF; i++) {
        pos = index($i, "=")
        if (pos > 1) {
            key = substr($i, 1, pos - 1)
            if (!(key in field)) field[key] = substr($i, pos + 1)
        }
    }

    ts = getv("ts")
    if (ts !~ /^[0-9]+$/ || ts + 0 < since || ts + 0 > until) next
    rows++
    if (!("qch" in field) || !("qcd" in field)) next
    schema++

    qch = getv("qch")
    qcd = getv("qcd")
    if (qch !~ /^[0-9]+$/ || qcd !~ /^[0-9]+$/) next
    numeric++
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        qch, qcd, getv("class"), getv("domain"), getv("ckn"),
        getv("rown"), getv("apresent"), getv("dgup"), getv("dgtn"),
        getv("qcw"), getv("qcb"), getv("qcx"), getv("qcr")
}
END { printf "%d %d %d\n", rows + 0, schema + 0, numeric + 0 > meta }
' > "$DATA"

read -r ROWS SCHEMA NUMERIC < "$META"

echo "=== QCH DISTRIBUTION ==="
echo "node=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
echo "since=$SINCE"
echo "until=$UNTIL"
echo "elapsed_seconds=$((UNTIL - SINCE))"
echo "rows=$ROWS schema=$SCHEMA numeric=$NUMERIC"

if [ "$ROWS" -gt 0 ] && [ "$SCHEMA" -eq 0 ]; then
    die "qch/qcd schema not found after marker"
fi
if [ "$NUMERIC" -eq 0 ]; then
    echo "QCHSTAT_EMPTY no query-bearing rows after marker"
    exit 0
fi

LC_ALL=C awk -F '\t' '$3 == "navigation" || $3 == "unknown"' \
    "$DATA" > "$TMP/page"
LC_ALL=C awk -F '\t' '$3 != "navigation" && $3 != "unknown"' \
    "$DATA" > "$TMP/application"
LC_ALL=C awk -F '\t' '$7 == "true"' "$DATA" > "$TMP/actor"
LC_ALL=C awk -F '\t' '$5 == "true" && $6 != "-" && $6 + 0 >= 0.50' \
    "$DATA" > "$TMP/first_party"
LC_ALL=C awk -F '\t' '$8 ~ /^[0-9]+([.][0-9]+)?$/ && $8 + 0 >= 2.0' \
    "$DATA" > "$TMP/slow"

metric() {
    local file=$1 column=$2 count
    count=$(wc -l < "$file")
    count=${count//[[:space:]]/}
    if [ "$count" -eq 0 ]; then
        printf 'p50=- p95=- p99=- max=-'
        return
    fi
    cut -f "$column" "$file" | LC_ALL=C sort -n | LC_ALL=C awk '
        { value[NR] = $1 }
        END {
            p50 = int((NR * 50 + 99) / 100)
            p95 = int((NR * 95 + 99) / 100)
            p99 = int((NR * 99 + 99) / 100)
            printf "p50=%s p95=%s p99=%s max=%s",
                value[p50], value[p95], value[p99], value[NR]
        }'
}

summary() {
    local name=$1 file=$2 count
    count=$(wc -l < "$file")
    count=${count//[[:space:]]/}
    printf 'SET %s rows=%s qch[' "$name" "$count"
    metric "$file" 1
    printf '] qcd['
    metric "$file" 2
    echo ']'
}

summary all "$DATA"
summary page "$TMP/page"
summary application "$TMP/application"
summary actor_presented "$TMP/actor"
summary first_party_strong "$TMP/first_party"
summary upstream_ge_2s "$TMP/slow"

echo
echo "=== QUERY CHURN SHADOW TELEMETRY ==="
echo "would_qch=$(LC_ALL=C awk -F '\t' '$10 == "true" {n++} END {print n+0}' "$DATA")"
echo "exclusive=$(LC_ALL=C awk -F '\t' '$12 == "true" {n++} END {print n+0}' "$DATA")"
LC_ALL=C awk -F '\t' 'BEGIN {n=0; x=0} {n++; if ($12 == "true") x++} END {
    if (n) printf "exclusive_rate=%.3f (%d/%d)\n", x/n, x, n
    else print "exclusive_rate=- (0/0)"
}' "$DATA"
LC_ALL=C awk -F '\t' '$13 ~ /^[0-9]+([.][0-9]+)?$/ {v=$13+0; n++; sum+=v} END {
    if (n) printf "exclusive_ratio_mean=%.3f samples=%d\n", sum/n, n
    else print "exclusive_ratio_mean=- samples=0"
}' "$DATA"

echo
echo "=== PAGE DOMAIN MAX (TOP 20 BY MAX_QCD) ==="
echo "domain rows max_qch max_qcd"
LC_ALL=C awk -F '\t' '
{
    domain = $4
    count[domain]++
    if ($1 + 0 > max_h[domain]) max_h[domain] = $1 + 0
    if ($2 + 0 > max_d[domain]) max_d[domain] = $2 + 0
}
END {
    for (domain in count)
        printf "%s %d %d %d\n", domain, count[domain],
            max_h[domain] + 0, max_d[domain] + 0
}' "$TMP/page" | LC_ALL=C sort -k4,4nr -k3,3nr | sed -n '1,20p'

echo
echo "=== HIGHEST PAGE ROWS (TOP 20) ==="
echo "qch qcd class domain ckn rown apresent dgup dgtn qcw qcb qcx qcr"
LC_ALL=C sort -t $'\t' -k2,2nr -k1,1nr "$TMP/page" | sed -n '1,20p' | \
    tr '\t' ' '

echo "QCHSTAT_OK"
