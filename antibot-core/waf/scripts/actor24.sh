#!/bin/bash
# Collect actor/q2 telemetry since the deployment marker.
# ASCII-only on purpose: this file is pasted/deployed across mixed locales.

set -euo pipefail

LOGDIR=${1:-/var/log/antibot}
MARK=${2:-/etc/antibot/actor.deploy_ts}
OUTDIR=${3:-/root}

die() {
    echo "ACTOR24_ERROR $*" >&2
    exit 2
}

[ -d "$LOGDIR" ] || die "log directory not found: $LOGDIR"
[ -r "$MARK" ] || die "marker not readable: $MARK"
[ -d "$OUTDIR" ] || die "output directory not found: $OUTDIR"
[ -w "$OUTDIR" ] || die "output directory not writable: $OUTDIR"

SINCE=$(tr -d '[:space:]' < "$MARK")
case "$SINCE" in
    ''|*[!0-9]*) die "marker is not an epoch: $SINCE" ;;
esac

UNTIL=$(date +%s)
NODE=$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9._-')
[ -n "$NODE" ] || NODE=unknown

REPORT="$OUTDIR/actor24_${NODE}_${SINCE}_${UNTIL}.txt"
ARCHIVE="${REPORT}.gz"

cleanup() {
    rm -f -- "$REPORT"
}
trap cleanup EXIT HUP INT TERM

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

{
    echo "=== ACTOR Q2 REPORT ==="
    echo "node=$NODE"
    echo "since=$SINCE"
    echo "until=$UNTIL"
    echo "elapsed_seconds=$((UNTIL - SINCE))"
    echo
    echo "=== FILES ==="
    while IFS= read -r -d '' file; do
        echo "$file"
    done < <(list_logs)
} > "$REPORT"

emit_logs | LC_ALL=C awk -v since="$SINCE" -v until="$UNTIL" '
function getv(name) {
    return (name in field) ? field[name] : "-"
}
function metric(name, value) {
    printf "%s=%d\n", name, value + 0
}
{
    for (key in field) delete field[key]

    for (i = 1; i <= NF; i++) {
        pos = index($i, "=")
        if (pos > 1) {
            key = substr($i, 1, pos - 1)
            if (!(key in field)) field[key] = substr($i, pos + 1)
        }
    }

    ts = getv("ts") + 0
    if (ts < since || ts > until) next

    rows++
    if (!("apresent" in field)) {
        old_schema++
        next
    }

    schema++
    domain = getv("domain")
    req_class = getv("class")
    reason = getv("reason")
    invalid = getv("ainvalid")
    suppression = getv("bsup")
    bkind = getv("bkind")
    bscope = getv("bscope")
    persisted = getv("bpersist")
    ckn = getv("ckn")
    richness = getv("richness") + 0
    is_q2 = (reason == "actor_quarantine" || reason == "actor_quarantine_challenge")

    if (getv("aissued") == "true") issued++
    if (getv("apresent") == "true") presented++
    if (getv("apresent") == "true" && getv("avalid") == "true") valid_presented++

    if (invalid != "-") {
        invalid_count++
        invalid_by[invalid]++
    }

    if (persisted == "true") {
        persisted_count++
        persist_domain[domain]++
        if (bkind != "actor" || bscope != "host") bad_persist_scope++
    }

    if (is_q2) {
        q2_total++
        q2_domain[domain]++
        q2_class[req_class]++
        if (reason == "actor_quarantine") q2_block++
        else q2_challenge++
        if (bkind != "actor" || bscope != "host") bad_q2_scope++
    }

    if (getv("aqclear") == "true") q2_cleared++
    if (getv("ipold") == "true") old_ip_ignored++
    if (getv("ipmanual") == "true") manual_ip++

    if (suppression != "-") {
        suppressed++
        suppress_by[suppression]++
    }

    if (suppression == "no_presented_actor") {
        fn_no_actor++
        fn_domain[domain]++
    }

    fp = (is_q2 && (ckn == "true" || richness >= 0.50 || req_class == "interaction" || req_class == "auth_endpoint" || req_class == "api_callback"))
    if (fp) {
        fp_candidate++
        fp_domain[domain]++
    }

    interesting = (getv("aissued") == "true" || persisted == "true" || is_q2 || getv("aqclear") == "true" || invalid != "-" || suppression != "-")
    if (interesting && sample_count < 50) {
        sample_count++
        sample[sample_count] = $0
    }
}
END {
    print ""
    print "=== SUMMARY ==="
    metric("rows", rows)
    metric("actor_schema_rows", schema)
    metric("old_schema_after_mark", old_schema)
    metric("actor_issued", issued)
    metric("actor_presented", presented)
    metric("actor_valid_presented", valid_presented)
    metric("actor_invalid", invalid_count)
    metric("q2_persisted", persisted_count)
    metric("q2_total", q2_total)
    metric("q2_block", q2_block)
    metric("q2_challenge", q2_challenge)
    metric("q2_cleared", q2_cleared)
    metric("fp_candidate", fp_candidate)
    metric("fn_no_presented_actor", fn_no_actor)
    metric("bad_persist_scope", bad_persist_scope)
    metric("bad_q2_scope", bad_q2_scope)
    metric("old_ip_ignored", old_ip_ignored)
    metric("manual_ip", manual_ip)

    print ""
    print "=== INVALID ==="
    for (key in invalid_by) printf "%d %s\n", invalid_by[key], key

    print ""
    print "=== SUPPRESS ==="
    for (key in suppress_by) printf "%d %s\n", suppress_by[key], key

    print ""
    print "=== Q2 DOMAIN ==="
    for (key in q2_domain) printf "%d %s\n", q2_domain[key], key

    print ""
    print "=== Q2 CLASS ==="
    for (key in q2_class) printf "%d %s\n", q2_class[key], key

    print ""
    print "=== PERSIST DOMAIN ==="
    for (key in persist_domain) printf "%d %s\n", persist_domain[key], key

    print ""
    print "=== FP DOMAIN ==="
    for (key in fp_domain) printf "%d %s\n", fp_domain[key], key

    print ""
    print "=== FN DOMAIN ==="
    for (key in fn_domain) printf "%d %s\n", fn_domain[key], key

    print ""
    print "=== SAMPLES MAX 50 ==="
    for (i = 1; i <= sample_count; i++) print sample[i]
}
' >> "$REPORT"

gzip -f -- "$REPORT"
trap - EXIT HUP INT TERM

SUMMARY=$(gzip -cd -- "$ARCHIVE" | LC_ALL=C awk -F= '
    /^(rows|q2_total|fp_candidate|fn_no_presented_actor|actor_invalid)=/ {
        printf "%s%s", separator, $0
        separator = " "
    }
    END { print "" }
')

echo "ACTOR24_READY file=$ARCHIVE"
echo "ACTOR24_SUMMARY $SUMMARY"

