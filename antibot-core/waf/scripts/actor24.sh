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
NODE_RAW=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)
NODE=$(printf '%s' "$NODE_RAW" | tr -cd 'A-Za-z0-9._-')
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
function map_size(values, key, n) {
    n = 0
    for (key in values) n++
    return n
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
    issue_error = getv("aissueerr")
    # Logs before the split of ainvalid/aissueerr stored deployment failures
    # in ainvalid.  Preserve those windows without treating them as hostile
    # cookies.
    if (!("aissueerr" in field) && invalid == "secret_unavailable") {
        issue_error = invalid
        invalid = "-"
        legacy_issue_error++
    }
    suppression = getv("bsup")
    bkind = getv("bkind")
    bscope = getv("bscope")
    persisted = getv("bpersist")
    ckn = getv("ckn")
    richness = getv("richness") + 0
    own_raw = getv("rown")
    own_richness = (own_raw == "-") ? -1 : own_raw + 0
    aid = getv("aid")
    actor_key = (aid == "-") ? "" : domain SUBSEP aid
    is_q2 = (reason == "actor_quarantine" || reason == "actor_quarantine_challenge")

    if (getv("aissued") == "true") issued++
    if (getv("apresent") == "true") presented++
    if (getv("apresent") == "true" && getv("avalid") == "true") {
        valid_presented++
        if (actor_key != "") valid_actor[actor_key] = 1
    }

    if (invalid != "-") {
        cookie_invalid_count++
        invalid_by[invalid]++
        if (invalid_sample_count < 10) {
            invalid_sample_count++
            invalid_sample[invalid_sample_count] = $0
        }
    }
    if (issue_error != "-") {
        issue_error_count++
        issue_error_by[issue_error]++
        if (issue_error == "secret_unavailable") secret_unavailable++
        if (issue_sample_count < 10) {
            issue_sample_count++
            issue_sample[issue_sample_count] = $0
        }
    }

    if (persisted == "true") {
        persisted_count++
        persist_domain[domain]++
        if (actor_key != "") persist_actor[actor_key] = 1
        if (bkind != "actor" || bscope != "host") bad_persist_scope++
        if (persist_sample_count < 10) {
            persist_sample_count++
            persist_sample[persist_sample_count] = $0
        }
    }

    if (is_q2) {
        q2_total++
        q2_domain[domain]++
        q2_class[req_class]++
        if (actor_key != "") q2_actor[actor_key] = 1
        if (ckn == "true") q2_known_cookie++
        if (own_richness >= 0.50) q2_rich_own++
        if (req_class == "navigation" || req_class == "interaction" ||
            req_class == "auth_endpoint" || req_class == "api_callback") {
            q2_human_class++
        }
        if (reason == "actor_quarantine") {
            q2_block++
            if (q2_block_sample_count < 10) {
                q2_block_sample_count++
                q2_block_sample[q2_block_sample_count] = $0
            }
        } else {
            q2_challenge++
            if (q2_challenge_sample_count < 10) {
                q2_challenge_sample_count++
                q2_challenge_sample[q2_challenge_sample_count] = $0
            }
        }
        # The active log can be read while its last line is still being
        # appended. `reason=` appears near the front, while actor/scope
        # telemetry is appended near the end. Absence is therefore an
        # incomplete observation, not proof of a wrong runtime scope.
        if (!("bkind" in field) || !("bscope" in field)) {
            q2_scope_missing++
            if (q2_scope_missing_sample_count < 10) {
                q2_scope_missing_sample_count++
                q2_scope_missing_sample[q2_scope_missing_sample_count] = $0
            }
        } else if (bkind != "actor" || bscope != "host") {
            bad_q2_scope++
            if (bad_q2_scope_sample_count < 10) {
                bad_q2_scope_sample_count++
                bad_q2_scope_sample[bad_q2_scope_sample_count] = $0
            }
        }
    }

    if (getv("aqclear") == "true") {
        q2_cleared++
        if (actor_key != "") cleared_actor[actor_key] = 1
        if (clear_sample_count < 10) {
            clear_sample_count++
            clear_sample[clear_sample_count] = $0
        }
    }
    if (getv("ipold") == "true") old_ip_ignored++
    if (getv("ipmanual") == "true") manual_ip++

    if (suppression != "-") {
        suppressed++
        suppress_by[suppression]++
    }

    if (suppression == "no_presented_actor") {
        fn_no_actor++
        fn_domain[domain]++
        if (no_actor_sample_count < 10) {
            no_actor_sample_count++
            no_actor_sample[no_actor_sample_count] = $0
        }
    }

    # V1 is kept for comparison with the first fleet report.  It is a broad
    # review queue, NOT an FP rate.  V2 requires request-owned richness,
    # first-party cookie evidence and a human-facing class, and excludes
    # explicit crawler/http-client device classes.  It still remains a review
    # candidate; neither metric changes a verdict.
    fp = (is_q2 && (ckn == "true" || richness >= 0.50 || req_class == "interaction" || req_class == "auth_endpoint" || req_class == "api_callback"))
    if (fp) {
        fp_candidate++
        fp_domain[domain]++
    }
    fp_v2 = (is_q2 && ckn == "true" && own_richness >= 0.50 &&
             (req_class == "navigation" || req_class == "interaction" ||
              req_class == "auth_endpoint" || req_class == "api_callback") &&
             getv("dev") != "crawler" && getv("dev") != "http_client")
    if (fp_v2) {
        fp_candidate_v2++
        fp_v2_domain[domain]++
    }
}
END {
    issue_attempts = issued + issue_error_count
    health = (issue_error_count > 0 || bad_persist_scope > 0 ||
              bad_q2_scope > 0) ? "DEGRADED" : "OK"
    print ""
    print "=== SUMMARY ==="
    metric("rows", rows)
    metric("actor_schema_rows", schema)
    metric("old_schema_after_mark", old_schema)
    metric("actor_issued", issued)
    metric("actor_presented", presented)
    metric("actor_valid_presented", valid_presented)
    metric("actor_unique_valid", map_size(valid_actor))
    metric("actor_invalid", cookie_invalid_count + issue_error_count)
    metric("actor_cookie_invalid", cookie_invalid_count)
    metric("actor_issue_attempts", issue_attempts)
    metric("actor_issue_error", issue_error_count)
    metric("actor_secret_unavailable", secret_unavailable)
    metric("legacy_issue_error_rows", legacy_issue_error)
    metric("q2_persisted", persisted_count)
    metric("q2_unique_persist_actor", map_size(persist_actor))
    metric("q2_total", q2_total)
    metric("q2_unique_actor", map_size(q2_actor))
    metric("q2_block", q2_block)
    metric("q2_challenge", q2_challenge)
    metric("q2_cleared", q2_cleared)
    metric("q2_unique_cleared_actor", map_size(cleared_actor))
    metric("q2_known_cookie", q2_known_cookie)
    metric("q2_rown_ge_050", q2_rich_own)
    metric("q2_human_class", q2_human_class)
    metric("fp_candidate", fp_candidate)
    metric("fp_candidate_v2", fp_candidate_v2)
    metric("fn_no_presented_actor", fn_no_actor)
    metric("bad_persist_scope", bad_persist_scope)
    metric("bad_q2_scope", bad_q2_scope)
    metric("q2_scope_missing", q2_scope_missing)
    metric("old_ip_ignored", old_ip_ignored)
    metric("manual_ip", manual_ip)
    printf "actor_health=%s\n", health

    print ""
    print "=== COOKIE INVALID ==="
    for (key in invalid_by) printf "%d %s\n", invalid_by[key], key

    print ""
    print "=== ISSUE ERROR ==="
    for (key in issue_error_by) printf "%d %s\n", issue_error_by[key], key

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
    print "=== FP V2 DOMAIN ==="
    for (key in fp_v2_domain) printf "%d %s\n", fp_v2_domain[key], key

    print ""
    print "=== FN DOMAIN ==="
    for (key in fn_domain) printf "%d %s\n", fn_domain[key], key

    print ""
    print "=== SAMPLE ISSUE ERROR MAX 10 ==="
    for (i = 1; i <= issue_sample_count; i++) print issue_sample[i]

    print ""
    print "=== SAMPLE COOKIE INVALID MAX 10 ==="
    for (i = 1; i <= invalid_sample_count; i++) print invalid_sample[i]

    print ""
    print "=== SAMPLE PERSIST MAX 10 ==="
    for (i = 1; i <= persist_sample_count; i++) print persist_sample[i]

    print ""
    print "=== SAMPLE Q2 BLOCK MAX 10 ==="
    for (i = 1; i <= q2_block_sample_count; i++) print q2_block_sample[i]

    print ""
    print "=== SAMPLE Q2 CHALLENGE MAX 10 ==="
    for (i = 1; i <= q2_challenge_sample_count; i++) print q2_challenge_sample[i]

    print ""
    print "=== SAMPLE Q2 CLEAR MAX 10 ==="
    for (i = 1; i <= clear_sample_count; i++) print clear_sample[i]

    print ""
    print "=== SAMPLE Q2 BAD SCOPE MAX 10 ==="
    for (i = 1; i <= bad_q2_scope_sample_count; i++) print bad_q2_scope_sample[i]

    print ""
    print "=== SAMPLE Q2 SCOPE MISSING MAX 10 ==="
    for (i = 1; i <= q2_scope_missing_sample_count; i++) print q2_scope_missing_sample[i]

    print ""
    print "=== SAMPLE NO PRESENTED ACTOR MAX 10 ==="
    for (i = 1; i <= no_actor_sample_count; i++) print no_actor_sample[i]
}
' >> "$REPORT"

gzip -f -- "$REPORT"
trap - EXIT HUP INT TERM

SUMMARY=$(gzip -cd -- "$ARCHIVE" | LC_ALL=C awk -F= '
    /^(rows|actor_issue_error|q2_total|q2_unique_actor|fp_candidate_v2|fn_no_presented_actor|actor_invalid|bad_q2_scope|q2_scope_missing)=/ {
        printf "%s%s", separator, $0
        separator = " "
    }
    END { print "" }
')

echo "ACTOR24_READY file=$ARCHIVE"
echo "ACTOR24_SUMMARY $SUMMARY"

