#!/bin/bash
# Fast post-deploy health check for actor/q2.  This is a monitor, not a policy
# controller: it never writes Redis, secrets, markers, or nginx state.

set -euo pipefail

MINUTES=${1:-15}
LOGDIR=${2:-/var/log/antibot}
SECRET_FILE=${ANTIBOT_SECRETS_FILE:-/etc/antibot/secrets.json}
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)

case "$MINUTES" in
    ''|*[!0-9]*) echo "ACTOR_HEALTH_ERROR minutes must be an integer" >&2; exit 2 ;;
esac
[ "$MINUTES" -ge 1 ] || { echo "ACTOR_HEALTH_ERROR minutes must be >= 1" >&2; exit 2; }
[ -d "$LOGDIR" ] || { echo "ACTOR_HEALTH_ERROR missing log dir: $LOGDIR" >&2; exit 2; }
[ -x "$RESTY" ] || { echo "ACTOR_HEALTH_ERROR resty not executable: $RESTY" >&2; exit 2; }

SECRET_STATUS=OK
SECRET_DETAIL=$(
    ANTIBOT_SRC="$ROOT/" ANTIBOT_SECRETS_FILE="$SECRET_FILE" "$RESTY" -e '
        local root = assert(os.getenv("ANTIBOT_SRC"))
        local checker = assert(loadfile(root .. "waf/scripts/actor_secret_check.lua"))()
        local state, err = checker.check(root, os.getenv("ANTIBOT_SECRETS_FILE"))
        if not state then
            io.stderr:write("ACTOR_SECRET_ERROR ", tostring(err), "\n")
            os.exit(1)
        end
        io.write("ACTOR_SECRET_OK current_bytes=", state.current_bytes,
                 " previous=", state.has_previous and "yes" or "no", "\n")
    ' 2>&1
) || SECRET_STATUS=CRITICAL

SINCE=$(( $(date +%s) - MINUTES * 60 ))
UNTIL=$(date +%s)
NODE_RAW=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)
NODE=$(printf '%s' "$NODE_RAW" | tr -cd 'A-Za-z0-9._-')
[ -n "$NODE" ] || NODE=unknown

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

STATS=$(emit_logs | LC_ALL=C awk -v since="$SINCE" -v until="$UNTIL" '
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
    ts = getv("ts") + 0
    if (ts < since || ts > until) next
    rows++
    if (!("apresent" in field)) { old_schema++; next }
    schema++

    invalid = getv("ainvalid")
    issue_error = getv("aissueerr")
    if (!("aissueerr" in field) && invalid == "secret_unavailable") {
        issue_error = invalid
        invalid = "-"
        legacy_issue_error++
    }
    if (getv("aissued") == "true") issued++
    if (getv("apresent") == "true") {
        presented++
        if (getv("avalid") == "true") valid_presented++
    }
    if (invalid != "-") cookie_invalid++
    if (issue_error != "-") {
        issue_errors++
        if (issue_error == "secret_unavailable") secret_unavailable++
    }
    reason = getv("reason")
    if (reason == "actor_quarantine" || reason == "actor_quarantine_challenge") {
        q2++
        if (!("bkind" in field) || !("bscope" in field)) q2_scope_missing++
        else if (getv("bkind") != "actor" || getv("bscope") != "host") bad_q2++
    }
    if (getv("bpersist") == "true") {
        persisted++
        if (getv("bkind") != "actor" || getv("bscope") != "host") bad_persist++
    }
}
END {
    printf "rows=%d\n", rows + 0
    printf "actor_schema_rows=%d\n", schema + 0
    printf "old_schema=%d\n", old_schema + 0
    printf "actor_issued=%d\n", issued + 0
    printf "actor_presented=%d\n", presented + 0
    printf "actor_valid_presented=%d\n", valid_presented + 0
    printf "actor_cookie_invalid=%d\n", cookie_invalid + 0
    printf "actor_issue_error=%d\n", issue_errors + 0
    printf "actor_secret_unavailable=%d\n", secret_unavailable + 0
    printf "legacy_issue_error_rows=%d\n", legacy_issue_error + 0
    printf "q2_persisted=%d\n", persisted + 0
    printf "q2_total=%d\n", q2 + 0
    printf "bad_persist_scope=%d\n", bad_persist + 0
    printf "bad_q2_scope=%d\n", bad_q2 + 0
    printf "q2_scope_missing=%d\n", q2_scope_missing + 0
}
')

value() {
    printf '%s\n' "$STATS" | sed -n "s/^$1=//p"
}

STATUS=OK
if [ "$SECRET_STATUS" != "OK" ]; then
    STATUS=CRITICAL
elif [ "$(value bad_persist_scope)" -gt 0 ] || [ "$(value bad_q2_scope)" -gt 0 ]; then
    STATUS=CRITICAL
elif [ "$(value actor_issue_error)" -gt 0 ]; then
    STATUS=DEGRADED
elif [ "$(value actor_schema_rows)" -eq 0 ]; then
    STATUS=NO_DATA
fi

echo "ACTOR_HEALTH node=$NODE status=$STATUS window_minutes=$MINUTES since=$SINCE until=$UNTIL"
echo "$SECRET_DETAIL"
printf '%s\n' "$STATS"

case "$STATUS" in
    OK|NO_DATA) exit 0 ;;
    *)          exit 1 ;;
esac
