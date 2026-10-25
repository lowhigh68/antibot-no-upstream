#!/bin/bash
# healthstat.sh -- P1.2 unified node-health view.
#
# Read-only by design: it reads the structured request log, policy artifacts,
# Redis feed markers and nginx error log.  It never writes a key, changes a
# policy or scans tenant files.  The default window is one hour; pass an epoch
# as argument 1 to align several nodes to exactly the same interval.
#
# Usage:
#   bash healthstat.sh [since_epoch] [antibot.log]
#
# Useful overrides for tests/non-standard installs:
#   NOW LOG POLICY_DIR POLICYCTL ERROR_LOG LIVE
#   HEALTH_REDIS_CLI HEALTH_REDIS_HOST HEALTH_REDIS_PORT HEALTH_REDIS_DB
#   ANTIBOT_REDIS_PASS ANTIBOT_REDIS_PASS_FILE

set -uo pipefail
export LC_ALL=C

NOW=${NOW:-$(date +%s)}
SINCE=${1:-$((NOW - 3600))}
LOG=${2:-${LOG:-/var/log/antibot/antibot.log}}
LOGDIR=$(dirname "$LOG")
LOGBASE=$(basename "$LOG")
LIVE=${LIVE:-/usr/local/openresty/nginx/conf/antibot}
POLICY_DIR=${POLICY_DIR:-/etc/antibot/policy}
POLICYCTL=${POLICYCTL:-$LIVE/waf/scripts/policyctl.sh}
ERROR_LOG=${ERROR_LOG:-/usr/local/openresty/nginx/logs/error.log}

case "$SINCE:$NOW" in
    *[!0-9:]*) echo "HEALTH_ERROR since/NOW phai la epoch"; exit 2 ;;
esac
if [ "$SINCE" -gt "$NOW" ]; then
    echo "HEALTH_ERROR since nam sau NOW"; exit 2
fi

LOGGER="$LIVE/async/logger.lua"
if [ ! -r "$LOGGER" ]; then
    echo "HEALTH_ERROR khong doc duoc $LOGGER"; exit 2
fi

# A zero caused by an old logger is not a measurement.  Gate the exact fields
# this report consumes before touching logs.
missing=""
for field in ' pver=' ' dschema=' ' dkind=' ' dup=' ' autuptime=' \
             ' epuptime=' ' dgpcid=' ' dgpcwork=' ' ckn='; do
    grep -qF "$field" "$LOGGER" 2>/dev/null || missing="$missing$field"
done
if [ -n "$missing" ]; then
    echo "HEALTH_ERROR logger schema thieu:$missing"
    echo "  ma P1.2 chua len node; khong bien schema=0 thanh ket luan xanh"
    exit 3
fi

WORK=$(mktemp -d /tmp/antibot-health.XXXXXX) || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM
RAW="$WORK/requests.log"
ERRS="$WORK/errors.log"
: > "$RAW"
: > "$ERRS"

# Select by mtime only to avoid reading every retained archive, then use ts=
# as the authoritative boundary.  Always include the live file even when it
# has no row yet after rotation.
TREF=$(date -d "@$SINCE" '+%Y-%m-%d %H:%M:%S')
ERR_TREF=$(date -d "@$SINCE" '+%Y/%m/%d %H:%M:%S')
FILES=$(find "$LOGDIR" -maxdepth 1 -type f -name "$LOGBASE*" \
        -newermt "$TREF" -printf '%T@ %p\n' 2>/dev/null \
        | sort -n | cut -d' ' -f2-)
have_live=0
while IFS= read -r f; do
    [ "$f" = "$LOG" ] && have_live=1
done <<EOF
$FILES
EOF
[ "$have_live" -eq 1 ] || FILES="${FILES}${FILES:+
}$LOG"

read_files() {
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        case "$f" in
            *.gz) gzip -cd -- "$f" ;;
            *)    cat -- "$f" ;;
        esac
    done
}

printf '%s\n' "$FILES" | read_files | awk -v lo="$SINCE" -v hi="$NOW" '
function value(name, i, p) {
    p = name "="
    for (i=1; i<=NF; i++) if (index($i,p)==1) return substr($i,length(p)+1)
    return ""
}
{
    t=value("ts")
    if (t != "" && t+0 >= lo && t+0 <= hi) print
}' > "$RAW"

ROWS=$(wc -l < "$RAW")
MAX_TS=$(awk '
{ for(i=1;i<=NF;i++) if($i~/^ts=/){split($i,a,"="); if(a[2]>m)m=a[2]} }
END{print m+0}' "$RAW")
LAG=-1
[ "$MAX_TS" -gt 0 ] && LAG=$((NOW - MAX_TS))

echo "=== NODE / WINDOW ==="
echo "host=$(hostname) since=$SINCE until=$NOW rows=$ROWS last_ts=$MAX_TS log_lag_s=$LAG"
printf 'files='
while IFS= read -r f; do [ -f "$f" ] && printf '%s ' "${f##*/}"; done <<EOF
$FILES
EOF
echo

echo "=== POLICY FILES ==="
if [ -r "$POLICYCTL" ]; then
    bash "$POLICYCTL" status 2>&1 || echo "policy_status=degraded"
else
    for f in active.json last-good.json; do
        if [ -r "$POLICY_DIR/$f" ]; then
            v=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                "$POLICY_DIR/$f" | head -1)
            echo "$f present version=${v:--}"
        else
            echo "$f missing_or_unreadable"
        fi
    done
fi

echo "=== REQUEST HEALTH ==="
if [ "$ROWS" -eq 0 ]; then
    echo "NO_DATA: khong co request trong cua so; cac ty le traffic khong duoc danh gia"
else
awk '
function get(name,  i,p) {
    p=name "="
    for(i=1;i<=NF;i++) if(index($i,p)==1) return substr($i,length(p)+1)
    return ""
}
function rejected(a) { return a=="block" || a=="challenge" || a=="throttled" }
function numeric(v) { return v ~ /^[0-9]+([.][0-9]+)?$/ }
function key_subject( id,ip,dom) {
    id=get("id"); ip=get("ip"); dom=get("domain")
    return dom "|" ((id!="" && id!="-") ? id : ip)
}
{
    rows++
    pv=get("pver"); ds=get("dschema"); du=get("dup")
    ac=get("action"); dk=get("dkind"); dr=get("drule")
    if(pv=="") { pv="<missing>"; missing_version=1 }
    if(ds=="") { ds="<missing>"; missing_schema=1 }
    pvers[pv]++; schemas[ds]++
    if(du=="true") upstream++; else if(du=="false") local++; else unknown_up++
    actions[ac==""?"<missing>":ac]++
    kinds[dk==""?"<missing>":dk]++
    if(du=="false" && rejected(ac)) local_rules[dr==""?"<missing>":dr]++

    anydeg=0
    for(i=1;i<=NF;i++) {
        split($i,a,"="); k=a[1]; v=substr($i,length(k)+2)
        if((k=="ideg" && v!="" && v!="-") || (k ~ /deg$/ && v=="true")) {
            degraded[k]++; anydeg=1
        }
    }
    if(anydeg) degraded_rows++

    subj=key_subject()
    if(ac=="challenge") { challenges++; challenge_n[subj]++ }
    if(challenge_n[subj]>0 && (get("reason")=="verified_human" ||
       get("reason")=="cookie_verified" || get("dev")=="verified_fastpath"))
        challenge_recovered[subj]=1

    ckn=get("ckn")
    if(ckn=="true") { known++; if(rejected(ac)) known_reject++ }
    human=(get("dev")=="verified_fastpath" || get("reason")=="verified_human" ||
           get("reason")=="cookie_verified")
    if(human) { human_v++; if(rejected(ac)) human_v_reject++ }
    bot=(get("auttier")=="verified" || get("autctier")=="verified_aggressive")
    if(bot) { bot_v++; if(rejected(ac)) bot_v_reject++ }

    principal=get("autp"); up=get("autuptime")
    if(principal!="" && principal!="-" && numeric(up)) {
        pwork[principal]+=up; preq[principal]++
    }
    ep=get("ep"); eup=get("epuptime")
    if(ep!="" && ep!="-" && numeric(eup)) { ework[ep]+=eup; ereq[ep]++ }
    cohort=get("dgpcid"); cw=get("dgpcwork")
    if(cohort!="" && cohort!="-" && numeric(cw)) {
        if(cw>cmax[cohort]) cmax[cohort]=cw
        cn[cohort]++
    }
}
END {
    np=ns=0
    for(v in pvers){ np++; printf "policy[%s]=%d\n",v,pvers[v] }
    for(v in schemas){ ns++; printf "schema[%s]=%d\n",v,schemas[v] }
    printf "version_state=%s policy_versions=%d schemas=%d\n", \
           (np==1 && ns==1 && !missing_version && !missing_schema \
             ? "ok" : "MIXED_OR_MISSING"),np,ns
    printf "decision rows=%d upstream=%d local=%d unknown=%d degraded_rows=%d\n", \
           rows,upstream+0,local+0,unknown_up+0,degraded_rows+0
    printf "actions"; for(v in actions) printf " %s=%d",v,actions[v]; print ""
    printf "kinds"; for(v in kinds) printf " %s=%d",v,kinds[v]; print ""
    printf "degraded"; n=0; for(v in degraded){printf " %s=%d",v,degraded[v];n++}
    if(n==0) printf " none=0"; print ""
    printf "local_reject_rules"; n=0
    for(v in local_rules){printf " %s=%d",v,local_rules[v];n++}
    if(n==0) printf " none=0"; print ""

    repeat=rec=0
    for(v in challenge_n){if(challenge_n[v]>=2)repeat++; if(challenge_recovered[v])rec++}
    printf "challenge issued=%d repeated_subjects=%d recovered_subjects=%d\n", \
           challenges+0,repeat,rec
    printf "fp_guard known_cookie=%d/%d verified_human=%d/%d verified_bot=%d/%d\n", \
           known_reject+0,known+0,human_v_reject+0,human_v+0,bot_v_reject+0,bot_v+0

    for(v in pwork) printf "P\t%.6f\t%d\t%s\n",pwork[v],preq[v],v
    for(v in ework) printf "E\t%.6f\t%d\t%s\n",ework[v],ereq[v],v
    for(v in cmax)  printf "C\t%.6f\t%d\t%s\n",cmax[v],cn[v],v
}' "$RAW" > "$WORK/report"

# Keep the scalar health block stable and sort only the three bounded top lists.
grep -vE '^[PEC]\t' "$WORK/report"
echo "top_principal_upstream_seconds"
awk -F '\t' '$1=="P"{print}' "$WORK/report" | sort -t $'\t' -k2,2nr | awk 'NR<=10' \
    | awk -F '\t' '{printf "  %s work=%.3f requests=%d\n",$4,$2,$3}'
echo "top_endpoint_upstream_seconds"
awk -F '\t' '$1=="E"{print}' "$WORK/report" | sort -t $'\t' -k2,2nr | awk 'NR<=10' \
    | awk -F '\t' '{printf "  %s work=%.3f requests=%d\n",$4,$2,$3}'
echo "top_cohort_window_work_max"
awk -F '\t' '$1=="C"{print}' "$WORK/report" | sort -t $'\t' -k2,2nr | awk 'NR<=10' \
    | awk -F '\t' '{printf "  %s max_work=%.3f observations=%d\n",$4,$2,$3}'
fi

echo "=== REDIS / FEEDS ==="
RCLI_BIN=${HEALTH_REDIS_CLI:-redis-cli}
RHOST=${HEALTH_REDIS_HOST:-127.0.0.1}
RPORT=${HEALTH_REDIS_PORT:-6379}
RDB=${HEALTH_REDIS_DB:-0}
RPASS=${ANTIBOT_REDIS_PASS:-}
if [ -z "$RPASS" ]; then
    RPF=${ANTIBOT_REDIS_PASS_FILE:-/etc/antibot/redis.pass}
    [ -r "$RPF" ] && RPASS=$(head -1 "$RPF" 2>/dev/null | tr -d '\r\n')
fi
RAUTH=()
[ -n "$RPASS" ] && RAUTH=(--no-auth-warning -a "$RPASS")
rcli() { "$RCLI_BIN" -h "$RHOST" -p "$RPORT" -n "$RDB" "${RAUTH[@]}" "$@"; }

if ! command -v "$RCLI_BIN" >/dev/null 2>&1; then
    echo "redis=unknown reason=client_missing"
elif [ "$(rcli --raw PING 2>/dev/null || :)" != "PONG" ]; then
    echo "redis=degraded reason=ping_failed"
else
    echo "redis=ok dbsize=$(rcli --raw DBSIZE 2>/dev/null || echo -)"
    for stem in threat:last_sync mon:last_sync; do
        t=$(rcli --raw GET "$stem" 2>/dev/null || :)
        if echo "$t" | grep -qE '^[0-9]+$' && [ "$t" -le "$NOW" ]; then
            echo "$stem=$t age_s=$((NOW - t))"
        else
            echo "$stem=${t:--} age_s=unknown"
        fi
    done
    stats=$(rcli --raw GET threat:stats 2>/dev/null || :)
    echo "threat:stats=${stats:--}"
    # Do not SCAN a 300k-key Redis database to discover eight bounded feed
    # names.  This list is the source-health contract; override it when a node
    # intentionally runs a different source set.
    OPERATOR_SOURCES=${HEALTH_OPERATOR_SOURCES:-"uptrends openai-gptbot openai-searchbot openai-chatgpt-user openai-adsbot anthropic perplexitybot perplexity-user"}
    nsrc=0; healthy_src=0
    for name in $OPERATOR_SOURCES; do
        nsrc=$((nsrc + 1))
        t=$(rcli --raw GET "mon:srcsync:$name" 2>/dev/null || :)
        count=$(rcli --raw GET "mon:src:$name" 2>/dev/null || :)
        age=unknown
        if echo "$t" | grep -qE '^[0-9]+$' && [ "$t" -le "$NOW" ]; then
            age=$((NOW - t)); healthy_src=$((healthy_src + 1))
        fi
        echo "source[$name] count=${count:--} age_s=$age"
    done
    echo "operator_sources=$nsrc readable=$healthy_src"
fi

echo "=== LOGGER ERRORS ==="
EFILES=$(find "$(dirname "$ERROR_LOG")" -maxdepth 1 -type f \
         -name "$(basename "$ERROR_LOG")*" \
         -newermt "$TREF" -printf '%T@ %p\n' 2>/dev/null \
         | sort -n | cut -d' ' -f2-)
case "
$EFILES
" in
    *"
$ERROR_LOG
"*) ;;
    *) [ -f "$ERROR_LOG" ] && EFILES="${EFILES}${EFILES:+
}$ERROR_LOG" ;;
esac
# The unusual parameterized loop below is intentionally tolerant: some nodes
# keep per-domain errors elsewhere, so absence is reported rather than green.
if [ -z "$EFILES" ]; then
    echo "logger_error_rows=unknown reason=error_log_missing"
else
    printf '%s\n' "$EFILES" | read_files | awk -v since_text="$ERR_TREF" '
substr($0,1,19)>=since_text {
    if (/\[antibot\]/ &&
        (/cannot open log file/ || /log flush timer failed/)) {
        print; logger_n++
    }
    if (/\[policy\]/ && (/candidate rejected/ || /CRITICAL/)) {
        print; policy_n++
    }
}
END{
    printf "logger_error_rows=%d\n",logger_n+0
    printf "policy_error_rows=%d\n",policy_n+0
}' > "$ERRS"
    cat "$ERRS"
fi

echo "NOTE reload_tail_loss_is_not_measurable bound=64_lines_per_worker_per_reload"
