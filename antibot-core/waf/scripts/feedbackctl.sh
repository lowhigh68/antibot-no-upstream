#!/bin/bash
# P1.3 labelled incident archive + honest shadow replay.
#
# No nginx worker reads this directory.  Capture/list/replay are explicit
# operator actions and never mutate Redis, policy, bans or request verdicts.
set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
TOOL="$ROOT/core/feedback_tool.lua"
STATE_DIR=${ANTIBOT_FEEDBACK_DIR:-/etc/antibot/feedback}
LOG=${ANTIBOT_FEEDBACK_LOG:-/var/log/antibot/antibot.log}
NOW=${NOW:-$(date +%s)}
export ANTIBOT_SRC="$ROOT/"

usage() {
    echo "Dung: $0 capture <label> <from_epoch> <to_epoch> <ttl_days> <actor> <note> <key=value>..."
    echo "      $0 list"
    echo "      $0 status"
    echo "      $0 replay"
    echo "      $0 prune-expired"
    echo "label: true_bot | legit_automation | human_fp | capacity_only"
    echo "Vi du: $0 capture human_fp 1793200000 1793200600 30 admin 'Zalo preview PoW' domain=no1computer.vn ip=183.81.9.113"
}

require_tool() {
    [ -x "$RESTY" ] || { echo "FEEDBACK_ERROR khong tim thay resty: $RESTY"; return 2; }
    [ -r "$TOOL" ] || { echo "FEEDBACK_ERROR khong tim thay tool: $TOOL"; return 2; }
}

prepare_dir() {
    if [ "${FEEDBACKCTL_TEST_MODE:-0}" = "1" ]; then
        mkdir -p "$STATE_DIR" && chmod 0700 "$STATE_DIR"
    else
        [ "$(id -u)" = "0" ] || {
            echo "FEEDBACK_ERROR capture phai chay root"; return 2;
        }
        install -d -m 0700 -o root -g root "$STATE_DIR"
    fi
}

manifest_paths() {
    [ -d "$STATE_DIR" ] || return 0
    find "$STATE_DIR" -mindepth 2 -maxdepth 2 -type f \
        -name manifest.json -print 2>/dev/null | sort
}

read_files() {
    while IFS= read -r file; do
        [ -f "$file" ] || continue
        case "$file" in
            *.gz) gzip -cd -- "$file" ;;
            *)    cat -- "$file" ;;
        esac
    done
}

discard_capture() {
    local path=$1
    case "$path" in
        "$STATE_DIR"/.capture.*)
            rm -f -- "$path/filters" "$path/evidence.log" "$path/manifest.json"
            rmdir -- "$path" 2>/dev/null || :
            ;;
        *) echo "FEEDBACK_ERROR tu choi don thu muc tam ngoai state dir: $path" >&2 ;;
    esac
}

capture() {
    [ "$#" -ge 8 ] || { usage; return 2; }
    local label=$2 from=$3 to=$4 ttl_days=$5 actor=$6 note=$7
    shift 7

    case "$label" in
        true_bot|legit_automation|human_fp|capacity_only) ;;
        *) echo "FEEDBACK_ERROR label khong hop le: $label"; return 2 ;;
    esac
    case "$from:$to:$ttl_days:$NOW" in
        *[!0-9:]*) echo "FEEDBACK_ERROR time/ttl phai la so nguyen duong"; return 2 ;;
    esac
    [ "$from" -le "$to" ] && [ "$to" -le "$NOW" ] || {
        echo "FEEDBACK_ERROR cua so thoi gian khong hop le"; return 2;
    }
    [ "$ttl_days" -ge 1 ] && [ "$ttl_days" -le 365 ] || {
        echo "FEEDBACK_ERROR ttl_days phai trong 1..365"; return 2;
    }
    case "$actor" in
        ""|*[!A-Za-z0-9._@-]*) echo "FEEDBACK_ERROR actor khong hop le"; return 2 ;;
    esac
    [ "${#actor}" -le 96 ] && [ -n "$note" ] && [ "${#note}" -le 512 ] || {
        echo "FEEDBACK_ERROR actor/note rong hoac qua dai"; return 2;
    }
    case "$note" in *$'\n'*|*$'\r'*) echo "FEEDBACK_ERROR note khong duoc xuong dong"; return 2 ;; esac
    [ "$#" -ge 1 ] || { echo "FEEDBACK_ERROR can it nhat mot filter exact key=value"; return 2; }

    require_tool || return $?
    prepare_dir || return $?
    [ -r "$LOG" ] || { echo "FEEDBACK_ERROR khong doc duoc log: $LOG"; return 2; }

    local work filters evidence manifest filters_csv item key value
    work=$(mktemp -d "$STATE_DIR/.capture.XXXXXX") || return 2
    filters="$work/filters"
    evidence="$work/evidence.log"
    manifest="$work/manifest.json"
    : > "$filters"
    filters_csv=""
    for item in "$@"; do
        case "$item" in
            *=*) key=${item%%=*}; value=${item#*=} ;;
            *) echo "FEEDBACK_ERROR filter phai la key=value: $item"; discard_capture "$work"; return 2 ;;
        esac
        case "$key" in
            ""|*[!A-Za-z0-9_]*) echo "FEEDBACK_ERROR filter key khong hop le: $key"; discard_capture "$work"; return 2 ;;
        esac
        [ -n "$value" ] && [ "${#value}" -le 256 ] || {
            echo "FEEDBACK_ERROR filter value rong/qua dai"; discard_capture "$work"; return 2;
        }
        case "$value" in *[[:space:],]*) echo "FEEDBACK_ERROR filter value khong duoc co space/comma"; discard_capture "$work"; return 2 ;; esac
        printf '%s=%s\n' "$key" "$value" >> "$filters"
        filters_csv="${filters_csv}${filters_csv:+,}${key}=${value}"
    done

    local logdir logbase tref files have_live
    logdir=$(dirname "$LOG"); logbase=$(basename "$LOG")
    tref=$(date -d "@$from" '+%Y-%m-%d %H:%M:%S') || { discard_capture "$work"; return 2; }
    files=$(find "$logdir" -maxdepth 1 -type f -name "$logbase*" \
        -newermt "$tref" -printf '%T@ %p\n' 2>/dev/null \
        | sort -n | cut -d' ' -f2-)
    have_live=0
    while IFS= read -r item; do [ "$item" = "$LOG" ] && have_live=1; done <<EOF
$files
EOF
    [ "$have_live" -eq 1 ] || files="${files}${files:+
}$LOG"

    printf '%s\n' "$files" | read_files | awk -v lo="$from" -v hi="$to" '
NR==FNR {
    p=index($0,"="); if(p>1){ fk[++nf]=substr($0,1,p-1); fv[nf]=substr($0,p+1) }
    next
}
function val(k,  i,p){ p=k"="; for(i=1;i<=NF;i++) if(index($i,p)==1)return substr($i,length(p)+1); return "" }
{
    t=val("ts")+0
    if(t<lo || t>hi) next
    for(j=1;j<=nf;j++) if(val(fk[j])!=fv[j]) next
    print
}' "$filters" - > "$evidence"

    local rows bytes sha created expires id final host
    rows=$(wc -l < "$evidence")
    bytes=$(wc -c < "$evidence")
    [ "$rows" -ge 1 ] || { echo "FEEDBACK_ERROR khong co dong nao khop"; discard_capture "$work"; return 1; }
    [ "$rows" -le 50000 ] && [ "$bytes" -le 67108864 ] || {
        echo "FEEDBACK_ERROR evidence vuot tran 50000 dong/64MiB"; discard_capture "$work"; return 2;
    }
    sha=$(sha256sum "$evidence" | awk '{print $1}')
    created=$NOW; expires=$((created + ttl_days * 86400))
    id="fb-${created}-${sha:0:12}"
    final="$STATE_DIR/$id"
    [ ! -e "$final" ] || { echo "FEEDBACK_ERROR incident da ton tai: $id"; discard_capture "$work"; return 2; }
    host=$(hostname)

    if ! FB_EVIDENCE="$evidence" FB_ID="$id" FB_LABEL="$label" \
      FB_ACTOR="$actor" FB_NOTE="$note" FB_FILTERS="$filters_csv" \
      FB_SHA256="$sha" FB_HOST="$host" FB_SOURCE_LOG="$LOG" \
      FB_FROM="$from" FB_TO="$to" FB_CREATED="$created" FB_EXPIRES="$expires" \
      "$RESTY" "$TOOL" manifest > "$manifest"; then
        echo "FEEDBACK_ERROR tao manifest that bai"; discard_capture "$work"; return 2
    fi
    grep -q '"schema":"1"' "$manifest" || {
        echo "FEEDBACK_ERROR manifest khong hop le"; discard_capture "$work"; return 2;
    }
    rm -f "$filters"
    chmod 0600 "$evidence" "$manifest"
    mv "$work" "$final" || { echo "FEEDBACK_ERROR atomic publish that bai"; discard_capture "$work"; return 2; }
    chmod 0700 "$final"
    echo "FEEDBACK_CAPTURED id=$id label=$label rows=$rows sha256=$sha expires=$expires"
}

verify_bundles() {
    local manifest dir expected got
    while IFS= read -r manifest; do
        [ -n "$manifest" ] || continue
        dir=$(dirname "$manifest")
        [ -r "$dir/evidence.log" ] || { echo "FEEDBACK_ERROR missing evidence: $dir"; return 2; }
        expected=$(sed -n 's/.*"evidence_sha256":"\([0-9a-f]*\)".*/\1/p' "$manifest" | head -1)
        got=$(sha256sum "$dir/evidence.log" | awk '{print $1}')
        [ "${#expected}" -eq 64 ] && [ "$got" = "$expected" ] || {
            echo "FEEDBACK_ERROR evidence digest mismatch: $dir"; return 2;
        }
    done
}

run_tool_on_manifests() {
    local mode=$1 out rc
    mapfile -t manifests < <(manifest_paths)
    if [ "${#manifests[@]}" -eq 0 ]; then
        if [ "$mode" = replay ]; then echo "REPLAY_NO_DATA active=0 expired=0"
        else echo "feedback active=0 expired=0 true_bot=0 legit_automation=0 human_fp=0 capacity_only=0"; fi
        return 0
    fi
    printf '%s\n' "${manifests[@]}" | verify_bundles || return $?
    out=$(mktemp) || return 2
    "$RESTY" "$TOOL" "$mode" "$NOW" "${manifests[@]}" > "$out" 2>&1
    rc=$?
    cat "$out"
    if grep -q '^REPLAY_BLOCK ' "$out"; then rm -f "$out"; return 1; fi
    if [ "$mode" = replay ]; then
        grep -qE '^REPLAY_(OK|NO_DATA) ' "$out" || { rm -f "$out"; return 2; }
    else
        grep -q '^feedback ' "$out" || { rm -f "$out"; return 2; }
    fi
    rm -f "$out"
    [ "$rc" -eq 0 ] || return 2
    return 0
}

prune_expired() {
    prepare_dir || return $?
    local manifest dir expires removed=0
    while IFS= read -r manifest; do
        [ -n "$manifest" ] || continue
        dir=$(dirname "$manifest")
        expires=$(sed -n 's/.*"expires_at":\([0-9][0-9]*\).*/\1/p' "$manifest" | head -1)
        case "$expires" in ""|*[!0-9]*) echo "FEEDBACK_ERROR expires_at khong hop le: $manifest"; return 2 ;; esac
        [ "$expires" -lt "$NOW" ] || continue
        case "$dir" in
            "$STATE_DIR"/fb-*)
                rm -f -- "$dir/evidence.log" "$dir/manifest.json"
                if rmdir -- "$dir" 2>/dev/null; then removed=$((removed + 1))
                else echo "FEEDBACK_ERROR incident co tep la, khong xoa: $dir"; return 2; fi
                ;;
            *) echo "FEEDBACK_ERROR tu choi prune ngoai state dir: $dir"; return 2 ;;
        esac
    done < <(manifest_paths)
    echo "FEEDBACK_PRUNED expired=$removed"
}

command=${1:-}
case "$command" in
    capture) capture "$@" ;;
    list)
        require_tool || exit $?
        run_tool_on_manifests list
        ;;
    status)
        require_tool || exit $?
        tmp=$(mktemp) || exit 2
        if run_tool_on_manifests list > "$tmp"; then rc=0; else rc=$?; fi
        if [ "$rc" -eq 0 ]; then tail -1 "$tmp"; else cat "$tmp"; fi
        rm -f "$tmp"; exit "$rc"
        ;;
    replay)
        require_tool || exit $?
        run_tool_on_manifests replay
        ;;
    prune-expired) prune_expired ;;
    *) usage; exit 2 ;;
esac
