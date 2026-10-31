#!/usr/bin/env bash
# Read-only audit for interactive PoW pages served to non-interactive clients.
#
# Usage:
#   previewstat.sh FROM_EPOCH TO_EPOCH [LOG_DIR]
#
# The report is intentionally structural: it does not contain a WhatsApp/Zalo
# allowlist.  A candidate is a GET/HEAD request that production actually sent
# to `pow_challenge` while device classification said `http_client`.  These are
# clients that cannot execute the challenge and may be link-preview/unfurl
# fetchers, monitoring tools, or hostile HTTP libraries.  The distributions
# below are the evidence needed to design a bounded lane without granting all
# HTTP tools a bypass.
set -u

FROM=${1:-}
TO=${2:-}
LOG_DIR=${3:-/var/log/antibot}

case "$FROM" in ''|*[!0-9]*) echo "usage: $0 FROM_EPOCH TO_EPOCH [LOG_DIR]" >&2; exit 2;; esac
case "$TO"   in ''|*[!0-9]*) echo "usage: $0 FROM_EPOCH TO_EPOCH [LOG_DIR]" >&2; exit 2;; esac
if [ "$FROM" -gt "$TO" ]; then
    echo "FROM_EPOCH must be <= TO_EPOCH" >&2
    exit 2
fi
if [ ! -d "$LOG_DIR" ]; then
    echo "log directory not found: $LOG_DIR" >&2
    exit 2
fi

TMP=$(mktemp "${TMPDIR:-/tmp}/previewstat.XXXXXX") || exit 2
trap 'rm -f -- "$TMP"' EXIT HUP INT TERM

found=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    found=1
    case "$f" in
        *.gz) gzip -cd -- "$f" >> "$TMP" || exit 2 ;;
        *)    cat -- "$f" >> "$TMP" || exit 2 ;;
    esac
done < <(find "$LOG_DIR" -maxdepth 1 -type f -name 'antibot.log*' -print | sort)

if [ "$found" -eq 0 ]; then
    echo "no antibot.log files in $LOG_DIR" >&2
    exit 2
fi

awk -v from="$FROM" -v to="$TO" '
function val(name,   i,prefix) {
    prefix = name "="
    for (i=1; i<=NF; i++) {
        if (index($i,prefix)==1) return substr($i,length(prefix)+1)
    }
    return "-"
}
function top(a,n,title,   i,k,bk,bv) {
    print title
    for (i=1; i<=n; i++) {
        bk=""; bv=0
        for (k in a) if (a[k]>bv) { bk=k; bv=a[k] }
        if (bk=="") break
        printf "  %7d  %s\n", bv, bk
        delete a[bk]
    }
}
{
    ts=val("ts")
    if (ts !~ /^[0-9]+$/ || ts+0 < from || ts+0 > to) next
    rows++
    action=val("action"); drule=val("drule"); dev=val("dev")
    method=val("m"); class=val("class")
    if (action!="challenge" || drule!="pow_challenge") next
    pow++
    powdev[dev]++
    powclass[class]++

    if ((method!="GET" && method!="HEAD") || dev!="http_client") next
    cand++
    domain=val("domain"); ua=val("ua"); ckn=val("ckn"); sf=val("sf")
    eff=val("eff"); score=val("score")
    canddomain[domain]++
    candua[ua]++
    candclass[class]++
    candckn[ckn]++
    candsf[sf]++
    if (eff !~ /^-?[0-9]+([.][0-9]+)?$/) effbin["missing"]++
    else if (eff+0 < 55) effbin["<55"]++
    else if (eff+0 < 65) effbin["55-64"]++
    else if (eff+0 < 80) effbin["65-79"]++
    else effbin[">=80"]++
    if (sample_n < 40) {
        sample_n++
        sample[sample_n] = "ts=" ts " domain=" domain " ip=" val("ip") \
            " class=" class " score=" score " eff=" eff " ckn=" ckn \
            " sf=" sf " ua=" ua
    }
}
END {
    printf "window_from=%d window_to=%d rows=%d pow=%d noninteractive_candidates=%d\n", \
        from,to,rows+0,pow+0,cand+0
    top(powdev,20,"=== POW BY DEVICE ===")
    top(powclass,20,"=== POW BY CLASS ===")
    top(canddomain,20,"=== CANDIDATE BY DOMAIN ===")
    top(candua,30,"=== CANDIDATE BY UA ===")
    top(candclass,20,"=== CANDIDATE BY CLASS ===")
    top(effbin,10,"=== CANDIDATE EFFECTIVE SCORE ===")
    top(candckn,10,"=== CANDIDATE COOKIE REGISTRY ===")
    top(candsf,10,"=== CANDIDATE SEC-FETCH ===")
    print "=== CANDIDATE SAMPLES (MAX 40) ==="
    for (i=1; i<=sample_n; i++) print sample[i]
}
' "$TMP"

