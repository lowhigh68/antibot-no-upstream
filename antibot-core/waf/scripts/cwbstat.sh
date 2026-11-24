#!/bin/bash
# Completed-work shadow report.  Reads rotated antibot logs and deduplicates
# cumulative snapshots by domain/cohort/60-second bucket.
set -euo pipefail

LOGDIR=${1:-/var/log/antibot}
MARK=${2:-/etc/antibot/cwb.deploy_ts}
[ -d "$LOGDIR" ] || { echo "CWBSTAT_ERROR log directory not found" >&2; exit 2; }
[ -r "$MARK" ] || { echo "CWBSTAT_ERROR marker not readable" >&2; exit 2; }
SINCE=$(tr -d '[:space:]' < "$MARK")
case "$SINCE" in ''|*[!0-9]*) echo "CWBSTAT_ERROR invalid marker" >&2; exit 2;; esac
UNTIL=$(date +%s)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/cwbstat.XXXXXX")
RAW="$TMP/raw.tsv"; DATA="$TMP/data.tsv"
trap 'rm -rf -- "$TMP"' EXIT HUP INT TERM

emit_logs() {
  local f
  while IFS= read -r -d '' f; do
    case "$f" in *.gz) gzip -cd -- "$f";; *) cat -- "$f";; esac
  done < <(find "$LOGDIR" -maxdepth 1 -type f -name 'antibot.log*' \
    -newermt "@$SINCE" -print0 | sort -z)
}

emit_logs | LC_ALL=C awk -v since="$SINCE" -v until="$UNTIL" '
function v(k) { return (k in f) ? f[k] : "-" }
{
  delete f
  for (i=1;i<=NF;i++) { p=index($i,"="); if (p>1) {
    k=substr($i,1,p-1); if (!(k in f)) f[k]=substr($i,p+1)
  }}
  ts=v("ts")+0; w=v("cwb"); n=v("cwbn"); b=v("cwbb")
  if (ts<since || ts>until) next
  if (w !~ /^[0-9]+([.][0-9]+)?$/ || n !~ /^[0-9]+$/ || b !~ /^[0-9]+$/) next
  ev=v("cwbev"); ro="-"
  if (ev ~ /^ro=[0-9]+([.][0-9]+)?$/) ro=substr(ev,4)
  ck=v("ck"); ap=v("ap"); ver=v("v")
  # First-party requires request-own richness plus its cookie, or an actor/
  # verified proof. Cookie-known alone is intentionally not enough.
  fp=(ap=="true" || ver=="true" ||
      (ck=="true" && ro ~ /^[0-9]+([.][0-9]+)?$/ && ro+0>=0.5))
  dom=v("domain"); cid=v("dgpcid"); bucket=int(ts/60)
  key=dom SUBSEP cid SUBSEP bucket
  if (!(key in maxw) || w+0 > maxw[key]+0) {
    maxw[key]=w+0; maxn[key]=n+0; maxb[key]=b+0
    outdom[key]=dom; outcid[key]=cid; outbucket[key]=bucket
  }
  if (fp) fp_seen[key]=1; else anon_seen[key]=1
}
END {
  for (key in maxw) {
    if (fp_seen[key] && anon_seen[key]) cls="mixed"
    else if (fp_seen[key]) cls="first_party"
    else cls="anonymous"
    print cls, maxw[key], maxn[key], maxb[key], outdom[key], outcid[key], outbucket[key]
  }
}' > "$RAW"

echo "=== CWB DISTRIBUTION ==="
echo "since=$SINCE until=$UNTIL"
echo "dedupe_key=domain+dgpcid+bucket60"
echo "rows=$(wc -l < "$RAW" | tr -d ' ')"
for cls in anonymous first_party mixed; do
  echo "--- $cls (cwbn>=20,cwbb>=3) ---"
  awk -v c="$cls" '$1==c && $3>=20 && $4>=3 {print $2}' "$RAW" | sort -n |
    awk '{a[NR]=$1} END {if(!NR) print "samples=0";
      else {p50=int((NR*50+99)/100);p95=int((NR*95+99)/100);p99=int((NR*99+99)/100);
      printf "samples=%d p50=%s p95=%s p99=%s max=%s\n",NR,a[p50],a[p95],a[p99],a[NR]}}'
done
echo "=== TOP MIXED COHORTS ==="
awk '$1=="mixed" && $3>=20 && $4>=3 {print $2,$3,$4,$5,$6,$7}' "$RAW" | sort -nr | head -20
echo "CWBSTAT_OK"
