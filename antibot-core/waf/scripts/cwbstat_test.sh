#!/bin/bash
# Contract for cwbstat.sh.
#
# The first version of this file asserted with bare `grep -q` under `set -e`
# and cleaned up from an EXIT trap.  A successful trap command RESETS the
# shell exit status, so every failing assertion still exited 0: nine separate
# mutations of cwbstat.sh (cookie-only first-party, no richness floor, actor
# and verified proofs dropped, cohort or bucket removed from the dedupe key,
# first snapshot kept instead of the max, the mixed class hidden, the deploy
# marker ignored) all passed.  Assertions are therefore counted explicitly
# here and the trap re-raises the recorded status.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
pass=0
fail=0
cleanup() { local rc=$?; rm -rf -- "$TMP"; exit "$rc"; }
trap cleanup EXIT HUP INT TERM

ok() { # ok <description> <condition-rc>
  if [ "$2" -eq 0 ]; then pass=$((pass + 1))
  else fail=$((fail + 1)); printf 'FAIL: %s\n' "$1" >&2; fi
}
has() { # has <description> <pattern>
  printf '%s\n' "$OUT" | grep -qE -- "$2"; ok "$1" $?
}
hasnt() {
  printf '%s\n' "$OUT" | grep -qE -- "$2"
  if [ $? -ne 0 ]; then pass=$((pass + 1))
  else fail=$((fail + 1)); printf 'FAIL: %s\n' "$1" >&2; fi
}

mkdir -p "$TMP/log"
MARK="$TMP/mark"
NOW=$(date +%s)
echo $((NOW - 600)) > "$MARK"

# cohort1: three snapshots in ONE bucket.  Two anonymous plus one carrying a
# real session (ro=0.80 ck=true) makes it `mixed`, and the deduplicated value
# must be the LARGEST snapshot, not the first.
# cohort2: a pure first-party cohort.
# cohort3: `ck=true` with ro BELOW the floor, so it must count as anonymous.
# cohort4: no cookie at all but a valid actor -> first_party.
# cohort5: verified -> first_party.
{
  echo "[x] ts=$((NOW-9)) domain=a.test class=navigation dgpcid=cohort1 cwb=100 cwbn=25 cwbb=3 cwbev=ro=0.00 ck=false ckn=- ap=false v=false"
  echo "[x] ts=$((NOW-8)) domain=a.test class=navigation dgpcid=cohort1 cwb=101 cwbn=26 cwbb=3 cwbev=ro=0.80 ck=true ckn=true ap=false v=false"
  echo "[x] ts=$((NOW-7)) domain=a.test class=navigation dgpcid=cohort1 cwb=102 cwbn=27 cwbb=3 cwbev=ro=0.00 ck=false ckn=false ap=false v=false"
  echo "[x] ts=$((NOW-6)) domain=b.test class=navigation dgpcid=cohort2 cwb=300 cwbn=30 cwbb=4 cwbev=ro=0.80 ck=true ckn=true ap=false v=false"
  echo "[x] ts=$((NOW-6)) domain=c.test class=navigation dgpcid=cohort3 cwb=400 cwbn=40 cwbb=5 cwbev=ro=0.20 ck=true ckn=true ap=false v=false"
  echo "[x] ts=$((NOW-6)) domain=d.test class=navigation dgpcid=cohort4 cwb=500 cwbn=41 cwbb=5 cwbev=ro=0.00 ck=false ckn=false ap=true v=false"
  echo "[x] ts=$((NOW-6)) domain=e.test class=navigation dgpcid=cohort5 cwb=600 cwbn=42 cwbb=5 cwbev=ro=0.00 ck=false ckn=- ap=false v=true"
  # Two DIFFERENT cohorts on the SAME domain in the SAME bucket.  Without the
  # cohort in the dedupe key these two collapse into one row and the larger
  # value hides the smaller, so this pair is what makes the key observable.
  echo "[x] ts=$((NOW-5)) domain=f.test class=navigation dgpcid=cohortA cwb=700 cwbn=43 cwbb=5 cwbev=ro=0.00 ck=false ckn=- ap=false v=false"
  echo "[x] ts=$((NOW-5)) domain=f.test class=navigation dgpcid=cohortB cwb=800 cwbn=44 cwbb=5 cwbev=ro=0.00 ck=false ckn=- ap=false v=false"
} > "$TMP/log/antibot.log"

# Same cohort, a DIFFERENT 60s bucket: proves the bucket is part of the key.
# Rotated .gz must be read too.
printf '%s\n' \
  "[x] ts=$((NOW-200)) domain=a.test class=navigation dgpcid=cohort1 cwb=90 cwbn=22 cwbb=3 cwbev=ro=0.00 ck=false ckn=- ap=false v=false" \
  | gzip -c > "$TMP/log/antibot.log.1.gz"

# Before the marker: must be excluded entirely.
echo "[x] ts=$((NOW-99999)) domain=z.test class=navigation dgpcid=oldcohort cwb=9999 cwbn=99 cwbb=9 cwbev=ro=0.00 ck=false ckn=- ap=false v=false" \
  >> "$TMP/log/antibot.log"

OUT=$(bash "$HERE/cwbstat.sh" "$TMP/log" "$MARK")

has  "header names the dedupe key" '^dedupe_key=domain\+dgpcid\+bucket60$'
has  "script completes"            '^CWBSTAT_OK$'
has  "cookie state preserves unknown" '^cookie_state=true=2 false=2 unknown=4$'
# 5 cohorts in the current bucket + cohort1 in an older bucket from the .gz.
has  "rows counts cohort-buckets, not log lines" '^rows=8$'
# Raw rows print only for the mixed class, so two ANONYMOUS cohorts sharing
# one domain are observable through the counts: dropping the cohort from the
# dedupe key merges them, taking rows 8 -> 7 and anonymous samples 4 -> 3.
hasnt "rows before the marker are excluded"      'oldcohort|9999'

# Classification. cohort1 is mixed; cohort2 (ck+ro) and cohort4 (actor) and
# cohort5 (verified) are first_party; cohort3 (ck with ro<0.5) is anonymous.
# The .gz row for cohort1 in the older bucket is anonymous as well, so the
# counts are: anonymous 2, first_party 3, mixed 1.
has "mixed cohort is counted once"          '^samples=1 p50=102 '
has "the three proof paths are first_party" '^samples=3 p50=500 '
has "cookie with ro<0.5 is NOT first_party" '^samples=4 p50=400 .*max=800$'
# The largest snapshot wins within a bucket (100/101/102 -> 102).
has "mixed cohort keeps the LARGEST snapshot" 'p50=102 p95=102 p99=102 max=102'
# Eight rows only add up when the rotated .gz is read: it supplies cohort1's
# older bucket. Without it the count is 7.
has "rotated .gz is read"                     '^rows=8$'

# The mixed cohort must also be listed on its own, which is the whole point:
# it is the signal that a crawler and a real session share one cohort.
has "mixed cohorts are listed separately" '^=== TOP MIXED COHORTS ==='
has "the mixed cohort appears in that list" '^102 27 3 a.test cohort1 '

# Error paths: a missing marker or directory must not be reported as data.
set +e
bash "$HERE/cwbstat.sh" "$TMP/log" "$TMP/no_such_marker" >/dev/null 2>&1
ok "a missing marker exits non-zero" "$([ $? -ne 0 ] && echo 0 || echo 1)"
bash "$HERE/cwbstat.sh" "$TMP/no_such_dir" "$MARK" >/dev/null 2>&1
ok "a missing log directory exits non-zero" "$([ $? -ne 0 ] && echo 0 || echo 1)"
set -e

printf 'cwbstat_test: %d pass, %d fail\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
