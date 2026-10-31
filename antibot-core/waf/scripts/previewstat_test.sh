#!/usr/bin/env bash
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/previewstat-test.XXXXXX") || exit 1
trap 'rm -rf -- "$T"' EXIT HUP INT TERM
pass=0 fail=0
ok() { if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); fi; }
has() { grep -qE -- "$2" "$1"; }

cat > "$T/antibot.log" <<'EOF'
[x] [antibot] ts=100 domain=a.test class=navigation ip=1.1.1.1 ua=WhatsApp/2 score=74.6 eff=74.6 action=challenge ckn=- sf=0 m=GET drule=pow_challenge
[x] [antibot] ts=101 domain=a.test class=navigation ip=1.1.1.2 ua=curl/8 score=60 eff=60 action=challenge ckn=false sf=0 m=GET drule=pow_challenge
[x] [antibot] ts=102 domain=a.test class=navigation ip=1.1.1.3 ua=Browser score=60 eff=60 action=challenge ckn=true sf=1 m=GET drule=pow_challenge dev=desktop_chrome
[x] [antibot] ts=103 domain=a.test class=navigation ip=1.1.1.4 ua=POSTTool score=60 eff=60 action=challenge ckn=- sf=0 m=POST drule=pow_challenge dev=http_client
[x] [antibot] ts=104 domain=a.test class=navigation ip=1.1.1.5 ua=curl/8 score=90 eff=90 action=block ckn=- sf=0 m=GET drule=score_block dev=http_client
EOF
# Add dev fields to the first two rows without relying on fixture token order.
sed -i '1s/$/ dev=http_client/;2s/$/ dev=http_client/' "$T/antibot.log"
printf '%s\n' '[x] [antibot] ts=105 domain=b.test class=unknown ip=2.2.2.2 ua=Tool/1 score=50 eff=50 action=challenge ckn=- sf=0 m=HEAD drule=pow_challenge dev=http_client' \
    | gzip -c > "$T/antibot.log.1.gz"

bash "$HERE/previewstat.sh" 100 105 "$T" > "$T/out"
ok has "$T/out" '^window_from=100 window_to=105 rows=6 pow=5 noninteractive_candidates=3$'
ok has "$T/out" '^[[:space:]]+2[[:space:]]+a\.test$'
ok has "$T/out" '^[[:space:]]+1[[:space:]]+b\.test$'
ok has "$T/out" '^[[:space:]]+2[[:space:]]+navigation$'
ok has "$T/out" '^[[:space:]]+1[[:space:]]+unknown$'
ok has "$T/out" '^[[:space:]]+1[[:space:]]+65-79$'
ok has "$T/out" '^[[:space:]]+1[[:space:]]+55-64$'
ok has "$T/out" '^[[:space:]]+1[[:space:]]+<55$'
ok has "$T/out" 'ua=WhatsApp/2'
ok has "$T/out" 'ua=Tool/1'

if bash "$HERE/previewstat.sh" bad 105 "$T" >/dev/null 2>&1; then
    fail=$((fail+1))
else
    pass=$((pass+1))
fi

echo "previewstat_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]

