#!/bin/bash
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d /tmp/healthstat-test.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
pass=0 fail=0
want() {
    local name=$1 pattern=$2 file=$3
    if grep -qE "$pattern" "$file"; then pass=$((pass+1))
    else fail=$((fail+1)); echo "FAIL healthstat: $name" >&2; fi
}

mkdir -p "$T/live/async" "$T/live/waf/scripts" "$T/log" "$T/policy" "$T/bin"
for f in ' pver=' ' dschema=' ' dkind=' ' dup=' ' autuptime=' \
         ' epuptime=' ' dgpcid=' ' dgpcwork=' ' ckn='; do
    printf '%s\n' "$f" >> "$T/live/async/logger.lua"
done

cat > "$T/live/waf/scripts/policyctl.sh" <<'EOF'
#!/bin/bash
echo 'active.json present version=test-v1 bytes=100'
echo 'last-good.json present version=test-v0 bytes=100'
EOF
chmod +x "$T/live/waf/scripts/policyctl.sh"

cat > "$T/live/waf/scripts/feedbackctl.sh" <<'EOF'
#!/bin/bash
echo 'feedback active=3 expired=1 true_bot=1 legit_automation=0 human_fp=1 capacity_only=1'
EOF
chmod +x "$T/live/waf/scripts/feedbackctl.sh"

cat > "$T/bin/redis-cli" <<'EOF'
#!/bin/bash
args=" $* "
case "$args" in
  *' PING '*) echo PONG ;;
  *' DBSIZE '*) echo 123 ;;
  *' GET threat:last_sync '*) echo 1990 ;;
  *' GET mon:last_sync '*) echo 1980 ;;
  *' GET threat:stats '*) echo '{"ip":10,"asn_rep":20}' ;;
  *" --scan --pattern mon:srcsync:* "*) echo mon:srcsync:openai ;;
  *' GET mon:srcsync:openai '*) echo 1970 ;;
  *' GET mon:src:openai '*) echo 42 ;;
esac
EOF
chmod +x "$T/bin/redis-cli"

cat > "$T/log/antibot.log" <<'EOF'
[x] [antibot] ts=1950 domain=a.test class=navigation id=id1 ip=1.1.1.1 action=challenge reason=score ckn=true autp=gptbot auttier=operator autuptime=2.500 ep=wp_oembed_embed epuptime=2.500 dgpcid=cohort-a dgpcwork=4.500 dgdeg=false pver=test-v1+aaaa dschema=1 dkind=challenge drule=pow dmode=enforce dup=false
[x] [antibot] ts=1960 domain=a.test class=navigation id=id1 ip=1.1.1.1 action=challenge reason=score ckn=true autp=gptbot auttier=operator autuptime=- ep=wp_oembed_embed epuptime=- dgpcid=cohort-a dgpcwork=6.500 cbdeg=true pver=test-v1+aaaa dschema=1 dkind=challenge drule=pow dmode=enforce dup=false
[x] [antibot] ts=1970 domain=a.test class=navigation id=id1 ip=1.1.1.1 action=allow reason=verified_human dev=verified_fastpath ckn=true autp=- auttier=- autuptime=- ep=- epuptime=- dgpcid=- dgpcwork=- pver=test-v1+aaaa dschema=1 dkind=policy drule=verified_cookie dmode=enforce dup=true
[x] [antibot] ts=1980 domain=b.test class=navigation id=id2 ip=2.2.2.2 action=allow reason=good_bot_verified ckn=- autp=googlebot auttier=verified autuptime=1.250 ep=wp_rest_posts_item epuptime=1.250 dgpcid=cohort-b dgpcwork=2.000 pver=test-v1+aaaa dschema=1 dkind=policy drule=goodbot dmode=enforce dup=true
EOF
cat > "$T/log/error.log" <<'EOF'
1970 harmless
EOF

OUT="$T/out"
NOW=2000 LIVE="$T/live" POLICY_DIR="$T/policy" \
POLICYCTL="$T/live/waf/scripts/policyctl.sh" ERROR_LOG="$T/log/error.log" \
HEALTH_REDIS_CLI="$T/bin/redis-cli" ANTIBOT_REDIS_PASS_FILE="$T/no-pass" \
HEALTH_OPERATOR_SOURCES="openai" \
bash "$HERE/healthstat.sh" 1900 "$T/log/antibot.log" > "$OUT"
rc=$?

want "exit green" '^$' <( [ "$rc" -eq 0 ] && echo || echo x )
want "window rows" 'rows=4 ' "$OUT"
want "policy stable" 'version_state=ok policy_versions=1 schemas=1' "$OUT"
want "feedback coverage" 'feedback active=3 expired=1 true_bot=1 legit_automation=0 human_fp=1 capacity_only=1' "$OUT"
want "decision split" 'decision rows=4 upstream=2 local=2 unknown=0 degraded_rows=1' "$OUT"
want "challenge loop" 'challenge issued=2 repeated_subjects=1 recovered_subjects=1' "$OUT"
want "known-cookie FP guard" 'fp_guard known_cookie=2/3 verified_human=0/1 verified_bot=0/1' "$OUT"
want "principal cost" 'gptbot work=2.500 requests=1' "$OUT"
want "endpoint cost" 'wp_oembed_embed work=2.500 requests=1' "$OUT"
want "cohort max not sum" 'cohort-a max_work=6.500 observations=2' "$OUT"
want "redis health" 'redis=ok dbsize=123' "$OUT"
want "feed age" 'source\[openai\] count=42 age_s=30' "$OUT"
want "logger errors" 'logger_error_rows=0' "$OUT"
want "policy errors" 'policy_error_rows=0' "$OUT"

# Missing schema must fail before producing reassuring zeroes.
printf ' pver=\n' > "$T/live/async/logger.lua"
if NOW=2000 LIVE="$T/live" bash "$HERE/healthstat.sh" 1900 \
   "$T/log/antibot.log" > "$T/gate" 2>&1; then
    fail=$((fail+1)); echo "FAIL healthstat: schema gate accepted old logger" >&2
else
    pass=$((pass+1))
fi
want "schema gate explains failure" 'logger schema thieu' "$T/gate"

# Hai danh sach ten feed phai KHOP: `SOURCES` trong monitor_ip_sync.sh (noi
# dong bo) va `OPERATOR_SOURCES` trong healthstat.sh (noi bao suc khoe). Lech
# nhau thi sinh canh bao TU GAY RA: mot ten co o healthstat ma khong con o
# SOURCES se khong bao gio co `mon:srcsync:<ten>` -> bao dong vinh vien ve mot
# feed khong ai dong bo; nguoc lai, mot feed that bai se khong ai bao.
#
# Do duoc 2026-10-29: go `openai-chatgpt-user` khoi SOURCES ma quen healthstat
# thi `readable=7/8` keu mai mai. Ghim bang phep SO, khong bang chu thich.
MIS="$HERE/../../../nginx/scripts/monitor_ip_sync.sh"
if [ -f "$MIS" ]; then
    src_names=$(sed -n '/^SOURCES=(/,/^)/p' "$MIS" \
        | grep -o '"[^|"]*|' | tr -d '"|' | sort | tr '\n' ' ')
    hs_names=$(grep -o 'HEALTH_OPERATOR_SOURCES:-"[^"]*"' "$HERE/healthstat.sh" \
        | sed 's/.*:-"//; s/"$//' | tr ' ' '\n' | sort | tr '\n' ' ')
    if [ -z "$src_names" ] || [ -z "$hs_names" ]; then
        fail=$((fail+1))
        echo "FAIL healthstat: khong trich duoc danh sach feed (src='$src_names' hs='$hs_names')" >&2
    elif [ "$src_names" = "$hs_names" ]; then
        pass=$((pass+1))
    else
        fail=$((fail+1))
        echo "FAIL healthstat: danh sach feed LECH nhau" >&2
        echo "  monitor_ip_sync SOURCES : $src_names" >&2
        echo "  healthstat OPERATOR     : $hs_names" >&2
    fi
else
    fail=$((fail+1))
    echo "FAIL healthstat: khong thay $MIS (phep so lech feed khong chay)" >&2
fi

echo "healthstat_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
