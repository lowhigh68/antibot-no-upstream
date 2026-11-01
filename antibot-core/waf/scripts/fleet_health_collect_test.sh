#!/bin/bash
set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d /tmp/fleet-health-test.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
pass=0 fail=0
want() {
    local name=$1 pattern=$2 file=$3
    if grep -qE "$pattern" "$file"; then pass=$((pass + 1))
    else fail=$((fail + 1)); echo "FAIL fleet_health: $name" >&2; fi
}

cat > "$T/ssh" <<'EOF'
#!/bin/bash
args=" $* "
case "$args" in
  *'@bad.example '*) echo unavailable >&2; exit 255 ;;
  *'/healthstat.sh '*) echo 'host=fake rows=10 version_state=ok'; exit 0 ;;
  *'/fleet_policyctl.sh status '*) echo 'fleet_release=applied sequence=7'; exit 0 ;;
esac
exit 2
EOF
chmod +x "$T/ssh"
printf '# fleet\na.example\nb.example\n' > "$T/hosts"

SSH_BIN="$T/ssh" bash "$HERE/fleet_health_collect.sh" "$T/hosts" \
  "$T/report" 1234 > "$T/out"
rc=$?
if [ "$rc" -eq 0 ]; then pass=$((pass + 1)); else fail=$((fail + 1)); fi
want "collector marker" 'FLEET_HEALTH_COLLECTED nodes=2 failures=0' "$T/out"
want "summary has first node" '^host=a\.example health_rc=0 release_rc=0$' \
  "$T/report/summary.txt"
want "summary has exact window" 'fleet_nodes=2 failures=0 since=1234' \
  "$T/report/summary.txt"
want "health output retained" 'version_state=ok' "$T/report/a.example.health.txt"
want "release output retained" 'fleet_release=applied sequence=7' \
  "$T/report/b.example.release.txt"

printf 'a.example\nbad.example\n' > "$T/hosts-bad"
if SSH_BIN="$T/ssh" bash "$HERE/fleet_health_collect.sh" "$T/hosts-bad" \
  "$T/report-bad" 1234 > "$T/bad.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_health: partial failure returned green" >&2
else pass=$((pass + 1)); fi
want "partial report is still published" 'fleet_nodes=2 failures=1' \
  "$T/report-bad/summary.txt"

printf '%s\n' '--ProxyCommand=bad' > "$T/hosts-inject"
if SSH_BIN="$T/ssh" bash "$HERE/fleet_health_collect.sh" "$T/hosts-inject" \
  "$T/inject" 1234 > "$T/inject.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_health: option-like host accepted" >&2
else pass=$((pass + 1)); fi
want "invalid host explains rejection" 'host khong hop le' "$T/inject.out"

echo "fleet_health_collect_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
