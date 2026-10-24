#!/bin/bash
# End-to-end P1.1 publisher/LKG test.  Everything lives in mktemp; this never
# touches /etc/antibot, nginx or the production policy.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
STATE="$T/state"
mkdir -p "$STATE"
PASS="$T/pass.sh"
FAIL="$T/fail.sh"
printf '#!/bin/bash\nexit 0\n' > "$PASS"
printf '#!/bin/bash\nexit 1\n' > "$FAIL"

pass=0
fail=0
want() {
    local name="$1"; shift
    if "$@"; then pass=$((pass + 1))
    else fail=$((fail + 1)); echo "FAIL policy_store_test: $name" >&2
    fi
}
has_version() {
    grep -q '"version":"'"$2"'"' "$1"
}
contains() {
    case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac
}
publish() {
    local candidate="$1" tests="$2"
    POLICYCTL_TEST_MODE=1 ANTIBOT_POLICY_DIR="$STATE" \
      POLICY_TEST_CMD="$tests" RESTY="$RESTY" \
      bash "$HERE/policyctl.sh" publish "$candidate" >/dev/null 2>&1
}

make_candidate() {
    local path="$1" version="$2" status="$3"
    sed -e "s/__VERSION__/$version/" -e "s/__STATUS__/$status/" \
      "$T/template.lua" > "$path"
}

printf '%s\n' \
  'return {' \
  '  schema = "1", version = "__VERSION__",' \
  '  global = { settings = { l7_admission = { status = __STATUS__ } } },' \
  '  servers = {}, tenants = {}, principals = {},' \
  '}' > "$T/template.lua"

make_candidate "$T/v1.lua" "v1" 430
make_candidate "$T/v2.lua" "v2" 431
make_candidate "$T/v3.lua" "v3" 432

want "first publish succeeds" publish "$T/v1.lua" "$PASS"
want "first active is v1" has_version "$STATE/active.json" v1
want "first publish seeds LKG" has_version "$STATE/last-good.json" v1

want "second publish succeeds" publish "$T/v2.lua" "$PASS"
want "second active is v2" has_version "$STATE/active.json" v2
want "old active becomes LKG" has_version "$STATE/last-good.json" v1

before_active=$(sha256sum "$STATE/active.json" | awk '{print $1}')
before_lkg=$(sha256sum "$STATE/last-good.json" | awk '{print $1}')
printf 'return { schema="1", version="bad", typo=true }\n' > "$T/bad.lua"
if publish "$T/bad.lua" "$PASS"; then
    fail=$((fail + 1)); echo "FAIL policy_store_test: invalid candidate promoted" >&2
else
    pass=$((pass + 1))
fi
want "validator failure preserves active" test "$before_active" = \
  "$(sha256sum "$STATE/active.json" | awk '{print $1}')"
want "validator failure preserves LKG" test "$before_lkg" = \
  "$(sha256sum "$STATE/last-good.json" | awk '{print $1}')"

if publish "$T/v3.lua" "$FAIL"; then
    fail=$((fail + 1)); echo "FAIL policy_store_test: test failure promoted" >&2
else
    pass=$((pass + 1))
fi
want "test failure preserves active" test "$before_active" = \
  "$(sha256sum "$STATE/active.json" | awk '{print $1}')"
want "test failure preserves LKG" test "$before_lkg" = \
  "$(sha256sum "$STATE/last-good.json" | awk '{print $1}')"

POLICYCTL_TEST_MODE=1 ANTIBOT_POLICY_DIR="$STATE" RESTY="$RESTY" \
  bash "$HERE/policyctl.sh" rollback >/dev/null 2>&1
want "rollback restores LKG into active" has_version "$STATE/active.json" v1
want "rollback does not consume LKG" has_version "$STATE/last-good.json" v1

# A corrupt active must never overwrite the good LKG during a later publish.
printf '{corrupt' > "$STATE/active.json"
want "publish recovers from corrupt active" publish "$T/v3.lua" "$PASS"
want "recovered active is v3" has_version "$STATE/active.json" v3
want "existing valid LKG survives corrupt active" has_version "$STATE/last-good.json" v1

status=$(POLICYCTL_TEST_MODE=1 ANTIBOT_POLICY_DIR="$STATE" RESTY="$RESTY" \
  bash "$HERE/policyctl.sh" status)
want "status reports active version" contains "$status" "active.json present version=v3"
want "status reports LKG version" contains "$status" "last-good.json present version=v1"

if find "$STATE" -maxdepth 1 -name '*.tmp.*' -print | grep -q .; then
    fail=$((fail + 1)); echo "FAIL policy_store_test: temp artifact remains" >&2
else
    pass=$((pass + 1))
fi

echo "policy_store_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
