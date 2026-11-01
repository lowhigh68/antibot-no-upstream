#!/bin/bash
# P1.4 signing/replay tests.  All keys, bundles and policy state stay in /tmp.
set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
T=$(mktemp -d /tmp/fleet-policy-test.XXXXXX) || exit 2
trap 'rm -rf "$T"' EXIT INT TERM
STATE="$T/state"
BUNDLES="$T/bundles"
mkdir -p "$STATE" "$BUNDLES"
pass=0 fail=0

want() {
    local name=$1; shift
    if "$@"; then pass=$((pass + 1))
    else fail=$((fail + 1)); echo "FAIL fleet_policyctl: $name" >&2; fi
}
contains() { grep -qF "$2" "$1"; }
state_sequence() { grep -q "^sequence=$2$" "$1"; }

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$T/private.pem" >/dev/null 2>&1 || exit 2
chmod 0600 "$T/private.pem"
openssl pkey -in "$T/private.pem" -pubout -out "$T/public.pem" \
  >/dev/null 2>&1 || exit 2

cat > "$T/policyctl-fake.sh" <<'EOF'
#!/bin/bash
set -u
[ "${1:-}" = publish ] || exit 2
[ "${POLICYCTL_FAIL:-0}" = 0 ] || exit 1
mkdir -p "$ANTIBOT_POLICY_DIR"
if [ -r "$ANTIBOT_POLICY_DIR/active.json" ]; then
    cp "$ANTIBOT_POLICY_DIR/active.json" "$ANTIBOT_POLICY_DIR/last-good.json"
else
    cp "$2" "$ANTIBOT_POLICY_DIR/last-good.json"
fi
cp "$2" "$ANTIBOT_POLICY_DIR/active.json"
echo "POLICY_PROMOTED test"
EOF
chmod +x "$T/policyctl-fake.sh"

cat > "$T/template.lua" <<'EOF'
return {
  schema = "1", version = "__VERSION__",
  global = { settings = { l7_admission = { status = __STATUS__ } } },
  servers = {}, tenants = {}, principals = {},
}
EOF
sed -e 's/__VERSION__/fleet-v1/' -e 's/__STATUS__/430/' \
  "$T/template.lua" > "$T/v1.lua"
sed -e 's/__VERSION__/fleet-v2/' -e 's/__STATUS__/431/' \
  "$T/template.lua" > "$T/v2.lua"

fp() {
    FLEET_POLICY_TEST_MODE=1 ANTIBOT_POLICY_DIR="$STATE" \
      ANTIBOT_FLEET_PUBLIC_KEY="$T/public.pem" \
      ANTIBOT_FLEET_STATE="$STATE/fleet-release.state" \
      POLICYCTL="$T/policyctl-fake.sh" RESTY="$RESTY" \
      bash "$HERE/fleet_policyctl.sh" "$@"
}

want "build signed v1" fp build 10 "$T/v1.lua" "$BUNDLES/r10" \
  "$T/private.pem" 3600
chmod 0644 "$T/private.pem"
if fp build 8 "$T/v1.lua" "$BUNDLES/insecure-private" \
  "$T/private.pem" 3600 > "$T/insecure-private.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: insecure private key accepted" >&2
else pass=$((pass + 1)); fi
want "private key mode reason" contains "$T/insecure-private.out" \
  'private key phai co mode 0400 hoac 0600'
chmod 0600 "$T/private.pem"
want "bundle has exactly three files" test \
  "$(find "$BUNDLES/r10" -maxdepth 1 -type f | wc -l)" -eq 3
want "bundle is readable by transport account" test \
  "$(stat -c '%a' "$BUNDLES/r10")" = 755
want "verify signed v1" fp verify "$BUNDLES/r10"
chmod 0666 "$T/public.pem"
if fp verify "$BUNDLES/r10" > "$T/insecure-key" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: writable public key accepted" >&2
else pass=$((pass + 1)); fi
want "writable public key reason" contains "$T/insecure-key" 'public key khong doc duoc/khong an toan'
chmod 0644 "$T/public.pem"
want "apply delegates and records sequence" fp apply "$BUNDLES/r10"
want "active published" test -s "$STATE/active.json"
want "state records sequence 10" state_sequence "$STATE/fleet-release.state" 10

fp apply "$BUNDLES/r10" > "$T/idempotent" 2>&1
want "same release is idempotent only while active matches" contains \
  "$T/idempotent" 'FLEET_ALREADY_APPLIED sequence=10'

want "build same sequence different policy" fp build 10 "$T/v2.lua" \
  "$BUNDLES/r10-other" "$T/private.pem" 3600
if fp apply "$BUNDLES/r10-other" > "$T/collision" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: sequence collision accepted" >&2
else pass=$((pass + 1)); fi
want "collision reason" contains "$T/collision" 'sequence da dung'

want "build lower sequence" fp build 9 "$T/v1.lua" "$BUNDLES/r9" \
  "$T/private.pem" 3600
if fp apply "$BUNDLES/r9" > "$T/replay" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: downgrade accepted" >&2
else pass=$((pass + 1)); fi
want "downgrade reason" contains "$T/replay" 'downgrade/replay'

cp -a "$BUNDLES/r10" "$BUNDLES/tamper-policy"
printf 'x' >> "$BUNDLES/tamper-policy/policy.json"
if fp verify "$BUNDLES/tamper-policy" > "$T/tamper-policy.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: tampered policy accepted" >&2
else pass=$((pass + 1)); fi
want "tampered policy reason" contains "$T/tamper-policy.out" 'policy hash khong khop'

cp -a "$BUNDLES/r10" "$BUNDLES/tamper-manifest"
sed -i 's/sequence=10/sequence=11/' "$BUNDLES/tamper-manifest/manifest.txt"
if fp verify "$BUNDLES/tamper-manifest" > "$T/tamper-manifest.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: bad signature accepted" >&2
else pass=$((pass + 1)); fi
want "bad signature reason" contains "$T/tamper-manifest.out" 'chu ky khong hop le'

FLEET_NOW=1000 FLEET_POLICY_TEST_MODE=1 ANTIBOT_POLICY_DIR="$STATE" \
  ANTIBOT_FLEET_PUBLIC_KEY="$T/public.pem" POLICYCTL="$T/policyctl-fake.sh" \
  RESTY="$RESTY" bash "$HERE/fleet_policyctl.sh" build 11 "$T/v2.lua" \
  "$BUNDLES/expired" "$T/private.pem" 10 >/dev/null
if FLEET_NOW=2000 fp verify "$BUNDLES/expired" > "$T/expired.out" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: expired release accepted" >&2
else pass=$((pass + 1)); fi
want "expired reason" contains "$T/expired.out" 'release da het han'

want "build next release" fp build 11 "$T/v2.lua" "$BUNDLES/r11" \
  "$T/private.pem" 3600
before=$(sha256sum "$STATE/fleet-release.state" | awk '{print $1}')
if POLICYCTL_FAIL=1 fp apply "$BUNDLES/r11" > "$T/gate-fail" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: failed P1.1 gate accepted" >&2
else pass=$((pass + 1)); fi
want "failed P1.1 leaves sequence state unchanged" test "$before" = \
  "$(sha256sum "$STATE/fleet-release.state" | awk '{print $1}')"
want "successful next release" fp apply "$BUNDLES/r11"
want "state advances to 11" state_sequence "$STATE/fleet-release.state" 11

# A local LKG rollback deliberately does not roll the signed sequence back.
# Reusing the consumed bundle would silently undo the emergency action.
cp "$BUNDLES/r10/policy.json" "$STATE/active.json"
if fp apply "$BUNDLES/r11" > "$T/consumed" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: consumed release restored rollback" >&2
else pass=$((pass + 1)); fi
want "rollback requires new signed sequence" contains "$T/consumed" \
  'sequence da consume nhung active khac'

fp status > "$T/status"
want "status reports key fingerprint" contains "$T/status" 'fleet_key=ready fingerprint='
want "status reports applied sequence" contains "$T/status" \
  'fleet_release=applied sequence=11'

cp "$STATE/fleet-release.state" "$T/good-state"
printf 'corrupt\n' > "$STATE/fleet-release.state"
if fp status > "$T/corrupt-state" 2>&1; then
    fail=$((fail + 1)); echo "FAIL fleet_policyctl: corrupt sequence state reported green" >&2
else pass=$((pass + 1)); fi
want "corrupt state reason" contains "$T/corrupt-state" \
  'fleet_release=degraded reason=invalid_state'
cp "$T/good-state" "$STATE/fleet-release.state"

echo "fleet_policyctl_test: $pass qua, $fail hong"
[ "$fail" -eq 0 ]
