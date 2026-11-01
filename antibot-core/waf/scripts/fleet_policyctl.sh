#!/bin/bash
# P1.4 signed policy release gate.
#
# This tool is deliberately outside nginx.  Workers never execute it and the
# request path still reads only the policy already compiled in worker RAM.
# A signed bundle is transport evidence, not a shortcut around P1.1: `apply`
# always delegates to policyctl.sh, which validates, runs the full regression
# gate and atomically promotes active/LKG.
set -uo pipefail
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
TOOL=${POLICY_TOOL:-$ROOT/core/policy_tool.lua}
POLICYCTL=${POLICYCTL:-$HERE/policyctl.sh}
STATE_DIR=${ANTIBOT_POLICY_DIR:-/etc/antibot/policy}
POLICY_GROUP=${ANTIBOT_POLICY_GROUP:-nginx}
PUBLIC_KEY=${ANTIBOT_FLEET_PUBLIC_KEY:-$STATE_DIR/fleet-policy-rsa.pub}
RELEASE_STATE=${ANTIBOT_FLEET_STATE:-$STATE_DIR/fleet-release.state}
OPENSSL=${OPENSSL:-openssl}
NOW=${FLEET_NOW:-$(date +%s)}
MAX_CLOCK_SKEW=${FLEET_MAX_CLOCK_SKEW:-300}
MAX_TTL=${FLEET_MAX_TTL:-604800}

usage() {
    cat <<EOF
Dung:
  $0 build <sequence> <candidate.lua|json> <bundle-dir> <private-key> [ttl_s]
  $0 verify <bundle-dir>
  $0 apply <bundle-dir>
  $0 status

build chi chay tren controller giu private key. verify/apply chay tren node.
apply KHONG reload nginx va KHONG rollout node khac.
EOF
}

die() { echo "FLEET_POLICY_ERROR $*" >&2; return 1; }

is_uint() {
    local v=${1:-} max_digits=${2:-15}
    case "$v" in ''|*[!0-9]*) return 1 ;; esac
    [ "$v" = "0" ] || [ "${v#0}" = "$v" ] || return 1
    [ "${#v}" -le "$max_digits" ]
}

require_runtime() {
    is_uint "$NOW" 12 || { die "FLEET_NOW khong hop le"; return 1; }
    is_uint "$MAX_CLOCK_SKEW" 7 || { die "clock skew khong hop le"; return 1; }
    is_uint "$MAX_TTL" 7 || { die "max TTL khong hop le"; return 1; }
    [ -x "$RESTY" ] || { die "khong tim thay resty: $RESTY"; return 1; }
    [ -f "$TOOL" ] || { die "khong tim thay policy tool: $TOOL"; return 1; }
    command -v "$OPENSSL" >/dev/null 2>&1 || {
        die "khong tim thay openssl: $OPENSSL"; return 1;
    }
    command -v sha256sum >/dev/null 2>&1 || {
        die "khong tim thay sha256sum"; return 1;
    }
}

not_group_or_other_writable() {
    local mode
    mode=$(stat -c '%A' "$1" 2>/dev/null || :)  # e.g. -rw-r--r--
    [ "${#mode}" -eq 10 ] || return 1
    [ "${mode:5:1}" != w ] && [ "${mode:8:1}" != w ]
}

secure_public_key() {
    [ -r "$PUBLIC_KEY" ] && [ -f "$PUBLIC_KEY" ] && [ ! -L "$PUBLIC_KEY" ] \
      || return 1
    not_group_or_other_writable "$PUBLIC_KEY" || return 1
    if [ "${FLEET_POLICY_TEST_MODE:-0}" != "1" ]; then
        [ "$(stat -c '%u' "$PUBLIC_KEY" 2>/dev/null || :)" = 0 ] || return 1
    fi
}

marker_validate() {
    # Sets VALIDATED_VERSION.  The normalized temporary artifact is discarded;
    # P1.1 validates again immediately before promotion.
    local candidate=$1 tmp out rc
    tmp=$(mktemp) || return 1
    out=$(ANTIBOT_SRC="$ROOT/" "$RESTY" "$TOOL" validate "$candidate" "$tmp" 2>&1)
    rc=$?
    rm -f "$tmp"
    printf '%s\n' "$out"
    if [ "$rc" -ne 0 ] || ! printf '%s\n' "$out" | grep -q '^POLICY_VALID version='; then
        return 1
    fi
    VALIDATED_VERSION=$(printf '%s\n' "$out" \
        | sed -n 's/^POLICY_VALID version=//p' | tail -1)
    case "$VALIDATED_VERSION" in
        ''|*[!A-Za-z0-9._:+-]*) return 1 ;;
    esac
    [ "${#VALIDATED_VERSION}" -le 160 ]
}

read_manifest() {
    local bundle=$1 manifest="$1/manifest.txt" n
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || {
        die "bundle khong phai thu muc that: $bundle"; return 1;
    }
    for n in manifest.txt manifest.sig policy.json; do
        [ -f "$bundle/$n" ] && [ ! -L "$bundle/$n" ] || {
            die "bundle thieu/khong an toan: $n"; return 1;
        }
    done
    n=$(find "$bundle" -mindepth 1 -maxdepth 1 -type f -printf x 2>/dev/null \
        | wc -c)
    [ "$n" -eq 3 ] || { die "bundle phai co dung 3 tep"; return 1; }
    if find "$bundle" -mindepth 1 -maxdepth 1 ! -type f -print -quit \
       | grep -q .; then
        die "bundle chua entry khong phai regular file"; return 1
    fi
    mapfile -t MF_LINES < "$manifest" || return 1
    [ "${#MF_LINES[@]}" -eq 6 ] || {
        die "manifest phai co dung 6 dong"; return 1;
    }
    case "${MF_LINES[*]}" in *$'\r'*) die "manifest chua CR"; return 1 ;; esac
    [[ ${MF_LINES[0]} == schema=* ]] || { die "manifest sai schema"; return 1; }
    [[ ${MF_LINES[1]} == sequence=* ]] || { die "manifest sai sequence"; return 1; }
    [[ ${MF_LINES[2]} == version=* ]] || { die "manifest sai version"; return 1; }
    [[ ${MF_LINES[3]} == policy_sha256=* ]] || { die "manifest sai hash"; return 1; }
    [[ ${MF_LINES[4]} == created_epoch=* ]] || { die "manifest sai created"; return 1; }
    [[ ${MF_LINES[5]} == expires_epoch=* ]] || { die "manifest sai expires"; return 1; }
    MF_SCHEMA=${MF_LINES[0]#schema=}
    MF_SEQUENCE=${MF_LINES[1]#sequence=}
    MF_VERSION=${MF_LINES[2]#version=}
    MF_SHA=${MF_LINES[3]#policy_sha256=}
    MF_CREATED=${MF_LINES[4]#created_epoch=}
    MF_EXPIRES=${MF_LINES[5]#expires_epoch=}
    [ "$MF_SCHEMA" = "1" ] || { die "schema khong ho tro: $MF_SCHEMA"; return 1; }
    is_uint "$MF_SEQUENCE" 15 || { die "sequence khong hop le"; return 1; }
    case "$MF_VERSION" in
        ''|*[!A-Za-z0-9._:+-]*) die "version khong hop le"; return 1 ;;
    esac
    [ "${#MF_VERSION}" -le 160 ] || { die "version qua dai"; return 1; }
    case "$MF_SHA" in
        *[!0-9a-f]*|'') die "policy_sha256 khong hop le"; return 1 ;;
    esac
    [ "${#MF_SHA}" -eq 64 ] || { die "policy_sha256 sai do dai"; return 1; }
    is_uint "$MF_CREATED" 12 || { die "created_epoch khong hop le"; return 1; }
    is_uint "$MF_EXPIRES" 12 || { die "expires_epoch khong hop le"; return 1; }
    [ "$MF_EXPIRES" -gt "$MF_CREATED" ] || {
        die "expires_epoch phai sau created_epoch"; return 1;
    }
}

verify_bundle() {
    local bundle=$1 actual_sha
    require_runtime || return 1
    read_manifest "$bundle" || return 1
    secure_public_key || {
        die "public key khong doc duoc/khong an toan: $PUBLIC_KEY"; return 1;
    }
    "$OPENSSL" dgst -sha256 -verify "$PUBLIC_KEY" \
      -signature "$bundle/manifest.sig" "$bundle/manifest.txt" \
      >/dev/null 2>&1 || { die "chu ky khong hop le"; return 1; }
    actual_sha=$(sha256sum "$bundle/policy.json" | awk '{print $1}')
    [ "$actual_sha" = "$MF_SHA" ] || { die "policy hash khong khop"; return 1; }
    if [ "$MF_CREATED" -gt $((NOW + MAX_CLOCK_SKEW)) ]; then
        die "release den tu tuong lai (clock/replay)"; return 1
    fi
    if [ "$MF_EXPIRES" -lt $((NOW - MAX_CLOCK_SKEW)) ]; then
        die "release da het han"; return 1
    fi
    if [ $((MF_EXPIRES - MF_CREATED)) -gt "$MAX_TTL" ]; then
        die "release TTL vuot tran $MAX_TTL"; return 1
    fi
    if ! marker_validate "$bundle/policy.json"; then
        die "policy trong bundle khong qua validator"; return 1
    fi
    [ "$VALIDATED_VERSION" = "$MF_VERSION" ] || {
        die "manifest version khong khop compiled version"; return 1;
    }
    return 0
}

read_state() {
    local state=$1
    ST_SEQUENCE= ST_VERSION= ST_SHA= ST_APPLIED=
    [ -e "$state" ] || return 2
    [ -f "$state" ] && [ ! -L "$state" ] && [ -r "$state" ] || return 1
    not_group_or_other_writable "$state" || return 1
    if [ "${FLEET_POLICY_TEST_MODE:-0}" != "1" ] \
       && [ "$(stat -c '%u' "$state" 2>/dev/null || :)" != 0 ]; then
        return 1
    fi
    mapfile -t ST_LINES < "$state" || return 1
    [ "${#ST_LINES[@]}" -eq 5 ] || return 1
    [ "${ST_LINES[0]}" = "schema=1" ] || return 1
    [[ ${ST_LINES[1]} == sequence=* ]] || return 1
    [[ ${ST_LINES[2]} == version=* ]] || return 1
    [[ ${ST_LINES[3]} == policy_sha256=* ]] || return 1
    [[ ${ST_LINES[4]} == applied_epoch=* ]] || return 1
    ST_SEQUENCE=${ST_LINES[1]#sequence=}
    ST_VERSION=${ST_LINES[2]#version=}
    ST_SHA=${ST_LINES[3]#policy_sha256=}
    ST_APPLIED=${ST_LINES[4]#applied_epoch=}
    is_uint "$ST_SEQUENCE" 15 || return 1
    is_uint "$ST_APPLIED" 12 || return 1
    case "$ST_VERSION" in ''|*[!A-Za-z0-9._:+-]*) return 1 ;; esac
    case "$ST_SHA" in *[!0-9a-f]*|'') return 1 ;; esac
    [ "${#ST_SHA}" -eq 64 ] || return 1
}

prepare_state_dir() {
    if [ "${FLEET_POLICY_TEST_MODE:-0}" = "1" ]; then
        mkdir -p "$STATE_DIR" && chmod 0750 "$STATE_DIR"
    else
        [ "$(id -u)" = "0" ] || { die "apply phai chay root"; return 1; }
        install -d -m 0750 -o root -g "$POLICY_GROUP" "$STATE_DIR"
    fi
}

write_state() {
    local tmp
    tmp=$(mktemp "$STATE_DIR/.fleet-release.tmp.XXXXXX") || return 1
    if ! printf '%s\n' \
      'schema=1' \
      "sequence=$MF_SEQUENCE" \
      "version=$MF_VERSION" \
      "policy_sha256=$MF_SHA" \
      "applied_epoch=$NOW" > "$tmp"; then
        rm -f "$tmp"; return 1
    fi
    chmod 0640 "$tmp" || { rm -f "$tmp"; return 1; }
    if [ "${FLEET_POLICY_TEST_MODE:-0}" != "1" ]; then
        chown "root:$POLICY_GROUP" "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    sync -f "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$RELEASE_STATE" || { rm -f "$tmp"; return 1; }
    sync -f "$RELEASE_STATE" || return 1
    sync -f "$STATE_DIR" || return 1
}

active_version() {
    local active="$STATE_DIR/active.json"
    [ -r "$active" ] || return 1
    marker_validate "$active" >/dev/null 2>&1
}

command_build() {
    local sequence=${1:-} candidate=${2:-} output=${3:-} key=${4:-}
    local ttl=${5:-86400} parent base work normalized out version sha created expires key_mode key_uid
    require_runtime || return 1
    is_uint "$sequence" 15 || { die "sequence khong hop le"; return 1; }
    is_uint "$ttl" 7 || { die "ttl_s khong hop le"; return 1; }
    [ "$ttl" -gt 0 ] && [ "$ttl" -le "$MAX_TTL" ] || {
        die "ttl_s phai trong 1..$MAX_TTL"; return 1;
    }
    [ -f "$candidate" ] && [ ! -L "$candidate" ] || {
        die "candidate khong hop le: $candidate"; return 1;
    }
    [ -r "$key" ] && [ -f "$key" ] && [ ! -L "$key" ] || {
        die "private key khong doc duoc/khong an toan"; return 1;
    }
    key_mode=$(stat -c '%a' "$key" 2>/dev/null || :)
    key_uid=$(stat -c '%u' "$key" 2>/dev/null || :)
    case "$key_mode" in 400|600) ;; *)
        die "private key phai co mode 0400 hoac 0600"; return 1 ;;
    esac
    [ "$key_uid" = "$(id -u)" ] || {
        die "private key phai thuoc user dang build"; return 1;
    }
    [ -n "$output" ] || { die "thieu bundle-dir"; return 1; }
    [ ! -e "$output" ] || { die "bundle-dir da ton tai: $output"; return 1; }
    parent=$(dirname "$output"); base=$(basename "$output")
    mkdir -p "$parent" || return 1
    work=$(mktemp -d "$parent/.${base}.tmp.XXXXXX") || return 1
    normalized="$work/policy.json"
    out=$(ANTIBOT_SRC="$ROOT/" "$RESTY" "$TOOL" validate \
      "$candidate" "$normalized" 2>&1)
    if ! printf '%s\n' "$out" | grep -q '^POLICY_VALID version='; then
        printf '%s\n' "$out"; rm -rf "$work"
        die "candidate khong qua validator"; return 1
    fi
    version=$(printf '%s\n' "$out" | sed -n 's/^POLICY_VALID version=//p' | tail -1)
    case "$version" in ''|*[!A-Za-z0-9._:+-]*)
        rm -rf "$work"; die "compiled version khong an toan"; return 1 ;;
    esac
    sha=$(sha256sum "$normalized" | awk '{print $1}')
    created=$NOW; expires=$((created + ttl))
    printf '%s\n' \
      'schema=1' \
      "sequence=$sequence" \
      "version=$version" \
      "policy_sha256=$sha" \
      "created_epoch=$created" \
      "expires_epoch=$expires" > "$work/manifest.txt" || {
        rm -rf "$work"; return 1;
    }
    "$OPENSSL" dgst -sha256 -sign "$key" \
      -out "$work/manifest.sig" "$work/manifest.txt" >/dev/null 2>&1 || {
        rm -rf "$work"; die "khong ky duoc manifest"; return 1;
    }
    # Policy schema cannot contain secrets.  The release must remain readable
    # by the transport account even when root built it under /tmp; authenticity
    # comes from the signature, not from hiding the artifact.
    chmod 0755 "$work" || { rm -rf "$work"; return 1; }
    chmod 0644 "$work/policy.json" "$work/manifest.txt" "$work/manifest.sig"
    sync -f "$work/policy.json" && sync -f "$work/manifest.txt" \
      && sync -f "$work/manifest.sig" && sync -f "$work" || {
        rm -rf "$work"; return 1;
    }
    mv "$work" "$output" || { rm -rf "$work"; return 1; }
    sync -f "$parent" || return 1
    echo "FLEET_BUNDLE_READY sequence=$sequence version=$version sha256=$sha expires=$expires path=$output"
}

command_apply() {
    local bundle=$1 state_rc active_before
    verify_bundle "$bundle" || return 1
    prepare_state_dir || return 1
    read_state "$RELEASE_STATE"; state_rc=$?
    if [ "$state_rc" -eq 1 ]; then
        die "fleet release state bi hong; khong duoc fail-open"; return 1
    fi
    if [ "$state_rc" -eq 0 ]; then
        if [ "$MF_SEQUENCE" -lt "$ST_SEQUENCE" ]; then
            die "downgrade/replay sequence=$MF_SEQUENCE < applied=$ST_SEQUENCE"; return 1
        fi
        if [ "$MF_SEQUENCE" -eq "$ST_SEQUENCE" ]; then
            if [ "$MF_SHA" != "$ST_SHA" ] || [ "$MF_VERSION" != "$ST_VERSION" ]; then
                die "sequence da dung cho release khac"; return 1
            fi
            if active_version && [ "$VALIDATED_VERSION" = "$MF_VERSION" ]; then
                echo "FLEET_ALREADY_APPLIED sequence=$MF_SEQUENCE version=$MF_VERSION"
                return 0
            fi
            die "sequence da consume nhung active khac; ky sequence moi de re-apply"
            return 1
        fi
    fi
    [ -x "$POLICYCTL" ] || { die "policyctl khong executable: $POLICYCTL"; return 1; }
    # This is the only mutation.  P1.1 owns validation, full tests and atomic
    # active/LKG promotion; no signed release can bypass those gates.
    if ! bash "$POLICYCTL" publish "$bundle/policy.json"; then
        die "P1.1 policyctl tu choi release; fleet state khong doi"
        return 1
    fi
    if ! active_version || [ "$VALIDATED_VERSION" != "$MF_VERSION" ]; then
        die "active sau publish khong khop signed release; state khong doi"
        return 1
    fi
    write_state || { die "khong ghi duoc fleet release state"; return 1; }
    echo "FLEET_APPLIED sequence=$MF_SEQUENCE version=$MF_VERSION"
    echo "FLEET_RELOAD_REQUIRED chay nginx -t && nginx -s reload, canary 5-15 phut"
}

command_status() {
    local rc fp bad=0
    if secure_public_key; then
        if command -v "$OPENSSL" >/dev/null 2>&1 \
          && fp=$("$OPENSSL" pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null \
               | sha256sum | awk '{print $1}'); then
            echo "fleet_key=ready fingerprint=$fp"
        else
            echo "fleet_key=degraded reason=invalid_public_key"
            bad=1
        fi
    elif [ -e "$PUBLIC_KEY" ]; then
        echo "fleet_key=degraded reason=insecure_or_unreadable_public_key"
        bad=1
    else
        echo "fleet_key=unprovisioned path=$PUBLIC_KEY"
        bad=1
    fi
    read_state "$RELEASE_STATE"; rc=$?
    case "$rc" in
      0) echo "fleet_release=applied sequence=$ST_SEQUENCE version=$ST_VERSION sha256=$ST_SHA applied_epoch=$ST_APPLIED" ;;
      2) echo "fleet_release=none" ;;
      *) echo "fleet_release=degraded reason=invalid_state path=$RELEASE_STATE"; return 1 ;;
    esac
    [ "$bad" -eq 0 ]
}

command=${1:-}
case "$command" in
  build) shift; [ "$#" -ge 4 ] && [ "$#" -le 5 ] || { usage; exit 2; }
         command_build "$@" ;;
  verify) [ "$#" -eq 2 ] || { usage; exit 2; }
          if verify_bundle "$2"; then
              echo "FLEET_VERIFIED sequence=$MF_SEQUENCE version=$MF_VERSION sha256=$MF_SHA"
          else exit 1; fi ;;
  apply) [ "$#" -eq 2 ] || { usage; exit 2; }; command_apply "$2" ;;
  status) [ "$#" -eq 1 ] || { usage; exit 2; }; command_status ;;
  *) usage; exit 2 ;;
esac
