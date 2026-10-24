#!/bin/bash
# Explicit P1.1 policy publisher.  Nothing calls this automatically.
# A canary remains an operator action: publish/reload one node, inspect pver
# and policy errors for 5-15 minutes, then repeat on the remaining nodes.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
STATE_DIR=${ANTIBOT_POLICY_DIR:-/etc/antibot/policy}
POLICY_GROUP=${ANTIBOT_POLICY_GROUP:-nginx}
TOOL="$ROOT/core/policy_tool.lua"
RUN_TESTS=${POLICY_TEST_CMD:-$HERE/run.sh}
export ANTIBOT_SRC="$ROOT/"

usage() {
    echo "Dung: $0 publish [candidate.lua|candidate.json]"
    echo "      $0 rollback"
    echo "      $0 status"
}

marker_run() {
    local want="$1"; shift
    local out rc
    out=$(mktemp) || return 2
    "$@" >"$out" 2>&1
    rc=$?
    cat "$out"
    if [ "$rc" -ne 0 ] || ! grep -q "^${want} " "$out"; then
        rm -f "$out"
        return 1
    fi
    rm -f "$out"
    return 0
}

prepare_dir() {
    if [ "${POLICYCTL_TEST_MODE:-0}" = "1" ]; then
        mkdir -p "$STATE_DIR" || return 1
        chmod 0750 "$STATE_DIR" || return 1
    else
        [ "$(id -u)" = "0" ] || { echo "POLICY_ERROR publish/rollback phai chay root"; return 1; }
        install -d -m 0750 -o root -g "$POLICY_GROUP" "$STATE_DIR" || return 1
    fi
}

command=${1:-}
case "$command" in
    publish)
        candidate=${2:-$ROOT/core/policy_runtime.lua}
        [ -x "$RESTY" ] || { echo "POLICY_ERROR khong tim thay resty: $RESTY"; exit 2; }
        [ -f "$candidate" ] || { echo "POLICY_ERROR khong tim thay candidate: $candidate"; exit 2; }
        prepare_dir || exit 2
        work=$(mktemp -d) || exit 2
        trap 'rm -rf "$work"' EXIT INT TERM
        normalized="$work/candidate.json"

        echo "[policy 1/3] Validate/compile candidate..."
        if ! marker_run POLICY_VALID "$RESTY" "$TOOL" validate "$candidate" "$normalized"; then
            echo "POLICY_ABORT validator that bai; active/LKG khong thay doi"
            exit 1
        fi

        echo "[policy 2/3] Full regression gate..."
        if ! bash "$RUN_TESTS"; then
            echo "POLICY_ABORT test that bai; active/LKG khong thay doi"
            exit 1
        fi

        echo "[policy 3/3] Atomic promotion..."
        if ! marker_run POLICY_PROMOTED "$RESTY" "$TOOL" promote "$normalized" "$STATE_DIR"; then
            echo "POLICY_ABORT promotion that bai"
            exit 1
        fi
        if [ "${POLICYCTL_TEST_MODE:-0}" != "1" ]; then
            chown "root:$POLICY_GROUP" "$STATE_DIR/active.json" "$STATE_DIR/last-good.json"
            chmod 0640 "$STATE_DIR/active.json" "$STATE_DIR/last-good.json"
        fi
        echo "POLICY_READY chay nginx -t && nginx -s reload, sau do canary 5-15 phut"
        ;;
    rollback)
        [ -x "$RESTY" ] || { echo "POLICY_ERROR khong tim thay resty: $RESTY"; exit 2; }
        prepare_dir || exit 2
        if ! marker_run POLICY_ROLLED_BACK "$RESTY" "$TOOL" rollback "$STATE_DIR"; then
            echo "POLICY_ABORT rollback that bai; active khong bi ghi do"
            exit 1
        fi
        if [ "${POLICYCTL_TEST_MODE:-0}" != "1" ]; then
            chown "root:$POLICY_GROUP" "$STATE_DIR/active.json"
            chmod 0640 "$STATE_DIR/active.json"
        fi
        echo "POLICY_READY chay nginx -t && nginx -s reload"
        ;;
    status)
        for f in active.json last-good.json; do
            p="$STATE_DIR/$f"
            if [ -r "$p" ]; then
                v=$(grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$p" \
                    | head -1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)"/\1/')
                echo "$f present version=${v:--} bytes=$(wc -c < "$p")"
            else
                echo "$f missing_or_unreadable"
            fi
        done
        ;;
    *) usage; exit 2 ;;
esac
