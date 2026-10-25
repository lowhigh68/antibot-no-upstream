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

# `run.sh` is a SOURCE-TREE gate: some contracts intentionally inspect
# ../nginx/deploy.sh and git history.  The rsynced runtime tree has neither, so
# running its copy creates false failures (postdeploy/fim) even when policy is
# valid.  A live policyctl therefore discovers the canonical repo used by the
# existing deploy.sh.  Override only for a different installation layout.
DEFAULT_SOURCE_ROOT="/home/xadmin/antibot/antibot-no-upstream/antibot-core"
SOURCE_ROOT=${ANTIBOT_POLICY_SOURCE_DIR:-}
if [ -z "$SOURCE_ROOT" ]; then
    if [ -f "$DEFAULT_SOURCE_ROOT/waf/scripts/run.sh" ]; then
        SOURCE_ROOT="$DEFAULT_SOURCE_ROOT"
    else
        SOURCE_ROOT="$ROOT"
    fi
fi
SOURCE_ROOT=$(cd "$SOURCE_ROOT" 2>/dev/null && pwd) || {
    echo "POLICY_ERROR source tree khong ton tai: $SOURCE_ROOT"
    exit 2
}
RUN_TESTS=${POLICY_TEST_CMD:-$SOURCE_ROOT/waf/scripts/run.sh}
POLICY_RUN_BASE=${POLICY_RUN_BASE:-HEAD}
SOURCE_REPO=$(cd "$SOURCE_ROOT/.." 2>/dev/null && pwd) || SOURCE_REPO="$SOURCE_ROOT"
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

verify_test_source() {
    # Unit tests inject a tiny test command and do not need repository layout.
    if [ -n "${POLICY_TEST_CMD:-}" ]; then return 0; fi
    if [ ! -f "$SOURCE_ROOT/../nginx/deploy.sh" ]; then
        echo "POLICY_ERROR run.sh phai chay tu source tree, khong phai cay live"
        echo "  Dat ANTIBOT_POLICY_SOURCE_DIR=/duong/dan/toi/antibot-core"
        return 1
    fi
    [ -f "$RUN_TESTS" ] || {
        echo "POLICY_ERROR khong tim thay test gate: $RUN_TESTS"
        return 1
    }

    # When invoked from /usr/local/.../conf/antibot, prove that the code being
    # tested is byte-identical to the code that will parse the artifact.  This
    # prevents a green old checkout from authorizing a different live build.
    if [ "$SOURCE_ROOT" != "$ROOT" ]; then
        local rel
        for rel in \
          core/config.lua core/policy.lua core/policy_store.lua \
          core/policy_tool.lua core/policy_runtime.lua \
          waf/scripts/run.sh waf/scripts/policyctl.sh; do
            if [ ! -f "$SOURCE_ROOT/$rel" ] || [ ! -f "$ROOT/$rel" ] \
               || ! cmp -s "$SOURCE_ROOT/$rel" "$ROOT/$rel"; then
                echo "POLICY_ERROR source/live khong dong bo: $rel"
                echo "  Deploy --no-reload lai truoc khi publish"
                return 1
            fi
        done
    fi
    return 0
}

command=${1:-}
case "$command" in
    publish)
        candidate=${2:-$SOURCE_ROOT/core/policy_runtime.lua}
        [ -x "$RESTY" ] || { echo "POLICY_ERROR khong tim thay resty: $RESTY"; exit 2; }
        [ -f "$candidate" ] || { echo "POLICY_ERROR khong tim thay candidate: $candidate"; exit 2; }
        verify_test_source || exit 2
        prepare_dir || exit 2
        work=$(mktemp -d) || exit 2
        trap 'rm -rf "$work"' EXIT INT TERM
        normalized="$work/candidate.json"

        echo "[policy 1/3] Validate/compile candidate..."
        if ! marker_run POLICY_VALID "$RESTY" "$TOOL" validate "$candidate" "$normalized"; then
            echo "POLICY_ABORT validator that bai; active/LKG khong thay doi"
            exit 1
        fi

        echo "[policy 2/3] Full regression gate: $RUN_TESTS (RUN_BASE=$POLICY_RUN_BASE)"
        # A policy publish happens AFTER deploy.sh has tested the code delta.
        # Re-running with HEAD~1 would re-trigger conditional FIM/postdeploy
        # suites merely because the previous code commit touched them.  HEAD
        # still runs every unconditional policy/pipeline/L7 contract, and the
        # conditional suites still run if their files are dirty right now.
        # safe.directory is process-local; no global git config is mutated.
        if ! env RUN_BASE="$POLICY_RUN_BASE" \
          GIT_CONFIG_COUNT=1 \
          GIT_CONFIG_KEY_0=safe.directory \
          GIT_CONFIG_VALUE_0="$SOURCE_REPO" \
          bash "$RUN_TESTS"; then
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
