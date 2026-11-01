#!/bin/bash
# P1.4 read-only fleet health collector.  It executes only the fixed
# healthstat/fleet-policy status commands and never publishes or reloads.
set -uo pipefail
export LC_ALL=C

SSH_BIN=${SSH_BIN:-ssh}
SSH_USER=${FLEET_SSH_USER:-root}
REMOTE_HEALTH=${FLEET_REMOTE_HEALTH:-/usr/local/openresty/nginx/conf/antibot/waf/scripts/healthstat.sh}
REMOTE_FLEET_POLICY=${FLEET_REMOTE_POLICYCTL:-/usr/local/openresty/nginx/conf/antibot/waf/scripts/fleet_policyctl.sh}
CONNECT_TIMEOUT=${FLEET_CONNECT_TIMEOUT:-10}

usage() { echo "Dung: $0 <hosts.txt> <output-dir> [since_epoch]"; }
die() { echo "FLEET_HEALTH_ERROR $*" >&2; return 1; }

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { usage; exit 2; }
HOSTS=$1
OUTPUT=$2
SINCE=${3:-$(( $(date +%s) - 3600 ))}

[ -f "$HOSTS" ] && [ ! -L "$HOSTS" ] || { die "hosts file khong hop le"; exit 2; }
case "$SINCE" in ''|*[!0-9]*) die "since_epoch khong hop le"; exit 2 ;; esac
case "$SSH_USER" in [A-Za-z_]* ) ;; *) die "SSH user khong hop le"; exit 2 ;; esac
case "$SSH_USER" in *[!A-Za-z0-9_-]*) die "SSH user khong hop le"; exit 2 ;; esac
case "$REMOTE_HEALTH:$REMOTE_FLEET_POLICY" in
  *[!A-Za-z0-9_./:-]*) die "remote tool path khong hop le"; exit 2 ;;
esac
case "$CONNECT_TIMEOUT" in ''|*[!0-9]*) die "connect timeout khong hop le"; exit 2 ;; esac
[ ! -e "$OUTPUT" ] || { die "output-dir da ton tai"; exit 2; }

PARENT=$(dirname "$OUTPUT"); BASE=$(basename "$OUTPUT")
mkdir -p "$PARENT" || exit 2
WORK=$(mktemp -d "$PARENT/.${BASE}.tmp.XXXXXX") || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM
: > "$WORK/summary.txt"
seen=' '
nodes=0 failures=0

while IFS= read -r raw || [ -n "$raw" ]; do
    host=${raw%%#*}
    host=$(printf '%s' "$host" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -n "$host" ] || continue
    case "$host" in
      [A-Za-z0-9]* ) ;;
      *) die "host khong hop le: $host"; exit 2 ;;
    esac
    case "$host" in *[!A-Za-z0-9._-]*) die "host khong hop le: $host"; exit 2 ;; esac
    case "$seen" in *" $host "*) die "host trung lap: $host"; exit 2 ;; esac
    seen="$seen$host "
    nodes=$((nodes + 1))
    target="$SSH_USER@$host"
    health="$WORK/$host.health.txt"
    release="$WORK/$host.release.txt"
    hrc=0; rrc=0
    "$SSH_BIN" -o BatchMode=yes -o ConnectTimeout="$CONNECT_TIMEOUT" -- \
      "$target" bash "$REMOTE_HEALTH" "$SINCE" > "$health" 2>&1 || hrc=$?
    "$SSH_BIN" -o BatchMode=yes -o ConnectTimeout="$CONNECT_TIMEOUT" -- \
      "$target" bash "$REMOTE_FLEET_POLICY" status > "$release" 2>&1 || rrc=$?
    [ "$hrc" -eq 0 ] && [ "$rrc" -eq 0 ] || failures=$((failures + 1))
    printf 'host=%s health_rc=%s release_rc=%s\n' "$host" "$hrc" "$rrc" \
      >> "$WORK/summary.txt"
done < "$HOSTS"

[ "$nodes" -gt 0 ] || { die "hosts file khong co node"; exit 2; }
printf 'fleet_nodes=%d failures=%d since=%s collected_epoch=%s\n' \
  "$nodes" "$failures" "$SINCE" "$(date +%s)" >> "$WORK/summary.txt"
chmod 0750 "$WORK"
chmod 0640 "$WORK"/*
mv "$WORK" "$OUTPUT" || exit 2
trap - EXIT INT TERM
echo "FLEET_HEALTH_COLLECTED nodes=$nodes failures=$failures path=$OUTPUT"
[ "$failures" -eq 0 ]
