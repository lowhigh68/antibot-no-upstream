#!/bin/bash
# Chay T. Can OpenResty vi bon luat WAF quyet dinh bang PCRE lookahead cua
# ngx.re — thu ma luajit tran khong co.
#
# Ma thoat:  0 = qua het   1 = co test hong   2 = khong chay duoc
set -u

RESTY=${RESTY:-/usr/local/openresty/bin/resty}
HERE=$(cd "$(dirname "$0")" && pwd)
export ANTIBOT_SRC="$(cd "$HERE/.." && pwd)/antibot-core/"

if [ ! -x "$RESTY" ]; then
    echo "khong tim thay resty tai $RESTY"
    echo "T phai chay bang resty. Dat RESTY=/duong/dan neu OpenResty o cho khac."
    exit 2
fi

exec "$RESTY" --shdict "antibot_cache 1m" "$HERE/wp_paths_test.lua"
