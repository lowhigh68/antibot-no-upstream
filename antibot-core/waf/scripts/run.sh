#!/bin/bash
# Chay T. Can OpenResty vi bon luat WAF quyet dinh bang PCRE lookahead cua
# ngx.re — thu ma luajit tran khong co.
#
# Ma thoat:  0 = qua het   1 = co test hong   2 = khong chay duoc
set -u

RESTY=${RESTY:-/usr/local/openresty/bin/resty}
HERE=$(cd "$(dirname "$0")" && pwd)
# waf/scripts/ -> len hai cap la goc cay nguon (antibot-core/, hoac thu muc conf
# da deploy). Duong dan TUONG DOI nen chay dung o ca hai noi: deploy.sh goi no
# tu repo TRUOC khi rsync, con chay tay tren server thi tu cay da deploy.
export ANTIBOT_SRC="$(cd "$HERE/../.." && pwd)/"

if [ ! -x "$RESTY" ]; then
    echo "khong tim thay resty tai $RESTY"
    echo "T phai chay bang resty. Dat RESTY=/duong/dan neu OpenResty o cho khac."
    exit 2
fi

# Chay TUNG bo test. `exec` chi chay duoc mot cai, nen phai gom ma thoat tay:
# neu bo dau hong ma van `exec` bo sau thi ma thoat cua bo dau BIEN MAT va cong
# [3b] cua deploy.sh se cho qua mot ban hong.
rc=0

echo "── wp_paths ──────────────────────────────────────────"
"$RESTY" --shdict "antibot_cache 1m" "$HERE/wp_paths_test.lua" || rc=1

echo
echo "── args ──────────────────────────────────────────────"
"$RESTY" "$HERE/args_test.lua" || rc=1

echo
echo "── body ──────────────────────────────────────────────"
"$RESTY" "$HERE/body_test.lua" || rc=1

exit $rc
