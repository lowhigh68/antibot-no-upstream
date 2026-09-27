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

# `policy_test` chay DAU TIEN: registry/policy/telemetry la nen cua moi phan con
# lai, va mot registry lech detector thi bon bo test sau se bao loi kho doc thay
# vi chi ra dung nguyen nhan.
echo "── policy / registry / telemetry ────────────────────────────"
"$RESTY" --shdict "antibot_cache 1m" "$HERE/policy_test.lua" || rc=1

echo
echo "── wordpress/paths ──────────────────────────────────────────"
"$RESTY" --shdict "antibot_cache 1m" "$HERE/wordpress_paths_test.lua" || rc=1

echo
echo "── hop dong giua cac module ──────────────────────────"
"$RESTY" "$HERE/contract_test.lua" || rc=1

echo
echo "── args ──────────────────────────────────────────────"
"$RESTY" "$HERE/args_test.lua" || rc=1

echo
echo "── body ──────────────────────────────────────────────"
"$RESTY" "$HERE/body_test.lua" || rc=1

echo
echo "── upload (P1) ───────────────────────────────────────"
"$RESTY" "$HERE/upload_test.lua" || rc=1

echo
echo "── upload_content + cung part (buoc 3-4) ─────────────"
"$RESTY" "$HERE/upload_content_test.lua" || rc=1

echo
echo "── upload_magic (muc 7: duoi vs byte dau) ────────────"
"$RESTY" "$HERE/upload_magic_test.lua" || rc=1

# `postdeploy.sh` la mot lenh DO, va mot lenh do hong khong bao loi — no tra ve so
# trong-co-ly. Bo nay sinh log GIA co dap an biet truoc roi doi chieu. Chay bang
# bash chu khong resty (no kiem mot script shell).
#
# Can `date -d`, `find -newermt`, `zcat` — co san tren fleet lan WSL. Neu mai chay
# o cho thieu chung thi bo nay do va do la dung: `postdeploy.sh` cung se sai o do.
echo
echo "── postdeploy.sh (bao cao tu kiem) ───────────────────"
bash "$HERE/postdeploy_test.sh" || rc=1

# `fim.sh` quyet dinh cai gi DEN DUOC WAF, va truoc muc 8 no khong co phep kiem nao.
# Bo nay chay `baseline` + `check` that tren mot cay thu muc `mktemp -d` voi
# `redis-cli` GIA — khong cham /home, khong cham Redis, khong cham /var/lib.
echo
echo "── fim.sh (muc 8: tep cau hinh bi sua) ───────────────"
bash "$HERE/fim_test.sh" || rc=1

exit $rc
