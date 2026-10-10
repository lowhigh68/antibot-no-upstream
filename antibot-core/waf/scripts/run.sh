#!/bin/bash
# Chay T. Can OpenResty vi bon luat WAF quyet dinh bang PCRE lookahead cua
# ngx.re — thu ma luajit tran khong co.
#
# Ma thoat:  0 = qua het   1 = co test hong   2 = khong chay duoc
set -u

# `export` chu khong chi gan: `fim_test.sh` nhom 29 goi `init.lua` qua `resty` de kiem
# phep merge cha-con, va khong co bien nay thi no BAO QUA MAT thay vi chay — mot ca
# khong chay phai noi ro, nhung o day no CHAY DUOC nen phai truyen xuong.
export RESTY=${RESTY:-/usr/local/openresty/bin/resty}
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
# Bo test shell: chay qua `sh_suite` chu khong goi thang.
#
# VI SAO: ba bo nay chi dung `set -u` va ket luan bang bien `fail`, nen mot LOI SHELL
# ngoai `want()` khong lam suite do. Do duoc 01-10: mot dong bi lap trong `fim_test.sh`
# khien shell thu chay mot lenh ten `5`, va hai `cross` trong `htaccess_fixture_test.sh`
# duoc goi TRUOC khi ham duoc dinh nghia — `command not found`, hai ca KHONG CHAY, suite
# van bao xanh va `run.sh` van tra 0. "Assertion da chay deu qua" KHAC "toan bo test
# thuc thi sach".
#
# `sh_suite` doc stderr va coi cac dang loi shell la THAT BAI, ke ca khi suite tra 0.
# Khong dung `set -e` trong cac suite: chung CO Y de mot so lenh that bai (vi du
# `fim.sh check` tra 1 khi co phat hien), nen `set -e` se lam chung chet giua duong.
sh_suite() {
    local name="$1"; shift
    local err erc
    err=$(mktemp) || return 2
    # KHONG dung `2> >(tee ...)`: voi process substitution thi `$?` lay tu tien trinh
    # cua `tee`, nen ma thoat THAT cua suite bien mat va cong nay luon thay 0 (do duoc
    # 01-10 — dot bien chen mot ham khong ton tai KHONG bi bat). Ghi stderr vao tep roi
    # IN LAI; thu tu dong doi mot chut nhung ma thoat dung.
    bash "$@" 2>"$err"
    erc=$?
    cat "$err" >&2
    # Cac dang loi shell. `command not found` va `unbound variable` la hai cai da THAT
    # SU xay ra 01-10; ba cai con lai cung ho (lenh khong chay duoc / cu phap).
    if grep -qE 'command not found|unbound variable|syntax error|cannot execute' "$err"; then
        echo "  !! $name: CO LOI SHELL -- suite KHONG thuc thi sach:" >&2
        grep -nE 'command not found|unbound variable|syntax error|cannot execute' "$err" \
          | head -5 | sed 's/^/     /' >&2
        rm -f "$err"
        return 1
    fi
    rm -f "$err"
    return $erc
}


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

echo
echo "── routes (muc 5: hop dong endpoint) ─────────────────"
"$RESTY" "$HERE/routes_test.lua" || rc=1

# L7 la lop DUY NHAT tra 429/503 TRUOC khi request toi backend, va truoc ban nay
# bo kiem cua no KHONG nam trong `run.sh`. Hau qua: moi commit cham L7 di qua mot
# cong khong kiem L7. Bat duoc 05-10 bang `grep -c l7_regression run.sh` = 0 ngay
# sau khi `run.sh` vua bao rc=0 cho mot thay doi admission.
#
# `$ANTIBOT_SRC` chu khong duong dan tuong doi: bo nay chay duoc o CA HAI noi —
# repo (`antibot-core/`) lan cay da deploy (`conf/antibot/`), vi chinh loader cua
# no doc bien do. Ban dong cung `./antibot-core/` truoc day la ly do no khong vao
# duoc `run.sh`.
echo
echo "── l7 (admission + circuit breaker) ──────────────────"
"$RESTY" "${ANTIBOT_SRC}l7/tests/l7_regression.lua" || rc=1

echo "── admin: duong ra bo dem L7 ──────────────────────────"
"$RESTY" "${ANTIBOT_SRC}admin/tests/admin_l7_test.lua" || rc=1

echo "── admin: duong ra FIM (the dashboard) ────────────────"
"$RESTY" "${ANTIBOT_SRC}admin/tests/admin_fim_test.lua" || rc=1

echo "── admin: tab WAF (bang theo domain) ──────────────────"
"$RESTY" "${ANTIBOT_SRC}admin/tests/admin_fimwaf_test.lua" || rc=1

echo "── secaudit (bo nghiem thu ranh gioi) ────────────────"
bash "${ANTIBOT_SRC}waf/scripts/secaudit_test.sh" || rc=1

# `postdeploy.sh` la mot lenh DO, va mot lenh do hong khong bao loi — no tra ve so
# trong-co-ly. Bo nay sinh log GIA co dap an biet truoc roi doi chieu. Chay bang
# bash chu khong resty (no kiem mot script shell).
#
# Can `date -d`, `find -newermt`, `zcat` — co san tren fleet lan WSL. Neu mai chay
# o cho thieu chung thi bo nay do va do la dung: `postdeploy.sh` cung se sai o do.
echo
echo "── postdeploy.sh (bao cao tu kiem) ───────────────────"
sh_suite postdeploy_test "$HERE/postdeploy_test.sh" || rc=1

# `uploads_harden.sh` GHI vao thu muc cua khach, nen no la ban duy nhat trong cay
# nay co the pha du lieu nguoi dung. Bo kiem chay CHINH no tren mot cay `mktemp -d`
# qua `UPLOADS_HARDEN_ROOT` — khong cham /home — va ghim hai bat bien dat nhat:
# `>>` chu khong `>` (mot `>` xoa cau hinh rewrite cua khach), va mac dinh la
# CHE DO IN RA (mot lan chay quen `--apply` khong duoc ghi gi).
echo
echo "── uploads_harden.sh (cung hoa uploads/) ─────────────"
sh_suite uploads_harden_test "$HERE/uploads_harden_test.sh" || rc=1

# `fim.sh` quyet dinh cai gi DEN DUOC WAF, va truoc muc 8 no khong co phep kiem nao.
# Bo nay chay `baseline` + `check` that tren mot cay thu muc `mktemp -d` voi
# `redis-cli` GIA — khong cham /home, khong cham Redis, khong cham /var/lib.
echo
echo "── fim.sh (muc 8: tep cau hinh bi sua) ───────────────"
sh_suite fim_test "$HERE/fim_test.sh" || rc=1

# `wpinv` ghi CHINH cac khoa ma `is_wp_root` doc, va ba luat HARD-BLOCK duoc gate
# bang chung. Lech mot ky tu la inventory ghi mot noi, WAF doc mot noi.
echo
echo "── fim.sh wpinv (inventory WordPress root) ───────────"
sh_suite wpinv_test "$HERE/wpinv_test.sh" || rc=1

# HAI parser `.htaccess` (Lua doc part upload, awk doc tep tren dia) tra loi CUNG
# mot cau hoi bang hai hien thuc. Bo nay chay ca hai tren CUNG tap fixture va doi
# chung dong y — lech theo huong awk bo sot la FALSE NEGATIVE im lang.
echo
echo "── hai parser .htaccess tren cung tap fixture ────────"
sh_suite htaccess_fixture_test "$HERE/htaccess_fixture_test.sh" || rc=1

exit $rc
