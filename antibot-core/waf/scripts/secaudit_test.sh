#!/bin/bash
# secaudit_test.sh — kiem BO NGHIEM THU, khong kiem may.
#
# VI SAO CAN. `secaudit.sh` la mot phep do ve MAY DANG CHAY, nen no khong the
# chay trong WSL de lay ket qua that. Nhung ba thu CO THE kiem o day, va ca ba
# deu la cho da tung sai trong repo nay:
#
#   1. BA TRANG THAI khong duoc gop. `BO QUA` (khong do duoc) phai KHAC `PASS`.
#      Gop lai la lop loi da giet `wp_paths.mark()` 4 thang va da tai sinh o
#      `fim.sh`, `postdeploy.sh` — nen no can mot ca ghim.
#   2. Ma thoat phan biet "co FAIL" (1) voi "khong do duoc gi" (2). Mot may HONG
#      va mot may THUNG RANH GIOI khong duoc tra cung mot so.
#   3. KHONG dat tep thuc thi len production. Rang buoc cung cua nguoi dung.
#      Muc 6 dat mot tep `.php` chua TEXT THUAN — neu ai sau nay doi noi dung do
#      thanh ma PHP thi ca nay bao ngay.
#
# CHAY:  bash waf/scripts/secaudit_test.sh
set -u
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)
S="$HERE/secaudit.sh"
SRC=$(cat "$S")
pass=0; fail=0
want() {
    if [ "$2" = "$3" ]; then pass=$((pass+1))
    else fail=$((fail+1)); printf 'HONG  %s: got=%s want=%s\n' "$1" "$2" "$3"; fi
}
has() {
    if printf '%s\n' "$3" | grep -qF -- "$2"; then pass=$((pass+1))
    else fail=$((fail+1)); printf 'HONG  %s: khong thay "%s"\n' "$1" "$2"; fi
}
hasnt() {
    if printf '%s\n' "$3" | grep -qF -- "$2"; then
        fail=$((fail+1)); printf 'HONG  %s: KHONG duoc co "%s"\n' "$1" "$2"
    else pass=$((pass+1)); fi
}

printf '── 1. khong co tenant -> rc=2 (khong do duoc), KHONG phai 0 ──\n'
OUT=$(SEC_HOME=/nonexistent-secaudit bash "$S" 2>&1); RC=$?
want "rc khi khong co tenant" "$RC" "2"
has  "noi ro la khong do duoc" "khong do duoc" "$OUT"
hasnt "khong duoc bao PASS" "PASS   " "$OUT"

printf '\n── 2. chay khong phai root -> rc=2, KHONG tu nhan la da do ──\n'
# `u1`/`u2` KHONG phai user that tren may, nen script khong `su` vao duoc —
# va do chinh la ca dang do: no phai ra `rc=2` (khong do duoc) chu khong duoc
# im lang bao PASS. Thong diep cu the thi tuy nhanh nao trung truoc, nen ca nay
# ghim MA THOAT va "khong do duoc", khong ghim mot cau chu.
if [ "$(id -u)" -ne 0 ]; then
    H=$(mktemp -d)
    mkdir -p "$H/u1/domains/a.test/public_html" "$H/u2/domains/b.test/public_html"
    OUT=$(SEC_HOME="$H" bash "$S" 2>&1); RC=$?
    want "rc khi khong ha duoc uid" "$RC" "2"
    has  "noi ro khong do duoc" "khong do duoc" "$OUT"
    hasnt "khong duoc bao PASS khi chua ha uid" "PASS   " "$OUT"
    rm -rf "$H"
else
    printf '  BO QUA: dang chay bang root, khong tai hien duoc\n'
fi
printf '\n── 3. tep thu cua muc 6 KHONG duoc chua ma PHP ──\n'
# Doc CHINH dong `printf` sinh noi dung tep thu. Mot ban sau doi no thanh
# `<?php` se bien bo nghiem thu thanh thu ma no ton tai de ngan.
probe_body=$(grep -A1 "Noi dung KHONG phai ma PHP" "$S" | tail -1)
hasnt "tep thu khong co the mo php" "<?php" "$probe_body"
hasnt "tep thu khong co the mo ngan" "<?=" "$probe_body"
hasnt "tep thu khong co script" "<script" "$probe_body"
has   "tep thu co ghi ro la text probe" "secaudit text probe" "$probe_body"

printf '\n── 4. muc 6 phai DON tep thu trong moi duong ra ──\n'
# `trap ... RETURN` chu khong `rm` o cuoi ham: mot `timeout` giet phep do giua
# duong van phai don. Thieu dong nay thi may khach dinh rac mang ten script.
#
# Dem DONG `trap` thuc su, khong grep rieng chuoi "RETURN": tu do con xuat hien
# trong chu thich, nen mot ca grep "RETURN" se PASS ke ca khi dong trap da bi
# go — da kiem bang dot bien va no khong bat duoc.
ntrap=$(grep -cE "^[[:space:]]*trap .*rm -f.*RETURN" "$S")
want "co dung mot dong trap don tep" "$ntrap" "1"
printf '\n── 5. phep thu GHI redis phai dung khoa RIENG, khong cham khoa that ──\n'
wblock=$(grep -n "redis GHI" "$S" | head -1 | cut -d: -f1)
wctx=$(awk -v N="$wblock" 'NR>=N-20 && NR<=N+10' "$S")
has   "dung tien to secaudit:" "secaudit:probe:" "$wctx"
hasnt "KHONG ghi vao verified:" 'SET verified:' "$wctx"
hasnt "KHONG ghi vao waf:" 'SET waf:' "$wctx"
has   "co don khoa sau khi ghi duoc" "DEL" "$wctx"

printf '\n── 6. ba muc moi deu co mat ──\n'
for m in "apache Host: di vong" "redis GHI" "ghi duoc != chay duoc"; do
    has "muc '$m' ton tai" "$m" "$SRC"
done

printf '\nsecaudit_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
