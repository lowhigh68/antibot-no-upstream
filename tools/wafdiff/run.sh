#!/bin/bash
# wafdiff — fuzz VI SAI giua `antibot-core/waf/body_core.lua` va parser multipart
# THAT cua PHP (roadmap WAF muc 3, review 26-09 lan 2).
#
# CHI chay tren may dev (WSL). Script nay goi `php-cgi` voi mot script PHP in
# `$_POST`/`$_FILES` — dung thu nguyen tac "khong dat file test chay ma len
# production" cam. Nen:
#   · TU CHOI tren moi may co DirectAdmin;
#   · KHONG co file `.php` nao trong repo (repo duoc `git pull` ve server): oracle
#     duoc SINH ra luc chay, vao thu muc tam RIENG cua lan chay;
#   · nam NGOAI `antibot-core/`, nen `deploy.sh` (rsync `antibot-core/`) khong bao
#     gio dua no vao cay chay cua nginx.
#
# DUNG:   bash tools/wafdiff/run.sh              (N=1500 ca ngau nhien + quet cat)
#         N=5000 SEED=42 bash tools/wafdiff/run.sh
# Ma thoat: 0 = khong vi pham NGUY HIEM/LOI VA oracle chay dung moi ca,
#           1 = co vi pham, 2 = khong chay duoc / khong bao dam duoc ket qua.
# Chay truoc moi commit cham `file_ranges`/`projection`/`scan_disposition_headers`.
#
# FAIL-CLOSED, co do (review 27-09): ban truoc chi `set -u` va ghi oracle vao
# /var/tmp/wafdiff-oracle CO DINH. Thu muc do thuoc user khac thi `cat >` bao
# Permission denied, script VAN chay tiep voi dump.php CU — hoac voi mot dump.php
# do nguoi khac dat vao thu muc chung — va co the thoat 0. Nay: moi lan chay mot
# thu muc `mktemp -d` rieng (0700), moi buoc hong la thoat 2.
set -euo pipefail
fail() { echo "wafdiff: $*" >&2; exit 2; }

[ -d /usr/local/directadmin ] && fail "may nay co DirectAdmin — KHONG chay tren production."
HERE=$(cd "$(dirname "$0")" && pwd) || fail "khong xac dinh duoc thu muc cua run.sh"
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
[ -x "$RESTY" ] || fail "khong co resty tai $RESTY"
command -v "${PHPCGI:-php-cgi}" >/dev/null || fail "khong co php-cgi"
SRC_DIR=$(cd "$HERE/../../antibot-core" && pwd) || fail "khong thay antibot-core/"

WORK=$(mktemp -d /var/tmp/wafdiff.XXXXXX) || fail "khong tao duoc thu muc tam"
keep=0
cleanup() {
    if [ "$keep" = 1 ]; then echo "wafdiff: giu $WORK de xem ca loi"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

cat > "$WORK/dump.php" <<'PHP' || fail "khong ghi duoc oracle vao $WORK"
<?php
// Oracle cua wafdiff: PHP THAT doc than multipart thanh gi (base64 cho an toan nhi
// phan). Sinh boi tools/wafdiff/run.sh tren may dev — khong bao gio o webroot.
// `full_path` (PHP >= 8.1) la ten tep PHP doc ra TRUOC basename.
$files = [];
foreach ($_FILES as $field => $f) {
    if (is_array($f['name'])) continue;
    $c = null;
    if ($f['error'] === UPLOAD_ERR_OK && is_file($f['tmp_name'])) {
        $c = base64_encode(file_get_contents($f['tmp_name']));
    }
    $fp = isset($f['full_path']) ? base64_encode($f['full_path']) : null;
    $files[] = ['name' => base64_encode($f['name']), 'full_path' => $fp,
                'error' => $f['error'], 'content' => $c];
}
$post = [];
foreach ($_POST as $k => $v) {
    if (is_array($v)) continue;
    $post[] = ['value' => base64_encode($v)];
}
echo json_encode(['post' => $post, 'files' => $files]), "\n";
PHP
[ -s "$WORK/dump.php" ] || fail "oracle rong sau khi ghi"

export ANTIBOT_SRC="$SRC_DIR/"
export WAFDIFF_DUMP="$WORK/dump.php"
# Ca loi mac dinh nam trong thu muc tam cua lan chay, va duoc GIU khi thoat khac 0.
# Dat OUT= thi ca loi ra cho do (wafdiff.lua xoa va tao lai no).
if [ -z "${OUT:-}" ]; then export OUT="$WORK/cases"; own_out=1; else own_out=0; fi

rc=0
"$RESTY" "$HERE/wafdiff.lua" || rc=$?
[ "$rc" -ne 0 ] && [ "$own_out" = 1 ] && keep=1
exit "$rc"
