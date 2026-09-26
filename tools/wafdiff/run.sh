#!/bin/bash
# wafdiff — fuzz VI SAI giua `antibot-core/waf/body_core.lua` va parser multipart
# THAT cua PHP (roadmap WAF muc 3, review 26-09 lan 2).
#
# CHI chay tren may dev (WSL). Script nay goi `php-cgi` voi mot script PHP in
# `$_POST`/`$_FILES` — dung thu nguyen tac "khong dat file test chay ma len
# production" cam. Nen:
#   · TU CHOI tren moi may co DirectAdmin;
#   · KHONG co file `.php` nao trong repo (repo duoc `git pull` ve server): oracle
#     duoc SINH ra luc chay, vao /var/tmp cua may dev;
#   · nam NGOAI `antibot-core/`, nen `deploy.sh` (rsync `antibot-core/`) khong bao
#     gio dua no vao cay chay cua nginx.
#
# DUNG:   bash tools/wafdiff/run.sh              (N=1500 ca ngau nhien + quet cat)
#         N=5000 SEED=42 bash tools/wafdiff/run.sh
# Ma thoat: 0 = khong vi pham NGUY HIEM/LOI, 1 = co, 2 = khong chay duoc.
# Chay truoc moi commit cham `file_ranges`/`projection`/`scan_disposition_headers`.
set -u
if [ -d /usr/local/directadmin ]; then
    echo "wafdiff: may nay co DirectAdmin — KHONG chay tren production."
    exit 2
fi
HERE=$(cd "$(dirname "$0")" && pwd)
RESTY=${RESTY:-/usr/local/openresty/bin/resty}
[ -x "$RESTY" ] || { echo "wafdiff: khong co resty tai $RESTY"; exit 2; }
command -v "${PHPCGI:-php-cgi}" >/dev/null || { echo "wafdiff: khong co php-cgi"; exit 2; }

ORACLE=/var/tmp/wafdiff-oracle
mkdir -p "$ORACLE" || exit 2
cat > "$ORACLE/dump.php" <<'PHP'
<?php
// Oracle cua wafdiff: PHP THAT doc than multipart thanh gi (base64 cho an toan nhi
// phan). Sinh boi tools/wafdiff/run.sh tren may dev — khong bao gio o webroot.
$files = [];
foreach ($_FILES as $field => $f) {
    if (is_array($f['name'])) continue;
    $c = null;
    if ($f['error'] === UPLOAD_ERR_OK && is_file($f['tmp_name'])) {
        $c = base64_encode(file_get_contents($f['tmp_name']));
    }
    $files[] = ['name' => base64_encode($f['name']), 'error' => $f['error'], 'content' => $c];
}
$post = [];
foreach ($_POST as $k => $v) {
    if (is_array($v)) continue;
    $post[] = ['value' => base64_encode($v)];
}
echo json_encode(['post' => $post, 'files' => $files]), "\n";
PHP

export ANTIBOT_SRC="$(cd "$HERE/../../antibot-core" && pwd)/"
export WAFDIFF_DUMP="$ORACLE/dump.php"
exec "$RESTY" "$HERE/wafdiff.lua"
