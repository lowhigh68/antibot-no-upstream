#!/bin/bash
#
# uploads_harden.sh — chan THUC THI trong `wp-content/uploads/` bang `.htaccess`.
#
# CHAY TAY, MOT LAN MOI MAY. `deploy.sh` KHONG goi, `fim.sh` KHONG goi, khong
# cron. Cung ly le voi `fim.sh baseline`: ban nay GHI vao thu muc cua khach, nen
# phai co nguoi doc danh sach roi bam. Mac dinh la CHE DO IN RA; phai `--apply`
# moi ghi.
#
# ── VI SAO `.htaccess` VA KHONG PHAI THU KHAC ────────────────────────
#
# Do 10-10-2026 tren cloud168-123: `httpd -M` chi co `proxy_fcgi_module`, KHONG
# co `php_module`. Fleet chay PHP-FPM, nen:
#   * `php_admin_flag engine off` la directive cua `mod_php` — Apache se bao
#     `Invalid command` va TU CHOI KHOI DONG. Khong dung duoc.
#   * `security.limit_extensions` nam o `/usr/local/php*/etc/` — tep DirectAdmin
#     quan ly, `custombuild` ghi de im lang. Nguoi dung da quyet GIU NGUYEN.
#   * `Require all denied` thuoc `mod_authz_core` (loi Apache), chay TRUOC khi
#     chon handler, nen chan ca khi PHP di qua FPM. Va `.htaccess` nam trong thu
#     muc khach, khong phai tep DA sinh.
#
# Nghiem thu da do, hai chieu:
#   `.txt`   -> HTTP 200  (anh/PDF/tai lieu van phuc vu)
#   `.phtml` -> HTTP 403  (duoi thuc thi duoc bi chan)
# `AllowOverride All` o `<Directory />` trong `httpd-directories.conf` nen
# `.htaccess` co hieu luc tren toan cay `/home/*/domains/*/public_html/`.
#
# ── GIOI HAN, NOI RO DE KHONG AI TIN QUA MUC ─────────────────────────
#
# Chan duoc:  HTTP truc tiep toi `uploads/shell.php`
# KHONG chan: `include('.../uploads/x.php')` tu code, va LFI — PHP doc tep qua
#             filesystem, Apache khong tham gia. Che duong do can `open_basedir`
#             (cau hinh DirectAdmin, ngoai pham vi ban nay).
# Do 10-10: KHONG mot plugin nao tren fleet `include` tep trong `uploads/`
# (3 dong khop ban dau deu la van ban readme / ten ham / ten tep), nen ban nay
# khong the lam vo plugin nao.
#
# Khach hoac plugin co the XOA `.htaccess`. Muc 24 cua `postdeploy.sh` bao thu
# muc mat dau, va `fim.sh` dem duoi thuc thi duoc trong `uploads/`.

set -u

APPLY=0
case "${1:-}" in
    --apply) APPLY=1 ;;
    ""|--dry-run) APPLY=0 ;;
    *) echo "dung: $0 [--apply]" >&2; exit 2 ;;
esac

# Dau de (a) chay lai khong ghi trung, (b) `postdeploy.sh` muc 24 va `fim.sh`
# nhan ra day la thay doi CO CHU Y chu khong phai tep la.
# Goc tim kiem. `/home` tren production; bien nay ton tai de BO KIEM chay duoc
# tren fixture — khong co no thi `uploads_harden_test.sh` phai mo phong lai vong
# lap, va mo phong la thu da lam lot ba ban deploy hong (xem
# `feedback_contract_emulation` trong memory). Bo kiem chay CHINH ban nay.
SEARCH_ROOT="${UPLOADS_HARDEN_ROOT:-/home}"
if [ ! -d "$SEARCH_ROOT" ]; then
    echo "khong co thu muc goc: $SEARCH_ROOT" >&2
    exit 2
fi

MARK='# antibot-uploads-harden'

# `(?i:)` cua PCRE KHONG dung duoc trong `FilesMatch` cua Apache 2.4 o moi ban,
# nen dung `[Pp][Hh][Pp]` tuong duong — chac chan hon, va `.PHP`/`.Php` van bi
# chan (attacker thu bien the case la chuyen thuong).
#
# `php[0-9]`: `.php5`/`.php7` deu nam trong `limit_extensions` cua FPM.
# `phar`    : PHP thuc thi duoc archive.
# `inc`     : co trong `limit_extensions` (nguoi dung giu nguyen theo DA).
# KHONG `Require all denied` ca thu muc: `uploads/` phai phuc vu anh/PDF.
read -r -d '' BLOCK << 'EOF' || true
<FilesMatch "\.([Pp][Hh][Pp][0-9]?|[Pp][Hh][Tt][Mm][Ll]|[Pp][Hh][Aa][Rr]|[Ii][Nn][Cc]|[Cc][Gg][Ii]|[Pp][Ll]|[Pp][Yy]|[Ss][Hh])$">
    Require all denied
</FilesMatch>
EOF

n_skip=0; n_todo=0; n_done=0; n_err=0

while IFS= read -r d; do
    [ -d "$d" ] || continue
    ht="$d/.htaccess"

    if [ -f "$ht" ] && grep -qF "$MARK" "$ht" 2>/dev/null; then
        printf '  BO QUA  %s (da co dau)\n' "$d"
        n_skip=$((n_skip + 1))
        continue
    fi

    if [ "$APPLY" = "0" ]; then
        printf '  SE GHI  %s\n' "$ht"
        n_todo=$((n_todo + 1))
        continue
    fi

    # Ban luu TRUOC khi sua. Neu `cp` that bai thi KHONG ghi — thieu ban luu la
    # ly do du de dung, khong phai canh bao bo qua duoc.
    if [ -f "$ht" ]; then
        if ! cp -p "$ht" "$ht.pre-harden.$(date +%Y%m%d)" 2>/dev/null; then
            printf '  LOI     %s (khong tao duoc ban luu, BO QUA)\n' "$ht" >&2
            n_err=$((n_err + 1))
            continue
        fi
    fi

    # `>>` chu KHONG `>`: noi dung `.htaccess` cua khach giu nguyen, chi them
    # vao cuoi. Mot `>` o day xoa cau hinh rewrite cua ho.
    {
        [ -f "$ht" ] && echo
        echo "$MARK"
        echo "$BLOCK"
    } >> "$ht" || { printf '  LOI     %s (ghi that bai)\n' "$ht" >&2
                    n_err=$((n_err + 1)); continue; }

    # Chu so huu theo CHINH thu muc uploads: tep thuoc khach, khong thuoc root.
    chown --reference="$d" "$ht" 2>/dev/null || :
    chmod 0644 "$ht" 2>/dev/null || :
    printf '  DA GHI  %s\n' "$ht"
    n_done=$((n_done + 1))
done < <(find "$SEARCH_ROOT" -maxdepth 6 -type d -name uploads -path '*wp-content*' 2>/dev/null)

echo
if [ "$APPLY" = "0" ]; then
    printf 'CHE DO IN RA: %d se ghi, %d bo qua. Chay lai voi --apply de ghi that.\n' \
        "$n_todo" "$n_skip"
    exit 0
fi

printf 'DA GHI %d, bo qua %d, loi %d. Ban luu o <.htaccess>.pre-harden.<ngay>\n' \
    "$n_done" "$n_skip" "$n_err"
echo
echo 'NGHIEM THU (thay DOM/D bang mot domain that tren may nay):'
echo '  D=/home/<user>/domains/<domain>/public_html/wp-content/uploads'
echo '  DOM=<domain>'
echo '  echo ok > "$D/zz_v.txt"; echo text > "$D/zz_v.phtml"'
echo '  curl -ks -o /dev/null -w "txt=%{http_code}\n"   "https://$DOM/wp-content/uploads/zz_v.txt"'
echo '  curl -ks -o /dev/null -w "phtml=%{http_code}\n" "https://$DOM/wp-content/uploads/zz_v.phtml"'
echo '  rm -f "$D"/zz_v.*        # <- DON NGAY, dung de tep la trong thu muc khach'
echo '  ky vong: txt=200  phtml=403'

[ "$n_err" -gt 0 ] && exit 1
exit 0
