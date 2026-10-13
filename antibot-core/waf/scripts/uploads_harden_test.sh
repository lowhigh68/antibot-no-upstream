#!/bin/bash
#
# Bo kiem cho `uploads_harden.sh`. Chay CHINH ban nay tren fixture that qua
# `UPLOADS_HARDEN_ROOT` — khong mo phong lai vong lap (mo phong da lam lot ba
# ban deploy hong, xem `feedback_contract_emulation`).
#
# Bat bien duoc ghim, moi cai vi mot ly do cu the:
#   1. mac dinh la CHE DO IN RA — mot lan chay quen `--apply` khong duoc ghi gi
#   2. `>>` chu khong `>` — noi dung `.htaccess` cua khach PHAI con nguyen
#   3. dau chong trung — chay hai lan khong them hai khoi
#   4. `--apply` tao ban luu truoc khi sua
#   5. khoi chan DUNG duoi thuc thi duoc, va KHONG chan anh/PDF
#   6. tham so la cho nhan loi, khong doan

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SUT="$HERE/uploads_harden.sh"
pass=0; fail=0

ok()  { pass=$((pass+1)); printf '  OK   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  SAI  %s\n' "$1"; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# Fixture: hai thu muc uploads, mot CO `.htaccess` san cua khach, mot KHONG.
mk() {
    mkdir -p "$T/home/$1/domains/$2/public_html/wp-content/uploads"
    echo "$T/home/$1/domains/$2/public_html/wp-content/uploads"
}
U1="$(mk userA site-a.vn)"
U2="$(mk userB site-b.vn)"

# `.htaccess` san co cua khach — noi dung nay PHAI con nguyen sau khi chay.
CUST='RewriteEngine On
RewriteRule ^old\.jpg$ /new.jpg [R=301,L]'
printf '%s\n' "$CUST" > "$U1/.htaccess"

run() { UPLOADS_HARDEN_ROOT="$T/home" bash "$SUT" "$@" 2>&1; }

echo "── 1. mac dinh KHONG ghi gi ──────────────────────────────────"
out="$(run)"
if printf '%s' "$out" | grep -q 'SE GHI'; then
    ok "che do in ra bao 'SE GHI'"
else
    bad "che do in ra khong liet ke gi: $out"
fi
if [ -f "$U2/.htaccess" ]; then
    bad "che do in ra DA TAO .htaccess — phai khong ghi gi"
else
    ok "che do in ra khong tao tep nao"
fi
if grep -qF 'antibot-uploads-harden' "$U1/.htaccess"; then
    bad "che do in ra DA SUA .htaccess san co"
else
    ok "che do in ra khong sua tep san co"
fi

echo "── 2. --apply: noi dung khach con nguyen ─────────────────────"
run --apply >/dev/null
if grep -qF 'RewriteRule ^old\.jpg$' "$U1/.htaccess"; then
    ok "noi dung khach con nguyen (>> chu khong >)"
else
    bad "MAT noi dung khach — dang dung '>' thay vi '>>'"
fi
if grep -qF 'antibot-uploads-harden' "$U1/.htaccess" \
   && grep -qF 'antibot-uploads-harden' "$U2/.htaccess"; then
    ok "ca hai thu muc da co dau"
else
    bad "thieu dau o mot trong hai thu muc"
fi

echo "── 3. ban luu duoc tao TRUOC khi sua ─────────────────────────"
bk="$(ls "$U1"/.htaccess.pre-harden.* 2>/dev/null | head -1)"
if [ -n "$bk" ] && grep -qF 'RewriteRule ^old\.jpg$' "$bk" \
   && ! grep -qF 'antibot-uploads-harden' "$bk"; then
    ok "ban luu chua noi dung TRUOC khi sua"
else
    bad "ban luu thieu hoac da chua khoi moi: $bk"
fi
# Thu muc khong co `.htaccess` thi khong can ban luu — va khong duoc tao ban rong.
if ls "$U2"/.htaccess.pre-harden.* >/dev/null 2>&1; then
    bad "tao ban luu cho thu muc vua khong co .htaccess"
else
    ok "khong tao ban luu rong"
fi

echo "── 4. chay lai KHONG ghi trung ───────────────────────────────"
n1=$(grep -cF 'antibot-uploads-harden' "$U1/.htaccess")
run --apply >/dev/null
n2=$(grep -cF 'antibot-uploads-harden' "$U1/.htaccess")
if [ "$n1" = "1" ] && [ "$n2" = "1" ]; then
    ok "dau xuat hien dung MOT lan sau hai lan chay"
else
    bad "dau trung: lan1=$n1 lan2=$n2"
fi
out="$(run --apply)"
if printf '%s' "$out" | grep -q 'BO QUA'; then
    ok "lan hai bao BO QUA"
else
    bad "lan hai khong bao BO QUA"
fi

echo "── 5. regex khop DUNG duoi — kiem bang chinh bieu thuc ───────"
# Trich bieu thuc tu `.htaccess` roi THU KHOP ten tep that bang `grep -E`.
# Doc "co chu FilesMatch" la phep kiem rong: no khong noi bieu thuc khop gi.
rx="$(sed -nE 's/^<FilesMatch "(.*)">$/\1/p' "$U2/.htaccess" | head -1)"
if [ -z "$rx" ]; then
    bad "khong trich duoc bieu thuc FilesMatch"
else
    # Apache dung PCRE; `grep -E` du cho lop ky tu va `?` o day.
    must_block='shell.php x.PHP y.Php a.php5 b.phtml c.phar d.inc e.cgi f.pl g.py h.sh'
    must_pass='anh.jpg tai-lieu.pdf a.png b.webp c.mp4 d.zip e.svg f.txt g.phpx h.incx'
    nb=0; np=0
    for f in $must_block; do
        if printf '%s' "$f" | grep -qE "$rx"; then nb=$((nb+1))
        else bad "duoi thuc thi duoc KHONG bi chan: $f"; fi
    done
    [ "$nb" = 11 ] && ok "chan du 11 duoi thuc thi duoc (ca bien the CASE)"
    [ "$nb" = 11 ] || bad "chi chan $nb/11 duoi thuc thi duoc"
    for f in $must_pass; do
        if printf '%s' "$f" | grep -qE "$rx"; then
            bad "tep AN TOAN bi chan: $f"
        else np=$((np+1)); fi
    done
    if [ "$np" = 10 ]; then ok "khong chan 10 tep an toan (anh/PDF/video/zip)"
    else bad "chi $np/10 tep an toan di qua"; fi
fi
if grep -qF 'Require all denied' "$U2/.htaccess"; then
    ok "co 'Require all denied'"
else
    bad "thieu 'Require all denied'"
fi
# `php_admin_flag` KHONG duoc xuat hien: fleet khong co mod_php, no lam Apache
# TU CHOI KHOI DONG (do 10-10: httpd -M chi co proxy_fcgi_module).
if grep -qE '^[[:space:]]*php_(admin_)?(flag|value)' "$U2/.htaccess"; then
    bad "co directive php_* — Apache se tu choi khoi dong"
else
    ok "khong dung directive php_* (dung: fleet chay PHP-FPM)"
fi
echo "── 6. tham so la: bao loi, khong doan ────────────────────────"
if UPLOADS_HARDEN_ROOT="$T/home" bash "$SUT" --xoa-het >/dev/null 2>&1; then
    bad "tham so la duoc chap nhan"
else
    ok "tham so la bi tu choi"
fi
if UPLOADS_HARDEN_ROOT="$T/khong-ton-tai" bash "$SUT" >/dev/null 2>&1; then
    bad "goc khong ton tai van chay"
else
    ok "goc khong ton tai -> thoat loi"
fi

echo "── 7. WordPress LONG trong thu muc con (site da ngu) ─────────"
#
# VI SAO NHOM NAY TON TAI. `maxdepth 6` tim duoc 29/43 thu muc uploads tren
# cloud186-126 (do 13-10) — **14 thu muc bi bo HOAN TOAN**, khong co `.htaccess`
# nao, tuc chay PHP duoc va khong chan gi. Tat ca deu la cai dat WordPress THU
# HAI trong cung docroot cua site da ngu:
#     public_html/en/wp-content/uploads      (va `cn/`, `vi/`, `vn/`, `Eng/`)
#     public_html/origin/wp-content/uploads  (4 site)
#     public_html/en-old/`, `en__2873314/`
#
# Fixture cu CHI co duong chuan `public_html/wp-content/uploads`, nen ca suite
# XANH voi `maxdepth 6` — dung lo `feedback_fixture_khong_dai_dien`: fixture
# mang gia dinh cua nguoi viet (mot WP mot docroot) nen no luon PASS.
#
# Dem do bang `find` THAT, khong dem tay: duong chuan depth 6, them mot tang
# thu muc ngon ngu thanh depth 7.
mkn() {  # mkn <user> <domain> <thu-muc-con>
    mkdir -p "$T/home/$1/domains/$2/public_html/$3/wp-content/uploads"
    echo "$T/home/$1/domains/$2/public_html/$3/wp-content/uploads"
}
N1="$(mkn userC site-c.vn en)"
N2="$(mkn userC site-c.vn origin)"
N3="$(mkn userD site-d.vn en__2873314)"

out="$(run --apply)"
for p in "$N1" "$N2" "$N3"; do
    if [ -f "$p/.htaccess" ] && grep -q '# antibot-uploads-harden' "$p/.htaccess"; then
        ok "WP long duoc hardening: ${p#"$T/home/"}"
    else
        bad "WP long BI BO QUA: ${p#"$T/home/"}  (maxdepth qua thap?)"
    fi
done

# Va KHONG duoc queu ra ngoai: mot thu muc `uploads` KHONG nam duoi `wp-content`
# thi khong phai uploads cua WordPress — `-path '*wp-content*'` phai chan no.
mkdir -p "$T/home/userE/domains/site-e.vn/public_html/files/uploads"
run --apply >/dev/null
if [ -f "$T/home/userE/domains/site-e.vn/public_html/files/uploads/.htaccess" ]; then
    bad "ghi vao thu muc uploads KHONG thuoc wp-content — queu qua rong"
else
    ok "thu muc uploads ngoai wp-content KHONG bi cham"
fi

echo
printf 'uploads_harden_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
