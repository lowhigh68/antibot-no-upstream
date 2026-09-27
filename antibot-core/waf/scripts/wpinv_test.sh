#!/bin/bash
# wpinv_test.sh — kiem mode `wpinv` cua fim.sh (inventory WordPress root).
#
# VI SAO CAN: `wpinv` ghi CHINH cac khoa ma `waf/wordpress/paths.lua:is_wp_root`
# doc, va ba luat HARD-BLOCK sap duoc gate bang chung. Lech mot ky tu trong khoa la
# inventory ghi mot noi, WAF doc mot noi, va KHONG AI BAO LOI — dung ho loi da giet
# `wp_paths.mark()` bon thang.
#
# Bo nay dung mot cay DirectAdmin gia (domains.list + .pointers + .subdomains) va
# mot `redis-cli` GIA, roi doi chieu tung khoa voi dap an tinh TAY.
#
# CHAY:  bash waf/scripts/wpinv_test.sh
# Ma thoat: 0 = moi khoa khop, 1 = co lech, 2 = khong do duoc.
set -u
export LC_ALL=C
HERE=$(cd "$(dirname "$0")" && pwd)

R=$(mktemp -d /var/tmp/wpinv.XXXXXX) || exit 2
trap 'rm -rf "$R"' EXIT

# ── Cay tren DIA ────────────────────────────────────────────────────
# u1/site1.test        WordPress o GOC
# u1/site2.test        KHONG WordPress
# u1/site3.test        WordPress trong THU MUC CON `/blog`
# u2/shop.test         WordPress o goc, co pointer va subdomain
H="$R/home"
mk() { mkdir -p "$1"; }
mk "$H/u1/domains/site1.test/public_html"
mk "$H/u1/domains/site2.test/public_html"
mk "$H/u1/domains/site3.test/public_html/blog"
mk "$H/u2/domains/shop.test/public_html"
mk "$H/u2/domains/shop.test/public_html/sub1"

# `wp-settings.php` la dau nhan WordPress (dong bo voi nhanh `check` cua fim.sh).
: > "$H/u1/domains/site1.test/public_html/wp-settings.php"
: > "$H/u1/domains/site3.test/public_html/blog/wp-settings.php"
: > "$H/u2/domains/shop.test/public_html/wp-settings.php"
: > "$H/u2/domains/shop.test/public_html/sub1/wp-settings.php"
# site2 KHONG co -> khong duoc sinh khoa nao.
: > "$H/u1/domains/site2.test/public_html/index.php"

# ── Cay DirectAdmin gia ─────────────────────────────────────────────
DA="$R/da"
mkdir -p "$DA/u1/domains" "$DA/u2/domains"
printf 'site1.test\nsite2.test\nsite3.test\n' > "$DA/u1/domains.list"
printf 'shop.test\n'                          > "$DA/u2/domains.list"
# Pointer: `alias1.test` dung CHUNG docroot voi site1.test.
printf 'alias1.test=type=alias\n' > "$DA/u1/domains/site1.test.pointers"
# Subdomain `sub1` cua shop.test: KHONG co thu muc rieng -> docroot la
# `public_html/sub1` (theo `da_to_openresty.sh:315-318`).
printf 'sub1\n' > "$DA/u2/domains/shop.test.subdomains"

# ── `redis-cli` GIA ─────────────────────────────────────────────────
mkdir -p "$R/bin"
cat > "$R/bin/rcli" <<'RCLI'
#!/bin/bash
while [ $# -gt 0 ]; do
    case "$1" in
        -n) shift 2 ;;
        GET) awk -v k="$2" '$1=="SETEX" && $2==k { print $4; f=1 }
                            END { if (!f) print "" }' "$RCLI_OUT" | tail -1
             exit 0 ;;
        *) shift ;;
    esac
done
cat >> "$RCLI_OUT"
RCLI
chmod +x "$R/bin/rcli"
export RCLI_OUT="$R/cmds.txt"; : > "$RCLI_OUT"

export FIM_ROOTS="$H/*/domains/*/public_html"
export FIM_STATE="$R/state"; mkdir -p "$FIM_STATE"
export FIM_LOG="$R/fim.log"
export FIM_CRITLOG="$R/crit.log"
export FIM_REDIS_CLI="$R/bin/rcli"
export FIM_DA_DATA="$DA"
# KHONG export `FIM_WPINV_TTL`: phep kiem TTL phai kiem GIA TRI MAC DINH cua
# `fim.sh` (no phai khop `WP_HOST_TTL_REDIS` trong paths.lua). Dat bien o day la
# ghi de mac dinh, va khi do phep kiem TTL khong kiem gi — dot bien "doi mac dinh
# thanh 300" da XANH vi the.

pass=0; fail=0
want() {
    if [ "$2" = "$3" ]; then pass=$((pass+1))
    else fail=$((fail+1)); printf 'HONG  %s\n      duoc=%s  mong=%s\n' "$1" "$2" "$3"; fi
}
has() {
    if grep -q "^SETEX $1 " "$RCLI_OUT" 2>/dev/null; then echo yes; else echo no; fi
}
nkeys() { grep -c '^SETEX ' "$RCLI_OUT" 2>/dev/null || true; }

echo "wpinv_test: inventory WordPress root tu dia"

# `wpinv` doc `$ROOTS` bang glob, nen phai chay qua bash voi glob mo rong. Duong
# dan tren dia KHONG bat dau bang `/home` that, nen phep ghep docroot cua fim.sh
# (`/home/<user>/domains/...`) se KHONG khop — do la dung, va bo nay dung
# `FIM_DA_DATA` + mot ban va duong dan de kiem ca duong ghep.
#
# Vi `wpinv` hardcode `/home/$user/domains/...`, o day ta bind bang mot symlink de
# `/home` tro vao cay gia. Khong doi duoc `/home` that nen dung `FIM_HOME`.
out=$(FIM_HOME="$H" bash "$HERE/fim.sh" wpinv 2>&1) || rc=$?
echo "$out" | sed 's/^/    /'

want "1 co ghi khoa" "$([ "$(nkeys)" -gt 0 ] && echo yes || echo no)" "yes"

# In khoa khi co lech: khong thi mot phep kiem do bat buoc phai doan.
[ -n "${WPINV_TEST_DEBUG:-}" ] && { echo "--- khoa da ghi ---"; cat "$RCLI_OUT"; }

# ── Dap an tinh TAY ─────────────────────────────────────────────────
# WP root tren dia: site1 (goc), site3/blog, shop (goc), shop/sub1  = 4
# Host tu DA:
#   site1.test   -> .../site1.test/public_html
#   alias1.test  -> .../site1.test/public_html    (pointer, CUNG docroot)
#   site2.test   -> .../site2.test/public_html
#   site3.test   -> .../site3.test/public_html
#   shop.test    -> .../shop.test/public_html
#   sub1.shop.test -> .../shop.test/public_html/sub1
# Khoa mong doi:
#   waf:wphost:site1.test              (site1 goc)
#   waf:wphost:alias1.test             (alias CUNG docroot -> CUNG duoc bao ve)
#   waf:wproot:site3.test:/blog        (WP trong thu muc con)
#   waf:wphost:shop.test               (shop goc)
#   waf:wphost:sub1.shop.test          (subdomain co docroot RIENG, WP o goc do)
# KHONG duoc co: site2.test (khong WordPress)
want "2 site1 goc"        "$(has 'waf:wphost:site1.test')"       "yes"
want "2 alias CUNG docroot" "$(has 'waf:wphost:alias1.test')"    "yes"
want "2 site3 tien to blog" "$(has 'waf:wproot:site3.test:/blog')" "yes"
want "2 shop goc"         "$(has 'waf:wphost:shop.test')"        "yes"
want "2 subdomain"        "$(has 'waf:wphost:sub1.shop.test')"   "yes"
# Chong FP: site2 KHONG phai WordPress -> KHONG duoc co khoa.
want "3 site2 KHONG co khoa" "$(has 'waf:wphost:site2.test')"    "no"
# site3 o GOC khong phai WordPress (chi `/blog` la) -> khong duoc co khoa goc.
want "3 site3 goc KHONG co khoa" "$(has 'waf:wphost:site3.test')" "no"

# TTL phai KHOP `WP_HOST_TTL_REDIS` trong paths.lua — lech thi khoa het som hon
# WAF nghi, va gate im lang dung sau khi khoa het.
#
# Doc hang so TU CHINH `paths.lua`, khong viet lai so o day: hai noi giu cung mot
# con so thi lan sua thu ba se lech, va phep kiem nay ton tai de chan dung dieu do.
WPTTL=$(grep -oE 'WP_HOST_TTL_REDIS  = [0-9]+' "$HERE/../wordpress/paths.lua" \
        | grep -oE '[0-9]+' | head -1)
want "4 doc duoc WP_HOST_TTL_REDIS" "$([ -n "$WPTTL" ] && echo yes || echo no)" "yes"
ttl=$(awk '$2=="waf:wphost:site1.test" {print $3}' "$RCLI_OUT" | head -1)
want "4 TTL khop WP_HOST_TTL_REDIS" "$ttl" "$WPTTL"

# Gia tri phai la "1": `is_wp_root` so `== "1"`.
val=$(awk '$2=="waf:wphost:site1.test" {print $4}' "$RCLI_OUT" | head -1)
want "4 gia tri la 1" "$val" "1"

# `--dry` KHONG duoc ghi.
: > "$RCLI_OUT"
FIM_HOME="$H" bash "$HERE/fim.sh" wpinv --dry >/dev/null 2>&1 || true
want "5 --dry khong ghi gi" "$(nkeys)" "0"

printf '\nwpinv_test: %d qua, %d hong\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
