#!/bin/bash
# secaudit.sh — NGHIEM THU RANH GIOI TIN CAY (Review 4, muc 6). CHI DOC.
#
# Khac moi script khac trong thu muc nay: cac phep do o day KHONG noi ve code trong
# repo, chung noi ve MAY DANG CHAY. `run.sh` chung minh parser dung; script nay
# chung minh tenant KHONG di vong duoc qua OpenResty. Hai cau hoi khac nhau, va
# bo test xanh KHONG tra loi cau thu hai.
#
# ── VI SAO PHAI CHAY BANG UID TENANT ─────────────────────────────────
#
# Review 4 doi "chay tu PHP-FPM process/UID that cua A, khong chay bang root", va
# day la yeu cau KY THUAT chu khong phai thu tuc: root ket noi duoc 6379 KHONG noi
# gi ve tenant, va root bi chan cung KHONG noi gi — hai ket qua deu VO NGHIA voi
# cau hoi dang hoi. Luat `nft ... meta skuid` loc theo UID cua process goi, nen
# phep do chi dung khi process goi MANG UID do.
#
#   root chay  -> bao "BO QUA (can UID tenant)", KHONG bao "dat"
#   tenant chay -> moi muc ra PASS/FAIL that
#
# Vi vay script tu doi UID: chay bang root thi `su - <user>` vao mot tenant that
# roi chay lai chinh no. Khong co tenant nao thi BO QUA, khong doan.
#
# ── BA TRANG THAI, KHONG PHAI HAI ────────────────────────────────────
#
# `PASS` = da do va dung. `FAIL` = da do va SAI. `BO QUA` = KHONG DO DUOC.
# Gop `BO QUA` vao `PASS` la loi da giet lop nay mot lan: `fim.sh` tung coi
# `redis-cli` thieu binary la "khong co gi doi", va `postdeploy` tung coi log da
# xoay la "khong co su kien". Mot ranh gioi KHONG DO DUOC phai hien ra la mot lo
# trong, chu khong duoc bao cao thanh an toan.
#
# Ma thoat: 0 = moi muc do duoc deu PASS. 1 = co FAIL. 2 = khong do duoc gi.
#
# DUNG (tren server, bang root — script tu ha quyen):
#   bash /usr/local/openresty/nginx/conf/antibot/waf/scripts/secaudit.sh
export LC_ALL=C

NPASS=0; NFAIL=0; NSKIP=0

ok()   { printf '  PASS   %s\n' "$1"; NPASS=$((NPASS+1)); }
bad()  { printf '  FAIL   %s\n' "$1"; NFAIL=$((NFAIL+1)); }
# ── TRANG THAI THU TU: NGOAI PHAM VI ────────────────────────────────
#
# Khac han `BO QUA`. `BO QUA` = chua do duoc, van la cau hoi mo. `NGOAI` = da do,
# ket qua co the la SAI, nhung viec sua KHONG thuoc nginx+lua nen DA QUYET DINH
# khong lam (nguoi dung chot 04-10: "cai nao khong thuoc pham vi cua nginx+lua thi
# bo").
#
# Vi sao khong de nguyen FAIL: bon cong nay se FAIL VINH VIEN. Mot bao cao luon do
# la bao cao nhieu — no se bi lo di, va roi che mat mot FAIL THAT. Day dung bai hoc
# "canh bao dung ma khong ai mo".
#
# Vi sao khong xoa han phep do: ket qua van la su that ve ranh gioi may, va neu mai
# co nguoi dat nftables thi dong nay tu doi sang PASS ma khong phai sua script.
NOOS=0
oos() { printf '  NGOAI  %s -- %s\n' "$1" "$2"; NOOS=$((NOOS+1)); }

skip() { printf '  BO QUA %s -- %s\n' "$1" "$2"; NSKIP=$((NSKIP+1)); }

# ── TCP PROBE: BA ket qua, khong phai hai ────────────────────────────
#
# `bash /dev/tcp` tra ma thoat khac 0 cho CA "refused" VA "timeout", nhung hai cai
# do la hai ket luan KHAC NHAU: refused = co luat chan (PASS); timeout = goi tin bi
# DROP im lang, co the la luat chan va cung co the la may dich khong len (KHONG KET
# LUAN duoc). Gop ca hai thanh "khong ket noi duoc" la cach de bao PASS cho mot
# cong thuc ra dang mo nhung cham.
#
# Nen do them: mot cong KHONG CO AI NGHE cung "refused". Vi vay truoc khi ket luan
# tenant bi chan, phai biet cong do CO SONG tu goc nhin cua root (muc 0 lam viec
# nay va truyen xuong qua SEC_LIVE_*).
tcp_probe() {
    local host="$1" port="$2" t="${3:-3}"
    local out rc
    out=$(timeout "$t" bash -c "exec 3<>/dev/tcp/$host/$port" 2>&1); rc=$?
    if [ "$rc" -eq 0 ]; then printf 'OPEN'; return 0; fi
    if [ "$rc" -eq 124 ]; then printf 'TIMEOUT'; return 0; fi
    case "$out" in
        *"onnection refused"*) printf 'REFUSED' ;;
        *"ermission denied"*)  printf 'DENIED' ;;
        *)                     printf 'ERR:%s' "$rc" ;;
    esac
}

# Mot cong backend/control-plane PHAI khong voi tay toi duoc tu tenant.
#
# Tham so 5 `ngoai=1` nghia la: sua duoc cho nay la `nftables`/Unix socket, tuc
# KHONG thuoc nginx+lua -> `OPEN` bao `NGOAI` chu khong bao `FAIL`. Phep do van
# chay y nguyen, nen neu mai co nguoi dat luat thi dong nay tu doi sang PASS.
must_blocked() {
    local nhan="$1" host="$2" port="$3" live="$4" ngoai="${5:-0}" r
    r=$(tcp_probe "$host" "$port")
    case "$r" in
        OPEN)
            if [ "$ngoai" = "1" ]; then
                oos "$nhan" "tenant MO duoc $host:$port — sua bang nftables/Unix socket, ngoai nginx+lua"
            else
                bad "$nhan -- tenant MO duoc $host:$port ($r)"
            fi ;;
        TIMEOUT)          skip "$nhan" "goi tin bi DROP, khong phan biet duoc chan hay dich chet ($r)" ;;
        REFUSED|DENIED)
            if [ "$live" = "1" ]; then ok "$nhan -- $r (cong dang song voi root)"
            else skip "$nhan" "$r nhung cong KHONG song voi root -> chua chung minh duoc la do luat chan"; fi ;;
        *)                skip "$nhan" "ket qua khong hieu ($r)" ;;
    esac
}

APACHE_HTTP_PORT="${SEC_APACHE_HTTP:-8080}"
APACHE_HTTPS_PORT="${SEC_APACHE_HTTPS:-8081}"
REDIS_PORT="${SEC_REDIS_PORT:-6379}"
HOME_BASE="${SEC_HOME:-/home}"
DA_USERS="${SEC_DA_USERS:-/usr/local/directadmin/data/users}"

# ── CHON TENANT: phai la KHACH, khong phai tai khoan quan tri ────────
#
# Ban dau lay thu muc DAU TIEN trong `/home/*/domains` va bo loc `uid >= 500`. Do
# 04-10 tren cloud171-96: no chon `admin` (uid 1000) — tai khoan QUAN TRI cua
# DirectAdmin, `usertype=admin`, `creator=root`, `domains.list` RONG. Glob tra
# `admin` truoc vi thu tu ASCII, nen no LUON bi chon.
#
# Hau qua: ca bon muc con lai do bang quyen cua mot tai khoan duoc phep nhieu hon
# tenant, nen FAIL/PASS cua chung khong tra loi dung cau hoi. `admin` doc duoc
# `config.lua` co the la HOP LE; mot tenant khach doc duoc thi la LO THAT.
#
# Nay loc bang BANG CHUNG cua DirectAdmin chu khong bang UID:
#   · `usertype=admin`/`reseller` -> KHONG phai tenant khach
#   · `domains.list` rong         -> khong co site, khong dai dien cho tenant
# Do duoc tren fleet: 73 user co `domains/` va 73 muc trong `data/users` -> KHOP,
# nen `data/users` la nguon dung de hoi "ai la user".
pick_tenant() {
    local d u ut
    for d in "$HOME_BASE"/*/domains; do
        [ -d "$d" ] || continue
        u=${d%/domains}; u=${u##*/}
        id "$u" >/dev/null 2>&1 || continue
        [ "$(id -u "$u")" -ge 500 ] 2>/dev/null || continue
        # Loai admin/reseller theo khai bao cua chinh DirectAdmin.
        ut=$(sed -n 's/^usertype=//p' "$DA_USERS/$u/user.conf" 2>/dev/null)
        case "$ut" in admin|reseller) continue ;; esac
        # Phai co it nhat mot domain THAT tren dia.
        [ -n "$(ls -1 "$d" 2>/dev/null | head -1)" ] || continue
        printf '%s' "$u"; return 0
    done
    return 1
}

if [ "${SEC_AS_TENANT:-0}" != "1" ]; then
    echo "=== 0. GOC NHIN ROOT: cong nao dang song ==="
    [ "$(id -u)" -eq 0 ] || echo "  (khong phai root -- muc 0 co the thieu)"
    LIVE_HTTP=0; LIVE_HTTPS=0; LIVE_REDIS=0
    r=$(tcp_probe 127.0.0.1 "$APACHE_HTTP_PORT");  [ "$r" = OPEN ] && LIVE_HTTP=1
    printf '  apache http  127.0.0.1:%s = %s\n' "$APACHE_HTTP_PORT" "$r"
    r=$(tcp_probe 127.0.0.1 "$APACHE_HTTPS_PORT"); [ "$r" = OPEN ] && LIVE_HTTPS=1
    printf '  apache https 127.0.0.1:%s = %s\n' "$APACHE_HTTPS_PORT" "$r"
    r=$(tcp_probe 127.0.0.1 "$REDIS_PORT");        [ "$r" = OPEN ] && LIVE_REDIS=1
    printf '  redis        127.0.0.1:%s = %s\n' "$REDIS_PORT" "$r"
    LIVE_DA=0
    r=$(tcp_probe 127.0.0.1 2222);                 [ "$r" = OPEN ] && LIVE_DA=1
    printf '  directadmin  127.0.0.1:2222 = %s\n' "$r"
    echo

    TEN=$(pick_tenant) || TEN=""
    if [ -z "$TEN" ]; then
        echo "KHONG tim duoc tenant nao duoi $HOME_BASE/*/domains -- khong the do ranh gioi."
        echo "=> rc=2 (khong do duoc)"
        exit 2
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "Can root de ha quyen sang '$TEN'. Chay lai bang root."
        echo "=> rc=2 (khong do duoc)"
        exit 2
    fi
    # Danh sach tenant KHAC, do root lap (tenant khong doc duoc `$DA_USERS`).
    # Cat 40 ten de dong `su -c` khong phinh vo han; 40 du de ket luan "tat ca bi
    # tu choi" hay "co cho mo duoc".
    OTHERS=""
    n_oth=0
    for _ud in "$DA_USERS"/*; do
        [ -d "$_ud" ] || continue
        _u=${_ud##*/}
        [ "$_u" = "$TEN" ] && continue
        case "$(sed -n 's/^usertype=//p' "$_ud/user.conf" 2>/dev/null)" in
            admin|reseller) continue ;;
        esac
        OTHERS="$OTHERS $_u"
        n_oth=$((n_oth + 1))
        [ "$n_oth" -ge 40 ] && break
    done
    printf '  tenant khac se do: %s\n' "$n_oth"

    echo "Ha quyen sang tenant '$TEN' (uid $(id -u "$TEN")) roi chay lai..."
    echo
    # `su - <user> -c` chay lai CHINH script nay. Truyen trang thai song qua bien
    # moi truong vi tenant khong do lai duoc (do la toan bo diem cua phep do).
    exec su -s /bin/bash - "$TEN" -c "SEC_AS_TENANT=1 SEC_TENANT='$TEN' \
        SEC_LIVE_HTTP=$LIVE_HTTP SEC_LIVE_HTTPS=$LIVE_HTTPS SEC_LIVE_REDIS=$LIVE_REDIS \
        SEC_LIVE_DA=$LIVE_DA \
        SEC_APACHE_HTTP='$APACHE_HTTP_PORT' SEC_APACHE_HTTPS='$APACHE_HTTPS_PORT' \
        SEC_REDIS_PORT='$REDIS_PORT' SEC_HOME='$HOME_BASE' SEC_DA_USERS='$DA_USERS' \
        SEC_OTHERS='$OTHERS' \
        bash '$(readlink -f "$0")'"
fi

echo "=== NGHIEM THU RANH GIOI -- chay bang uid $(id -u) ($(id -un)) ==="
echo
echo "--- 1. Apache backend: tenant khong duoc di vong qua OpenResty (Review 4, 4.1) ---"
must_blocked "apache http  :$APACHE_HTTP_PORT"  127.0.0.1 "$APACHE_HTTP_PORT"  "${SEC_LIVE_HTTP:-0}"  1
must_blocked "apache https :$APACHE_HTTPS_PORT" 127.0.0.1 "$APACHE_HTTPS_PORT" "${SEC_LIVE_HTTPS:-0}" 1
echo

echo "--- 2. Redis la control plane cua WAF (Review 4, 4.2) ---"
# Hai cau hoi DOC LAP, va cau thu hai moi la cau quan trong:
#   (a) tenant co MO duoc socket khong?
#   (b) neu mo duoc, Redis co DOI AUTH khong?
# Mot Redis `default on nopass ~* +@all` ma tenant mo duoc = tenant GHI duoc
# `verified:*` va khoa FIM. Chon DB khac KHONG phai isolation.
rr=$(tcp_probe 127.0.0.1 "$REDIS_PORT")
case "$rr" in
    OPEN)
        # SOCKET mo duoc = `nftables`/Unix socket -> NGOAI pham vi nginx+lua.
        # Nhung AUTH (ngay duoi) thi CHINH LA nginx+lua, nen no van la PASS/FAIL
        # thuc su: `requirepass` chan LENH, con cong thi khong chan duoc tu Lua.
        oos "redis :$REDIS_PORT (socket)" "tenant mo duoc cong — sua bang nftables/Unix socket, ngoai nginx+lua"
        # Da mo duoc thi do tiep: khong AUTH ma PING duoc la khong co ACL.
        # `read -t` MOT DONG, khong `head -c N`. Redis tra dung `+PONG\r\n` = 7 byte,
        # nen `head -c 64` CHO du 64 byte, bi `timeout` giet, va tra ve RONG -> phep do
        # bao "khong doc duoc tra loi" tren mot Redis dang MO TOANG. Do duoc trong WSL:
        # `head -c 64` -> rong; `read -t 2` -> `+PONG`. Mot blind spot bao cao thanh
        # "chua do duoc" la dung cai lop nay ton tai de tranh.
        pong=$(timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$REDIS_PORT
            printf 'PING\r\n' >&3; read -t 2 -r L <&3; printf '%s' \"\$L\"" 2>/dev/null)
        case "$pong" in
            *PONG*)      bad "redis AUTH -- PING khong can mat khau da tra PONG (ACL/requirepass TAT)" ;;
            *NOAUTH*|*NOPERM*|*WRONGPASS*)
                         ok  "redis AUTH -- server doi xac thuc ($(printf '%s' "$pong" | tr -d '\r\n' | head -c 40))" ;;
            "")          skip "redis AUTH" "mo duoc socket nhung khong doc duoc tra loi" ;;
            *)           skip "redis AUTH" "tra loi khong hieu: $(printf '%s' "$pong" | tr -d '\r\n' | head -c 40)" ;;
        esac ;;
    TIMEOUT)          skip "redis :$REDIS_PORT" "DROP im lang, khong phan biet duoc ($rr)" ;;
    REFUSED|DENIED)
        if [ "${SEC_LIVE_REDIS:-0}" = "1" ]; then ok "redis :$REDIS_PORT -- $rr (dang song voi root)"
        else skip "redis :$REDIS_PORT" "$rr nhung Redis khong song voi root -> chua chung minh duoc"; fi ;;
    *)                skip "redis :$REDIS_PORT" "ket qua khong hieu ($rr)" ;;
esac
echo

echo "--- 3. Control plane khac (Review 4, 4.4 muc 4) ---"
# KHONG doc noi dung gi trong cac socket nay; chi hoi "co voi tay toi duoc khong".
for s in /var/run/docker.sock /usr/local/directadmin/data/task.queue; do
    if [ ! -e "$s" ]; then skip "$s" "khong ton tai tren may nay"
    elif [ -r "$s" ]; then bad "$s -- tenant DOC duoc"
    else ok "$s -- tenant khong doc duoc"; fi
done
must_blocked "directadmin :2222" 127.0.0.1 2222 "${SEC_LIVE_DA:-0}" 1
echo
echo "--- 4. Cach ly giua tenant (Review 4, 4.3) ---"
# ── KHONG DOC DU LIEU KHACH ──────────────────────────────────────────
#
# Day la rang buoc CUNG, khong phai danh doi. Phep do o day hoi "co MO duoc khong",
# bang `[ -r ]` va `[ -w ]`, va KHONG BAO GIO `cat` mot tep cua khach. Mot phep do
# chung minh duoc cach ly bang cach in `wp-config.php` ra man hinh la mot phep do
# TU NO vi pham chinh dieu dang kiem.
#
# `-r` chay bang UID tenant nen tra loi dung cau hoi cua kernel. Luu y gioi han:
# `-r` dung cho DAC QUYEN UID, con `open_basedir` la rao cua PHP va KHONG hien ra
# o day -- do la ly do muc nay do bang UID that chu khong do bang PHP.
# ── `-d` THAT BAI LA BANG CHUNG, KHONG PHAI "KHONG CO GI DE SO" ──────
#
# Ban truoc `continue` khi `[ -d "$d" ]` false. Nhung phep do nay chay bang UID
# TENANT, va `/home/<user>` o DirectAdmin la `711`/`750` — nen tenant KHONG stat
# duoc `/home/khac/domains` va `-d` tra false. Ket qua: dem ra 0, roi bao
#     "chi co 1 tenant duoi /home -> khong co gi de so"
# trong khi tren may co 73 tenant va `-d` false CHINH LA cach ly dang hoat dong.
# Mot bang chung PASS bi dich thanh "khong do duoc" (do 04-10, cloud171-96).
#
# Nen danh sach tenant lay tu `DA_USERS` (root tao, tenant khong can stat `/home`
# cua nguoi khac), con `-r`/`-w` moi la phep do. Ba trang thai:
#   doc duoc        -> FAIL (ho ca ly)
#   khong doc duoc  -> PASS (ke ca khi `-d` false: khong voi tay toi duoc)
#   khong co ai khac -> BO QUA
ME="${SEC_TENANT:-$(id -un)}"
nkhac=0; ndoc=0; nghi=0
# Danh sach tenant do ROOT lap o muc 0 roi truyen xuong qua `SEC_OTHERS`.
#
# KHONG liet ke `$DA_USERS` o day: thu muc do la `700 diradmin` nen tenant khong
# doc duoc, va vong `for` se khong khop gi -> `nkhac=0` -> lai roi vao dung cai
# "BO QUA" ma sua nay dang go. Cung ho voi `-d` false o ban truoc: dung mot phep
# BI CHAN lam nguon danh sach thi mat luon kha nang do.
for u in ${SEC_OTHERS:-}; do
    [ "$u" = "$ME" ] && continue
    d="$HOME_BASE/$u/domains"
    nkhac=$((nkhac+1))
    # Chi hoi quyen, khong liet ke, khong doc tep ben trong cua khach.
    [ -r "$d" ] && ndoc=$((ndoc+1))
    [ -w "$d" ] && nghi=$((nghi+1))
done
if [ "$nkhac" -eq 0 ]; then
    skip "cach ly tenant" "chi co 1 tenant duoi $HOME_BASE -> khong co gi de so"
else
    [ "$ndoc" -eq 0 ] && ok  "doc thu muc cua $nkhac tenant khac -- tat ca bi tu choi" \
                       || bad "doc thu muc cua tenant khac -- $ndoc/$nkhac MO duoc"
    [ "$nghi" -eq 0 ] && ok  "ghi thu muc cua $nkhac tenant khac -- tat ca bi tu choi" \
                       || bad "ghi thu muc cua tenant khac -- $nghi/$nkhac GHI duoc"
fi
echo

echo "--- 5. Secret cua WAF/OpenResty (Review 4, 4.3 muc cuoi) ---"
# `config.lua` chua `pow.challenge_secret`, `admin/init.lua` chua AUTH_USER/AUTH_PASS.
# Tenant doc duoc mot trong hai la doc duoc bi mat ky challenge -> tu sinh cookie
# `verified:*` hop le va di qua toan bo lop cham diem.
A="${SEC_ANTIBOT:-/usr/local/openresty/nginx/conf/antibot}"
# In them CHE DO BAT PHAN: `-r` chi tra loi "tenant nay doc duoc khong", con cai
# sua duoc la "tep co world-readable khong". Do 04-10: ca hai tep la `644
# root:root`, tuc MOI user tren may doc duoc — khong rieng gi tenant nao. Thieu cot
# nay thi nguoi doc khong biet phai `chmod` cai gi.
for f in "$A/core/config.lua" "$A/admin/init.lua"; do
    if [ ! -e "$f" ]; then skip "$f" "khong ton tai"
    elif [ -r "$f" ]; then
        bad "$f -- tenant DOC duoc (che do $(stat -c '%a %U:%G' "$f" 2>/dev/null))"
    else ok "$f -- tenant khong doc duoc"; fi
done
# `waf.log` chi sinh ra khi co luot WAF ghi, nen "khong ton tai" o day la BO QUA
# dung nghia. `antibot.log` thi phai co: thu muc la `750 nginx:nginx` nen tenant
# khong stat duoc -> `-e` false -> BO QUA "khong ton tai". Do la KET LUAN SAI ve
# mot tep CO THAT (do 04-10: 51 MB, `640 nginx:nginx`). Phan biet hai ca bang
# cach hoi thu muc cha.
for f in /var/log/antibot/antibot.log /var/log/antibot/waf.log; do
    if [ -r "$f" ]; then bad "$f -- tenant DOC duoc log cua he thong"
    elif [ -e "$f" ]; then ok "$f -- co that, tenant khong doc duoc"
    elif [ -r "${f%/*}" ]; then skip "$f" "thu muc doc duoc nhung tep khong ton tai"
    else ok "$f -- tenant khong voi tay toi duoc (ke ca thu muc cha)"; fi
done
echo
echo "=== TONG ==="
printf '  PASS   %d\n  FAIL   %d\n  BO QUA %d\n  NGOAI  %d\n' \
       "$NPASS" "$NFAIL" "$NSKIP" "$NOOS"
echo
# BON trang thai, va chi `FAIL` lam rc khac 0:
#   PASS   da do, dung
#   FAIL   da do, SAI, va sua duoc trong nginx+lua -> phai hanh dong
#   BO QUA chua do duoc -> mot cau hoi mo, KHONG duoc doc thanh "an toan"
#   NGOAI  da do, co the sai, nhung sua bang nftables/php-fpm/systemd — DA QUYET
#          DINH khong lam (nguoi dung chot 04-10). Khong lam rc khac 0, nhung van
#          in ra: mot lo trong da biet van la lo trong.
if [ "$NFAIL" -gt 0 ]; then
    echo "=> rc=1: co ranh gioi DA DO va SAI trong pham vi nginx+lua. Phai hanh dong."
    exit 1
fi
if [ "$NPASS" -eq 0 ]; then
    echo "=> rc=2: khong do duoc muc nao."
    exit 2
fi
[ "$NSKIP" -gt 0 ] && echo "LUU Y: $NSKIP muc KHONG DO DUOC -- chua phai la 'an toan'."
[ "$NOOS"  -gt 0 ] && echo "LUU Y: $NOOS muc NGOAI pham vi nginx+lua -- lo trong DA BIET, khong phai da dong."
echo "=> rc=0: moi muc trong pham vi nginx+lua deu dat."
exit 0
