#!/bin/bash
#
# Deploy antibot: pull -> kiem cu phap -> sync -> nginx -t -> reload.
#
# ============================================================================
# NGUYEN TAC: bao tri Redis KHONG BAO GIO chay tu dong.
#
# Cac nhanh --fleet / --goodbot / --crawler deu XOA khoa Redis, va moi lan xoa
# la MO MOT CUA SO PHONG THU (khoa cam bien mat cho toi khi bot tai pham va bi
# ghi an lai). Chung phai la thao tac TAY, co chu dich, nguoi chay biet minh
# dang xoa gi. Dung bao gio them chung vao duong mac dinh hay vao cron.
# ============================================================================
#
# Dung:
#   ./deploy.sh                     # pull + sync + kiem + reload  (an toan)
#   ./deploy.sh --no-reload         # deploy nhung khong reload
#   ./deploy.sh --fleet             # + xoa moi fl:dyn:*
#   ./deploy.sh --goodbot ten [...] # + xoa goodbot:dns|asn|ptr_only:<ten>
#   ./deploy.sh --crawler           # + go an cho IP co PTR crawler chinh chu
#
# Khi nao can tung nhanh -- xem bang cuoi file.

set -e

REPO_DIR="/home/xadmin/antibot/antibot-no-upstream"
SOURCE_DIR="$REPO_DIR/antibot-core/"
TARGET_DIR="/usr/local/openresty/nginx/conf/antibot"
NGINX="/usr/local/openresty/nginx/sbin/nginx"
LUAJIT="/usr/local/openresty/luajit/bin/luajit"
RESTY="/usr/local/openresty/bin/resty"

DO_RELOAD=1
# Bat Redis `requirepass` la thao tac EXPLICIT, khong phai tac dung le cua deploy.
# Review 7 muc 1: deploy thuong chi KIEM TRA trang thai; bat auth tu dong lam mot co
# ten `--no-reload` co ngoai le an (buoc [9] van reload), va mot transaction nua
# duong co the persist `requirepass` vao `redis.conf` khi worker chua nap duoc.
DO_REDIS_AUTH=0
DO_FLEET=0
DO_CRAWLER=0
GOODBOT_NAMES=()

# Thu muc tam RIENG, quyen 700, KHONG dung ten co dinh trong /tmp.
# Day la may shared hosting: co nguoi dung cuc bo khong tin cay. Mot ten co
# dinh nhu /tmp/fl_dyn_removed.txt cho phep ho tao san mot symlink tro toi
# /etc/shadow (hay bat ky file nao); script chay bang root, `tee` di theo
# symlink va ghi de file do bang quyen root.
TMPD=$(mktemp -d) || { echo "khong tao duoc thu muc tam"; exit 1; }
chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT

while [ $# -gt 0 ]; do
    case "$1" in
        --no-reload) DO_RELOAD=0; shift ;;
        --enable-redis-auth) DO_REDIS_AUTH=1; shift ;;
        --fleet)     DO_FLEET=1;  shift ;;
        --crawler)   DO_CRAWLER=1; shift ;;
        --goodbot)   shift
                     while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do
                         GOODBOT_NAMES+=("$1"); shift
                     done ;;
        *) echo "Tham so la: $1"; exit 1 ;;
    esac
done

echo "=== START DEPLOY ==="

cd "$REPO_DIR"

echo "[1] Pull latest code..."
git pull origin main
echo "    commit: $(git rev-parse --short HEAD) $(git log -1 --format=%s)"

# Kiem cu phap TREN NGUON, truoc khi cham vao cay dang chay.
# May dev khong co Lua nen day la lan kiem cu phap DAU TIEN cua moi thay doi.
# Sai cu phap ma da rsync roi thi cay live hong san, chi con may man la nginx
# chua reload. Chan tu day thi cay live khong bao gio bi cham toi.
echo "[2] Kiem cu phap Lua..."
lua_fail=0
while IFS= read -r f; do
    if ! "$LUAJIT" -b "$f" /dev/null 2>/dev/null; then
        echo "    LOI CU PHAP: $f"
        "$LUAJIT" -b "$f" /dev/null || true
        lua_fail=1
    fi

    # Module thieu `return _M` van DUNG CU PHAP hoan toan, nen `luajit -b` o tren
    # cho qua. Nhung Lua 5.1 khong bao loi khi module tra nil — `require` tra
    # `true` (boolean). Loi no MUON, o cho dung module do:
    #     local body = require "antibot.waf.body"   -- = true
    #     body.probe(ctx)   -- attempt to index a boolean value
    # Voi `waf/body.lua` thi cho do la `run_pre`, access phase, tren moi request
    # khong di nhanh `block` => 500 dien rong ca dan may.
    #
    # Da xay ra that ngay 2026-09-04 (f69b896): mot lan ghep file bang sed nuot
    # mat dong cuoi. Bo test bat duoc, nhung chi vi tinh co co bo test cho dung
    # module do — mot module khong co test se di thang ra san xuat.
    if grep -qE '^local _M[[:space:]]*=[[:space:]]*{' "$f" && ! grep -qE '^return _M' "$f"; then
        echo "    THIEU 'return _M': $f"
        lua_fail=1
    fi
done < <(find "$SOURCE_DIR" -name '*.lua')
if [ $lua_fail -ne 0 ]; then
    echo "HUY: co file Lua hong. KHONG sync, cay dang chay giu nguyen."
    exit 1
fi

# .sh trong antibot-core cung phai qua cong nay, cung ly le voi Lua o tren:
# waf/scripts/fim.sh la thanh phan cua tang WAF va no CHAY TU CAY DA DEPLOY,
# nen mot loi
# cu phap o do la cron im lang khong chay nua — kieu hong khong ai thay.
sh_fail=0
while IFS= read -r f; do
    if ! bash -n "$f" 2>/dev/null; then
        echo "    LOI CU PHAP: $f"
        bash -n "$f" || true
        sh_fail=1
    fi
done < <(find "$SOURCE_DIR" -name '*.sh')
if [ $sh_fail -ne 0 ]; then
    echo "HUY: co file shell sai cu phap. KHONG sync, cay dang chay giu nguyen."
    exit 1
fi
echo "    OK"

# [2b] `thread_pool` doi OpenResty build voi `--with-threads`.
#
# CHAN O DAY, TRUOC RSYNC, chu khong de `nginx -t` o [4d] bat. Neu de toi do
# thi cay antibot-core DA sync xong, nginx.conf bi khoi phuc, script exit 1 va
# KHONG reload — may do chay code cu voi cay moi tren dia, mot trang thai nua
# voi. Chan som thi khong dong gi ca.
#
# Dieu kien nay khac moi cong khac o cho no phu thuoc BAN BUILD cua tung may,
# khong phai noi dung repo. cloud168-101 co (xac nhan 05-09); may nao khong co
# thi hoac build lai OpenResty, hoac them dau `#` vao dong do trong repo —
# code tu bao `scan=nothread`, khong hong gi.
if grep -qE '^[[:space:]]*thread_pool[[:space:]]+antibot_waf_io' "$REPO_DIR/nginx/nginx.conf"; then
    echo "[2b] Kiem --with-threads..."
    if "$NGINX" -V 2>&1 | grep -q -- '--with-threads'; then
        echo "    OK"
    else
        echo "    OpenResty tren may nay build KHONG co --with-threads."
        echo "    nginx.conf trong repo lai co 'thread_pool antibot_waf_io' dang bat"
        echo "    => nginx -t se bao 'unknown directive'."
        echo "HUY: KHONG sync, cay dang chay giu nguyen."
        echo "     Cach xu ly: them dau # vao dong thread_pool trong"
        echo "     nginx/nginx.conf CUA REPO. Than tran ra file tam se khong duoc"
        echo "     soi, va cot scan=nothread trong waf.log noi ro bao nhieu."
        exit 1
    fi
fi

# goodbot.json hong = goodbot_seed bo qua toan bo registry -> moi bot xin
# tut xuong duong attest hoac bi cham diem. Im lang, kho lan ra.
if [ -x "$RESTY" ] && [ -f "$SOURCE_DIR/core/data/goodbot.json" ]; then
    echo "[3] Kiem goodbot.json..."
    if ! "$RESTY" -e '
        local f = io.open("'"$SOURCE_DIR"'core/data/goodbot.json", "r")
        if not f then os.exit(1) end
        local c = f:read("*a"); f:close()
        local d = require("cjson.safe").decode(c)
        if not d or not d.bots then os.exit(1) end
        local n = 0; for _ in pairs(d.bots) do n = n + 1 end
        io.write("    OK - ", n, " bot trong registry\n")
    '; then
        echo "HUY: goodbot.json khong parse duoc hoac thieu khoa .bots"
        exit 1
    fi
fi

# T — bo test luat WAF. Chay TREN NGUON, cung ly do voi buoc [2]: mot luat sai
# NGU NGHIA van qua duoc `luajit -b` sach se. Cho no ra production nghia la
# phat hien FP bang cach gay ra FP tren luu luong khach hang.
# Can resty chu khong phai luajit: luat quyet dinh bang PCRE lookahead cua ngx.re.
if [ -x "$RESTY" ] && [ -x "$REPO_DIR/antibot-core/waf/scripts/run.sh" ]; then
    echo "[3b] Chay T (test luat WAF + L7 admission/circuit breaker)..."

    # ── REDIS TAM cho nhom 27 (`LC_ALL=C`) ──────────────────────────
    #
    # Nhom 27 kiem mot loi protocol THAT: RESP khai do dai doi so bang BYTE, nhung
    # `${#s}` va `length()` dem KY TU khi locale la UTF-8 — nen mot thu muc ten tieng
    # Viet lam CA batch that bai (`ERR Protocol error: expected '$', got '/'`) va 12
    # khoa khong duoc ghi. Stub KHONG tai hien duoc: no khong doc do dai.
    #
    # Khong co Redis o 6399 thi nhom do bao `BO QUA` — do duoc 04-10 tren 171-96, va do
    # la nhom DUY NHAT bi bo qua. Mot deploy khong tu kiem duoc `LC_ALL` tren may co
    # locale khac WSL thi loi do quay lai trong im lang.
    #
    # PORT 6399 chu khong 6379: khong cham instance dang phuc vu. `--save ''` +
    # `--appendonly no` de khong ghi dia. Tat o `trap` nen no khong song sot qua mot
    # deploy that bai.
    RTEST_PORT=6399
    RTEST_PID=""
    if command -v redis-server >/dev/null 2>&1 \
       && [ "$(redis-cli -p "$RTEST_PORT" ping 2>/dev/null)" != "PONG" ]; then
        redis-server --port "$RTEST_PORT" --daemonize yes --save '' \
                     --appendonly no --bind 127.0.0.1 >/dev/null 2>&1 || :
        # Cho toi 2 giay. KHONG `sleep` co dinh: mot may nhanh khong phai cho, va mot
        # may cham thi 0.2s khong du.
        for _i in 1 2 3 4 5 6 7 8 9 10; do
            [ "$(redis-cli -p "$RTEST_PORT" ping 2>/dev/null)" = "PONG" ] && break
            sleep 0.2
        done
        if [ "$(redis-cli -p "$RTEST_PORT" ping 2>/dev/null)" = "PONG" ]; then
            RTEST_PID=$(redis-cli -p "$RTEST_PORT" INFO server 2>/dev/null \
                        | sed -n 's/^process_id:\([0-9]*\).*/\1/p')
            echo "     Redis tam o port $RTEST_PORT (pid ${RTEST_PID:-?}) cho nhom 27."
        else
            echo "     KHONG khoi dong duoc Redis tam -- nhom 27 se BO QUA."
        fi
    fi
    # Tat NGAY khi roi buoc nay, ke ca khi test hong hay script bi ngat.
    rtest_stop() {
        [ -n "${RTEST_PID:-}" ] || return 0
        redis-cli -p "$RTEST_PORT" SHUTDOWN NOSAVE >/dev/null 2>&1 || kill "$RTEST_PID" 2>/dev/null || :
        RTEST_PID=""
    }
    trap rtest_stop EXIT INT TERM

    if ! "$REPO_DIR/antibot-core/waf/scripts/run.sh"; then
        rtest_stop
        if [ "${SKIP_TEST:-0}" = "1" ]; then
            echo "     SKIP_TEST=1 — di tiep BAT CHAP test hong."
        else
            echo "HUY: co test hong. KHONG sync, cay dang chay giu nguyen."
            echo "     Ep di tiep khi that su can: SKIP_TEST=1 ./deploy.sh"
            exit 1
        fi
    fi
    rtest_stop
    trap - EXIT INT TERM
fi

echo "[4] Sync core folder..."
rsync -avz --delete "$SOURCE_DIR" "$TARGET_DIR"

# BIT THUC THI — rsync -a BAO TOAN mode TU NGUON, nen mot script 644 trong git
# toi day van 644 va `./postdeploy.sh` tra RC=126 ("found but not executable").
#
# DA XAY RA, va kieu that bai cua no la cai dang so: 05-10-2026 `postdeploy.sh`
# o mode 100644 trong git tren CA 6 MAY. Script tu kiem sau deploy chua tung
# chay duoc bang cach goi truc tiep, va vi no khong in gi ca thi output rong
# trong nhu "khong co van de" chu khong nhu "khong chay duoc". Mot lan truoc do
# ket luan "muc 21 chua commit" cung tu output rong nay — dung ket luan, sai ly
# do, vi khong ai doc $?.
#
# Vi sao sua o DAY chu khong chi `git update-index --chmod=+x`: mode trong git la
# nguon that, nhung mot file .sh moi tao tren Windows (core.filemode=false) vao
# index la 644 va KHONG AI THAY cho den khi goi no tren may that. Vong nay dong
# lai sau deploy, khong phu thuoc ai nho chmod luc commit.
#
# `-type f -name '*.sh'` chu khong `chmod -R +x`: thu muc va .lua/.awk/.txt
# khong can bit nay.
find "$TARGET_DIR/waf/scripts" "$TARGET_DIR/intelligence/threat/scripts" \
     -type f -name '*.sh' -exec chmod 0755 {} + 2>/dev/null || :

# DAU BAN — PHAI ghi SAU rsync, vi buoc tren dung `--delete` va se xoa chinh
# file nay neu no da nam san trong $TARGET_DIR.
#
# VI SAO CAN. 2026-09-11: cloud183-139 chay ban truoc `aca6bef`, tuc cot `ua=`
# van cat o 120 ky tu. Hau qua khong phai "thieu mot tinh nang" ma la SO LIEU
# SAI MA KHONG BAO: 2.250/3.086 dong trong mot phep do hoa ra la anh ao, va suyt
# dan toi viec them mot nhanh Android WebView vao `pseudo_header.lua` de sua mot
# loi KHONG TON TAI. Day la lan thu sau mot ket luan bi cot log cat cut lam hong.
#
# Goc cua no khong nam trong ma Lua nao ca: KHONG CO CACH NAO HOI MOT MAY DANG
# CHAY BAN NAO. Suy ra tu do dai chuoi UA la meo vat, va meo vat thi chi dung
# cho dung mot phep do. Ba dong duoi bien cau hoi do thanh mot lenh `cat`.
#
# `git -C` chu khong phai `cd`: deploy.sh co the duoc goi tu bat ky thu muc nao.
# Moi gia tri deu co duong lui, vi mot may thieu `git` van phai deploy duoc.
{
    echo "sha=$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    echo "subject=$(git -C "$REPO_DIR" log -1 --pretty=%s 2>/dev/null || echo unknown)"
    echo "committed=$(git -C "$REPO_DIR" log -1 --date=iso --pretty=%cd 2>/dev/null || echo unknown)"
    echo "deployed=$(date '+%Y-%m-%d %H:%M:%S')"
    echo "host=$(hostname)"
} > "$TARGET_DIR/VERSION"
chmod 0644 "$TARGET_DIR/VERSION"
sed 's/^/    /' "$TARGET_DIR/VERSION"

# ---------------------------------------------------------------------------
# DIA CHI CUA CHINH MAY NAY -> self_addrs.txt
#
# `core/ip_scope.lua:is_self()` gac hai cong: khong tu ket an va khong tu gan
# nhan dan-thiet-bi. No so dia chi nguon voi `$server_addr`, va phep so do dung
# voi hai trong ba hinh thai mang:
#
#   1. khong NAT, card chi co IP public            -> `$server_addr` du
#   2. co NAT, card co CA public lan private       -> `$server_addr` du
#   3. co NAT, card CHI co IP private              -> KHONG du
#
# Hinh thai 3 (do 15-09: cloud168-101 chi co `192.168.168.101` tren card, vao
# va ra deu qua `123.30.168.101`) can dia chi public, ma may sau NAT khong tu
# suy ra duoc tu ben trong. Ghi o day chu KHONG khai tay trong `config.lua`:
# `config.lua` deploy chung cho ca dan may, nen khai tay se bat moi may mang
# danh sach IP cua moi may khac, va may thu sau lai phai sua tay lan nua.
#
# Sinh TAI CHO tren tung may, moi lan deploy:
#   - `ip addr`   -> dia chi thuc tren card (hinh thai 1 va 2)
#   - `getent`    -> hostname cua may tro toi dau (hinh thai 3; dung NSS nen an
#                    theo ca /etc/hosts lan DNS, khong can `dig`)
#
# Loai loopback va 0.0.0.0. Khong loai dia chi private: chung vo hai o day va
# da duoc `is_private` xu ly o cho khac.
#
# PHAI ghi SAU rsync — `--delete` se xoa file khong co trong nguon, dung ly do
# VERSION o tren cung nam sau.
{
    ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
    getent ahostsv4 "$(hostname -f 2>/dev/null || hostname)" 2>/dev/null | awk '{print $1}'
} | grep -vE '^(127\.|0\.0\.0\.0$)' | sort -u > "$TARGET_DIR/self_addrs.txt"
chmod 0644 "$TARGET_DIR/self_addrs.txt"
n_self=$(grep -c . "$TARGET_DIR/self_addrs.txt" || echo 0)
echo "    self_addrs ($n_self): $(tr '\n' ' ' < "$TARGET_DIR/self_addrs.txt")"
if [ "${n_self:-0}" -eq 0 ]; then
    echo "    *** KHONG xac dinh duoc dia chi nao cua may — is_self() se khong ***"
    echo "    *** bao gio kich hoat, may co the tu ban chinh no.               ***"
fi

# Cau hinh logrotate nam trong repo chu khong cau hinh tay tren tung may:
# da co ca antibot.log khong xoay suot 28 ngay vi trot bo sot mot may.
# Chi ghi de khi noi dung khac -> chay lai deploy nhieu lan khong gay nhieu.
if [ -f "$REPO_DIR/nginx/logrotate/antibot" ] && [ -d /etc/logrotate.d ]; then
    if ! cmp -s "$REPO_DIR/nginx/logrotate/antibot" /etc/logrotate.d/antibot; then
        cp "$REPO_DIR/nginx/logrotate/antibot" /etc/logrotate.d/antibot
        chmod 0644 /etc/logrotate.d/antibot
        echo "[4b] logrotate: da cap nhat /etc/logrotate.d/antibot"
    fi
fi

# Quyen thu muc log. CHAN O THU MUC, khong phai o tung file.
#
# `async/logger.lua` va `async/waf_logger.lua` deu tao file bang
# `io.open(path,"a")` — Lua khong dat duoc mode, no lay 0666 tru umask, va umask
# cua worker tren dan may nay bang 0. Ket qua: moi file log do CHINH antibot tao
# ra deu la `-rw-rw-rw-`.
#
# Do 2026-09-05 tren cloud183-139: `antibot.log-20260905` 8,9 GB, mode 666.
# Tren hosting chia se co tenant khong tin cay, do la moi khach hang deu DOC
# duoc IP/UA/domain/hash danh tinh cua moi domain khac, va GHI them duoc dong
# gia vao dung file ma moi phep do dang dua vao.
#
# Vi sao sua o THU MUC chu khong chmod tung file: chmod file chi dung toi luc
# file do bi xoa hoac chua ton tai — lan `ensure()` ke tiep tao lai la 666 lai.
# Thu muc khong cho `others` di vao thi mode cua file ben trong thanh vo nghia,
# va no dung cho ca file chua duoc tao. logrotate `create 0640` lo phan con lai.
#
# 0750 chu khong phai 0700: giu nhom `nginx` doc duoc, vi worker chay duoi user
# do va `admin/init.lua` cung o trong so.
if [ -d /var/log/antibot ]; then
    cur=$(stat -c '%a' /var/log/antibot 2>/dev/null || echo "?")
    if [ "$cur" != "750" ]; then
        chown nginx:nginx /var/log/antibot
        chmod 0750 /var/log/antibot
        echo "[4c] quyen log: /var/log/antibot $cur -> 750 (nginx:nginx)"
    fi
    # Vet lai file da bi tao 666 truoc khi co buoc nay. `|| :` vi thu muc co the
    # rong o lan deploy dau tien tren mot may moi.
    find /var/log/antibot -maxdepth 1 -type f -perm /0066 \
         -exec chmod 0640 {} + 2>/dev/null || :
fi

# nginx.conf — dong bo tu repo, CO SAO LUU VA TU LUI LAI.
#
# Vi sao them buoc nay. Do 2026-09-05: repo va may chu lech dung mot dong
# (`client_body_buffer_size`) suot ba ngay ma khong ai biet, vi `deploy.sh` chi
# rsync `antibot-core/`. Toi them directive do vao repo va tuong no tu toi may
# chu. Cung loai voi bit thuc thi cua `fim.sh` va cau hinh logrotate: THU NAM
# TRONG REPO KHONG TU NO TOI MAY CHU.
#
# KHAC `antibot-core/`: mot nginx.conf hong lam nginx KHONG KHOI DONG LAI DUOC.
# Nen buoc nay tu kiem va tu lui, khong dua vao buoc [5]:
#   1. In diff ra truoc — nguoi van hanh thay minh sap thay gi
#   2. Sao luu ban dang chay kem dau thoi gian
#   3. Chep, roi `nginx -t` NGAY
#   4. Hong thi khoi phuc ban sao luu va HUY deploy
# Chua reload nen ngay ca luc file tren dia sai, worker dang chay van giu cau
# hinh cu — cua so nguy hiem bang khong.
#
# CANH BAO: buoc nay GHI DE. Neu ai do sua nginx.conf thang tren may chu (vi du
# `nginx/CF/install.sh` chen mot dong `include cloudflare-realip.conf;`) thi sua
# do bi xoa. Muon giu thi phai dua vao repo. Ban sao luu o `/root/` la duong lui.
NGINX_CONF_SRC="$REPO_DIR/nginx/nginx.conf"
NGINX_CONF_DST="/usr/local/openresty/nginx/conf/nginx.conf"
if [ -f "$NGINX_CONF_SRC" ] && [ -f "$NGINX_CONF_DST" ]; then
    if ! cmp -s "$NGINX_CONF_SRC" "$NGINX_CONF_DST"; then
        echo "[4d] nginx.conf lech — thay doi sap ap dung:"
        diff "$NGINX_CONF_DST" "$NGINX_CONF_SRC" | sed 's/^/     /' || :
        BAK="/root/nginx.conf.$(date +%Y%m%d-%H%M%S).bak"
        cp -p "$NGINX_CONF_DST" "$BAK"
        cp "$NGINX_CONF_SRC" "$NGINX_CONF_DST"
        if "$NGINX" -t >/dev/null 2>&1; then
            echo "[4d] da cap nhat nginx.conf (sao luu: $BAK)"
        else
            cp -p "$BAK" "$NGINX_CONF_DST"
            echo "[4d] nginx.conf MOI KHONG QUA nginx -t — da khoi phuc ban cu."
            "$NGINX" -t || :
            echo "HUY: cay antibot-core da sync nhung nginx.conf giu nguyen."
            echo "     Sua nginx/nginx.conf trong repo roi chay lai."
            exit 1
        fi
    fi
fi

# [4e] Trang thai duong doc file tam, de doc log biet dang o che do nao.
#
# `waf/body.lua` soi duoc than da tran ra file tam qua `ngx.run_worker_thread`,
# nhung `thread_pool` chi ton tai neu OpenResty build voi `--with-threads`.
# Thieu no thi "unknown directive" -> `nginx -t` hong -> buoc [4d] o tren huy ca
# lan deploy. Nen dong do de comment trong repo.
#
# KHONG tu bo dau `#` ho: lam vay thi ban da deploy khac ban trong repo, va
# [4d] (so byte bang `cmp`) se ghi de nguoc lai o lan deploy sau — mot vong lap
# im lang. Chi nhac; nguoi van hanh sua trong repo mot lan.
# [4e] Bao trang thai cua duong doc file tam, de doc log biet dang o che do nao.
# Dieu kien build da duoc chan o [2b]; day chi la mot dong trang thai.
if grep -qE '^[[:space:]]*thread_pool[[:space:]]+antibot_waf_io' "$NGINX_CONF_DST" 2>/dev/null; then
    echo "[4e] thread_pool BAT — than tran ra file tam duoc soi trong thread pool."
    echo "     Kiem sau vai gio: grep -o 'scan=[^ ]*' /var/log/antibot/waf.log | sort | uniq -c"
    echo "     Mong doi: scan=nothread ve 0, va scan=ok tang len."
else
    echo "[4e] thread_pool TAT — than tran ra file tam KHONG duoc soi (scan=nothread)."
fi

# ---------------------------------------------------------------------------
# [4b] BI MAT: chuan hoa quyen NGAY SAU rsync, TRUOC `nginx -t`/reload.
#
# VI SAO O DAY chu khong o cuoi (Review 7 muc 3; output nguoi dung 04-10 xac nhan):
# buoc [4] dung `rsync -avz`, va `-a` BAO TOAN mode NGUON — `config.lua` trong repo
# la 644, nen moi lan deploy no QUAY VE `644 root:root`. Dong
#     config.lua: 644 root:root -> 640 root:nginx (da sua)
# xuat hien tren mot may DA sua hom truoc chinh la bang chung.
#
# Dat o cuoi sinh ra HAI cua so, ca hai deu that:
#   · reload o buoc [6] tao worker MOI khi `config.lua` con 644 -> trong khoang do
#     tenant doc duoc `pow.challenge_secret`
#   · neu `redis.pass` chua doc duoc, worker vua reload nap `password = ""` va GIU
#     nguyen trong module cache; sua quyen SAU do khong lam worker doc lai
#
# Nen quyen phai dung TRUOC khi co worker nao nap config.
echo "[4b] Bi mat: quyen doc..."
NGX_USER=$(sed -n 's/^[[:space:]]*user[[:space:]]\+\([^;[:space:]]*\).*/\1/p' \
           "$(dirname "$TARGET_DIR")/nginx.conf" 2>/dev/null | head -1)
NGX_USER="${NGX_USER:-nginx}"
echo "    worker chay bang: $NGX_USER"
# TU SUA, khong chi in goi y. Buoc [4c] o tren da tu `chown nginx:nginx` +
# `chmod 0750` cho `/var/log/antibot`, nen in goi y o day la HAI CHUAN trong cung
# mot tep — va vi dieu nay phai dung tren CA SAU may, in goi y nghia la nam may
# con lai bi bo sot cho den khi co nguoi doc log deploy.
#
# `640 root:nginx`: worker (`user nginx`) PHAI doc duoc vi cay nay khong co
# `init_by_lua` — `config.lua` duoc `require` lan dau trong WORKER da ha quyen.
# Tenant KHONG duoc doc: `config.lua` chua `pow.challenge_secret`, doc duoc la tu
# sinh cookie `verified:*` hop le va di qua TOAN BO lop cham diem.
for _f in "$TARGET_DIR/core/config.lua" "$TARGET_DIR/admin/init.lua"; do
    [ -e "$_f" ] || continue
    _m=$(stat -c '%a' "$_f" 2>/dev/null)
    _og=$(stat -c '%U:%G' "$_f" 2>/dev/null)
    if world_readable "$_m" || [ "$_og" != "root:$NGX_USER" ]; then
        chown "root:$NGX_USER" "$_f" 2>/dev/null || :
        chmod 0640 "$_f" 2>/dev/null || :
        _m2=$(stat -c '%a %U:%G' "$_f" 2>/dev/null)
        if [ "$_m2" = "640 root:$NGX_USER" ]; then
            echo "    ${_f##*/}: $_m $_og -> $_m2 (da sua)"
        else
            echo "    *** ${_f##*/}: SUA KHONG DUOC, con $_m2 ***"
            echo "        chmod 640 '$_f' && chown root:$NGX_USER '$_f'"
        fi
    else
        echo "    ${_f##*/}: $_m $_og — ok"
    fi
done
# `redis.pass`: phai KHONG world-readable, nhung PHAI de worker doc duoc.
_pw=/etc/antibot/redis.pass
if [ -e "$_pw" ]; then
    # Thu muc TRUOC, tep SAU. Do 04-10 tren cloud171-96: tep da `640 root:nginx`
    # ma `nginx` VAN bi `Permission denied`, vi `/etc/antibot` la `700 root:root`.
    # Doc mot tep can bit `x` tren MOI thu muc tren duong dan, nen sua tep ma
    # khong sua thu muc la sua xong ma van hong.
    _pd=${_pw%/*}
    if [ -d "$_pd" ]; then
        _dm=$(stat -c '%a %U:%G' "$_pd" 2>/dev/null)
        if [ "$_dm" != "750 root:$NGX_USER" ]; then
            chown "root:$NGX_USER" "$_pd" 2>/dev/null || :
            chmod 0750 "$_pd" 2>/dev/null || :
            echo "    $_pd: $_dm -> $(stat -c '%a %U:%G' "$_pd" 2>/dev/null)"
        fi
    fi
    _pm=$(stat -c '%a %U:%G' "$_pw" 2>/dev/null)
    if [ "$_pm" != "640 root:$NGX_USER" ]; then
        chown "root:$NGX_USER" "$_pw" 2>/dev/null || :
        chmod 0640 "$_pw" 2>/dev/null || :
        echo "    redis.pass: $_pm -> $(stat -c '%a %U:%G' "$_pw" 2>/dev/null)"
    fi
fi

echo "[5] nginx -t..."
"$NGINX" -t

if [ $DO_RELOAD -eq 1 ]; then
    echo "[6] Reload..."
    "$NGINX" -s reload
    # MOC THOI GIAN DEPLOY, ghi SAU khi reload thanh cong.
    #
    # Cac script do TRUOC/SAU tung lay mtime cua mot file trong cay da deploy
    # lam moc. Sai: buoc [4] dung `rsync -a`, ma `-a` BAO TOAN mtime NGUON, nen
    # mtime dich la luc `git pull` ghi file do — con mot file KHONG doi trong
    # lan pull nay thi mtime cua no la cua lan pull TRUOC. Moc lech mot cach im
    # lang, va phep so sanh TRUOC/SAU thanh vo nghia ma van in ra so rat dep.
    #
    # File nay chi mang mot thu: thoi diem reload.
    mkdir -p /var/log/antibot
    # GHI THEM, khong ghi de: script do can biet ca lan deploy TRUOC do. Cua so
    # TRUOC cua phep so sanh khong duoc voi nguoc qua lan deploy truoc, neu
    # khong no tron hai phien ban code lam mot roi van in ra bang so rat dep.
    date +%s >> /var/log/antibot/.deploy_ts
    tail -50 /var/log/antibot/.deploy_ts > /var/log/antibot/.deploy_ts.tmp
    mv /var/log/antibot/.deploy_ts.tmp /var/log/antibot/.deploy_ts
    echo "    moc deploy -> /var/log/antibot/.deploy_ts"
else
    echo "[6] Bo qua reload (--no-reload)"
fi

# ---------------------------------------------------------------------------
# [7] TRANG THAI FIM — CHI DOC. Khong cai cron, khong chay baseline.
#
# `waf/scripts/fim.sh` la NUA NGOAI-REQUEST cua tang WAF: thu duy nhat thay
# duoc mu-plugins tu chay, LFI, va cron/CLI/vao thang Apache — ba duong ma mot
# WAF theo URI mu hoan toan. Nhung no chay bang CRON, va deploy.sh KHONG cai
# cron. Khong co gi bat buoc hai thu do gap nhau.
#
# DO 2026-09-11: BA TREN NAM may chua tung chay no. Script co mat, dung bit
# thuc thi, nhung khong manifest va khong lich. Moi dong `fim=` trong waf.log
# cua ba may do deu la 0 — khong phai vi may sach, ma vi KHONG AI NHIN. Cung
# ho voi ca `nginx.conf` lech mot dong suot ba ngay (xem buoc dong bo o tren):
# THU NAM TRONG REPO KHONG TU NO TOI MAY CHU.
#
# VI SAO KHONG TU CAI: `baseline` la mot QUYET DINH AN NINH — no cong nhan moi
# file dang co tren dia la dang tin. Tren may da bi xam nhap, baseline im lang
# la hop thuc hoa ma doc. Do phai la hanh dong co y cua nguoi van hanh.
# Buoc nay chi bao dam khong ai con KHONG BIET.
echo "[7] Trang thai FIM..."
FIM_STATE_DIR="${FIM_STATE:-/var/lib/antibot/fim}"
FIM_SH="$TARGET_DIR/waf/scripts/fim.sh"
fim_cron=$( { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } \
            | grep -c 'fim\.sh' || : )
fim_cron=${fim_cron:-0}
if [ ! -s "$FIM_STATE_DIR/manifest.full.txt" ] && [ ! -s "$FIM_STATE_DIR/manifest.hot.txt" ]; then
    echo "    *** FIM CHUA TUNG CHAY TREN MAY NAY — nua ngoai-request cua WAF dang TAT ***"
    echo "    Doc ky truoc khi chay: baseline cong nhan moi file HIEN CO la dang tin."
    echo "      $FIM_SH baseline --hot"
    echo "      $FIM_SH baseline"
    echo "    Roi dat lich (vi du):"
    echo "      */5  * * * * $FIM_SH check --hot"
    echo "      */30 * * * * $FIM_SH check"
elif [ "$fim_cron" -eq 0 ]; then
    echo "    *** CO MANIFEST NHUNG KHONG CO CRON — FIM khong chay dinh ky ***"
else
    echo "    OK: co manifest, $fim_cron dong cron goi fim.sh"

    # DEM THEO TUNG TANG, khong dem gop. Ban truoc chi dem so dong chua
    # `fim.sh`, nen mot may CHI dat lich tang day, MOT NGAY MOT LAN, van duoc
    # bao "OK" — do la ca da gap that (fim.log 09-06..09-11: sau ngay lien
    # tiep, khong mot dong `[hot]` nao). Mot buoc kiem bao OK sai thi te hon
    # khong co buoc kiem nao, vi no dap tat dung cau hoi can hoi.
    cronlines=$( { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } \
                 | grep 'fim\.sh' | grep -v '^[[:space:]]*#' || : )
    printf '%s\n' "$cronlines" | sed 's/^/      | /'
    hot_n=$( printf '%s\n' "$cronlines" | grep -c -- '--hot' || : )
    full_n=$( printf '%s\n' "$cronlines" | grep 'check' | grep -vc -- '--hot' || : )
    base_n=$( printf '%s\n' "$cronlines" | grep -c 'baseline' || : )

    if [ "${hot_n:-0}" -eq 0 ]; then
        echo "    *** KHONG CO CRON CHO TANG NONG (--hot) ***"
        echo "    Tang day chay thua khong thay the duoc no: WordPress include"
        echo "    MOI .php trong mu-plugins tren MOI request, nen khong co mot"
        echo "    request nao de WAF chan — FIM la phong tuyen DUY NHAT o do."
        echo "      */5 * * * * $FIM_SH check --hot"
    fi
    if [ "${full_n:-0}" -eq 0 ]; then
        echo "    *** KHONG CO CRON CHO TANG DAY ***"
        echo "      */30 * * * * $FIM_SH check"
    fi
    # `baseline` trong cron la thu nguy hiem nhat co the dat o day: no cong
    # nhan MOI file dang co tren dia la dang tin. Dat dinh ky = tu dong hop
    # thuc hoa bat ky thu gi vua duoc tha vao, va tu do FIM khong bao gi nua.
    # Im lang y het luc no khoe manh.
    if [ "${base_n:-0}" -gt 0 ]; then
        echo "    *** $base_n dong cron chay 'baseline' — GO NGAY ***"
        echo "    baseline cong nhan moi file HIEN CO la dang tin. Chay dinh ky"
        echo "    = moi webshell vua tha vao deu duoc hop thuc hoa o lan chay"
        echo "    ke tiep, va FIM se im lang y het luc no khoe manh."
    fi
    # Canh bao duong dan CU. `fim.sh` tung nam o `nginx/scripts/`; tren
    # cloud168-101 con hai dong cron tro vao do, va chung hong im lang tu luc
    # file doi cho sang `antibot-core/waf/scripts/`.
    stale=$( { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } \
             | grep -c 'nginx/scripts/fim\.sh' || : )
    [ "${stale:-0}" -gt 0 ] && \
        echo "    *** $stale dong cron tro vao duong dan CU nginx/scripts/fim.sh — da hong, nen xoa ***"
fi

# ── [7b] TANG BAM: TU dat lich, nhung KHONG tu baseline ─────────────
#
# Ranh gioi "tu lam / khong tu lam" o day khong phai tuy y:
#
#   `baseline --hash`  KHONG tu chay. No cong nhan moi file HIEN CO la dang tin;
#                      tren may da bi xam nhap, baseline im lang la hop thuc hoa
#                      ma doc. Phai la hanh dong co y cua nguoi van hanh.
#   dong cron          TU dat. `check --hash` chi DOC va SO SANH — no khong cong
#                      nhan gi, khong ghi manifest, khong sua tep nao. Giu no o
#                      dang "mot dong de nguoi dung tu dan" la cach chac chan de
#                      sau may thi vai may khong co — dung lop loi
#                      `threat_feed_sync` da mac (cron tro sai duong, bao im lang,
#                      `asn_rep` trong so 35 dung 0 nhieu thang).
#
# Dung `/etc/cron.d` chu khong `crontab -`: `crontab - ` GHI DE toan bo crontab
# cua root, va tren may nay crontab do dang giu ba dong (`threat_feed_sync`,
# `fim.sh check --hot`, `fim.sh check`). Mot lan ghi de sai la mat ca ba.
#
# `0 4 * * 0` = 4h sang Chu nhat. Thua co y: tang nay doc het moi byte cua tap
# duoc chon, khac han hai tang kia chi `stat`.
HASH_CRON=/etc/cron.d/antibot-fim-hash
if [ -d /etc/cron.d ]; then
    _hc_want="0 4 * * 0 root $FIM_SH check --hash >/dev/null 2>&1"
    # So sanh DUNG DONG LICH, khong so ca tep: tep con `SHELL=`/`PATH=` nen mot
    # phep loc chi bo `^#` va `^$` se LUON thay khac -> ghi lai moi lan deploy.
    # Do 04-10: lan hai van bao "da dat lich". Mot buoc "chi ghi khi khac" ma
    # thuc te ghi moi lan thi khong con la "chi ghi khi khac".
    _hc_cur=$(grep -E '^[0-9*]' "$HASH_CRON" 2>/dev/null | head -1 || :)
    if [ "$_hc_cur" != "$_hc_want" ]; then
        {
            echo "# antibot FIM tang BAM (P1-5). Tu dat boi nginx/deploy.sh."
            echo "# Bat ca sua noi dung giu nguyen size+mtime — hai tang metadata mu truoc ca do."
            echo "# 'baseline --hash' KHONG tu chay: do la quyet dinh an ninh."
            echo "SHELL=/bin/bash"
            echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin"
            echo "$_hc_want"
        } > "$HASH_CRON"
        chmod 0644 "$HASH_CRON"
        echo "    da dat lich tang bam: $HASH_CRON (0 4 * * 0)"
    else
        echo "    lich tang bam: da co, dung noi dung"
    fi
    # NOI RO DAY LA VIEC MOT LAN. Ban truoc chi in "CHUA co baseline" roi dua
    # lenh, khong noi tan suat — nen moi lan deploy thong bao lai y nguyen, va
    # nguoi van hanh chi co hai duong doan: chay lai (baseline XOA lich su
    # $PREVCHG/$CHGCOUNT/$NEWCOUNT, fim.sh:1986-1991) hoac bo qua (tang bam
    # chet). Ca hai deu sai. Manifest nam o /var/lib/antibot/fim/, NGOAI cay
    # deploy, va `rsync --delete` o buoc [4] chi cham $TARGET_DIR — nen deploy
    # KHONG BAO GIO lam mat baseline.
    if [ ! -s "$FIM_STATE_DIR/manifest.hash.txt" ]; then
        echo "    *** tang bam CHUA co baseline — lich da dat nhung se khong do duoc gi ***"
        echo "    VIEC MOT LAN cho may nay: manifest o $FIM_STATE_DIR nam ngoai cay"
        echo "    deploy, nen cac lan deploy sau KHONG lam mat no va dong nay se tu im."
        echo "    Chay lai khi da co baseline la CO HAI — no xoa lich su thay doi."
        echo "    Nen doi chieu core truoc (cung phien ban tren nhieu site thi phai"
        echo "    cung bam; mot bam le = tep bi sua), roi chay:"
        echo "      $FIM_SH baseline --hash"
    fi
else
    echo "    khong co /etc/cron.d — dat tay: 0 4 * * 0 $FIM_SH check --hash"
fi

# ---------------------------------------------------------------------------
# VI SAO CO BUOC NAY. `threat_feed_sync.sh` truoc nam o `nginx/scripts/`, ma
# deploy.sh chi rsync `antibot-core/` — nen no KHONG BAO GIO tu toi may chu.
# Do 2026-09-12: so khoa `rep:asn:` tren ba may la 0 / 820 / 53.454. Cung mot
# request bi cham diem khac han nhau tuy may nao nhan, ma `asn_rep` nang 35 —
# cao thu nhi trong bang. Nay script di theo rsync; buoc nay bao cron va du lieu
# co theo kip khong.
# ── AUTH cho cac phep do Redis PRODUCTION o duoi ─────────────────────
#
# Cac buoc [8]+ doc Redis THAT (cong 6379), khac han Redis tam o 6399 cua buoc
# [3b]. Tu khi bat `requirepass` (04-10), `redis-cli --scan` khong auth tra RONG
# — va buoc [8] doc cai rong do thanh "0 khoa" roi in
#     *** 0 khoa — asn_rep dung 0: mot tin hieu 35 diem DANG CHET ***
# tren mot Redis co day du khoa. Mot BAO DONG GIA, va dung lop "lenh do hong tra
# so trong-co-ly" — nguy hon im lang vi no lam nguoi doc di sua cai khong hong.
#
# Mat khau: bien moi truong truoc, roi tep (deploy chay bang root nen doc duoc).
_DPW="${ANTIBOT_REDIS_PASS:-}"
if [ -z "$_DPW" ]; then
    _dpwf="${ANTIBOT_REDIS_PASS_FILE:-/etc/antibot/redis.pass}"
    [ -r "$_dpwf" ] && _DPW="$(head -1 "$_dpwf" 2>/dev/null | tr -d '\r\n')"
fi
RCLI_P=(redis-cli)
[ -n "$_DPW" ] && RCLI_P=(redis-cli --no-auth-warning -a "$_DPW")

echo "[8] Trang thai nguon cap ASN..."
TFS="$TARGET_DIR/intelligence/threat/scripts/threat_feed_sync.sh"
[ -x "$TFS" ] || echo "    *** $TFS thieu bit thuc thi — cron se chet cam ***"
tfs_all=$( { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } \
           | grep 'threat_feed_sync' | grep -v '^[[:space:]]*#' || : )
if [ -z "$tfs_all" ]; then
    echo "    *** KHONG CO CRON — nguon cap ASN khong bao gio duoc lam moi ***"
    echo "    asn_rep (trong so 35) se dung 0 vinh vien tren may nay."
    echo "      17 4 * * * $TFS"
else
    printf '%s\n' "$tfs_all" | sed 's/^/      | /'
fi
# ── DO BANG "CO TRO DUNG CHO KHONG", khong phai "co trung mot duong SAI da biet" ──
#
# Ban truoc chi dem duong cu `nginx/scripts/`. Do 04-10 tren cloud171-96: cron that
# tro vao `/usr/local/openresty/nginx/conf/scripts/threat_feed_sync.sh` — mot duong
# thu BA, khong phai `nginx/scripts/` cung khong phai duong dung. `grep -c` tra 0,
# buoc [8] bao im lang, va cron do da chet cam (khong co tep o day) trong khi
# `asn_rep` nang 35 diem.
#
# Liet ke duong SAI thi luon thieu mot duong. Nen dao nguoc phep do: dem dong cron
# KHONG tro dung `$TFS`. Bat ky duong nao khac dung deu la sai, ke ca duong chua ai
# nghi ra.
tfs_stale=0
if [ -n "$tfs_all" ]; then
    while IFS= read -r _l; do
        [ -n "$_l" ] || continue
        case "$_l" in
            *"$TFS"*) ;;
            *) tfs_stale=$((tfs_stale + 1)) ;;
        esac
    done <<< "$tfs_all"
fi
if [ "$tfs_stale" -gt 0 ]; then
    echo "    *** $tfs_stale dong cron KHONG tro vao duong dung ***"
    echo "    Duong dung: $TFS"
    echo "    Cron tro vao cho khac = script khong bao gio chay = asn_rep (35 diem) dung 0."
fi
# ── DEM KHOA: loai dong LOI ra khoi phep dem ─────────────────────────
#
# `redis-cli --scan` in loi ra STDOUT, khong phai STDERR. Nen khi khong auth duoc,
# `--scan | wc -l` dem chinh dong `ERROR: NOAUTH Authentication required.` va tra
# **1**, khong phai 0 — do duoc 04-10 tren mot Redis co 3 khoa that.
#
# Cai nay nguy hon tra 0: `1` loai het CA HAI nhanh bao dong (`-eq 0` va `-gt
# 20000`), nen buoc [8] in `rep:asn: 1 khoa` va im lang. Mot con so TRONG-CO-LY cho
# mot phep do da chet.
#
# `dem_khoa <mau>` -> so khoa THAT, hoac `LOI` neu khong do duoc. Ben goi phai
# phan biet "0 khoa" voi "khong do duoc" — gop hai cai la lop loi da bat nhieu lan
# trong tep nay.
dem_khoa() {
    local out
    out=$("${RCLI_P[@]}" --scan --pattern "$1" 2>&1) || { printf 'LOI'; return 0; }
    case "$out" in
        ERROR:*|NOAUTH*|*"Authentication required"*|*"Connection refused"*)
            printf 'LOI'; return 0 ;;
    esac
    [ -z "$out" ] && { printf '0'; return 0; }
    printf '%s' "$out" | grep -c . 
}

if command -v redis-cli >/dev/null 2>&1; then
    n_rep=$(dem_khoa 'rep:asn:*')
    if [ "$n_rep" = "LOI" ]; then
        # KHONG DO DUOC khac han "0 khoa". Bao dung cai da xay ra.
        echo "    *** rep:asn: KHONG DO DUOC (Redis tu choi hoac khong ket noi) ***"
        echo "    Kiem: mat khau o /etc/antibot/redis.pass co khop requirepass khong."
    else
    echo "    rep:asn: $n_rep khoa"
    # Ban da va cho ~800-1000 muc. 0 = chua tung chay. Hang chuc nghin = nguon
    # doi dinh dang va dang ghi rac (xem chu thich ASN_MAX trong chinh script):
    # moi khoa rac la +15,75 diem tho OAN cho mot ASN vo toi.
    if [ "$n_rep" -eq 0 ]; then
        echo "    *** 0 khoa — asn_rep dung 0: mot tin hieu 35 diem DANG CHET ***"
    elif [ "$n_rep" -gt 20000 ]; then
        echo "    *** $n_rep khoa la QUA NHIEU — nguon dang ghi rac (ban da va ~800) ***"
        echo "    Chay tay mot lan de thay the: $TFS"
    fi
    fi
fi

# ---------------------------------------------------------------------------
# [9] BI MAT: ai doc duoc gi.
#
# Do tren cloud171-96 04-10 bang `waf/scripts/secaudit.sh` chay bang UID tenant:
# `core/config.lua` va `admin/init.lua` la `644 root:root`, tuc MOI tenant tren
# may doc duoc `pow.challenge_secret` va `AUTH_USER`/`AUTH_PASS`. Doc duoc
# challenge secret = tu sinh cookie `verified:*` hop le = di qua TOAN BO lop cham
# diem. Day khong phai lo ly thuyet.
#
# Chieu NGUOC lai cung chet, va de quen hon: cay nay KHONG co `init_by_lua`, chi
# co `init_worker_by_lua_block`, nen `config.lua` duoc `require` lan dau trong
# WORKER — da ha quyen sang `user nginx`. Dat `600 root:root` thi worker doc ra
# chuoi RONG, khong gui AUTH, va moi phep Redis that bai IM LANG (fail-open).
# Vi vay dung muc tieu la `640 root:nginx`, KHONG phai `600 root:root`.
# ---------------------------------------------------------------------------
# `case "$m" in *[2367])` KHONG dung: `case` khop CHUOI nen `*[2367]` chi xet KY TU
# CUOI, va `644` ket thuc bang `4` -> KHONG khop -> bo sot dung ca pho bien nhat.
# Do duoc 04-10: 644/604/664 deu ra "ok" trong khi ca ba la world-readable.
# Dung phep toan BIT tren chu so "other".
world_readable() {
    local m="$1" o
    o=${m#"${m%?}"}
    [ -n "$o" ] || return 1
    [ $(( o & 4 )) -ne 0 ]
}

# ---------------------------------------------------------------------------
# [9] REDIS AUTH: trang thai thuc te sau khi worker da nap config.
#
# Quyen da duoc chuan hoa o buoc [4b], TRUOC reload. Muc nay chi tra loi: worker
# dang chay co that su dung mat khau khong, va hai ben co khop khong.
echo "[9] Redis auth: trang thai..."
_pw=/etc/antibot/redis.pass
if [ -e "$_pw" ]; then
    # BANG CHUNG THAT, khong suy ra tu che do: ACL/SELinux/mount co the khac.
    if ! su -s /bin/sh -c "head -1 '$_pw' >/dev/null 2>&1" "$NGX_USER" 2>/dev/null; then
        echo "    *** $NGX_USER VAN KHONG doc duoc $_pw ***"
        echo "        Worker doc ra chuoi rong -> khong gui AUTH -> MOI phep Redis cua"
        echo "        WAF that bai IM LANG (fail-open). LUU Y: khi do error.log KHONG co"
        echo "        dong NOAUTH nao va site van tra 200 — ca hai KHONG phai bang chung tot."
        _d=${_pw%/*}; [ -n "$_d" ] || _d=/
        while [ -n "$_d" ]; do
            su -s /bin/sh -c "test -x '$_d'" "$NGX_USER" 2>/dev/null \
              || echo "        chan tai THU MUC $_d ($(stat -c '%a %U:%G' "$_d" 2>/dev/null))"
            [ "$_d" = "/" ] && break
            _d=${_d%/*}; [ -n "$_d" ] || _d=/
        done
    else
        echo "    redis.pass: $(stat -c '%a %U:%G' "$_pw" 2>/dev/null) — $NGX_USER doc duoc, ok"
        # TU NGHIEM THU, khong in huong dan chay tay. Output nguoi dung 04-10 cho
        # thay ba dong goi y nay roi KHONG AI chay — va neu co chay thi chung lai
        # dung dung phep do da bi Review 7 muc 2 bac: `redis-cli -a` tu gui AUTH
        # nen `cmdstat_auth` tu tang.
        #
        # Day dung bai hoc "canh bao dung ma khong ai mo". Phep do dung la dem khoa
        # do WORKER ghi — `res_ip:<ip>` / `burst:<id>` (`l7/rate/res_ip_counter.lua`,
        # `l7/burst/burst_counter.lua`) — vi chung chi ton tai khi worker AUTH duoc
        # VA ghi duoc.
        _wk=$(REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 --scan --pattern 'res_ip:*' 2>/dev/null | grep -c . )
        _wb=$(REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 --scan --pattern 'burst:*'  2>/dev/null | grep -c . )
        if [ "${_wk:-0}" -gt 0 ] || [ "${_wb:-0}" -gt 0 ]; then
            echo "    worker DANG ghi Redis (res_ip=$_wk burst=$_wb) -- AUTH that su hoat dong"
        else
            # TTL ngan (`burst` 1s, `res_ip` theo `ttl.rate`) nen 0 co the chi la
            # may dang khong co luu luong. Khong ket luan "hong", nhung cung KHONG
            # bao "ok" -- do la mot cau hoi chua co cau tra loi.
            echo "    CHUA THAY khoa nao do worker ghi (res_ip=0 burst=0)."
            echo "      Co the may dang khong co request (TTL cac khoa nay rat ngan),"
            echo "      cung co the worker dang fail-open. Do lai khi co luu luong:"
            echo "      REDISCLI_AUTH=\$(cat $_pw) redis-cli --scan --pattern 'res_ip:*' | head"
        fi
    fi
else
    # ── BON TRANG THAI, theo bang cua Review 7 muc 2 ──────────────────
    #
    #   tep KHONG + Redis KHONG auth -> chua lam; CHI bat khi co --enable-redis-auth
    #   tep KHONG + Redis CO auth    -> SU CO: mat secret, WAF fail-open ngay luc nay
    #   tep CO    + Redis KHONG auth -> LECH: worker gui AUTH vao Redis khong doi
    #   tep CO    + Redis CO auth    -> phai chung minh mat khau trong tep MO DUOC
    #
    # Ban truoc chi phan biet "co tep hay khong", nen trang thai LECH bi bao OK.
    _rping=$(redis-cli -p 6379 PING 2>&1 | head -1)
    case "$_rping" in
        *NOAUTH*|*"Authentication required"*) _rauth=1 ;;
        PONG)                                 _rauth=0 ;;
        *)                                    _rauth=-1 ;;
    esac
    if [ "$_rauth" = "-1" ]; then
        echo "    *** khong ket noi duoc Redis ($_rping) -- KHONG DO DUOC trang thai auth ***"
    elif [ ! -e "$_pw" ] && [ "$_rauth" = "1" ]; then
        echo "    *** SU CO: Redis DOI mat khau ma $_pw KHONG CO ***"
        echo "    WAF dang fail-open NGAY LUC NAY. Ghi lai mat khau vao tep do"
        echo "    (chown root:$NGX_USER, chmod 640) roi reload, HOAC tat requirepass."
    elif [ -e "$_pw" ] && [ "$_rauth" = "0" ]; then
        echo "    *** LECH: co $_pw ma Redis KHONG doi mat khau ***"
        echo "    Worker gui AUTH vao mot Redis chua cau hinh -> moi phep Redis loi."
        echo "    Bat lai bang: redis-cli -p 6379 -x CONFIG SET requirepass < $_pw"
        echo "    Hoac xoa tep neu co y khong dung auth."
    elif [ -e "$_pw" ] && [ "$_rauth" = "1" ]; then
        # Khong chi kiem "nginx doc duoc tep" -- phai kiem mat khau TRONG tep mo
        # duoc Redis. Review 7 muc 2: neu lan truoc CONFIG SET that bai thi tep van
        # con lai, va lan deploy sau di vao nhanh nay roi bao OK.
        if REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 PING 2>/dev/null | grep -q PONG; then
            echo "    redis auth: tep khop requirepass -- ok"
        else
            echo "    *** SU CO: mat khau trong $_pw KHONG mo duoc Redis ***"
            echo "    Hai ben LECH nhau. Worker dang fail-open."
        fi
    elif [ "$DO_REDIS_AUTH" != "1" ]; then
        echo "    redis.pass: khong co, Redis cung chua dat mat khau."
        echo "    Day la P0 Review 4 muc 4.2. Bat bang mot lan chay EXPLICIT:"
        echo "      nginx/deploy.sh --enable-redis-auth"
    else
        # ── TRANSACTION: gate cung + rollback (Review 7 muc 1) ─────────
        #
        # Ban truoc reload that bai thi chi IN CANH BAO roi van CONFIG REWRITE, tuc
        # persist mot trang thai fail-open qua ca Redis restart. Nay moi khau that
        # bai deu ROLLBACK requirepass ve rong roi exit 1.
        echo "    BAT requirepass (--enable-redis-auth)"
        _ok=1
        install -d -m 750 -o root -g "$NGX_USER" /etc/antibot 2>/dev/null || _ok=0
        if [ ! -s "$_pw" ]; then
            ( umask 077
              if command -v openssl >/dev/null 2>&1; then
                  openssl rand -base64 36 | tr -d '/+=' | head -c 32 > "$_pw"
              else
                  tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32 > "$_pw"
              fi ) || _ok=0
        fi
        chown "root:$NGX_USER" "$_pw" 2>/dev/null || _ok=0
        chmod 0640 "$_pw" 2>/dev/null || _ok=0
        _pl=$(wc -c < "$_pw" 2>/dev/null | tr -d ' ')
        if [ "$_ok" != 1 ] || [ "${_pl:-0}" -lt 16 ]; then
            echo "    *** khong tao duoc $_pw (do dai=${_pl:-0}) -- Redis giu nguyen ***"
            exit 1
        fi
        # GATE 1: worker phai doc duoc TRUOC khi bat.
        if ! su -s /bin/sh -c "head -1 '$_pw' >/dev/null 2>&1" "$NGX_USER" 2>/dev/null; then
            echo "    *** $NGX_USER khong doc duoc $_pw -- KHONG bat ***"
            exit 1
        fi
        # Mat khau qua STDIN, khong qua argv: /proc/<pid>/cmdline doc duoc boi tenant
        # neu /proc khong hidepid (Review 7 muc 4).
        if ! redis-cli -p 6379 -x CONFIG SET requirepass < "$_pw" >/dev/null 2>&1; then
            echo "    *** CONFIG SET requirepass that bai -- Redis giu nguyen ***"
            exit 1
        fi
        echo "    requirepass: BAT (do dai $_pl)"
        # Tu day moi duong thoat LOI deu phai rollback.
        _rollback() {
            echo "    ROLLBACK: tat requirepass de WAF khong fail-open"
            if REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 CONFIG SET requirepass "" >/dev/null 2>&1; then
                echo "    rollback: xong (requirepass TAT, redis.conf chua bi ghi)"
            else
                echo "    *** ROLLBACK THAT BAI -- Redis doi mat khau ma worker chua nap ***"
                echo "    Chay tay: REDISCLI_AUTH=\$(cat $_pw) redis-cli -p 6379 CONFIG SET requirepass \"\""
            fi
        }
        # GATE 2: reload phai thanh cong. `--no-reload` thi KHONG tu reload -- mot co
        # da tuyen bo bo reload khong duoc co ngoai le an (Review 7 muc 1).
        if [ "$DO_RELOAD" != "1" ]; then
            echo "    *** --no-reload: khong the nghiem thu worker -> rollback ***"
            _rollback; exit 1
        fi
        if ! $NGINX -t >/dev/null 2>&1 || ! $NGINX -s reload >/dev/null 2>&1; then
            echo "    *** nginx -t/reload THAT BAI -> rollback ***"
            _rollback; exit 1
        fi
        echo "    nginx: reloaded"
        # GATE 3: CANARY -- phai chung minh WORKER cham duoc Redis.
        #
        # Review 7 muc 2: `redis-cli -a` TU gui AUTH truoc `INFO`, nen
        # `cmdstat_auth:calls>=1` LUON dung du worker khong he AUTH. Do duoc 04-10:
        # tren mot Redis KHONG co client nao khac, chi mot lenh quan sat da cho
        # `cmdstat_auth:calls=1`. Bang chung do la RONG, va toi da bao "xong" dua
        # tren no.
        #
        # Bang chung THAT: `res_ip:<ip>` va `burst:<id>` do WORKER `safe_incr` khi co
        # request (`l7/rate/res_ip_counter.lua:30`, `l7/burst/burst_counter.lua:23`).
        _cnt_keys() { REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 --scan --pattern "$1" 2>/dev/null | grep -c . ; }
        _k0=$(_cnt_keys 'res_ip:*'); _b0=$(_cnt_keys 'burst:*')
        _host=$(ls -1 /home/*/domains 2>/dev/null | grep -m1 '[.]')
        if [ -n "$_host" ]; then
            curl -s -o /dev/null -k --max-time 5 "https://127.0.0.1/" -H "Host: $_host" 2>/dev/null || :
            curl -s -o /dev/null    --max-time 5 "http://127.0.0.1/"  -H "Host: $_host" 2>/dev/null || :
        fi
        sleep 2
        _k1=$(_cnt_keys 'res_ip:*'); _b1=$(_cnt_keys 'burst:*')
        if [ "${_k1:-0}" -gt "${_k0:-0}" ] || [ "${_b1:-0}" -gt "${_b0:-0}" ]; then
            echo "    canary: WORKER ghi duoc Redis (res_ip $_k0->$_k1, burst $_b0->$_b1) -- ok"
        elif [ "${_k1:-0}" -gt 0 ] || [ "${_b1:-0}" -gt 0 ]; then
            echo "    canary: co khoa do worker ghi (res_ip=$_k1 burst=$_b1) -- ok"
        else
            echo "    *** canary: KHONG co khoa nao do worker ghi (host=$_host) ***"
            echo "    Worker co the dang fail-open. KHONG ghi vao redis.conf."
            _rollback; exit 1
        fi
        # CHI den day moi persist.
        if REDISCLI_AUTH=$(cat "$_pw") redis-cli -p 6379 CONFIG REWRITE >/dev/null 2>&1; then
            echo "    CONFIG REWRITE: da ghi vao redis.conf (song qua restart)"
        else
            echo "    *** CONFIG REWRITE that bai -- restart Redis se MAT mat khau ***"
            echo "      Kiem: redis-cli INFO server | grep config_file"
        fi
        # Dung lai mang AUTH cho cac nhanh bao tri PHIA SAU: `RCLI_P` duoc dung o
        # buoc truoc nen con cau hinh KHONG auth (Review 7 muc 4).
        _DPW=$(cat "$_pw")
        RCLI_P=(redis-cli --no-auth-warning -a "$_DPW")
    fi
fi

# ---------------------------------------------------------------------------
# Bao tri Redis - CHI khi co co.
#
# Ly do ton tai: mot so khoa Redis lam request THOAT SOM, TRUOC khi code moi
# kip chay. Chung khong bao gio tu sua duoc, nen doi logic ma khong xoa thi
# quyet dinh cu tiep tuc thi hanh vo thoi han. Khoa co TTL ngan (rate, burst,
# sess, dns_ptr, crawler, botverdict) thi TU LANH - dung dung toi.
# ---------------------------------------------------------------------------

if [ $DO_FLEET -eq 1 ]; then
    echo "[bao tri] Xoa fl:dyn:* ..."
    n=$("${RCLI_P[@]}" --scan --pattern 'fl:dyn:*' | tee "$TMPD/fl_dyn.txt" | wc -l)
    # Phai dung if chu khong dung `[ ] && cmd`: duoi set -e, mot danh sach && ma
    # ve trai sai se lam ca script thoat khi n=0.
    if [ "$n" -gt 0 ]; then
        # KHONG dung `xargs redis-cli`: no goi binary TRAN nen mat toan bo option
        # auth, va khi `requirepass` da bat thi moi lenh DEL that bai trong khi
        # nhanh nay van in nhu da xoa (Review 7 muc 4). Goi qua wrapper da AUTH.
        _ndel=0
        while IFS= read -r _k; do
            [ -n "$_k" ] || continue
            "${RCLI_P[@]}" DEL "$_k" >/dev/null 2>&1 && _ndel=$((_ndel + 1))
        done < "$TMPD/fl_dyn.txt"
        if [ "$_ndel" -ne "$n" ]; then
            echo "    *** chi xoa duoc $_ndel/$n khoa — kiem auth Redis ***"
        fi
        cp "$TMPD/fl_dyn.txt" /root/fl_dyn_removed.txt
    fi
    echo "    da xoa $n co chan dai (luu tai /root/fl_dyn_removed.txt)"
fi

if [ ${#GOODBOT_NAMES[@]} -gt 0 ]; then
    echo "[bao tri] Xoa registry: ${GOODBOT_NAMES[*]}"
    # goodbot_seed CHI GHI khoa chua ton tai - khong cap nhat, khong xoa.
    # Nen sua suffix cua mot bot DA CO trong goodbot.json se KHONG co tac dung,
    # va go mot ten khoi JSON cung KHONG go khoi Redis. Da tra gia 2 lan:
    # ahrefsbot (2026-08-06) va truoc do. Xoa tay o day roi reload de seed lai.
    for n in "${GOODBOT_NAMES[@]}"; do
        "${RCLI_P[@]}" DEL "goodbot:dns:$n" "goodbot:asn:$n" "goodbot:ptr_only:$n" > /dev/null
        echo "    $n"
    done
    echo "    reload lai de goodbot_seed nap ban moi:"
    echo "      $NGINX -s reload"
fi

if [ $DO_CRAWLER -eq 1 ]; then
    echo "[bao tri] Go an cho crawler chinh chu ..."
    # An toan: chi go an cho IP co PTR thuoc crawler xac minh duoc.
    # Ke gia danh khong dat duoc PTR do nen khong loi dung duoc nhanh nay.
    #
    # Phan lon truong hop nhanh nay KHONG can thiet: l7/ban/ip_ban_check hoan
    # thi hanh cho moi UA chua bot/spider/crawler, nen an len crawler von da
    # TRO. Giu lai de don rac va cho truong hop UA khong co token bot.
    "${RCLI_P[@]}" --scan --pattern 'ban:*' \
      | grep -oP '^ban:\K(\d{1,3}\.){3}\d{1,3}$' | sort -u \
      | while read -r ip; do
          p=$(dig +short -x "$ip" 2>/dev/null | head -1)
          p=${p%.}                       # bo dau cham cuoi cua dig
          # NEO O CUOI CHUOI, va bat buoc co dau cham dang truoc.
          # Dung `*coccoc.com*` (khop moi vi tri) la mot LO HONG: PTR do KE TAN
          # CONG tu dat cho IP cua chinh ho, nen `x.coccoc.com.attacker.net` se
          # khop va lenh cam cua ho bi go. Mau `*.coccoc.com` chi khop khi
          # coccoc.com that su la duoi cua ten - thu ma chi chu vung nguoc DNS
          # cua coccoc.com dat duoc.
          case "$p" in
            *.googlebot.com|*.google.com|*.search.msn.com|*.crawl.baidu.com\
            |*.yandex.ru|*.yandex.net|*.yandex.com\
            |*.applebot.apple.com|*.coccoc.com|*.petalsearch.com|*.ahrefs.net\
            |*.blex.seranking.com\
            |*.fbsv.net|*.facebook.com|*.crawl.amazonbot.amazon)
              "${RCLI_P[@]}" DEL "ban:$ip" "ban:hit:$ip" "ban_ctx:$ip" > /dev/null
              echo "    go $ip $p" ;;
          esac
        done
fi

echo "=== DEPLOY DONE ==="

# ---------------------------------------------------------------------------
# Khi nao dung co nao
#
#   --goodbot <ten>   BAT BUOC khi sua/go mot muc DA CO trong goodbot.json.
#                     Them ten MOI thi khong can (seed tu ghi khoa moi).
#
#   --fleet           HIEM khi can, nhung CHUA bo duoc. Tu 2026-08-09 co day du
#                     chuoi tu lanh: aggregator thay `crawler:<ip>` thi return
#                     truoc pipeline 27 lenh (thoi nuoi xo) -> diem tut duoi
#                     confirm -> analyzer thoi gia han -> fl:dyn het han sau
#                     dyn_block_ttl (1h). check_block con mo ca /24 khi thay
#                     `crawler24:<cidr>`.
#                     CHO HO CON LAI - do la ly do giu nhanh nay: dau /24 doi
#                     `good_bot_verified AND dns_rev_valid`, nen bot di duong
#                     S2.5 (ahrefs, seranking, petalbot, moi contact_*_match)
#                     CHI co dau per-IP TTL 1h, khong bao gio co dau /24. Mot IP
#                     S2.5 MOI roi vao /24 dang bi chan se an RST truoc khi kip
#                     xac minh, ma aggregator chay TRUOC check_block nen chinh
#                     request vua bi ban lai gia han cai co da ban no -> ket
#                     vinh vien. Ahrefs xoay IP trong 54.39/142.44 nhanh hon
#                     TTL 1h nen la ung vien so mot.
#                     DAU HIEU PHAI CHAY: `redis-cli --scan --pattern 'fl:dyn:*'`
#                     con khoa sau > 1h, va error.log van FAST DYN BLOCK dung
#                     dai do.
#
#   --crawler         Don rac. Hau nhu khong con can - xem chu thich tren.
#
# KHONG can co nao cho: ban:*, ip_risk:*, risk:*, rate:*, burst:*, sess:*,
# iptour:*, fl:24:*, dns_ptr:*, crawler:*, crawler24:*, botverdict:*  -- tat ca
# deu co TTL va tu lanh. Rieng crawler24:* (TTL 6h) con duoc gac boi
# `ctx.fleet_dyn_present` o detection/bot/init.lua: chi ghi khi dai DANG bi
# chan, nen no khong the tich tu thanh mot danh sach mien tru am tham nhu hoi
# 2026-08-09 (341 dau, hau het EC2, tren may 246).
# Xoa ban:* hang loat la mo cua so phong thu that su; neu can thi lam tay, co
# sao luu, va doc ky l7/CLAUDE.md truoc.
# ---------------------------------------------------------------------------
