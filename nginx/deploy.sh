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
    echo "[3b] Chay T (test luat WAF)..."
    if ! "$REPO_DIR/antibot-core/waf/scripts/run.sh"; then
        if [ "${SKIP_TEST:-0}" = "1" ]; then
            echo "     SKIP_TEST=1 — di tiep BAT CHAP test hong."
        else
            echo "HUY: co test hong. KHONG sync, cay dang chay giu nguyen."
            echo "     Ep di tiep khi that su can: SKIP_TEST=1 ./deploy.sh"
            exit 1
        fi
    fi
fi

echo "[4] Sync core folder..."
rsync -avz --delete "$SOURCE_DIR" "$TARGET_DIR"

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

echo "[5] nginx -t..."
"$NGINX" -t

if [ $DO_RELOAD -eq 1 ]; then
    echo "[6] Reload..."
    "$NGINX" -s reload
else
    echo "[6] Bo qua reload (--no-reload)"
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
    n=$(redis-cli --scan --pattern 'fl:dyn:*' | tee "$TMPD/fl_dyn.txt" | wc -l)
    # Phai dung if chu khong dung `[ ] && cmd`: duoi set -e, mot danh sach && ma
    # ve trai sai se lam ca script thoat khi n=0.
    if [ "$n" -gt 0 ]; then
        xargs -r redis-cli DEL < "$TMPD/fl_dyn.txt" > /dev/null
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
        redis-cli DEL "goodbot:dns:$n" "goodbot:asn:$n" "goodbot:ptr_only:$n" > /dev/null
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
    redis-cli --scan --pattern 'ban:*' \
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
              redis-cli DEL "ban:$ip" "ban:hit:$ip" "ban_ctx:$ip" > /dev/null
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
