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
done < <(find "$SOURCE_DIR" -name '*.lua')
if [ $lua_fail -ne 0 ]; then
    echo "HUY: co file Lua sai cu phap. KHONG sync, cay dang chay giu nguyen."
    exit 1
fi
echo "    OK"

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
if [ -x "$RESTY" ] && [ -x "$REPO_DIR/test/run.sh" ]; then
    echo "[3b] Chay T (test luat WAF)..."
    if ! "$REPO_DIR/test/run.sh"; then
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
