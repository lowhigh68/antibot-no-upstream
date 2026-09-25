#!/bin/bash
# FIM — giam sat toan ven file tren hosting chia se.
#
# VI SAO CAN, khi da co WAF: luat theo URI chi thay thu di qua HTTP. Ba duong
# tan cong pho bien nhat KHONG di qua do:
#   - mu-plugins tu chay: WordPress `include` moi .php o day tren MOI request,
#     ke tan cong khong can gui request nao. Do 2026-09-02: quet dia tim ra file
#     tren 13 site, con WAF thi mu hoan toan.
#   - LFI: `/index.php?f=uploads/shell.php` — shell duoc `include`, khong bao gio
#     la mot HTTP request rieng.
#   - cron / CLI / vao thang Apache 127.0.0.1:8080: khong di qua OpenResty.
#
# METADATA CHU KHONG BAM NOI DUNG. `find -printf` gan nhu mien phi; sha256sum
# tren ~150k file PHP moi ngay la ganh I/O that tren may chia se. Danh doi:
#   BAT duoc  file moi (moi de doa chinh), file bi xoa, doi kich thuoc, doi mtime
#   BAT duoc  file bi LUI NGAY (`touch -t 2020...`) — thu ma `find -mtime -1` bo
#             lot hoan toan, vi duong dan do la MOI trong manifest du mtime ghi gi
#   BO SOT    sua noi dung roi `touch -r` tra lai mtime VA chen cho dung bang
#             kich thuoc cu. Can chan ca cai do thi doi sang sha256sum va chay
#             hang tuan thay vi hang ngay.
#
# HAI TANG. Do tren may that: quet day du 317.343 file / 27 giay, ba lan lien
# tiep deu 27 giay — cache am khong giup gi. Chi tiet o chu thich `scan_hot`.
#   --hot   chi nhung noi chay duoc MA KHONG CAN mot HTTP request nao. Gan nhu
#           mien phi, dat lich day (5 phut).
#   (mac dinh) day du. Dat lich thua (30-60 phut).
# Manifest va lock TACH RIENG cho tung tang.
#
# DUNG:
#   fim.sh baseline [--hot]           tao manifest dau tien, khong bao cao gi
#   fim.sh check    [--hot] [--dry] [-v]
#     --dry  bao cao nhung KHONG cap nhat manifest
#     -v     in ca khi khong co gi (mac dinh im lang de cron khong spam mail)
#
# COT `sc=` — CANARY, diem CHUA quyet dinh gi. Cong diem nhieu bat bien thay cho
# `sev()` phan nhanh mot chieu. Doc `pscore()` de biet vi sao va bang trong so.
# Dang o giai doan do phan bo; khong noi vao `crit`, `sev` hay ma thoat.
#
# Ma thoat: 0 = khong co gi dang chu y   1 = co phat hien CRITICAL/HIGH
#           2 = KHONG CHAY DUOC (thieu flock, scan rong, manifest bat thuong)
#           3 = chay duoc, khong co file moi, NHUNG co TON DONG mu-plugins
#
# 3 tach rieng khoi 2 mot cach co y: 2 nghia la "khong do duoc", 3 nghia la "do
# duoc va co su co". Tron lai thi mot may hong va mot may nhiem webshell tra ve
# cung mot ma. Tach rieng khoi 1 vi 1 doc `$crit` — so file MOI — ma ton dong
# theo dinh nghia la thu KHONG con moi nua.
set -uo pipefail

# Ba bien cho phep ghi de bang moi truong CHI de chay thu tren cay gia. Mac dinh
# la duong that; khong co cai nay thi script nay khong the kiem duoc o dau ngoai
# production, va hom nay da hai lan phai giao ma chua chay.
ROOTS="${FIM_ROOTS:-/home/*/domains/*/public_html}"
STATE="${FIM_STATE:-/var/lib/antibot/fim}"
LOG="${FIM_LOG:-/var/log/antibot/fim.log}"
# Duong bao thu hai, cho `admin/init.lua` doc — xem khoi ghi o cuoi file. Dat o
# DAY cung voi cac duong dan khac, khong o cho dung: nguong ton dong mu-plugins
# ghi vao no TRUOC diem do.
CRITLOG="${FIM_CRITLOG:-/var/log/antibot/fim_critical.log}"

# TAO VA DAT QUYEN NGAY O DAY, mot cho duy nhat. Truoc ban nay co BA cho goi
# `chgrp nginx` + `chmod 0640`, va ca ba deu nam SAU `tee` cua nhanh chung —
# tuc chi chay khi DUNG NHANH DO co canh bao. Do 24-09 tren 5 may:
#     168-101  -rw-------  root root   50.066 byte  <- CAM
#     28-246   -rw-------  root root   34.132 byte  <- CAM
#     171-96   -rw-r-----  root nginx  16.776 byte
#     186-126  -rw-r-----  root nginx  29.100 byte
#     183-139  -rw-r-----  root nginx        0 byte
# Hai may co 50KB va 34KB canh bao ma worker `nginx` KHONG MO DUOC. Co che sinh
# ra loi: mot nhanh (`tee` voi umask mac dinh) tao file 0600 root:root, roi nhanh
# CO `chgrp` khong bao gio chay de sua. Day la lan THU BA cua cung ho loi
# (memory feedback_alert_reaches_nobody): canh bao dung, di vao noi khong ai doc.
#
# `|| :` vi script cung chay duoi user khong phai root khi test; that bai o day
# khong duoc lam chet phan phat hien.
# `2>/dev/null` PHAI o day va `|| :` mot minh KHONG du: loi cua `: > file` la loi
# REDIRECT cua shell, khong phai ma thoat cua lenh, nen `|| :` khong bat duoc.
# Da thay that khi chay thu voi $CRITLOG tro vao thu muc khong ton tai — mot dong
# stderr o cron la mot mail rac moi 5 phut.
if [ ! -e "$CRITLOG" ]; then
    { : > "$CRITLOG"; } 2>/dev/null || :
fi
chgrp nginx "$CRITLOG" 2>/dev/null || :
chmod 0640  "$CRITLOG" 2>/dev/null || :

# Tap "ma CORE WordPress nam o tang 0 webroot". Dung cho nhanh `del1_core`:
# mot ten cach core dung mot ky tu MA noi dung la core thi KHONG phai ke gia
# dang — do la ban cach ly/sao luu. Do 24-09 tren 186-126: 17/20 file >=40 la
# loai nay, tat ca tren DUNG 2 site, mtime 2016-2017, tuc MOT su kien lich su
# (mot cong cu quet da doi ten toan bo entry point core) chu khong phai 17 phat
# hien. `fim.sh` la may do THAY DOI; 17 file bat dong 9 nam khong thuoc pham vi
# no, va giu chung o 40 diem thi 85% $CRITLOG la nhieu co dinh -> nguoi doc bo
# qua ca 3 file that.
#
# Chi quet `$ROOTS/*.php` (tang 0, KHONG `-r`): dan so 441 file tren 186-126.
# Hai dieu kien phai CUNG co — `@package WordPress` mot minh co trong ca plugin
# hop le, con `wp-load|wp-blog-header|wp-config` mot minh co trong moi webshell
# muon nap WordPress.
#
# `find ... -maxdepth 1` chu khong phai `grep -l ... $ROOTS/*.php`. Ban `grep`
# CHAY DUNG (da kiem tren cay 3 webroot: ca hai cho 3/3), nhung no dua vao hai
# thu khong noi ra: `$ROOTS` khong quote de shell no glob, va `grep` khong co
# `-r` nen tang 0 la he qua chu khong phai y dinh. `-maxdepth 1` noi thang y do.
core_like_list() {
    find $ROOTS -maxdepth 1 -name '*.php' -type f 2>/dev/null \
    | while IFS= read -r _f; do
        grep -q '@package WordPress' "$_f" 2>/dev/null || continue
        grep -qE 'wp-load|wp-blog-header|wp-config' "$_f" 2>/dev/null \
            && printf '%s\n' "$_f"
      done | sort || :
}
# MANIFEST dat sau khi biet tier — xem chu thich tai cho gan.

# Nguong gom nhom. Mot ban cap nhat plugin hoac core cham hang tram file cung
# luc; mot webshell cham DUNG MOT. Nhom dong hon nguong nay gop thanh mot dong
# tom tat, nhom nho thi liet ke tung file. Day la co che chong nhieu theo BE
# RONG, va no du vi hai dan so do khac nhau ve BAC do lon. Co che thu hai, theo
# THOI GIAN, o $PREVCHG ben duoi — bon file Wordfence thoat duoc cai nay chi vi
# 4 < 5, khong phai vi chung vo hai.
GROUP_MAX=5

# ── Bao tin hieu sang WAF ─────────────────────────────────────────────
# FIM ghi `waf:fimnew:<DUONG-DAN-FILE-TUYET-DOI>` — KHONG phai `<host>:<uri>`.
# Dong nay truoc ghi sai, va sai theo huong nguy hiem: ai doc chu thich roi sua
# mot dau cho khop voi no se lam LECH KHOA, tuc FIM danh dau mot noi con WAF
# doc mot noi, hong trong IM LANG. Su that o duoi (dong `SETEX`) va o
# `waf/init.lua`: ca hai dung `document_root .. script_path(uri)`.
# `waf/scripts/wordpress_paths_test.lua` ghim dieu nay; `fim.sh` con tu doc nguoc mot
# key vua ghi de xac minh vong tron.
# `waf/init.lua` doc key nay khi mot luat
# `signal` ban va nang tin hieu len. KHONG phai chan: luat WAF dong gop tin hieu,
# engine quyet cung ba tang tin cay — nen quan tri vien dang nhap that
# (session_richness >= 0.5) van duoc `auth_session_cap` giu o monitor, con
# scanner an danh thi len block. An toan FP theo cau truc, khong can luat mien tru.
#
# DB PHAI KHOP `core/config.lua` _M.redis.db (hien tai 0). Lech db thi FIM ghi
# mot noi WAF doc mot noi, khong bao gio khop, va KHONG AI BAO LOI. Vi vay ham
# `push_marks` doc nguoc mot key vua ghi de tu xac minh.
REDIS_CLI="${FIM_REDIS_CLI:-redis-cli}"
REDIS_DB="${FIM_REDIS_DB:-0}"
MARK_TTL="${FIM_MARK_TTL:-604800}"   # 7 ngay

# `audit` khong nhan co nao: no khong co tier (soi mot tap co dinh — mu-plugins
# tron do sau, uploads chi tang 1), khong ghi gi nen `--dry` vo nghia, va luon in
# day du nen `-v` cung vay.
usage() { echo "dung: $0 {baseline|check|audit|score} [--hot] [--dry] [-v]" >&2; exit 2; }

# Be mat thuc thi + cau hinh. `.htaccess` va `.user.ini` co trong danh sach vi
# chung DOI DUOC handler: tha mot `.htaccess` vao uploads la bat lai PHP o do —
# loi vong ma khong luat URI nao nhin thay.
NAMES=( \( -name '*.php'  -o -name '*.php[0-9]' -o -name '*.phtml' \
        -o -name '*.phar' -o -name '*.pht'      -o -name '*.phps'  \
        -o -name '.htaccess' -o -name '.user.ini' \) )

# `|| :` GIU LAI du da co `2>/dev/null`: hai thu chan hai duong khac nhau.
# `2>/dev/null` nuot THONG BAO, `|| :` nuot MA THOAT. Voi `set -o pipefail`
# (dong 37) mot ma thoat khac 0 o bat ky khau nao lam hong ca pipeline, va
# `find` tra 1 khi duong dan khong ton tai — day la chuyen BINH THUONG o
# `scan_hot` vi glob khong khop thi bash de nguyen chuoi mau. Xem chu thich o do.
#
# Cai gia: mot loi that (dia hong, mount bien mat) cung im lang. Bu lai bang
# chot "quet ra 0 file" o ca hai nhanh baseline va check ben duoi — do moi la
# thu phan biet duoc "khong co gi" voi "khong nhin thay gi".
scan_full() {
    { find $ROOTS "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :; } 2>/dev/null | sort
}

# TANG NONG — chi nhung noi CHAY DUOC MA KHONG CAN MOT HTTP REQUEST NAO.
#
# Do tren may that: quet day du la 317.343 file / 27 giay, va ba lan chay lien
# tiep deu 27 giay — cache am khong giup gi, nut that la so lan stat chu khong
# phai tim dia. Chay moi 10 phut la 43 phut CPU/ngay, va day moi la may NHO.
#
# Nhung 95% so file do nam trong plugins/ va themes/ — dung nhung cho script
# phan loai ROUTINE roi gop thanh mot dong. Nen tach tang khong lam mat gi.
#
# Tieu chi chon KHONG phai la re, ma la: WAF co thay duoc khong.
#   mu-plugins/       WordPress `include` moi .php o day tren MOI request. Khong
#                     co request nao de chan — FIM la phong tuyen DUY NHAT.
#   web root          wp-config.php bi sua la cua hau chay tren moi request.
#   wp-content/ (1)   drop-in: advanced-cache.php, object-cache.php, db.php,
#                     sunrise.php… WordPress tu include, khong ai goi qua HTTP.
#
# uploads/ CO Y khong nam o day: webshell trong do phai co HTTP request moi chay
# duoc, va `wp_upload_exec` chan thang o WAF. No cung la cho traversal dat nhat
# (day anh). Quet day du van phu no.
#
# `-maxdepth 1` tren hai muc dau la thu lam tang nay gan nhu mien phi.
# MOI `find` PHAI co `|| :`. Day khong phai phong thu thua ma la dieu kien
# VAN HANH BINH THUONG: `$ROOTS` khong dat trong nhay nen bash bung glob, va khi
# mot mau khong khop gi (may khong co WordPress cai trong thu muc con) bash de
# NGUYEN CHUOI MAU lam tham so — `find` nhan duong dan khong ton tai va tra 1.
# Voi `set -o pipefail` o dong 37, mot ma thoat 1 lam hong ca pipeline va script
# bao "quet that bai" du 5/6 nhanh chay tot.
#
# Da gap that tren cloud168-101 (2026-09-02): tang day chay ngon 317.343 file,
# tang nong chet ngay tu baseline chi vi nhanh `mu-plugins` cua subdomain khong
# khop. Ba nhanh sau day la ba nhanh TUY CHON theo dinh nghia — khong phai may
# nao cung co subdomain.
#
# `shopt -s nullglob` KHONG dung duoc thay cho cach nay: glob rong se lam `find`
# chay khong tham so, tuc quet THU MUC HIEN TAI. Doi mot loi on ao lay mot loi
# im lang va sai dia chi.
scan_hot() {
    {
        find $ROOTS               -maxdepth 1 "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
        find $ROOTS/wp-content    -maxdepth 1 "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
        find $ROOTS/wp-content/mu-plugins     "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
        # THEM MOT TANG: WordPress cai trong thu muc con cua public_html. Rat pho
        # bien tren may nay vi `da_to_openresty.sh:271` cho SUBDOMAIN mot webroot
        # dang <public_html>/<sub_name> — nen mu-plugins cua moi subdomain nam o
        # do, va ban truoc cua tang nong khong he thay chung.
        #
        # DUNG CAT `$ROOTS/*` DU NO TRONG NHU NHIEU. Do tren cloud168-101
        # (2026-09-02, 15.770 file / 0,474 giay): wp-includes 10.523 + wp-admin
        # 4.257 = 93,7% tang nong den TU DAY, chu khong tu subdomain (en 69,
        # id 17, libraries 5, cli 4). Nhin qua thi day la phinh — no KHONG phai,
        # va lan review dau tien cua chinh nguoi viet dong nay da suyt cat nham.
        #
        # Ly do giu y het ly do mu-plugins co mat: `wp-includes/*.php` do sau 1
        # (functions.php, load.php, plugin.php, formatting.php…) la nhung file
        # WordPress `require` luc khoi dong. Backdoor that hiem khi la FILE MOI —
        # no la dong CHEN VAO mot file core co san, roi chay tren MOI request.
        # Khong co request HTTP nao go vao duong dan do de WAF chan. Luat
        # `wp_includes_exec` chan viec GO THANG /wp-includes/xxx.php — chuyen
        # khac han.
        #
        # GIOI HAN da biet, chap nhan: `-maxdepth 1` nen file core o do sau 2+
        # (wp-includes/rest-api/…, wp-includes/blocks/…) KHONG nam trong tang
        # nong, du chung cung duoc core require. Chung van duoc TANG DAY phu,
        # chi la mot ngay mot lan thay vi 15 phut.
        # Van la glob co dich chu khong phai traversal, nen chi phi gan nhu khong doi.
        find $ROOTS/*             -maxdepth 1 "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
        find $ROOTS/*/wp-content  -maxdepth 1 "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
        find $ROOTS/*/wp-content/mu-plugins   "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' || :
    } 2>/dev/null | sort -u
}

scan() { if [ "$tier" = "hot" ]; then scan_hot; else scan_full; fi; }

mode="${1:-}"; [ -n "$mode" ] || usage
shift
dry=0; verbose=0; tier=full
for a in "$@"; do
    case "$a" in
        --hot)        tier=hot ;;
        --dry)        dry=1 ;;
        -v|--verbose) verbose=1 ;;
        *)            usage ;;
    esac
done

# ── score: HIEU CHINH TRONG SO tren tap DA CO, khong doi ngay nao ─────
#
# VI SAO CAN MODE NAY — no sua mot loi phuong phap cua chinh toi. Khi them cot
# `sc=` toi sao chep quy trinh canary cua `auth_session_cap` (dat 10-09): chay
# 1-2 tuan, doc phan bo, roi dat nguong. Nhung canary do do REQUEST — hang nghin
# mau moi gio. Con day do FILE TREN DIA: tap gan nhu tinh, 317k file ma chi vai
# chuc cai doi moi ngay. Doi "dan so tu nhien" xuat hien la doi vo han.
#
# Va tap du lieu DA NAM SAN. Cot `sc=` chi cham diem `$diff_out` — nhung 317.343
# file kia deu cham diem duoc NGAY BAY GIO. Mode nay doc manifest co san, cham
# diem het, in phan bo. Vai giay, 317k mau thay vi vai chuc.
#
# OWASP CRS lam chuyen tuong duong the nao: CRS cung cong diem (anomaly scoring,
# CRITICAL=5 ERROR=4 WARNING=3 NOTICE=2, nguong mac dinh 5) nhung KHONG doi tuan
# nao de hieu chinh — no ship san Paranoia Level 1-4, PL1 chi bat luat gan nhu
# khong FP, PL4 bat ca luat nhieu. Nguoi van hanh CHON MUC. Diem CRS khong ap
# duoc o day la no cham REQUEST (su kien doc lap, do phan bo nhanh); tap file thi
# tinh, nen phai do NGUOC — cham diem ca tap co san mot luot.
#
# KHONG ghi gi: khong manifest, khong Redis, khong $CRITLOG. Chi doc va in.
if [ "$mode" = "score" ]; then
    MANIFEST="$STATE/manifest.$tier.txt"
    if [ ! -s "$MANIFEST" ]; then
        echo "khong co $MANIFEST -- chay 'baseline' truoc." >&2
        exit 2
    fi

    # Hai tin hieu NOI DUNG phai grep thuc su (manifest chi co metadata). Chi o
    # tier day du, cung ly do nhu trong `check`.
    PWFILE=$(mktemp) || exit 2
    FRAGFILE=$(mktemp) || exit 2
    CLFILE=$(mktemp) || exit 2
    trap 'rm -f "$PWFILE" "$FRAGFILE" "$CLFILE"' EXIT
    # KHONG gioi han o tier day du: chi quet tang 0 (441 file tren 186-126), re
    # bang mot phan nghin lan `grep -r`, va o tier nong thieu no thi 17 file cach
    # ly lai an 25 diem.
    core_like_list > "$CLFILE" || :
    if [ "$tier" = "full" ]; then
        grep -rl 'md5(md5(md5(' $ROOTS --include='*.php' 2>/dev/null | sort > "$PWFILE" || :
        grep -rlE "'ba'\s*\.|'base'\s*\.\s*'64|'str'\s*\.\s*'rev'|'str'\s*\.\s*'_'" \
            $ROOTS --include='*.php' 2>/dev/null | sort > "$FRAGFILE" || :
    fi

    # `t` truyen la "NEW" cho moi dong: manifest khong co khai niem NEW/CHG. Hai
    # tin hieu phu thuoc `t` (samesize +10, prev -20) vi vay KHONG tinh o day —
    # do la dieu phai biet khi doc so: phan bo nay la diem NEN cua tung file,
    # chua co phan dong hoc.
    awk -F'|' -v pwfile="$PWFILE" -v fragfile="$FRAGFILE" -v clfile="$CLFILE" -v det="$verbose" '
        BEGIN {
            if (pwfile   != "") while ((getline _x < pwfile)   > 0) if (_x != "") pwhit[_x] = 1
            if (fragfile != "") while ((getline _x < fragfile) > 0) if (_x != "") fraghit[_x] = 1
            if (clfile   != "") while ((getline _x < clfile)   > 0) if (_x != "") corelike[_x] = 1
            split("index.php wp-config.php wp-config-sample.php wp-login.php " \
                  "wp-settings.php wp-load.php wp-blog-header.php wp-cron.php " \
                  "wp-links-opml.php wp-mail.php wp-signup.php wp-trackback.php " \
                  "wp-activate.php wp-comments-post.php xmlrpc.php " \
                  "wp-admin.php wordfence-waf.php", _c0, " ")
            for (_i in _c0) core0[_c0[_i]] = 1
        }
        function basename(p,   i) {
            i = length(p)
            while (i > 1 && substr(p, i, 1) != "/") i--
            return substr(p, i + 1)
        }
        function wproot(p,   i) {
            i = index(p, "/public_html")
            if (i == 0) return ""
            return substr(p, 1, i + 11)
        }
        # Y het `del1_core` trong `check` — xem chu thich o do (regex cu cho
        # 4.101 duong tinh gia).
        function del1_core(b,   L, j, cand, dot) {
            if (b in core0) return 0
            L = length(b); dot = L - 4
            for (j = 1; j <= L; j++) {
                cand = substr(b, 1, j - 1) substr(b, j + 1)
                if (cand in core0) return (j == dot) ? 1 : 2
            }
            return 0
        }
        # BAN SAO cua `pscore()` trong `check`, bo hai nhanh phu thuoc `t`.
        # Trung lap co y: mot ham dung chung phai nam trong file awk rieng, va
        # mot file phu thuoc ngoai la mot file se dung tren may nay va khong
        # dung tren may sau (cung ly do da khong dung logrotate).
        function base_score(p,   s, b, nm) {
            s = 0; b = basename(p)
            if (p in pwhit)                                                   s += 50
            if (p ~ /\/uploads\/20[0-9][0-9]\/[0-9][0-9]\// && b != "index.php") s += 25
            if (p ~ /\/wp-content\/mu-plugins\//)                             s += 25
            if (p ~ /\/wp-content\/uploads\/[^\/]+$/ && b != "index.php")      s += 20
            # Co CONG NHAN CMS, y het `pscore()` — xem chu thich o do.
            if (p ~ /\/public_html\/[^\/]+\.php$/ && !(b in core0) \
                && (wproot(p) in iswp))                                        s += 15
            # Ba tin hieu them 24-09, PHAI GIONG `pscore()` — neu thieu o day thi
            # mode `score` khong thay thu dang chay trong `check`, tuc cong cu do
            # mu voi chinh he thong no do. Chu thich day du o `pscore()`.
            # `corelike` = 0 diem, y het `pscore()` — chu thich day du o do.
            if ((wproot(p) in iswp) && !(p in corelike)) {
                nm = del1_core(b)
                if (nm == 2)      s += 25
                else if (nm == 1) s += 10
            }
            if (p ~ /\/wp-content\/plugins\/[a-z-]+-[0-9a-f]{6,}\//)           s += 20
            if (p ~ /\/wp-content\/[^\/]+\/[^\/]+\.php$/ \
                && p !~ /\/wp-content\/(plugins|themes|uploads|upgrade|upgrade-temp-backup|languages|mu-plugins)\// \
                && (wproot(p) in iswp))                                        s += 15
            # wp-(includes|admin)/ DA BO — xem chu thich o `pscore()` trong
            # `check`. Do 24-09: 183.908/1.357.213 file (13,5%) an diem nay.
            if (p in fraghit)                                                 s += 10
            return s
        }
        # Manifest truyen HAI LAN: luot dau thu `iswp` (webroot nao co
        # `wp-settings.php`), luot hai moi cham diem. Can hai luot vi mot file o
        # dau manifest phai biet webroot cua no co WordPress khong, ma bang chung
        # do co the nam o dong bat ky phia sau.
        NR == FNR {
            if ($1 ~ /\/public_html\/wp-settings\.php$/) iswp[wproot($1)] = 1
            next
        }
        {
            s = base_score($1)
            hist[s]++
            tot++
            if (s >= 40) top[$1] = s
        }
        END {
            printf "=== PHAN BO DIEM NEN tren %d file ===\n", tot
            # KHONG dung `asorti`: no la gawk-only va day la cho DUY NHAT trong
            # ca script can sap xep khoa. Script goi `awk` khong dinh danh, nen
            # tren may co mawk/BWK awk thi `asorti` hong CAM — dung cai loi im
            # lang ma ca ban nay duoc viet ra de tranh. Diem la boi so cua 5 va
            # co chan tren, nen dem xuoi tu cao xuong thap la du.
            cum = 0
            for (k = 160; k >= 0; k -= 5) {
                if (!(k in hist)) continue
                cum += hist[k]
                printf "  sc=%-4d %8d file   (tu diem nay tro len: %d)\n", k, hist[k], cum
            }
            print ""
            print "=== FILE >= 40 DIEM ==="
            m = 0
            for (p in top) { printf "  sc=%-4d %s\n", top[p], p; m++ }
            if (m == 0) print "  (khong co)"
            print ""
            print "DOC SO NAY THE NAO: cot cuoi la so file se bi bao neu dat"
            print "nguong tai dong do. Nguong dat duoc la nguong ma so do du nho"
            print "de nguoi that doc het, VA khong bo sot file da biet la webshell."
        }
    ' "$MANIFEST" "$MANIFEST"
    exit 0
fi

# ── audit: HIEN TRANG, khong phai THAY DOI ────────────────────────────
#
# VI SAO CAN MOT CHE DO RIENG, va day la lo hong cua chinh ban `MUPLUG` vua
# them: `check` chi bao NEW/CHG so voi manifest. 20-09, sau khi deploy `MUPLUG`
# len 28-246, `check --hot` tra `exit=0` va khong in gi — dung trong khi may do
# dang co 20 webshell trong `mu-plugins`. Khong phai loi: 20 file da vao
# `manifest.hot.txt` tu thang 7 nen chung khong con la NEW. Mot may do THAY DOI
# thi mot webshell da nam trong anh chup se im lang VINH VIEN.
#
# `check` tra loi "co gi doi", `audit` tra loi "dang co gi". Cau thu hai la cau
# phai hoi khi nghi may DA bi xam nhap, va no khong doc manifest mot dong nao.
#
# HAI BO, va do la kien truc chu khong phai mot ghi chu:
#   [GENERIC]   chay tren MOI webroot, ke ca site khong dung CMS nao. Hien chi
#               co mot nhanh — file cau hinh world-writable — vi hai truc doc
#               lap CMS khac da THU va BI BAC BO tren 5 may (so lieu o trong).
#   [WORDPRESS] chi chay o webroot co `wp-includes/version.php` tren dia. Bon
#               nhanh: mu-plugins, uploads/ tang 1, wp-content/ tang 1,
#               themes/ tang 1.
# May khong co WordPress nao thi bo thu hai bi BO QUA va noi ro la bo qua, thay
# vi in bon bang rong gay tuong la "da soi va sach".
#
# Moi nhanh deu la `-maxdepth`-co-chu-dich: `plugins/` va tung theme co hang
# nghin file hop le nen liet ke tron la vo dung — do la viec cua `check`.
#
# KHONG doc/ghi manifest, KHONG ghi Redis, KHONG ghi $CRITLOG: `audit` la mot
# phep DOC. Chay no bao nhieu lan cung khong doi trang thai gi — nen no an toan
# de chay giua luc dieu tra, khac `baseline` (quyet dinh bao mat).
if [ "$mode" = "audit" ]; then
    # Mot ham, nhieu vung, vi chung khac nhau o DO SAU chu khong o cach doc.
    # Doc tu stdin, tra so dong qua $AUDIT_N (bash khong tra duoc so tu ham).
    # `sort -u` TRONG ham, khong o tung cho goi — va day la mot loi THAT da lot
    # ra production 20-09, khong phai phong thu thua.
    #
    # Moi nhanh chay HAI `find`: `$ROOTS/...` va `$ROOTS/*/...` (nhanh thu hai
    # phu WordPress cai trong thu muc con cua public_html). Voi `-maxdepth 2` thi
    # `$ROOTS` DA phu toi `public_html/*/x.php`, nen `$ROOTS/*` quet lai CHINH
    # vung do va moi file bi dem HAI LAN.
    #
    # Trieu chung khi do tren may that: `audit` dem 20 / 16 / 10 / 8 trong khi
    # `find` truc tiep ra 10 / 8 / 5 / 4 — ty le 2:1 CHINH XAC tren bon may khac
    # nhau. Mot con so gap doi deu dan nhu vay khong bao gio la trung hop; do la
    # dau hieu quet chong.
    #
    # Dat o DAY chu khong o tung cho goi: bon nhanh + nhanh GENERIC deu co cung
    # hinh dang, va sua o mot cho thi khong the sot cho nao.
    audit_list() {
        printf '%-6s %-9s %s\n' 'SO' 'KICH CO' 'DUONG DAN'
        local n=0 p s _t
        # KHONG them `sort`: bash bung glob `$ROOTS` theo thu tu da sap xep nen
        # cac file cung mot site von da lien nhau, va "site nao co bao nhieu
        # file" — hinh dang cua mot vu xam nhap — doc duoc ngay. Da kiem bang
        # phep thu chu khong gia dinh.
        while IFS='|' read -r p s _t; do
            [ -n "$p" ] || continue
            n=$((n + 1))
            printf '%-6s %-9s %s\n' "$n" "$s" "$p"
        done < <(sort -u)
        AUDIT_N=$n
    }

    # ══ BO GENERIC — moi CMS, va moi site KHONG CMS ═══════════════════
    #
    # VI SAO PHAI TACH THANH HAI BO chu khong ghi mot dong chu thich: cac nhanh
    # WordPress ben duoi mu HOAN TOAN voi Drupal, Joomla, Magento, Laravel va
    # site code tay. Do 20-09: may 183-139 (code tay) tra 0 cho MOI nhanh
    # WordPress — `audit` khong nhin thay gi tren ca mot may.
    #
    # HAI TRUC "doc lap CMS" DA THU VA BI BAC BO tren ca 5 may. Ghi ra day voi
    # con so de khong ai xay lai:
    #
    #   (a) Ten file co chu HOA lan THUONG  ->  196.134 file tren 171-96 (52%
    #       toan bo .php), 76k-89k tren cac may khac. Composer/PSR-4 BAT BUOC
    #       CamelCase cho class file (`ClassLoader.php`,
    #       `ActionScheduler_Action.php`). Truc nay khong phan biet duoc gi.
    #
    #   (b) File .php co execute bit  ->  7.195 / 1.066 / 11 / 0 / 0. Phan bo
    #       khong dong nhat giua cac may nen khong phai truc on dinh; phan lon
    #       la rac `__MACOSX/._*` tu zip giai nen tren macOS.
    #
    # Ket luan rut ra, va no la ly do bo GENERIC nho the nay: KHONG co truc nao
    # phan biet duoc webshell ma khong biet cau truc site. Webshell la file PHP
    # hop le dat o noi hop le ve filesystem — thu duy nhat sai la NO KHONG THUOC
    # VE PHAN MEM NAO DANG CAI, va cau do chi tra loi duoc khi biet phan mem gi.
    # Tren site code tay thi khai niem do khong ton tai: `msmobile.vn` co
    # `CopyOfvertical.php`, `Lib+/`, `alepay-installment_____/` — lap trinh vien
    # de lai file nhap, va moi truc "ten bat thuong" se bao het.
    #
    # Nen voi CMS khac va site code tay, phong tuyen la `fim.sh check`: no KHONG
    # can biet CMS, no so voi manifest cua CHINH site do. File moi la file moi,
    # bat ke Drupal hay code tay. Do dung la thu bat duoc 20 webshell 20-09.
    # `audit` chi bo sung cho ca webshell DA nam trong manifest tu truoc.
    #
    # Truc duy nhat o bo nay da chung minh gia tri: file CAU HINH world-writable.
    # Do 20-09: 6 site co `wp-config.php` mode o+w tren 3 may. Do la file chua
    # mat khau database. `open_basedir` chan PHP cua user khac nhung KHONG chan
    # SSH/cron cua chinh user do. Ap cho moi CMS vi moi CMS deu co file cau hinh.
    # Ten file cau hinh cua cac CMS pho bien. Danh sach nay KHONG can day du —
    # no chi can phu cai dang chay tren dan may, va mo rong duoc khi gap CMS moi.
    #   wp-config.php      WordPress
    #   configuration.php  Joomla
    #   settings.php       Drupal
    #   LocalSettings.php  MediaWiki
    #   config.php         Magento/phpBB/nhieu framework va site code tay
    #   .env               Laravel/Symfony
    #
    # CHUA THU DUOC TAI CHO: may dev la Git Bash tren Windows, `chmod` khong doi
    # duoc bit `o+w` nen khong dung duoc mot file world-writable de doi chieu.
    # Da kiem cu phap `-perm -o+w` chay khong loi va nhanh `find` tim dung file
    # khi bo dieu kien perm; phan LOC thi chi xac minh duoc tren may that.
    # Lenh doi chieu tren may that:
    #   find /home/*/domains/*/public_html -maxdepth 2 -name 'wp-config.php' \
    #        -type f -perm -o+w
    # phai ra dung 6 file da do 20-09 (3 may). Ra 0 thi nhanh nay CAM, khong
    # phai "khong co file nao" — phan biet hai cai do truoc khi tin.
    CONF_NAMES=( \( -name 'wp-config.php' -o -name 'configuration.php' \
                 -o -name 'settings.php'  -o -name 'config.php'        \
                 -o -name 'LocalSettings.php' -o -name '.env' \) )

    echo "### [GENERIC] File cau hinh world-writable -- moi CMS ###"
    audit_list <<EOF
$(find $ROOTS   -maxdepth 2 "${CONF_NAMES[@]}" -type f -perm -o+w -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/* -maxdepth 2 "${CONF_NAMES[@]}" -type f -perm -o+w -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    conf_n=$AUDIT_N
    echo
    echo "tong: $conf_n file -- 0 la binh thuong. File nay chua mat khau database."

    # ══ BO WORDPRESS ══════════════════════════════════════════════════
    #
    # CHI chay khi tim thay WordPress that tren dia. Dau hieu la
    # `wp-includes/version.php` — file core, moi ban WordPress deu co, va khong
    # doan theo ten thu muc. Neu may khong co WordPress nao thi cac nhanh duoi
    # bi bo qua hoan toan thay vi in ba bang rong gay tuong la "da soi va sach".
    wp_roots=$(
        { find $ROOTS   -maxdepth 2 -path '*/wp-includes/version.php' -type f 2>/dev/null || :
          find $ROOTS/* -maxdepth 2 -path '*/wp-includes/version.php' -type f 2>/dev/null || :
        } | sed 's#/wp-includes/version\.php$##' | sort -u)
    wp_count=$(printf '%s\n' "$wp_roots" | grep -c . || :)

    echo
    if [ "${wp_count:-0}" -eq 0 ]; then
        echo "### [WORDPRESS] khong tim thay WordPress nao -- bo qua ###"
        echo "(dau hieu: wp-includes/version.php. Site khong-WordPress dua vao"
        echo " 'fim.sh check', xem chu thich bo GENERIC o tren.)"
        exit 0
    fi
    echo "### [WORDPRESS] $wp_count webroot -- cac nhanh duoi CHI ap cho WordPress ###"
    echo

    echo "### mu-plugins -- WordPress include MOI .php o day tren MOI request ###"
    audit_list <<EOF
$(find $ROOTS/wp-content/mu-plugins   "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content/mu-plugins "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    mu_n=$AUDIT_N
    echo
    # DOC SO NAY THE NAO — ghi ra day vi con so tran khong tu noi gi. Do 20-09:
    # site sach co DUNG MOT file (cua SEO agency, ~7.316 byte, xem
    # memory/project_muplugins_agency_file.md). Site nhiem co 8 va 14.
    echo "tong: $mu_n file -- site LANH thuong 0-1. Nhieu hon la dang xem tung file."

    # ── uploads/ — CHI TANG MOT, va do la ca thiet ke ─────────────────
    #
    # `-maxdepth 1` khong phai de re. No la TRUC PHAN BIET, rut ra tu do
    # 20-09 tren ca 5 may:
    #
    #   ~424 file .php trong uploads/ toan dan  ->  CHI 5 file nam THANG trong
    #   uploads/ (da bo index.php). Ty le loc 98,8%, va giu duoc tren CA 5 MAY.
    #
    # Ly do no dung: WordPress bat plugin ghi vao THU MUC RIENG cua no —
    # `sucuri/`, `wpo/`, `smush/`, `woocommerce_uploads/`, `smile_fonts/`,
    # `wp-staging/`. Ke tan cong tha webshell o noi URL NGAN NHAT va chac chan
    # ton tai. Day la khac biet ve CACH LAM chu khong ve ten file, nen khong
    # can biet plugin nao ten gi — dung cai khong bao gio biet het duoc.
    #
    # TRUC DA BI BAC BO, ghi lai de khong ai xay lai: "file trung hash tren
    # >=2 site la lanh". Do 5 may bac bo — 62% file la DUY NHAT tren 28-246,
    # 30% tren 168-101. Vi plugin bao mat (Sucuri) ghi DU LIEU RIENG cua tung
    # site vao file .php (audit log, failed login, settings) nen moi site mot
    # hash. Trung lap KHONG phai dau hieu lanh tinh.
    #
    # `index.php` bi loai: WordPress chuan, 0 byte, chong liet ke thu muc — 58
    # cai chi rieng 171-96.
    #
    # KET QUA THAT cua 5 file loc duoc (20-09): 3 la Really Simple SSL
    # (`code-execution.php`, 150 byte, da xac minh noi dung), 2 la WEBSHELL:
    #   `wp-blockup.php` 416B — RCE co MAT KHAU (md5 cua $_REQUEST[lt]), ghep
    #       `base64_decode` bang chr() de ne grep, ghi file tam roi `unlink`
    #       ngay sau khi chay => chong phap chung.
    #   `icVp.php` 0B — ten 4 ky tu ngau nhien, mtime 2023-03 nhung ctime
    #       2024-07: LECH 16 THANG, tuc co nguoi dat lai mtime cho khop file
    #       xung quanh. Plugin hop le khong lam vay.
    # 2/5 la that. Do la ty le tin hieu/nhieu cao nhat trong moi phep do cua
    # ngay hom do.
    echo
    echo "### uploads/ -- CHI tang 1, bo index.php (xem chu thich: truc phan biet) ###"
    audit_list <<EOF
$(find $ROOTS/wp-content/uploads   -maxdepth 1 "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content/uploads -maxdepth 1 "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    up_n=$AUDIT_N
    echo
    echo "tong: $up_n file -- 0 la binh thuong. Bat ky file nao o day cung dang doc."

    # ── uploads/YYYY/MM/ — THU MUC MEDIA, bat bien khac han tang 1 ─────
    #
    # Nhanh tren loc theo DO SAU va gia thuyet "ke tan cong muon URL ngan".
    # Dung cho webshell go tay, SAI cho thu tu cai: no khong can ai go URL.
    # Do 22-09 bat duoc dung cho mu: `easypost-1781527859-2818.php` 144KB nam
    # o `uploads/2026/06/` — DO SAU 3, nhanh tren mu hoan toan suot 3 thang.
    #
    # Truc o day khong phai do sau ma la NGHIA CUA THU MUC: `uploads/YYYY/MM/`
    # la noi WordPress bo MEDIA (anh, pdf). Plugin ghi vao thu muc rieng cua
    # no, khong ai ghi .php vao thu muc anh theo thang. Bat bien hep va kiem
    # duoc — khac han "moi /uploads/ deu khong chay PHP" (gia thuyet rong,
    # da bi bac).
    #
    # DAN SO DO TRUOC KHI VIET, 5 may, moi do sau: 9 file.
    #   6 la `index.php` (chot chan liet ke thu muc, WordPress rai khap noi
    #     — da mien tu 02-09 o `wp_theme_direct`), bi loai o day.
    #   3 con lai DEU dang bao:
    #     `easypost-1781266669-2828.php` 31KB + `...2818.php` 144KB — endpoint
    #        tu nap wp-load.php (do len 6 cap), doc header tuy y, xac thuc bang
    #        token, va co PUBLIC KEY de nhan ban cap nhat ky so (OTA). Chay
    #        NGOAI index.php nen moi plugin bao mat va moi hook deu bi bo qua.
    #        Do plugin `wp-content/plugins/easypost/` tu ghi ra bang
    #        `file_put_contents(base64_decode(...))`.
    #     `zgepd_oddsd.php` 0 byte tu 2020 — cung dang 0 byte voi `icVp.php`.
    # => 3 dong/5 may, KHONG FP. Ty le sach hon ca truc tang 1.
    #
    # NHANH DA XET VA BAC cung ngay: "thu muc LA o wp-content/ tang 1". Do
    # 171-96 tra ve hon 20 thu muc ten PLUGIN (`contact-form-7`, `woocommerce`,
    # `classic-editor`, `duplicator`, `really-simple-ssl`) nam sai cap — giai
    # nen hong hoac ban sao luu, khong phai xam nhap. Viet luat do thi
    # `easypost` chim trong 20 dong nhieu. Do dung la bai toan liet ke ten da
    # bac o `exposed.lua`, chi khac la liet ke phia cho phep.
    echo
    echo "### uploads/YYYY/MM/ -- thu muc MEDIA, .php o day khong co ly do chinh dang ###"
    audit_list <<EOF
$(find $ROOTS/wp-content/uploads   -regextype posix-extended -regex '.*/uploads/20[0-9]{2}/[0-9]{2}/.*' "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content/uploads -regextype posix-extended -regex '.*/uploads/20[0-9]{2}/[0-9]{2}/.*' "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    med_n=$AUDIT_N
    echo
    echo "tong: $med_n file -- 0 la binh thuong. Do 5 may: 3 file, ca 3 deu dang bao."

    # ── wp-content/ tang 1 — DROP-IN la mot tap DONG ──────────────────
    #
    # WordPress tu `include` dung 7 ten o day, va danh sach do nam trong CORE
    # chu khong phu thuoc plugin nao: advanced-cache, object-cache, db,
    # db-error, install, maintenance, sunrise. Mot file .php khac o tang 1 thi
    # WordPress KHONG nap — no chi chay khi co HTTP request go thang vao.
    #
    # Do 20-09 tren 4 may WordPress: ngoai `index.php` va 7 drop-in tren, chi
    # con `wp-cache-config.php` (WP Super Cache, 5 site) va `advanced-headers.php`
    # (plugin cache, 1 site) — hai ten nay them vao danh sach tha vi da do duoc.
    # Sau khi tru het: 3 file, TAT CA tren cung mot site.
    #
    #   `JFYUvWNTPCy.php`  36KB  ghep ten ham tu chi so ky tu cua mot cau tieng
    #                            Anh -> ne moi phep grep chu ky
    #   `cfunteuvom.php`  166KB  FoxAutoV5 / Leaf PHP Mailer (anonymousfox.co)
    #                            — bo gui spam
    #   `themes.php`        29B  `<?php system($_GET['vk']); ?>` va chmod 777.
    #                            Khong mat khau, khong che giau.
    # Site do (`thegioibds.online`) bi chiem tu 2022 — ba nam.
    DROPIN=( ! -name 'index.php'         ! -name 'advanced-cache.php' \
             ! -name 'object-cache.php'  ! -name 'db.php'             \
             ! -name 'db-error.php'      ! -name 'install.php'        \
             ! -name 'maintenance.php'   ! -name 'sunrise.php'        \
             ! -name 'wp-cache-config.php' ! -name 'advanced-headers.php' )

    echo
    echo "### wp-content/ tang 1 -- tru index.php + 7 drop-in core + 2 ten cache ###"
    audit_list <<EOF
$(find $ROOTS/wp-content   -maxdepth 1 "${NAMES[@]}" -type f "${DROPIN[@]}" -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content -maxdepth 1 "${NAMES[@]}" -type f "${DROPIN[@]}" -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    wpc_n=$AUDIT_N
    echo
    echo "tong: $wpc_n file -- 0 la binh thuong. WordPress KHONG nap file nao khac o day."

    # ── themes/ tang 1 — khong thuoc theme nao ────────────────────────
    #
    # File .php nam THANG trong `themes/` thi khong thuoc theme nao ca —
    # WordPress khong sinh ra thu do. Do 20-09 tren 4 may: 39-45 file/may va
    # TAT CA la `index.php` (chong liet ke thu muc), tru dung MOT ngoai le:
    # `themes/themes.php` tren `thegioibds.online` — ban sao cua webshell 29
    # byte o tren.
    echo
    echo "### themes/ tang 1 -- file khong thuoc theme nao, tru index.php ###"
    audit_list <<EOF
$(find $ROOTS/wp-content/themes   -maxdepth 1 "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content/themes -maxdepth 1 "${NAMES[@]}" -type f ! -name 'index.php' -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    th_n=$AUDIT_N
    echo
    echo "tong: $th_n file -- 0 la binh thuong."

    echo
    echo "audit KHONG phan biet duoc lanh/doc -- no chi liet ke. Thu muc con cua"
    echo "uploads/ va tung theme KHONG duoc soi (do la noi plugin/theme ghi hop"
    echo "le); dung 'find <duong-dan> -name \"*.php\"' neu can nhin het."
    exit 0
fi

# MANIFEST RIENG CHO TUNG TIER, va day la yeu cau DUNG DAN chu khong phai gon
# gang: tang nong quet mot tap con: doi chieu no voi manifest day du se bao MOI
# FILE KHONG DUOC PHU la DEL. Mot lan chay --hot se bien manifest day du thanh
# rac va nuot luon moi thay doi ve sau.
MANIFEST="$STATE/manifest.$tier.txt"

# Tap duong dan da CHG o lan chay TRUOC — co che chong nhieu theo THOI GIAN.
#
# Bat bien: mot file doi o HAI lan quet LIEN TIEP la file TRANG THAI cua ung
# dung, khong phai xam nhap. Wordfence ghi wp-content/wflogs/*.php khong ngung;
# plugin cache ghi .php khong ngung. Xam nhap thi nguoc lai — no cham mot file
# DUNG MOT LAN roi thoi.
#
# CO Y khong dung danh sach ten thu muc. Danh sach ten sai ca hai chieu: no
# khong biet plugin cache thu 50 ten gi, con ke tan cong doc duoc danh sach thi
# biet chinh xac cho nao duoc mien. Bat bien tren khong can biet ten gi het.
#
# HAI RANG BUOC giu cho no khong che mat viec that:
#   - lan doi DAU TIEN cua mot duong dan luon bao o bac day du; chi tu lan thu
#     hai LIEN TIEP tro di moi ha xuong STATE.
#   - file MOI (NEW) khong bao gio bi ha bac.
#
# Gioi han da biet: file doi cach quang (doi - yen - doi - yen) khong bao gio bi
# ha; va ke tan cong sua tiep mot file dang on ao thi lan sua thu hai roi xuong
# STATE — nhung lan thu nhat da bao roi, va dong STATE van nam day du trong $LOG.
PREVCHG="$STATE/prevchg.$tier.txt"

# QUYEN FILE. Script nay truoc khong dat umask, nen quyen phu thuoc umask cua
# root tung may. Do 13-09: bon may ra 0640, rieng cloud183-139 ra 0644 — khac
# nhau do tinh co, khong do thiet ke.
#
# Tren shared hosting dieu do co nghia that: `manifest.full.txt` la danh muc
# DAY DU duong dan va kich thuoc file cua MOI khach hang tren may (13.636 dong
# tren 183-139). De 0644 thi PHP cua bat ky khach nao cung doc duoc ban do file
# cua tat ca khach con lai — ke ca ten file backup va ten thu muc admin tu dat.
#
# Dat umask o day chu khong chmod tay tung may, vi may moi dung se lai sinh ra
# sai quyen y nhu cu.
umask 077

mkdir -p "$STATE" || { echo "khong tao duoc $STATE" >&2; exit 2; }
# umask khong dong toi file DA TON TAI. Sua lai nhung cai da sinh ra voi quyen
# rong tren cac may cu; `|| :` vi $LOG co the chua ton tai o lan chay dau.
chmod 0700 "$STATE" 2>/dev/null || :
chmod 0600 "$STATE"/* "$LOG" 2>/dev/null || :

# KHOA CHONG CHAY CHONG. Bat buoc khi chay day (moi 15 phut): neu mot lan quet
# lau hon khoang cach giua hai lan, hai tien trinh se cung ghi $MANIFEST va ban
# ghi thang nao ket thuc sau thi thang. Hau qua khong phai bao dong sai ma la
# BO SOT: manifest bi ghi de bang anh chup cu hon, va thay doi giua hai moc do
# bien mat vinh vien.
#
# `-n` = khong doi. Lan chay bi trung se thoat im lang: no khong co gi de bao,
# lan dang chay se bao.
#
# Kiem su ton tai cua `flock` RIENG, truoc khi goi. `if ! flock -n 9` khong phan
# biet duoc "khoa dang bi giu" (exit 1) voi "khong co lenh flock" (exit 127) —
# ca hai deu vao nhanh thoat 0 im lang. Nghia la tren may thieu util-linux,
# FIM se KHONG LAM GI CA va bao thanh cong, mai mai. Chet o day to tieng con hon.
command -v flock >/dev/null 2>&1 || {
    echo "thieu lenh 'flock' (goi util-linux). Khong chay ma khong co khoa:" >&2
    echo "hai lan chay chong nhau se ghi de manifest bang anh chup cu hon." >&2
    exit 2
}

exec 9>"$STATE/.lock.$tier" || { echo "khong mo duoc lockfile" >&2; exit 2; }
if ! flock -n 9; then
    [ $verbose -eq 1 ] && echo "dang co lan chay khac, bo qua"
    exit 0
fi

if [ "$mode" = "baseline" ]; then
    scan > "$MANIFEST" || { echo "quet that bai" >&2; exit 2; }
    n=$(wc -l < "$MANIFEST")
    # 0 file KHONG phai mot ket qua hop le. Tren mot may hosting dang chay,
    # `/home/*/domains/*/public_html` luon co it nhat mot .php — quet ra rong
    # nghia la FIM_ROOTS sai, mount chua gan, hoac khong co quyen doc. Neu de
    # manifest rong ton tai thi lan `check` sau se coi MOI file la NEW.
    if [ "$n" -eq 0 ]; then
        rm -f "$MANIFEST"
        echo "quet ra 0 file -- khong ghi manifest. Kiem FIM_ROOTS=$ROOTS" >&2
        exit 2
    fi
    # Manifest moi thi moi so sanh CHG truoc do het nghia.
    : > "$PREVCHG"
    echo "baseline: $n file"
    exit 0
fi

[ "$mode" = "check" ] || usage
[ -s "$MANIFEST" ] || { echo "chua co manifest — chay '$0 baseline' truoc" >&2; exit 2; }

new_scan=$(mktemp) || exit 2
diff_out=$(mktemp) || exit 2
# Ba file phu cho cot `sc=` (cham diem canary). Khai bao o day chu khong o cho
# `$marks` vi `$SZSAME` phai ton tai TRUOC awk diff — do la noi duy nhat co ca
# kich thuoc cu va moi trong tay.
SZSAME=$(mktemp) || exit 2
PWFILE=$(mktemp) || exit 2
FRAGFILE=$(mktemp) || exit 2
CLFILE=$(mktemp) || exit 2
trap 'rm -f "$new_scan" "$diff_out" "$SZSAME" "$PWFILE" "$FRAGFILE" "$CLFILE"' EXIT
# NGOAI khoi `tier = full`: 17 file cach ly nam o tang 0 webroot, ma `scan_hot`
# CO quet tang 0 — thieu o day thi tier nong lai cham 25 diem cho chung.
core_like_list > "$CLFILE" || :

scan > "$new_scan" || { echo "quet that bai" >&2; exit 2; }

# CHOT AN TOAN — thu duy nhat dung giua mot lan quet HONG va mot tham hoa.
#
# Chuoi su kien neu thieu no: quet ra rong (mount roi, FIM_ROOTS sai, doi user
# chay cron) → khoi END cua awk in `DEL|` cho ca 317.343 duong dan → script van
# chay tiep → dong `cp "$new_scan" "$MANIFEST"` o cuoi ghi de manifest bang file
# RONG → lan chay ke tiep thay ca 317.343 file la NEW → day tat ca thanh khoa
# `waf:fimnew:` vao Redis. Moi file PHP tren may duoc nang tin hieu cung mot luc,
# tuc canh bao mat het y nghia dung luc no phai co y nghia nhat.
#
# `pipefail` von dang chan viec nay mot cach TINH CO. Sau khi them `|| :` vao
# tung `find` o tren, cho chan do khong con — nen phai noi thanh loi o day.
#
# CHI chan truong hop 0. Xoa mot domain that su co the lam bien mat hang nghin
# file, nen mot nguong theo TY LE se chan ca thao tac hop le; con 0 file thi
# khong the la ket qua that khi manifest dang co san hang tram nghin.
if [ ! -s "$new_scan" ]; then
    echo "quet ra 0 file trong khi manifest co $(wc -l < "$MANIFEST") -- coi la" >&2
    echo "LOI QUET, khong phai xoa hang loat. Manifest giu nguyen." >&2
    echo "Kiem FIM_ROOTS=$ROOTS va quyen doc cua user dang chay." >&2
    exit 2
fi

# Mot luot awk: NEW (duong dan chua tung thay), CHG (kich thuoc hoac mtime doi),
# DEL (bien mat). So sanh theo DUONG DAN chu khong theo dong, nen mot file doi
# noi dung ra dung mot dong CHG chu khong phai mot NEW cong mot DEL.
#
# `szfile`: danh sach duong dan CHG ma KICH THUOC khong doi (chi mtime doi).
# Sinh ngay o day vi day la cho duy nhat co CA hai gia tri trong tay — lam o awk
# bao cao thi phai doc lai ca `$MANIFEST` va `$new_scan`, hai file 317k dong.
# Dung cho cot `sc=` (cham diem canary): `wp-cron-vosi.php` doi mtime 4 lan
# trong 2 ngay ma luon 1.659 byte — co cai gi dang `touch` no.
awk -F'|' -v szfile="$SZSAME" '
    NR==FNR { old[$1] = $2 "|" $3; olds[$1] = $2; next }
    {
        if (!($1 in old))              print "NEW|" $1
        else if (old[$1] != $2 "|" $3) {
            print "CHG|" $1
            if (olds[$1] == $2) print $1 > szfile
        }
        seen[$1] = 1
    }
    END { for (p in old) if (!(p in seen)) print "DEL|" p }
' "$MANIFEST" "$new_scan" > "$diff_out"

# ── NGUONG TON DONG mu-plugins ────────────────────────────────────────
#
# VI SAO PHAI CHAY TRUOC NHANH `total -eq 0`: 20-09 tren 28-246, `check --hot`
# tra exit=0 va im lang trong khi may do dang co 37 file .php trong mu-plugins,
# 21 trong so do la webshell. Khong sai: chung da vao manifest tu thang 7 nen
# khong con la NEW. Nhung mot may chi bao THAY DOI thi mot ton dong da nam san
# se im lang vinh vien, va `audit` chi noi khi co nguoi go lenh.
#
# Day la duong bao KHONG can ai nho gi: `check` dang chay san moi 5 phut.
#
# NGUONG THEO SITE, khong theo may, va con so den TU DO chu khong tu cam giac:
# do 20-09 tren dan may — 16/18 site co DUNG MOT file (cua SEO agency, xem
# memory/project_muplugins_agency_file.md), hai site nhiem co 8 va 14.
#
# 3 -> 2 (do lai 23-09, 4 may WordPress). Nguong 3 SAI VA DA BO SOT THAT:
# `dichthuattienganh.org` co dung 2 file, CA HAI la webshell, va `2 >= 3` la
# sai nen khong mail, khong ghi $CRITLOG — site nhiem hoan toan, canh bao im
# lang. Nguong 3 rong hon dan so mot bac: site lanh la 0-1, nen no bo trong
# han vung "2 file" va webshell roi dung vao do.
#
# PHAN BO TOAN DAN 23-09, 4 may:
#     1 file -> 36 site (SEO agency, da xac minh khong phai malware)
#     2 file ->  3 site -> CA 3 DEU NHIEM, khong mot site lanh nao
#     3 file ->  2 site | 8 file -> 1 | 14 file -> 1
# Vung "dung 2 file" khong co site lanh nao => ha xuong 2 thi FP du kien = 0.
#
# Ba site 2-file la cung mot bo: `wp2shell-batch-guard.php` DUNG 1967 byte tren
# ca ba (chep nguyen), `firewall.php` 983/997/1004 (lech vai byte — nhung phan
# rieng theo site). Chung di THEO CAP: mot file la shell, mot file giu cho.
# Do la ly do ky thuat khien nguong le (3) bo sot mot lop tan cong di chan (2).
#
# KHONG ha xuong 1: 36 site lanh dang co dung 1 file => nguong 1 = 36 dong
# nhieu moi lan chay, dung cai ho den ma ban nay duoc viet ra de thay the.
#
# CHONG LAP: chi bao khi con so DOI so voi lan truoc. Khong co no thi day la 288
# dong giong het nhau moi ngay, tuc mot ho den thu ba — dung thu ma ca ban nay
# duoc viet ra de thay the.
MU_MAX="${FIM_MU_MAX:-2}"
MUSTATE="$STATE/mucount.$tier.txt"

mu_over=$(awk -F'|' -v max="$MU_MAX" '
    # Khoa la THU MUC mu-plugins, tuc mot dong cho mot site. Cat tai
    # "/wp-content/mu-plugins/" chu khong dung dirname: WordPress cai trong thu
    # muc con cung phai gop dung ve site cua no.
    {
        i = index($1, "/wp-content/mu-plugins/")
        if (i == 0) next
        n[substr($1, 1, i - 1)]++
    }
    END { for (s in n) if (n[s] >= max) printf "%d|%s\n", n[s], s }
' "$new_scan" | sort -t'|' -k1,1rn)

# CO THOAT, dat NGOAI khoi chong lap mot cach co y. `mu_over` co gia tri moi
# lan con site vuot nguong; phan IN RA thi chi chay khi con so DOI. Neu dat co
# nay ben trong khoi chong lap thi lan chay thu hai tra exit=0 trong khi 5 site
# van dang nhiem — dung cai sai ma no sinh ra de va.
mu_pending=0
if [ -n "$mu_over" ]; then
    mu_pending=1
    mu_sig=$(printf '%s\n' "$mu_over" | md5sum 2>/dev/null | cut -d' ' -f1)
    mu_prev=$(cat "$MUSTATE" 2>/dev/null || :)
    if [ "$mu_sig" != "$mu_prev" ]; then
        {
            echo "=== $(date '+%Y-%m-%d %H:%M') [$tier] TON DONG mu-plugins ==="
            printf '%s\n' "$mu_over" | while IFS='|' read -r c s; do
                printf '  %3d file  %s\n' "$c" "$s"
            done
            echo "  (nguong $MU_MAX/site; site lanh thuong 0-1. Liet ke: fim.sh audit)"
        # `tee`: stdout de cron mail thay, VA vao $CRITLOG de trang admin thay.
        # Hai duong vi chung that bai khac nhau — mail thi chim, file thi co the
        # mat quyen doc (da gap 20-09).
        } | tee -a "$CRITLOG" 2>/dev/null || :
        # Du thua sau ban 24-09 (quyen dat mot cho o dau file), GIU LAI: neu ai
        # xoa file bang tay giua hai lan chay thi nhanh nay tu sua.
        chgrp nginx "$CRITLOG" 2>/dev/null || :
        chmod 0640 "$CRITLOG" 2>/dev/null || :
        [ $dry -eq 0 ] && printf '%s\n' "$mu_sig" > "$MUSTATE"
    fi
fi

# ── KHUON XAC THUC md5(md5(md5( ────────────────────────────────────────
#
# NHANH DUY NHAT DOC NOI DUNG FILE. Header script dat nguyen tac "METADATA CHU
# KHONG BAM NOI DUNG" va nguyen tac do van dung — day la ngoai le co can do,
# khong phai bo nguyen tac: `grep -l` DUNG o match dau tien moi file va doc tuan
# tu, khac han sha256sum phai doc het moi byte cua 150k file.
#
# VI SAO PHAI DOC NOI DUNG O DAY, khi moi nhanh khac chi xem metadata: webshell
# `wp-cron-vosi.php` (23-09, phiendichquocte.net) KHONG the phat hien bang ten
# hay vi tri — ten giong WordPress, nam o webroot depth 0 cung cho voi 13 file
# core hop le. Chi noi dung to no ra.
#
# VI SAO `md5(md5(md5(` chu khong phai `eval`/`base64_decode`: file do ghi
#     $b = 'ba'.'s'.'e'.'6'.'4_'.'de'.'co'.'de';
# nen `grep 'base64_decode'` TRUOT HOAN TOAN — da thu, tra ve rong. Ten ham
# ghep duoc tu manh chuoi; `md5(md5(md5(` la CU PHAP, khong ghep duoc.
#
# DAN SO DO TRUOC KHI VIET, 5 may:
#     186-126 -> 2 file (cung 1 site) | 168-101, 171-96, 28-246, 183-139 -> 0
# Ca 2 file deu la webshell da doc ma: `wp-cron-vosi.php` (uploader ghi file bat
# ky vao duong dan bat ky, xac thuc bang cookie `pwd`, giai 4 lop
# rot13->strrev->base64->gzuncompress, tra 500 khi sai mat khau de trong nhu loi
# server) va `filefuns.php` cung site. KHONG mot false positive nao.
#
# Bam ba lan khong co ly do chinh dang: mot lan la du cho moi muc dich hop le;
# ba lan chi de lam cham viec do mat khau bang bang tra.
#
# NHANH DA XET VA BAC cung ngay, ghi lai de khong ai xay lai:
#   - "ten ham ghep tu manh chuoi" (`'ba'.'s'.'e'...`) — 22/23 file la THU VIEN
#     HOP LE: `less.php` compiler (theme g5plus `innovation` tren 8 site/3 may),
#     `cs-framework/helpers.php` (theme RT, 2 site). Compiler DICH ma nen ghep
#     ten ham la viec that cua no. Lap luan cu dua tren Y DINH ("ghep manh = ne
#     grep"), ma bat bien phai dua tren CAU TRUC.
#   - "thu muc ten ngau nhien 6-9 ky tu trong uploads" — `revslider/templates/`
#     co hang chuc: `filmstrip` `snowscene` `clubflyer` `rockband` `deskscene`.
#   - "ten file core bi chen ky tu" (`wp-sett1ings.php`, `wp-blog-head1er.php`)
#     — khuon that va rat dang ngo, NHUNG chi co tren 1 may (4 site, mtime
#     2015-2019). Khong xay luat tu mau mot may.
#
# CHI TIER DAY DU: do tren 186-126 — ca cay PHP 67 giay, webroot depth 0-1 chi
# 1,8 giay, CUNG ket qua. Nhung `--hot` chay moi 5 phut nen 67 giay la 22% thoi
# gian may; con depth 0-1 thi bo sot
# `uploads/pxgqsbu/zq1vgje/vo1rqbf/index.php` (depth 5) da tim thay that. Tier
# day du chay 30-60 phut/lan va da ton 27 giay cho `find`, nen 67 giay o nhip do
# la chap nhan duoc.
if [ "$tier" = "full" ]; then
    pw_hits=$(grep -rl 'md5(md5(md5(' $ROOTS --include='*.php' 2>/dev/null | sort || :)
    if [ -n "$pw_hits" ]; then
        pw_sig=$(printf '%s\n' "$pw_hits" | md5sum 2>/dev/null | cut -d' ' -f1)
        pw_prev=$(cat "$STATE/pwcount.txt" 2>/dev/null || :)
        if [ "$pw_sig" != "$pw_prev" ]; then
            {
                echo "=== $(date '+%Y-%m-%d %H:%M') [$tier] KHUON XAC THUC md5x3 ==="
                printf '%s\n' "$pw_hits" | while read -r f; do
                    [ -n "$f" ] || continue
                    printf '  %7s  %s\n' "$(stat -c '%s' "$f" 2>/dev/null || echo '?')" "$f"
                done
                echo "  (md5(md5(md5( = mat khau webshell; do 5 may: 2 file, ca 2 deu la webshell)"
            } | tee -a "$CRITLOG" 2>/dev/null || :
            chgrp nginx "$CRITLOG" 2>/dev/null || :
            chmod 0640 "$CRITLOG" 2>/dev/null || :
            [ $dry -eq 0 ] && printf '%s\n' "$pw_sig" > "$STATE/pwcount.txt"
        fi
        # Dung chung co voi ton dong mu-plugins: ca hai la "do duoc, co su co"
        # nen cung tra exit 3. Dat NGOAI khoi chong lap, cung ly do.
        mu_pending=1
    fi
    # Cho cot `sc=`: dung lai ket qua o tren, KHONG grep lai lan hai.
    printf '%s\n' "$pw_hits" > "$PWFILE"

    # Ten ham ghep tu manh chuoi. TRUC NAY DA BI BAC lam luat (22/23 file la thu
    # vien LESS/framework hop le) va CHINH VI THE no o day: voi trong so 10 no
    # vo hai, con mot file co CA no VA md5x3 thi tong la 60. Do la diem cua co
    # che cong diem — truc nhieu van dung duoc, khong phai bo di.
    grep -rlE "'ba'\s*\.|'base'\s*\.\s*'64|'str'\s*\.\s*'rev'|'str'\s*\.\s*'_'" \
        $ROOTS --include='*.php' 2>/dev/null | sort > "$FRAGFILE" || :
fi

total=$(wc -l < "$diff_out")
if [ "$total" -eq 0 ]; then
    [ $dry -eq 0 ] && cp "$new_scan" "$MANIFEST"
    # PHAI xoa. Khong co CHG nao nghia la moi duong dan deu da yen. Giu lai tap
    # cu se ha bac nham cho mot file on ao tu thang truoc roi im, nay doi lai —
    # dung cai lan doi dang duoc bao nhat.
    [ $dry -eq 0 ] && : > "$PREVCHG"
    # IM LANG khi khong co gi. cron gui mail theo BAT KY dong stdout nao, khong
    # phai theo ma thoat — in "khong co thay doi" moi 15 phut la 96 mail/ngay,
    # va hop thu bi nhan chim thi canh bao that cung chim theo.
    [ $verbose -eq 1 ] && echo "khong co thay doi nao"
    # TON DONG van la su co, du khong co file NAO MOI. Do 23-09 tren 186-126:
    # `check --hot` in 5 site ton dong (3 trong so do la webshell da xac minh)
    # roi tra exit=0 — vi khoi ton dong o tren doc `$mu_over`, con nhanh nay chi
    # doc `$total` (so file MOI). Duong ra thu ba — ma thoat — cam han, nen bat
    # ky script giam sat nao doc `$?` deu ket luan la sach.
    #
    # 3 chu KHONG phai 2: `exit 2` o script nay da co nghia "KHONG DO DUOC"
    # (thieu flock, scan ra rong, manifest bat thuong). Ton dong la "DO DUOC, va
    # co su co" — nghia nguoc han. Tron hai cai lai thi mot may HONG va mot may
    # NHIEM WEBSHELL tra ve cung mot ma.
    [ "$mu_pending" -eq 1 ] && exit 3
    exit 0
fi

# Phan loai + gom nhom trong DUNG MOT luot awk.
#
# KHONG dung vong `while read` goi `classify`/`dirname` cho tung dong: mot ban
# cap nhat core 2.000 file se sinh 4.000 tien trinh con. Da tra gia cho dung sai
# lam do mot lan (script khao sat chay 11 phut 21 giay), khong lap lai.
#
# mu-plugins/: BAC RIENG, xem `sev()`. uploads/: khong co ly do chinh dang nao
# de PHP MOI xuat hien. wp-includes/ va wp-admin/: thu vien core, chi doi khi
# cap nhat core — ma cap nhat core cham hang tram file nen roi vao nhanh gom
# nhom, khong gay nhieu.
# plugins/ va themes/: doi thuong xuyen va hop le nen ha xuong ROUTINE.
# Con lai (web root, wp-config.php, .htaccess ngoai cung) la HIGH.
#
# Sap xep theo chuoi muc do cho ra dung thu tu can doc:
#   0SCORE < 1MUPLUG < 2CRITICAL < 3HIGH < 4ROUTINE < 5STATE
#
# TIEN TO SO la BAT BUOC, khong phai trang tri. Ban truoc dua vao thu tu chu
# cai va no DUNG chi vi tinh co: C < H < R < S. Them `MUPLUG` la lo ra ngay —
# `sort` xep M vao GIUA (C, H, M, R, S), tuc bac nang nhat nam thu ba trong
# bao cao. Da kiem bang `printf ... | sort` chu khong suy luan.
# Tien to bi cat khi in (xem `lbl()`), nen nguoi doc khong thay no.
# (STATE = file trang thai, xem $PREVCHG.)
marks=$(mktemp) || exit 2
trap 'rm -f "$new_scan" "$diff_out" "$marks" "$SZSAME" "$PWFILE" "$FRAGFILE" "$CLFILE"' EXIT

report=$(awk -F'|' -v max="$GROUP_MAX" -v markfile="$marks" -v prevfile="$PREVCHG" \
             -v pwfile="$PWFILE" -v fragfile="$FRAGFILE" -v szfile="$SZSAME" \
             -v clfile="$CLFILE" '
    BEGIN {
        # `getline < file` tra -1 khi file khong ton tai — KHONG phai loi, nen
        # lan chay dau tien (chua co prevchg) di thang qua day.
        if (prevfile != "")
            while ((getline _pl < prevfile) > 0) prev[_pl] = 1

        # Ba bang cho cot `sc=`. Cung ly do nhu tren: file rong hay khong ton
        # tai thi `getline` tra <=0 va vong lap khong chay lan nao — `--hot`
        # khong sinh $PWFILE/$FRAGFILE nen o tang nong ba bang nay rong, va do
        # la dung: hai tin hieu noi dung chi do o tier day du.
        if (pwfile   != "") while ((getline _x < pwfile)   > 0) if (_x != "") pwhit[_x] = 1
        if (fragfile != "") while ((getline _x < fragfile) > 0) if (_x != "") fraghit[_x] = 1
        if (clfile   != "") while ((getline _x < clfile)   > 0) if (_x != "") corelike[_x] = 1
        if (szfile   != "") while ((getline _x < szfile)   > 0) if (_x != "") samesize[_x] = 1

        # Tap DONG cac file .php WordPress core dat o webroot tang 0. Danh sach
        # nam trong core, khong phu thuoc plugin nao — cung loai bat bien da cho
        # drop-in `wp-content/` ty le loc cao. `wp-config.php` va
        # `wp-config-sample.php` deu hop le (do 186-126: 21/78 dong la
        # wp-config-sample.php, 3.339 byte giong nhau tren 20 site).
        split("index.php wp-config.php wp-config-sample.php wp-login.php " \
              "wp-settings.php wp-load.php wp-blog-header.php wp-cron.php " \
              "wp-links-opml.php wp-mail.php wp-signup.php wp-trackback.php " \
              "wp-activate.php wp-comments-post.php xmlrpc.php " \
              "wp-admin.php wordfence-waf.php", _c0, " ")
        for (_i in _c0) core0[_c0[_i]] = 1
    }
    function sev(p, t) {
        # mu-plugins/ DUNG TRUOC phep ha bac, va day la ca ly do no co bac rieng.
        #
        # WordPress `include` MOI .php o day tren MOI request, truoc ca khi plugin
        # bao mat khoi dong — nen Wordfence khong thay no (do 20-09: 13 file song
        # hai thang tren mot site CO Wordfence). Khong co request HTTP nao go vao
        # duong dan do de WAF chan. FIM la phong tuyen duy nhat.
        #
        # Do tren dan may 20-09: 16/18 site co DUNG MOT file o day, khong doi tu
        # thang 2. Hai site nhiem co 8 va 14. Thu muc nay ve ban chat KHONG DOI.
        #
        # Vi vay bat bien "doi hai lan lien tiep = file trang thai" ($PREVCHG)
        # DUNG voi wflogs/ va cache, SAI hoan toan o day: khong ung dung hop le
        # nao ghi lien tuc vao mu-plugins. De dong `prev` chay truoc la de ho mot
        # duong ne that — sua mot file mu-plugin hai lan lien tiep thi lan thu hai
        # xuong STATE, `crit` khong dem STATE, tuc KHONG mail va `exit 0`.
        #
        # CHG o day dang ngo ngang NEW, va kin hon: chen dong vao
        # `dev-ci-lint-...php` co san khong lam so file thay doi.
        # DIEM >= 40 THANG MOI PHAN NHANH VI TRI, va day la cho cot `sc=` thoi
        # la canary. Nguong den TU SO LIEU: mode `score` tren 1.357.213 file / 5
        # may (24-09) cho dung 2 file tren 40 diem, ca hai la webshell da doc ma
        # (`wp-cron-vosi.php` 75, `filefuns.php` 65), 0 false positive. Ba may
        # khong co site nhiem tra ve 0.
        #
        # 40 khong phai so chon bua: phan bo co KHOANG TRONG 40 DIEM giua 25
        # (161 file: uploads/YYYY/MM + mu-plugins) va 65. Nguong nam giua mot
        # khoang trong thi on dinh; nguong cat giua dam dong thi khong.
        #
        # Phai dat TRUOC nhanh `mu-plugins` va truoc phep ha bac `prev`: ca hai
        # webshell nay nam o WEBROOT depth 0, va `wp-cron-vosi.php` doi mtime 4
        # lan trong 2 ngay nen no DA vao `prev` — dung duong ne ma nhanh nay sinh
        # ra de dong.
        # Bac RIENG `0SCORE`, khong dung lai `1MUPLUG`: nhan in ra la chu sau
        # tien to, nen `MUPLUG` se bao nguoi doc di tim trong mu-plugins — ma ca
        # hai file do nam o WEBROOT. Tien to `0` cho no sap TRUOC MUPLUG.
        if (pscore(p, t) >= 40)               return "0SCORE"
        if (p ~ /\/wp-content\/mu-plugins\//) return "1MUPLUG"
        # Ha bac TRUOC moi phep phan vung con lai: file trang thai nam trong
        # wp-includes/ thi van la file trang thai. CHI ap cho CHG — NEW khong
        # bao gio bi ha.
        if (t == "CHG" && (p in prev))       return "5STATE"
        if (p ~ /\/wp-content\/uploads\//)    return "2CRITICAL"
        if (p ~ /\/wp-includes\//)            return "2CRITICAL"
        if (p ~ /\/wp-admin\//)               return "2CRITICAL"
        if (p ~ /\/wp-content\/plugins\//)    return "4ROUTINE"
        if (p ~ /\/wp-content\/themes\//)     return "4ROUTINE"
        return "3HIGH"
    }
    # ── CHAM DIEM — CANARY, DIEM CHUA QUYET DINH GI ──────────────────
    #
    # `sev()` o tren phan nhanh MOT CHIEU: ai khop truoc thi thoi. Do la ly do
    # `wp-cron-vosi.php` — webshell that, uploader ghi file bat ky, xac thuc
    # bang cookie `pwd` — bi ha xuong `5STATE` (bac THAP NHAT, `crit` khong dem,
    # khong mail) chi vi no doi mtime hai lan lien tiep. Mot bac duy nhat phai
    # vua la "o dau" vua la "la gi", nen no khong the la ca hai.
    #
    # Cong diem thi khong co chuyen do: moi bat bien gop phan cua no, va mot
    # truc NHIEU van dung duoc voi trong so THAP. Do la khac biet quan trong
    # nhat — no doi cach lam viec: bon ngay qua 12 truc duoc de xuat, 9 bi bac
    # vi cau hoi luon la "truc nay MOT MINH co du sach de bao dong khong?".
    # Voi `less.php` (22 file thu vien LESS hop le) thi cau tra loi la khong.
    # Nhung neu no CONG 10 DIEM thay vi BAO DONG, 22 file kia dung o 10 diem va
    # khong ai phai doc chung. Them tin hieu tro thanh CONG DON thay vi THAY THE.
    #
    # KHI NAO CAN DO DAN SO, VA KHI NAO KHONG — sua lai quy tac cua chinh ban
    # nay (24-09). Ban dau o day ghi "CHI nhung tin hieu DA CO DAN SO". Quy tac
    # do DUNG cho kien truc CU (`sev()` phan nhanh): mot truc thanh LUAT thi no
    # bao dong mot minh, va bao sai lam nguoi ta bo doc bao cao — nen phai dem
    # truoc.
    #
    # Cong diem xoa cau hoi do. Voi trong so 10, mot truc nhieu KHONG BAO GI CA
    # — no chi gop phan. Bang chung nam ngay trong bang nay: `fraghit` nhieu 96%
    # (22/23 file la thu vien LESS) va chinh no la thu tach 75 khoi 65 cho hai
    # webshell tren 186-126. Vo hai o muc 10, co ich khi cong don.
    #
    # Nen quy tac dung la: DO DAN SO khi trong so du lon de MOT MINH vuot nguong
    # 40 (tuc >= 40), KHONG CAN DO khi trong so <= 25 va bat bien la ve CACH LAM
    # chu khong ve TEN. Vi du khong can dem: khong ai dat ten sao luu bang cach
    # chen ky tu vao GIUA tu (`wp-sett1ings.php`), khong ai dat ten plugin co
    # hau to hex ngau nhien (`wp-helper-d698ed`).
    #
    # Nguong 40 da hieu chinh tu 1.357.213 mau (xem `sev()`), nen moi trong so
    # <= 25 deu an toan: du hai truc <= 25 cung nhau van chua toi 40 neu chung
    # doc lap, va khi chung CUNG khop tren mot file thi do chinh la thong tin.
    function pscore(p, t,   s, b, nm) {
        s = 0
        b = basename(p)

        # 50 — noi dung: khuon xac thuc webshell. Do 5 may: 2 file, ca 2 la
        # webshell da doc ma, 0 FP. Danh sach nam trong $PWFILE (tier day du).
        if (p in pwhit) s += 50

        # 25 — uploads/YYYY/MM la thu muc MEDIA. Do 5 may moi do sau: 9 file,
        # 6 la index.php (loai), 3 con lai DEU dang bao.
        if (p ~ /\/uploads\/20[0-9][0-9]\/[0-9][0-9]\// && b != "index.php") s += 25

        # 25 — mu-plugins: WordPress `include` moi .php o day tren MOI request.
        # Do 20-09: 36/40 site lanh co DUNG 1 file, khong doi tu thang 2.
        if (p ~ /\/wp-content\/mu-plugins\//) s += 25

        # 20 — uploads/ tang 1. Do 20-09: ~424 file .php trong uploads/ toan
        # dan -> CHI 5 file nam thang o tang 1. Ty le loc 98,8%.
        if (p ~ /\/wp-content\/uploads\/[^\/]+$/ && b != "index.php") s += 20

        # 15 — webroot tang 0, ten khong thuoc core WordPress. Tap dong: core co
        # dung ~13 file .php o day. Do 186-126: 78 dong, 21 la
        # wp-config-sample.php HOP LE (3.339 byte tren 20 site) — day la ly do
        # trong so THAP chu khong phai bo truc.
        # 15 — webroot tang 0, ten khong thuoc core WordPress. CO CONG NHAN CMS:
        # `core0` la danh sach WordPress, ap len site KHONG phai WordPress thi
        # MOI file deu "la". Do 24-09 tren 183-139 (code tay): 15 file an diem
        # nay, va `router.php` `provinces.php` `kqxs.php` `dashboard.php` deu la
        # file HOP LE cua ho. Cung ho loi voi trong so `wp-includes/` vua bo —
        # gia dinh WordPress dat vao cho khong co cong nhan dien
        # (memory feedback_generic_vs_overlay).
        #
        # Bang chung tren dia la `wp-includes/version.php`, va no DA co trong
        # manifest nen doc duoc ma khong can `find` them.
        if (p ~ /\/public_html\/[^\/]+\.php$/ && !(b in core0) && (wproot(p) in iswp)) s += 15

        # 25 — TEN FILE CORE BI CHEN MOT KY TU. `wp-sett1ings.php`
        # `wp-blog-head1er.php` `wp-tr1ackback.php` `wp-cro1n.php`. Ban sao file
        # core truoc khi SUA file that, hoac dau vet mot lan don dep khong hoan
        # chinh — thay tren 186-126, 4 site, kich thuoc KHOP CHINH XAC file core
        # (wp-settings 16.246, wp-login 37.804, wp-signup 30.091).
        #
        # BAN DAU LA MOT REGEX, VA SO LIEU BAC NGAY. `^(wp-)?[a-z-]*[0-9][a-z-]+`
        # cho **4.101 file** tren 186-126 (do 24-09) — no khong kiem "giong ten
        # core", no chi kiem "co chu so o giua ten". `md5.php` `base64.php`
        # `h5ai.php` `file2html.php` `bootstrap4.php` deu khop. Toi mo ta dung bat
        # bien trong commit message ("sai dung mot ky tu so voi ten core") roi
        # KHONG viet dieu do ra trong code.
        #
        # Phep dung la khoang cach xoa-mot-ky-tu toi tap `core0`: bo lan luot
        # tung ky tu cua ten, neu ra mot ten core thi khop. Thu tren 26 ten that:
        # 13/13 ten chen ky tu khop, 13/13 ten hop le khong khop.
        #
        # Cong cong nhan CMS: tren site khong phai WordPress thi moi ten deu
        # "gan giong core WordPress" mot cach vo nghia.
        # `corelike` TRU TOAN BO truc nay, khong ha bac. Do 24-09 tren 186-126:
        # 17/20 file >= 40 diem la ten cach core mot ky tu MA noi dung LA core —
        # `wp-m1ail.php` `wp-cro1n.php` `wp-sett1ings.php` `wp-activ1ate.php`...
        # tuc gan DU tap entry point core tang 0, tren DUNG 2 site, mtime
        # 2016-2017. Mot ke tan cong khong doi ten `wp-settings.php` (site chet
        # ngay); day la MOT cong cu quet da cach ly ca loat, tuc MOT su kien lich
        # su bat dong 9 nam — khong phai 17 phat hien.
        #
        # Tai sao 0 chu khong phai 20: `fim.sh` la may do THAY DOI. 17 file khong
        # doi tu 2017 nen chung khong thuoc pham vi no; giu o 20 thi chung hien
        # trong `score` mai mai va $CRITLOG co 85% nhieu co dinh — dung benh
        # "canh bao dung ma khong ai doc" da mac. Ba webshell that trong cung tap
        # (`filefuns.php` `wp-cron-vosi.php`) KHONG khop `del1_core`; chung dat 40
        # bang truc khac, nen bo truc nay khong bo sot gi da biet.
        #
        # RUI RO da nhan: ke tan cong dat webshell ten `wp-m1ail.php` CO them hai
        # chuoi core vao dau file thi duoc mien 25 diem nay. Chap nhan vi (a) 25
        # mot minh khong dat 40 nen day khong phai luat chan, (b) neu file do co
        # md5x3 hay nam trong uploads thi cac truc kia van cong du, (c) doi lai la
        # $CRITLOG doc duoc.
        #
        # Cai con nguy that — 17 ban core WP 4.x goi duoc qua HTTP, dung ngoai moi
        # lan update — thuoc tang URI (`waf/wordpress/paths.lua`), khong thuoc day:
        # rui ro nam o REQUEST toi chung, khong o viec file ton tai.
        if ((wproot(p) in iswp) && !(p in corelike)) {
            nm = del1_core(b)
            # Chen GIUA (vi tri xoa khong phai ky tu cuoi truoc `.php`) dang ngo
            # hon HAU TO CUOI: `wp-config1.php` `xmlrpc1.php` la ban sao luu
            # nguoi quan tri tu tao, co tren 3/4 may. Tach hai muc.
            if (nm == 2)      s += 25
            else if (nm == 1) s += 10
        }

        # 20 — TEN THU MUC PLUGIN CO HAU TO HEX NGAU NHIEN. `wp-helper-d698ed`
        # (28-246): sau ky tu hex sau dau gach, va ten file TRUNG ten thu muc.
        # Khong plugin hop le nao dat ten vay — hex ngau nhien la de tranh trung
        # khi TU CAI, dung khuon `easypost-1781527859-2818.php`.
        if (p ~ /\/wp-content\/plugins\/[a-z-]+-[0-9a-f]{6,}\//) s += 20

        # 15 — THU MUC CON LA o `wp-content/` tang 1. WordPress core tao dung
        # `plugins/ themes/ uploads/ upgrade/ languages/ cache/ mu-plugins/`;
        # `easypost/` la webshell that (24-09, ghi ra bang
        # file_put_contents(base64_decode(...)) tu mot plugin co header hop le).
        #
        # Trong so THAP vi truc nay NHIEU: 171-96 co >20 thu muc ten PLUGIN nam
        # sai cap (`contact-form-7` `woocommerce` `classic-editor` `duplicator`
        # `really-simple-ssl`) — giai nen hong hoac ban sao luu. O muc 15 chung
        # vo hai; con `easypost/easypost.php` thi cong voi "webroot" va nhung
        # truc khac.
        if (p ~ /\/wp-content\/[^\/]+\/[^\/]+\.php$/ \
            && p !~ /\/wp-content\/(plugins|themes|uploads|upgrade|upgrade-temp-backup|languages|mu-plugins)\// \
            && (wproot(p) in iswp)) s += 15

        # wp-includes/ + wp-admin/ — DA THU 15 DIEM, DA BO. Do 24-09 bang mode
        # `score` tren 1.357.213 file / 5 may: 183.908 file an diem nay, tuc
        # 13,5% TOAN BO tap. Moi file core WordPress cua moi site deu nam o do.
        #
        # Va van de KHONG phai do lon — ha xuong 5 thi 183.908 file an 5 diem,
        # van vo nghia, chi nho hon. Van de la tin hieu nay KHONG MANG THONG TIN:
        # no dung voi moi file core, tuc khong phan biet duoc gi. No chi noi "day
        # la site WordPress".
        #
        # `sev()` dung `wp-includes/` lam 2CRITICAL va do DUNG cho CHG — mot file
        # core bi SUA la dang ngo that. Nhung `pscore` tinh ca NEW, va o do no
        # thanh nhieu. Tin hieu dung phai la "file LA trong wp-includes/", khong
        # phai "file trong wp-includes/" — va do la tin hieu CHUA DO, nen khong
        # them.

        # 10 — ten ham ghep tu manh chuoi. TRUC DA BI BAC lam LUAT (22/23 file
        # la thu vien hop le: `less.php` compiler theme g5plus tren 8 site/3
        # may, `cs-framework/helpers.php` theme RT tren 2 site). Giu lai o day
        # DUNG DE chung minh co che: voi trong so 10 no vo hai, va neu mot file
        # co CA no VA md5x3 thi tong la 60 chu khong phai 10.
        if (p in fraghit) s += 10

        # 10 — CHG ma kich thuoc KHONG doi. `wp-cron-vosi.php` doi mtime 4 lan
        # trong 2 ngay, luon 1.659 byte — co cai gi dang `touch` no.
        if (t == "CHG" && (p in samesize)) s += 10

        # -20 — file trang thai da biet ($PREVCHG). Day la phep HA BAC cu, nhung
        # o dang CONG DIEM AM thay vi `return "5STATE"` chan het moi bat bien
        # khac. Nho vay webshell o webroot khong con bien mat khi no doi hai lan.
        if (t == "CHG" && (p in prev)) s -= 20

        return s
    }
    function basename(p,   i) {
        i = length(p)
        while (i > 1 && substr(p, i, 1) != "/") i--
        return substr(p, i + 1)
    }
    # Cat tai `/public_html` de lay webroot. KHONG dung `dirn()`: file o tang 0
    # thi dirname DA la webroot, nhung ham nay con duoc goi cho duong dan sau
    # nay neu them tin hieu khac, nen cat theo MOC co dinh thi dung ca hai ca.
    function wproot(p,   i) {
        i = index(p, "/public_html")
        if (i == 0) return ""
        return substr(p, 1, i + 11)
    }
    # Bo DUNG MOT ky tu khoi `b`; neu ra mot ten trong `core0` thi tra:
    #   2 = ky tu bi xoa nam GIUA ten (`wp-sett1ings.php`)
    #   1 = ky tu bi xoa nam ngay truoc `.php` (`wp-config1.php` — hau to cuoi)
    #   0 = khong khop
    # Thay cho mot regex tung cho 4.101 duong tinh gia — xem chu thich o
    # `pscore()`. O(n) voi n = do dai ten file, chi chay cho file tang 0 cua
    # webroot WordPress nen dan so rat nho.
    function del1_core(b,   L, j, cand, dot) {
        if (b in core0) return 0
        L = length(b)
        dot = L - 4          # vi tri ky tu cuoi truoc ".php"
        for (j = 1; j <= L; j++) {
            cand = substr(b, 1, j - 1) substr(b, j + 1)
            if (cand in core0) return (j == dot) ? 1 : 2
        }
        return 0
    }
    # Cat tien to so khi in. Tien to chi ton tai de `sort` cho ra dung thu tu
    # doc; nguoi doc bao cao khong can thay no.
    function lbl(s) { return substr(s, 2) }
    function dirn(p,   i) {
        i = length(p)
        while (i > 1 && substr(p, i, 1) != "/") i--
        return substr(p, 1, i - 1)
    }
    # Gom theo SLUG cua plugin/theme, khong theo thu muc chua file.
    # Mot ban cai/cap nhat goi la MOT giao dich nhung trai tren hang chuc thu muc
    # con (assets/, includes/, languages/…). Gom theo dirname se dem no thanh
    # hang chuc nhom nho, moi nhom duoi nguong, va the la ca goi bi liet ke tung
    # file nhu the tung file den mot minh — dung nguoc voi y do.
    function gkey(p) {
        if (match(p, /\/wp-content\/(plugins|themes)\/[^\/]+/))
            return substr(p, 1, RSTART + RLENGTH - 1)
        return dirn(p)
    }
    # Muc tin cay "file MOI = doc hai", theo vung va theo viec no den mot minh
    # hay den trong mot dot. Khong con nhi phan danh-dau/khong-danh-dau nua:
    # GROUP_MAX la nguong CONG KHAI, ke tan cong chi can tha 6 file la thoat sach.
    # Ha muc tin cay thi khong co nguong nao de vuot qua.
    function boost(p, bulk) {
        # >= 40 diem: 1.0 BAT KE `bulk`. Nguong gom nhom sinh ra de chong nhieu
        # tu cap nhat phan mem — ma o muc diem nay khong co cap nhat nao (do
        # 24-09: 2 file tren 1.357.213). Khong ha muc tin cay chi vi no den cung
        # luc voi file khac.
        if (pscore(p, "NEW") >= 40)                 return "1.0"
        if (p ~ /\/wp-content\/mu-plugins\//)       return bulk ? "0.75" : "1.0"
        if (p ~ /\/wp-content\/(plugins|themes)\//) return bulk ? "0.35" : "0.75"
        return bulk ? "0.5" : "1.0"
    }
    # File DAU TIEN la `$new_scan` (dinh dang `duong|kich thuoc|mtime`), chi de
    # thu bang `iswp`: webroot nao CO `wp-includes/version.php` tren dia. Do la
    # cong nhan CMS cho tin hieu "webroot tang 0 ten la" — khong doan theo ten
    # thu muc. Khong in gi o luot nay.
    NR == FNR {
        # `wp-settings.php` chu KHONG phai `wp-includes/version.php`:
        # `scan_hot` KHONG quet `wp-includes/` (chi webroot tang 1,
        # `wp-content/` tang 1, `mu-plugins/`), nen dung version.php se lam
        # `iswp` RONG o tier nong va tin hieu tat cam — dung loai hoi quy im
        # lang ma ca ban nay duoc viet ra de tranh. `wp-settings.php` nam o
        # webroot TANG 0, co o CA HAI tier, va WordPress khong chay duoc neu
        # thieu no.
        if ($1 ~ /\/public_html\/wp-settings\.php$/) iswp[wproot($1)] = 1
        next
    }
    {
        key = sev($2, $1) "\t" $1 "\t" gkey($2)
        n[key]++
        if (n[key] <= max) item[key] = item[key] $2 "\n"
        # Giu MOI duong dan dang danh dau, khong chi max cai dau — de END con
        # danh dau het.
        #
        # NEW o moi noi; CHG CHI o mu-plugins. Ly do khac nhau cho hai ve:
        # `CHG` o plugins/themes la cap nhat phan mem, danh dau se thanh nhieu
        # lien tuc. O mu-plugins thi khong co "cap nhat" — file o day khong doi.
        if (markfile != "" && ($1 == "NEW" || ($1 == "CHG" && $2 ~ /\/wp-content\/mu-plugins\//)))
            allnew[key] = allnew[key] $2 "\n"
    }
    END {
        for (k in n) {
            split(k, f, "\t")
            bulk = (n[k] > max)
            if (bulk)
                # Chu thich cua dong gom KHAC NHAU theo vung, va day khong phai
                # chuyen cau chu. "nhieu kha nang la cap nhat" dan tren mot dot
                # file vao mu-plugins la dan dung cau khien nguoi doc bo qua no:
                # o thu muc do khong co cap nhat phan mem nao, mot dot dong nghia
                # la NANG HON mot file le, khong phai nhe hon. Do la chinh hinh
                # dang vu 20-09 (13 file).
                {
                    note = "(nhieu kha nang la cap nhat)"
                    if (f[1] == "1MUPLUG")
                        note = "(MOT DOT — o day khong co cap nhat hop le)"
                    printf "%-8s %-3s %4d file trong %s  %s\n", \
                           lbl(f[1]), f[2], n[k], f[3], note
                }
            else {
                m = split(item[k], L, "\n")
                # `sc=` di o CUOI dong, khong phai dau. Hai cho phu thuoc vao
                # dinh dang nay: `sort` o cuoi pipeline (sap theo bac, phai giu
                # tien to o dau) va `crit=` doc bang grep neo dau dong
                # CRITICAL/HIGH — chen vao dau dong la hong ca hai.
                for (i = 1; i < m; i++)
                    printf "%-8s %-3s %s  sc=%d\n", \
                           lbl(f[1]), f[2], L[i], pscore(L[i], f[2])
            }
            if (markfile != "" && (k in allnew)) {
                m = split(allnew[k], L, "\n")
                for (i = 1; i < m; i++)
                    printf "%s|%s\n", boost(L[i], bulk), L[i] > markfile
            }
        }
    }' "$new_scan" "$diff_out" | sort)

# Chi dem cac dong DUOC LIET KE TUNG FILE. Dong tom tat cua mot nhom dong la cap
# nhat phan mem — bao dong o do la bien script thanh thu khong ai doc nua.
#
# `MUPLUG` la NGOAI LE cua cau tren: no dem CA dong gom nhom. Mot dot 6 file la
# vao mu-plugins KHONG phai "nhieu kha nang la cap nhat" — do la chinh hinh dang
# cua vu 20-09 (13 file tren mot site). Nguong gom nhom sinh ra de chong nhieu
# tu cap nhat phan mem, ma o thu muc nay thi khong co cap nhat phan mem nao.
crit=$(printf '%s\n' "$report" | grep -E '^(CRITICAL|HIGH) ' | grep -vc 'cap nhat')
muplug=$(printf '%s\n' "$report" | grep -c '^MUPLUG ' || :)
# `SCORE` la NGOAI LE cung ly do nhu `MUPLUG`, va phai dem RIENG: `crit=` o tren
# chi neo `CRITICAL|HIGH`, nen mot dong `SCORE` khong khop cai nao — in ra roi
# `crit=0`, khong mail, `exit 0`. Dung cai lo vua sua 23-09 (ton dong mu-plugins
# tra exit=0), lap lai o nhanh moi. Bac nay la >= 40 diem, tuc 2 file tren
# 1.357.213 do duoc: neu no khong dem thi khong co gi dang dem.
score_n=$(printf '%s\n' "$report" | grep -c '^SCORE ' || :)
crit=$((crit + score_n))
crit=$((crit + muplug))

# ── Day danh dau sang Redis cho WAF ───────────────────────────────────
# Bo qua o --dry: --dry nghia la "xem thu", ma ghi Redis la tac dong that.
marked=0; mark_err=""
if [ $dry -eq 0 ] && [ -s "$marks" ]; then
  if ! command -v "$REDIS_CLI" >/dev/null 2>&1; then
    # KHONG chet: FIM van phat hien va van bao. Chi la WAF khong duoc bao tin.
    mark_err="thieu '$REDIS_CLI' — phat hien van chay, nhung WAF khong nhan duoc tin hieu."
  else
    # KHOA LA CHINH DUONG DAN FILE, khong phai <host>:<uri>.
    #
    # Ban dau toi dinh tach host + uri roi ghi them bien the `www.`. Sai o hai
    # cho, va `da_to_openresty.sh:271` chi ra vi sao:
    #     webroot="/home/<user>/domains/<parent>/public_html/<sub_name>"
    # SUBDOMAIN co document_root la mot THU MUC CON cua public_html. Nen
    # <public_html>:<uri-tinh-tu-public_html> khong bao gio khop voi cai WAF
    # nhin thay, va domain pointer/alias thi phai liet ke ra moi phu duoc.
    #
    # `document_root .. uri` LUON bang dung duong dan that tren dia — cho domain
    # chinh, subdomain, lan WordPress cai trong thu muc con. FIM biet duong dan
    # do truc tiep; WAF ghep lai tu hai bien no da co san. Khong phan tich chuoi
    # o dau ca, va pointer/alias tu dung vi chung dung chung docroot.
    #
    # Gioi han da biet, dong nhat voi `target_exists`: PATH_INFO (`/shell.php/x`)
    # ghep ra mot duong dan khong ton tai nen tra miss.
    cmds=$(awk -v ttl="$MARK_TTL" '
        {
            i = index($0, "|");  if (i == 0) { bad++; next }
            b = substr($0, 1, i - 1)
            p = substr($0, i + 1)
            # Key di qua STDIN cua redis-cli, noi khoang trang la ranh gioi doi
            # so va dau nhay la cu phap. Mot duong dan chua chung se thanh mot
            # LENH KHAC. Loc trang, va dem so bi bo de khong mat lang le.
            if (p !~ /^[A-Za-z0-9._~:@!$&()*+,;=%\/-]+$/) { bad++; next }
            printf "SETEX waf:fimnew:%s %d %s\n", p, ttl, b
        }
        END { if (bad) printf "  [fim] %d duong dan KHONG danh dau duoc (ky tu khong an toan cho key Redis)\n", bad > "/dev/stderr" }
    ' "$marks" 2>>"$LOG")

    if [ -n "$cmds" ]; then
        marked=$(printf '%s\n' "$cmds" | wc -l)
        printf '%s\n' "$cmds" | "$REDIS_CLI" -n "$REDIS_DB" >/dev/null 2>>"$LOG"
        # XAC MINH VONG TRON. Doc nguoc mot key vua ghi. Lech db giua redis-cli
        # va core/config.lua, sai host, Redis chet — het thay deu lo ra o day
        # thay vi de FIM ghi mot noi va WAF doc mot noi, mai mai khong khop ma
        # khong ai bao loi.
        # So voi GIA TRI DA GHI, khong phai hang so "1".
        #
        # Cho nay tung dung: ban a253016 ghi `... %d 1` nen `!= "1"` la phep so
        # sanh chinh xac. Ban nay (boost theo bac) ghi 1.0 / 0.75 / 0.35 / 0.5 —
        # nen so voi "1" thi KHONG BAO GIO khop, va vong xac minh bao hong o MOI
        # lan chay du Redis hoan toan khoe. Mot canh bao luon sang la mot canh bao
        # day nguoi van hanh bo qua no, dung luc no can duoc tin.
        # Dong `SETEX <key> <ttl> <boost>`: $2 = key, $4 = gia tri.
        probe=$(printf '%s\n' "$cmds" | head -1 | awk '{print $2}')
        want=$(printf  '%s\n' "$cmds" | head -1 | awk '{print $4}')
        if [ "$("$REDIS_CLI" -n "$REDIS_DB" GET "$probe" 2>/dev/null)" != "$want" ]; then
            mark_err="KHONG XAC MINH DUOC: da ghi $marked key nhung doc nguoc that bai."
            mark_err="$mark_err Kiem FIM_REDIS_DB=$REDIS_DB co khop _M.redis.db trong core/config.lua khong."
        fi
    fi
  fi
fi

header="=== FIM $(date '+%Y-%m-%d %H:%M') [$tier] — $total thay doi, $crit dang chu y, $marked key bao WAF ==="
[ -n "$mark_err" ] && header="$header
!! $mark_err"

# LOG luon nhan day du, ke ca ROUTINE: khi dieu tra mot vu thi lich su cap nhat
# plugin lai la thu can doi chieu.
{ echo "$header"; printf '%s\n' "$report"; } >> "$LOG"

# ── Duong bao thu hai: file rieng cho trang admin ─────────────────────
#
# VI SAO CAN DUONG THU HAI, va day la bai hoc dat nhat cua vu 20-09:
# `fim.sh` DA phat hien va DA bao. `ea_f9543a7c.php` la NEW trong mu-plugins,
# CRITICAL, den mot minh — dung nhanh `crit > 0` nen da in ra stdout va cron da
# gui mail. Co che chay du. No hong o cho mail cron tren shared hosting gan nhu
# luon la mot ho den: 13 lan bao trong hai thang, khong ai mo.
#
# Nen day KHONG phai "them mot canh bao nua". Do la doi NOI canh bao di toi, ve
# mot cho co the mo bang trinh duyet (`admin/init.lua` route /antibot-admin/fim).
#
# CHI ghi MUPLUG va CRITICAL. Khong ROUTINE. File nay phai DOC HET TRONG 10
# GIAY — dai ra thi no thanh ho den thu hai, va luc do ta da tra gia hai lan
# cho cung mot bai hoc.
#
# `cap nhat` (dong gom nhom) bi loai o CRITICAL nhung KHONG o MUPLUG — cung
# ngoai le da ghi o `crit` ben tren, va bo sot no thi chinh ca that bi loc ra:
# 13 file cua vu 20-09 vuot GROUP_MAX=5 nen thanh mot dong gom, va mot `grep -v`
# dat nham cho se bo dung no khoi file nay.
# $CRITLOG dinh nghia o dong 48, khong lap lai o day: nguong ton dong
# mu-plugins ghi vao no truoc diem nay.
critlines=$(printf '%s\n' "$report" \
    | grep -E '^(MUPLUG|CRITICAL) ' \
    | grep -vE '^CRITICAL .*cap nhat' || :)
if [ -n "$critlines" ]; then
    {
        echo "=== $(date '+%Y-%m-%d %H:%M') [$tier] ==="
        printf '%s\n' "$critlines"
        # LEO THANG. 13 file trong hai thang da sinh ra 13 lan bao GIONG HET
        # nhau. Dong nay noi dung thu ma lan bao truoc khong noi duoc: NO VAN
        # CON DO. Dem TRANG THAI HIEN TAI, khong phai thay doi cua lan nay —
        # hai con so khac nhau va con dang bao dong la con thu nhat.
        #
        # Dem tu `$new_scan`, KHONG tu `$MANIFEST`: manifest chi duoc `cp` o
        # cuoi script nen o day no con la anh chup CU. Phep thu tai cho da bat
        # dung loi nay — bao "tong cong 1 file" ngay sau khi 6 webshell xuat
        # hien, tuc con so leo thang noi nguoc voi dong ngay tren no.
        mu_now=$(grep -c '/wp-content/mu-plugins/' "$new_scan" 2>/dev/null || :)
        [ "${mu_now:-0}" -gt 0 ] && \
            echo "  [trang thai] tong cong $mu_now file .php trong mu-plugins tren toan may"
    } >> "$CRITLOG"
    # 0640 root:nginx — KHAC 0600 cua $LOG va $MANIFEST, va co ly do.
    #
    # File nay TON TAI de `admin/init.lua` doc, ma OpenResty worker chay user
    # `nginx` (nginx.conf:19). Voi 0600 root thi endpoint /antibot-admin/fim tra
    # `Permission denied` — da gap that 20-09 ngay sau khi deploy.
    #
    # KHONG noi thanh 0644. Khac biet voi $MANIFEST la o NOI DUNG: manifest la
    # danh muc day du duong dan file cua MOI khach tren may (13.636 dong), con
    # file nay chi co dong CRITICAL/MUPLUG. Nhung "it hon" khong phai "duoc phep
    # doc boi moi khach" — PHP cua bat ky khach nao doc duoc 0644, va mot dong
    # MUPLUG van chi ra duong dan tuyet doi cua site khac.
    #
    # `chgrp` co the that bai (khong co group `nginx`, hoac OS khac): `|| :` de
    # khong lam chet ca lan quet, va `chmod` chay sau de it nhat khong noi rong
    # hon 0640. Neu chgrp truot thi endpoint van bao `exists:false` — tuc bao ra,
    # khong im lang.
    chgrp nginx "$CRITLOG" 2>/dev/null || :
    chmod 0640 "$CRITLOG" 2>/dev/null || :

    # CAT VONG TAI CHO, khong giao cho logrotate. File nay chi co gia tri neu
    # DOC HET DUOC TRONG 10 GIAY; de no phinh la bien no thanh ho den thu hai,
    # dung cai ma no vua duoc sinh ra de thay the. Giu 400 dong cuoi.
    #
    # Khong dung logrotate vi mot file phu thuoc cau hinh ngoai la mot file se
    # dung tren may nay va khong dung tren may sau.
    if [ "$(wc -l < "$CRITLOG" 2>/dev/null || echo 0)" -gt 400 ]; then
        tail -n 400 "$CRITLOG" > "$CRITLOG.tmp" 2>/dev/null &&
            mv "$CRITLOG.tmp" "$CRITLOG" || rm -f "$CRITLOG.tmp"
    fi
fi

# stdout — tuc mail cua cron — CHI khi co gi dang chu y. Cap nhat plugin dinh ky
# ma cung gui mail thi vai tuan nua khong ai mo mail cua no nua.
if [ "$crit" -gt 0 ] || [ -n "$mark_err" ] || [ $verbose -eq 1 ]; then
    echo "$header"
    printf '%s\n' "$report"
fi

if [ $dry -eq 0 ]; then
    cp "$new_scan" "$MANIFEST"
    awk -F'|' '$1 == "CHG" { print $2 }' "$diff_out" > "$PREVCHG"
fi

[ "$crit" -gt 0 ] && exit 1
# Cung ly do nhu nhanh `total -eq 0` o tren: ton dong mu-plugins la su co ke ca
# khi dot nay khong co file nao dang bao. Khong co dong nay thi mot ban cap nhat
# plugin binh thuong (crit=0) se che mat 5 site dang nhiem.
[ "$mu_pending" -eq 1 ] && exit 3
exit 0
