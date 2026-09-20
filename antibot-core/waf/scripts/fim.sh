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
# Ma thoat: 0 = khong co gi dang chu y   1 = co phat hien CRITICAL/HIGH
#           2 = khong chay duoc
set -uo pipefail

# Ba bien cho phep ghi de bang moi truong CHI de chay thu tren cay gia. Mac dinh
# la duong that; khong co cai nay thi script nay khong the kiem duoc o dau ngoai
# production, va hom nay da hai lan phai giao ma chua chay.
ROOTS="${FIM_ROOTS:-/home/*/domains/*/public_html}"
STATE="${FIM_STATE:-/var/lib/antibot/fim}"
LOG="${FIM_LOG:-/var/log/antibot/fim.log}"
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
# `waf/scripts/wp_paths_test.lua` ghim dieu nay; `fim.sh` con tu doc nguoc mot
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

# `audit` khong nhan co nao: no khong co tier (chi soi mu-plugins), khong ghi gi
# nen `--dry` vo nghia, va luon in day du nen `-v` cung vay.
usage() { echo "dung: $0 {baseline|check|audit} [--hot] [--dry] [-v]" >&2; exit 2; }

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
# Chi soi `mu-plugins/`, co y. Do 20-09 tren dan may: 16/18 site co DUNG MOT
# file o day, khong doi tu thang 2 — nen mot danh sach day du van DOC DUOC bang
# mat. `plugins/` co hang nghin file hop le nen liet ke tron la vo dung; do la
# viec cua `check`.
#
# KHONG doc/ghi manifest, KHONG ghi Redis, KHONG ghi $CRITLOG: `audit` la mot
# phep DOC. Chay no bao nhieu lan cung khong doi trang thai gi — nen no an toan
# de chay giua luc dieu tra, khac `baseline` (quyet dinh bao mat).
if [ "$mode" = "audit" ]; then
    printf '%-6s %-9s %s\n' 'SO' 'KICH CO' 'DUONG DAN'
    n=0
    # KHONG them `sort`: bash bung glob `$ROOTS` theo thu tu da sap xep nen cac
    # file cung mot site von da lien nhau, va "site nao co bao nhieu file" — hinh
    # dang cua mot vu xam nhap — doc duoc ngay. Da kiem bang phep thu chu khong
    # gia dinh; mot `sort` them vao day chi la lop khong lam gi.
    while IFS='|' read -r p s _t; do
        [ -n "$p" ] || continue
        n=$((n + 1))
        printf '%-6s %-9s %s\n' "$n" "$s" "$p"
    done <<EOF
$(find $ROOTS/wp-content/mu-plugins   "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' 2>/dev/null || :
  find $ROOTS/*/wp-content/mu-plugins "${NAMES[@]}" -type f -printf '%p|%s|%T@\n' 2>/dev/null || :)
EOF
    echo
    echo "tong: $n file co the chay duoc trong mu-plugins"
    # DOC SO NAY THE NAO — ghi ra day vi con so tran khong tu noi gi. Do 20-09:
    # site sach co DUNG MOT file (cua SEO agency, ~7.316 byte, xem
    # memory/project_muplugins_agency_file.md). Site nhiem co 8 va 14.
    echo "de doc: mot site LANH thuong co 0-1 file. Nhieu hon la dang xem tung file."
    echo "        audit KHONG phan biet duoc lanh/doc — no chi liet ke."
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
        echo "quet ra 0 file — khong ghi manifest. Kiem FIM_ROOTS=$ROOTS" >&2
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
trap 'rm -f "$new_scan" "$diff_out"' EXIT

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
    echo "quet ra 0 file trong khi manifest co $(wc -l < "$MANIFEST") — coi la" >&2
    echo "LOI QUET, khong phai xoa hang loat. Manifest giu nguyen." >&2
    echo "Kiem FIM_ROOTS=$ROOTS va quyen doc cua user dang chay." >&2
    exit 2
fi

# Mot luot awk: NEW (duong dan chua tung thay), CHG (kich thuoc hoac mtime doi),
# DEL (bien mat). So sanh theo DUONG DAN chu khong theo dong, nen mot file doi
# noi dung ra dung mot dong CHG chu khong phai mot NEW cong mot DEL.
awk -F'|' '
    NR==FNR { old[$1] = $2 "|" $3; next }
    {
        if (!($1 in old))              print "NEW|" $1
        else if (old[$1] != $2 "|" $3) print "CHG|" $1
        seen[$1] = 1
    }
    END { for (p in old) if (!(p in seen)) print "DEL|" p }
' "$MANIFEST" "$new_scan" > "$diff_out"

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
#   1MUPLUG < 2CRITICAL < 3HIGH < 4ROUTINE < 5STATE
#
# TIEN TO SO la BAT BUOC, khong phai trang tri. Ban truoc dua vao thu tu chu
# cai va no DUNG chi vi tinh co: C < H < R < S. Them `MUPLUG` la lo ra ngay —
# `sort` xep M vao GIUA (C, H, M, R, S), tuc bac nang nhat nam thu ba trong
# bao cao. Da kiem bang `printf ... | sort` chu khong suy luan.
# Tien to bi cat khi in (xem `lbl()`), nen nguoi doc khong thay no.
# (STATE = file trang thai, xem $PREVCHG.)
marks=$(mktemp) || exit 2
trap 'rm -f "$new_scan" "$diff_out" "$marks"' EXIT

report=$(awk -F'|' -v max="$GROUP_MAX" -v markfile="$marks" -v prevfile="$PREVCHG" '
    BEGIN {
        # `getline < file` tra -1 khi file khong ton tai — KHONG phai loi, nen
        # lan chay dau tien (chua co prevchg) di thang qua day.
        if (prevfile != "")
            while ((getline _pl < prevfile) > 0) prev[_pl] = 1
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
        if (p ~ /\/wp-content\/mu-plugins\//)       return bulk ? "0.75" : "1.0"
        if (p ~ /\/wp-content\/(plugins|themes)\//) return bulk ? "0.35" : "0.75"
        return bulk ? "0.5" : "1.0"
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
                for (i = 1; i < m; i++) printf "%-8s %-3s %s\n", lbl(f[1]), f[2], L[i]
            }
            if (markfile != "" && (k in allnew)) {
                m = split(allnew[k], L, "\n")
                for (i = 1; i < m; i++)
                    printf "%s|%s\n", boost(L[i], bulk), L[i] > markfile
            }
        }
    }' "$diff_out" | sort)

# Chi dem cac dong DUOC LIET KE TUNG FILE. Dong tom tat cua mot nhom dong la cap
# nhat phan mem — bao dong o do la bien script thanh thu khong ai doc nua.
#
# `MUPLUG` la NGOAI LE cua cau tren: no dem CA dong gom nhom. Mot dot 6 file la
# vao mu-plugins KHONG phai "nhieu kha nang la cap nhat" — do la chinh hinh dang
# cua vu 20-09 (13 file tren mot site). Nguong gom nhom sinh ra de chong nhieu
# tu cap nhat phan mem, ma o thu muc nay thi khong co cap nhat phan mem nao.
crit=$(printf '%s\n' "$report" | grep -E '^(CRITICAL|HIGH) ' | grep -vc 'cap nhat')
muplug=$(printf '%s\n' "$report" | grep -c '^MUPLUG ' || :)
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
CRITLOG="${FIM_CRITLOG:-/var/log/antibot/fim_critical.log}"
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
exit 0
