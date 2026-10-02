# Parser `.htaccess` — MOT hien thuc duy nhat, dung boi `fim.sh` VA
# `htaccess_fixture_test.sh`.
#
# VI SAO LA MOT TEP RIENG: truoc day khoi awk nay nam trong `fim.sh`, va bo test
# phai TRICH no ra bang moc comment. Mot phep trich la mot cho de lech — da hong
# mot lan (mat dong dau + dau dong cua khoi). Nay ca hai ben `-f` cung tep.
#
# HOP DONG, cung cau hoi ma `upload_content.lua` tra loi: dong nay co lam mot duoi
# thanh THUC THI DUOC khong? In ra, mot token moi dong:
#   <duoi>     duoi cu the tu `AddType`/`AddHandler`
#   @all       handler ap CA thu muc: `SetHandler`/`ForceType`
#   @execcgi   `Options +ExecCGI` — CHI cap quyen chay CGI trong thu muc, KHONG noi
#              tep nao la CGI. Con phai co `AddHandler`/`SetHandler` xac dinh dieu
#              do. HAI buoc RIENG theo tai lieu Apache, nen gop vao `@all` la bao
#              MANH HON su that (nguoi dung bat 28-09).
# `@execcgi` chi co nghia khi WEBSERVER cho `.htaccess` dat `ExecCGI`. Do KHONG phai
# tinh chat cua tep — do la `AllowOverride` cua `<Directory>` phu no, va tren
# DirectAdmin no la mot WHITELIST:
#
#   AllowOverride AuthConfig FileInfo Indexes Limit \
#     Options=Indexes,IncludesNOEXEC,MultiViews,SymLinksIfOwnerMatch,FollowSymLinks,None
#
# `ExecCGI` KHONG co trong danh sach do, nen `Options +ExecCGI` trong `.htaccess` cua
# khach khong cap duoc gi — con `Options All` thi lam Apache tra 500 (do duoc 30-09:
# thu muc co `Options All -Indexes` tra `http=500`, goc site 200). Tuc mot dau
# `@execcgi` tren fleet nay la SO LIEU RAC, va neu luat duoc promote thi la FP.
#
# `FileInfo` THI CO, nen `AddHandler`/`SetHandler`/`ForceType` duoc doc binh thuong
# (do duoc: hai site co `AddHandler` o goc tra 200 va 301, khong 500). Nen `ext:` va
# `@all` la tin hieu THAT va khong bi anh huong o day.
#
# DO chu khong HARDCODE: `AllowOverride` khac nhau theo may va theo `<Directory>`, nen
# `fim.sh` do no tu cau hinh Apache THAT roi truyen vao. `execcgi_ok` mac dinh la 1
# (giu nguyen hanh vi cu) — mot bo test hay mot may khong do duoc thi khong mat tin
# hieu, chi mat phep ha bac.
#
#   execcgi_ok=1  ->  `@execcgi`      nhu cu
#   execcgi_ok=0  ->  `@execcgi:noop` webserver KHONG cho, ghi lai de con dem duoc
#
# Ghi `:noop` chu khong im lang: neu mai `AllowOverride` doi thi so dong nay cho biet
# co bao nhieu thu muc se BAT tin hieu tro lai, va do la con so can de quyet.
#
# Khong in gi = khong co gi nguy hiem.
#
# BAT BIEN doc tu tai lieu Apache:
#   · ten directive VA ten container KHONG phan biet hoa thuong
#   · noi dong bang gach nguoc cuoi dong
#   · `AddType`/`AddHandler`: token DAU la mime/handler, cac token sau la duoi
#   · `SetHandler`/`ForceType`: token DAU, KHONG mang duoi
#   · `Options`: cac token `+x`/`-x` xu ly TUAN TU; `All` gom ExecCGI
#   · `<FilesMatch>`/`<Files>`/`<Location>`/`<Directory>`/`<If>` GIOI HAN pham vi
#     theo tep/duong dan -> ben trong KHONG nang thanh `@all`
#   · `<IfModule>` KHONG gioi han pham vi theo tep -> dem RIENG, khong dung
#     `depth`. Ban truoc tang `ifdepth` nhung `</IfModule>` lai GIAM `depth`, nen
#     mot `<FilesMatch>` long `<IfModule>` bi THOAT SCOPE SOM (da tai hien duoc).

# Tach dong thanh token, TON TRONG dau nhay: trong dau nhay thi khoang trang KHONG
# phai ranh gioi. `split()` khong lam duoc viec nay, va do la ly do
# `AddHandler "application/x-httpd-php extra" .php` tung cho ra `extra"` — mot token
# RAC co the trung mot duoi that. Fixture khi do BAO XANH vi no chi so mot BIT
# co/khong, chu khong so tung token.
#
# Tra so token, dien vao TOK[1..n]. Dau nhay bao quanh bi BO.
function tokenize(s, TOK,   n, i, c, q, cur, inw) {
    n = 0; q = ""; cur = ""; inw = 0
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q != "") {
            if (c == q) { q = "" } else { cur = cur c }
            inw = 1
            continue
        }
        if (c == "\"" || c == "'") { q = c; inw = 1; continue }
        if (c == " " || c == "\t") {
            if (inw) { TOK[++n] = cur; cur = ""; inw = 0 }
            continue
        }
        cur = cur c; inw = 1
    }
    if (inw) TOK[++n] = cur
    return n
}

# `\r` bi bo CUNG CHO voi space/tab, khong phai mot buoc rieng: mot tep `.htaccess`
# sua tu Windows (hoac upload tu Windows) dung CRLF, va khi do token cuoi dong mang
# mot `\r` o duoi — `Options +ExecCGI\r\n` cho token `+execcgi\r` khong khop
# `+execcgi` nen BO SOT (tai hien duoc 29-09, trong WSL; `awk` cua Git Bash xu ly
# khac nen phai do o noi ma THAT chay).
#
# Bo o `trim` chu khong o `tokenize`: `trim` chay tren CA dong TRUOC khi tach token,
# nen mot cho sua dong ca duong. Neu bo trong `tokenize` thi phep noi dong
# (`line ~ /\$/`) van thay `\` cach `\r` va khong ghep duoc.
function trim(s) { sub(/^[ \t\r]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }

# Bo chu thich `#`, NHUNG khong bo `#` nam trong dau nhay: mot gia tri handler co
# the chua `#` (vi du duong socket). Apache khong co chu thich giua dong cho mot
# gia tri da nhay.
function strip_comment(s,   out, i, c, q) {
    out = ""; q = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == q) q = ""; out = out c; continue }
        if (c == "\"" || c == "'") { q = c; out = out c; continue }
        if (c == "#") break
        out = out c
    }
    return out
}

# BA trang thai cho moi truc "ca thu muc": -1 CHUA NOI GI, 0 TAT tuong minh, 1 BAT.
# `-1` khong phai gia tri mac dinh cua awk (awk cho "" / 0), nen phai dat tuong minh —
# va do la ly do `@execcgi` tung KHONG BAO GIO in: `opt[depth]` voi `depth` chua khoi
# tao ghi vao `opt[""]` trong khi `END` doc `opt[0]`, va awk danh chi muc bang CHUOI
# nen `"" != "0"`.
BEGIN { depth = 0; ifdepth = 0; sh = -1; ft = -1; opt[0] = -1
        if (execcgi_ok == "") execcgi_ok = 1 }

{
    line = $0
    # Noi dong: gach nguoc cuoi dong -> ghep voi dong sau.
    #
    # HAI gach nguoc, va day la so DO DUOC chu khong suy luan: thu ca bon dang tren
    # mot tep co gach nguoc cuoi dong that, chi `/\\$/` ghep duoc hai dong (1, 3, 4
    # deu khong). Mot ban truoc cua tep nay chi co MOT — heredoc cua cong cu dev gop
    # hai gach nguoc thanh mot — nen phep noi dong CHUA BAO GIO chay, va bo test van
    # xanh vi fixture khi do cung khong sinh dung byte. HAI loi che nhau.
    while (line ~ /\\$/) {
        sub(/\\$/, " ", line)
        if ((getline nxt) <= 0) break
        line = line trim(nxt)
    }
    line = trim(strip_comment(line))
    if (line == "") next

    low = tolower(line)

    # `<IfModule>` dem RIENG: no la dieu kien theo module, khong gioi han pham vi
    # theo tep, nen directive ben trong VAN ap cho ca thu muc.
    if (low ~ /^<[ \t]*ifmodule/)          { ifdepth++; next }
    if (low ~ /^<[ \t]*\/[ \t]*ifmodule/)  { if (ifdepth > 0) ifdepth--; next }

    # Container GIOI HAN pham vi theo tep/duong dan. HOA THUONG KHONG phan biet:
    # ban truoc dung regex phan biet hoa thuong nen `<filesmatch>` viet thuong KHONG
    # duoc tinh la container, va `SetHandler` ben trong bi nang thanh `@all` (da tai
    # hien duoc).
    if (low ~ /^<[ \t]*\/[ \t]*(filesmatch|files|location|locationmatch|directory|directorymatch|if)/) {
        if (depth > 0) depth--
        next
    }
    if (low ~ /^<[ \t]*(filesmatch|files|location|locationmatch|directory|directorymatch|if)[ \t>]/) {
        depth++; next
    }

    nf = tokenize(line, TOK)
    if (nf < 2) next
    d = tolower(TOK[1])
    # `tokenize` da BO dau nhay, nen khong con `gsub` tay va khong con token rac.
    v = TOK[2]

    # HAI TRUC DOC LAP: `AddHandler`/`RemoveHandler` dat HANDLER, `AddType`/`RemoveType`
    # dat MEDIA TYPE. Apache (mod_mime) phan biet ro hai truc nay, va gop chung vao mot
    # bit sinh ra hai loi NGUOC NHAU (nguoi dung bat 01-10):
    #
    #   FALSE NEGATIVE:  cha `AddHandler ... .jpg` + con `RemoveType .jpg`
    #                    -> `RemoveType` KHONG xoa handler, Apache VAN chay `.jpg`,
    #                       nhung parser cu xoa ca `ext:jpg`.
    #   FALSE POSITIVE:  cha `AddHandler ... .jpg` + con `AddHandler default-handler .jpg`
    #                    -> Apache ghi de bang handler LANH, nhung parser cu bo qua dong
    #                       khong chua `php|cgi` nen van giu `ext:jpg`.
    #
    # Nen giu TRANG THAI THEO TRUC: `h` cho handler, `t` cho type. Ben doc (hoac
    # `dir_tokens_inherited`) merge tung truc roi mon quy ve `ext:`/`rm:`.
    #
    # `AddHandler <bat ky> .jpg` o con GHI DE handler cua cha — ke ca handler lanh. Nen
    # dong khong chua `php|cgi` KHONG duoc bo qua: no dat `h[e] = 0`.
    # `AddHandler` LA MOT PHAT BIEU TUONG MINH ve truc handler cua duoi do — ke ca khi
    # handler LANH. Do la chenh lech voi `AddType`, va no co ly do trong tai lieu
    # Apache: `AddHandler` DAT handler, nen `AddHandler default-handler .jpg` noi
    # "duoi .jpg dung handler mac dinh" va dieu do GHI DE moi handler ke thua.
    #
    # Ban truoc chi dat `neg` khi CHINH TEP NAY da bat `.jpg` o dong truoc, nen mot tep
    # con chi co mot dong `AddHandler default-handler .jpg` phat `[]` — khong noi gi —
    # va handler PHP cua cha thang. Do la ca2 cua review: FP.
    #
    # `AddType` thi KHAC va giu nguyen hanh vi cu: `AddType text/css .css` chi khai bao
    # content type cho mot duoi lanh, no khong phu dinh gi (bo test bat 8 ca khi toi dat
    # `neg` o day). Mot `AddType` lanh chi la phu dinh khi no GHI DE mot type da bat
    # trong CUNG pham vi.
    #
    # `hneg`/`tneg` RIENG, khong con mot `neg` dung chung: mot `RemoveType .jpg` khong
    # duoc lam truc HANDLER phat `h-:jpg`. Dung chung bang la chinh cho gop hai truc
    # ma `END` vua duoc tach ra khoi.
    if (d == "addhandler") {
        dang = (tolower(v) ~ /php|cgi|proxy:unix:|proxy:fcgi:/) ? 1 : 0
        for (i = 3; i <= nf; i++) {
            e = TOK[i]; sub(/^\./, "", e)
            if (e != "") {
                ee = tolower(e)
                h[ee] = dang
                if (dang == 0) hneg[ee] = 1
            }
        }
        next
    }
    if (d == "addtype") {
        dang = (tolower(v) ~ /php|cgi|proxy:unix:|proxy:fcgi:/) ? 1 : 0
        for (i = 3; i <= nf; i++) {
            e = TOK[i]; sub(/^\./, "", e)
            if (e != "") {
                ee = tolower(e)
                if (dang == 0 && (ee in t) && t[ee]) tneg[ee] = 1
                t[ee] = dang
            }
        }
        next
    }
    # `RemoveHandler` chi xoa truc HANDLER; `RemoveType` chi xoa truc TYPE. Doi so la
    # DANH SACH DUOI tu token thu HAI (khong co mime/handler o dau).
    if (d == "removehandler") {
        for (i = 2; i <= nf; i++) { e = TOK[i]; sub(/^\./, "", e); if (e != "") { h[tolower(e)] = 0; hneg[tolower(e)] = 1 } }
        next
    }
    if (d == "removetype") {
        for (i = 2; i <= nf; i++) { e = TOK[i]; sub(/^\./, "", e); if (e != "") { t[tolower(e)] = 0; tneg[tolower(e)] = 1 } }
        next
    }

    # `SetHandler` / `ForceType`: HAI TRUC RIENG, va moi truc co BA trang thai.
    #
    # Ban truoc `next` ngay khi gia tri lanh:
    #     if (tolower(v) !~ /php|cgi|.../) next
    # nen `SetHandler none` o con IM LANG HOAN TOAN — no khong rut lai `@all` ma cha
    # da dat, du `none` la cu phap chinh thuc de HUY handler (nguoi dung bat 01-10).
    # Cung the voi `ForceType text/plain` sau mot `ForceType application/x-httpd-php`.
    #
    # BA trang thai, khong hai: "khong co phat bieu" KHAC "phat bieu TAT". Mot thu muc
    # khong noi gi thi thua huong cha; mot thu muc noi `none` thi RUT LAI cua cha. Ban
    # truoc nhap hai thu do lam mot (khong in gi) nen mat chieu rut.
    #   sh = -1 chua noi gi | 0 TAT tuong minh | 1 BAT
    if (d == "sethandler") {
        if (depth == 0) sh = (tolower(v) ~ /php|cgi|proxy:unix:|proxy:fcgi:/) ? 1 : 0
        next
    }
    if (d == "forcetype") {
        if (depth == 0) ft = (tolower(v) ~ /php|cgi|proxy:unix:|proxy:fcgi:/) ? 1 : 0
        next
    }

    # `Options`: TRANG THAI THEO PHAM VI, khong phai mot trang thai duy nhat.
    #
    # Apache xu ly tuan tu va dong SAU ghi de dong TRUOC — NHUNG chi trong CUNG mot
    # pham vi. Mot `Options -ExecCGI` trong `<FilesMatch>` chi ap cho tap tep hep do,
    # KHONG rut lai quyen da cap cho ca thu muc. Ban truoc dung MOT cap
    # (`execcgi_on`, `execcgi_depth`), nen
    #     Options +ExecCGI
    #     <FilesMatch "x">
    #       Options -ExecCGI
    #     </FilesMatch>
    # cho [] — BO SOT mot thu muc that su chay CGI duoc (nguoi dung bat 30-09).
    #
    # Nay giu mot trang thai cho TUNG `depth`, va chi doc `depth 0` o `END`. Cau hoi
    # can tra loi la "CA THU MUC co chay CGI duoc khong", nen chi pham vi ngoai cung
    # tra loi duoc no; cac pham vi trong la tap con, va mot `+ExecCGI` chi trong
    # `<FilesMatch>` khong phai quyen ca thu muc.
    # CU PHAP TUYET DOI vs TUONG DOI — hai nghia KHAC NHAU, va ban truoc chi hieu mot.
    #
    # Tai lieu Apache (mod_core, `Options`): neu MOI tuy chon tren dong deu co `+` hoac
    # `-` thi chung SUA tap dang co; neu co BAT KY token nao KHONG dau thi dong do THAY
    # HOAN TOAN tap cua pham vi cha. Nen:
    #
    #     Options Includes        -> tap moi = {Includes}. ExecCGI BI LOAI, du cha bat.
    #     Options -Indexes        -> sua tap cu. ExecCGI cua cha GIU NGUYEN.
    #     Options All -Indexes    -> `All` khong dau -> THAY tap, va `All` gom ExecCGI.
    #
    # Ban truoc chi do `all`/`none`/`±execcgi` nen `Options Includes` khong khop nhanh
    # nao -> `opt` giu `-1` = "chua noi gi" -> ke thua cha. Do la ca4 cua review: mot FP,
    # vi Apache da TAT ExecCGI o thu muc do.
    #
    # Do 02-10 tren 171-96: trong 47 dong `Options` toan-thu-muc o tang con, 46 la TUONG
    # DOI va 1 la tuyet doi (`Options All -Indexes`, tuc BAT). Nen phep sua nay khong
    # doi ket qua cua bat ky thu muc nao dang co tren fleet — no dong mot lo hong co
    # che, chu khong chua mot FP dang xay ra.
    if (d == "options") {
        tuyetdoi = 0
        for (i = 2; i <= nf; i++) {
            o = tolower(TOK[i])
            if (o != "" && o !~ /^[+-]/) { tuyetdoi = 1; break }
        }
        # Tuyet doi: tap bat dau TU RONG, roi tung token tren dong them vao. Mot dong
        # khong he nhac ExecCGI thi ket qua la TAT TUONG MINH (`0`), khong phai `-1`.
        if (tuyetdoi) opt[depth] = 0
        for (i = 2; i <= nf; i++) {
            o = tolower(TOK[i])
            if (o == "all")                              opt[depth] = 1
            else if (o == "none")                        opt[depth] = 0
            else if (o == "+execcgi" || o == "execcgi")  opt[depth] = 1
            else if (o == "-execcgi")                    opt[depth] = 0
        }
        next
    }
}

# `@execcgi` in o DAY, sau khi da doc het tep: chi luc do moi biet dong `Options`
# CUOI CUNG o pham vi 0 la dong nao. Chi `opt[0]` duoc doc — xem ly do o tren.
END {
    # ── BON TRUC, BON KHONG GIAN TEN, KHONG gop o day ────────────────
    #
    # Ban truoc QUY BON TRUC VE MOT ngay trong `END` nay:
    #     on = h[e] || t[e]        -> `ext:<e>`     (gop handler voi type)
    #     sh -> "@all",  ft -> "@all"               (gop hai truc toan-thu-muc)
    # Tuc parser TRA LOI THAY cho ben doc. Va mot phep OR khong the mo ta Apache, vi
    # Apache co THU TU UU TIEN chu khong phai phep hop:
    #
    #   `SetHandler` dat handler cho CA thu muc va GHI DE moi `AddHandler`.
    #   `AddHandler <ext>` dat handler cho mot duoi va GHI DE content type.
    #   Content type (`AddType`/`ForceType`) CHI tro thanh "handler" khi khong co
    #   handler nao — do la co che `AddType application/x-httpd-php` cu.
    #
    # Gop bang OR mat ca hai chieu: mot `SetHandler none` o con khong rut lai duoc
    # `AddHandler php` cua cha (phai rut — `SetHandler` uu tien cao hon), va mot
    # `AddHandler default-handler` o con khong rut lai duoc `AddType php` cua cha
    # (phai rut — handler uu tien cao hon type). Hai ca nay la ca1..ca3 cua review, va
    # luoi nhom 29 do chung tren duong day-du.
    #
    # Nen parser gio chi BAO CAO tung truc, con PRECEDENCE o ben doc (`init.lua`), noi
    # duy nhat biet duoi cua request la gi:
    #
    #   h+:<e> / h-:<e>   truc HANDLER theo duoi   (`AddHandler` / `RemoveHandler`)
    #   t+:<e> / t-:<e>   truc TYPE theo duoi      (`AddType` / `RemoveType`)
    #   @sh+ / @sh-       `SetHandler` ca thu muc
    #   @ft+ / @ft-       `ForceType` ca thu muc
    #   @exec+ / @exec-   `Options ... ExecCGI`
    #
    # `+` = BAT tuong minh, `-` = TAT tuong minh, KHONG PHAT = chua noi gi (ke thua).
    # Ba trang thai cho MOI truc, va day la cho `-1` khac `0`.
    for (e in h) seen[e] = 1
    for (e in t) seen[e] = 1
    for (e in seen) {
        # MOI TRUC doc BANG PHU DINH CUA RIENG NO. Dung chung mot `neg` thi mot
        # `RemoveType .jpg` lam truc HANDLER phat `h-:jpg` — tuc van gop hai truc, chi
        # di qua cua sau.
        if (e in h) {
            if (h[e])           print "h+:" e
            else if (e in hneg) print "h-:" e
        }
        if (e in t) {
            if (t[e])           print "t+:" e
            else if (e in tneg) print "t-:" e
        }
    }
    if (sh == 1)      print "@sh+"
    else if (sh == 0) print "@sh-"
    if (ft == 1)      print "@ft+"
    else if (ft == 0) print "@ft-"
    # `@exec+` in o DAY, sau khi da doc het tep: chi luc do moi biet dong `Options`
    # CUOI CUNG o pham vi 0 la dong nao. Chi `opt[0]` duoc doc — xem ly do o tren.
    if (opt[0] == 1)      print (execcgi_ok + 0 == 0) ? "@exec+:noop" : "@exec+"
    else if (opt[0] == 0) print "@exec-"
}
