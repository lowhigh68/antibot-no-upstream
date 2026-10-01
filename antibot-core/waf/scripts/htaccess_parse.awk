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

BEGIN { depth = 0; ifdepth = 0; if (execcgi_ok == "") execcgi_ok = 1 }

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

    # `AddType`/`AddHandler` TICH LUY theo duoi, va `RemoveType`/`RemoveHandler` RUT
    # LAI mot duoi cu the. Apache xu ly tuan tu trong CUNG mot tep, va o thu muc CON
    # mot `Remove*` huy mapping KE THUA tu cha (tai lieu mod_mime).
    #
    # Nen khong in ngay: GHI TRANG THAI theo duoi roi in o `END`. Ban truoc in ngay
    # tai dong, nen `AddHandler ... .jpg` roi `RemoveHandler .jpg` van cho `ext:jpg`.
    if (d == "addtype" || d == "addhandler") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        for (i = 3; i <= nf; i++) {
            e = TOK[i]; sub(/^\./, "", e)
            # `ext:` chu KHONG duoi tho. Ban truoc in `php`, `jpg` vao CUNG khong
            # gian ten voi `@all`/`@php`/`@phpini`/`@execcgi`, nen mot tep ten
            # `.@all` cho token `@all` va `init.lua` doc thanh "handler ap CA thu
            # muc" (nguoi dung tai hien 29-09). Tien to lam hai khong gian KHONG THE
            # gap nhau: mot duoi luon la `ext:<gi do>`, mot co luon bat dau `@`.
            #
            # Loc ky tu la cach SAI cho viec nay: danh sach ky tu cam phai doan truoc
            # moi duoi hop le, va Apache khong cam gi ca. Tien to dung voi MOI duoi.
            if (e != "") extst[tolower(e)] = 1
        }
        next
    }

    # `RemoveHandler`/`RemoveType`: KHONG loc theo `v` nhu `Add*`. Doi so cua chung la
    # DANH SACH DUOI tu token thu HAI (khong co mime/handler o dau), va chung rut lai
    # bat ke handler cu la gi.
    if (d == "removehandler" || d == "removetype") {
        for (i = 2; i <= nf; i++) {
            e = TOK[i]; sub(/^\./, "", e)
            if (e != "") extst[tolower(e)] = 0
        }
        next
    }

    if (d == "sethandler" || d == "forcetype") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        # Trong container thi KHONG ap ca thu muc -> bo sot CO Y.
        if (depth == 0) print "@all"
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
    if (d == "options") {
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
    # Duoi: in TRANG THAI CUOI, va `rm:` cho duoi bi RUT LAI. `rm:` can thiet vi
    # `RemoveHandler` o thu muc CON huy mapping ke thua tu CHA — ben doc phai biet
    # "duoi nay da bi tat o day" chu khong chi "khong co gi o day".
    for (e in extst) {
        if (extst[e]) print "ext:" e
        else          print "rm:" e
    }
    # `@execcgi` in o DAY, sau khi da doc het tep: chi luc do moi biet dong `Options`
    # CUOI CUNG o pham vi 0 la dong nao. Chi `opt[0]` duoc doc — xem ly do o tren.
    if (opt[0]) print (execcgi_ok + 0 == 0) ? "@execcgi:noop" : "@execcgi"
}
