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

function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

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

    if (d == "addtype" || d == "addhandler") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        for (i = 3; i <= nf; i++) {
            e = TOK[i]; sub(/^\./, "", e)
            if (e != "") print tolower(e)
        }
        next
    }

    if (d == "sethandler" || d == "forcetype") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        # Trong container thi KHONG ap ca thu muc -> bo sot CO Y.
        if (depth == 0) print "@all"
        next
    }

    # `Options`: xu ly TUAN TU nhu Apache. `All` gom ExecCGI; `-ExecCGI` tat.
    if (d == "options") {
        on = 0
        for (i = 2; i <= nf; i++) {
            o = tolower(TOK[i])
            if (o == "all")                              on = 1
            else if (o == "none")                        on = 0
            else if (o == "+execcgi" || o == "execcgi")   on = 1
            else if (o == "-execcgi")                    on = 0
        }
        # `@execcgi` chu KHONG `@all`: xem khoi hop dong o dau tep.
        if (on && depth == 0) print "@execcgi"
        next
    }
}
