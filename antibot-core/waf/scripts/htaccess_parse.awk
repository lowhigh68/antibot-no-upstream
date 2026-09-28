# Parser `.htaccess` — MOT hien thuc duy nhat, dung boi `fim.sh` VA
# `htaccess_fixture_test.sh`.
#
# VI SAO LA MOT TEP RIENG: truoc day khoi awk nay nam nhung trong `fim.sh`, va bo
# test phai TRICH no ra bang moc comment. Mot phep trich la mot cho de lech — da
# hong mot lan (mat dong dau + dau dong cua khoi). Nay ca hai ben `-f` cung tep.
#
# HOP DONG, cung mot cau hoi ma `upload_content.lua` tra loi: dong nay co lam mot
# duoi thanh THUC THI DUOC khong? In ra:
#   <duoi>   duoi cu the tu `AddType`/`AddHandler`   (mot dong moi duoi)
#   @all     ap CA thu muc: `SetHandler`/`ForceType`/`Options +ExecCGI`
# Khong in gi = khong co gi nguy hiem.
#
# BAT BIEN doc tu tai lieu Apache, khong tu tri tuong tuong:
#   · ten directive KHONG phan biet hoa thuong
#   · noi dong bang gach nguoc cuoi dong
#   · `AddType`/`AddHandler`: token THU NHAT la mime/handler, cac token sau la duoi
#   · `SetHandler`/`ForceType`: token THU NHAT, KHONG mang duoi
#   · `Options`: cac token `+x`/`-x` xu ly TUAN TU; `All` bao gom ExecCGI
#
# `<FilesMatch>`/`<Files>`/`<Location>`: `SetHandler` trong container KHONG ap cho
# ca thu muc. Chua doc duoc container context day du, nen ben trong container ta
# KHONG nang thanh `@all` — huong sai la BO SOT, khong phai bao oan.

function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

# Bo chu thich `#`, NHUNG khong bo `#` nam trong dau nhay: mot gia tri handler co
# the chua `#`. Apache khong co chu thich giua dong cho gia tri da nhay.
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
    # mot tep co gach nguoc cuoi dong that, chi `/\\$/` ghep duoc hai dong
    # (`1`, `3`, `4` deu khong). Ban truoc file nay chi co MOT — heredoc cua cong cu
    # dev gop `\\` thanh `\` — nen phep noi dong CHUA BAO GIO chay, va bo test van
    # xanh vi fixture khi do cung khong sinh dung byte. HAI loi che nhau.
    while (line ~ /\\$/) {
        sub(/\\$/, " ", line)
        if ((getline nxt) <= 0) break
        line = line trim(nxt)
    }
    line = trim(strip_comment(line))
    if (line == "") next

    # Theo doi container: `<FilesMatch ...>` mo, `</FilesMatch>` dong. Dem theo do
    # sau chu khong co/khong — long nhau la chuyen binh thuong.
    if (line ~ /^<[ \t]*\/[ \t]*(FilesMatch|Files|Location|LocationMatch|Directory|DirectoryMatch|If|IfModule)/) {
        if (depth > 0) depth--
        next
    }
    if (line ~ /^<[ \t]*(FilesMatch|Files|Location|LocationMatch|Directory|DirectoryMatch)/) {
        depth++; next
    }
    # `<IfModule>` KHONG tinh la container gioi han pham vi: no la dieu kien theo
    # module, va directive ben trong van ap cho ca thu muc.
    if (line ~ /^<[ \t]*IfModule/) { ifdepth++; next }

    nf = split(line, T, /[ \t]+/)
    if (nf < 2) next
    d = tolower(T[1])

    # Token THU NHAT quyet dinh, bo nhay neu co.
    v = T[2]
    gsub(/^["']|["']$/, "", v)

    if (d == "addtype" || d == "addhandler") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        for (i = 3; i <= nf; i++) {
            e = T[i]; sub(/^\./, "", e)
            if (e != "") print tolower(e)
        }
        next
    }

    if (d == "sethandler" || d == "forcetype") {
        if (tolower(v) !~ /php|cgi|proxy:unix:|proxy:fcgi:/) next
        # Trong container thi KHONG ap ca thu muc -> bo sot co y.
        if (depth == 0) print "@all"
        next
    }

    # `Options`: xu ly TUAN TU nhu Apache. `All` bao gom ExecCGI; `-ExecCGI` tat.
    if (d == "options") {
        on = 0
        for (i = 2; i <= nf; i++) {
            o = tolower(T[i])
            if (o == "all")                        on = 1
            else if (o == "none")                  on = 0
            else if (o == "+execcgi" || o == "execcgi") on = 1
            else if (o == "-execcgi")              on = 0
        }
        if (on && depth == 0) print "@all"
        next
    }
}
