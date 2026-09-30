# Parser `.user.ini`/`php.ini` — co nap ma qua autoload khong?
#
# MOT hien thuc, dung boi `fim.sh` va bo test. Ma thoat 0 = CO nap ma.
#
# `none` la gia tri VO HIEU HOA (da doi chung voi PHP), va dong
# `auto_prepend_file=none` co THAT trong nhieu `php.ini` hop le de TAT tinh nang.
# Loai no y nhu `upload_content.lua` — hai noi phai cung mot dinh nghia "gia tri co
# nap ma".
#
# CU PHAP INI, KHONG phai Apache: `;` va `#` bat dau chu thich, va KHONG co noi dong
# bang gach nguoc. Day la ly do hai parser la hai tep chu khong dung chung mot:
# `.htaccess` la cu phap Apache, `.user.ini` la Zend INI.
#
# ── `#` va `;` TRONG DAU NHAY KHONG phai chu thich ────────────────────
#
# Ban truoc dung `sub(/[;#].*/, "")` tren ca dong, nen
#     auto_prepend_file="none#payload.php"
# bi cat thanh `auto_prepend_file="none` -> gia tri doc ra la `none` -> KET LUAN
# "vo hieu hoa", tuc BO SOT mot autoload that. Nguoi dung tai hien duoc 28-09.
# Lua (`upload_content.lua:strip`) xu ly dau nhay DUNG, nen day la mot lech giua
# hai parser theo huong FALSE NEGATIVE.
#
# Zend doc gia tri INI den het dong roi trim, va mot gia tri duoc nhay thi noi dung
# trong nhay duoc giu nguyen — nen `#` ben trong la mot KY TU cua duong dan, khong
# phai dau mo chu thich.
function strip_comment(s,   out, i, c, q) {
    out = ""; q = ""
    for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == q) q = ""; out = out c; continue }
        if (c == "\"" || c == "'") { q = c; out = out c; continue }
        if (c == "#" || c == ";") break
        out = out c
    }
    return out
}

{
    line = strip_comment($0)
    if (tolower(line) ~ /^[ \t\r]*auto_(pre|ap)pend_file[ \t]*=/) {
        # HAI directive DOC LAP, hai trang thai rieng. Ban truoc dung MOT bien `found`
        # cho ca hai, nen
        #     auto_prepend_file=/tmp/x.php
        #     auto_append_file=none
        # cho "khong nap ma" — BO SOT mot autoload dang bat (nguoi dung bat 30-09).
        # Zend giu mot gia tri RIENG cho tung khoa; last-wins ap trong TUNG khoa,
        # khong ap cheo. Ket luan cuoi la HOAC cua hai.
        k = tolower(line); sub(/^[ \t\r]*/, "", k); sub(/[ \t]*=.*/, "", k)
        v = line
        sub(/^[^=]*=[ \t]*/, "", v)
        # `\r` PHAI o day: mot `.user.ini` sua tu Windows dung CRLF, va khi do
        # `auto_prepend_file=none\r\n` cho `v = "none\r"` -> `!= "none"` -> KET LUAN
        # "co nap ma", tuc mot FALSE POSITIVE tren dong TAT tinh nang. Va
        # `auto_prepend_file=\r\n` (gia tri rong) cho `v = "\r"` -> `!= ""` -> cung
        # FP. Tai hien duoc 29-09 trong WSL.
        gsub(/[ \t\r"']/, "", v)
        # LAN CUOI THANG trong TUNG khoa: Zend doc tuan tu va directive SAU ghi de
        # directive TRUOC, nen
        #     auto_prepend_file=/tmp/x.php
        #     auto_prepend_file=none
        # la TAT. Ban truoc dat `found = 1` mot chieu nen khong bao gio rut lai duoc
        # (nguoi dung bat 29-09).
        on[k] = (v != "" && tolower(v) != "none") ? 1 : 0
    }
}
END { exit((on["auto_prepend_file"] || on["auto_append_file"]) ? 0 : 1) }
