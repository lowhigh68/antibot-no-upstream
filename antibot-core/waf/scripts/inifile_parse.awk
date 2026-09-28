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
    if (tolower(line) ~ /^[ \t]*auto_(pre|ap)pend_file[ \t]*=/) {
        v = line
        sub(/^[^=]*=[ \t]*/, "", v)
        gsub(/[ \t"']/, "", v)
        if (v != "" && tolower(v) != "none") found = 1
    }
}
END { exit(found ? 0 : 1) }
