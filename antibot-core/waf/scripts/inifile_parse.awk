# Parser `.user.ini`/`php.ini` — co nap ma qua autoload khong?
#
# MOT hien thuc, dung boi `fim.sh` va bo test. Ma thoat 0 = CO nap ma.
#
# `none` la gia tri VO HIEU HOA (da doi chung voi PHP), va dong
# `auto_prepend_file=none` co THAT trong nhieu `php.ini` hop le de TAT tinh nang.
# Loai no y nhu `upload_content.lua` — hai noi phai cung mot dinh nghia "gia tri
# co nap ma".
#
# CU PHAP INI, KHONG phai Apache: `;` va `#` bat dau chu thich, va KHONG co noi
# dong bang gach nguoc. Day la ly do hai parser tach lam hai tep chu khong dung
# chung mot: `.htaccess` la cu phap Apache, `.user.ini` la Zend INI.
{
    line = $0
    sub(/[;#].*/, "", line)
    if (tolower(line) ~ /^[ \t]*auto_(pre|ap)pend_file[ \t]*=/) {
        v = line
        sub(/^[^=]*=[ \t]*/, "", v)
        gsub(/[ \t"']/, "", v)
        if (v != "" && tolower(v) != "none") found = 1
    }
}
END { exit(found ? 0 : 1) }
