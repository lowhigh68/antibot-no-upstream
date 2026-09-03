local _M = {}

-- Soi THAM SO, khong phai duong dan.
--
-- Day la lo hong lon nhat cua tang nay cho toi 2026-09-03: muoi luat deu doc
-- `ngx.var.uri` va khong gi khac. Nhung tren WordPress hosting chia se, viec
-- chiem quyen THAT SU hau nhu luon di qua mot lo hong PLUGIN khai thac bang
-- tham so — LFI, doc file tuy y, RCE qua stream wrapper. Duong dan cua nhung
-- request do hoan toan binh thuong: `/index.php`, `/wp-admin/admin-ajax.php`.
-- Tai trong nam trong query string.
--
-- BA LUAT, KHONG PHAI BA TRAM. Day khong phai CRS thu nho. Ba mau duoi day
-- duoc chon vi chung gan nhu khong co ban sao hop le trong luu luong that:
-- khong plugin WordPress nao gui `../` trong tham so, khong ai gui `php://`,
-- khong ai gui byte NUL. So sanh voi luat SQLi/XSS cua CRS — vốn noi tieng
-- ban oan noi dung bai viet va o tim kiem tren chinh WordPress — thi day la
-- dau kia cua thang do.
--
-- Giu nguyen nguyen tac cua tang: SIGNAL, khong chan. `engine.lua` quyet cung
-- ba tang tin cay. Ngay ca 1.0 x trong so 50 = 50 diem van duoi CHALLENGE(55).
-- Nang len block hay khong la viec cua so lieu, sau vai ngay doc waf.log.

-- `..` theo sau bang `/` hoac `\`. Khong bat `..` tran: mot dau cham doi trong
-- ten file (`bao-cao..pdf`) hay trong so thap phan la chuyen binh thuong.
--
-- CHUOI CO NHAY, KHONG DUOC dung `[[...]]`. Mau ket thuc bang mot lop ky tu
-- `[/\\]`, nen viet `[[\.\.[/\\]]]` thi Lua doc `]]` DAU TIEN la dau dong chuoi
-- va con lai mot `]` lac => loi cu phap. Dung cai bay da ghi san cho RX_DOTFILE
-- ben exposed.lua, va van mac lai — chu thich dung khong cuu duoc gi neu nguoi
-- viet khong doc lai no.
-- Trong chuoi co nhay, moi `\` phai nhan doi: "\\." ra `\.`, "\\\\" ra `\\`.
local RX_TRAVERSAL = "\\.\\.[/\\\\]"

-- Stream wrapper cua PHP. `://` la bat buoc trong mau — thieu no thi
-- `data:image/png;base64,...` (dang HTML hop le, khong co hai dau gach) se bi
-- bat oan. Co `://` thi do la dang wrapper, va dang do khong co cong dung hop le
-- nao trong mot tham so HTTP.
local RX_WRAPPER = [[(?:php|data|expect|phar|zip|glob|file|compress\.\w+)://]]

-- Byte NUL, ca dang ma hoa lan dang tho. Dung de cat chuoi trong ham C ben duoi
-- PHP (`include($x . ".php")` voi `$x` ket thuc bang NUL). Khong bao gio hop le
-- trong query string.
local RX_NULLBYTE = [[%00|\x00]]

local RULES = {
    arg_traversal   = { action = "signal", score = 0.75,
        why = "`../` trong tham so — LFI/doc file tuy y" },
    arg_php_wrapper = { action = "signal", score = 1.00,
        why = "stream wrapper PHP (php:// data:// phar://) trong tham so" },
    arg_null_byte   = { action = "signal", score = 1.00,
        why = "byte NUL trong tham so — cat chuoi de vuot kiem tra duoi file" },
}
_M.RULES = RULES

-- SO MOT LAN LA KHONG DU. Ke tan cong ma hoa nhieu lop de vuot bo loc chi nhin
-- mot lop: `%2e%2e%2f` giai ma mot lan ra `../`, con `%252e%252e%252f` phai giai
-- HAI lan. Mot bo loc chi kiem chuoi tho se truot ca hai; mot bo loc giai ma
-- dung mot lan se truot cai thu hai.
--
-- Duyet toi da BA muc (goc + 2 lan giai ma) va dung ngay khi khong con gi de
-- giai. Ba la du: chua thay tai trong that nao ma hoa sau hon, va can tren nay
-- chan viec mot chuoi doc hai bat CPU giai ma vo han.
local MAX_DECODE = 3

function _M.check(args)
    if not args or args == "" then return nil end

    local s = args:lower()
    for i = 1, MAX_DECODE do
        -- Thu tu theo do CHAC CHAN giam dan, vi chi tra ve mot rule_id: NUL va
        -- wrapper gan nhu khong the la nham lan, con `../` thi hiem khi nhung
        -- van co the la mot URL tuong doi trong tham so redirect.
        if ngx.re.find(s, RX_NULLBYTE,  "jo") then return "arg_null_byte"   end
        if ngx.re.find(s, RX_WRAPPER,   "jo") then return "arg_php_wrapper" end
        if ngx.re.find(s, RX_TRAVERSAL, "jo") then return "arg_traversal"   end

        if i == MAX_DECODE then break end
        local dec = ngx.unescape_uri(s)
        if dec == s then break end   -- da giai het, khong con lop nao
        s = dec
    end

    return nil
end

return _M
