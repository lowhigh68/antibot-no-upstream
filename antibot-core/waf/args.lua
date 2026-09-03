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

-- `decode` MAC DINH true (query string luon la percent-encoded). Nguoi goi PHAI
-- truyen false cho nhung noi dung KHONG phai percent-encoding.
--
-- Khong phai de tiet kiem — de khong TU TAO duong tinh gia. Body multipart la
-- byte tho kem boundary, JSON dung `\uXXXX`. Giai ma chung la dien giai sai
-- ban chat du lieu: mot file .txt upload chua dung chuoi ky tu `%2e%2e%2f` se
-- BIEN THANH `../` sau mot lan unescape va ban — mot FP hoan toan do buoc giai
-- ma tao ra, khong he co trong du lieu goc.
--
-- Tien the: giam tu toi da 9 luot regex + 2 lan cap phat chuoi 64k xuong con 3
-- luot regex + 0 cap phat cho nhom multipart/json/binary.
function _M.check(args, decode)
    if not args or args == "" then return nil end
    if decode == nil then decode = true end

    local s = args:lower()
    for i = 1, (decode and MAX_DECODE or 1) do
        -- Thu tu theo do CHAC CHAN giam dan, vi chi tra ve mot rule_id: NUL va
        -- wrapper gan nhu khong the la nham lan, con `../` thi hiem khi nhung
        -- van co the la mot URL tuong doi trong tham so redirect.
        if ngx.re.find(s, RX_NULLBYTE,  "jo") then return "arg_null_byte"   end
        if ngx.re.find(s, RX_WRAPPER,   "jo") then return "arg_php_wrapper" end
        if ngx.re.find(s, RX_TRAVERSAL, "jo") then return "arg_traversal"   end

        if not decode or i == MAX_DECODE then break end
        local dec = ngx.unescape_uri(s)
        if dec == s then break end   -- da giai het, khong con lop nao
        s = dec
    end

    return nil
end

-- Mo ta mot query string de ghi log MA KHONG ghi gia tri.
--
-- Tra ve dang `<ten1,ten2:len>`, vi du `<action,key,login:84>`.
--
-- VI SAO KHONG GHI NGUYEN QUERY STRING. Lap luan cu cua toi la "mat khau khong
-- di qua URL" — dung voi mat khau, SAI voi token dat lai mat khau, ma do chinh
-- la dinh dang cua WordPress:
--     /wp-login.php?action=rp&key=<token>&login=<user>
-- Mot credential song nam tron trong query string. Cong OAuth authorization
-- code, API key trong tich hop cu, signed URL, email trong tham so. Ghi nguyen
-- van vao waf.log — file text, giu 30 ngay — la lam ro chung ra.
--
-- TEN tham so thi ghi duoc: do la lUOC DO, khong phai du lieu. Va no la thu
-- huu ich nhat khi doc log: biet luat ban o `key=` hay o `s=` la biet ngay day
-- la tan cong hay mot o tim kiem.
--
-- Do dai giu lai vi no phan biet mot payload ngan voi mot lan dan nhieu KB.
local MAX_NAMES = 8
local MAX_NAME_LEN = 32

function _M.describe(qs)
    if not qs or qs == "" then return "-" end

    local names, n = {}, 0
    local pos = 1
    while n < MAX_NAMES do
        local amp = qs:find("&", pos, true)
        local pair = amp and qs:sub(pos, amp - 1) or qs:sub(pos)
        local eq = pair:find("=", 1, true)
        local name = eq and pair:sub(1, eq - 1) or pair
        if name ~= "" then
            n = n + 1
            names[n] = #name > MAX_NAME_LEN
                and (name:sub(1, MAX_NAME_LEN) .. "~") or name
        end
        if not amp then break end
        pos = amp + 1
    end

    if n == 0 then return "<:" .. #qs .. ">" end
    local more = (qs:find("&", pos, true) and n >= MAX_NAMES) and ",+" or ""
    return "<" .. table.concat(names, ",") .. more .. ":" .. #qs .. ">"
end

return _M
