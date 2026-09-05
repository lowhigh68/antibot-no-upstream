local _M = {}
local core = require "antibot.waf.body_core"

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

local RULES = {
    arg_traversal   = { action = "signal", score = 0.75,
        why = "`../` trong tham so — LFI/doc file tuy y" },
    arg_php_wrapper = { action = "signal", score = 1.00,
        why = "stream wrapper PHP (php:// data:// phar://) trong tham so" },
    arg_null_byte   = { action = "signal", score = 1.00,
        why = "byte NUL trong tham so — cat chuoi de vuot kiem tra duoi file" },
}
_M.RULES = RULES

-- ── MOT ban cai dat, khong phai hai ─────────────────────────────────
--
-- Ba mau tren truoc day duoc viet HAI LAN: mot ban `ngx.re` o day cho query
-- string, mot ban Lua thuan trong `body_core` cho than request. Trung lap la
-- BAT BUOC ve kien truc — `ngx.run_worker_thread` chay ham trong mot VM khong
-- co `ngx`, nen ban doc file tam khong the dung `ngx.re`.
--
-- Nhung hai ban da lech that, va lech theo huong tao lo hong: ban `ngx.re`
-- khong `lower()` LAI sau moi vong giai ma, nen
--     %50hp%3A%2F%2Finput   ->  giai ma ra  `Php://input`
-- va no khong khop mau chu thuong `php://`. Mot bypass hoan chinh cua luat
-- `arg_php_wrapper` tren duong query string.
--
-- Nen chieu uy quyen la NGUOC lai voi truc giac: khong phai `body_core` goi
-- `args.lua`, ma `args.lua` goi `body_core`. Ban Lua thuan la ban chay duoc o
-- CA HAI noi, nen no phai la ban duy nhat.
--
-- Cai gia: mat JIT cua PCRE tren query string. Do duoc — query string dai vai
-- tram byte, va ba phep `string.find` tho tren no re hon mot lan bien dich
-- pattern. Cai KHONG do duoc la hai ngu nghia khac nhau cho cung mot ten luat.
--
-- ── Gia tri tra ve ─────────────────────────────────────────────────
-- Tra ve `rule_id, from` — `from` la vi tri byte cua lan khop.
--
-- `from` CHI CO NGHIA KHI `decode == false`. Luc do vong lap chay dung mot luot
-- tren ban `lower()`, ma `lower()` giu nguyen do dai byte, nen `from` anh xa
-- 1:1 sang chuoi goc. Voi `decode == true` thi chuoi co the la ban da giai ma —
-- do dai khac han — nen `from` tro vao mot chuoi khong con ton tai. Nguoi goi
-- duy nhat dung `from` la `body_core.legacy_fnm` cho multipart, va multipart
-- luon `decode = false`.
--
-- CANH BAO cho lan doc so lieu sau: ham nay tra ve MOT rule_id theo thu tu
-- NUL -> wrapper -> traversal. Nen con so "0 luot traversal/wrapper tren body"
-- do duoc TRUOC 05-09 KHONG chung minh chung sach — chung dang bi NUL che.
_M.check = core.check_args

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

-- Ten tham so cung la DU LIEU KE GUI DIEU KHIEN. `waf_logger.scrub` da ep ve
-- ASCII in duoc nen khong gia mao duoc dong log, nhung `,` `:` `<` `>` van
-- song sot va lam nhieu dung dinh dang `<a,b:35>` cua chinh ham nay. Ep ve mot
-- bang chu cai hep. Thay bang `_` chu KHONG bam: `describe()` ton tai de nguoi
-- doc log hieu ngay, mot hash bien no thanh thu phai tra nguoc, con `_` da noi
-- du rang cho do co ky tu la va `:35` van giu do dai that.
local function safe_name(name)
    return (name:gsub("[^A-Za-z0-9_.%-]", "_"))
end

function _M.describe(qs)
    if not qs or qs == "" then return "-" end

    local names, n = {}, 0
    local pos = 1

    -- `truncated` = co phai ta dung vi CHAM TRAN MAX_NAMES khong.
    --
    -- Ban truoc hoi sai cau: no kiem "phia sau `pos` con dau `&` nao khong".
    -- Voi dung 9 tham so, vong 8 xu ly tham so thu 8 va day `pos` toi dau tham
    -- so thu 9 — la tham so CUOI, khong con `&` nao phia sau — nen marker `,+`
    -- khong xuat hien va 9 tham so hien ra y het 8. Marker chi bat dau dung tu
    -- 10 tro len. Co nay hoi dung cau can hoi.
    local truncated = true
    while n < MAX_NAMES do
        local amp = qs:find("&", pos, true)
        local pair = amp and qs:sub(pos, amp - 1) or qs:sub(pos)
        local eq = pair:find("=", 1, true)

        local name, keyonly
        if eq then
            name = pair:sub(1, eq - 1)
        elseif pair ~= "" then
            -- THAM SO KHONG CO DAU `=`: ca chuoi CHINH LA gia tri.
            --
            -- Ghi "ten" o day la ghi noi dung ra log — dung thu ca ham nay sinh
            -- ra de tranh. Mot token dat trong query dang key-only (`?<token>`)
            -- se ro 32 ky tu dau qua duong nay, va whitelist ky tu KHONG cuu
            -- duoc: mot token base64 toan [A-Za-z0-9] di qua bo loc nguyen ven.
            -- Nen khong ghi gi ca, chi ghi rang co mot tham so dang do.
            name, keyonly = "?", true
        end

        if name and name ~= "" then
            -- `?` la nhan CUA TA, khong phai du lieu ke gui — khong dua qua
            -- `safe_name` (no se doi `?` thanh `_`, lan voi mot ten that co ky
            -- tu la) va khong can cat do dai.
            if not keyonly then
                name = safe_name(name)
                if #name > MAX_NAME_LEN then
                    name = name:sub(1, MAX_NAME_LEN) .. "~"
                end
            end
            n = n + 1
            names[n] = name
        end
        if not amp then truncated = false; break end
        pos = amp + 1
    end

    if n == 0 then return "<:" .. #qs .. ">" end
    -- `pos <= #qs` de mot dau `&` thua o cuoi khong bia ra tham so thu 9.
    local more = (truncated and pos <= #qs) and ",+" or ""
    return "<" .. table.concat(names, ",") .. more .. ":" .. #qs .. ">"
end

return _M
