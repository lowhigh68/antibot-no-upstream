local _M = {}

-- BO DO BODY — giai doan 1: CHI QUAN SAT, khong luat nao ban.
--
-- Vi sao chua co luat. Ca phien lam viec nay da bac bo sau gia thuyet lien tiep
-- bang so lieu that (mu-plugins "backdoor" hoa ra la ban va cua agency SEO;
-- "status=200 nghia la da bi chiem" sai hai lan; "cong cu quan tri WP tap trung"
-- bi chinh output bac bo). Viet luat body ma khong biet body tren dan may nay
-- chua gi la lap lai dung sai lam do — chi khac la lan nay hau qua roi vao
-- 43 domain that.
--
-- Nen module nay ghi lai NHUNG GI CO TRONG BODY va khong quyet dinh gi ca. Sau
-- vai ngay se co phan bo that de viet luat co can cu.
--
-- ── Cai gia thuc su bang KHONG ──────────────────────────────────────────
-- `ngx.req.read_body()` nghe thi dat, thuc te khong them gi:
-- `proxy_request_buffering` KHONG duoc dat trong repo nay ⇒ mac dinh `on` ⇒
-- nginx VON DA doc va dem tron body truoc khi gui len Apache. Doc no o day chi
-- la nhin vao thu da nam san trong bo nho.
-- (`proxy_buffering off` trong `da_to_openresty.sh` la dem PHAN HOI — directive
-- khac, dung nham thi ket luan nguoc.)

local args = require "antibot.waf.args"

local INSPECT_METHODS = {
    POST = true, PUT = true, PATCH = true, DELETE = true,
}

-- The mo PHP, khong phan biet hoa thuong: `<?PHP` cung la PHP hop le.
-- `<?=` la short echo tag, bat mac dinh tu PHP 5.4.
-- KHONG bat `<?` tran: XML khai bao `<?xml` va se lam nhieu moi upload SVG/RSS.
local RX_PHP_OPEN = [[<\?(?:php|=)]]

-- Family nao mang BYTE NHI PHAN. Dung de tat luat NUL — xem chu thich day du o
-- `args.check`, tham so `binary`.
--
-- Do 2026-09-05: 67/67 luot `arg_null_byte` deu nam trong NOI DUNG file upload
-- (`fnm=0` cho ca 61 luot multipart do duoc). Moi file nhi phan chua byte NUL
-- theo dinh nghia dinh dang, nen luat do khong phat hien tan cong — no phat
-- hien "vua co nguoi upload file".
--
-- `other` vao danh sach nay vi no la nhan cho Content-Type khong khop mau nao,
-- ma `application/octet-stream` roi dung vao do. Do duoc 4 luot NUL mang nhan
-- `other` kich thuoc 2–7 KB. Doan sai theo huong AN TOAN: bo mot tin hieu con
-- hon ban oan moi upload tren 43 domain.
local BINARY_FAMILY = {
    multipart = true,
    other     = true,
}

-- Phan loai content-type ve mot nhan NGAN de dem duoc.
-- Chuoi that dai va co bien the (`multipart/form-data; boundary=----WebKit...`),
-- do nguyen vao log thi khong nhom duoc bang uniq -c.
local function ct_family(ct)
    if not ct or ct == "" then return "-" end
    local low = ct:lower()
    if low:find("multipart/form-data", 1, true)               then return "multipart"  end
    if low:find("application/x-www-form-urlencoded", 1, true) then return "urlencoded" end
    if low:find("json", 1, true)                              then return "json"       end
    if low:find("xml",  1, true)                              then return "xml"        end
    if low:find("text/", 1, true)                             then return "text"       end
    return "other"
end

-- Dem tham so body bang cach dem `&`, KHONG goi `ngx.req.get_post_args()`.
-- Cung ba ly do da ghi o `async/logger.lua:414` cho tham so query:
--   1. `get_post_args()` mac dinh CAT O 100 phan tu va khong bao gi. Ta can con
--      so THAT, ke ca khi ben gui 500 tham so — do chinh la truong hop dang ngo.
--   2. No cap phat mot bang Lua moi request; dem `&` chi quet chuoi.
--   3. Day la access phase, nam tren duong di cua moi request.
-- Chi co nghia voi urlencoded. Multipart phan cach bang boundary, dem `&` ra so
-- vo nghia — nen tra nil de log ghi `-` thay vi mot con so sai.
local function count_args(body, family)
    if family ~= "urlencoded" or not body or body == "" then return nil end
    local n = 1
    local pos = 1
    while true do
        local i = body:find("&", pos, true)
        if not i then break end
        n = n + 1
        pos = i + 1
    end
    return n
end

-- Lan khop DUOC CHON co nam trong mot `filename=` cua multipart khong.
--
-- COT PHAN TANG, KHONG PHAI LUAT. No khong chan gi, khong doi diem — no tra
-- loi mot cau hoi ma phan bo hien tai KHONG tra loi duoc: trong so lan
-- `arg_rule` ban tren than multipart, bao nhieu la ten file (gan nhu chac chan
-- la tan cong) va bao nhieu la NOI DUNG file/bai viet (gan nhu chac chan la FP).
--
-- ĐINH CHINH 2026-09-05, doc ky truoc khi dung con so nay:
--   `fnm` mo ta VI TRI CUA LAN KHOP DUOC CHON, khong phai "request nay co tan
--   cong o ten file hay khong". `args.check` tra ve MOT rule_id theo thu tu
--   NUL -> wrapper -> traversal roi dung lai. Mot request vua co `php://` trong
--   NOI DUNG file vua co `../../shell.php` trong TEN FILE se cho wrapper thang,
--   `fnm=0`, du tan cong o ten file la co that.
--   Nen `fnm=0` doc dung la "lan khop duoc chon nam ngoai ten file", KHONG
--   phai "khong co tan cong ten file". Toi da noi qua dieu nay khi bao cao so
--   lieu 05-09: dung la 0/61 lan khop DUOC CHON nam trong ten file, con "khong
--   co tan cong ten file nao" thi chua bao gio duoc chung minh.
--
-- Vi sao them cot thay vi thu hep luat ngay. Thu hep bay gio la ra ket luan
-- roi moi di tim du lieu ung ho no: se khong bao gio biet noi dung tu do ban
-- bao nhieu lan, ma do dung la con so can de quyet dinh co nen thu hep hay
-- khong. Trong so dang la 0 nen quet rong khong ton gi ngoai mot dong log.
--
-- CACH XAC DINH. Cau truc mot phan multipart:
--     --BOUNDARY\r\n
--     Content-Disposition: form-data; name="f"; filename="../../x.php"\r\n
--     \r\n
--     <noi dung file>\r\n
-- Ten file nam TREN CUNG MOT DONG voi `filename=`; noi dung file thi nam sau
-- mot dong trong. Nen phep kiem dung la "cung dong", khong phai mot cua so
-- nhin-lui tuy y — cua so thi phai chon do rong, ma moi lua chon deu sai voi
-- mot header du dai.
--
-- BAT CA `filename*=` (RFC 5987, dang `filename*=UTF-8''..%2F..%2Fx.php`).
-- `find("filename=")` KHONG khop chuoi do vi co dau `*` chen giua — mot cho
-- nup neu ai do coi day la luat thay vi cot do.
--
-- GIOI HAN CON LAI, ghi ro de khong ai tuong da phu: gia tri cua `filename*=`
-- la percent-encoding, ma than multipart chay voi `decode=false`, nen
-- `..%2F..%2F` trong do KHONG duoc phat hien. Va nay khong vao vong giai ma
-- toan than: lam vay se dung lai chinh cai FP da tranh (mot file .txt chua
-- chuoi ky tu `%2e%2e%2f`). Muon bit thi phai tach rieng gia tri `filename*`
-- va giai ma MOT MINH no — viec do chi dang lam khi filename traversal duoc
-- nang len thanh tin hieu that.
--
-- Chi chay khi `arg_rule` DA ban, tuc gan nhu khong bao gio. Chi phi tren luu
-- luong thuong bang 0.
--
-- `at` chi co nghia voi `decode == false`, va multipart luon la truong hop do
-- — xem chu thich cua `args.check`.
local function in_filename(body, family, at)
    if not at or family ~= "multipart" then return nil end

    -- Dau dong chua vi tri `at`: dau xuong dong cuoi cung TRUOC no.
    local bol, p = 0, 1
    while true do
        local i = body:find("\n", p, true)
        if not i or i >= at then break end
        bol = i
        p = i + 1
    end

    local head = body:sub(bol + 1, at - 1):lower()
    return head:find("filename=", 1, true) ~= nil
        or head:find("filename*=", 1, true) ~= nil
end

-- Soi RIENG TEN FILE cua tung phan multipart, doc lap voi than.
--
-- VI SAO PHAI TACH RA. `fnm` o tren tai su dung VI TRI cua luat toan than, nen
-- no keo theo hai khuyet tat cua cach lam do:
--
--   1. Le thuoc thu tu uu tien. `args.check` tra ve MOT rule_id theo thu tu
--      NUL -> wrapper -> traversal roi dung. Mot request vua co `php://` trong
--      NOI DUNG file vua co `../../shell.php` trong TEN FILE se cho wrapper
--      thang, `fnm=0`, du tan cong o ten file la co that. Nen `fnm` khong dung
--      de DEM so request co tan cong ten file.
--
--   2. Khong soi duoc `filename*=`. Than multipart chay `decode=false` (dung —
--      giai ma noi dung nhi phan tu tao ra FP), nhung gia tri cua `filename*=`
--      theo RFC 5987 LA percent-encoding. Nen `filename*=UTF-8''..%2F..%2F
--      shell.php` lot sach.
--
-- Ham nay chay `args.check` len RIENG gia tri ten file. Ket qua vao `fn_rule`,
-- KHONG dung chung voi `arg_rule`, va KHONG dat tin hieu nao trong ctx: day van
-- la telemetry o trong so 0. Nang no len tin hieu that la quyet dinh sau, khi
-- da co so dem.
--
-- ── GIAI MA CO PHAN BIET, va day la cho chiu luc ──────────────────────
--   `filename*=`  RFC 5987 dinh nghia LA percent-encoding  => decode = true
--   `filename=`   gia tri THO (UTF-8 hoac RFC 2047)        => decode = false
-- Giai ma bua ca hai thi mot file ten `a..%2Fb.pdf` — hop le, khach dat ten the
-- that — se bien thanh `a../b.pdf` va ban. Dung dang FP ma ca tang nay tranh.
--
-- ── Cac tinh huong da tinh den ───────────────────────────────────────
--   · NHIEU phan: quet HET, khong dung o cai dau. Upload thu vien anh co hang
--     chuc phan, tan cong thuong nam o phan cuoi.
--   · Ba dang cu phap: `filename="x"`, `filename=x` (khong nhay, khong chuan
--     nhung client that co gui), `filename*=UTF-8''x`.
--   · Khong phan biet hoa thuong: header la case-insensitive (`Filename=`).
--   · Nhay thoat `\"` ben trong: quet HET moi lan xuat hien nen mot ten file
--     co `filename=\"../x\"` chen giua van bi bat o lan xuat hien thu hai.
--   · Chan so luong (MAX_PARTS) va do dai (MAX_HDR_LEN, MAX_FN_LEN): mot than doc hai
--     nhoi hang nghin `filename=` khong bien ham nay thanh o CPU.
--   · KHONG lowercase ban sao cua than: dung co `i` cua ngx.re thay vi
--     `body:lower()`, tiet mot lan cap phat 80 KB cho MOI multipart POST.
--   · Nhom bat tham gia cua ngx.re tra ve `false` chu KHONG phai nil — phai
--     kiem ca hai, neu khong `m[3]` bi doc nham thanh chuoi.
--
-- ── Gioi han da biet ─────────────────────────────────────────────────
-- Quet TOAN BO than chu khong rieng dong Content-Disposition. Nen mot file van
-- ban duoc upload MA NOI DUNG no chua chuoi `filename="../x"` (vi du mot file
-- log, hay chinh bo luat WAF) se bi dem. Hiem, va do duoc — de nguyen roi doc
-- so lieu, dung thu hep truoc khi biet no co that hay khong.
-- ── Mau, va tung manh cua no la mot ca da bi bat hut ────────────────
--   `(?:^|[;\s])`  DAU PHAN CACH truoc `filename`. Thieu no thi
--       `myfilename="../x"` — bat ky chuoi nao KET THUC bang `filename` — cung
--       khop. Trong header multipart, `filename` luon di sau `;` hoac khoang
--       trang. `^` la de mot than bat dau thang bang `filename=` van khop.
--   `\s*=\s*`      khoang trang o CA HAI ben dau bang. `filename = "../x.php"`
--       khong chuan nhung parser ben duoi chap nhan, nen ta cung phai chap nhan.
--   `"((?:[^"\\]|\\.)*)"`  chuoi trong nhay CO XU LY NHAY THOAT.
--       Ban truoc dung `[^"]*` va toi ghi trong chu thich rang "quet moi lan
--       xuat hien nen van bat duoc o lan sau". SAI: voi
--       `filename="abc\"../../x.php"` chi co MOT lan xuat hien, `[^"]*` dung
--       ngay o dau nhay da thoat, va toan bo tai trong phia sau khong duoc kiem
--       — trong khi parser multipart ben duoi van doc no la mot ten file.
--       Hai nhanh `[^"\\]` va `\\.` loai tru nhau o ky tu dau nen khong co
--       backtracking cap so nhan.
--       DAU `\` PHAI VIET DOI. Long string `[[...]]` cua Lua khong xu ly chuoi
--       thoat, nen cai ta go la cai PCRE nhan. Mot dau `\` don le bien
--       `[^"\]` thanh mot lop ky tu KHONG DONG (`\]` la dau `]` da thoat), lop
--       do nuot tiep toi dau `]` sau va bo lai mot `(?:` khong dong => CA MAU
--       LOI CU PHAP. Da xay ra that o `8dfafd2`.
--       LOI CU PHAP. Da xay ra that o `8dfafd2`.
--       LOP KY TU PHAI LOAI CA CR/LF, va ban truoc thi khong. `[^"\\]` cho qua
--       `\r` va `\n`, nen mot dau nhay KHONG DONG an xuyen dong:
--           ; filename="
--           Content-Disposition: form-data; name=f; filename="../../shell.php"
--       Lan khop gia bat dau o dau nhay dong tren, nuot ca dong duoi cho toi
--       dau nhay MO cua header that, roi dong lai o do. Ket qua: gia tri bat ra
--       la mot doan header vo hai, `filename=` THAT da bi tieu thu nen gmatch
--       khong con thay no, va ham tra `nil, false` — tuc bao la DA SOI SACH.
--       Do la mot lan bo sot TU BAO CAO LA HOAN TAT, dung dang loi nang nhat
--       trong ca module nay.
--       `\\[^\r\n]` (thay vi `\\.`) vi trong PCRE khong co co `s`, dau `.` van
--       khop `\r`. Ten file that khong the chua CR/LF: header multipart ket
--       thuc o CRLF theo dinh nghia, nen loai chung khong mat gi.
--       Chua dut diem — mot noi dung file co ca `filename="..."` tren MOT dong
--       van dem. Cai do la dieu kien chan so 1, phai tach part theo boundary.
--   `([^;"\r\n]*)`  dang khong nhay, va dang ext-value cua `filename*=`.
local RX_FILENAME  = [[(?:^|[;\s])filename(\*?)\s*=\s*(?:"((?:[^"\\\r\n]|\\[^\r\n])*)"|([^;"\r\n]*))]]

-- Da keu chua? Mot co moi worker, khong chia se — dung y do: moi worker keu mot
-- lan la du de thay trong error.log, va van la so lan huu han.
local rx_broken = false

-- Trich `boundary` tu Content-Type. RFC 2046 cho hai dang: co nhay va khong.
-- Doi dau phan cach `[;\s]` truoc `boundary` vi cung mot ly do da doi no truoc
-- `filename`: thieu no thi bat ky tham so nao KET THUC bang `boundary` cung
-- khop.
local RX_BOUNDARY = [[(?:^|[;\s])boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))]]

-- BA TRAN, ba nghia KHAC nhau. Truoc day chi co mot (`MAX_FILENAMES`), va no
-- vua dem so ten file vua lam vien chan chi phi — hai viec khac nhau gop lam
-- mot thi khong chinh duoc cai nao ma khong lam hong cai kia.
local MAX_PARTS   = 64     -- so phan multipart soi toi da
local MAX_HDR_LEN = 2048   -- do dai vung header cua MOT phan
local MAX_FN_LEN  = 512    -- do dai mot gia tri ten file

local function boundary_of(ct)
    if not ct or ct == "" then return nil end
    local m = ngx.re.match(ct, RX_BOUNDARY, "ijo")
    if not m then return nil end
    return (m[1] and m[1] ~= "" and m[1])
        or (m[2] and m[2] ~= "" and m[2])
        or nil
end

-- Tra ve `rule_id, truncated`.
--
-- ── SOI VUNG HEADER CUA TUNG PHAN, KHONG SOI TOAN THAN ──────────────
--
-- Ban truoc chay mot `gmatch` tren TOAN BO than. Cai do khong chi gay nhieu —
-- no lam TRAN 32 tro nen VO NGHIA, vi ngan sach bi tieu vao noi dung ma ke tan
-- cong soan ra:
--     Phan 1 (mot o text):  32 chuoi `filename="x.jpg"` gia
--     Phan 2 (header that): filename="../../shell.php"
--                           ^ het suat truoc khi toi day
-- `fn_trunc="n"` lam no HIEN RA nhung khong lam no BI BAT. Va nang tran khong
-- cuu duoc: ke tan cong dieu khien so luong, ta thi khong.
--
-- ── DANH DOI, va huong danh doi la CO CHU Y ─────────────────────────
--
-- Quet toan than co mot uu diem that: no KHONG PHU THUOC PARSER. Cat theo
-- boundary thi de ra rui ro LECH PARSER — neu ta doi `\r\n` ma PHP chap nhan
-- `\n`, ke tan cong dung `\n` va ta thay MOT phan khong lo trong khi PHP thay
-- hai.
--
-- Nguyen tac thoat ra: BO QUET PHAI LA TAP CHA CUA PARSER. Cho nao khong chac
-- thi cat NHIEU hon, dung cat it hon. Nen o day:
--   · dau phan cach nhan `\n--B` (tuc chap ca `\r\n--B` lan `\n--B` tran)
--   · dong trong ket thuc header nhan ca `\r\n\r\n` lan `\n\n`
-- Cat thua chi dua ta ve dung cai nhieu dang co; cat thieu moi tao duong ne.
--
-- ── VUNG MU MOI no tao ra, ghi ra chu khong giau ─────────────────────
-- Multipart LONG NHAU (`multipart/mixed` trong mot phan): header cua phan con
-- nam trong THAN cua phan cha nen khong duoc soi. Quet toan than truoc day
-- thay chung. Hiem trong form web, va PHP cung khong dua chung vao `$_FILES`.
--
-- ── Gia tri `truncated`: LA LY DO, KHONG PHAI CO ────────────────────
--     "rx"   mau khong bien dich duoc -> loi luc deploy, sua ngay
--     "nb"   Content-Type khong co boundary doc duoc -> khong cat duoc phan nao
--     "hdr"  mot vung header > 2 KB   -> bat thuong, hoac than khong co dong
--                                        trong; chi soi 2 KB dau
--     "len"  mot ten file > 512 byte  -> hiem, va tu no da dang ngo
--     "n"    hon 64 phan              -> upload thu vien anh that thi nang tran
--     "stop" dung lai vi DA TIM THAY  -> binh thuong, di kem mot `fn_rule`
--
-- Uu tien khi cham nhieu tran: "len" > "hdr" > "n" > "stop". Xep theo do BAT
-- THUONG, vi cot nay ton tai de noi CAN LAM GI TIEP, khong phai de dem.
--
-- Tra ve: `nil` khong ap dung | `false` da soi het | mot trong sau chuoi tren.
-- `false` (cot `fntr=0`) chi con dung MOT nghia: da soi het moi vung header va
-- khong luat nao ban.
local function filename_rule(body, family, ct)
    if family ~= "multipart" then return nil, nil end

    -- Khong co boundary thi khong cat duoc phan nao. Bao ra chu KHONG lui ve
    -- quet toan than: chay am tham mot thuat toan khac la dung cai bay ma ca
    -- module nay dung de tranh. Va mot Content-Type multipart khong co boundary
    -- thi PHP cung khong phan tich duoc — day la request bat thuong, khong phai
    -- truong hop can chieu co.
    local bnd = boundary_of(ct)
    if not bnd then return nil, "nb" end

    local delim, trunc = "--" .. bnd, false
    local dlen = #delim
    local pos, nparts = 1, 0

    -- `worse` giu thu tu uu tien o mot cho, thay vi rai `if trunc ~= "..."`
    -- khap noi — cach cu chi so sanh duoc voi MOT gia tri va da bo sot.
    local RANK = { stop = 1, n = 2, hdr = 3, len = 4 }
    local function worse(v)
        if (RANK[v] or 0) > (RANK[trunc] or 0) then trunc = v end
    end

    while nparts < MAX_PARTS do
        -- Dau phan cach phai o DAU DONG, neu khong thi `--B` nam trong noi dung
        -- file cung cat duoc phan gia.
        local ds
        while true do
            local i = body:find(delim, pos, true)
            if not i then break end
            if i == 1 or body:byte(i - 1) == 10 then ds = i; break end
            pos = i + dlen
        end
        -- Het phan that su. `trunc` giu nguyen: `false` neu chua cham tran nao,
        -- va do la lan DUY NHAT cot `fntr=0` duoc phat ra.
        if not ds then return nil, trunc end
        pos = ds + dlen

        -- DAU DONG KET THUC (`--B--`). No KHONG phai mot phan. Coi no la phan
        -- thi khong tim thay dong trong nao sau no va `worse("hdr")` se ban
        -- tren MOI than multipart LANH — mot bao dong 100% gia.
        if body:sub(pos, pos + 1) == "--" then break end
        nparts = nparts + 1

        -- Het dong phan cach -> bat dau vung header.
        local eol = body:find("\n", pos, true)
        if not eol then break end
        local hs = eol + 1

        -- Het vung header = dong trong dau tien. Nhan CA HAI dang xuong dong.
        local b1 = body:find("\n\r\n", eol, true)
        local b2 = body:find("\n\n",   eol, true)
        local he
        if b1 and b2 then he = (b1 < b2) and b1 or b2 else he = b1 or b2 end
        if not he or he - hs > MAX_HDR_LEN then
            he = hs + MAX_HDR_LEN
            worse("hdr")
        end
        if he < hs then he = hs end

        local head = body:sub(hs, he)
        local it, err = ngx.re.gmatch(head, RX_FILENAME, "ijo")
        if not it then
            -- Mau la HANG SO nen day la loi luc deploy, khong phai loi cua
            -- request. Keu mot lan moi worker; duong bao duoc doc that la cot
            -- `fntr=rx` chay lien tuc.
            if not rx_broken then
                rx_broken = true
                ngx.log(ngx.ERR, "[waf] RX_FILENAME khong bien dich duoc: ",
                        err or "khong ro. fn_rule DA NGUNG SOI ten file.")
            end
            return nil, "rx"
        end

        while true do
            local m = it()
            if not m then break end

            -- Nhom khong tham gia -> `false`, khong phai nil.
            -- Phai NHO da di nhanh nao: chi nhanh trong nhay mang quoted-pair.
            local quoted = (m[2] and m[2] ~= "") and true or false
            local v = (quoted and m[2])
                   or (m[3] and m[3] ~= "" and m[3])
                   or nil
            if v then
                if #v > MAX_FN_LEN then
                    v = v:sub(1, MAX_FN_LEN)
                    worse("len")
                end

                -- GIAI MA DUNG MOT LAN cho `filename*=`. RFC 5987 dinh nghia
                -- ext-value la percent-encoding MOT LOP; giai them mot lop nua
                -- tao FP that: `filename*=UTF-8''a..%252Fb.txt` giai dung mot
                -- lan ra `a..%2Fb.txt` — ten file hop le chua ky tu `%` — con
                -- vong thu hai bien no thanh `a../b.txt` va ban.
                --
                -- MEP CO CHU Y: `x%2500.jpg` giai mot lan ra `x%00.jpg`, roi
                -- `RX_NUL_ENC` van ban vi no khop `%00` dang VAN BAN. Tuc rieng
                -- luat NUL doc them mot lop. Giu vay — app ha nguon giai ma lai
                -- ten file la chuyen pho bien va lam sai. Ghim bang test.
                if m[1] == "*" then v = ngx.unescape_uri(v) end

                -- `binary` de mac dinh false: ten file la VAN BAN, ca hai mau
                -- NUL deu co nghia o day.
                local rule = args.check(v, false)

                -- QUOTED-PAIR: soi THEM dang da bo dau `\`, va soi CA HAI chu
                -- khong thay the.
                --     filename=".\./shell.php"  -> parser doc ra ../shell.php
                --     filename="..\..\shell.php" -> dang THO moi khop `\.\.[/\\]`
                -- Bo escape mot cach pha huy la doi mot lo hong lay mot lo
                -- hong. Khong biet parser ha nguon doc kieu nao thi soi ca hai.
                -- Gia: mot `find` byte tho, va chi khi dang tho DA SACH.
                if not rule and quoted and v:find("\\", 1, true) then
                    local unq = v:gsub("\\(.)", "%1")
                    if unq ~= v then rule = args.check(unq, false) end
                end

                if rule then
                    worse("stop")
                    return rule, trunc
                end
            end
        end

        -- Vong sau tim tu DAU vung header, KHONG tu cuoi no.
        --
        -- Nhay toi `he` nhanh hon nhung SAI khi `he` bi cap 2 KB: cai cap do co
        -- the nam VUOT QUA dau phan cach ke tiep, va the la mat han mot phan —
        -- tuc cat IT hon parser, dung dieu ca ham nay dat ra de tranh. Tu `hs`
        -- thi phep tim chi duyet lai vung header (toi da 2 KB) va khong bao gio
        -- bo sot. `hs > ds` nen vong lap van tien len, khong quan.
        pos = hs
    end

    -- Cham tran so phan. Con phan nua khong? Mot lan tim nua de biet — khong de
    -- "het ngan sach" tra ve giong "da soi het va sach".
    if nparts >= MAX_PARTS then
        local i = body:find(delim, pos, true)
        while i do
            if i == 1 or body:byte(i - 1) == 10 then worse("n"); break end
            i = body:find(delim, i + dlen, true)
        end
    end

    return nil, trunc
end

-- Chay trong `waf.run_pre`, TRUOC cua thoat tin cay — cung ly do ca tang WAF
-- dung o do: cookie `verified` song 7200s, va danh tinh da xac minh khong noi gi
-- ve NOI DUNG request.
--
-- Cong loc phai RE, vi no chay cho moi request:
--   1. method — mot lan `ngx.req.get_method()`, khong I/O
--   2. co Content-Type khong
-- GET/HEAD (gan het luu luong) thoat o buoc 1.
--
-- CONG LA Content-Type, TUYET DOI KHONG PHAI Content-Length.
-- Do 2026-09-02 tren luu luong that: 387 POST multipart trong 24h bao `cl=0`
-- — chunked transfer-encoding thi khong co Content-Length. Gac bang `cl > 0` se
-- bo qua dung nhom dang quan tam nhat (upload file), va bo qua trong im lang.
function _M.probe(ctx)
    if not INSPECT_METHODS[ngx.req.get_method()] then return end

    local ct = ngx.var.http_content_type
    if not ct or ct == "" then return end

    local family = ct_family(ct)

    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if not body then
        -- `get_body_data()` tra nil o BA tinh huong khac nhau, va gop chung lam
        -- mot la lam hong chinh phep do nay:
        --   1. body vuot `client_body_buffer_size` -> nginx ghi ra file tam
        --   2. khong co body (POST rong, hoac Content-Length 0)
        --   3. body rong
        -- Chi (1) moi la `spill`. Phan biet bang `get_body_file()`: co duong dan
        -- file tam nghia la (1), khong co nghia la (2)/(3).
        --
        -- Neu goi ca ba la spill thi con so dung de quyet dinh
        -- `client_body_buffer_size` bi thoi phong bang so POST rong — tuc quyet
        -- dinh sai tren mot phep dem sai.
        local spilled = ngx.req.get_body_file() ~= nil

        -- KHONG doc file tam o day: access phase, `io.open` la I/O CHAN nam tren
        -- duong di cua moi request — dung dieu luat repo cam (xem `run_log`,
        -- noi phep cham dia duy nhat cua tang nay duoc phep ton tai).
        --
        -- `php` va `arg_rule` de NIL, khong phai `false`/`0`.
        -- "Khong soi duoc" khac han "da soi, khong thay gi". Ban truoc ghi
        -- `php = false` ngay canh chu thich noi dung dieu do — tuc tu mau thuan.
        -- Neu mot phep thong ke ve sau coi `php=0` la am tinh thi moi ty le deu
        -- lech, va khong ai biet vi log trong nhu binh thuong.
        ctx.waf_body = {
            family   = family,
            spill    = spilled,
            -- `-1` CHI cho spill: do dai co that, ta khong doc. Voi hai truong
            -- hop con lai (khong co body / body rong) thi do dai DA BIET va
            -- bang 0 — ghi `-1` o do la gop "khong biet" vao mot gia tri, dung
            -- toi da lam voi `php = false` ngay ben duoi, va no se thoi phong
            -- chinh con so dung de chon `client_body_buffer_size`.
            len      = spilled and -1 or 0,
            php      = nil,
            nargs    = nil,
            arg_rule = nil,
            fnm      = nil,
            fn_rule  = nil,
            -- `"spill"`, KHONG phai `nil`. `nil` in ra `fntr=-` = "khong ap
            -- dung", va no dung voi request khong phai multipart. Voi multipart
            -- DA SPILL thi khong ap dung la sai: co ten file that o trong do,
            -- ta chi khong doc duoc. Gop hai thu vao mot dau `-` la giau mot
            -- VUNG MU trong mot nhan vo can — lan thu tu cua cung dang loi
            -- (`php = false`, `fntr` kieu co, `fntr=0` mang hai nghia).
            --
            -- Hau qua cu the neu de `nil`: ai do dem "so lan quet hoan tat" =
            -- count(fntr=0) va "so vung mu" = count(rx|len|n) thi multipart da
            -- spill khong roi vao O NAO CA — tong hai o khong bang tong so
            -- multipart, va cai thieu di dung la cai bi bo qua.
            fn_trunc = (family == "multipart") and "spill" or nil,
        }
        return
    end

    -- Ba luat tham so, ap len than request. `args.check` khong biet gi ve NGUON
    -- chuoi no nhan, nen dung lai nguyen ven — cung ba mau, cung vong giai ma.
    --
    -- Co ap cho multipart: `../` trong TEN FILE cua mot phan multipart la dung
    -- ky thuat traversal khi upload, va no khong xuat hien o dau khac.
    --
    -- KHAC BIET THAT SU so voi query string, va la ly do nay chi la SIGNAL:
    -- than request chua NOI DUNG NGUOI DUNG SOAN. Mot quan tri vien viet bai ve
    -- stream wrapper PHP roi bam Luu se gui `php://` trong than POST toi
    -- /wp-admin/post.php. Query string khong bao gio co chuyen do.
    --
    -- `decode` CHI bat cho urlencoded. Da giai thich day du o `args.check`:
    -- giai ma mot noi dung khong phai percent-encoding la dien giai sai ban
    -- chat du lieu va TU TAO ra duong tinh gia — mot file .txt upload chua
    -- chuoi ky tu `%2e%2e%2f` se bien thanh `../` sau mot lan unescape.
    -- `binary` = family mang byte nhi phan => bo luat NUL. `decode` = family la
    -- percent-encoding => moi giai ma. Hai truc doc lap; bang tra day du o
    -- `args.check`.
    local rule, at = args.check(body, family == "urlencoded", BINARY_FAMILY[family] == true)
    local fn_rule, fn_trunc = filename_rule(body, family, ct)

    ctx.waf_body = {
        family = family,
        spill  = false,
        len    = #body,
        -- Mot luot PCRE da JIT tren toi da `client_body_buffer_size` byte.
        php    = ngx.re.find(body, RX_PHP_OPEN, "ijo") ~= nil,
        nargs  = count_args(body, family),
        arg_rule = rule,
        fnm    = in_filename(body, family, at),
        -- Doc lap voi `arg_rule`: soi RIENG gia tri ten file, khong le thuoc
        -- thu tu uu tien cua luat toan than. Day moi la con so dung de dem
        -- "co bao nhieu request tan cong o ten file".
        fn_rule  = fn_rule,
        -- LY DO khong soi het, khong phai co: `nil` khong ap dung | `false` da
        -- soi het | `"rx"` mau hong | `"len"` ten file > 512 byte | `"n"` hon
        -- 32 phan. Doc kem `fn_rule`: bat ky gia tri chuoi nao cung nghia la
        -- KHONG BIET, khong phai sach — ba nguyen nhan chi khac nhau o viec
        -- phai lam gi tiep.
        fn_trunc = fn_trunc,
    }
end

return _M
