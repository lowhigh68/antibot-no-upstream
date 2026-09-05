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
--   · Chan so luong (MAX_FILENAMES) va do dai (MAX_FN_LEN): mot than doc hai
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

-- 32 chu khong phai 16: mot lan dang thu vien anh that co the co hon 16 phan,
-- va tran qua thap thi co `fn_trunc` bao dong lien tuc tren luu luong lanh.
-- Van co tran vi mot than doc hai nhoi hang nghin `filename=` khong duoc bien
-- ham nay thanh o CPU.
local MAX_FILENAMES = 32
local MAX_FN_LEN    = 512

-- Da keu chua? Mot co moi worker, khong chia se — dung y do: moi worker keu mot
-- lan la du de thay trong error.log, va van la so lan huu han.
local rx_broken = false

-- Tra ve `rule_id, truncated`.
--
-- `truncated` KHONG duoc bo qua. Cham tran nghia la ta KHONG SOI HET, va im
-- lang coi do la "sach" la dung loi da sua o `php = false`: bien mot khoang
-- trong thanh mot am tinh. Va no la mot duong ne tranh that: nhoi 32 chuoi
-- `filename=` gia vao noi dung file thi bo quet dung truoc khi toi header that.
--
-- LA LY DO, KHONG PHAI CO. Ban truoc tra `true` cho ca ba nguyen nhan, tuc
-- dung nghia "khong soi het" nhung khong doc duoc: ba nguyen nhan doi ba viec
-- khac han nhau.
--     "rx"   mau khong bien dich duoc  -> loi luc deploy, sua ngay
--     "len"  mot ten file > 512 byte   -> hiem, va tu no da dang ngo
--     "n"    hon 32 phan               -> thuong la upload thu vien anh that,
--                                         cach xu ly la nang tran
--     "stop" dung lai vi DA TIM THAY    -> binh thuong, di kem mot `fn_rule`
-- Mot request co the cham ca "len" lan "n". Uu tien "len" vi no la cai bat
-- thuong hon; "n" mot minh gan nhu luon la luu luong lanh. `"len"` cung thang
-- `"stop"` — da cham tran do dai truoc khi tim thay thi van la co vung mu.
--
-- Tra ve: `nil` khong ap dung | `false` da soi het | mot trong bon chuoi tren.
-- Nho `"stop"`, `false` (cot `fntr=0`) chi con dung MOT nghia: da soi het moi
-- ten file va khong luat nao ban.
local function filename_rule(body, family)
    if family ~= "multipart" then return nil, nil end

    -- `nil` o day KHONG co nghia la "khong tim thay ten file nao" — gmatch tra
    -- nil khi MAU KHONG BIEN DICH DUOC. Ban dau cho nay `return nil, nil`, tuc
    -- mot mau hong hien ra thanh `fnrule=- fntr=-` tren MOI multipart: giong het
    -- mot tang dang chay va khong thay gi. Dung dang am tinh gia da sua o
    -- `php = false`, chi khac la lan nay no che ca bo luat.
    --
    -- Hai duong bao, vi mot duong khong du:
    --   `fntr=1`  chay lien tuc, doc duoc bang wafstat muc 7, khong can ai mo
    --             error.log. Day moi la duong duoc doc.
    --   ngx.ERR   mot lan moi worker. Mau la HANG SO nen loi la loi luc deploy,
    --             khong phai loi cua request — ghi moi request thi 43 domain do
    --             error.log ma khong them mot bit thong tin nao.
    local it, err = ngx.re.gmatch(body, RX_FILENAME, "ijo")
    if not it then
        if not rx_broken then
            rx_broken = true
            ngx.log(ngx.ERR, "[waf] RX_FILENAME khong bien dich duoc: ",
                    err or "khong ro. fn_rule DA NGUNG SOI ten file.")
        end
        return nil, "rx"   -- khong soi duoc, khong phai da soi xong
    end

    local trunc, n = false, 0
    while n < MAX_FILENAMES do
        local m = it()
        if not m then return nil, trunc end
        n = n + 1

        -- Nhom khong tham gia -> `false`, khong phai nil.
        -- Phai NHO da di nhanh nao: chi nhanh trong nhay moi mang quoted-pair.
        local quoted = (m[2] and m[2] ~= "") and true or false
        local v = (quoted and m[2])
               or (m[3] and m[3] ~= "" and m[3])
               or nil

        if v then
            if #v > MAX_FN_LEN then
                v = v:sub(1, MAX_FN_LEN)
                trunc = "len"
            end

            -- GIAI MA DUNG MOT LAN cho `filename*=`, roi goi luat voi
            -- `decode=false`. KHONG dua no vao vong 3 muc cua `args.check`.
            --
            -- RFC 5987 dinh nghia ext-value la percent-encoding MOT LOP. Giai
            -- them mot lop nua la doc nhieu hon cai ma dinh dang noi, va no tao
            -- ra FP that: `filename*=UTF-8''a..%252Fb.txt` giai dung mot lan ra
            -- `a..%2Fb.txt` — mot ten file hop le chua ky tu `%` — con vong thu
            -- hai bien no thanh `a../b.txt` va ban.
            --
            -- Ban truoc truyen `decode = (m[1] == "*")` nen dinh dung cai bay
            -- ma khoi chu thich ngay tren day viet ra de tranh.
            --
            -- MOT MEP, va no la NGOAI LE CO CHU Y chu khong phai so sot.
            -- `filename*=UTF-8''x%2500.jpg` giai dung mot lan ra `x%00.jpg` —
            -- ten file that chua ba KY TU `%`, `0`, `0`. `args.check(v, false)`
            -- khong giai ma them, nhung `RX_NUL_ENC` van ban vi no khop `%00`
            -- dang VAN BAN. Vay rieng luat NUL CO doc them mot lop, va cau
            -- "giai ma dung mot lan" khong con thuan tuy.
            -- Giu vay: app ha nguon giai ma lai ten file la chuyen pho bien va
            -- lam sai, `x%00.jpg` giai them lan nua thanh `x<NUL>.jpg` — dung
            -- cai cat chuoi ma luat NUL sinh ra de bat. Cung mot lua chon da
            -- lam cho than nhi phan. Ghim bang test doi chung trong body_test.
            if m[1] == "*" then v = ngx.unescape_uri(v) end

            -- `binary` de mac dinh false: ten file la VAN BAN, ca hai mau NUL
            -- deu co nghia o day.
            local rule = args.check(v, false)

            -- QUOTED-PAIR: soi THEM dang da bo dau `\`, va soi CA HAI chu khong
            -- thay the.
            --
            -- Mau da hoc CU PHAP quoted-pair (nhanh `\\.` la ly do no khop duoc
            -- `filename="abc\"..."`) nhung gia tri bat ra van con nguyen dau
            -- `\`. Trong quoted-string, parser ha nguon bo dau do, nen:
            --     filename=".\./shell.php"   ->  ../shell.php
            --     filename="p\hp://input"    ->  php://input
            -- Ca hai deu lot vi dang tho khong co `..` lien nhau, khong co
            -- `php://`. Do la cu phap duoc phan tich ma ngu nghia thi khong.
            --
            -- VI SAO SOI CA HAI, khong don gian bo escape roi soi mot lan: dang
            -- tho MOT MINH bat duoc mot lop khac.
            --     filename="..\..\shell.php"   Windows-style, traversal THAT
            --     tho       ..\..\shell.php    RX_TRAVERSAL `\.\.[/\\]` KHOP
            --     bo escape ...shell.php       KHONG con khop
            -- Bo escape mot cach pha huy la doi mot lo hong lay mot lo hong.
            -- Ta khong biet parser ha nguon dung cach doc nao — PHP, Python,
            -- Node moi thu mot kieu — nen soi ca hai cach doc.
            --
            -- Gia: mot `find` byte tho, va chi khi dang tho DA SACH. Ten file
            -- binh thuong khong co dau `\` nen duong nay khong chay.
            if not rule and quoted and v:find("\\", 1, true) then
                local unq = v:gsub("\\(.)", "%1")
                if unq ~= v then rule = args.check(unq, false) end
            end

            -- `"stop"`, KHONG phai `false`. Ham thoat ngay khi co luat dau
            -- tien, nen luc do ta CHUA soi cac ten file phia sau. Tra `false`
            -- o day lam `fntr=0` mang hai nghia: "da soi het va sach" va "dung
            -- lai vi tim thay". Cai thu hai khong sai ve phan quyet — request
            -- da bi danh dau roi — nhung no lam hong phep dem "bao nhieu lan
            -- quet hoan tat".
            -- Lam thanh mot GIA TRI thay vi mot quy uoc phai nho: `fntr=0` gio
            -- chi con dung mot nghia, va no khong the bi doc nham.
            -- `trunc or "stop"`: neu da cham `"len"` truoc do thi giu `"len"`.
            if rule then return rule, trunc or "stop" end
        end
    end

    -- Cham tran 32. Con phan thu 33 khong? Mot lan goi nua de biet — khong de
    -- "het ngan sach" tra ve giong "da soi het va sach".
    -- "len" thang "n": mot ten file dai hon 512 byte la cai bat thuong hon, con
    -- hon 32 phan mot minh gan nhu luon la mot lan dang thu vien anh that.
    if it() and trunc ~= "len" then trunc = "n" end
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
            fn_trunc = nil,
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
    local fn_rule, fn_trunc = filename_rule(body, family)

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
