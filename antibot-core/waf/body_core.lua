local _M = {}

-- LOI SOI NOI DUNG — Lua THUAN, KHONG dung `ngx`.
--
-- Rang buoc "khong dung ngx" la BAT BUOC chu khong phai lua chon phong cach:
-- than request vuot `client_body_buffer_size` bi nginx ghi ra file tam, va cach
-- duy nhat doc no ma khong chan event loop la `ngx.run_worker_thread` — thu chay
-- ham Lua trong MOT VM RIENG, noi khong co bat ky API `ngx` nao. Nen moi thu o
-- day phai la `string.find` va Lua pattern, khong duoc dung `ngx.re`.
--
-- Cai gia phai tra, ghi ro de khong ai ngac nhien: `body:lower()` cap phat MOT
-- BAN SAO TRON THAN. Voi than trong bo nho (mac dinh 8k/16k) thi khong dang ke.
-- Voi mot file tam 50 MiB thi la 50 MiB doc + 50 MiB copy, nhan voi so thread
-- trong pool. Do la con so phai nho khi chon `threads=` cho `thread_pool`.
-- Doi lai: khong con vung mu spill, thu ma nang `client_body_buffer_size` KHONG
-- BAO GIO dong duoc (buffer 64K thi ke tan cong don 65K).
--
-- ── Vi sao lai la MOT loi dung chung ────────────────────────────────
-- `args.lua` uy quyen `check` xuong day. Truoc do co HAI ban cai dat cua cung
-- ba luat — mot bang `ngx.re` cho query string, mot bang Lua thuan cho than —
-- va chung da lech that: ban `ngx.re` khong `lower()` lai sau moi vong giai ma,
-- nen `%50hp%3A%2F%2Finput` giai ra `Php://input` va KHONG khop mau chu thuong.
-- Mot bypass co that, chi vi hai ban cai dat.

-- P1: bang duoi chay duoc + ten file cau hinh. File RIENG vi no tra loi mot cau
-- KHAC — "server co chay file nay khong" — chu khong phai "gia tri nay co chua
-- mau tan cong khong". Cung phai la Lua thuan, cung ly do da ghi o dau file.
local upload = require "antibot.waf.upload"

local MAX_PARTS   = 64     -- so phan multipart soi toi da
local MAX_HDR_LEN = 2048   -- do dai vung header cua MOT phan
local MAX_FN_LEN  = 512    -- nguong BAO CAO cho mot gia tri ten file

-- Do NGHIEM TRONG, khong phai do "muon xu ly truoc". Cot `fntr=` ton tai de noi
-- CAN LAM GI TIEP, nen khi cham nhieu tran thi giu lai cai doi hanh dong lon
-- nhat.
--
--   len     mot ten file > 512 byte — TIN HIEU, khong phai vung mu (xem duoi)
--   n       hon 64 phan
--   disp    Content-Disposition dang sai
--   ending  khong thay dau dong ket thuc
--   bd      co boundary nhung khong tim thay dau phan cach nao trong than
--   bdup    Content-Type co NHIEU boundary khac nhau
--   bval    gia tri boundary khong dung duoc
--   hdr     mot vung header > 2 KB — VUNG MU THAT
--   nb      khong doc duoc boundary nao
--
-- `len` KHAC HAN cac muc khac va day la cho de doc nham nhat: gia tri ten file
-- van duoc kiem TRON VEN, khong cat. Cat roi moi kiem — cai ban truoc lam — la
-- tu tao duong ne: don 512 byte la che duoc traversal phia sau. Nen `len` bao
-- "ten file dai bat thuong", KHONG bao "co cho chua soi".
local STATUS_RANK = {
    len = 2, n = 3,
    disp = 4, ending = 4,
    bd = 5, bdup = 5, bval = 5,
    hdr = 6,
    -- `bmax`: so boundary candidate vuot tran. Cung muc `nb` (khong co boundary
    -- nao) vi ca hai nghia la "khong phan giai duoc cau truc".
    bmax = 7, nb = 7,
}

local function worse(a, b)
    if not b or b == false then return a end
    if not a or a == false then return b end
    return ((STATUS_RANK[b] or 0) > (STATUS_RANK[a] or 0)) and b or a
end
_M.worse = worse

local function trim(s)
    return (s:gsub("^[ \t]+", ""):gsub("[ \t]+$", ""))
end

-- ── Phan loai Content-Type ──────────────────────────────────────────
-- So khop CHINH XAC tren media type (phan truoc dau `;`) chu khong tim chuoi
-- con o bat ky dau. `find("multipart/form-data")` kieu cu se coi
-- `text/plain; note="multipart/form-data; boundary=x"` la multipart.
local function ct_family(ct)
    if not ct or ct == "" then return "-" end
    local media = trim((ct:match("^([^;]*)") or ct):lower())
    if media == "multipart/form-data" then return "multipart" end
    if media == "application/x-www-form-urlencoded" then return "urlencoded" end
    if media:match("[/+]json$") then return "json" end
    if media:match("[/+]xml$")  then return "xml"  end
    if media:sub(1, 5) == "text/" then return "text" end
    return "other"
end
_M.ct_family = ct_family

-- ── Ba luat tham so ─────────────────────────────────────────────────
local function percent_decode_once(s)
    return (s:gsub("%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end))
end

-- `://` la BAT BUOC trong mau — thieu no thi `data:image/png;base64,...` (dang
-- HTML hop le) bi bat oan.
local FIXED_WRAPPERS = {
    "php://", "data://", "expect://", "phar://",
    "zip://", "glob://", "file://",
}

local function find_wrapper(s, init)
    local first
    for i = 1, #FIXED_WRAPPERS do
        local p = s:find(FIXED_WRAPPERS[i], init or 1, true)
        if p and (not first or p < first) then first = p end
    end
    local p = s:find("compress%.[%w_]+://", init or 1)
    if p and (not first or p < first) then first = p end
    return first
end

-- `..` PHAI di kem `/` hoac `\`. Thieu ve sau thi `bao-cao..pdf` va moi so thap
-- phan deu ban.
local function find_traversal(s, init)
    local pos = init or 1
    while true do
        local p = s:find("..", pos, true)
        if not p then return nil end
        local c = s:sub(p + 2, p + 2)
        if c == "/" or c == "\\" then return p end
        pos = p + 1
    end
end

local MAX_DECODE = 3

-- Nhan chuoi DA `lower()`. Tra ve `rule_id, vi_tri`.
--
-- `vi_tri` CHI CO NGHIA KHI `decode == false` — luc do vong chay dung mot luot
-- va `lower()` giu nguyen do dai byte nen anh xa 1:1 sang chuoi goc.
--
-- HAI TRUC DOC LAP:
--     query string          decode=true   binary=false
--     body urlencoded       decode=true   binary=false
--     body json/xml/text    decode=false  binary=false
--     body multipart/other  decode=false  binary=TRUE
--
-- `binary` CHI tat mau BYTE THO `\0`. Moi dinh dang nhi phan chua byte do theo
-- dac ta, nen o than multipart no phat hien "co file dinh kem" chu khong phat
-- hien tan cong (do 05-09: 67/67 luot deu nam trong noi dung file). Mau VAN BAN
-- `%00` thi KHONG tat — ba ky tu do chi xuat hien o cho co nguoi go ra.
local function check_args_lower(low, decode, binary)
    local s = low
    for i = 1, (decode and MAX_DECODE or 1) do
        local p
        if not binary then
            p = s:find("\0", 1, true)
            if p then return "arg_null_byte", p end
        end
        p = s:find("%00", 1, true)
        if p then return "arg_null_byte", p end
        p = find_wrapper(s)
        if p then return "arg_php_wrapper", p end
        p = find_traversal(s)
        if p then return "arg_traversal", p end

        if not decode or i == MAX_DECODE then break end
        local dec = percent_decode_once(s)
        if dec == s then break end
        -- PHAI `lower()` LAI. `%50` giai ma ra `P` — mot byte chua he di qua
        -- lan `lower()` dau tien. Thieu dong nay thi `%50hp%3A%2F%2Finput` ra
        -- `Php://input` va truot mau chu thuong. Do la bypass co that cua ban
        -- `ngx.re` truoc day.
        s = dec:lower()
    end
    return nil
end
_M.check_args_lower = check_args_lower

-- ── V7: TAP luat cua mot vung, khong phai "luat dau tien" ────────────────────
--
-- `check_args_lower` tra MOT luat — cai dau tien theo thu tu kiem — va van la cau
-- tra loi dung cho query string (`args.lua`): moi target chi can mot luat. Bang
-- chung THEO VUNG cua than thi phai bao CA TAP. Policy gop theo luat (cung luat
-- qua nhieu target lay max, khac luat thi cong), nen neu moi vung chi bao luat
-- manh nhat thi THEM noi dung co the lam diem GIAM:
--     field `../` (35) + tep `php://input` (50)            = 85
--     them `php://` vao field -> field chi con bao wrapper,
--     trung luat voi tep, gop bang max                     = 50
-- Bao ca tap thi them noi dung chi co the them fact, va tong chi tang.
--
-- Cung ba phep tim va cung vong giai ma voi `check_args_lower`; `body_test` ghim
-- hai ham dong y voi nhau tren moi mau cua no.
local function rules_in_lower(low, decode, binary, out)
    local s = low
    for i = 1, (decode and MAX_DECODE or 1) do
        if (not binary and s:find("\0", 1, true)) or s:find("%00", 1, true) then
            out.arg_null_byte = true
        end
        if find_wrapper(s) then out.arg_php_wrapper = true end
        if find_traversal(s) then out.arg_traversal = true end

        if not decode or i == MAX_DECODE then break end
        local dec = percent_decode_once(s)
        if dec == s then break end
        -- PHAI `lower()` LAI — cung ly do voi `check_args_lower`.
        s = dec:lower()
    end
    return out
end
_M.rules_in_lower = rules_in_lower

-- Tap -> mang DA SAP XEP (thu tu co dinh cho log va test), `nil` neu rong.
local function rule_list(set)
    local out = {}
    for id in pairs(set) do out[#out + 1] = id end
    if #out == 0 then return nil end
    table.sort(out)
    return out
end

-- Vung `file`: co lan khop nao BAT DAU trong mot khoang noi dung tep khong.
--
-- KHONG sao chep byte tep: mot tep 50 MiB da co hai ban (than va `low`). Moi mau
-- di MOT luot tu trai sang phai tren `low`, gap lan khop o khe giua hai khoang thi
-- nhay toi dau khoang ke tiep — `pos` chi tang, nen moi mau la tuyen tinh.
--
-- Lan khop bat dau trong khoang thi cung KET THUC trong khoang: sau moi khoang la
-- `\r\n--B`, va khong mau nao chua `\r`. Truoc moi khoang la `\r\n\r\n`, va khong
-- mau nao bat dau bang `\r`/`\n`. Nen khong lan khop nao vat ngang ranh gioi vung.
local function any_in_ranges(low, ranges, find)
    local i, pos = 1, ranges[1][1]
    while true do
        local p = find(low, pos)
        if not p then return false end
        while ranges[i] and ranges[i][2] < p do i = i + 1 end
        if not ranges[i] then return false end
        if p >= ranges[i][1] then return true end
        pos = ranges[i][1]
    end
end

-- `binary = true`, `decode = false` nhu phep quet phang cu tren multipart: byte 0
-- tho la cua dinh dang nhi phan, noi dung part khong percent-encode (RFC 7578).
local function find_nul_text(s, init) return s:find("%00", init, true) end
local function rules_in_ranges(low, ranges, out)
    if #ranges == 0 then return out end
    if any_in_ranges(low, ranges, find_nul_text) then out.arg_null_byte = true end
    if any_in_ranges(low, ranges, find_wrapper) then out.arg_php_wrapper = true end
    if any_in_ranges(low, ranges, find_traversal) then out.arg_traversal = true end
    return out
end

local function check_args(s, decode, binary)
    if not s or s == "" then return nil end
    if decode == nil then decode = true end
    return check_args_lower(s:lower(), decode, binary)
end
_M.check_args = check_args

-- ── Bo phan tich tham so co dau `;` ─────────────────────────────────
-- Dau `;` va `=` NAM TRONG chuoi co nhay khong phai cu phap. Thieu dieu nay thi
-- `name="x; filename=../../inside.php"` bi tach thanh mot tham so `filename`
-- khong he ton tai.
--
-- Moi muc giu CA HAI dang:
--   `raw`       nguyen van tren day, con dau `\`
--   `semantic`  da bo quoted-pair MOT LAN
-- vi ta khong biet parser ha nguon doc kieu nao — PHP, Python, Node moi thu mot
-- kieu — nen luat chay tren ca hai cach doc.
local function parse_parameters(s)
    local out, malformed = {}, false
    local semi = s:find(";", 1, true)
    if not semi then return out, false end

    local i, n = semi + 1, #s
    while i <= n do
        while i <= n do
            local c = s:sub(i, i)
            if c == ";" or c == " " or c == "\t" then i = i + 1 else break end
        end
        if i > n then break end

        local ns = i
        while i <= n do
            local c = s:sub(i, i)
            if c == "=" or c == ";" or c == " " or c == "\t" then break end
            i = i + 1
        end
        local name = s:sub(ns, i - 1):lower()
        while i <= n and (s:sub(i, i) == " " or s:sub(i, i) == "\t") do i = i + 1 end

        if name == "" or s:sub(i, i) ~= "=" then
            malformed = true
            while i <= n and s:sub(i, i) ~= ";" do i = i + 1 end
        else
            i = i + 1
            while i <= n and (s:sub(i, i) == " " or s:sub(i, i) == "\t") do i = i + 1 end

            local raw, semantic, quoted
            if s:sub(i, i) == '"' then
                quoted = true
                i = i + 1
                local rr, uu, closed = {}, {}, false
                while i <= n do
                    local c = s:sub(i, i)
                    if c == '"' then
                        closed = true
                        i = i + 1
                        break
                    elseif c == "\r" or c == "\n" then
                        -- Nhay khong dong an sang dong khac. Parser ha nguon
                        -- ket thuc header o CRLF, nen ta cung dung o day.
                        malformed = true
                        break
                    elseif c == "\\" then
                        local nextc = s:sub(i + 1, i + 1)
                        if nextc == "" or nextc == "\r" or nextc == "\n" then
                            malformed = true
                            break
                        end
                        rr[#rr + 1] = c .. nextc
                        uu[#uu + 1] = nextc
                        i = i + 2
                    else
                        rr[#rr + 1], uu[#uu + 1] = c, c
                        i = i + 1
                    end
                end
                if not closed then malformed = true end
                raw, semantic = table.concat(rr), table.concat(uu)
                while i <= n and (s:sub(i, i) == " " or s:sub(i, i) == "\t") do i = i + 1 end
                if i <= n and s:sub(i, i) ~= ";" then
                    malformed = true
                    while i <= n and s:sub(i, i) ~= ";" do i = i + 1 end
                end
            else
                local vs = i
                while i <= n and s:sub(i, i) ~= ";" do i = i + 1 end
                raw = trim(s:sub(vs, i - 1))
                semantic = raw
                quoted = false
            end

            out[#out + 1] = {
                name = name, raw = raw or "",
                semantic = semantic or "", quoted = quoted,
            }
        end
    end
    return out, malformed
end
_M.parse_parameters = parse_parameters

-- Tra ve MOI gia tri `boundary` khac nhau o cap cao nhat.
--
-- `Content-Type: multipart/form-data; boundary=A; boundary=B` la hop le ve cu
-- phap va parser khac nhau chon khac nhau. Quet voi TAT CA candidate, va van
-- danh dau `bdup` du khong luat nao ban — vi ta khong biet parser ha nguon
-- chon cai nao, nen khong the noi da soi dung cai no dung.
-- So boundary candidate toi da. `scan_one_boundary` quet TOAN BO than mot lan cho
-- MOI boundary, nen chi phi la `so boundary x kich thuoc than` — mot
-- Content-Type khai muoi boundary tren mot than 50 MB thanh 500 MB cong viec tren
-- worker thread. Do la CPU amplification, va `Content-Type` la thu ke gui dat.
--
-- 4 du rong: mot than hop le co DUNG mot boundary. Hai gia tri la da bat thuong
-- (`bdup`), va bon la de cho mot proxy nao do them mot gia tri.
--
-- Vuot tran thi danh dau `bmax` va DUNG LAI — KHONG ha diem, khong bo qua than.
-- Cac boundary da thu van duoc soi; chi cac boundary sau tran thi khong.
local MAX_BOUNDARIES = 4

local function boundaries_of(ct)
    local params, malformed = parse_parameters(ct or "")
    local values, seen = {}, {}
    local status = malformed and "bval" or false
    for i = 1, #params do
        local p = params[i]
        if p.name == "boundary" then
            local v = p.semantic
            if v == "" or #v > 1024 or v:find("[\r\n%z]") then
                status = worse(status, "bval")
            elseif seen[v] then
                -- Gia tri DA CO khong ton them mot lan quet, nen khong tinh vao
                -- tran. Kiem tran TRUOC (ban cu) thi `A;B;C;D;A` bao `bmax` oan
                -- tren mot than chi co bon boundary (review 26-09 diem 4).
            elseif #values >= MAX_BOUNDARIES then
                status = worse(status, "bmax")
            else
                seen[v] = true
                values[#values + 1] = v
            end
        end
    end
    if #values == 0 then return values, status or "nb" end
    if #values > 1 then status = worse(status, "bdup") end
    return values, status
end

-- ── Cat phan theo boundary ──────────────────────────────────────────
--
-- QUYET DINH DA CAN NHAC: dau phan cach phai KHOP DUNG, `--Bxyz` khong tinh.
-- Dung RFC, va no chan viec noi dung file tu che ra phan gia. Danh doi: neu co
-- parser ha nguon khop boundary theo TIEN TO thi ta cat IT hon no. Chua kiem
-- duoc PHP xu ly ra sao; ghi ra day de lan sau do bang mot request that thay vi
-- doan.
--
-- Nguoc lai, cho nao KHONG chac thi cat RONG TAY: nhan ca `\r\n--B` lan `\n--B`
-- tran, va dong trong nhan ca `\r\n\r\n` lan `\n\n`. Bo quet phai la TAP CHA
-- cua parser — cat thua chi ton mot lan quet, cat thieu la mot duong ne.
local function delimiter_at(body, at, delim)
    if at ~= 1 and body:byte(at - 1) ~= 10 then return nil end

    local n, p = #body, at + #delim
    local closing = body:sub(p, p + 1) == "--"
    if closing then p = p + 2 end
    while p <= n do
        local b = body:byte(p)
        if b == 32 or b == 9 then p = p + 1 else break end
    end

    if p > n then return closing and "close" or nil, p end
    if body:sub(p, p + 1) == "\r\n" then
        return closing and "close" or "open", p + 2
    end
    if body:byte(p) == 10 then
        return closing and "close" or "open", p + 1
    end
    return nil
end

local function next_delimiter(body, pos, delim)
    while true do
        local at = body:find(delim, pos, true)
        if not at then return nil end
        local kind, after = delimiter_at(body, at, delim)
        if kind then return kind, at, after end
        pos = at + 1
    end
end

-- Header gap dong (RFC 5322 obs-fold): dong bat dau bang space/tab la phan noi
-- tiep cua dong truoc. Khong go thi `Content-Disposition:` xuong dong roi moi
-- toi `filename=` se lot.
local function unfolded_header_lines(head)
    local lines, current = {}, nil
    for line in (head .. "\n"):gmatch("(.-)\n") do
        if line:sub(-1) == "\r" then line = line:sub(1, -2) end
        if (line:sub(1, 1) == " " or line:sub(1, 1) == "\t") and current then
            current = current .. " " .. trim(line)
            lines[#lines] = current
        else
            current = line
            lines[#lines + 1] = line
        end
    end
    return lines
end

-- `filename*=` la ext-value RFC 5987: percent-encoding MOT LOP. Giai them mot
-- lop nua tao FP that — `a..%252Fb.txt` giai mot lan ra `a..%2Fb.txt` (ten file
-- hop le chua ky tu `%`), giai lan hai thanh `a../b.txt` va ban.
--
-- MEP CO CHU Y: `x%2500.jpg` giai mot lan ra `x%00.jpg` roi mau VAN BAN `%00`
-- van ban. Tuc rieng luat NUL doc them mot lop. Giu vay — app ha nguon giai ma
-- lai ten file la chuyen pho bien va lam sai, va `x%00.jpg` giai them lan nua
-- dung la cai cat chuoi ma luat NUL sinh ra de bat.
local function filename_variants(p)
    local values, seen = {}, {}
    local function add(v)
        if v and not seen[v] then seen[v] = true; values[#values + 1] = v end
    end

    if p.name == "filename*" then
        local decoded_raw = percent_decode_once(p.raw)
        add(decoded_raw)
        if p.quoted then
            add(percent_decode_once(p.semantic))
            add((decoded_raw:gsub("\\(.)", "%1")))
        end
        -- TACH CAU TRUC RFC 5987 — mot view THEM, khong thay view tren.
        --
        -- RFC 5987 dinh nghia gia tri la `charset'language'value`, nen
        --     filename*=UTF-8''%2Ehtaccess
        -- ma chi percent-decode ca chuoi thi ra `UTF-8''.htaccess` — KHONG khop
        -- `.htaccess` trong `APACHE_CONFIG`. Cac ten co DUOI thi van bat duoc nho
        -- `extensions()` (`%2Ephp` -> `.php` van co duoi `php`), nhung ten cau
        -- hinh thi so khop CHINH XAC ca ten, nen tien to lam no truot:
        --     filename*=UTF-8''%2Ehtaccess   -> truot APACHE_CONFIG
        --     filename*=UTF-8''%2Euser%2Eini -> truot PHP_CONFIG
        --
        -- THEM view chu khong SUA view cu: mot client that co the gui gia tri
        -- khong dung dinh dang RFC (thieu hai dau `'`), va view `decoded_raw` o
        -- tren la cai bat duoc truong hop do. Bo no di la doi mot lo hong nay lay
        -- mot lo hong khac.
        --
        -- `percent_decode_once` DUNG MOT LAN tren phan value, y het cac view khac
        -- — xem chu thich ve `x%2500.jpg` ngay tren ham nay. Khong giai hai lan.
        --
        -- Chi ap cho `filename*`, KHONG ap cho `filename=` thuong: mot ten file
        -- hop le duoc phep chua dau `'` (`john's-cv.pdf`), nen cat o dau `'` thu
        -- hai cua `filename=` se lam bien mat phan dau cua ten that.
        local lang_stripped = p.raw:match("^[^']*'[^']*'(.*)$")
        if lang_stripped then
            add(percent_decode_once(lang_stripped))
        end
    else
        add(p.raw)
        if p.quoted then add(p.semantic) end
    end
    return values
end

-- ── Goc nhin CUA PHP len Content-Disposition (main/rfc1867.c) ────────────────
--
-- `parse_parameters` doc tham so theo RFC. PHP doc KHAC, va voi kenh TEN TEP thi
-- goc nhin cua PHP moi quyet dinh: PHP luu tep theo ten NO doc ra. `tools/wafdiff`
-- do 26-09 (3.750 ca): 26/26 ca ten tep nguy hiem PHP thay ma `up_rule` truot deu
-- la NHAY DON — `filename='shell.php'`: `php_ap_getword` hieu nhay don, tokenizer
-- tren thi khong.
--
-- Them goc nhin nay nhu mot BIEN THE nua, KHONG thay goc nhin cu. Kenh ten tep la
-- kenh BAT: them goc nhin chi tang phat hien, khong mo duong ha diem nao. Vung
-- `file` — noi duy nhat duoc ha diem — KHONG dung cac ham nay: no doi than o dang
-- chuan tac ma moi parser doc giong nhau (`file_ranges`).
--
-- Mo phong ba ham C (doc ma nguon 26-09):
--   php_ap_getword(line, stop)  quet toi `stop`, bo qua noi dung trong nhay kep
--                               HOAC nhay don (gach nguoc + nhay la ky tu thoat),
--                               roi bo moi `stop` lien tiep.
--   php_ap_getword_conf(str)    bo khoang trang dau; mo bang nhay -> toi nhay dong
--                               cung loai; khong nhay -> toi khoang trang.
--   substring_conf              gach nguoc + (gach nguoc | nhay dong) -> ky tu sau.
-- Key la phan truoc `=` KHONG trim, so bang `strcasecmp`; `filename` SAU CUNG
-- thang; khong co `filename*`. Header la chuoi C: NUL cat gia tri.
local SLASH = 92
local function php_getword(s, pos, stop)
    local n, i = #s, pos
    while i <= n and s:byte(i) ~= stop do
        local q = s:byte(i)
        if q == 34 or q == 39 then
            i = i + 1
            while i <= n and s:byte(i) ~= q do
                if s:byte(i) == SLASH and s:byte(i + 1) == q then i = i + 2 else i = i + 1 end
            end
            if i <= n then i = i + 1 end
        else
            i = i + 1
        end
    end
    local word = s:sub(pos, i - 1)
    while i <= n and s:byte(i) == stop do i = i + 1 end
    return word, i
end

local function php_getword_conf(s)
    s = s:gsub("^%s+", "")
    if s == "" then return "" end
    local q, body = s:byte(1), nil
    if q == 34 or q == 39 then body = s:sub(2) else q, body = nil, s:match("^%S*") end
    local out, i, n = {}, 1, #body
    while i <= n and body:byte(i) ~= q do
        local c, nx = body:byte(i), body:byte(i + 1)
        if c == SLASH and (nx == SLASH or (q and nx == q)) then
            out[#out + 1] = string.char(nx); i = i + 2
        else
            out[#out + 1] = string.char(c); i = i + 1
        end
    end
    return table.concat(out)
end

-- Ten tep PHP doc ra tu MOT gia tri Content-Disposition, hoac nil.
local function php_filename(cd)
    local s = (cd:match("^[^%z]*")):gsub("^%s+", "")
    local pos, n, filename = 1, #s, nil
    while pos <= n do
        local pair
        pair, pos = php_getword(s, pos, 59)              -- `;`
        while pos <= n and s:sub(pos, pos):match("%s") do pos = pos + 1 end
        if pair:find("=", 1, true) then
            local key, kpos = php_getword(pair, 1, 61)   -- `=`
            if key:lower() == "filename" then filename = php_getword_conf(pair:sub(kpos)) end
        end
    end
    return filename
end
_M.php_filename = php_filename

-- Tra ve `status, up_rule`. Luat tham so khop trong gia tri ten tep ghi vao TAP
-- `fn_set` — vung `filename` cua `_M.scan`.
--
-- `up_rule` la KENH RIENG, khong tranh cho voi luat tham so. Cung lap
-- luan da tach `waf_arg` khoi `waf_wp_path`: hai cau hoi khac nhau ve cung mot
-- byte. `check_args` hoi "gia tri nay co chua mau tan cong khong";
-- `upload.check_filename` hoi "server co chay file nay khong". Mot
-- `filename="shell.php"` KHONG chua mau nao cua `check_args` — khong `..`,
-- khong `php://`, khong `%00` — nen gop hai ket qua vao mot duong `return` la
-- lam P1 bien mat o dung nhom no sinh ra de bat.
--
-- Nguoc lai, `filename="../../x.php"` khop CA HAI, va luc do ta muon CA HAI so
-- dem, khong phai mot.
local function scan_disposition_headers(head, status, fn_set)
    local lines = unfolded_header_lines(head)
    local up_rule = nil
    for i = 1, #lines do
        local line = lines[i]
        local colon = line:find(":", 1, true)
        if colon and trim(line:sub(1, colon - 1)):lower() == "content-disposition" then
            local params, malformed = parse_parameters(line:sub(colon + 1))
            if malformed then status = worse(status, "disp") end
            for j = 1, #params do
                local p = params[j]
                if p.name == "filename" or p.name == "filename*" then
                    local variants = filename_variants(p)
                    for k = 1, #variants do
                        local v = variants[k]
                        -- BAO CAO do dai, KHONG cat. Vung header da bi chan boi
                        -- MAX_HDR_LEN nen soi tron gia tri khong the vo han.
                        -- Cat o 512 roi moi kiem — cai ban truoc lam — la de ke
                        -- tan cong don 512 byte cho traversal nam ra ngoai.
                        if #v > MAX_FN_LEN then status = worse(status, "len") end
                        -- `worse_up` giu luat NGHIEM TRONG NHAT, khong phai luat
                        -- DAU TIEN. Voi `web.config` o part 1 va `shell.php` o
                        -- part 2, giu cai dau lam so lieu bao `foreign_config`
                        -- va mat `php_ext` — tuc chinh con so dung de quyet dinh
                        -- trong so bi lam ban boi thu tu part, la thu ke gui
                        -- dieu khien.
                        up_rule = upload.worse_up(up_rule,
                                                  upload.check_filename(v))
                        -- Cung ly do cho luat tham so: TAP qua moi bien the va
                        -- moi part, khong dung o lan khop dau.
                        rules_in_lower(v:lower(), false, false, fn_set)
                    end
                end
            end
            -- Goc nhin CUA PHP (`php_filename`): mot bien the NUA, cung hai kenh.
            local pf = php_filename(line:sub(colon + 1))
            if pf and pf ~= "" then
                if #pf > MAX_FN_LEN then status = worse(status, "len") end
                up_rule = upload.worse_up(up_rule, upload.check_filename(pf))
                rules_in_lower(pf:lower(), false, false, fn_set)
            end
        end
    end
    return status, up_rule
end

-- Tra ve `vi_tri_ket_thuc_header, da_bi_cat`.
local function header_separator(body, hs, next_boundary)
    -- PHAN KHONG CO HEADER NAO: dong trong nam ngay sau dau phan cach. Khong
    -- xu ly rieng thi khong tim thay `\r\n\r\n` nao va `hdr` ban OAN tren mot
    -- than hoan toan hop le.
    if body:sub(hs, hs + 1) == "\r\n" or body:byte(hs) == 10 then
        return hs, false
    end

    local b1 = body:find("\r\n\r\n", hs, true)
    local b2 = body:find("\n\n", hs, true)
    local he
    if b1 and b2 then he = math.min(b1, b2) else he = b1 or b2 end
    if he and next_boundary and he >= next_boundary then he = nil end
    if he and he - hs <= MAX_HDR_LEN then return he, false end

    local cap = hs + MAX_HDR_LEN
    if next_boundary then cap = math.min(cap, next_boundary - 1) end
    return math.min(cap, #body + 1), true
end

-- Tra ve `status, up_rule`. Luat tham so khop trong ten tep ghi vao TAP `fn_set`.
--
-- MOI LOI RA phai mang theo `up_rule`. Bo sot mot cai thi P1 mat tin hieu TRONG
-- IM LANG o dung nhom do — vd tran `MAX_PARTS`: mot upload 70 phan trong do
-- phan thu 3 la `shell.php` se thoat o nhanh `n` va bao cao "khong co gi". Do la
-- khuon loi da cat 4 thang cua `wp_paths.mark()`.
--
-- V7 bo kenh soi NOI DUNG tung part (`arg_field`/`arg_content`, cap 8 KB cho
-- tep): no chi la telemetry cua `arg_origin`. Vung noi dung gio do `_M.scan` tach
-- bang `file_ranges` — theo dung parser PHP, khong theo tokenizer nay.
local function scan_one_boundary(body, boundary, initial_status, fn_set)
    local delim = "--" .. boundary
    local status = initial_status or false
    local up_rule = nil
    local kind, _, after = next_delimiter(body, 1, delim)
    -- HAI gia tri o MOI loi ra, ke ca loi ra nay noi `up_rule` chac chan la
    -- `nil`. Viet du ra la mot rang buoc de doc va de hop dong [27a] ghim duoc:
    -- neu mot loi ra duoc phep ngan hon, thi khi ai do them mot truong se khong
    -- con cach nao phan biet "co y bo qua" voi "quen".
    if not kind then return worse(status, "bd"), nil end

    local nparts, saw_open = 0, false
    while kind do
        -- Kiem `close` TRUOC tran. Dau dong ket thuc khong phai mot phan, va
        -- dem no vao lam upload dung 64 file bi gan `n` — mot "khong biet" gia.
        if kind == "close" then return status, up_rule end
        if nparts >= MAX_PARTS then return worse(status, "n"), up_rule end
        nparts, saw_open = nparts + 1, true

        -- Tim dau phan cach ke tiep tu DAU vung header, khong tu cuoi no: cai
        -- cap 2 KB co the nam vuot qua dau phan cach ke tiep va the la mat han
        -- mot phan — tuc cat IT hon parser.
        local next_kind, next_at, next_after = next_delimiter(body, after, delim)
        local he, capped = header_separator(body, after, next_at)
        if capped then status = worse(status, "hdr") end

        -- KHONG `return` khi mot ten tep khop luat tham so. Ban truoc 19-09 lam
        -- vay, va do la mot duong ne THAT:
        --     part 1  filename="../../photo.jpg"   -> khop arg_traversal
        --     part 2  filename="shell.php"         -> KHONG BAO GIO duoc soi
        -- Luat tham so vao TAP `fn_set`, `up_rule` gop bang `worse_up`, va vong
        -- lap duyet tiep het cac part.
        local part_up
        status, part_up = scan_disposition_headers(body:sub(after, he - 1),
                                                   status, fn_set)
        -- `up_rule`: giu luat NGHIEM TRONG NHAT tren toan bo cac phan.
        up_rule = upload.worse_up(up_rule, part_up)

        kind, after = next_kind, next_after
    end

    -- Den day nghia la KHONG gap dau dong ket thuc: mot backend co the van chap
    -- nhan cac part phia truoc, nhung ta khong biet con part nao nua khong.
    if saw_open then status = worse(status, "ending") end
    return status, up_rule
end

-- Tra ve `status, up_rule`. Vung `filename` ghi vao TAP `fn_set`.
local function filename_rule(body, family, ct, fn_set)
    -- HAI gia tri o moi loi ra, cung ly le nhu `scan_one_boundary`.
    if family ~= "multipart" then return nil, nil end
    local boundaries, status = boundaries_of(ct)
    if #boundaries == 0 then return status, nil end

    local combined = status or false
    local up_rule = nil
    for i = 1, #boundaries do
        -- `Content-Type` co the khai nhieu gia tri boundary. `fn_set` la MOT tap
        -- cho moi candidate, nen boundary dau tien khop khong che cac boundary sau.
        local st, up = scan_one_boundary(body, boundaries[i], combined, fn_set)
        combined = worse(combined, st)
        -- Cung `worse_up` nhu hai tang tren. Tang nay gop qua NHIEU BOUNDARY, va bo
        -- sot no o day thi boundary dau tien khop se che cac boundary sau — dung
        -- lo ma [27d] bat duoc khi toi sua hai tang tren ma quen tang nay.
        up_rule = upload.worse_up(up_rule, up)
        -- KHONG `return` o day, cung ly do nhu hai tang tren.
    end
    return combined, up_rule
end

-- Dem `&` thay vi `get_post_args()`: ham do CAT O 100 va khong bao gi, ma 500
-- tham so moi la truong hop dang ngo nhat.
local function count_args(body, family)
    if family ~= "urlencoded" or body == "" then return nil end
    local n, pos = 1, 1
    while true do
        local p = body:find("&", pos, true)
        if not p then return n end
        n, pos = n + 1, p + 1
    end
end

-- ── Vung `file`: CHUNG MINH byte nao la noi dung tep ────────────────────────
--
-- `_M.scan` chia than multipart thanh ba vung. Vung `file` — noi registry duoc
-- doi luat tham so sang luat khac (`region_rule`) — CHI ton tai khi chung minh
-- duoc bang SU CO MAT rang cac khoang do CHAC CHAN la noi dung tep: `file_ranges`
-- doc than theo DUNG parser PHP va tra ve cac khoang noi dung tep. Khong chung
-- minh duoc thi KHONG co vung `file`: ca than la `nonfile`, giu nguyen diem —
-- "khong biet" khac "khong co". Khong co gioi han do dai nao, khong co co nao de
-- suy.
--
-- Vi sao chung minh ma khong doc bang tokenizer rieng: V5 doc "part nay la tep"
-- bang tokenizer CUA MINH, lech PHP o bon cho (`filename*`, Content-Disposition
-- trung, khoang trang truoc `=`, nhay don). Moi cho lech la mot cach bien mot
-- form field thanh "tep" de payload trong no bi ha diem.
--
-- "CHAC CHAN" nghia la than o DANG CHUAN TAC ma trinh duyet gui — dang ma PHP
-- (`main/rfc1867.c`) va moi parser khac doc ra giong nhau. Lech mot byte thi
-- KHONG chung minh gi: ca than giu nguyen diem. KHONG sua tung cho lech — bon
-- cho lech da biet cua tokenizer la bang chung cuoc dua do khong thang duoc.
--
-- Nhung diem dang chuan tac phai khop PHP TUNG BYTE (doc tu rfc1867.c 26-09):
--   · boundary: PHP lay bang CHUOI CON `strstr(ct, "boundary")`, gia tri khong
--     nhay dung o `,`/`;`. Chi nhan `multipart/form-data; boundary=X` (hoac X
--     trong nhay) voi X la bchars khong `,` `;` khoang trang: o dang do moi cach
--     doc ra cung X.
--   · noi dung mot part ket thuc o `\n--X` DAU TIEN — PHP khop theo `\n`, KHONG
--     doi `\r`, va theo TIEN TO. Nen tim dung chuoi do roi DOI no la `\r\n--X`
--     theo sau boi `\r\n` hoac `--`. Tim thang `\r\n--X` la SAI: mot `\n--X` tran
--     trong noi dung tep lam PHP cat tep o do va doc phan sau thanh FORM FIELD,
--     trong khi ta van coi la tep va xoa mat payload.
--   · sau `--X--` PHP VAN tim tiep dong `--X` — no khong coi dong ket thuc la
--     het. Byte nao sau `--X--\r\n` cung la khong chuan tac.
--   · header: PHP lay Content-Disposition DAU TIEN, so `filename` bang
--     `strcasecmp` (khong co `filename*`), KHONG trim key, hieu ca nhay don, va
--     doc header nhu chuoi C (dung o NUL). Chi nhan dung MOT Content-Disposition
--     dang `form-data; name="..."` hoac `form-data; name="..."; filename="..."`
--     (khong `"`, `\` trong gia tri), cong toi da MOT Content-Type.
--
-- Tran `MAX_PARTS` cung la "khong chung minh" (`pf=n`): so do CPU, khong phai do
-- ngu nghia. Nang no chi khi co so lieu `pf=n` tren upload that.

-- Boundary o dang ma PHP va ta doc ra GIONG NHAU, hoac nil.
local function canonical_boundary(ct)
    if type(ct) ~= "string" then return nil end
    local b = ct:match('^multipart/form%-data; ?boundary="([^"]*)"$')
           or ct:match('^multipart/form%-data; ?boundary=([^"]*)$')
    if not b or #b > 70 or not b:find("^[%w'()+_./:=?-]+$") then return nil end
    return b
end

-- Ly do KHONG chung minh duoc (cot `pf=`). Di qua ham nay chu KHONG viet
-- `return nil, "..."`: trong file nay dang do la MA SCAN — hop dong SCAN_STATUS
-- trong `contract_test.lua` quet dung dang do de bat ma `scan` bi quen. Ly do
-- chung minh la ho KHAC: chi ra cot `pf=`, khong bao gio vao `scan=` hay counter
-- `waf:v2:scan:*`, nen KHONG duoc them vao `SCAN_STATUS`.
local function no_proof(why) return nil, why end

-- Vung header cua MOT part (khong ke CRLF ket thuc): "file", "field", hoac
-- `nil, ly_do`.
local function canonical_part_head(head)
    local cd, has_ct = nil, false
    for line in (head .. "\r\n"):gmatch("(.-)\r\n") do
        -- CR/LF le hoac NUL trong mot dong: PHP cat dong o `\n` va doc header nhu
        -- chuoi C, nen tu day hai ben co the thay hai header khac nhau.
        if line:find("[\r\n%z]") then return no_proof("hdr") end
        local name, value = line:match("^([%w-]+): (.*)$")
        if not name then return no_proof("hdr") end
        name = name:lower()
        if name == "content-disposition" then
            if cd then return no_proof("cd") end
            cd = value
        elseif name == "content-type" and not has_ct then
            has_ct = true
        else
            return no_proof("hdr")
        end
    end
    if not cd then return no_proof("cd") end
    if cd:find('^form%-data; name="[^"\\]*"; filename="[^"\\]*"$') then
        return "file"
    end
    if cd:find('^form%-data; name="[^"\\]*"$') then return "field" end
    return no_proof("cd")
end

-- Cac khoang `{dau, cuoi}` la NOI DUNG TEP da chung minh, hoac `nil, ly_do`.
-- Ly do ra log o cot `pf=`:
--   ct   Content-Type khong chuan tac    pre  co byte truoc dong phan cach dau
--   hdr  vung header cua mot part        cd   Content-Disposition
--   dl   dau phan cach sau noi dung      end  thieu dong ket thuc / co byte sau no
--   n    hon MAX_PARTS phan
local function file_ranges(body, ct)
    local b = canonical_boundary(ct)
    if not b then return no_proof("ct") end
    local open = "--" .. b .. "\r\n"
    if body:sub(1, #open) ~= open then return no_proof("pre") end
    local next_delim = "\n--" .. b
    local ranges, pos, nparts = {}, #open + 1, 0
    while true do
        nparts = nparts + 1
        if nparts > MAX_PARTS then return no_proof("n") end
        local he = body:find("\r\n\r\n", pos, true)
        if not he or he - pos > MAX_HDR_LEN then return no_proof("hdr") end
        local kind, why = canonical_part_head(body:sub(pos, he - 1))
        if not kind then return nil, why end
        local cs = he + 4
        local at = body:find(next_delim, cs, true)
        if not at then return no_proof("end") end
        if at <= cs or body:byte(at - 1) ~= 13 then return no_proof("dl") end
        if kind == "file" and at - 2 >= cs then
            ranges[#ranges + 1] = { cs, at - 2 }
        end
        local after = at + #next_delim
        local tail = body:sub(after, after + 1)
        if tail == "\r\n" then
            pos = after + 2
        elseif tail == "--" then
            local rest = body:sub(after + 2)
            if rest ~= "" and rest ~= "\r\n" then return no_proof("end") end
            return ranges
        else
            return no_proof("dl")
        end
    end
end

-- Than goc TRU cac khoang noi dung tep. Chi bo NOI DUNG — header, dau phan cach
-- va CRLF quanh chung van o lai, nen hai manh ghep lai khong tao ra mau moi.
local function projection(body, ranges)
    local out, pos = {}, 1
    for i = 1, #ranges do
        out[#out + 1] = body:sub(pos, ranges[i][1] - 1)
        pos = ranges[i][2] + 1
    end
    out[#out + 1] = body:sub(pos)
    return table.concat(out)
end

-- CHI de kiem: `tools/wafdiff` doi chieu hai ham nay voi parser multipart THAT
-- cua PHP (roadmap muc 3). Khong module nao cua WAF goi chung qua `_M`.
_M.file_ranges = file_ranges
_M.projection  = projection

function _M.scan(body, ct)
    assert(type(body) == "string", "body_core.scan: body phai la chuoi")
    local family = ct_family(ct)
    local low    = body:lower()

    -- ── V7: BA VUNG, moi vung bao TAP luat tham so khop trong no ─────────────
    --
    -- Bo quet KHONG chon va KHONG xep hang giua cac bang chung (review 26-09 lan
    -- 2: "phat fact theo vung doc lap, policy quyet dinh"). V4–V6 ep moi thu vao
    -- MOT `arg_rule` roi gan nhan `arg_origin`, va moi lan chon — thu tu part,
    -- "luat ngoai tep luon thang", `ARG_RANK` — la mot cho ke gui dieu khien duoc.
    --
    --   nonfile   moi byte CHUA chung minh duoc la noi dung tep. Khong phai
    --             multipart, hoac `proof` khac "ok": CA THAN, y nhu phep quet phang
    --             cu. `proof = "ok"`: ban chieu (header, form field, dau phan cach)
    --             quet `binary = false` — mot NUL tho trong field la tin hieu.
    --   file      noi dung tep, CHI khi `proof = "ok"`. Quet TRON, khong cat.
    --   filename  gia tri `filename`/`filename*` cua moi part, moi bien the.
    --
    -- `nonfile` CO chua vung header, nen `../` trong ten tep nam o ca `nonfile`
    -- lan `filename`. Khong bi dem hai lan: policy gop CUNG luat qua cac target
    -- bang max. Doi luat theo vung (`../` trong tep -> luat observe) la viec cua
    -- `registry.region_rule`, khong phai cua ham nay.
    local fn_set = {}
    local fn_trunc, up_rule = filename_rule(body, family, ct, fn_set)

    local nonfile, file, proof, ranges = {}, {}, nil, nil
    if family == "multipart" then
        ranges, proof = file_ranges(body, ct)
        if ranges then proof = "ok" end
    end
    if ranges then
        -- `lower()` giu nguyen do dai byte, nen khoang cua `file_ranges` (do tren
        -- `body`) dung duoc tren `low`.
        rules_in_lower(projection(low, ranges), false, false, nonfile)
        rules_in_ranges(low, ranges, file)
    else
        -- Khong tach duoc tep khoi field: quet phang `binary = true` voi
        -- multipart/other, neu khong moi byte 0 cua mot tep thanh `arg_null_byte`.
        rules_in_lower(low, family == "urlencoded",
                       family == "multipart" or family == "other", nonfile)
    end

    return {
        family = family,
        spill  = false,
        source = "memory",
        scan   = "ok",
        len    = #body,
        -- `<?PHP` cung la PHP hop le; `<?=` la short echo tag. KHONG bat `<?`
        -- tran: `<?xml` se lam nhieu moi upload SVG/RSS.
        php    = low:find("<?php", 1, true) ~= nil or low:find("<?=", 1, true) ~= nil,
        nargs  = count_args(body, family),
        -- Mang da sap xep, `nil` khi vung khong co luat nao HOAC khong ton tai
        -- (`file` ngoai `proof = "ok"`). Da soi hay chua thi doc `scan`.
        nonfile_rules  = rule_list(nonfile),
        file_rules     = rule_list(file),
        filename_rules = rule_list(fn_set),
        fn_trunc = fn_trunc,
        -- P1. `nil` gop BA truong hop: khong phai multipart, khong co
        -- `filename=` nao, hoac da soi va khong co duoi chay duoc. Ba nguyen
        -- nhan nhung CUNG mot ket luan "khong co gi de bao", nen mot gia tri la
        -- du. Khac han `php`, noi `nil` = CHUA SOI va la mot y nghia thu ba thuc
        -- su — dung cho `waf_body_php` phai so `== true`.
        up_rule  = up_rule,
        -- LY DO khi khong chung minh duoc — cot `pf=`, de do duoc upload that hong
        -- o buoc nao. `nil` ngoai multipart.
        proof    = proof,
    }
end

-- ── Dong goi de di qua ranh gioi thread ─────────────────────────────
-- `ngx.run_worker_thread` chi truyen duoc kieu vo huong, khong truyen bang Lua.
local SEP = string.char(31)

local function enc(v)
    if v == nil then return "-" end
    if v == true then return "1" end
    if v == false then return "0" end
    return tostring(v)
end

-- Mang luat <-> chuoi `a,b` de di qua ranh gioi thread. Ten luat la [%w_] nen
-- khong bao gio chua `,` hay `SEP`.
local function list_str(t) return t and table.concat(t, ",") or nil end

function _M.pack(r)
    -- V7 thay bay truong (`arg_rule`, `fnm`, `fn_rule`, `arg_origin`, `arg_field`,
    -- `arg_content`, `fields_complete`) bang BA VUNG. PHAI nang phien ban khi doi
    -- truong: `unpack` gac bang `#f ~= <so truong>`, nen mot ban `pack` moi gap
    -- mot ban `unpack` cu se tra `bad_payload` — TRONG IM LANG, va chi voi than
    -- DA SPILL, tuc dung nhom upload lon. Doi phien ban lam cho su khong khop do
    -- CO TEN.
    --
    -- Moi truong di qua `enc(` — hop dong [27c] dem `enc(` de doi chieu so truong
    -- voi `unpack`.
    return table.concat({
        "V7", enc(r.family), enc(r.len), enc(r.php), enc(r.nargs),
        enc(list_str(r.nonfile_rules)), enc(list_str(r.file_rules)),
        enc(list_str(r.filename_rules)),
        enc(r.fn_trunc), enc(r.scan), enc(r.up_rule), enc(r.proof),
    }, SEP)
end

-- ── DANH SACH TRANG THAI `scan`, MOT NGUON DUY NHAT ─────────────────────────
--
-- Truoc 25-09 co HAI danh sach: mot o day (ngam, rai rac trong ma cua ba file) va
-- mot trong `telemetry.lua` (`local SCANS = {...}`, go tay). Chung lech nhau
-- 7/11 ma: `telemetry` thieu sau ma cua `body_worker.lua` (`spill_path`,
-- `spill_open`, `spill_seek`, `spill_big`, `spill_read`, `spill_short`) va
-- `bad_payload` cua chinh file nay.
--
-- Hau qua: counter `waf:v2:scan:spill_open` VAN duoc ghi nhung `snapshot()` khong
-- doc ra — bang so lieu thieu lang le dung cac ma noi request that su hong. Va
-- hop dong toi viet de chan chuyen do chi quet `body.lua`, nen no BAO XANH trong
-- khi bo sot bay ma. Lan thu hai cung mot phep kiem bo sot: lan truoc toi sua no
-- quet hai DANG trong mot file, lan nay la hai FILE khac.
--
-- Nen dat o day, va o day la dung cho: `body_core` la module ma ca ba ben da dung
-- chung (`body_worker` require no de goi `pack_error`, `body.lua` require no de
-- goi `scan`/`unpack`, va no la Lua THUAN nen `telemetry` require duoc ma khong
-- keo theo phu thuoc `ngx`).
--
-- THEM MOT MA MOI thi them vao day, khong them o `telemetry.lua`. Hop dong trong
-- `contract_test.lua` ghim nguoc lai: moi chuoi truyen cho `pack_error` va moi
-- ma trong `body.lua` phai co mat trong bang nay.
_M.SCAN_STATUS = {
    -- da soi xong
    "ok",
    -- than rong that (`get_body_file()` tra nil): KHONG phai vung mu
    "empty",
    -- khong soi duoc, o tang truy cap `body.lua`
    "nothread",      -- `ngx.run_worker_thread` khong co (thread_pool tat)
    "spill_thread",  -- goi thread that bai
    "spill_worker",  -- worker tra loi
    -- khong soi duoc, o trong worker (`body_worker.lua`)
    "spill_path",    -- duong dan file tam khong hop le
    "spill_open",    -- khong mo duoc file tam
    "spill_seek",    -- seek that bai
    "spill_big",     -- vuot gioi han doc
    "spill_read",    -- doc that bai
    "spill_short",   -- doc thieu byte
    -- goi tin giua worker va tien trinh chinh bi hong (`unpack` o file nay)
    "bad_payload",
}

function _M.pack_error(reason, len)
    return table.concat({ "E", enc(reason), enc(len) }, SEP)
end

local function split(s)
    local out, pos = {}, 1
    while true do
        local p = s:find(SEP, pos, true)
        if not p then out[#out + 1] = s:sub(pos); return out end
        out[#out + 1], pos = s:sub(pos, p - 1), p + 1
    end
end

-- KHONG duoc viet `(v == "-" or v == "") and nil or v`. Do la BAY TAM GIAC cua
-- Lua: khi dieu kien dung, `and nil` ra nil, roi `nil or v` ra... V. Bieu thuc
-- do KHONG BAO GIO tra ve nil duoc.
--
-- Hau qua neu de nguyen: moi truong rong quay ve tu worker thread mang chuoi
-- `"-"` thay vi nil. Cot log van in ra `-` nen NHIN GIONG HET, nhung trong ctx
-- thi `up_rule = "-"` la mot gia tri THAT — no truthy, no pha phan biet
-- nil/false ma ca thiet ke nay dua vao, va no lam `notable` trong waf_logger
-- dung voi MOI than da spill. Test "pack/unpack giu nil" bat duoc cho nay.
local function dec(v)
    if v == "-" or v == "" then return nil end
    return v
end
local function dec_bool(v) if v == "1" then return true elseif v == "0" then return false end end
local function dec_stat(v) if v == "0" then return false end return dec(v) end
local function dec_list(v)
    v = dec(v)
    if not v then return nil end
    local out = {}
    for id in v:gmatch("[^,]+") do out[#out + 1] = id end
    return out
end

function _M.unpack(payload)
    if type(payload) ~= "string" then return nil, "bad_payload" end
    local f = split(payload)
    if f[1] == "E"  then return nil, f[2] or "worker", tonumber(f[3]) end
    -- CHI nhan V7. KHONG chap nhan ban cu nhu mot ban tuong thich nguoc, va do la
    -- quyet dinh co y: `body_worker.lua` chay trong MOT VM RIENG do
    -- `ngx.run_worker_thread` dung len, nhung ca hai ben deu nap tu CUNG mot file
    -- tren dia — nen chung khong bao gio lech phien ban TRU trong khoang giua hai
    -- lan `nginx -s reload` cua mot lan deploy. Trong khoang do, `bad_payload` la
    -- cau tra loi DUNG: no co ten, di vao `waf:v2:scan:bad_payload`, va chi anh
    -- huong than da spill. Chap nhan V6 se lam khoang do trong nhu binh thuong
    -- trong khi ba vung lang le bang nil.
    if f[1] ~= "V7" or #f ~= 12 then return nil, "bad_payload" end
    return {
        family   = dec(f[2]),
        len      = tonumber(f[3]),
        php      = dec_bool(f[4]),
        nargs    = tonumber(dec(f[5]) or ""),
        nonfile_rules  = dec_list(f[6]),
        file_rules     = dec_list(f[7]),
        filename_rules = dec_list(f[8]),
        fn_trunc = dec_stat(f[9]),
        scan     = dec(f[10]) or "ok",
        up_rule  = dec(f[11]),
        proof    = dec(f[12]),
    }
end

return _M
