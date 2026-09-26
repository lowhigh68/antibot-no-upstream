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
-- Do dai NOI DUNG mot phan duoc soi. Mot tep dinh kem 2 MB thi soi tron la chi
-- phi that tren duong request, va `find_traversal`/`find_wrapper` deu la quet
-- tuyen tinh. 8 KB chon theo hai lap luan:
--   · mot payload traversal that dai vai tram byte (do duoc: botnet 77..242 byte),
--     nen 8 KB du rong de khong bao gio cat mat mot payload tham so.
--   · mot tep that thi 8 KB dau la header cua dinh dang (PNG/JPEG/PDF/ZIP), noi
--     `../` khong xuat hien tu nhien — nen cat o day KHONG lam mat tin hieu that.
-- Khi cat, danh dau `ct` vao `fn_trunc` de doc log biet minh dang xem mot phan.
--
-- Tu V6 vung cat nay CHI con anh huong cot `acnt=` (telemetry). V5 dat quyet dinh
-- reroute len `acnt`, nen `../` nam sau 8 KB dau cua mot tep lon lam quyet dinh
-- do khong bao gio dat duoc. V6 quyet dinh bang `file_ranges`, noi khong co gioi
-- han nao theo do dai.
local MAX_PART_LEN = 8192

-- Do NGHIEM TRONG, khong phai do "muon xu ly truoc". Cot `fntr=` ton tai de noi
-- CAN LAM GI TIEP, nen khi cham nhieu tran thi giu lai cai doi hanh dong lon
-- nhat.
--
--   stop    da tim thay, dung lai — BINH THUONG
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
    stop = 1, len = 2, n = 3,
    disp = 4, ending = 4,
    bd = 5, bdup = 5, bval = 5,
    -- `ct`: noi dung MOT TEP da bi cat o `MAX_PART_LEN` trong phep soi TUNG PHAN.
    -- Xep CAO HON `stop`/`len` de cot `fntr=` khong bi mot ghi chu ve do dai che
    -- mat. Tu V6 bang nay KHONG gac `arg_origin` nua: no la bang MUC DO de bao
    -- cao, va V5 suy "da soi tron" tu no — nen moi tep > 8 KB mat duong reroute
    -- (review 26-09 diem 2).
    ct = 6,
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

local function find_wrapper(s)
    local first
    for i = 1, #FIXED_WRAPPERS do
        local p = s:find(FIXED_WRAPPERS[i], 1, true)
        if p and (not first or p < first) then first = p end
    end
    local p = s:find("compress%.[%w_]+://")
    if p and (not first or p < first) then first = p end
    return first
end

-- `..` PHAI di kem `/` hoac `\`. Thieu ve sau thi `bao-cao..pdf` va moi so thap
-- phan deu ban.
local function find_traversal(s)
    local pos = 1
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

-- Tra ve `arg_rule, status, up_rule`.
--
-- `up_rule` la KENH RIENG, khong tranh cho `return` voi `arg_rule`. Cung lap
-- luan da tach `waf_arg` khoi `waf_wp_path`: hai cau hoi khac nhau ve cung mot
-- byte. `check_args` hoi "gia tri nay co chua mau tan cong khong";
-- `upload.check_filename` hoi "server co chay file nay khong". Mot
-- `filename="shell.php"` KHONG chua mau nao cua `check_args` — khong `..`,
-- khong `php://`, khong `%00` — nen gop hai ket qua vao mot duong `return` la
-- lam P1 bien mat o dung nhom no sinh ra de bat.
--
-- Nguoc lai, `filename="../../x.php"` khop CA HAI, va luc do ta muon CA HAI so
-- dem, khong phai mot.
local function scan_disposition_headers(head, status)
    local lines = unfolded_header_lines(head)
    local up_rule    = nil
    local first_arg  = nil     -- lan khop `check_args` DAU TIEN (hop dong cu)
    local arg_status = nil     -- `status` tai dung luc do, de giu nghia `stop`
    local has_filename = false -- phan nay la TEP DINH KEM hay FORM FIELD (V4)
    for i = 1, #lines do
        local line = lines[i]
        local colon = line:find(":", 1, true)
        if colon and trim(line:sub(1, colon - 1)):lower() == "content-disposition" then
            local params, malformed = parse_parameters(line:sub(colon + 1))
            if malformed then status = worse(status, "disp") end
            for j = 1, #params do
                local p = params[j]
                if p.name == "filename" or p.name == "filename*" then
                    -- Dat o day chu khong sau vong lap `variants`: mot
                    -- `filename=""` rong VAN la mot tep dinh kem theo RFC 7578,
                    -- va `filename_variants` co the tra bang rong cho no. Doc su
                    -- CO MAT cua tham so, khong doc gia tri.
                    has_filename = true
                    local variants = filename_variants(p)
                    for k = 1, #variants do
                        local v = variants[k]
                        -- BAO CAO do dai, KHONG cat. Vung header da bi chan boi
                        -- MAX_HDR_LEN nen soi tron gia tri khong the vo han.
                        -- Cat o 512 roi moi kiem — cai ban truoc lam — la de ke
                        -- tan cong don 512 byte cho traversal nam ra ngoai.
                        if #v > MAX_FN_LEN then status = worse(status, "len") end
                        -- P1 chay TRUOC va KHONG `return`.
                        --
                        -- `worse_up` giu luat NGHIEM TRONG NHAT, khong phai luat
                        -- DAU TIEN. Voi `web.config` o part 1 va `shell.php` o
                        -- part 2, giu cai dau lam so lieu bao `foreign_config`
                        -- va mat `php_ext` — tuc chinh con so dung de quyet dinh
                        -- trong so bi lam ban boi thu tu part, la thu ke gui
                        -- dieu khien.
                        up_rule = upload.worse_up(up_rule,
                                                  upload.check_filename(v))
                        local rule = check_args(v, false, false)
                        -- `arg_rule` DUNG LAI o lan khop dau (hop dong cua
                        -- `check_args`, va so lieu cu doc theo no), nhung P1 thi
                        -- KHONG: neu return o day thi mot `filename` khop
                        -- `check_args` o part 1 lam moi part phia sau khong bao
                        -- gio duoc `check_filename` soi. `../../a.jpg` roi
                        -- `shell.php` la duong ne that.
                        if rule and not first_arg then
                            first_arg  = rule
                            arg_status = worse(status, "stop")
                        end
                    end
                end
            end
        end
    end
    -- Da quet HET moi dong header cua phan nay. Tra `first_arg` neu co — gia tri
    -- y HET nhu ban cu voi `arg_rule`, nhung `up_rule` gio da thay moi
    -- `filename` trong phan, khong dung o cai dau tien khop `check_args`.
    --
    -- Gia tri thu TU (`has_filename`) la thu V4 can: no phan biet mot phan la TEP
    -- DINH KEM voi mot FORM FIELD, va do la thong tin duy nhat trong vung header
    -- noi len dieu do. RFC 7578: mot phan co `filename` la mot tep; khong co thi
    -- no la mot truong form thuong, va gia tri cua no di vao `$_POST` y nhu
    -- urlencoded.
    if first_arg then return first_arg, arg_status, up_rule, has_filename end
    return nil, status, up_rule, has_filename
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

-- Tra ve `arg_rule, status, up_rule`.
--
-- MOI LOI RA phai mang theo `up_rule`. Bo sot mot cai thi P1 mat tin hieu TRONG
-- IM LANG o dung nhom do — vd tran `MAX_PARTS`: mot upload 70 phan trong do
-- phan thu 3 la `shell.php` se thoat o nhanh `n` va bao cao "khong co gi". Do la
-- khuon loi da cat 4 thang cua `wp_paths.mark()`.
-- Quet NOI DUNG mot phan, tach khoi vung header.
--
-- VI SAO CAN, va day la lo toi tu tao ra roi phai tu dong: `_M.scan` goi
-- `check_args_lower` tren TOAN BO than nhu mot chuoi phang, nen mot lan khop
-- `../` khong the truy ve dau. Toi da dung dieu do de HA DIEM ca nhom multipart
-- (`arg_factor_body` tra 0.05), va do la mot duong ne mo cho nguoi ngoai: ke gui
-- dat `path=../../etc/passwd` thanh mot text part hop le thi PHP van nap vao
-- `$_POST` y nhu urlencoded, ma diem tu 35 xuong 1,75.
--
-- Cach dung khong phai ha diem theo DINH DANG ma la biet VI TRI. Ba nhom, va
-- chung khac nhau ve ban chat chu khong ve muc do:
--
--   form field    gia tri di vao `$_POST` — GIONG HET urlencoded, nen phai giu
--                 nguyen diem. Ke gui doi dinh dang khong doi duoc dieu nay.
--   file content  `../` trong byte cua mot tep dinh kem. Mot anh JPEG chua chuoi
--                 `../` la chuyen binh thuong; day la nhom FP that (9/9 ca do
--                 duoc tren Magento admin upload).
--   filename      da co kenh RIENG (`up_rule` + `fn_rule`), khong dung o day.
--
-- HAI DIEU KHAC NHAU GIUA HAI NHOM, va ca hai do review 26-09 chi ra:
--
--   1. CHI cap noi dung TEP, khong cap form field. Cap ca hai tao mot duong ne
--      that: nhoi 8 KB padding vao form field roi moi dat payload thi `arg_field`
--      thanh nil, `arg_content` van co (do `../` trong tep), nen `arg_origin`
--      thanh `file_content` va TOAN BO request duoc reroute sang mot luat score 0
--      — trong khi payload THAT nam trong form field. Mot form field thi khong
--      can cap: no la du lieu van ban di vao `$_POST`, va `check_args_lower` von
--      da quet toan than mot lan roi.
--   2. `binary` theo tung nhom. `binary = true` tat phat hien byte NUL THO —
--      dung cho noi dung tep (mot JPEG co byte 0 hop le) nhung SAI cho form
--      field: mot NUL tho trong mot truong van ban la tin hieu that.
local function scan_part_content(body, from, to, status, is_file)
    if not from or not to or to < from then return nil, status end
    local len = to - from + 1
    if len <= 0 then return nil, status end
    -- CHI cap tep. Xem ghi chu (1) tren. Tu V6 cap form field khong con la duong
    -- ne (quyet dinh doc `file_ranges`, khong doc kenh nay), nhung no van lam cot
    -- `afld=` bao sai — nen van khong cap.
    if is_file and len > MAX_PART_LEN then
        to = from + MAX_PART_LEN - 1
        status = worse(status, "ct")
    end
    local chunk = body:sub(from, to)
    -- `decode = false`: noi dung mot phan multipart KHONG duoc percent-encode
    -- (RFC 7578 dung transfer encoding, khong dung percent). Giai ma o day se
    -- bien `%2e%2e` trong mot tep nhi phan thanh `..` — mot lan khop gia.
    --
    -- `binary = is_file`: xem ghi chu (2) tren.
    return check_args(chunk, false, is_file), status
end

local function scan_one_boundary(body, boundary, initial_status)
    local delim = "--" .. boundary
    local status = initial_status or false
    local up_rule = nil
    local first_arg, first_arg_status = nil, nil
    -- HAI KENH DOC LAP, khong gop thanh mot. Mot than multipart co the co `../` o
    -- CA form field LAN noi dung tep; gop lai thi thu tu part quyet dinh ben nao
    -- thang, va thu tu part la thu ke gui dieu khien — dung lop loi ma `up_rule`
    -- da phai sua bang `worse_up` o ba tang.
    --
    -- Tu V6 hai kenh nay la TELEMETRY (`afld=`/`acnt=`). Duong reroute khong doc
    -- chung nua ma doc phep chung minh cua `file_ranges` — xem ghi chu o do. V5 co
    -- them truong thu sau `fields_complete` o day, suy tu cac trang thai parser;
    -- da go vi chinh phep suy do la loi (review 26-09 diem 2).
    local arg_field, arg_content = nil, nil
    local kind, at, after = next_delimiter(body, 1, delim)
    -- NAM gia tri o MOI loi ra, ke ca loi ra nay noi ca hai kenh chac chan la
    -- `nil`. Viet du ra la mot rang buoc de doc va de hop dong [27a] ghim duoc:
    -- neu mot loi ra duoc phep ngan hon, thi khi ai do them mot truong thu sau se
    -- khong con cach nao phan biet "co y bo qua" voi "quen".
    if not kind then return nil, worse(status, "bd"), nil, nil, nil end

    local nparts, saw_open = 0, false
    while kind do
        -- Kiem `close` TRUOC tran. Dau dong ket thuc khong phai mot phan, va
        -- dem no vao lam upload dung 64 file bi gan `n` — mot "khong biet" gia.
        if kind == "close" then
            return first_arg, (first_arg and first_arg_status or status), up_rule,
                   arg_field, arg_content
        end
        if nparts >= MAX_PARTS then
            return first_arg, worse(first_arg and first_arg_status or status, "n"),
                   up_rule, arg_field, arg_content
        end
        nparts, saw_open = nparts + 1, true

        -- Tim dau phan cach ke tiep tu DAU vung header, khong tu cuoi no: cai
        -- cap 2 KB co the nam vuot qua dau phan cach ke tiep va the la mat han
        -- mot phan — tuc cat IT hon parser.
        local next_kind, next_at, next_after = next_delimiter(body, after, delim)
        local he, capped = header_separator(body, after, next_at)
        if capped then status = worse(status, "hdr") end

        local rule, part_up, has_fn
        rule, status, part_up, has_fn =
            scan_disposition_headers(body:sub(after, he - 1), status)

        -- NOI DUNG phan: tu sau dong trong den truoc dau phan cach ke tiep.
        -- `he` tro toi dau dong trong; bo qua chinh dong do (2 byte `\r\n` hoac
        -- 1 byte `\n`) de khong dua ky tu phan cach vao noi dung.
        local body_from = he + ((body:sub(he, he + 1) == "\r\n") and 2 or 1)
        local body_to = (next_at and (next_at - 1)) or #body
        -- Bo `\r\n` cuoi truoc dau phan cach: theo RFC do la ky tu PHAN CACH,
        -- khong phai byte cuoi cua noi dung.
        while body_to >= body_from do
            local b = body:byte(body_to)
            if b == 10 or b == 13 then body_to = body_to - 1 else break end
        end
        -- `has_fn` quyet dinh CA kenh LAN cach soi: mot phan co `filename` la tep
        -- dinh kem (RFC 7578) nen duoc cap o `MAX_PART_LEN` va coi la nhi phan;
        -- khong co thi gia tri cua no di vao `$_POST` nen phai soi TRON va coi la
        -- van ban.
        local content_rule
        content_rule, status =
            scan_part_content(body, body_from, body_to, status, has_fn)
        if content_rule then
            if has_fn then
                if not arg_content then arg_content = content_rule end
            else
                if not arg_field then arg_field = content_rule end
            end
        end
        -- `up_rule`: giu luat NGHIEM TRONG NHAT tren toan bo cac phan.
        up_rule = upload.worse_up(up_rule, part_up)
        -- `arg_rule`: giu lan khop DAU (hop dong cu, so lieu doc theo no).
        --
        -- KHONG `return` o day. Ban truoc lam vay, va do la mot duong ne THAT:
        --     part 1  filename="../../photo.jpg"   -> khop arg_traversal
        --     part 2  filename="shell.php"         -> KHONG BAO GIO duoc soi
        -- Ke tan cong chi can dat mot ten file vo hai co `../` o phan dau la P1
        -- mu voi moi phan phia sau. Hai kenh doc lap o cap DU LIEU (hai truong
        -- khac nhau) nhung viec DUYET van chung nhau, nen `return` som cua kenh
        -- nay lam mat kenh kia.
        if rule and not first_arg then
            first_arg, first_arg_status = rule, status
        end

        kind, at, after = next_kind, next_at, next_after
    end

    -- Den day nghia la KHONG gap dau dong ket thuc: mot backend co the van chap
    -- nhan cac part phia truoc, nhung ta khong biet con part nao nua khong.
    if saw_open then status = worse(status, "ending") end
    if first_arg then
        return first_arg, worse(first_arg_status, "ending"), up_rule,
               arg_field, arg_content
    end
    return nil, status, up_rule, arg_field, arg_content
end

-- Tra ve `fn_rule, status, up_rule, arg_field, arg_content`.
local function filename_rule(body, family, ct)
    -- NAM gia tri o moi loi ra, cung ly le nhu `scan_one_boundary`.
    if family ~= "multipart" then return nil, nil, nil, nil, nil end
    local boundaries, status = boundaries_of(ct)
    if #boundaries == 0 then return nil, status, nil, nil, nil end

    local combined = status or false
    local up_rule = nil
    local first_arg = nil
    local arg_field, arg_content = nil, nil
    for i = 1, #boundaries do
        local rule, st, up, fld, cnt =
            scan_one_boundary(body, boundaries[i], combined)
        combined = worse(combined, st)
        -- Gop hai kenh qua NHIEU boundary, cung ly le nhu `up_rule` o ngay duoi:
        -- `Content-Type` co the khai nhieu gia tri boundary, va bo sot cho nay thi
        -- boundary dau tien khop se che cac boundary sau.
        if fld and not arg_field   then arg_field   = fld end
        if cnt and not arg_content then arg_content = cnt end
        -- Cung `worse_up` nhu hai tang tren. Tang nay gop qua NHIEU BOUNDARY
        -- (Content-Type khai nhieu gia tri boundary), va bo sot no o day thi
        -- boundary dau tien khop se che cac boundary sau — dung lo ma [27d] bat
        -- duoc khi toi sua hai tang tren ma quen tang nay.
        up_rule = upload.worse_up(up_rule, up)
        -- KHONG `return` o day, cung ly do nhu hai tang tren: mot boundary khop
        -- `check_args` se che cac boundary phia sau khoi `check_filename`.
        if rule and not first_arg then first_arg = rule end
    end
    return first_arg, combined, up_rule, arg_field, arg_content
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

-- Cot phan tang cho `arg_rule`: lan khop DUOC CHON co nam cung dong voi mot
-- `filename=` khong. KHONG phai "request nay co tan cong o ten file hay khong"
-- — `check_args` tra ve mot rule_id theo thu tu uu tien nen no le thuoc thu tu
-- do. `fn_rule` moi la con so tra loi duoc cau hoi kia.
local function legacy_fnm(body, family, at)
    if family ~= "multipart" or not at then return nil end
    local bol, pos = 0, 1
    while true do
        local p = body:find("\n", pos, true)
        if not p or p >= at then break end
        bol, pos = p, p + 1
    end
    local line = body:sub(bol + 1, at - 1):lower()
    return line:find("filename=", 1, true) ~= nil
        or line:find("filename*=", 1, true) ~= nil
end

-- ── V6: chung minh "lan khop nam trong NOI DUNG TEP" ────────────────────────
--
-- V5 SAI HAI LAN, ca hai do review 26-09 va phep do 2 gio sau deploy chi ra:
--
--   1. V5 hoi "moi form field da soi tron chua" bang cach suy tu `STATUS_RANK` —
--      bang MUC DO de bao cao. `ct` (tep > 8 KB) nam tren nguong, nen MOI upload
--      lon mat duong reroute: dung nhom 9/9 Magento 1-2 MB ma V4 sinh ra de xu ly.
--   2. V5 doi `acnt == argrule`, ma `acnt` chi thay 8 KB DAU cua tep.
--   Do 26-09 tren sau may: 12/12 luot luat tham so tren than tu phien WordPress
--   dang nhap ra `aorig=unknown`, 0 luot `file_content` tren toan dan may.
--
-- Va mot lo theo HUONG NGUOC LAI: V5 doc "part nay la tep" bang tokenizer CUA
-- MINH, lech PHP o bon cho (`filename*`, Content-Disposition trung, khoang trang
-- truoc `=`, nhay don). Moi cho lech la mot cach bien mot form field thanh "tep"
-- de payload trong no bi ha diem.
--
-- CACH V6, chung minh bang SU CO MAT chu khong bang su vang mat: bo cac vung
-- CHAC CHAN la noi dung tep ra khoi than, roi quet TOAN BO phan con lai
-- (`binary = false`). Phan con lai sach thi lan khop cua phep quet phang chi co
-- the nam trong noi dung tep. Khong co gioi han do dai nao, khong co co nao de
-- suy.
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

-- Vung header cua MOT part (khong ke CRLF ket thuc): "file", "field", hoac
-- `nil, ly_do`.
local function canonical_part_head(head)
    local cd, has_ct = nil, false
    for line in (head .. "\r\n"):gmatch("(.-)\r\n") do
        -- CR/LF le hoac NUL trong mot dong: PHP cat dong o `\n` va doc header nhu
        -- chuoi C, nen tu day hai ben co the thay hai header khac nhau.
        if line:find("[\r\n%z]") then return nil, "hdr" end
        local name, value = line:match("^([%w-]+): (.*)$")
        if not name then return nil, "hdr" end
        name = name:lower()
        if name == "content-disposition" then
            if cd then return nil, "cd" end
            cd = value
        elseif name == "content-type" and not has_ct then
            has_ct = true
        else
            return nil, "hdr"
        end
    end
    if not cd then return nil, "cd" end
    if cd:find('^form%-data; name="[^"\\]*"; filename="[^"\\]*"$') then
        return "file"
    end
    if cd:find('^form%-data; name="[^"\\]*"$') then return "field" end
    return nil, "cd"
end

-- Cac khoang `{dau, cuoi}` la NOI DUNG TEP da chung minh, hoac `nil, ly_do`.
-- Ly do ra log o cot `pf=`:
--   ct   Content-Type khong chuan tac    pre  co byte truoc dong phan cach dau
--   hdr  vung header cua mot part        cd   Content-Disposition
--   dl   dau phan cach sau noi dung      end  thieu dong ket thuc / co byte sau no
--   n    hon MAX_PARTS phan
local function file_ranges(body, ct)
    local b = canonical_boundary(ct)
    if not b then return nil, "ct" end
    local open = "--" .. b .. "\r\n"
    if body:sub(1, #open) ~= open then return nil, "pre" end
    local next_delim = "\n--" .. b
    local ranges, pos, nparts = {}, #open + 1, 0
    while true do
        nparts = nparts + 1
        if nparts > MAX_PARTS then return nil, "n" end
        local he = body:find("\r\n\r\n", pos, true)
        if not he or he - pos > MAX_HDR_LEN then return nil, "hdr" end
        local kind, why = canonical_part_head(body:sub(pos, he - 1))
        if not kind then return nil, why end
        local cs = he + 4
        local at = body:find(next_delim, cs, true)
        if not at then return nil, "end" end
        if at <= cs or body:byte(at - 1) ~= 13 then return nil, "dl" end
        if kind == "file" and at - 2 >= cs then
            ranges[#ranges + 1] = { cs, at - 2 }
        end
        local after = at + #next_delim
        local tail = body:sub(after, after + 1)
        if tail == "\r\n" then
            pos = after + 2
        elseif tail == "--" then
            local rest = body:sub(after + 2)
            if rest ~= "" and rest ~= "\r\n" then return nil, "end" end
            return ranges
        else
            return nil, "dl"
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

function _M.scan(body, ct)
    assert(type(body) == "string", "body_core.scan: body phai la chuoi")
    local family = ct_family(ct)
    local low    = body:lower()
    local arg_rule, at = check_args_lower(low, family == "urlencoded",
                                          family == "multipart" or family == "other")
    local fn_rule, fn_trunc, up_rule, arg_field, arg_content =
        filename_rule(body, family, ct)

    -- V6. Than chuan tac (`proof = "ok"`) thi `arg_rule` lay tu phan KHONG PHAI
    -- TEP neu phan do co luat: mot luat trong form field luon thang mot luat trong
    -- noi dung tep, bat ke thu tu uu tien giua cac luat. Phan do quet voi
    -- `binary = false`, nen mot NUL tho trong form field gio moi thanh `arg_rule`
    -- (V5 chi dua no ra `afld=`, tuc telemetry, khong cham diem).
    --
    -- Than KHONG chuan tac thi giu nguyen hanh vi cu: quet phang `binary = true`.
    -- Quet phang `binary = false` o do se bien moi byte 0 trong noi dung tep thanh
    -- `arg_null_byte` — ma o do ta khong tach duoc tep khoi form field.
    local proof, proj_rule, fnm_src = nil, nil, body
    if family == "multipart" then
        local ranges
        ranges, proof = file_ranges(body, ct)
        if ranges then
            proof = "ok"
            local proj = projection(body, ranges)
            local proj_at
            proj_rule, proj_at = check_args(proj, false, false)
            if proj_rule then
                -- `at` phai di cung CHUOI no duoc do tren: `legacy_fnm` tim dong
                -- chua lan khop, va vi tri trong ban chieu khac vi tri trong than.
                arg_rule, at, fnm_src = proj_rule, proj_at, proj
            end
        end
    end

    -- `arg_origin`: NOI lan khop cua `arg_rule` nam o dau. Day la truong V4 them,
    -- va no ton tai vi mot ly do duy nhat — `arg_rule` den tu `check_args_lower`
    -- tren TOAN BO than nhu mot chuoi phang, nen khong the truy ve dau.
    --
    -- PHAI so CUNG MOT RULE, khong chi "co rule nao do" (review 26-09). Ban truoc
    -- viet `elseif arg_field then`, nen mot than co
    --     form field   `../`          -> arg_field   = arg_traversal
    --     file content `php://input`  -> arg_content = arg_php_wrapper
    -- voi `arg_rule = arg_php_wrapper` (luat uu tien cao hon) se bao
    -- `arg_origin = form_field` — SAI NGUON. Chua tao bypass vi chi `arg_traversal`
    -- duoc reroute, nhung telemetry sai va se thanh bypass ngay khi reroute them
    -- wrapper hoac null-byte.
    --
    -- Mot chuoi duy nhat moi kenh KHONG bieu dien duoc nhieu rule cung xuat hien;
    -- do la gioi han da biet cua V4, va `arg_origin = unknown` la cau tra loi dung
    -- cho truong hop khong quy duoc.
    --
    -- THU TU UU TIEN co y, va no khong phai "cai nao manh hon":
    --
    --   form_field    Dat TRUOC `file_content`. Mot than co CUNG luat o hai cho thi
    --                 nhom quyet dinh la form field — vi gia tri form field di vao
    --                 `$_POST`, tuc mot tan cong tham so THAT.
    --   filename      `arg_rule` khop trong vung header cua mot phan. Kenh nay da
    --                 co duong RIENG (`fn_rule` + `up_rule`).
    --   file_content  V6: CHI khi than chuan tac (`proof = "ok"`) VA phan khong
    --                 phai tep da QUET va SACH. Dat SAU hai nhom tren vi hai kenh
    --                 do di tu parser cu: neu chung noi "trong field" thi mot bat
    --                 dong giua hai parser phai nghieng ve phia giu diem.
    --   flat          khong phai multipart. Nghia cu, khong doi.
    --   unknown       la multipart nhung khong quy duoc. TUYET DOI khong ha diem:
    --                 "khong biet" khac "khong co".
    local arg_origin
    if not arg_rule then
        arg_origin = nil
    elseif family ~= "multipart" then
        arg_origin = "flat"
    elseif arg_field == arg_rule then
        arg_origin = "form_field"
    elseif fn_rule == arg_rule then
        arg_origin = "filename"
    elseif proof == "ok" and not proj_rule then
        -- `not proj_rule` la TOAN BO phep chung minh: phan con lai sau khi bo noi
        -- dung tep da duoc QUET va khong co luat nao. Khong suy tu mot co, khong
        -- suy tu `acnt` — hai cach V5 da lam va ca hai deu sai.
        arg_origin = "file_content"
    else
        arg_origin = "unknown"
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
        arg_rule = arg_rule,
        fnm      = legacy_fnm(fnm_src, family, at),
        fn_rule  = fn_rule,
        fn_trunc = fn_trunc,
        -- P1. `nil` gop BA truong hop: khong phai multipart, khong co
        -- `filename=` nao, hoac da soi va khong co duoi chay duoc. Ba nguyen
        -- nhan nhung CUNG mot ket luan "khong co gi de bao", nen mot gia tri la
        -- du. Khac han `php`, noi `nil` = CHUA SOI va la mot y nghia thu ba thuc
        -- su — dung cho `waf_body_php` phai so `== true`.
        up_rule  = up_rule,
        -- V4. Ba truong DOC LAP chu khong mot truong `arg_origin` duy nhat: mot
        -- than co the co `../` o CA form field LAN noi dung tep, va mot truong
        -- buoc phai chon mot — khi do thu tu part quyet dinh chon cai nao, va thu
        -- tu part la thu ke gui dieu khien.
        arg_origin  = arg_origin,
        arg_field   = arg_field,
        arg_content = arg_content,
        -- V6: `fields_complete` = than chuan tac VA moi byte khong phai tep da duoc
        -- quet (`proof = "ok"`). Giu ten cu vi `init.lua` gac reroute tren no
        -- (`== true`) va cot `fc=` doc theo no. `proof` la LY DO khi khong chung
        -- minh duoc — ra cot `pf=`, de do duoc upload that hong o buoc nao.
        fields_complete = (proof == "ok"),
        proof           = proof,
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

function _M.pack(r)
    -- V6 them `proof`. (V5 da them `fields_complete`, V4 `arg_origin`/`arg_field`/
    -- `arg_content`.) PHAI nang phien ban khi
    -- them truong: `unpack` gac bang `#f ~= <so truong>`, nen mot ban `pack` moi
    -- gap mot ban `unpack` cu se tra `bad_payload` — TRONG IM LANG, va chi voi
    -- than DA SPILL, tuc dung nhom upload lon. Doi phien ban lam cho su khong khop
    -- do CO TEN.
    --
    -- (V3 da them `up_rule`; V2 va truoc do khong con tren dan may nao.)
    --
    -- Ba truong moi nam O CUOI chu khong xen vao giua: `unpack` doc theo CHI SO,
    -- nen xen giua se lam moi truong sau no lech mot o — va vi truong dau tien
    -- (`family`) van dung, loi se trong nhu mot loi du lieu chu khong nhu mot loi
    -- giao thuc.
    return table.concat({
        "V6", enc(r.family), enc(r.len), enc(r.php), enc(r.nargs),
        enc(r.arg_rule), enc(r.fnm), enc(r.fn_rule), enc(r.fn_trunc), enc(r.scan),
        enc(r.up_rule),
        enc(r.arg_origin), enc(r.arg_field), enc(r.arg_content),
        enc(r.fields_complete), enc(r.proof),
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
-- thi `arg_rule = "-"` la mot gia tri THAT — no truthy, no pha phan biet
-- nil/false ma ca thiet ke nay dua vao, va no lam `notable` trong waf_logger
-- dung voi MOI than da spill. Test "pack/unpack giu nil" bat duoc cho nay.
local function dec(v)
    if v == "-" or v == "" then return nil end
    return v
end
local function dec_bool(v) if v == "1" then return true elseif v == "0" then return false end end
local function dec_stat(v) if v == "0" then return false end return dec(v) end

function _M.unpack(payload)
    if type(payload) ~= "string" then return nil, "bad_payload" end
    local f = split(payload)
    if f[1] == "E"  then return nil, f[2] or "worker", tonumber(f[3]) end
    -- CHI nhan V6. KHONG chap nhan ban cu nhu mot ban tuong thich nguoc, va do la
    -- quyet dinh co y: `body_worker.lua` chay trong MOT VM RIENG do
    -- `ngx.run_worker_thread` dung len, nhung ca hai ben deu nap tu CUNG mot file
    -- tren dia — nen chung khong bao gio lech phien ban TRU trong khoang giua hai
    -- lan `nginx -s reload` cua mot lan deploy. Trong khoang do, `bad_payload` la
    -- cau tra loi DUNG: no co ten, di vao `waf:v2:scan:bad_payload`, va chi anh
    -- huong than da spill. Chap nhan V3 se lam khoang do trong nhu binh thuong
    -- trong khi ba truong moi lang le bang nil.
    if f[1] ~= "V6" or #f ~= 16 then return nil, "bad_payload" end
    return {
        family   = dec(f[2]),
        len      = tonumber(f[3]),
        php      = dec_bool(f[4]),
        nargs    = tonumber(dec(f[5]) or ""),
        arg_rule = dec(f[6]),
        fnm      = dec_bool(f[7]),
        fn_rule  = dec(f[8]),
        fn_trunc = dec_stat(f[9]),
        scan     = dec(f[10]) or "ok",
        up_rule  = dec(f[11]),
        arg_origin  = dec(f[12]),
        arg_field   = dec(f[13]),
        arg_content = dec(f[14]),
        -- `dec_bool` chu khong `dec`: `fields_complete` la mot DIEU KIEN gac
        -- cho reroute, nen mot chuoi "0" doc thanh true se mo lai dung cai
        -- bypass vua dong.
        fields_complete = dec_bool(f[15]),
        proof           = dec(f[16]),
    }
end

return _M
