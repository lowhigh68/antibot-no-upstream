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

local MAX_PARTS   = 64     -- so phan multipart soi toi da
local MAX_HDR_LEN = 2048   -- do dai vung header cua MOT phan
local MAX_FN_LEN  = 512    -- nguong BAO CAO cho mot gia tri ten file

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
    hdr = 6, nb = 7,
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
            elseif not seen[v] then
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
    else
        add(p.raw)
        if p.quoted then add(p.semantic) end
    end
    return values
end

local function scan_disposition_headers(head, status)
    local lines = unfolded_header_lines(head)
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
                        local rule = check_args(v, false, false)
                        if rule then return rule, worse(status, "stop") end
                    end
                end
            end
        end
    end
    return nil, status
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

local function scan_one_boundary(body, boundary, initial_status)
    local delim = "--" .. boundary
    local status = initial_status or false
    local kind, at, after = next_delimiter(body, 1, delim)
    if not kind then return nil, worse(status, "bd") end

    local nparts, saw_open = 0, false
    while kind do
        -- Kiem `close` TRUOC tran. Dau dong ket thuc khong phai mot phan, va
        -- dem no vao lam upload dung 64 file bi gan `n` — mot "khong biet" gia.
        if kind == "close" then return nil, status end
        if nparts >= MAX_PARTS then return nil, worse(status, "n") end
        nparts, saw_open = nparts + 1, true

        -- Tim dau phan cach ke tiep tu DAU vung header, khong tu cuoi no: cai
        -- cap 2 KB co the nam vuot qua dau phan cach ke tiep va the la mat han
        -- mot phan — tuc cat IT hon parser.
        local next_kind, next_at, next_after = next_delimiter(body, after, delim)
        local he, capped = header_separator(body, after, next_at)
        if capped then status = worse(status, "hdr") end

        local rule
        rule, status = scan_disposition_headers(body:sub(after, he - 1), status)
        if rule then return rule, status end

        kind, at, after = next_kind, next_at, next_after
    end

    if saw_open then status = worse(status, "ending") end
    return nil, status
end

local function filename_rule(body, family, ct)
    if family ~= "multipart" then return nil, nil end
    local boundaries, status = boundaries_of(ct)
    if #boundaries == 0 then return nil, status end

    local combined = status or false
    for i = 1, #boundaries do
        local rule, st = scan_one_boundary(body, boundaries[i], combined)
        combined = worse(combined, st)
        if rule then return rule, combined end
    end
    return nil, combined
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

function _M.scan(body, ct)
    assert(type(body) == "string", "body_core.scan: body phai la chuoi")
    local family = ct_family(ct)
    local low    = body:lower()
    local arg_rule, at = check_args_lower(low, family == "urlencoded",
                                          family == "multipart" or family == "other")
    local fn_rule, fn_trunc = filename_rule(body, family, ct)

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
        fnm      = legacy_fnm(body, family, at),
        fn_rule  = fn_rule,
        fn_trunc = fn_trunc,
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
    return table.concat({
        "V2", enc(r.family), enc(r.len), enc(r.php), enc(r.nargs),
        enc(r.arg_rule), enc(r.fnm), enc(r.fn_rule), enc(r.fn_trunc), enc(r.scan),
    }, SEP)
end

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

local function dec(v)      return (v == "-" or v == "") and nil or v end
local function dec_bool(v) if v == "1" then return true elseif v == "0" then return false end end
local function dec_stat(v) if v == "0" then return false end return dec(v) end

function _M.unpack(payload)
    if type(payload) ~= "string" then return nil, "bad_payload" end
    local f = split(payload)
    if f[1] == "E"  then return nil, f[2] or "worker", tonumber(f[3]) end
    if f[1] ~= "V2" or #f ~= 10 then return nil, "bad_payload" end
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
    }
end

return _M
