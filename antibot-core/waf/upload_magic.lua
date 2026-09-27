-- upload_magic.lua — roadmap muc 7: DUOI tep noi mot dang, BYTE DAU noi dang khac.
--
-- ── VI SAO LA MOT MODULE RIENG ──────────────────────────────────────
--
-- `upload.lua` tra loi "duoi nay co chay duoc tren server khong" — mot cau chi
-- can TEN. `upload_content.lua` tra loi "noi dung tep cau hinh nay co bat lai
-- PHP khong" — chi chay cho hai cai ten. Day tra loi cau thu ba:
--
--     "phan mo rong hua mot DINH DANG. Byte dau co dung dinh dang do khong?"
--
-- Cau do khong can biet Apache anh xa duoi nao, va khong can biet cu phap
-- Apache. No chi can mot bang chu ky. Nen tach.
--
-- BAT BUOC LA LUA THUAN, khong `ngx.*`: `body_core` goi file nay tu trong
-- `ngx.run_worker_thread` — mot VM KHONG co API `ngx`. Cung ly do `upload.lua`
-- va `upload_content.lua` la Lua thuan. Mot `ngx.re.find` o day khong hong luc
-- bien dich; no hong dung luc than request tran ra dia, tuc nhom upload lon.
--
-- ── VI SAO KHONG PHAI "libmagic trong Lua" ──────────────────────────
--
-- Bang duoi day CO Y hep. No khong nhan dang tep; no tra loi mot cau hep hon:
-- "duoi nay thuoc mot ho dinh dang ma toi biet chac chu ky, va byte dau co
-- khop khong". Ba nhom ket qua, va nhom thu ba la nhom quan trong nhat:
--
--   khop       duoi `.jpg`, byte `FF D8 FF`              -> khong phat gi
--   LECH       duoi `.jpg`, byte `<?php` hoac `MZ`       -> phat fact
--   KHONG BIET duoi `.dat`, `.bin`, khong co trong bang  -> KHONG phat gi
--
-- Nhom "khong biet" phai im lang, khong phai "dang nghi". Mot bang chu ky day
-- hon chi lam nhom 3 nho lai; no KHONG lam nhom 2 dung hon. Do la ly do khong
-- can libmagic de bat webshell doi ten thanh `.jpg`.
--
-- ── TRONG SO 0, VA VI SAO ───────────────────────────────────────────
--
-- Cung khuon `waf_arg`/`waf_body_arg`/`upload.lua`, va cung ly do B1/B3 o
-- roadmap muc 2: chua co MOT con so nao tren dan may nay ve bao nhieu upload
-- that co duoi lech byte dau. Co nhung nguon FP THAT va de nghi ra:
--
--   · `.jpg` do cong cu khac nhau ghi JFIF/Exif khac nhau o byte thu 4-6 — nen
--     chi kiem 3 byte dau.
--   · `.doc`/`.xls` cu la OLE2; `.docx`/`.xlsx` la ZIP. Cung ho Office, HAI
--     chu ky khac han. Lan lon hai cai nay la mot FP hang loat.
--   · `.svg` la XML, tuc TEXT — khong co chu ky nhi phan nao.
--
-- Nen: phat fact, ghi log, KHONG cong diem cho toi khi co so.  Tin hieu trong
-- so 0 cung KHONG duoc co mat trong `waf_signal()` — xem `waf/CLAUDE.md`, phan
-- hop dong hai chieu do `contract_test` gac.

local _M = {}

local char = string.char

-- ── Bang chu ky ─────────────────────────────────────────────────────
--
-- Tieu chi vao bang nay HEP va kiem tra duoc, y nhu `PHP_EXT` trong
-- `upload.lua`: chu ky phai la BAT BIEN cua dinh dang theo dac ta, khong phai
-- "byte toi thay o mot tep mau". Moi dong duoi day la mot chuoi byte co dinh o
-- offset 0, TRU `webp`/`wav`/`avi` (RIFF: 4 byte dau + 4 byte kieu o offset 8)
-- va `mp4` (`ftyp` o offset 4) — hai dang container duoc xu ly rieng.
--
-- ── VI SAO BANG NAY KHONG LAY TU `mime.types` ───────────────────────
--
-- Da sai mot lan dung ho lap luan nay: `PHP_EXT` ban dau co 12 duoi lay tu tai
-- lieu chung, va toi con khoa phong doan do vao `contract_test` nhu mot bat
-- bien. Do that tren fleet: 4 duoi, va bang cu THIEU `.inc` dang chay duoc.
--
-- Nen bang duoi day chi chua dinh dang co chu ky trong DAC TA cong khai
-- (JFIF/ISO/RFC/PKWARE), va MOI dong deu kiem duoc bang mot tep that. Nhung
-- duoi PHO BIEN tren fleet ma KHONG co chu ky on dinh thi CO Y khong co mat:
-- `.txt .csv .svg .html .xml .json .ini .md` la text, `.dat .bin` khong dinh
-- nghia gi. Thieu o day = im lang, khong phai canh bao.
--
-- Byte khong in duoc viet bang `char()`: cong cu Bash tren may dev bien gach
-- nguoc doi thanh mot, nen mot escape `\255` trong heredoc khong song sot —
-- cung ly do `body_core` dung `string.char(92)` cho gach nguoc.
local FF_D8_FF = char(255, 216, 255)
local PNG_SIG  = char(137) .. "PNG" .. char(13, 10, 26, 10)
local OLE2     = char(208, 207, 17, 224, 161, 177, 26, 225)

local SIG = {
    -- anh
    jpg  = { FF_D8_FF },
    jpeg = { FF_D8_FF },
    png  = { PNG_SIG },
    gif  = { "GIF87a", "GIF89a" },
    bmp  = { "BM" },
    ico  = { char(0, 0, 1, 0) },
    tif  = { "II*" .. char(0), "MM" .. char(0) .. "*" },
    tiff = { "II*" .. char(0), "MM" .. char(0) .. "*" },
    -- tai lieu
    pdf  = { "%PDF-" },
    -- ZIP container: docx/xlsx/pptx/odt deu la ZIP. `PK\3\4` la local file
    -- header; `PK\5\6` la archive RONG; `PK\7\8` la spanned.
    zip  = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    docx = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    xlsx = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    pptx = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    odt  = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    ods  = { "PK" .. char(3, 4), "PK" .. char(5, 6), "PK" .. char(7, 8) },
    -- OLE2 — `.doc`/`.xls` CU. KHAC han ZIP o tren; lan lon hai nhom nay la
    -- mot FP hang loat, nen hai dong rieng.
    doc  = { OLE2 },
    xls  = { OLE2 },
    ppt  = { OLE2 },
    -- nen
    gz   = { char(31, 139) },
    bz2  = { "BZh" },
    xz   = { char(253) .. "7zXZ" .. char(0) },
    rar  = { "Rar!" .. char(26, 7) },
    ["7z"] = { "7z" .. char(188, 175, 39, 28) },
    -- am thanh / video khong-container
    mp3  = { "ID3", char(255, 251), char(255, 243), char(255, 242) },
    flac = { "fLaC" },
    ogg  = { "OggS" },
    webm = { char(26, 69, 223, 163) },
    mkv  = { char(26, 69, 223, 163) },
    -- font
    woff  = { "wOFF" },
    woff2 = { "wOF2" },
    ttf   = { char(0, 1, 0, 0), "true", "ttcf" },
    otf   = { "OTTO" },
}

-- Container can doc o offset khac 0.
--   RIFF: "RIFF" o 0, kieu 4 byte o offset 8  (WEBP, WAVE, AVI )
--   ISOBMFF: "ftyp" o offset 4                (mp4, m4a, mov)
local RIFF_TYPE = {
    webp = "WEBP",
    wav  = "WAVE",
    avi  = "AVI ",
}
local FTYP = { mp4 = true, m4v = true, m4a = true, mov = true }

-- ── Chu ky NGUY HIEM: byte dau noi day la thu CHAY DUOC ─────────────
--
-- Tach khoi `SIG` vi hai bang tra loi hai cau khac nhau. `SIG` tra loi "co dung
-- dinh dang duoi hua khong". Bang nay tra loi "thu nay la MA", va cau do dang
-- quan tam KE CA khi duoi khong co trong `SIG`.
--
-- `<?php` / `<?=` KHONG nam o day: `body_core` da bat ca than bang
-- `find_php_tag` va da co `php_tag` trong `content_flags` theo tung part. Lap
-- lai o day chi lam hai phep dem cong nhau. Bang nay la cac dang ma
-- `find_php_tag` MU.
--
-- `CA FE BA BE` la CA Mach-O universal binary LAN Java `.class`. Khong phan
-- biet duoc bang 4 byte dau, va khong can: ca hai deu la "ma da bien dich", va
-- ca hai deu khong phai mot tep anh. Mot nhan chung `fatbin` duoc dung cho ca
-- hai — mot nhan SAI TEN thi de sua sau; mot phep dem TRON hai nhom thi khong,
-- nen khong dat ten `macho` roi cho `.class` di nho.
local EXEC_SIG = {
    { "MZ",                        "dos_pe" },   -- .exe/.dll Windows
    { char(127) .. "ELF",          "elf" },      -- nhi phan Linux
    { char(202, 254, 186, 190),    "fatbin" },   -- Mach-O universal HOAC .class
    { char(207, 250, 237, 254),    "macho" },    -- Mach-O 64 little-endian
    { char(254, 237, 250, 206),    "macho" },    -- Mach-O 64 big-endian
    { "dex" .. char(10),           "dex" },      -- Android DEX
    { "#!",                        "shebang" },  -- script co interpreter
}

_M.SIG       = SIG
_M.EXEC_SIG  = EXEC_SIG
_M.RIFF_TYPE = RIFF_TYPE
_M.FTYP      = FTYP

-- So byte can doc de tra loi moi cau tren. Chuoi dai nhat trong `SIG` la OLE2
-- (8 byte); RIFF can 12; `ftyp` can 8. Lay 16 cho du va cho tron.
local NEED = 16
_M.NEED = NEED

local function starts(s, sig)
    return s:sub(1, #sig) == sig
end

-- Byte dau co khop MOT trong cac chu ky cua duoi nay khong.
--
-- Tra `true` khop, `false` LECH, `nil` KHONG KET LUAN DUOC. Ba gia tri, khong
-- phai hai: `nil` la ca "duoi khong co trong bang" lan "chua du byte de biet".
-- Gop `nil` vao `false` la bien moi tep 2 byte thanh mot canh bao.
local function matches_ext(head, ext)
    local riff = RIFF_TYPE[ext]
    if riff then
        -- RIFF can ca kieu o offset 8. Thieu byte thi KHONG ket luan duoc.
        if not starts(head, "RIFF") then
            return #head >= 4 and false or nil
        end
        if #head < 12 then return nil end
        return head:sub(9, 12) == riff
    end
    if FTYP[ext] then
        if #head < 8 then return nil end
        return head:sub(5, 8) == "ftyp"
    end
    local list = SIG[ext]
    if not list then return nil end        -- duoi khong co trong bang
    local longest = 0
    for i = 1, #list do
        if starts(head, list[i]) then return true end
        if #list[i] > longest then longest = #list[i] end
    end
    -- Khong khop cai nao. Nhung neu con ngan hon chu ky dai nhat thi chua chac
    -- LECH — co the chi la thieu byte.
    if #head < longest then return nil end
    return false
end

-- Byte dau co phai mot dang CHAY DUOC khong. Tra ten dang, hoac `nil`.
local function exec_kind(head)
    for i = 1, #EXEC_SIG do
        if starts(head, EXEC_SIG[i][1]) then return EXEC_SIG[i][2] end
    end
    return nil
end

_M.matches_ext = matches_ext
_M.exec_kind   = exec_kind

-- ── Diem vao ────────────────────────────────────────────────────────
--
-- `head`  16 byte DAU cua noi dung part (khong phai ca part).
-- `exts`  danh sach duoi tu `upload.extensions` — PHAI THEO THU TU ben phai
--         truoc, y nhu `upload.lua` tra ve.
--
-- Tra `flags` (bang co, hoac `nil` khi khong co gi de noi):
--   `magic_exec`     byte dau la mot dang CHAY DUOC (ke ca khi duoi khong biet)
--   `magic_mismatch` duoi co trong bang, va byte dau KHONG khop
--
-- ── VI SAO GIA TRI LA `true`, KHONG PHAI TEN DANG ───────────────────
--
-- Ban dau toi tra `magic_exec = "elf"` va `magic_mismatch = "jpg"`. Hai co do
-- di qua `body_core.flags_str` sang giao thuc V8, va `flags_of` doc nguoc lai
-- thanh `true` — nen duong SPILL mat gia tri con duong MEMORY giu. Do dung la
-- khuon loi ma phep kiem P3 (`spill == memory`) ton tai de chan, va lan nay toi
-- tu dam vao no.
--
-- Cach sua dung la boolean, khong phai them truong vao giao thuc: giai doan DO
-- can biet CO BAO NHIEU part lech, khong can biet lech sang dang nao. Khi nao
-- so lieu doi hoi chi tiet thi them mot truong record, co phep kiem rieng.
--
-- Hai co DOC LAP nhau va co the cung bat: mot `shell.jpg` mang byte `MZ` vua
-- lech duoi vua la ma. Do la ca chu dich — hai bang chung khac nhau ve cung
-- mot part thi policy o tren co the doi xu khac mot bang chung.
--
-- ── VI SAO CHI XET DUOI PHAI NHAT CO TRONG BANG ─────────────────────
--
-- `archive.tar.gz` co `exts = {"gz", "tar"}`. Duoi PHAI NHAT quyet dinh dinh
-- dang that (`gz`), con `tar` la thu ben trong. Xet ca hai thi moi `.tar.gz`
-- hop le thanh `magic_mismatch` vi byte dau khong phai chu ky tar.
--
-- Nen: di tu phai sang trai, lay duoi DAU TIEN co trong bang, bo qua phan con
-- lai. `x.php.jpg` -> `jpg` (kenh TEN da bat `upload_php_double` rieng).
function _M.scan_head(head, exts)
    if not head or head == "" then return nil end
    local flags

    if exec_kind(head) then
        flags = { magic_exec = true }
    end

    if exts then
        for i = 1, #exts do
            local m = matches_ext(head, exts[i])
            if m ~= nil then
                -- Duoi nay co trong bang -> no quyet dinh, dung tai day.
                if m == false then
                    flags = flags or {}
                    flags.magic_mismatch = true
                end
                break
            end
        end
    end

    return flags
end

return _M
