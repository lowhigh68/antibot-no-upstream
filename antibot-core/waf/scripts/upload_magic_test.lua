-- T — bo test cho waf/upload_magic.lua (roadmap muc 7). CHAY: ./run.sh
--
-- Cau hoi ma bo nay tra loi: "DUOI hua mot dinh dang. Byte dau co dung dinh dang
-- do khong?" Khac `upload_test.lua` (chi hoi TEN co chay duoc khong) va khac
-- `upload_content_test.lua` (hoi noi dung tep CAU HINH).
--
-- Ba nhom ket qua phai duoc phan biet, va nhom thu ba la nhom de sai nhat:
--     khop       -> khong co gi
--     LECH       -> co
--     KHONG BIET -> khong co gi   (KHONG phai "dang nghi")
local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end
for _, m in ipairs({ "upload", "upload_content", "upload_magic",
                     "body_core", "body_worker" }) do
    package.preload["antibot.waf." .. m] = function()
        return dofile(SRC .. "waf/" .. m .. ".lua")
    end
end
local magic  = require "antibot.waf.upload_magic"
local upload = require "antibot.waf.upload"
local core   = require "antibot.waf.body_core"

local pass, fail = 0, 0
local function check(name, got, want)
    if got == want then pass = pass + 1
    else
        fail = fail + 1
        io.write(string.format("HONG  %s\n      duoc=%s  mong=%s\n",
                 name, tostring(got), tostring(want)))
    end
end

local char = string.char
-- Chu ky viet bang `char()` y nhu trong module: cong cu Bash tren may dev bien
-- gach nguoc doi thanh mot.
local JPEG = char(255, 216, 255) .. "JFIF" .. char(0, 1)
local PNG  = char(137) .. "PNG" .. char(13, 10, 26, 10) .. char(0, 0, 0, 13)
local ELF  = char(127) .. "ELF" .. char(2, 1, 1, 0, 0, 0, 0, 0)
local MZ   = "MZ" .. char(144, 0, 3, 0, 0, 0, 4, 0)
local OLE2 = char(208, 207, 17, 224, 161, 177, 26, 225)
local ZIP  = "PK" .. char(3, 4) .. char(20, 0, 0, 0, 8, 0)

-- `scan_head` voi mot ten tep: lay duoi bang chinh `upload.extensions` de bo test
-- di qua DUNG duong ma `body_core` di, khong phai mot danh sach duoi viet tay.
local function m(head, name)
    local f = magic.scan_head(head, (upload.extensions(name)))
    if type(f) ~= "table" then return "-" end
    local out = {}
    if f.magic_exec then out[#out + 1] = "exec" end
    if f.magic_mismatch then out[#out + 1] = "mismatch" end
    return table.concat(out, "+")
end

-- ══ 1. KHOP: khong phat gi ══════════════════════════════════════════════════
io.write("upload_magic: byte dau KHOP duoi -> im lang\n")
check("jpg khop",          m(JPEG, "anh.jpg"),        "-")
check("jpeg khop",         m(JPEG, "anh.jpeg"),       "-")
check("png khop",          m(PNG,  "anh.png"),        "-")
check("gif87 khop",        m("GIF87a" .. char(1, 0), "a.gif"), "-")
check("gif89 khop",        m("GIF89a" .. char(1, 0), "a.gif"), "-")
check("pdf khop",          m("%PDF-1.4 xx", "tl.pdf"), "-")
check("zip khop",          m(ZIP, "goi.zip"),         "-")
check("docx la ZIP",       m(ZIP, "vb.docx"),         "-")
check("xlsx la ZIP",       m(ZIP, "bang.xlsx"),       "-")
check("doc cu la OLE2",    m(OLE2, "vb.doc"),         "-")
check("xls cu la OLE2",    m(OLE2, "bang.xls"),       "-")
check("gz khop",           m(char(31, 139, 8, 0, 0, 0, 0, 0), "x.gz"), "-")
check("mp3 ID3 khop",      m("ID3" .. char(3, 0), "nhac.mp3"), "-")
check("mp3 frame khop",    m(char(255, 251, 144, 0), "nhac.mp3"), "-")
check("woff2 khop",        m("wOF2" .. char(0, 1, 0, 0), "f.woff2"), "-")

-- RIFF va ftyp: hai container doc o offset khac 0.
io.write("upload_magic: container RIFF + ftyp\n")
local WEBP = "RIFF" .. char(36, 0, 0, 0) .. "WEBP" .. "VP8 "
local WAVE = "RIFF" .. char(36, 0, 0, 0) .. "WAVE" .. "fmt "
check("webp khop",         m(WEBP, "anh.webp"),  "-")
check("wav khop",          m(WAVE, "am.wav"),    "-")
-- RIFF dung nhung KIEU sai: `.webp` mang mot WAVE la lech THAT.
check("webp mang WAVE",    m(WAVE, "anh.webp"),  "mismatch")
check("mp4 ftyp khop",     m(char(0, 0, 0, 24) .. "ftypisom", "v.mp4"), "-")
check("mp4 khong ftyp",    m(JPEG .. char(0, 0), "v.mp4"),  "mismatch")

-- ══ 2. LECH: phat co ════════════════════════════════════════════════════════
--
-- Day la nhom da lam module nay ton tai: ca kenh TEN lan `find_php_tag` deu mu.
io.write("upload_magic: duoi SACH nhung byte dau la MA\n")
check("shell.jpg la ELF",  m(ELF, "shell.jpg"),   "exec+mismatch")
check("anh.png la MZ",     m(MZ,  "anh.png"),     "exec+mismatch")
check("x.gif la ELF",      m(ELF, "x.gif"),       "exec+mismatch")
-- Duoi KHONG co trong bang, nhung byte dau van la ma -> chi `exec`.
check("x.dat la ELF",      m(ELF, "x.dat"),       "exec")
check("x.bin la MZ",       m(MZ,  "x.bin"),       "exec")
check("khong duoi, la ELF", m(ELF, "shell"),      "exec")
check("shebang khong duoi", m("#!/bin/sh\nid\n", "run"), "exec")
-- Lech nhung KHONG phai ma: mot `.jpg` chua van ban thuan.
check("jpg la text",       m("hello world xxxx", "anh.jpg"), "mismatch")
check("png la PDF",        m("%PDF-1.4 xxxx", "anh.png"),    "mismatch")
-- Mach-O 64 va fatbin.
check("jpg la macho64",    m(char(207, 250, 237, 254) .. char(7, 0, 0, 1), "a.jpg"),
      "exec+mismatch")
check("jpg la fatbin",     m(char(202, 254, 186, 190) .. char(0, 0, 0, 2), "a.jpg"),
      "exec+mismatch")

-- ══ 3. KHONG BIET: phai IM LANG ═════════════════════════════════════════════
--
-- Nhom de sai nhat. Mot bang chu ky day hon chi lam nhom nay NHO LAI; no khong
-- lam nhom 2 dung hon. Gop nhom nay vao "lech" la mot may FP.
io.write("upload_magic: KHONG KET LUAN DUOC -> im lang\n")
check("txt la text",       m("hello world xxxx", "ghi.txt"),   "-")
check("csv la text",       m("a,b,c\n1,2,3\n", "d.csv"),       "-")
check("svg la XML",        m('<svg xmlns="http', "h.svg"),     "-")
check("json la text",      m('{"a":1}        ', "d.json"),     "-")
check("dat khong biet",    m("random  bytes  ", "x.dat"),      "-")
check("khong duoi, text",  m("plain text here", "README"),     "-")
-- CHUA DU BYTE: mot part 2 byte khong the ket luan `.png` lech (chu ky 8 byte).
check("png 2 byte",        m(char(137) .. "P", "a.png"),       "-")
check("ole2 4 byte",       m(OLE2:sub(1, 4), "a.doc"),         "-")
check("riff 4 byte",       m("RIFF", "a.webp"),                "-")
check("ftyp 6 byte",       m(char(0, 0, 0, 24, 102, 116), "v.mp4"), "-")
check("rong",              m("", "a.jpg"),                     "-")
-- ... nhung `jpg` chi can 3 byte, nen 3 byte SAI la lech THAT.
check("jpg 3 byte sai",    m("abc", "a.jpg"),                  "mismatch")
check("jpg 2 byte",        m(char(255, 216), "a.jpg"),         "-")

-- ══ 4. Duoi KEP: duoi PHAI NHAT co trong bang quyet dinh ════════════════════
--
-- `archive.tar.gz` -> `gz`, khong xet `tar`. Thieu dieu nay thi moi `.tar.gz` hop
-- le thanh `magic_mismatch` vi byte dau khong phai chu ky tar.
io.write("upload_magic: duoi KEP — duoi phai nhat trong bang quyet dinh\n")
local GZ = char(31, 139, 8, 0, 0, 0, 0, 0)
check("tar.gz hop le",     m(GZ, "luu.tar.gz"),      "-")
check("tar.gz sai byte",   m(JPEG, "luu.tar.gz"),    "mismatch")
-- `tar` khong co trong bang -> bo qua, xet tiep sang trai... nhung `gz` la duoi
-- PHAI NHAT nen no quyet dinh truoc. Doi chieu: `.jpg.tar` thi `tar` khong biet,
-- di tiep sang `jpg`.
check("x.jpg.tar la JPEG", m(JPEG, "x.jpg.tar"),     "-")
check("x.jpg.tar la ELF",  m(ELF,  "x.jpg.tar"),     "exec+mismatch")
-- `x.php.jpg`: kenh TEN da bat `upload_php_double` rieng; o day chi xet `jpg`.
check("x.php.jpg la JPEG", m(JPEG, "x.php.jpg"),     "-")
check("x.php.jpg la PHP",  m("<?php system(1); ", "x.php.jpg"), "mismatch")

-- ══ 5. `<?php` KHONG nam trong EXEC_SIG ═════════════════════════════════════
--
-- `body_core.find_php_tag` da bat ca than va da co `php_tag` theo tung part. Lap
-- lai o day chi lam hai phep dem cong nhau. Dong nay KHOA dieu do.
io.write("upload_magic: `<?php` khong phai viec cua module nay\n")
check("php khong la exec", magic.exec_kind("<?php system(1);") == nil, true)
check("php= khong la exec", magic.exec_kind("<?= $x ?>       ") == nil, true)
-- Nhung mot `.jpg` chua `<?php` VAN lech duoi — do la cau KHAC.
check("jpg chua php lech", m("<?php system(1); ", "a.jpg"), "mismatch")

-- ══ 6. Gia tri co la BOOLEAN, khong phai ten dang ═══════════════════════════
--
-- Ban dau toi tra `magic_exec = "elf"`. Hai co do di qua `flags_str` sang giao
-- thuc V8 roi `flags_of` doc nguoc thanh `true`, nen duong SPILL mat gia tri con
-- duong MEMORY giu — dung khuon loi ma P3 ton tai de chan. Dong nay khoa lai.
io.write("upload_magic: co la boolean (spill == memory)\n")
local f = magic.scan_head(ELF, (upload.extensions("shell.jpg")))
check("magic_exec == true",     f.magic_exec,     true)
check("magic_mismatch == true", f.magic_mismatch, true)

-- ══ 7. Duong DAY DU qua body_core: part record mang co magic ════════════════
--
-- Cac muc tren goi `scan_head` truc tiep. Muc nay di qua `core.scan`, tuc dung
-- duong ma production di: `file_ranges` phai tinh co magic TRONG LUC con giu ten
-- tep, va `_M.scan` KHONG duoc ghi de no.
io.write("upload_magic: qua body_core.scan — part record\n")
local B = "----x"
local function mp(parts)
    local out = {}
    for i = 1, #parts do
        out[#out + 1] = "--" .. B .. "\r\n" .. parts[i] .. "\r\n"
    end
    return table.concat(out) .. "--" .. B .. "--\r\n"
end
local function part(fn, body)
    return 'Content-Disposition: form-data; name="f"; filename="' .. fn ..
           '"\r\n\r\n' .. body
end
local CT = "multipart/form-data; boundary=" .. B

local function parts_of_body(body)
    local r = core.scan(body, CT)
    return r.parts
end

-- 7a. Mot part `shell.jpg` chua ELF: ten SACH, co magic phai co.
local p = parts_of_body(mp({ part("shell.jpg", ELF) }))
check("7a co parts",        p ~= nil and #p or 0,        1)
check("7a ten sach",       p and p[1].name_flags,        false)
check("7a magic_exec",     p and p[1].content_flags and p[1].content_flags.magic_exec, true)
check("7a magic_mismatch", p and p[1].content_flags and p[1].content_flags.magic_mismatch, true)

-- 7b. Anh THAT: khong co co nao. Day la phep chong-FP cua ca muc 7.
p = parts_of_body(mp({ part("anh.jpg", JPEG .. string.rep("x", 40)) }))
check("7b anh that sach",  p and p[1].content_flags,     false)

-- 7c. KHONG GHI DE: part vua co `php_tag` vua co magic. Truoc khi sua, `_M.scan`
-- dat `cf = { php_tag = true }` tu `nil` va xoa mat co magic — tuc mat dung o ca
-- nguy hiem nhat (`shell.jpg` co byte `MZ` VA chua `<?php`).
local both = MZ .. " <?php system($_GET[1]); ?>"
p = parts_of_body(mp({ part("anh.jpg", both) }))
check("7c php_tag",        p and p[1].content_flags and p[1].content_flags.php_tag, true)
check("7c magic_exec giu", p and p[1].content_flags and p[1].content_flags.magic_exec, true)
check("7c mismatch giu",   p and p[1].content_flags and p[1].content_flags.magic_mismatch, true)

-- 7d. Part FIELD (khong filename) khong sinh record, nen khong co co magic.
local fieldpart = 'Content-Disposition: form-data; name="t"\r\n\r\n' .. ELF
p = parts_of_body(mp({ fieldpart, part("a.jpg", JPEG .. "xxxx") }))
check("7d chi 1 record",   p and #p,                     1)
check("7d record la tep",  p and p[1].slot,              2)

-- 7e. Hai part, mot lech mot sach: slot phai dung.
p = parts_of_body(mp({ part("ok.png", PNG), part("bad.png", ELF) }))
check("7e 2 record",       p and #p,                     2)
check("7e part1 sach",     p and p[1].content_flags,     false)
check("7e part2 exec",     p and p[2].content_flags and p[2].content_flags.magic_exec, true)
check("7e slot part2",     p and p[2].slot,              2)

-- ══ 8. spill == memory qua pack/unpack ══════════════════════════════════════
--
-- Phep kiem P3 cua wafdiff so sanh chuoi hai duong. Neu `CONTENT_FLAGS` thieu mot
-- ten thi co do bien mat LANG LE tren duong spill — da xay ra that voi
-- `handler`/`autoload` o buoc 3.
io.write("upload_magic: pack/unpack giu co magic\n")
local r  = core.scan(mp({ part("shell.jpg", ELF) }), CT)
local r2 = core.unpack(core.pack(r))
check("8 unpack ok",       r2 ~= nil,                    true)
check("8 co parts",        r2 and r2.parts and #r2.parts, 1)
check("8 exec qua spill",  r2 and r2.parts[1].content_flags.magic_exec, true)
check("8 mismatch spill",  r2 and r2.parts[1].content_flags.magic_mismatch, true)
check("8 ten sach spill",  r2 and r2.parts[1].name_flags, false)

-- Va ca huong nguoc: part sach thi `content_flags` phai la `false` sau round-trip,
-- KHONG phai bang rong — "da soi, sach" khac "chua soi".
r  = core.scan(mp({ part("anh.jpg", JPEG .. "xxxx") }), CT)
r2 = core.unpack(core.pack(r))
check("8 sach van false",  r2 and r2.parts[1].content_flags, false)

io.write(string.format("\nupload_magic: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
