-- T — bo test cho waf/body_core.lua + body_worker.lua + body.lua
--
-- CHAY: ./run.sh
--
-- Toan bo logic soi nam o `body_core` — Lua THUAN, khong `ngx`. Do la rang buoc
-- kien truc: `ngx.run_worker_thread` chay ham trong mot VM khong co API `ngx`.
-- Nho vay bo test nay khong can stub gi ca cho phan loi.
--
-- `body.lua` (lop truy cap ngx) duoc kiem qua `_probe_with_runner`, cho phep
-- thay bo chay thread bang mot ham dong bo va thay `ngx.var`/`ngx.req` bang bang
-- Lua thuong — khong dung toi bien toan cuc `ngx` nen mot test hong khong lam
-- hong cac test sau no.

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

-- `body_core` require `upload` (P1), nen phai preload CA HAI. Thieu cai thu hai
-- thi `require` di tim theo `package.path` cua `resty` va bao "module not found"
-- — hong ngay tu dong nap, truoc khi chay mot assertion nao.
package.preload["antibot.waf.upload"] = function()
    return dofile(SRC .. "waf/upload.lua")
end
package.preload["antibot.waf.body_core"] = function()
    return dofile(SRC .. "waf/body_core.lua")
end
package.preload["antibot.waf.body_worker"] = function()
    return dofile(SRC .. "waf/body_worker.lua")
end

local core   = require "antibot.waf.body_core"
local worker = require "antibot.waf.body_worker"
local body   = dofile(SRC .. "waf/body.lua")

local pass, fail = 0, 0
local function check(name, got, want)
    if got == want then
        pass = pass + 1
    else
        fail = fail + 1
        io.write(string.format("HONG  %s\n      duoc=%s  mong=%s\n",
                 name, tostring(got), tostring(want)))
    end
end

local B      = "----WebKitFormBoundaryAbC123"
local MULTI  = "multipart/form-data; boundary=" .. B
local URLENC = "application/x-www-form-urlencoded"
local CD     = 'Content-Disposition: form-data; name="f"; '

-- THAN MULTIPART THAT. Ban truoc cua bo test nay truyen mot MANH header tran
-- khong co dau phan cach nao — no chay duoc chi vi bo quet cu quet toan than,
-- tuc bo test khong he kiem cai cau truc ma no dang khang dinh.
local function part(hdr, content, nl)
    nl = nl or "\r\n"
    return "--" .. B .. nl .. hdr .. nl .. nl .. (content or "noi dung") .. nl
end
local function mp(parts, nl)
    nl = nl or "\r\n"
    return table.concat(parts) .. "--" .. B .. "--" .. nl
end
-- V7: moi vung la MANG luat. `check` so sanh chuoi, nen gan them ban chuoi `a,b`
-- cua tung vung (`nf`, `fl`, `fnr`) va ban gop `all` = "nonfile|file|filename"
-- ("-" cho vung rong). Bang tu worker/unpack thi dung `list(...)`.
local function list(t) return t and table.concat(t, ",") or nil end
local function scan(data, ct)
    local r = core.scan(data, ct or MULTI)
    r.nf, r.fl, r.fnr = list(r.nonfile_rules), list(r.file_rules), list(r.filename_rules)
    r.all = (r.nf or "-") .. "|" .. (r.fl or "-") .. "|" .. (r.fnr or "-")
    return r
end

-- ══ 1. Phan loai content-type ═══════════════════════════════════════
io.write("core: phan loai content-type\n")
check("family urlencoded", scan("a=1", URLENC).family, "urlencoded")
check("family multipart",  scan("x", MULTI).family,    "multipart")
check("family json",       scan("{}", "application/json").family, "json")
check("family json co suffix", scan("{}", "application/ld+json").family, "json")
check("family xml",        scan("<a/>", "text/xml").family, "xml")
check("family text",       scan("xin chao", "text/plain").family, "text")
check("family other",      scan("\1\2", "application/octet-stream").family, "other")
check("family khong phan biet hoa thuong",
      scan("{}", "APPLICATION/JSON").family, "json")
check("co tham so van ra dung family",
      scan("a=1", URLENC .. "; charset=UTF-8").family, "urlencoded")
-- SO KHOP CHINH XAC tren media type, khong tim chuoi con o bat ky dau. Kieu cu
-- (`find("multipart/form-data")`) coi dong duoi day la multipart.
check("media type gia trong tham so co nhay khong thanh multipart",
      scan("plain", 'text/plain; note="multipart/form-data; boundary=' .. B .. '"').family,
      "text")

-- ══ 2. Ba luat tham so ══════════════════════════════════════════════
io.write("\ncore: ba luat tham so\n")
check("traversal tho", scan("f=../../etc/passwd", URLENC).nf, "arg_traversal")
check("wrapper tho",   scan("f=php://input", URLENC).nf, "arg_php_wrapper")
check("NUL tho",       scan("f=x" .. string.char(0), URLENC).nf, "arg_null_byte")
check("body lanh",     scan("name=nguyen&city=ha noi", URLENC).nf, nil)
-- `..` PHAI di kem `/` hoac `\`. Thieu ve sau thi moi so thap phan deu ban.
check("hai cham khong kem gach -> im", scan("gia=1..5", URLENC).nf, nil)
-- `://` bat buoc, neu khong `data:image/png;base64,...` bi bat oan.
check("data URI hop le -> im",
      scan("img=data:image/png;base64,iVBOR", URLENC).nf, nil)

check("ma hoa hai lop van bat",
      scan("f=%252e%252e%252fetc", URLENC).nf, "arg_traversal")
-- BYPASS THAT cua ban `ngx.re` cu: no khong `lower()` LAI sau moi vong giai ma,
-- nen `%50` ra `P` va `Php://input` truot mau chu thuong.
check("giai ma sinh chu HOA van phai khop",
      scan("f=%50hp%3A%2F%2Finput", URLENC).nf, "arg_php_wrapper")
-- Noi dung KHONG phai percent-encoding thi khong duoc giai ma: mot file .txt
-- chua chuoi ky tu `%2e%2e%2f` se BIEN THANH `../` va ban — FP do chinh buoc
-- giai ma tao ra.
check("noi dung khong giai ma thi khong tu tao FP",
      scan(mp({ part(CD .. 'filename="a.txt"', "%2e%2e%2fetc") })).all, "-|-|-")
-- Byte NUL tat cho nhi phan (moi PNG/JPEG/PDF chua no theo dac ta), nhung mau
-- VAN BAN `%00` thi khong tat.
check("multipart: byte NUL tho khong ban",
      scan(mp({ part(CD .. 'filename="a.png"', "PNG" .. string.char(0)) })).all, "-|-|-")
check("multipart: `%00` van ban VAN ban",
      scan(mp({ part(CD .. 'filename="x.php%00.jpg"') })).all, "arg_null_byte|-|arg_null_byte")

-- ══ 3. The mo PHP, dem tham so ══════════════════════════════════════
io.write("\ncore: the mo PHP va dem tham so\n")
check("php thuong", scan("x<?php eval($_POST[0]);", MULTI).php, true)
check("php hoa",    scan("x<?PHP eval();", MULTI).php, true)
check("short echo tag", scan("a<?= $x ?>b", MULTI).php, true)
check("body sach",  scan("name=nguyen", URLENC).php, false)
-- `<?xml` KHONG duoc tinh la PHP: bat `<?` tran thi moi upload SVG, moi feed
-- RSS, moi SOAP envelope deu thanh duong tinh.
check("xml khong phai php", scan('<?xml version="1.0"?>', "text/xml").php, false)
check("dau hoi tran khong ke", scan("q=<?abc", URLENC).php, false)

check("nargs mot tham so", scan("a=1", URLENC).nargs, 1)
check("nargs ba tham so",  scan("a=1&b=2&c=3", URLENC).nargs, 3)
check("nargs chi co nghia voi urlencoded", scan("a=1&b=2", MULTI).nargs, nil)
check("len dung", scan("abcde", URLENC).len, 5)

-- ══ 4. Vung `filename` — soi vung header cua TUNG phan ═══════════════
io.write("\ncore: vung filename (vung header cua tung phan)\n")
check("filename that bi bat",
      scan(mp({ part(CD .. 'filename="../../shell.php"') })).fnr, "arg_traversal")
-- V7 khong con `stop`: bo quet khong dung o lan khop dau, nen mot lan quet co khop
-- va mot lan quet sach deu ra `fn_trunc = false` — cot `fntr=` chi con noi ve
-- nhung gioi han cua PARSER.
check("tim thay KHONG con danh dau stop",
      scan(mp({ part(CD .. 'filename="../../shell.php"') })).fn_trunc, false)

-- CAI DAT DUOC BANG VIEC CAT THEO BOUNDARY. Ban quet-toan-than lam tran 64 VO
-- NGHIA: nhoi `filename=` gia vao NOI DUNG phan 1 la het suat truoc khi toi
-- header that o phan 2.
local pad = ""
for i = 1, 80 do pad = pad .. '; filename="pad' .. i .. '.jpg"' end
check("noi dung phan 1 KHONG tieu ngan sach cua phan 2",
      scan(mp({ part('Content-Disposition: form-data; name="t"', pad),
                part(CD .. 'filename="../../shell.php"') })).fnr, "arg_traversal")
check("`filename=` trong NOI DUNG file khong bi dem",
      scan(mp({ part('Content-Disposition: form-data; name="t"',
                     '; filename="../../x.php"') })).fnr, nil)
check("noi dung khong lam ban trang thai",
      scan(mp({ part('Content-Disposition: form-data; name="t"',
                     '; filename="../../x.php"') })).fn_trunc, false)

-- CHI tham so cua CHINH Content-Disposition moi la ung vien.
check("filename trong header KHAC khong bi dem",
      scan(mp({ part('Content-Disposition: form-data; name="f"\r\n'
                     .. 'X-Debug: filename="../../debug.php"') })).fnr, nil)
-- Dau `;` NAM TRONG chuoi co nhay khong phai cu phap.
check("filename trong quoted name khong bi tach thanh tham so",
      scan(mp({ part('Content-Disposition: form-data; name="x; filename=../../in.php"') })).fnr,
      nil)

check("khong phan biet hoa thuong",
      scan(mp({ part('Content-Disposition: form-data; FILENAME="../x"') })).fnr,
      "arg_traversal")
check("ten file lanh -> im",
      scan(mp({ part(CD .. 'filename="anh-san-pham.jpg"') })).fnr, nil)
check("PNG co byte NUL, ten file lanh -> im",
      scan(mp({ part(CD .. 'filename="anh.jpg"',
                     "\137PNG\r\n\26\n" .. string.char(0,0,0,13) .. "IHDR") })).fnr, nil)
-- Upload thu vien anh co hang chuc phan va tan cong thuong nam o phan cuoi.
check("quet het moi phan, khong dung o cai dau",
      scan(mp({ part(CD .. 'filename="ok.jpg"'),
                part(CD .. 'filename="../../s.php"') })).fnr, "arg_traversal")
check("khong phai multipart -> nil",
      scan('filename="../../x"', URLENC).fnr, nil)
-- Header gap dong (obs-fold): dong bat dau bang space la phan noi tiep.
check("header gap dong van doc duoc filename",
      scan(mp({ part('Content-Disposition: form-data;\r\n name="f"; filename="../../x.php"') })).fnr,
      "arg_traversal")

-- ══ 5. Cat phan: dau phan cach ══════════════════════════════════════
io.write("\ncore: cat phan theo boundary\n")
-- `--Bxyz` KHONG phai dau phan cach. Neu khong thi noi dung file tu che ra phan.
check("boundary co hau to trong noi dung khong tao phan",
      scan(mp({ part(CD .. 'filename="safe.jpg"',
                     "alpha\r\n--" .. B .. "XYZ\r\n" .. CD
                     .. 'filename="../../fake.php"\r\n\r\nkhong-phai-phan') })).fnr,
      nil)
-- `--B--garbage` khong phai dau dong ket thuc hop le, nen KHONG duoc dung quet.
check("dau dong ket thuc gia khong duoc dung bo quet",
      scan(mp({ part(CD .. 'filename="safe.jpg"',
                     "truoc\r\n--" .. B .. "--rac\r\nsau"),
                part(CD .. 'filename="../../sau.php"') })).fnr, "arg_traversal")
-- CAT RONG TAY: chap ca `\n--B` tran. Neu ta doi `\r\n` ma parser ha nguon chap
-- `\n` thi ke tan cong dung `\n` va ta thay MOT phan khong lo trong khi PHP
-- thay hai.
check("than dung `\\n` tran van cat duoc phan",
      scan(mp({ part(CD .. 'filename="../../x.php"', nil, "\n") }, "\n")).fnr,
      "arg_traversal")
-- Phan KHONG CO HEADER NAO. Khong xu ly rieng thi khong tim thay `\r\n\r\n` nao
-- va `hdr` ban OAN tren mot than hoan toan hop le.
check("phan khong co header nao -> khong bao hdr oan",
      scan("--" .. B .. "\r\n\r\nnoi dung\r\n--" .. B .. "--\r\n").fn_trunc, false)

-- ══ 6. Boundary trong Content-Type ══════════════════════════════════
io.write("\ncore: boundary\n")
check("boundary co nhay",
      scan(mp({ part(CD .. 'filename="../../x.php"') }),
           'multipart/form-data; boundary="' .. B .. '"').fnr, "arg_traversal")
check("boundary that sau mot tham so co nhay van duoc dung",
      scan(mp({ part(CD .. 'filename="../../real.php"') }),
           'multipart/form-data; x="; boundary=gia"; boundary=' .. B).fnr,
      "arg_traversal")
-- HAI boundary khac nhau la hop le ve cu phap va parser khac nhau chon khac
-- nhau. Quet voi TAT CA candidate, va van khong bao sach.
check("boundary trung lap: quet moi candidate",
      scan(mp({ part(CD .. 'filename="../../dup.php"') }),
           "multipart/form-data; boundary=gia; boundary=" .. B).fnr, "arg_traversal")
check("boundary trung lap KHONG duoc bao sach",
      scan(mp({ part(CD .. 'filename="anh.jpg"') }),
           "multipart/form-data; boundary=gia; boundary=" .. B).fn_trunc, "bdup")
check("khong co boundary -> nb",
      scan(mp({ part(CD .. 'filename="../../x.php"') }), "multipart/form-data").fn_trunc, "nb")
check("khong co boundary -> fn_rule nil, KHONG phai sach",
      scan(mp({ part(CD .. 'filename="../../x.php"') }), "multipart/form-data").fnr, nil)
check("co boundary nhung than khong co dau phan cach -> bd",
      scan("than phang khong co dau phan cach").fn_trunc, "bd")

-- ══ 7. fn_trunc — LY DO, khong phai co ══════════════════════════════
io.write("\ncore: fn_trunc la LY DO\n")
-- Dung 64 phan + dau dong ket thuc la DA SOI HET. Dem dau dong ket thuc vao
-- lam upload dung 64 file bi gan `n` — mot "khong biet" gia.
local p64 = {}
for i = 1, 64 do p64[i] = part(CD .. 'filename="f' .. i .. '.jpg"') end
check("dung 64 phan + dau dong ket thuc -> sach", scan(mp(p64)).fn_trunc, false)
p64[65] = part(CD .. 'filename="f65.jpg"')
check("65 phan -> n", scan(mp(p64)).fn_trunc, "n")

check("thieu dau dong ket thuc -> ending",
      scan(part(CD .. 'filename="safe.jpg"')).fn_trunc, "ending")

check("vung header > 2 KB -> hdr",
      scan(mp({ part('Content-Disposition: form-data; name="f"; x="'
                     .. string.rep("z", 2500) .. '"') })).fn_trunc, "hdr")

-- `len` BAO CAO do dai, KHONG cat. Cat o 512 roi moi kiem — cai ban truoc lam —
-- la de ke tan cong don 512 byte cho traversal nam ra ngoai tam nhin.
local long_fn = CD .. 'filename="' .. string.rep("a", 600) .. '../x"'
check("ten file > 512 byte -> len", scan(mp({ part(long_fn) })).fn_trunc, "len")
check("don 512 byte KHONG che duoc traversal",
      scan(mp({ part(long_fn) })).fnr, "arg_traversal")

check("multipart binh thuong -> false",
      scan(mp({ part(CD .. 'filename="anh.jpg"') })).fn_trunc, false)
check("khong phai multipart -> nil", scan("a=1", URLENC).fn_trunc, nil)

-- ══ 8. Chuan hoa ten file ═══════════════════════════════════════════
io.write("\ncore: chuan hoa ten file\n")
check("filename*= giai ma DUNG MOT LOP",
      scan(mp({ part(CD .. "filename*=UTF-8''..%2F..%2Fx.php") })).fnr, "arg_traversal")
-- FP THAT do giai ma qua tay: `a..%252Fb.txt` giai mot lan ra `a..%2Fb.txt` —
-- ten file hop le chua ky tu `%`. Giai lan hai bien no thanh `a../b.txt`.
check("filename*= KHONG duoc giai hai lop",
      scan(mp({ part(CD .. "filename*=UTF-8''a..%252Fb.txt") })).fnr, nil)
check("filename thuong KHONG percent-decode",
      scan(mp({ part(CD .. 'filename="a..%2Fb.txt"') })).fnr, nil)
-- MEP CO CHU Y: `x%2500.jpg` giai mot lan ra `x%00.jpg` roi mau VAN BAN `%00`
-- van ban. Rieng luat NUL doc them mot lop, va do la lua chon.
check("`%2500` -> `%00` sau mot lan giai, mau van ban VAN ban",
      scan(mp({ part(CD .. "filename*=UTF-8''x%2500.jpg") })).fnr, "arg_null_byte")
check("`filename=` khong giai ma nen `%2500` khong thanh `%00`",
      scan(mp({ part(CD .. 'filename="x%2500.jpg"') })).fnr, nil)
-- QUOTED-PAIR: soi CA HAI dang. Dang semantic bat `.\./`, dang raw bat `..\..\`
-- — bo escape mot cach pha huy la doi mot lo hong lay mot lo hong.
check("quoted-pair: dang semantic bat duoc `.\\./`",
      scan(mp({ part(CD .. 'filename=".\\./x.php"') })).fnr, "arg_traversal")
check("quoted-pair: dang raw bat duoc Windows `..\\..\\`",
      scan(mp({ part(CD .. 'filename="..\\..\\x.php"') })).fnr, "arg_traversal")
check("nhay thoat khong lam mat tai trong",
      scan(mp({ part(CD .. 'filename="abc\\"../../x.php"') })).fnr, "arg_traversal")
check("duong dan Windows hop le -> im",
      scan(mp({ part(CD .. 'filename="C:\\Users\\me\\anh-san-pham.jpg"') })).fnr, nil)
-- Nhay khong dong: dung o CRLF nhu parser ha nguon, va vung header da bi cat
-- theo boundary nen khong voi sang phan khac duoc.
check("nhay khong dong KHONG an sang phan khac",
      scan(mp({ part('Content-Disposition: form-data; name="a"; filename="'),
                part(CD .. 'filename="../../shell.php"') })).fnr, "arg_traversal")

-- ══ 9. V7: TAP luat cua mot vung ═════════════════════════════════════
--
-- Moi vung bao CA TAP, khong chi luat dau tien theo thu tu kiem. Cot `fnm` (lan
-- khop DUOC CHON co nam cung dong voi `filename=` khong) da go cung voi viec chon.
io.write("\ncore: V7 tap luat cua mot vung\n")
check("hai luat trong cung mot field -> ca hai",
      scan(mp({ part('Content-Disposition: form-data; name="a"', "%00 va ../x") })).nf,
      "arg_null_byte,arg_traversal")
check("ba luat trong urlencoded -> ca ba",
      scan("a=%00&b=php://x&c=../y", URLENC).nf,
      "arg_null_byte,arg_php_wrapper,arg_traversal")
check("hai ten tep, hai luat -> ca hai (khong dung o part dau)",
      scan(mp({ part(CD .. 'filename="../a.jpg"'),
                part(CD .. 'filename="x%00.jpg"') })).fnr,
      "arg_null_byte,arg_traversal")

-- `rules_in_lower` phai DONG Y voi `check_args_lower` (query string van dung ham
-- sau): luat ma `check_args_lower` tra ve phai nam trong tap, va tap rong khi va
-- chi khi no tra nil. Cung ba phep tim — lech nhau la mot bypass tren mot trong
-- hai duong.
do
    local samples = { "a=../x", "a=%00", "php://input", "x" .. string.char(0) .. "y",
                      "%252e%252e%252f", "%50hp%3A%2F%2Finput", "sach", "1..5",
                      "data:image/png;base64,x", "compress.zlib://a",
                      ".." .. string.char(92) .. "x", "%00 php:// ../" }
    local modes = { { true, false }, { false, false }, { false, true } }
    for i = 1, #samples do
        for j = 1, #modes do
            local low = samples[i]:lower()
            local one = core.check_args_lower(low, modes[j][1], modes[j][2])
            local set = core.rules_in_lower(low, modes[j][1], modes[j][2], {})
            local agree = (one == nil and next(set) == nil) or
                          (one ~= nil and set[one] == true)
            check(string.format("dong y voi check_args_lower: %q mode %d",
                                samples[i], j), agree, true)
        end
    end
end

-- ══ 10. Dong goi qua ranh gioi thread ═══════════════════════════════
io.write("\ncore: pack/unpack\n")
local clean = scan(mp({ part(CD .. 'filename="safe.jpg"') }))
local rt, rt_err = core.unpack(core.pack(clean))
check("pack/unpack khong loi", rt_err, nil)
-- `false` va `nil` PHAI phan biet duoc qua ranh gioi: gop chung lam mot la bien
-- "da soi va sach" thanh "chua soi".
check("pack/unpack giu false", rt.fn_trunc, false)
check("pack/unpack giu nil", core.unpack(core.pack(scan("a=1", URLENC))).fn_trunc, nil)
do
    local r = scan(mp({ part('Content-Disposition: form-data; name="a"', "%00 ../x"),
                        part(CD .. 'filename="../x.jpg"', "php://input") }))
    local u = core.unpack(core.pack(r))
    check("pack/unpack giu nonfile", list(u.nonfile_rules), r.nf)
    check("pack/unpack giu file", list(u.file_rules), r.fl)
    check("pack/unpack giu filename", list(u.filename_rules), r.fnr)
    check("pack/unpack giu vung rong la nil",
          core.unpack(core.pack(scan("a=1", URLENC))).nonfile_rules, nil)
end
check("pack/unpack giu do dai", rt.len, clean.len)
check("payload rac -> bao loi", select(2, core.unpack("rac")), "bad_payload")

-- ══ 11. Worker doc file tam ═════════════════════════════════════════
io.write("\nworker: doc file tam\n")
local tmp = os.tmpname()
local fh, open_err = io.open(tmp, "wb")
if not fh then
    io.write("khong tao duoc file tam: " .. tostring(open_err) .. "\n"); os.exit(2)
end
local spilled_body = mp({ part(CD .. 'filename="../../spill.php"', "<?php echo 1;") })
fh:write(spilled_body); fh:close()

local sp, sp_err = core.unpack(worker.scan_file(tmp, MULTI))
check("worker khong loi", sp_err, nil)
check("worker soi duoc filename", list(sp.filename_rules), "arg_traversal")
check("worker soi duoc the PHP", sp.php, true)
check("worker tra do dai that", sp.len, #spilled_body)
-- Tran kich thuoc phai BAO chu khong am tham cat.
check("vuot tran -> spill_big", select(2, core.unpack(worker.scan_file(tmp, MULTI, 16))),
      "spill_big")
check("khong co file -> spill_open",
      select(2, core.unpack(worker.scan_file(tmp .. ".khong-ton-tai", MULTI))), "spill_open")

-- ══ 12. Lop truy cap ngx (body.lua) ═════════════════════════════════
io.write("\nbody: cong loc va dieu phoi\n")

local function runtime(method, ct, data, file)
    return {
        var = { http_content_type = ct },
        req = {
            get_method    = function() return method end,
            read_body     = function() end,
            get_body_data = function() return data end,
            get_body_file = function() return file end,
        },
    }
end
local function probe(method, ct, data, file, runner)
    local ctx = {}
    body._probe_with_runner(ctx, runner or function() return false, "nothread" end,
                            runtime(method, ct, data, file))
    return ctx.waf_body
end

-- Cong loc la nua quan trong hon: bo do chay o access phase tren duong di cua
-- moi request, mot cong loc hong nghia la moi GET deu tra gia.
check("GET khong soi",  probe("GET",  URLENC, "a=1"), nil)
check("HEAD khong soi", probe("HEAD", URLENC, "a=1"), nil)
check("thieu Content-Type", probe("POST", nil, "a=1"), nil)
check("Content-Type rong",  probe("POST", "",  "a=1"), nil)
for _, m in ipairs({ "POST", "PUT", "PATCH", "DELETE" }) do
    check(m .. " co soi", probe(m, URLENC, "a=1") ~= nil, true)
end

check("than trong bo nho -> scan=ok", probe("POST", URLENC, "a=1").scan, "ok")
check("than trong bo nho -> source=memory", probe("POST", URLENC, "a=1").source, "memory")

-- `get_body_data()` tra nil o BA tinh huong. Gop chung se thoi phong so spill
-- bang so POST rong — tuc quyet dinh `client_body_buffer_size` tren phep dem
-- sai. Va gan nhan "spill" cho than rong con bien no thanh mot vung mu gia.
local empty = probe("POST", MULTI, nil, nil)
check("khong co than -> scan=empty", empty.scan, "empty")
check("khong co than -> spill=false", empty.spill, false)
check("khong co than -> len 0, KHONG phai -1", empty.len, 0)
check("khong co than -> fntr=empty chu khong phai spill", empty.fn_trunc, "empty")

-- BAT `ngx.log` thay vi de no chay ra stderr. Hai duong test duoi day co CHU
-- DINH di vao nhanh loi, nen khong bat thi output cua `[3b]` co hai dong
-- `[error]` trong nhu deploy dang hong. Bat lai thi chung thanh phep kiem: kieu
-- gi cung phai keu, va chi keu MOT LAN moi ly do.
local ngx_log_real = ngx and ngx.log
local logged, capture_ok = {}, false
if ngx then
    -- `pcall`: neu ban OpenResty nao do khoa bang `ngx` thi bo test KHONG duoc
    -- chet vi mot tien nghi. Khong bat duoc thi chi mat hai dong assert, con
    -- 110 dong kia van chay.
    capture_ok = pcall(function()
        ngx.log = function() logged[#logged + 1] = true end
    end)
end

-- Chua bat `thread_pool`: phai BAO chu khong am tham bo qua.
local nothread = probe("POST", MULTI, nil, tmp)
check("chua co thread pool -> scan=nothread", nothread.scan, "nothread")
check("chua co thread pool -> van danh dau spill", nothread.spill, true)
check("chua co thread pool -> php la nil, KHONG phai false", nothread.php, nil)
check("chua co thread pool -> fn_trunc mang ly do", nothread.fn_trunc, "nothread")

-- Co thread pool: than da tran ra file tam VAN duoc soi. Day la vung mu ma
-- `client_body_buffer_size` khong bao gio dong duoc.
local ran = probe("POST", MULTI, nil, tmp, function(_, _, _, path, ct)
    return true, worker.scan_file(path, ct)
end)
check("spill duoc soi -> co fn_rule", list(ran.filename_rules), "arg_traversal")
check("spill duoc soi -> spill=true", ran.spill, true)
check("spill duoc soi -> source=file", ran.source, "file")
check("spill duoc soi -> scan=ok", ran.scan, "ok")

-- Thread chay nhung worker bao loi.
local werr = probe("POST", MULTI, nil, tmp, function(_, _, _, path, ct)
    return true, worker.scan_file(path, ct, 4)
end)
check("worker bao loi -> scan mang ly do", werr.scan, "spill_big")
check("worker bao loi -> fn_rule nil", list(werr.filename_rules), nil)

-- MOT LAN moi ly do, khong phai moi request. Mau va cau hinh la HANG SO nen loi
-- o day la loi luc deploy; ghi moi request thi 43 domain do day error.log ma
-- khong them mot bit thong tin nao. Duong bao duoc doc that la cot `scan=`.
if capture_ok then
    check("co keu ngx.ERR", #logged >= 2, true)
    probe("POST", MULTI, nil, tmp)   -- lan hai, cung ly do `nothread`
    check("chi keu MOT LAN moi ly do", #logged, 2)
    ngx.log = ngx_log_real
end


-- ══ P1: `up_rule` di TRON duong tren THAN MULTIPART THAT ════════════
--
-- `upload_test.lua` kiem `check_filename` CO LAP. Bo nay kiem thu khac: gia tri
-- co song qua BON chang `scan_disposition_headers -> scan_one_boundary ->
-- filename_rule -> scan` voi mot than that hay khong. Mot `return` danh roi
-- `up_rule` se xanh o bo kia va do o day.
io.write("\ncore: P1 up_rule (than multipart that)\n")

check("ten file sach -> nil",
      scan(mp({ part(CD .. 'filename="anh.jpg"') })).up_rule, nil)
check("shell.php -> upload_php_ext",
      scan(mp({ part(CD .. 'filename="shell.php"') })).up_rule, "upload_php_ext")
check("duoi kep x.php.jpg -> upload_php_double",
      scan(mp({ part(CD .. 'filename="x.php.jpg"') })).up_rule, "upload_php_double")
check(".htaccess -> upload_apache_config",
      scan(mp({ part(CD .. 'filename=".htaccess"') })).up_rule, "upload_apache_config")
check("logo.svg -> nil (SVG xu ly rieng)",
      scan(mp({ part(CD .. 'filename="logo.svg"') })).up_rule, nil)

-- Phan SACH dung TRUOC phan xau: neu vong lap `return` som o phan dau thi
-- phan thu hai khong bao gio duoc soi.
check("phan xau nam SAU phan sach",
      scan(mp({ part(CD .. 'filename="anh.jpg"'),
                part(CD .. 'filename="shell.php"') })).up_rule, "upload_php_ext")


-- `.inc` — DO TREN FLEET 19-09, khong phai suy luan. Ca ba dong `AddHandler`
-- tren dan may nay liet ke `.inc` NGAY CANH `.php`. Ban dau toi ghi nguoc
-- ("`.inc` khong duoc anh xa") va con cai phong doan do vao contract test [28]
-- nhu mot bat bien. Ca do la ly do co dong nay.
check("shell.inc -> upload_php_ext (do tren fleet)",
      scan(mp({ part(CD .. 'filename="shell.inc"') })).up_rule, "upload_php_ext")

-- Tang LEGACY dem rieng: `.phar`/`.phps`/`.php7`/`.pht` KHONG thay trong
-- `AddHandler` nao tren fleet. Van soi (mot may moi cai hay `.htaccess` cua
-- khach co the bat), nhung phai dem rieng de con so `upload_php_ext` tra loi
-- duoc "bao nhieu la duoi THAT SU chay duoc".
check("payload.phar -> legacy",
      scan(mp({ part(CD .. 'filename="payload.phar"') })).up_rule, "upload_php_legacy_ext")
check("x.php7 -> legacy",
      scan(mp({ part(CD .. 'filename="x.php7"') })).up_rule, "upload_php_legacy_ext")

-- BA nhan config, khong gop mot. `web.config` tren stack Linux/Apache gan nhu
-- khong co gia tri thuc thi, nen tron no vao `.htaccess` la lam con so
-- `.htaccess` phong len bang luu luong scanner vo hai.
check(".user.ini -> upload_php_config",
      scan(mp({ part(CD .. 'filename=".user.ini"') })).up_rule, "upload_php_config")
check("web.config -> upload_foreign_config",
      scan(mp({ part(CD .. 'filename="web.config"') })).up_rule, "upload_foreign_config")

-- NUL + dau phan cach: goc nhin cua mot thanh phan dung chuoi kieu C thay
-- `shell.php`, trong khi `basename` don thuan thay `benign.jpg`. Mot chuoi
-- normalize duy nhat PHA HUY thong tin nay — do la ly do `canonical_views` kiem
-- ba goc nhin. Thu pha: quay ve mot goc nhin => ca nay do.
check("shell.php\0/benign.jpg -> bat duoc",
      scan(mp({ part(CD .. 'filename="shell.php\0/benign.jpg"') })).up_rule,
      "upload_php_ext")

-- ══ DUONG NE "fn_rule som" — ca nay la ly do muc [27] chua du ════════
--
-- Truoc 19-09 (8), `scan_disposition_headers` va `scan_one_boundary` deu
-- `return` ngay khi `check_args` khop. Nen:
--
--     part 1  filename="../../photo.jpg"   -> khop arg_traversal -> RETURN
--     part 2  filename="shell.php"         -> KHONG BAO GIO duoc soi
--
-- Ke tan cong chi can dat mot ten file VO HAI co `../` len phan dau la P1 mu
-- voi moi phan phia sau. Hai kenh doc lap o cap DU LIEU (hai truong khac nhau)
-- nhung viec DUYET van chung nhau — nen `return` som cua kenh nay lam mat kenh
-- kia. Muc [27] chi doi moi `return` mang theo `up_rule`, khong doi rang duyet
-- tiep, nen no bao XANH tren chinh duong ne nay.
io.write("\ncore: P1 duong ne 'fn_rule som' (part vo hai dung truoc)\n")
do
    local r = scan(mp({ part(CD .. 'filename="../../photo.jpg"'),
                        part(CD .. 'filename="shell.php"') }))
    check("vung filename van co traversal", r.fnr, "arg_traversal")
    check("up_rule KHONG bi mat o part 2", r.up_rule, "upload_php_ext")
end

-- Ba part, cai nguy hiem nhat nam giua hai part khop `check_args`.
do
    local r = scan(mp({ part(CD .. 'filename="../a.jpg"'),
                        part(CD .. 'filename=".htaccess"'),
                        part(CD .. 'filename="../b.jpg"') }))
    check("up_rule bat .htaccess o giua", r.up_rule, "upload_apache_config")
end

-- `worse_up` o cap dau-cuoi: part vo hai (theo thang) dung TRUOC part nang.
do
    local r = scan(mp({ part(CD .. 'filename="web.config"'),
                        part(CD .. 'filename="shell.php"') }))
    check("giu luat NGHIEM TRONG NHAT, khong phai dau tien",
          r.up_rule, "upload_php_ext")
end
do
    local r = scan(mp({ part(CD .. 'filename="shell.php"'),
                        part(CD .. 'filename=".htaccess"') }))
    check("thu tu nguoc cho CUNG ket qua", r.up_rule, "upload_apache_config")
end

-- Duoi chay duoc nam sau muc bao cao cu (tran MAX_EXT = 6 da go).
check("shell.php.a.b.c.d.e.f -> bat duoc",
      scan(mp({ part(CD .. 'filename="shell.php.a.b.c.d.e.f"') })).up_rule,
      "upload_php_double")

-- `filename*=` RFC 5987: giai MOT lop. Than multipart chay `decode=false` nen
-- day la duong ma `check_args` khong thay — va la bypass da ghi trong CLAUDE.md.
check("filename*= percent-encoded",
      scan(mp({ part(CD .. "filename*=UTF-8''shell%2Ephp") })).up_rule, "upload_php_ext")

-- KHONG multipart thi khong ap dung — `nil`, khong phai `false`.
check("urlencoded -> nil", scan("a=1", URLENC).up_rule, nil)

-- Ca hai bang chung cung luc: `../` khop `check_args`, `.php` khop P1. Phai co
-- CA HAI, khong duoc de mot cai nuot cai kia.
do
    local r = scan(mp({ part(CD .. 'filename="../../wp-config.php"') }))
    check("ca hai: vung filename co", r.fnr, "arg_traversal")
    check("ca hai: up_rule co",  r.up_rule, "upload_php_ext")
end

-- pack/unpack phai giu `up_rule` qua ranh gioi thread. Lech mot truong la
-- `bad_payload` tren MOI than spill — im lang, va dung nhom upload lon.
do
    local r  = scan(mp({ part(CD .. 'filename="shell.php"') }))
    local rt, err = core.unpack(core.pack(r))
    check("pack/unpack khong loi", err, nil)
    check("pack/unpack giu up_rule", rt and rt.up_rule, "upload_php_ext")
    local clean = core.unpack(core.pack(scan(mp({ part(CD .. 'filename="a.jpg"') }))))
    check("pack/unpack giu up_rule nil", clean.up_rule, nil)
end

-- ── V7: BA VUNG — bang chung doc lap, khong chon ─────────────────────────────
--
-- Moi ca duoi day tung la mot ca cua `arg_origin` (V4–V6): mot `arg_rule` duoc
-- CHON roi gan nhan vi tri. V7 khong chon: moi vung bao tap luat cua no. Nen moi
-- ca gio ghim CA BA vung (`all` = nonfile|file|filename), va (7) ghim rang thu tu
-- part khong doi gi.
io.write("\ncore: V7 ba vung\n")
do
    -- (1) khong phai multipart -> ca than la `nonfile`.
    check("urlencoded -> ca than la nonfile",
          scan("path=../../etc/passwd", URLENC).all, "arg_traversal|-|-")

    -- (2) than sach -> ba vung rong.
    check("than sach -> ba vung rong",
          scan(mp({ part(CD .. 'name="a"', "noi dung sach") })).all, "-|-|-")

    -- (3) `../` trong TEXT FIELD: gia tri vao `$_POST` -> `nonfile`, du diem.
    check("text field -> nonfile",
          scan(mp({ part('Content-Disposition: form-data; name="path"',
                         "../../etc/passwd") })).all, "arg_traversal|-|-")

    -- (4) `../` trong TEN TEP: ca `nonfile` (header la phan khong phai tep) lan
    --     `filename`. Policy gop cung luat bang max, khong dem hai lan.
    check("ten tep -> nonfile va filename",
          scan(mp({ part(CD .. 'filename="../../a.jpg"') })).all,
          "arg_traversal|-|arg_traversal")

    -- (5) NHOM FP THAT: `../` trong NOI DUNG tep (9/9 ca Magento) -> CHI `file`.
    check("noi dung tep -> chi vung file",
          scan(mp({ part(CD .. 'filename="photo.jpg"',
                         "JFIF....../../khong phai tham so") })).all, "-|arg_traversal|-")

    -- (6) Field va tep deu co `../`: hai vung, khong vung nao che vung nao.
    local both = scan(mp({
        part(CD .. 'filename="photo.jpg"', "JFIF../../trong tep"),
        part('Content-Disposition: form-data; name="path"', "../../trong field"),
    }))
    check("field va tep -> ca hai vung", both.all, "arg_traversal|arg_traversal|-")

    -- (7) DAO THU TU PART: y het (6). Thu tu part la thu ke gui dieu khien.
    local rev = scan(mp({
        part('Content-Disposition: form-data; name="path"', "../../trong field"),
        part(CD .. 'filename="photo.jpg"', "JFIF../../trong tep"),
    }))
    check("dao thu tu part -> khong doi", rev.all, both.all)
end

-- ── V7: cac duong ne cua V4–V6 van dong ─────────────────────────────────────
io.write("\ncore: V7 cac duong ne cu van dong\n")
do
    -- (1) Form field nhoi 9 KB padding roi moi dat payload (review 26-09): payload
    --     van o `nonfile` — form field khong bao gio bi cap.
    local bypass = scan(mp({
        part(CD .. 'filename="photo.jpg"', "JFIF../../trong tep"),
        part('Content-Disposition: form-data; name="path"',
             string.rep("a", 9000) .. "../../etc/passwd"),
    }))
    check("padding 9 KB trong field -> van o nonfile", bypass.nf, "arg_traversal")

    -- (2) Payload o part 65 (> MAX_PARTS): khong chung minh duoc -> KHONG co vung
    --     `file`, ca than la `nonfile`.
    local many = {}
    for i = 1, 64 do
        many[i] = part('Content-Disposition: form-data; name="x' .. i .. '"', "sach")
    end
    many[65] = part(CD .. 'filename="photo.jpg"', "JFIF../../trong tep")
    local over = scan(mp(many))
    check("tran MAX_PARTS -> ca than la nonfile", over.all, "arg_traversal|-|-")
    check("tran MAX_PARTS -> pf n", over.proof, "n")

    -- (3) Thieu dong ket thuc: khong chung minh -> ca than la `nonfile`.
    check("thieu dong ket thuc -> ca than la nonfile",
          scan("--" .. B .. "\r\n" .. CD .. 'filename="photo.jpg"' ..
               "\r\n\r\nJFIF../../trong tep\r\n").all, "arg_traversal|-|-")

    -- (4a) REVIEW 26-09: field `../` + tep `php://input`. Luat yeu ngoai tep KHONG
    --      duoc xoa luat manh trong tep. V6 ban dau giu `../` (35), f7a4099 giu
    --      wrapper (50) — ca hai deu CHON. V7 giu ca hai.
    local mixed = scan(mp({
        part('Content-Disposition: form-data; name="a"', "../../trong field"),
        part(CD .. 'filename="x.jpg"', "php://input trong tep"),
    }))
    check("4a: field ../ va tep wrapper -> ca hai", mixed.all,
          "arg_traversal|arg_php_wrapper|-")
    check("4a: than chung minh duoc", mixed.proof, "ok")

    -- (4b) Them `php://` vao FIELD cua (4a). Voi "mot luat moi vung" field chi con
    --      bao wrapper, trung luat voi tep, policy gop max -> diem GIAM tu 85 xuong
    --      50. Voi tap thi field giu ca hai luat.
    check("4b: field giu CA traversal lan wrapper",
          scan(mp({
              part('Content-Disposition: form-data; name="a"', "../../ va php://x"),
              part(CD .. 'filename="x.jpg"', "php://input trong tep"),
          })).nf, "arg_php_wrapper,arg_traversal")

    -- (4c) Wrapper CHI trong tep -> chi `file`.
    check("4c: wrapper chi trong tep -> chi vung file",
          scan(mp({ part(CD .. 'filename="x.jpg"', "php://input trong tep") })).all,
          "-|arg_php_wrapper|-")

    -- (4d) NUL THO trong field + `../` trong tep: null-byte o `nonfile`, khong mat.
    check("4d: NUL trong field + ../ trong tep",
          scan(mp({
              part('Content-Disposition: form-data; name="a"', "x\0y"),
              part(CD .. 'filename="x.jpg"', "JFIF../../trong tep"),
          })).all, "arg_null_byte|arg_traversal|-")

    -- (4e) Ten tep `php://input`, `../` trong noi dung tep, `../` trong field: ba
    --      vung, moi vung dung tap cua no.
    check("4e: ten tep wrapper, noi dung ../, field ../",
          scan(mp({
              part(CD .. 'filename="php://input"', "../../trong noi dung tep"),
              part('Content-Disposition: form-data; name="a"', "../../trong field"),
          })).all, "arg_php_wrapper,arg_traversal|arg_traversal|arg_php_wrapper")

    -- (5) NUL THO: trong form field la tin hieu; trong noi dung tep thi bo qua (mot
    --     JPEG co byte 0 hop le).
    check("NUL tho trong form field -> nonfile",
          scan(mp({ part('Content-Disposition: form-data; name="a"', "x\0y") })).all,
          "arg_null_byte|-|-")
    check("NUL trong noi dung tep -> bo qua",
          scan(mp({ part(CD .. 'filename="x.jpg"', "x\0y") })).all, "-|-|-")

    -- (6) Tep 9 KB: KHONG con cat 8 KB — luat nam sau 8 KB van o vung `file`, than
    --     van chung minh duoc, va `fntr` khong con `ct`.
    local big = scan(mp({ part(CD .. 'filename="x.jpg"',
                               string.rep("b", 9000) .. "php://x") }))
    check("tep 9 KB, wrapper sau 8 KB -> vung file", big.all, "-|arg_php_wrapper|-")
    check("tep 9 KB -> pf ok", big.proof, "ok")
    check("tep 9 KB -> fntr sach (khong con ct)", big.fn_trunc, false)
end

io.write("\ncore: V7 giao thuc pack/unpack\n")
do
    local r = scan(mp({ part(CD .. 'filename="photo.jpg"', "JFIF../../x") }))
    local rt, err = core.unpack(core.pack(r))
    check("V7 pack/unpack khong loi", err, nil)
    check("V7 giu vung file", rt and list(rt.file_rules), "arg_traversal")
    check("V7 giu nonfile rong", rt and rt.nonfile_rules, nil)
    check("V7 giu proof", rt and rt.proof, "ok")
    -- Than KHONG chuan tac (thieu dong ket thuc): khong co vung `file`.
    local nfr = core.unpack(core.pack(scan("--" .. B .. "\r\n" .. CD ..
                'filename="x.jpg"' .. "\r\n\r\nJFIF../../x\r\n")))
    check("V7 giu ly do proof", nfr.proof, "end")
    check("V7 than khong chung minh -> khong co vung file", nfr.file_rules, nil)
    check("V7 giu proof nil ngoai multipart",
          core.unpack(core.pack(scan("a=1", URLENC))).proof, nil)

    -- Ban CU phai bi TU CHOI, khong duoc doc nham thanh mot ban V7 thieu truong.
    local old_ver = core.pack(r):gsub("^V7", "V6")
    check("ban V6 bi tu choi", select(2, core.unpack(old_ver)), "bad_payload")

    -- Than SPILL phai cho ket qua Y HET than trong bo nho — hai duong khac nhau
    -- (`core.scan` truc tiep vs `worker.scan_file` qua pack/unpack).
    local data = mp({ part(CD .. 'filename="photo.jpg"', "JFIF../../x"),
                      part('Content-Disposition: form-data; name="a"', "x\0y") })
    local mem = scan(data)
    local fh = io.open(tmp, "wb"); fh:write(data); fh:close()
    local sp = core.unpack(worker.scan_file(tmp, MULTI))
    check("spill: nonfile giong memory", sp and list(sp.nonfile_rules), mem.nf)
    check("spill: file giong memory", sp and list(sp.file_rules), mem.fl)
    check("spill: filename giong memory", sp and list(sp.filename_rules), mem.fnr)
    check("spill: proof giong memory", sp and sp.proof, mem.proof)
end

-- ── V6: phep chung minh theo DUNG parser PHP ─────────────────────────────────
--
-- Moi ca duoi day la mot cach lam mot FORM FIELD (voi PHP) trong nhu mot TEP
-- voi mot tokenizer, hoac lam ranh gioi tep cua ta lech PHP. Ca nao cung phai ra
-- KHONG co vung `file` (ca than o `nonfile`, giu nguyen diem). Nam ca dau la review 26-09
-- neu ten; cac ca con lai doc tu `main/rfc1867.c`.
io.write("\ncore: V6 phep chung minh theo parser PHP\n")
do
    local FILE_TRAV = "JFIF../../trong tep"
    local function no_proof(name, r, why)
        check(name .. " -> khong co vung file", r.fl, nil)
        check(name .. " -> payload o nonfile", r.nf ~= nil, true)
        check(name .. " -> pf", r.proof, why)
    end

    -- (1) `filename*=`: PHP KHONG biet tham so nay, nen part la FORM FIELD va
    --     `$_POST["path"]` mang payload. V5 coi la tep.
    no_proof("filename*", scan(mp({
        part([[Content-Disposition: form-data; name="path"; filename*=UTF-8''x.txt]],
             "../../etc/passwd"),
    })), "cd")

    -- (2) HAI Content-Disposition: PHP lay cai DAU (form field), V5 duyet het.
    no_proof("hai Content-Disposition", scan(mp({
        part('Content-Disposition: form-data; name="path"' .. "\r\n" ..
             'Content-Disposition: form-data; name="f"; filename="x.jpg"',
             "../../etc/passwd"),
    })), "cd")

    -- (3) `../` trong `name=`: vung header KHONG bi bo khoi ban chieu, nen than
    --     chuan tac van giu luat.
    local nm = scan(mp({
        part('Content-Disposition: form-data; name="../../etc"; filename="x.jpg"',
             FILE_TRAV),
    }))
    check("name= traversal -> pf ok", nm.proof, "ok")
    check("name= traversal -> nonfile (header) va vung file", nm.all,
          "arg_traversal|arg_traversal|-")

    -- (4) NHOM FP THAT: tep > 8 KB, `../` nam SAU 8 KB dau. V5 ra `unknown` vi
    --     hai ly do (`ct` va `acnt`); V6/V7 phai ra vung `file`.
    local bigf = scan(mp({
        part(CD .. 'filename="anh.jpg"',
             string.rep("J", 9000) .. "../x" .. string.rep("K", 100)),
    }))
    check("tep 9 KB, ../ sau 8 KB -> chi vung file", bigf.all, "-|arg_traversal|-")
    check("tep 9 KB -> pf ok", bigf.proof, "ok")
    check("tep 9 KB -> fntr sach (khong con ct)", bigf.fn_trunc, false)

    -- Upload kieu WordPress: ba form field sach + mot tep co Content-Type.
    local wp = scan(mp({
        part('Content-Disposition: form-data; name="name"', "anh.jpg"),
        part('Content-Disposition: form-data; name="action"', "upload-attachment"),
        part('Content-Disposition: form-data; name="_wpnonce"', "0a1b2c3d4e"),
        part(CD .. 'filename="anh.jpg"' .. "\r\nContent-Type: image/jpeg",
             string.rep("J", 20000) .. "../" .. string.rep("K", 10)),
    }))
    check("upload kieu WordPress -> pf ok", wp.proof, "ok")
    check("upload kieu WordPress -> chi vung file", wp.all, "-|arg_traversal|-")

    -- (5) Tep co `../` o part 1, payload o part 65 (sau `MAX_PARTS`).
    local many = { part(CD .. 'filename="x.jpg"', FILE_TRAV) }
    for i = 2, 64 do
        many[i] = part('Content-Disposition: form-data; name="x' .. i .. '"', "sach")
    end
    many[65] = part('Content-Disposition: form-data; name="path"', "../../etc/passwd")
    no_proof("tep o part 1, payload o part 65", scan(mp(many)), "n")

    -- (6) LF TRAN truoc `--B` trong noi dung tep. PHP cat tep o `\n--B` va doc
    --     phan sau thanh FORM FIELD `path`; tim `\r\n--B` thi ca doan con la tep
    --     va payload bi xoa khoi ban chieu.
    local lf = "--" .. B .. "\r\n" .. CD .. 'filename="x.jpg"' .. "\r\n\r\n" ..
               "JFIF../../x\n--" .. B .. "\r\n" ..
               'Content-Disposition: form-data; name="path"' .. "\r\n\r\n" ..
               "../../etc/passwd\r\n--" .. B .. "--\r\n"
    no_proof("LF tran truoc dau phan cach", scan(lf), "dl")

    -- (7) Boundary la CHUOI CON voi PHP: `xboundary=` dung truoc thi PHP lay no.
    no_proof("xboundary dung truoc boundary",
             scan(mp({ part(CD .. 'filename="x.jpg"', FILE_TRAV) }),
                  "multipart/form-data; xboundary=zz; boundary=" .. B), "ct")

    -- (8) Part SAU dong ket thuc: PHP van tim dong `--B` tiep va doc no.
    local epi = mp({ part(CD .. 'filename="x.jpg"', FILE_TRAV) }) ..
                "--" .. B .. "\r\n" .. 'Content-Disposition: form-data; name="path"' ..
                "\r\n\r\n../../etc/passwd\r\n--" .. B .. "--\r\n"
    no_proof("part sau dong ket thuc", scan(epi), "end")

    -- (9) Byte truoc dong phan cach dau.
    no_proof("preamble",
             scan("rac\r\n" .. mp({ part(CD .. 'filename="x.jpg"', FILE_TRAV) })), "pre")

    -- (10) Khoang trang truoc `=`: PHP khong trim key, nen `filename ` khong phai
    --      `filename` va part la FORM FIELD. Tokenizer cua ta bo qua khoang trang.
    no_proof("khoang trang truoc =", scan(mp({
        part('Content-Disposition: form-data; name="path"; filename ="x.jpg"',
             "../../etc/passwd"),
    })), "cd")

    -- (11) Nhay don: PHP hieu, tokenizer cua ta khong.
    no_proof("nhay don", scan(mp({
        part("Content-Disposition: form-data; name='path'; filename='x.jpg'",
             "../../etc/passwd"),
    })), "cd")

    -- (12) NUL trong header: PHP doc header nhu chuoi C va dung o NUL, nen voi no
    --      `filename` phia sau khong ton tai.
    no_proof("NUL trong header", scan(mp({
        part('Content-Disposition: form-data; name="a' .. "\0" ..
             '"; filename="x.jpg"', "../../etc/passwd"),
    })), "hdr")

    -- (13) Gach nguoc trong gia tri: PHP coi gach nguoc + nhay la nhay da thoat,
    --      nen ranh gioi tham so doi cho.
    no_proof("gach nguoc trong gia tri", scan(mp({
        part('Content-Disposition: form-data; name="a' .. string.char(92) ..
             '"; filename="x.jpg"', "../../etc/passwd"),
    })), "cd")

    -- (14) Header thu ba, va LF tran trong vung header.
    no_proof("header thu ba", scan(mp({
        part(CD .. 'filename="x.jpg"' .. "\r\nContent-Transfer-Encoding: binary",
             FILE_TRAV),
    })), "hdr")
    no_proof("LF tran trong header", scan(mp({
        part(CD .. 'filename="x.jpg"' .. "\nX-A: b", FILE_TRAV),
    })), "hdr")

    -- (15) Doi chung duong: boundary trong nhay va ten header viet thuong la dang
    --      PHP doc GIONG ta — phai chung minh duoc.
    local q = scan(mp({ part(CD .. 'filename="x.jpg"', FILE_TRAV) }),
                   'multipart/form-data; boundary="' .. B .. '"')
    check("boundary trong nhay -> pf ok", q.proof, "ok")
    check("boundary trong nhay -> chi vung file", q.all, "-|arg_traversal|-")
    local lc = scan(mp({
        part('content-disposition: form-data; name="f"; filename="x.jpg"', FILE_TRAV),
    }))
    check("ten header viet thuong -> pf ok", lc.proof, "ok")

    -- (16) `boundaries_of`: gia tri TRUNG khong duoc tinh vao tran (review 26-09
    --      diem 4). Bon boundary + mot lan lap lai la `bdup`, KHONG phai `bmax`.
    local b4 = "multipart/form-data; boundary=a1; boundary=a2; boundary=a3; boundary="
               .. B .. "; boundary=a1"
    check("4 boundary + 1 trung -> bdup",
          scan(mp({ part(CD .. 'filename="x.jpg"') }), b4).fn_trunc, "bdup")
    local b5 = "multipart/form-data; boundary=a1; boundary=a2; boundary=a3;" ..
               " boundary=a4; boundary=" .. B
    check("5 boundary khac nhau -> van bmax",
          scan(mp({ part(CD .. 'filename="x.jpg"') }), b5).fn_trunc, "bmax")
end

os.remove(tmp)


io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
