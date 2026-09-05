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
local function scan(data, ct) return core.scan(data, ct or MULTI) end

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
check("traversal tho", scan("f=../../etc/passwd", URLENC).arg_rule, "arg_traversal")
check("wrapper tho",   scan("f=php://input", URLENC).arg_rule, "arg_php_wrapper")
check("NUL tho",       scan("f=x" .. string.char(0), URLENC).arg_rule, "arg_null_byte")
check("body lanh",     scan("name=nguyen&city=ha noi", URLENC).arg_rule, nil)
-- `..` PHAI di kem `/` hoac `\`. Thieu ve sau thi moi so thap phan deu ban.
check("hai cham khong kem gach -> im", scan("gia=1..5", URLENC).arg_rule, nil)
-- `://` bat buoc, neu khong `data:image/png;base64,...` bi bat oan.
check("data URI hop le -> im",
      scan("img=data:image/png;base64,iVBOR", URLENC).arg_rule, nil)

check("ma hoa hai lop van bat",
      scan("f=%252e%252e%252fetc", URLENC).arg_rule, "arg_traversal")
-- BYPASS THAT cua ban `ngx.re` cu: no khong `lower()` LAI sau moi vong giai ma,
-- nen `%50` ra `P` va `Php://input` truot mau chu thuong.
check("giai ma sinh chu HOA van phai khop",
      scan("f=%50hp%3A%2F%2Finput", URLENC).arg_rule, "arg_php_wrapper")
-- Noi dung KHONG phai percent-encoding thi khong duoc giai ma: mot file .txt
-- chua chuoi ky tu `%2e%2e%2f` se BIEN THANH `../` va ban — FP do chinh buoc
-- giai ma tao ra.
check("noi dung khong giai ma thi khong tu tao FP",
      scan(mp({ part(CD .. 'filename="a.txt"', "%2e%2e%2fetc") })).arg_rule, nil)
-- Byte NUL tat cho nhi phan (moi PNG/JPEG/PDF chua no theo dac ta), nhung mau
-- VAN BAN `%00` thi khong tat.
check("multipart: byte NUL tho khong ban",
      scan(mp({ part(CD .. 'filename="a.png"', "PNG" .. string.char(0)) })).arg_rule, nil)
check("multipart: `%00` van ban VAN ban",
      scan(mp({ part(CD .. 'filename="x.php%00.jpg"') })).arg_rule, "arg_null_byte")

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

-- ══ 4. fn_rule — soi vung header cua TUNG phan ══════════════════════
io.write("\ncore: fn_rule (vung header cua tung phan)\n")
check("filename that bi bat",
      scan(mp({ part(CD .. 'filename="../../shell.php"') })).fn_rule, "arg_traversal")
check("tim thay som -> stop",
      scan(mp({ part(CD .. 'filename="../../shell.php"') })).fn_trunc, "stop")

-- CAI DAT DUOC BANG VIEC CAT THEO BOUNDARY. Ban quet-toan-than lam tran 64 VO
-- NGHIA: nhoi `filename=` gia vao NOI DUNG phan 1 la het suat truoc khi toi
-- header that o phan 2.
local pad = ""
for i = 1, 80 do pad = pad .. '; filename="pad' .. i .. '.jpg"' end
check("noi dung phan 1 KHONG tieu ngan sach cua phan 2",
      scan(mp({ part('Content-Disposition: form-data; name="t"', pad),
                part(CD .. 'filename="../../shell.php"') })).fn_rule, "arg_traversal")
check("`filename=` trong NOI DUNG file khong bi dem",
      scan(mp({ part('Content-Disposition: form-data; name="t"',
                     '; filename="../../x.php"') })).fn_rule, nil)
check("noi dung khong lam ban trang thai",
      scan(mp({ part('Content-Disposition: form-data; name="t"',
                     '; filename="../../x.php"') })).fn_trunc, false)

-- CHI tham so cua CHINH Content-Disposition moi la ung vien.
check("filename trong header KHAC khong bi dem",
      scan(mp({ part('Content-Disposition: form-data; name="f"\r\n'
                     .. 'X-Debug: filename="../../debug.php"') })).fn_rule, nil)
-- Dau `;` NAM TRONG chuoi co nhay khong phai cu phap.
check("filename trong quoted name khong bi tach thanh tham so",
      scan(mp({ part('Content-Disposition: form-data; name="x; filename=../../in.php"') })).fn_rule,
      nil)

check("khong phan biet hoa thuong",
      scan(mp({ part('Content-Disposition: form-data; FILENAME="../x"') })).fn_rule,
      "arg_traversal")
check("ten file lanh -> im",
      scan(mp({ part(CD .. 'filename="anh-san-pham.jpg"') })).fn_rule, nil)
check("PNG co byte NUL, ten file lanh -> im",
      scan(mp({ part(CD .. 'filename="anh.jpg"',
                     "\137PNG\r\n\26\n" .. string.char(0,0,0,13) .. "IHDR") })).fn_rule, nil)
-- Upload thu vien anh co hang chuc phan va tan cong thuong nam o phan cuoi.
check("quet het moi phan, khong dung o cai dau",
      scan(mp({ part(CD .. 'filename="ok.jpg"'),
                part(CD .. 'filename="../../s.php"') })).fn_rule, "arg_traversal")
check("khong phai multipart -> nil",
      scan('filename="../../x"', URLENC).fn_rule, nil)
-- Header gap dong (obs-fold): dong bat dau bang space la phan noi tiep.
check("header gap dong van doc duoc filename",
      scan(mp({ part('Content-Disposition: form-data;\r\n name="f"; filename="../../x.php"') })).fn_rule,
      "arg_traversal")

-- ══ 5. Cat phan: dau phan cach ══════════════════════════════════════
io.write("\ncore: cat phan theo boundary\n")
-- `--Bxyz` KHONG phai dau phan cach. Neu khong thi noi dung file tu che ra phan.
check("boundary co hau to trong noi dung khong tao phan",
      scan(mp({ part(CD .. 'filename="safe.jpg"',
                     "alpha\r\n--" .. B .. "XYZ\r\n" .. CD
                     .. 'filename="../../fake.php"\r\n\r\nkhong-phai-phan') })).fn_rule,
      nil)
-- `--B--garbage` khong phai dau dong ket thuc hop le, nen KHONG duoc dung quet.
check("dau dong ket thuc gia khong duoc dung bo quet",
      scan(mp({ part(CD .. 'filename="safe.jpg"',
                     "truoc\r\n--" .. B .. "--rac\r\nsau"),
                part(CD .. 'filename="../../sau.php"') })).fn_rule, "arg_traversal")
-- CAT RONG TAY: chap ca `\n--B` tran. Neu ta doi `\r\n` ma parser ha nguon chap
-- `\n` thi ke tan cong dung `\n` va ta thay MOT phan khong lo trong khi PHP
-- thay hai.
check("than dung `\\n` tran van cat duoc phan",
      scan(mp({ part(CD .. 'filename="../../x.php"', nil, "\n") }, "\n")).fn_rule,
      "arg_traversal")
-- Phan KHONG CO HEADER NAO. Khong xu ly rieng thi khong tim thay `\r\n\r\n` nao
-- va `hdr` ban OAN tren mot than hoan toan hop le.
check("phan khong co header nao -> khong bao hdr oan",
      scan("--" .. B .. "\r\n\r\nnoi dung\r\n--" .. B .. "--\r\n").fn_trunc, false)

-- ══ 6. Boundary trong Content-Type ══════════════════════════════════
io.write("\ncore: boundary\n")
check("boundary co nhay",
      scan(mp({ part(CD .. 'filename="../../x.php"') }),
           'multipart/form-data; boundary="' .. B .. '"').fn_rule, "arg_traversal")
check("boundary that sau mot tham so co nhay van duoc dung",
      scan(mp({ part(CD .. 'filename="../../real.php"') }),
           'multipart/form-data; x="; boundary=gia"; boundary=' .. B).fn_rule,
      "arg_traversal")
-- HAI boundary khac nhau la hop le ve cu phap va parser khac nhau chon khac
-- nhau. Quet voi TAT CA candidate, va van khong bao sach.
check("boundary trung lap: quet moi candidate",
      scan(mp({ part(CD .. 'filename="../../dup.php"') }),
           "multipart/form-data; boundary=gia; boundary=" .. B).fn_rule, "arg_traversal")
check("boundary trung lap KHONG duoc bao sach",
      scan(mp({ part(CD .. 'filename="anh.jpg"') }),
           "multipart/form-data; boundary=gia; boundary=" .. B).fn_trunc, "bdup")
check("khong co boundary -> nb",
      scan(mp({ part(CD .. 'filename="../../x.php"') }), "multipart/form-data").fn_trunc, "nb")
check("khong co boundary -> fn_rule nil, KHONG phai sach",
      scan(mp({ part(CD .. 'filename="../../x.php"') }), "multipart/form-data").fn_rule, nil)
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
      scan(mp({ part(long_fn) })).fn_rule, "arg_traversal")

check("multipart binh thuong -> false",
      scan(mp({ part(CD .. 'filename="anh.jpg"') })).fn_trunc, false)
check("khong phai multipart -> nil", scan("a=1", URLENC).fn_trunc, nil)

-- ══ 8. Chuan hoa ten file ═══════════════════════════════════════════
io.write("\ncore: chuan hoa ten file\n")
check("filename*= giai ma DUNG MOT LOP",
      scan(mp({ part(CD .. "filename*=UTF-8''..%2F..%2Fx.php") })).fn_rule, "arg_traversal")
-- FP THAT do giai ma qua tay: `a..%252Fb.txt` giai mot lan ra `a..%2Fb.txt` —
-- ten file hop le chua ky tu `%`. Giai lan hai bien no thanh `a../b.txt`.
check("filename*= KHONG duoc giai hai lop",
      scan(mp({ part(CD .. "filename*=UTF-8''a..%252Fb.txt") })).fn_rule, nil)
check("filename thuong KHONG percent-decode",
      scan(mp({ part(CD .. 'filename="a..%2Fb.txt"') })).fn_rule, nil)
-- MEP CO CHU Y: `x%2500.jpg` giai mot lan ra `x%00.jpg` roi mau VAN BAN `%00`
-- van ban. Rieng luat NUL doc them mot lop, va do la lua chon.
check("`%2500` -> `%00` sau mot lan giai, mau van ban VAN ban",
      scan(mp({ part(CD .. "filename*=UTF-8''x%2500.jpg") })).fn_rule, "arg_null_byte")
check("`filename=` khong giai ma nen `%2500` khong thanh `%00`",
      scan(mp({ part(CD .. 'filename="x%2500.jpg"') })).fn_rule, nil)
-- QUOTED-PAIR: soi CA HAI dang. Dang semantic bat `.\./`, dang raw bat `..\..\`
-- — bo escape mot cach pha huy la doi mot lo hong lay mot lo hong.
check("quoted-pair: dang semantic bat duoc `.\\./`",
      scan(mp({ part(CD .. 'filename=".\\./x.php"') })).fn_rule, "arg_traversal")
check("quoted-pair: dang raw bat duoc Windows `..\\..\\`",
      scan(mp({ part(CD .. 'filename="..\\..\\x.php"') })).fn_rule, "arg_traversal")
check("nhay thoat khong lam mat tai trong",
      scan(mp({ part(CD .. 'filename="abc\\"../../x.php"') })).fn_rule, "arg_traversal")
check("duong dan Windows hop le -> im",
      scan(mp({ part(CD .. 'filename="C:\\Users\\me\\anh-san-pham.jpg"') })).fn_rule, nil)
-- Nhay khong dong: dung o CRLF nhu parser ha nguon, va vung header da bi cat
-- theo boundary nen khong voi sang phan khac duoc.
check("nhay khong dong KHONG an sang phan khac",
      scan(mp({ part('Content-Disposition: form-data; name="a"; filename="'),
                part(CD .. 'filename="../../shell.php"') })).fn_rule, "arg_traversal")

-- ══ 9. fnm (cot phan tang cu) ═══════════════════════════════════════
io.write("\ncore: fnm\n")
check("fnm=1 khi lan khop nam cung dong voi filename",
      scan(mp({ part(CD .. 'filename="x.php%00.jpg"') })).fnm, true)
check("fnm=0 khi lan khop nam trong noi dung",
      scan(mp({ part(CD .. 'filename="a.txt"', "php://input") })).fnm, false)
check("fnm=nil khi khong luat nao ban",
      scan(mp({ part(CD .. 'filename="a.jpg"') })).fnm, nil)
check("fnm=nil khi khong phai multipart", scan("f=../x", URLENC).fnm, nil)

-- ══ 10. Dong goi qua ranh gioi thread ═══════════════════════════════
io.write("\ncore: pack/unpack\n")
local clean = scan(mp({ part(CD .. 'filename="safe.jpg"') }))
local rt, rt_err = core.unpack(core.pack(clean))
check("pack/unpack khong loi", rt_err, nil)
-- `false` va `nil` PHAI phan biet duoc qua ranh gioi: gop chung lam mot la bien
-- "da soi va sach" thanh "chua soi".
check("pack/unpack giu false", rt.fn_trunc, false)
check("pack/unpack giu nil", core.unpack(core.pack(scan("a=1", URLENC))).fn_trunc, nil)
check("pack/unpack giu fnm false",
      core.unpack(core.pack({ family = "multipart", len = 1, php = false,
                              fnm = false, fn_trunc = false, scan = "ok" })).fnm, false)
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
check("worker soi duoc filename", sp.fn_rule, "arg_traversal")
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
check("spill duoc soi -> co fn_rule", ran.fn_rule, "arg_traversal")
check("spill duoc soi -> spill=true", ran.spill, true)
check("spill duoc soi -> source=file", ran.source, "file")
check("spill duoc soi -> scan=ok", ran.scan, "ok")

-- Thread chay nhung worker bao loi.
local werr = probe("POST", MULTI, nil, tmp, function(_, _, _, path, ct)
    return true, worker.scan_file(path, ct, 4)
end)
check("worker bao loi -> scan mang ly do", werr.scan, "spill_big")
check("worker bao loi -> fn_rule nil", werr.fn_rule, nil)

-- MOT LAN moi ly do, khong phai moi request. Mau va cau hinh la HANG SO nen loi
-- o day la loi luc deploy; ghi moi request thi 43 domain do day error.log ma
-- khong them mot bit thong tin nao. Duong bao duoc doc that la cot `scan=`.
if capture_ok then
    check("co keu ngx.ERR", #logged >= 2, true)
    probe("POST", MULTI, nil, tmp)   -- lan hai, cung ly do `nothread`
    check("chi keu MOT LAN moi ly do", #logged, 2)
    ngx.log = ngx_log_real
end

os.remove(tmp)

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
