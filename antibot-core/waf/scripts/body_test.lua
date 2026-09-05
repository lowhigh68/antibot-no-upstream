-- T — bo test cho waf/body.lua (bo do body, giai doan 1)
--
-- CHAY: ./run.sh   (can OpenResty; dung `resty`, KHONG phai luajit tran)
--
-- Vi sao phai la resty: phep do the mo PHP dung `ngx.re.find(..., "ijo")` —
-- co JIT va co co `i`. Mot stub thuan Lua se kiem mot NGU NGHIA KHAC voi cai
-- chay that; test xanh ma sai ngu nghia con te hon khong co test.
--
-- CACH STUB: thay HAN `ngx.var` va `ngx.req` bang bang Lua thuong. Khong the
-- gan `ngx.var.http_content_type = ...` truc tiep vi ngoai request that,
-- `ngx.var` chi cho ghi len bien nginx da khai bao. `ngx.re` GIU NGUYEN ban
-- that — do la thu duy nhat trong module nay can dung engine.

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

-- `body.lua` require `antibot.waf.args`. Nap bang dofile thi duong dan module
-- khong phan giai duoc, nen phai preload — cung cach wp_paths_test lam voi
-- redis_pool. Preload BAN THAT chu khong phai stub: ta muon kiem dung ket noi
-- giua hai module, khong phai kiem mot ban gia cua no.
package.preload["antibot.waf.args"] = function()
    return dofile(SRC .. "waf/args.lua")
end

local body = dofile(SRC .. "waf/body.lua")

local ngx_var_real, ngx_req_real = ngx.var, ngx.req

-- Dung mot canh: method, content-type, va body nhan duoc.
-- `data = nil` mo phong `get_body_data()` tra nil. Nhung nil co BA nghia khac
-- nhau, va tham so `bodyfile` la thu phan biet chung:
--   bodyfile co gia tri -> body da ghi ra file tam (spill that)
--   bodyfile = false    -> khong co body / body rong (KHONG phai spill)
local function probe(method, ct, data, bodyfile)
    if bodyfile == nil then bodyfile = "/tmp/gia" end
    ngx.var = { http_content_type = ct }
    ngx.req = {
        get_method    = function() return method end,
        read_body     = function() end,
        get_body_data = function() return data end,
        get_body_file = function() return bodyfile or nil end,
    }
    local ctx = {}
    -- pcall BAT BUOC. Neu `probe` nem loi ma khong bat, hai dong khoi phuc duoi
    -- day khong chay, va MOI test con lai chay tren `ngx.var`/`ngx.req` gia —
    -- luc do xanh hay do deu vo nghia. Mot bo test tu lam hong minh giua chung
    -- la thu te hon khong co bo test.
    local ok, err = pcall(body.probe, ctx)
    ngx.var, ngx.req = ngx_var_real, ngx_req_real
    if not ok then
        io.write(string.format("NEM LOI  method=%s ct=%s: %s\n",
                 tostring(method), tostring(ct), tostring(err)))
        return { family = "<loi>", len = -2, spill = false, php = false }
    end
    return ctx.waf_body
end

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

local URLENC = "application/x-www-form-urlencoded"
local MULTI  = "multipart/form-data; boundary=----WebKitFormBoundaryAbC123"

-- ── Cong loc: cai gi KHONG duoc soi ──────────────────────────────────
-- Day la nua quan trong hon. Bo do chay o access phase, tren duong di cua moi
-- request; mot cong loc hong nghia la moi GET deu tra gia.
check("GET khong soi",           probe("GET",  URLENC, "a=1"), nil)
check("HEAD khong soi",          probe("HEAD", URLENC, "a=1"), nil)
check("POST thieu Content-Type", probe("POST", nil,    "a=1"), nil)
check("POST Content-Type rong",  probe("POST", "",     "a=1"), nil)

-- Bon method CO soi. DELETE co trong danh sach vi REST API that co goi
-- DELETE kem body (vi du xoa hang loat).
for _, m in ipairs({ "POST", "PUT", "PATCH", "DELETE" }) do
    check(m .. " co soi", probe(m, URLENC, "a=1") ~= nil, true)
end

-- ── Phan loai content-type ───────────────────────────────────────────
check("family urlencoded", probe("POST", URLENC, "a=1").family,                     "urlencoded")
check("family multipart",  probe("POST", MULTI,  "x").family,                       "multipart")
check("family json",       probe("POST", "application/json", "{}").family,          "json")
check("family xml",        probe("POST", "text/xml", "<a/>").family,                "xml")
-- `text/xml` phai ra "xml" chu khong phai "text": nhanh xml dung TRUOC nhanh
-- text/ trong ct_family, va thu tu do la co y.
check("family text",       probe("POST", "text/plain", "xin chao").family,          "text")
check("family other",      probe("POST", "application/octet-stream", "\1\2").family,"other")
-- Hoa thuong khong duoc anh huong: HTTP header value khong phan biet o day.
check("family khong phan biet hoa thuong",
      probe("POST", "APPLICATION/JSON", "{}").family, "json")

-- ── Do dai va spill ──────────────────────────────────────────────────
check("len dung",        probe("POST", URLENC, "abcde").len,   5)
check("body rong len 0", probe("POST", URLENC, "").len,        0)
check("khong spill",     probe("POST", URLENC, "a=1").spill,   false)
-- Body vuot buffer: nginx ghi ra file tam, get_body_data() tra nil.
-- Phai ghi nhan spill=true chu KHONG duoc bo qua im lang — chinh con so nay
-- quyet dinh `client_body_buffer_size` nen dat bao nhieu.
check("spill co ghi nhan", probe("POST", MULTI, nil).spill,    true)
check("spill len = -1",    probe("POST", MULTI, nil).len,      -1)
check("spill van co family", probe("POST", MULTI, nil).family, "multipart")
-- NIL chu khong phai false. "Khong soi duoc" khac han "da soi, sach" — neu mot
-- phep thong ke ve sau coi php=0 la am tinh thi moi ty le deu lech, va khong ai
-- biet vi log trong nhu binh thuong.
check("spill: php la nil (chua soi)",      probe("POST", MULTI, nil).php,      nil)
check("spill: arg_rule la nil (chua soi)", probe("POST", MULTI, nil).arg_rule, nil)

-- get_body_data() tra nil KHONG dong nghia voi spill: POST rong cung tra nil.
-- Phan biet bang get_body_file(). Gop chung lam mot se thoi phong so spill bang
-- so POST rong, tuc quyet dinh `client_body_buffer_size` tren mot phep dem sai.
check("khong co body -> KHONG phai spill",
      probe("POST", URLENC, nil, false).spill, false)
check("khong co body van co family",
      probe("POST", URLENC, nil, false).family, "urlencoded")
-- `-1` CHI cho spill: do dai co that, ta khong doc no. Khong co body / body
-- rong thi do dai DA BIET va bang 0. Ghi `-1` o day la gop "khong biet" vao
-- mot gia tri — dung loi da sua voi `php = false` — va se THOI PHONG con so
-- dung de chon `client_body_buffer_size`.
check("khong co body -> len 0, KHONG phai -1",
      probe("POST", URLENC, nil, false).len, 0)

-- ── The mo PHP ───────────────────────────────────────────────────────
check("php thuong",      probe("POST", MULTI, "x<?php eval($_POST[0]);").php, true)
check("php hoa",         probe("POST", MULTI, "x<?PHP eval();").php,          true)
check("php hoa thuong lan", probe("POST", MULTI, "<?PhP").php,                true)
check("short echo tag",  probe("POST", MULTI, "a<?= $x ?>b").php,             true)
check("body sach",       probe("POST", URLENC, "name=nguyen&city=ha noi").php,false)
-- `<?xml` KHONG duoc tinh la PHP. Neu bat `<?` tran thi moi upload SVG, moi
-- feed RSS, moi SOAP envelope deu thanh duong tinh — do la cach che ra mot co
-- may FP, dung luc ta dang co gang do xem FP nam o dau.
check("xml khong phai php",  probe("POST", "text/xml", '<?xml version="1.0"?>').php, false)
check("dau hoi tran khong ke", probe("POST", URLENC, "q=<?abc").php,          false)

-- ── Dem tham so ──────────────────────────────────────────────────────
-- Dem `&` thay vi goi get_post_args(): ham do CAT O 100 va khong bao gi, ma
-- 500 tham so moi la truong hop dang ngo nhat.
check("1 tham so",   probe("POST", URLENC, "a=1").nargs,         1)
check("2 tham so",   probe("POST", URLENC, "a=1&b=2").nargs,     2)
check("3 tham so",   probe("POST", URLENC, "a=1&b=2&c=3").nargs, 3)
-- `a&&b` ra 3 — hoi du. Chap nhan co y: doan rong VAN la mot muc tieu ma bo
-- luat phai duyet qua, nen dem no la dung theo muc dich cua con so nay.
check("doan rong van tinh", probe("POST", URLENC, "a=1&&b=2").nargs, 3)

local many = {}
for i = 1, 500 do many[i] = "k" .. i .. "=v" end
check("500 tham so KHONG bi cat",
      probe("POST", URLENC, table.concat(many, "&")).nargs, 500)

-- Multipart phan cach bang boundary chu khong phai `&`. Dem `&` o do ra mot so
-- VO NGHIA, nen phai tra nil de log ghi `-`. Mot con so sai te hon khong co so:
-- no se lang le di vao moi phep thong ke ve sau.
check("multipart nargs = nil", probe("POST", MULTI, "a&b&c").nargs, nil)
check("json nargs = nil",      probe("POST", "application/json", "{\"a\":1}").nargs, nil)

-- ── Luat tham so ap len THAN request ────────────────────────────────
-- Cung ba mau da kiem 35 assertion o args_test. O day chi kiem MOI NOI: than
-- request duoc dua qua args.check, va ket qua ve dung o `arg_rule`.
check("body traversal",  probe("POST", URLENC, "f=../../wp-config.php").arg_rule, "arg_traversal")
check("body wrapper",    probe("POST", URLENC, "f=php://input").arg_rule,         "arg_php_wrapper")
check("body NUL",        probe("POST", URLENC, "f=x%00.jpg").arg_rule,            "arg_null_byte")
check("body sach",       probe("POST", URLENC, "name=nguyen&city=ha noi").arg_rule, nil)
-- Multipart: `../` trong TEN FILE la ky thuat traversal khi upload, va no khong
-- xuat hien o dau khac. Phai bat.
check("multipart ten file traversal",
      probe("POST", MULTI, 'Content-Disposition: form-data; name="f"; filename="../../shell.php"').arg_rule,
      "arg_traversal")
-- Spill: khong co body trong bo nho thi khong the soi. Phai la nil, KHONG duoc
-- doan bua — mot ket qua bia o day se lam lech moi phep dem ve sau.
check("spill khong co arg_rule", probe("POST", MULTI, nil).arg_rule, nil)

-- ── Family NHI PHAN: luat NUL phai tat ───────────────────────────────
-- Do 2026-09-05: 67/67 luot `arg_null_byte` deu la byte NUL trong NOI DUNG
-- file upload, `fnm=0` cho ca 61 luot multipart. Moi dinh dang nhi phan chua
-- NUL theo dung dac ta cua no, nen luat khong phat hien tan cong — no phat hien
-- "vua co nguoi upload file". O trong so 50 thi moi anh san pham deu +50 diem.
local PNGPART = 'Content-Disposition: form-data; name="f"; filename="anh.jpg"\r\n'
             .. '\r\n' .. "\137PNG\r\n\26\n" .. string.char(0,0,0,13) .. "IHDR"

check("multipart chua NUL -> KHONG ban",
      probe("POST", MULTI, PNGPART).arg_rule, nil)

-- Nhung `%00` DANG CHUOI thi van phai ban, ke ca trong multipart: no la mau
-- VAN BAN nam o dong header, khong phai byte cua dinh dang nhi phan.
check("multipart: `%00` trong ten file VAN ban",
      probe("POST", MULTI,
            'Content-Disposition: form-data; name="f"; filename="shell.php%00.jpg"').arg_rule,
      "arg_null_byte")

-- `filename*=` (RFC 5987). `find("filename=")` KHONG khop chuoi nay vi co dau
-- `*` chen giua — mot cho nup neu ai do coi `fnm` la luat thay vi cot do.
check("fnm: nhan ca `filename*=` cua RFC 5987",
      probe("POST", MULTI,
            "content-disposition: form-data; name=\"f\"; filename*=utf-8''x../y").fnm,
      true)

-- Nhung urlencoded thi NUL VAN la bat thuong that: mot truong form khong bao
-- gio chua byte NUL. Chi than nhi phan moi duoc mien.
check("urlencoded chua NUL -> VAN ban",
      probe("POST", URLENC, "f=x%00.jpg").arg_rule, "arg_null_byte")

-- json/xml/text khong nam trong BINARY_FAMILY, nen cung van ban.
check("json chua NUL -> VAN ban",
      probe("POST", "application/json", '{"f":"x%00"}').arg_rule, "arg_null_byte")

-- Tat NUL KHONG duoc lam tat hai luat kia. Day cung la ca chung minh con so
-- "0 luot traversal tren body" truoc day chi la do NUL che khuat.
check("multipart: traversal trong ten file VAN ban",
      probe("POST", MULTI, 'filename="../../shell.php"' .. string.char(0)).arg_rule,
      "arg_traversal")


-- ── Cot phan tang `fnm` ─────────────────────────────────────────────
-- KHONG phai luat: no khong chan gi, khong doi diem. No tach hai dan so ma
-- `arg_rule` dang gop lam mot tren than multipart — TEN FILE (gan nhu chac chan
-- la tan cong) va NOI DUNG file/bai viet (gan nhu chac chan la FP) — de vai
-- ngay nua co can cu quyet dinh co nang `waf_body_arg` len khoi 0 hay khong.
--
-- Phep kiem la "cung DONG voi `filename=`", vi trong multipart ten file nam
-- tren dong header Content-Disposition con noi dung file nam sau mot dong
-- trong. Mot cua so nhin-lui tuy y thi phai chon do rong, va moi lua chon deu
-- sai voi mot header du dai.
local MP_NAME = 'Content-Disposition: form-data; name="f"; filename="../../shell.php"'
local MP_BODY = 'Content-Disposition: form-data; name="post_content"\r\n'
             .. '\r\n'
             .. 'Bai viet noi ve duong dan tuong doi ../ trong PHP\r\n'

check("fnm: khop trong ten file",   probe("POST", MULTI, MP_NAME).fnm, true)
check("fnm: khop trong noi dung",   probe("POST", MULTI, MP_BODY).fnm, false)

-- Ngoai multipart thi cau hoi khong co nghia — `-` chu khong phai 0. Cung
-- nguyen tac da dung cho `php` va `exists`: khong biet thi noi khong biet, dung
-- bien mot khoang trong thanh mot am tinh.
check("fnm: urlencoded -> nil",
      probe("POST", URLENC, "f=../../wp-config.php").fnm, nil)
check("fnm: multipart nhung khong luat nao ban -> nil",
      probe("POST", MULTI, "noi dung vo hai").fnm, nil)
check("fnm: spill -> nil", probe("POST", MULTI, nil).fnm, nil)

-- ── `fn_rule`: soi RIENG ten file, doc lap voi than ─────────────────
-- `fnm` tai su dung vi tri cua luat toan than nen (a) le thuoc thu tu uu tien
-- NUL->wrapper->traversal, (b) khong soi duoc `filename*=`. `fn_rule` chay luat
-- len CHINH gia tri ten file nen khong dinh ca hai.

local CD = 'Content-Disposition: form-data; name="f"; '

-- CA QUYET DINH CUA CA NHOM NAY. Truoc khi co ham nay, tai trong duoi day lot
-- sach: than multipart chay decode=false, ma gia tri `filename*=` theo RFC 5987
-- LA percent-encoding.
check("fn_rule: filename*= traversal da ma hoa",
      probe("POST", MULTI, CD .. "filename*=UTF-8''..%2F..%2Fshell.php").fn_rule,
      "arg_traversal")

-- CAP DOI CHUNG cho viec giai ma CO PHAN BIET. Cung mot chuoi `..%2F`, khac
-- moi dang cu phap: `filename*=` duoc giai ma, `filename=` thi KHONG. Neu giai
-- ma bua ca hai thi mot file khach dat ten `a..%2Fb.pdf` se ban — dung dang FP
-- ca tang nay tranh.
check("fn_rule: filename= KHONG duoc giai ma",
      probe("POST", MULTI, CD .. 'filename="a..%2Fb.pdf"').fn_rule, nil)

check("fn_rule: traversal tho trong ten file",
      probe("POST", MULTI, CD .. 'filename="../../shell.php"').fn_rule,
      "arg_traversal")
check("fn_rule: `%00` trong ten file khong nhay",
      probe("POST", MULTI, CD .. "filename=x.php%00.jpg").fn_rule,
      "arg_null_byte")
check("fn_rule: khong phan biet hoa thuong",
      probe("POST", MULTI, 'FILENAME="../x"').fn_rule, "arg_traversal")
check("fn_rule: ten file lanh -> im",
      probe("POST", MULTI, CD .. 'filename="anh-san-pham.jpg"').fn_rule, nil)

-- Noi dung nhi phan KHONG duoc lam ban: no khong chua `filename=` nen khong
-- vao duong nay. Day la khac biet then chot so voi `arg_rule`.
check("fn_rule: PNG co byte NUL, ten file lanh -> im",
      probe("POST", MULTI, CD .. 'filename="anh.jpg"\r\n\r\n'
            .. "\137PNG\r\n\26\n" .. string.char(0,0,0,13) .. "IHDR").fn_rule, nil)

-- NHIEU PHAN: phai quet HET. Upload thu vien anh co hang chuc phan va tan cong
-- thuong nam o phan cuoi, khong phai phan dau.
check("fn_rule: quet het moi phan, khong dung o cai dau",
      probe("POST", MULTI,
            CD .. 'filename="ok.jpg"\r\n\r\nAAA\r\n'
            .. 'Content-Disposition: form-data; name="b"; filename="../../s.php"').fn_rule,
      "arg_traversal")

check("fn_rule: khong phai multipart -> nil",
      probe("POST", URLENC, 'filename="../../x"').fn_rule, nil)
check("fn_rule: spill -> nil", probe("POST", MULTI, nil).fn_rule, nil)

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
