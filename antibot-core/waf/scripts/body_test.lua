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

local body = dofile(SRC .. "waf/body.lua")

local ngx_var_real, ngx_req_real = ngx.var, ngx.req

-- Dung mot canh: method, content-type, va body nhan duoc.
-- `data = nil` mo phong truong hop nginx da ghi body ra file tam (vuot
-- `client_body_buffer_size`), tuc `get_body_data()` tra nil.
local function probe(method, ct, data)
    ngx.var = { http_content_type = ct }
    ngx.req = {
        get_method    = function() return method end,
        read_body     = function() end,
        get_body_data = function() return data end,
        get_body_file = function() return "/tmp/gia" end,
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
check("spill khong doan php", probe("POST", MULTI, nil).php,   false)

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

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
