-- T — bo test cho waf/args.lua (luat THAM SO)
--
-- CHAY: ./run.sh   (can OpenResty; dung `resty`, KHONG phai luajit tran)
--
-- Vi sao phai la resty: `ngx.re.find` voi co "jo" va `ngx.unescape_uri`. Mot
-- stub thuan Lua se kiem mot NGU NGHIA KHAC voi cai chay that.
--
-- TRONG TAM CUA BO TEST NAY LA NHOM "PHAI IM", khong phai nhom "phai ban".
-- Ba luat nay chay tren query string cua MOI request co tham so — tren dan may
-- nay la hang tram nghin luot moi ngay. Mot mau bat qua rong khong lam sai mot
-- phan tich, no bien tang WAF thanh mot co may FP. Ban sot mot tai trong thi
-- con FIM va cac tang khac; ban oan mot o tim kiem thi hong ngay.

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

local args = dofile(SRC .. "waf/args.lua")

local pass, fail = 0, 0
local function check(qs, want, why)
    local ok, got = pcall(args.check, qs)
    if not ok then
        fail = fail + 1
        io.write(string.format("  LOI  %-52s %s\n", qs, tostring(got)))
    elseif got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  %-52s cho=%s duoc=%s\n       %s\n",
                 qs, tostring(want), tostring(got), why))
    else
        pass = pass + 1
    end
end

io.write("\nargs.check() — phai IM\n")

-- Query string that tu luu luong WordPress binh thuong. Day la nhom quyet dinh:
-- neu bat ky dong nao duoi day ban, luat khong duoc trien khai.
check("",                                    nil, "rong")
check("p=123",                               nil, "tham so thuong")
check("s=ao+dai+nam",                        nil, "o tim kiem tieng Viet")
check("s=gi%C3%A1+r%E1%BA%BB",               nil, "tim kiem UTF-8 da ma hoa")
check("post_type=product&orderby=price",     nil, "WooCommerce sap xep")
check("filter_size=39,40,41&min_price=100",  nil, "WooCommerce loc, co dau phay")
check("action=heartbeat&_nonce=a1b2c3",      nil, "admin-ajax heartbeat")
check("ver=6.4.2",                           nil, "tham so phien ban asset")
check("redirect_to=%2Fwp-admin%2F",          nil, "redirect_to chuan cua WP")
check("url=https%3A%2F%2Fexample.com%2Fa",   nil, "URL tuyet doi trong tham so")
-- `..` KHONG kem dau gach cheo: ten file, so thap phan, khoang gia.
check("f=bao-cao..pdf",                      nil, "hai dau cham trong ten file")
check("range=10..20",                        nil, "khoang so")
check("v=1.2..1.3",                          nil, "khoang phien ban")
-- `data:` dang HTML (KHONG co `//`) phai im. Chinh vi vay mau doi `://`.
check("img=data:image/png;base64,iVBORw0KGg", nil, "data URI dang HTML, khong phai wrapper")
check("proto=https",                         nil, "ten giao thuc tran")
check("note=file%20not%20found",             nil, "tu 'file' khong kem ://")

io.write("\nargs.check() — phai BAN\n")

-- Traversal
check("f=../../wp-config.php",               "arg_traversal", "LFI kinh dien")
check("page=..%2f..%2fetc%2fpasswd",         "arg_traversal", "ma hoa mot lop")
check("page=%252e%252e%252fetc",             "arg_traversal", "ma hoa HAI lop")
check("f=..\\..\\windows\\win.ini",          "arg_traversal", "dau gach nguoc")
check("a=1&b=../x",                          "arg_traversal", "nam o tham so thu hai")
check("F=../X",                              "arg_traversal", "khong phan biet hoa thuong")

-- Stream wrapper
check("f=php://input",                       "arg_php_wrapper", "php://input")
check("f=php://filter/convert.base64-encode/resource=wp-config.php",
                                             "arg_php_wrapper", "php://filter doc wp-config")
check("f=data://text/plain;base64,PD9waHA",  "arg_php_wrapper", "data:// dang wrapper (CO //)")
check("f=expect://id",                       "arg_php_wrapper", "expect:// = RCE")
check("f=phar://x.phar/a",                   "arg_php_wrapper", "phar:// deserialization")
check("f=php%3A%2F%2Finput",                 "arg_php_wrapper", "wrapper da ma hoa")
check("f=compress.zlib://x",                 "arg_php_wrapper", "compress.* wrapper")

-- Null byte
check("f=wp-config.php%00.jpg",              "arg_null_byte", "cat chuoi de vuot kiem duoi")
check("f=%2500",                             "arg_null_byte", "NUL ma hoa hai lop")

io.write("\nargs.check() — thu tu uu tien\n")

-- Chi tra ve MOT rule_id. Thu tu theo do CHAC CHAN giam dan, nen mot chuoi mang
-- ca hai dau hieu phai duoc gan nhan cai CHAC hon — do la nhan huu ich hon khi
-- doc log ve sau.
check("f=php://filter/resource=../../wp-config.php",
      "arg_php_wrapper", "co ca wrapper lan traversal — wrapper chac hon")
check("f=../x%00",  "arg_null_byte", "co ca traversal lan NUL — NUL chac hon")

io.write("\nargs.check(s, decode=false) — noi dung KHONG phai percent-encoding\n")

local function ncheck(s, want, why)
    local ok, got = pcall(args.check, s, false)
    if not ok then
        fail = fail + 1
        io.write(string.format("  LOI  %-52s %s\n", s, tostring(got)))
    elseif got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  %-52s cho=%s duoc=%s\n       %s\n",
                 s, tostring(want), tostring(got), why))
    else
        pass = pass + 1
    end
end

-- Mau THO van bat binh thuong.
ncheck("f=../../wp-config.php", "arg_traversal",   "mau tho van bat")
ncheck("f=php://input",         "arg_php_wrapper", "mau tho van bat")

-- DANH DOI CO Y, va day la ly do ton tai cua tham so nay: mot body multipart
-- chua dung chuoi KY TU `%2e%2e%2f` (vi du mot file .txt duoc upload) se BIEN
-- THANH `../` sau mot lan unescape va ban — mot FP hoan toan do buoc giai ma
-- tao ra, khong he co trong du lieu goc. Multipart/JSON/binary khong phai
-- percent-encoding, nen giai ma chung la dien giai sai ban chat du lieu.
ncheck("f=%2e%2e%2fx", nil, "khong giai ma => khong thay, va do la DUNG voi multipart")
ncheck("noi dung file: %2e%2e%2f la mot chuoi vo hai", nil,
       "chinh la FP ma tham so nay ngan chan")

io.write("\nargs.describe() — KHONG duoc lo gia tri\n")

local function dcheck(qs, want, why)
    local ok, got = pcall(args.describe, qs)
    if not ok then
        fail = fail + 1
        io.write(string.format("  LOI  %-52s %s\n", qs, tostring(got)))
    elseif got ~= want then
        fail = fail + 1
        io.write(string.format("  SAI  %-52s cho=%s duoc=%s\n       %s\n",
                 qs, tostring(want), tostring(got), why))
    else
        pass = pass + 1
    end
end

-- Ca quan trong nhat cua ca file nay. Day la dinh dang dat lai mat khau CUA
-- CHINH WordPress — mot credential song trong query string. Ten tham so duoc
-- ghi (lUOC DO, huu ich khi doc log), gia tri thi KHONG.
dcheck("action=rp&key=SECRET123&login=admin",
       "<action,key,login:35>", "token dat lai mat khau — chi ghi TEN")
dcheck("code=oauth_secret_abc&state=xyz",
       "<code,state:31>",       "OAuth authorization code")
dcheck("s=ao+dai",              "<s:8>",  "o tim kiem — gia tri cung khong ghi")
dcheck("",                      "-",      "rong")
dcheck("=chigiatri",            "<:10>",  "khong co ten tham so")

-- THAM SO KHONG CO DAU `=`: ca chuoi chinh la gia tri, nen ghi "ten" o day la
-- ghi noi dung. Mot token dat trong query dang key-only di qua duong nay se ro
-- 32 ky tu dau, va whitelist ky tu KHONG cuu duoc vi token base64 toan
-- [A-Za-z0-9]. Ghi `?`: co mot tham so dang do, khong noi no la gi.
dcheck("khongcodau",            "<?:10>", "key-only — KHONG duoc ghi noi dung")
dcheck("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdef",
       "<?:43>",                "JWT dat tran trong query — chi ghi `?`")
dcheck("a=1&SECRETTOKEN",       "<a,?:15>", "key-only nam sau mot tham so thuong")

-- Chan do dai: mot ten tham so dai bat thuong cung la du lieu ke tan cong dieu
-- khien, khong duoc de no chiem het dong log.
local long = string.rep("k", 60)
dcheck(long .. "=1", "<" .. string.rep("k", 32) .. "~:62>", "ten dai bi cat")

-- TEN THAM SO LA DU LIEU KE GUI DIEU KHIEN. `scrub` ben waf_logger da chan gia
-- mao dong log, nhung `,` `:` `<` `>` van song sot va lam nhieu dung dinh dang
-- `<a,b:35>` cua chinh ham nay. Ep ve [A-Za-z0-9_.-], thay bang `_`.
dcheck("a:9=1",       "<a_9:5>",   "dau `:` trong ten lam nhieu truong do dai")
dcheck("x,y=1",       "<x_y:5>",   "dau phay trong ten lam nhieu bang phan cach")
dcheck("<b>=1",       "<_b_:5>",   "dau nhon lam nhieu cap bao ngoai")
dcheck("ok_.-1=1",    "<ok_.-1:8>", "ky tu hop le KHONG bi doi")

io.write("\nargs.describe() — marker `,+` khi vuot MAX_NAMES\n")

-- MEP CUA MAX_NAMES = 8. Ban truoc hoi sai cau ("phia sau con dau `&` nao
-- khong") nen dung 9 tham so hien ra Y HET 8: vong thu 8 day `pos` toi tham so
-- CUOI, khong con `&` phia sau, marker khong bat. Bon ca duoi day neo ca hai
-- mep — 7 va 8 phai IM, 9 va 10 phai co marker.
local function mk(k)
    local t = {}
    for i = 1, k do t[i] = string.char(96 + i) .. "=1" end
    return table.concat(t, "&")
end

dcheck(mk(7),  "<a,b,c,d,e,f,g:27>",      "7 tham so — chua cham tran")
dcheck(mk(8),  "<a,b,c,d,e,f,g,h:31>",    "8 tham so — cham tran DUNG, khong du")
dcheck(mk(9),  "<a,b,c,d,e,f,g,h,+:35>",  "9 tham so — DUNG CA DA LOT")
dcheck(mk(10), "<a,b,c,d,e,f,g,h,+:39>",  "10 tham so — van co marker")
dcheck(mk(8) .. "&", "<a,b,c,d,e,f,g,h:32>",
       "8 tham so + dau `&` thua — KHONG duoc bia ra tham so thu 9")

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
