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

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
