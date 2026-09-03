local _M = {}

-- BO DO BODY — giai doan 1: CHI QUAN SAT, khong luat nao ban.
--
-- Vi sao chua co luat. Ca phien lam viec nay da bac bo sau gia thuyet lien tiep
-- bang so lieu that (mu-plugins "backdoor" hoa ra la ban va cua agency SEO;
-- "status=200 nghia la da bi chiem" sai hai lan; "cong cu quan tri WP tap trung"
-- bi chinh output bac bo). Viet luat body ma khong biet body tren dan may nay
-- chua gi la lap lai dung sai lam do — chi khac la lan nay hau qua roi vao
-- 43 domain that.
--
-- Nen module nay ghi lai NHUNG GI CO TRONG BODY va khong quyet dinh gi ca. Sau
-- vai ngay se co phan bo that de viet luat co can cu.
--
-- ── Cai gia thuc su bang KHONG ──────────────────────────────────────────
-- `ngx.req.read_body()` nghe thi dat, thuc te khong them gi:
-- `proxy_request_buffering` KHONG duoc dat trong repo nay ⇒ mac dinh `on` ⇒
-- nginx VON DA doc va dem tron body truoc khi gui len Apache. Doc no o day chi
-- la nhin vao thu da nam san trong bo nho.
-- (`proxy_buffering off` trong `da_to_openresty.sh` la dem PHAN HOI — directive
-- khac, dung nham thi ket luan nguoc.)

local args = require "antibot.waf.args"

local INSPECT_METHODS = {
    POST = true, PUT = true, PATCH = true, DELETE = true,
}

-- The mo PHP, khong phan biet hoa thuong: `<?PHP` cung la PHP hop le.
-- `<?=` la short echo tag, bat mac dinh tu PHP 5.4.
-- KHONG bat `<?` tran: XML khai bao `<?xml` va se lam nhieu moi upload SVG/RSS.
local RX_PHP_OPEN = [[<\?(?:php|=)]]

-- Phan loai content-type ve mot nhan NGAN de dem duoc.
-- Chuoi that dai va co bien the (`multipart/form-data; boundary=----WebKit...`),
-- do nguyen vao log thi khong nhom duoc bang uniq -c.
local function ct_family(ct)
    if not ct or ct == "" then return "-" end
    local low = ct:lower()
    if low:find("multipart/form-data", 1, true)               then return "multipart"  end
    if low:find("application/x-www-form-urlencoded", 1, true) then return "urlencoded" end
    if low:find("json", 1, true)                              then return "json"       end
    if low:find("xml",  1, true)                              then return "xml"        end
    if low:find("text/", 1, true)                             then return "text"       end
    return "other"
end

-- Dem tham so body bang cach dem `&`, KHONG goi `ngx.req.get_post_args()`.
-- Cung ba ly do da ghi o `async/logger.lua:414` cho tham so query:
--   1. `get_post_args()` mac dinh CAT O 100 phan tu va khong bao gi. Ta can con
--      so THAT, ke ca khi ben gui 500 tham so — do chinh la truong hop dang ngo.
--   2. No cap phat mot bang Lua moi request; dem `&` chi quet chuoi.
--   3. Day la access phase, nam tren duong di cua moi request.
-- Chi co nghia voi urlencoded. Multipart phan cach bang boundary, dem `&` ra so
-- vo nghia — nen tra nil de log ghi `-` thay vi mot con so sai.
local function count_args(body, family)
    if family ~= "urlencoded" or not body or body == "" then return nil end
    local n = 1
    local pos = 1
    while true do
        local i = body:find("&", pos, true)
        if not i then break end
        n = n + 1
        pos = i + 1
    end
    return n
end

-- Chay trong `waf.run_pre`, TRUOC cua thoat tin cay — cung ly do ca tang WAF
-- dung o do: cookie `verified` song 7200s, va danh tinh da xac minh khong noi gi
-- ve NOI DUNG request.
--
-- Cong loc phai RE, vi no chay cho moi request:
--   1. method — mot lan `ngx.req.get_method()`, khong I/O
--   2. co Content-Type khong
-- GET/HEAD (gan het luu luong) thoat o buoc 1.
--
-- CONG LA Content-Type, TUYET DOI KHONG PHAI Content-Length.
-- Do 2026-09-02 tren luu luong that: 387 POST multipart trong 24h bao `cl=0`
-- — chunked transfer-encoding thi khong co Content-Length. Gac bang `cl > 0` se
-- bo qua dung nhom dang quan tam nhat (upload file), va bo qua trong im lang.
function _M.probe(ctx)
    if not INSPECT_METHODS[ngx.req.get_method()] then return end

    local ct = ngx.var.http_content_type
    if not ct or ct == "" then return end

    local family = ct_family(ct)

    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if not body then
        -- `get_body_data()` tra nil o BA tinh huong khac nhau, va gop chung lam
        -- mot la lam hong chinh phep do nay:
        --   1. body vuot `client_body_buffer_size` -> nginx ghi ra file tam
        --   2. khong co body (POST rong, hoac Content-Length 0)
        --   3. body rong
        -- Chi (1) moi la `spill`. Phan biet bang `get_body_file()`: co duong dan
        -- file tam nghia la (1), khong co nghia la (2)/(3).
        --
        -- Neu goi ca ba la spill thi con so dung de quyet dinh
        -- `client_body_buffer_size` bi thoi phong bang so POST rong — tuc quyet
        -- dinh sai tren mot phep dem sai.
        local spilled = ngx.req.get_body_file() ~= nil

        -- KHONG doc file tam o day: access phase, `io.open` la I/O CHAN nam tren
        -- duong di cua moi request — dung dieu luat repo cam (xem `run_log`,
        -- noi phep cham dia duy nhat cua tang nay duoc phep ton tai).
        --
        -- `php` va `arg_rule` de NIL, khong phai `false`/`0`.
        -- "Khong soi duoc" khac han "da soi, khong thay gi". Ban truoc ghi
        -- `php = false` ngay canh chu thich noi dung dieu do — tuc tu mau thuan.
        -- Neu mot phep thong ke ve sau coi `php=0` la am tinh thi moi ty le deu
        -- lech, va khong ai biet vi log trong nhu binh thuong.
        ctx.waf_body = {
            family   = family,
            spill    = spilled,
            len      = -1,
            php      = nil,
            nargs    = nil,
            arg_rule = nil,
        }
        return
    end

    ctx.waf_body = {
        family = family,
        spill  = false,
        len    = #body,
        -- Mot luot PCRE da JIT tren toi da `client_body_buffer_size` byte.
        php    = ngx.re.find(body, RX_PHP_OPEN, "ijo") ~= nil,
        nargs  = count_args(body, family),

        -- Ba luat tham so, ap len than request. `args.check` khong biet gi ve
        -- NGUON chuoi no nhan, nen dung lai nguyen ven — cung ba mau, cung vong
        -- giai ma 3 muc, cung 35 assertion da kiem.
        --
        -- Co ap cho multipart: `../` trong TEN FILE cua mot phan multipart la
        -- dung ky thuat traversal khi upload, va no khong xuat hien o dau khac.
        --
        -- KHAC BIET THAT SU so voi query string, va la ly do nay chi la SIGNAL:
        -- than request chua NOI DUNG NGUOI DUNG SOAN. Mot quan tri vien viet bai
        -- ve stream wrapper PHP roi bam Luu se gui `php://` trong than POST toi
        -- /wp-admin/post.php. Query string khong bao gio co chuyen do. FP o day
        -- vo hai (50 diem duoi CHALLENGE, va `auth_session_cap` da chan quan tri
        -- vien dang nhap o muc monitor) nhung phai DEM duoc truoc khi tinh
        -- chuyen nang len block.
        -- `decode` CHI bat cho urlencoded. Da giai thich day du o `args.check`:
        -- giai ma mot noi dung khong phai percent-encoding la dien giai sai ban
        -- chat du lieu va TU TAO ra duong tinh gia — mot file .txt upload chua
        -- chuoi ky tu `%2e%2e%2f` se bien thanh `../` sau mot lan unescape.
        arg_rule = args.check(body, family == "urlencoded"),
    }
end

return _M
