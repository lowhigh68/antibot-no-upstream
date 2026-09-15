-- ip_scope — phep kiem "dia chi nay co thuoc dai noi bo khong".
--
-- VI SAO TACH RA MOT MODULE RIENG. Truoc day phep kiem nay la mot ham `local`
-- trong `core/access/whitelist.lua`, va no gac mot DAC QUYEN: dia chi noi bo
-- thi mien toan bo pipeline. Nay `core/ctx/init.lua` cung phai hoi dung cau
-- hoi ay, o mot cho khac han, de tu choi mot header dam khai minh la noi bo.
--
-- Hai ban sao cua cung mot phep kiem an ninh la cach chung bat dau lech nhau:
-- ai do them `100.64.0.0/10` vao mot ban, quen ban kia, va lo hong mo ra o
-- dung cho khong ai nhin. Nen chi co MOT ban, o day.
--
-- Pham vi bao phu (giu nguyen y het ban goc trong whitelist.lua):
--   127.0.0.0/8     loopback          10.0.0.0/8      RFC1918 A
--   172.16.0.0/12   RFC1918 B         192.168.0.0/16  RFC1918 C
--   ::1             IPv6 loopback     fe80::/10       IPv6 link-local
--   fc00::/7        IPv6 unique local (tien to fc / fd)

local _M    = {}
local cache = ngx.shared.antibot_cache

-- Dia chi cua CHINH MAY NAY, sinh tai cho boi `nginx/deploy.sh` moi lan deploy
-- (`ip addr` cho dia chi tren card + `getent` cho dia chi ma hostname tro toi,
-- tuc dia chi public cua may dung sau NAT). KHONG khai tay trong `config.lua`:
-- file do deploy chung cho ca dan may, nen khai tay se bat moi may mang danh
-- sach IP cua moi may khac, va may thu sau lai phai sua tay lan nua.
--
-- Doc MOT LAN luc nap module. Moi lan deploy deu reload nginx nen file duoc doc
-- lai — khong can timer, khong cham Redis, khong ton gi o duong request.
local SELF_PATH = ngx.config.prefix() .. "conf/antibot/self_addrs.txt"

local function load_self_addrs()
    local t, n = {}, 0
    local f = io.open(SELF_PATH, "r")
    if not f then return t, n end
    for line in f:lines() do
        local a = line:match("^%s*([%x%.:]+)%s*$")
        if a and a ~= "" then t[a] = true; n = n + 1 end
    end
    f:close()
    return t, n
end

local SELF_ADDRS, SELF_N = load_self_addrs()

function _M.is_private(ip)
    if not ip or ip == "" then return false end
    if ip:find("^127%.", 1, false) then return true end
    if ip:find("^10%.", 1, false) then return true end
    if ip:find("^192%.168%.", 1, false) then return true end
    local b = ip:match("^172%.(%d+)%.")
    if b then
        local n = tonumber(b)
        if n and n >= 16 and n <= 31 then return true end
    end
    if ip == "::1" then return true end
    local p2 = ip:sub(1, 2):lower()
    if p2 == "fc" or p2 == "fd" then return true end
    if ip:sub(1, 4):lower() == "fe80" then return true end
    return false
end

-- Dia chi TCP THAT cua ket noi, truoc khi `ngx_http_realip_module` kip ghi de
-- `remote_addr`.
--
-- BA TRANG THAI, KHONG PHAI HAI. `$realip_remote_addr` chi co gia tri khi
-- realip THUC SU ghi de; khong cau hinh realip thi no rong. Doc chuoi rong ay
-- thanh "dia chi rong" se bien moi request tren may khong dung Cloudflare
-- thanh mot ctx.ip rong — ma `ctx.ip == ""` la loi FATAL (FATAL_FIELDS o
-- `ctx/init.lua`). Rong o day nghia la "khong co realip", va luc do dia chi
-- TCP that CHINH LA remote_addr.
function _M.tcp_peer()
    local t = ngx.var.realip_remote_addr
    if not t or t == "" then
        return ngx.var.remote_addr or ""
    end
    return t
end

-- Request nay co phai do CHINH MAY NAY phat ra khong (may tu goi minh).
--
-- `$server_addr` la dia chi cua socket DA NHAN ket noi. Khi mot tien trinh tren
-- may goi `https://<domain cua chinh no>`, dich la mot dia chi cuc bo nen nhan
-- dinh tuyen qua `lo` va chon nguon bang chinh dia chi dich — hai ben bang
-- nhau. Voi may co NHIEU dia chi tren mot card (do 14-09 tren cloud186-126:
-- `192.168.186.126/24` VA `123.30.186.126/25` cung tren `ens160`), phep kiem
-- nay van dung cho tung dia chi, khac han viec lay "dia chi dau tien tren card"
-- — cai bay da lam mot lenh do bao `0` sai su that hom 14-09.
--
-- SO VOI `tcp_peer()`, KHONG so voi `ctx.ip`. `ctx.ip` co the do
-- `real_ip_header` ghi de tu mot header; `ctx/init.lua` chi tu choi dia chi
-- NOI BO do header khai, nen dia chi CONG CONG cua chinh may van lot qua duoc.
-- Ma ham nay cap MIEN TRU (khong ban, khong gan nhan farm), tuc mot dac quyen:
-- so voi gia tri client dat duoc la mo cua cho ke tan cong tu cap dac quyen
-- bang mot dong header. `$server_addr` va `$realip_remote_addr` deu khong the
-- gia mao tu xa.
-- BA HINH THAI MANG tren dan may nay, va `self_addrs.txt` phu ca ba:
--
--   1. KHONG NAT, card chi co IP public.
--      cloud171-96 `123.30.171.96`, cloud183-139, cloud28-246.
--      `$server_addr` = IP public, va `ip addr` cung thay no.
--
--   2. CO NAT, card mang CA public LAN private.
--      cloud186-126: `123.30.186.126/25` va `192.168.186.126/24` cung tren
--      `ens160`. `$server_addr` la dia chi cua socket DA NHAN ket noi nen tu
--      khop dung duong ma request di vao; `ip addr` thay ca hai.
--
--   3. CO NAT, card CHI co IP private.
--      cloud168-101: card chi co `192.168.168.101`, con vao va ra deu qua
--      `123.30.168.101`. `$server_addr` va dia chi cua luu luong tu-goi KHONG
--      BAO GIO khop. Day la hinh thai duy nhat can den `getent` — hostname cua
--      may tro toi dia chi public, va do la thu duy nhat ben trong may biet
--      duoc ve dia chi ben ngoai cua no.
function _M.is_self()
    local peer = _M.tcp_peer()
    if peer == "" then return false end

    if SELF_ADDRS[peer] then return true end

    local s = ngx.var.server_addr
    if s and s ~= "" and peer == s then return true end

    -- FILE THIEU HOAC RONG: canh bao, dung im lang.
    --
    -- Che do hong o day khong phai bao loi ma la KHONG LAM GI CA: ca hai cong
    -- goi ham nay se khong bao gio kich hoat, va may lai tu ket an chinh no ma
    -- khong ai thay. Dung lop that bai da giet `wp_paths.mark()` bon thang va
    -- lam mot phep do bao `0` sai su that hom 14-09.
    --
    -- Van con `$server_addr` do o tren, nen hinh thai 1 va 2 khong hong khi
    -- thieu file — chi hinh thai 3 mat bao ve. Canh bao cho ca hai truong hop vi
    -- tu trong Lua khong phan biet duoc may dang o hinh thai nao.
    if SELF_N == 0 and cache
       and cache:add("ip_scope_selfaddr_warn", 1, 3600) then
        ngx.log(ngx.WARN,
            "[ip_scope] ", SELF_PATH, " thieu hoac rong. May sau NAT (card chi ",
            "co IP private) se KHONG duoc bao ve khoi viec tu ket an chinh no. ",
            "Chay lai ./nginx/deploy.sh de sinh file.")
    end

    return false
end

return _M
