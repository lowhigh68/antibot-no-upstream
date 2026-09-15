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
local cfg   = require "antibot.core.config"
local cache = ngx.shared.antibot_cache

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
-- BA HINH THAI MANG, chi hinh thai thu ba can `cfg.self_addrs` (xem chu thich
-- day du tai `core/config.lua`):
--   1. khong NAT, card chi co IP public      => `$server_addr` du
--   2. co NAT, card co CA public lan private => `$server_addr` du
--   3. co NAT, card CHI co IP private        => PHAI khai `self_addrs`
function _M.is_self()
    local peer = _M.tcp_peer()
    if peer == "" then return false end

    local s = ngx.var.server_addr
    if s and s ~= "" and peer == s then return true end

    local list = cfg.self_addrs
    if list then
        for i = 1, #list do
            if peer == list[i] then return true end
        end
    end

    -- HINH THAI 3 MA CHUA KHAI: canh bao, dung im lang.
    --
    -- `$server_addr` la dia chi RIENG nghia la nginx dang lang nghe sau NAT, va
    -- dia chi public nam o noi khac. Khi do ca hai cong goi ham nay deu khong
    -- bao gio kich hoat, ma chung KHONG bao loi — chung chi... khong lam gi.
    -- Day dung lop that bai am tham da giet `wp_paths.mark()` bon thang va lam
    -- mot phep do bao `0` sai su that hom 14-09. Mot dong canh bao moi gio re
    -- hon nhieu so voi viec phat hien ra sau ba tuan.
    if (not list or #list == 0)
       and s and s ~= "" and _M.is_private(s) then
        if cache and cache:add("ip_scope_nat_warn", 1, 3600) then
            ngx.log(ngx.WARN,
                "[ip_scope] server_addr=", s, " la dia chi RIENG => may dung ",
                "sau NAT, nhung cfg.self_addrs RONG. Cac cong 'khong tu ket an' ",
                "va 'khong tu gan nhan farm' se KHONG BAO GIO kich hoat tren may ",
                "nay. Khai dia chi public vao core/config.lua: self_addrs.")
        end
    end

    return false
end

return _M
