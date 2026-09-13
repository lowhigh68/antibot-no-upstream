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

local _M = {}

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

return _M
