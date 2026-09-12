local _M    = {}
local pool  = require "antibot.core.redis_pool"
local cfg   = require "antibot.core.config"
local cache = ngx.shared.antibot_cache

-- `asn:type:<n>` da duoc `threat_feed_sync.sh` ghi tu lau (datacenter/vpn/
-- residential) nhung KHONG MOT DONG LUA NAO DOC. Duong doc cu bi xoa cung
-- `ip_classify.lua` ngay 2026-09-06 vi "khong ai dung" — dung vao luc do.
-- Nay co nguoi dung: phan biet VPN voi datacenter.
--
-- Cache 300s trong shm. Va xem cho goi: chi tra khi diem DA vuot tran, nen
-- luu luong binh thuong (khong co `rep:asn:`) tra them KHONG MOT phep I/O nao.
local function asn_type(n)
    local ck = "at:" .. n
    local t
    if cache then t = cache:get(ck) end
    if t == nil then
        t = pool.safe_get("asn:type:" .. n) or ""
        if cache then cache:set(ck, t, 300) end
    end
    return t
end

function _M.run(ctx)
    ctx.asn_rep = 0.0

    if not ctx.asn or not ctx.asn.asn_number then
        return
    end

    local val = pool.safe_get("rep:asn:" .. ctx.asn.asn_number)
    if val then
        local rep = tonumber(val)
        if rep then
            -- TRAN cho ASN kieu VPN. Feed cham VPN 0.75 va datacenter 0.45,
            -- tuc coi VPN dang ngo hon datacenter — sai thu tu. Egress VPN
            -- tieu dung cho phan lon la nguoi that; IP datacenter chay UA
            -- trinh duyet thi kha nang tu dong hoa cao hon han.
            --
            -- Thu tu phep kiem co chu y: `rep > cap` TRUOC khi tra
            -- `asn:type:`. ASN khong co `rep:asn:` thi da thoat o `if val`
            -- ben tren; ASN co diem duoi tran cung khong tra. Nen chi phi
            -- them chi roi vao dung nhom sap bi ha diem.
            local cap = cfg.asn_rep and cfg.asn_rep.vpn_max
            if cap and rep > cap
               and asn_type(ctx.asn.asn_number) == "vpn" then
                rep = cap
            end
            ctx.asn_rep = rep
            ngx.log(ngx.DEBUG,
                "[asn_rep] redis asn=", ctx.asn.asn_number,
                " rep=", rep,
                " ip=", ctx.ip or "?")
        end
    end

    -- S2.5 waiver: PTR contact attest (Path 1) or analyzer attest (Path 2)
    -- has already proven the IP belongs to the operator who declared the bot.
    -- Datacenter prior (asn_rep) is the wrong signal for an attested operator
    -- — Pinterestbot on AWS, PageSpeed on Google Cloud, etc. all run from
    -- datacenter ASNs by design. Drop asn_rep to 0 to prevent ~15pt penalty
    -- per request which keeps eff_score above CHALLENGE threshold.
    if ctx.bot_identity_tier == "S2.5" then
        ctx.asn_rep = 0.0
    end
end

return _M
