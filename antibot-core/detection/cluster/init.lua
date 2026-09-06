local _M = {}

-- `tls_cluster.lua` DA BI XOA (2026-09-06). No chay `safe_incr("cluster:tls:"
-- .. ctx.ja3, 600)` tren MOI request co JA3 — tuc moi request hom nay, vi
-- `ctx.ja3` khac nil ke ca khi partial.
--
-- DO TREN 5 MAY: phan bo `cluster:tls:*` LECH CUC MANH. cloud28-246 co 67
-- khoa, trung binh 19.205, nhung CHI 6 khoa >= 300 — nghia la vai JA3 pho bien
-- giu gan nhu toan bo luot, moi cai hang tram nghin, con duoi la mot cai duoi
-- dai duoi 300. Bon may kia cung hinh dang (5,9% / 7,4% / 2,0% khoa bao hoa).
--
-- VI THE TIN HIEU CHAY NGUOC. `min(count, 300)` roi `norm(v, 300) * 0.1`:
--   JA3 trinh duyet pho bien -> bao hoa -> 1.0 x 0.1 x trong so 25 = +2,5 diem
--   JA3 hiem (client la)     -> dem thap -> gan +0 diem
-- Tuc nguoi dung Chrome that an 2,5 diem con con bot dung TLS stack rieng thi
-- khong. No khong phan biet duoc "nhieu request chung van tay VI DO LA CHROME"
-- voi "...VI DO LA BOTNET", ma Chrome thi pho bien hon botnet rat nhieu.
--
-- Khong DAO chieu thanh "JA3 hiem = dang ngo": ban trinh duyet moi ra, thiet
-- bi la, hay mot bo TLS it gap deu hiem — do la mot nguon FP khac, khong phai
-- mot ban sua.

local ua_cluster      = require "antibot.detection.cluster.ua_cluster"
local ip_cluster      = require "antibot.detection.cluster.ip_cluster"
local uri_cluster     = require "antibot.detection.cluster.uri_cluster"
local swarm           = require "antibot.detection.cluster.swarm_detect"
local cluster_context = require "antibot.detection.cluster.cluster_context"
local score           = require "antibot.detection.cluster.cluster_score"

function _M.run(ctx)
    ua_cluster.run(ctx)
    ip_cluster.run(ctx)
    uri_cluster.run(ctx)
    swarm.run(ctx)
    cluster_context.run(ctx)
    score.run(ctx)
end

return _M
