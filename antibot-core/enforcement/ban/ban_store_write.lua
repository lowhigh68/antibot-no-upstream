local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local ip_scope = require "antibot.core.ip_scope"

function _M.run(ctx)
    local id    = ctx.identity or ctx.fp_light
    local ip    = ctx.ip
    local ttl   = ctx.ban_ttl
    local class = ctx.req_class or "unknown"

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[ban_write] redis unavailable: ", err)
        return
    end

    local ctx_json = ""
    local ok, cjson = pcall(require, "cjson")
    if ok then
        local host = (ctx.req and ctx.req.host) or ngx.var.host or "unknown"
        local ok2, json = pcall(cjson.encode, {
            domain      = host,
            score       = math.floor(ctx.score or 0),
            eff_score   = math.floor(ctx.effective_score or 0),
            action      = ctx.action or "block",
            req_class   = class,
            ts          = ngx.time(),
            identity    = id or "",
            fp_deg      = ctx.fp_degraded or false,
            device_type = ctx.device_type or "unknown",
            ua          = (ctx.ua or ""):sub(1, 180),
            ip          = ctx.ip or "",
            bot_score   = ctx.bot_score or 0,
        })
        if ok2 then ctx_json = json end
    end

    local ctx_ttl = (ttl and ttl > 0) and ttl or 86400

    local ip_risk_val   = ctx.ip_risk or 0.0
    -- HAI cơ chế swarm KHÁC NHAU, phải check cả hai:
    --   ctx.swarm       (cluster/swarm_detect) = uri_cluster>50 OR ip_cluster>30
    --   ctx.swarm_attack (distributed_swarm)    = distinct /24 per domain+ua, =1.0 khi HARD
    -- Attack "nhiều IP × 1 request" (residential-proxy botnet) fire ctx.swarm_attack=1.0
    -- nhưng KHÔNG set ctx.swarm (ip_cluster thấp vì mỗi IP chỉ 1 hit). Chỉ đọc
    -- ctx.swarm → trượt hoàn toàn loại swarm này. >=1.0 = ngưỡng "DISTRIBUTED ATTACK"
    -- đã xác nhận (count>=hard, vd navigation 45 /24) → an toàn FP, không dính emerging/flash-crowd.
    local swarm_active  = ctx.swarm == true or (ctx.swarm_attack or 0) >= 1.0

    -- Lấy viol counter hiện tại (đọc trước khi incr ở dưới) để escalate IP ban.
    -- Repeat offender → ban IP bất kể ip_risk thấp; permanent sau viol≥4.
    local viol_count = id and (tonumber(pool.safe_get("viol:" .. id)) or 0) or 0

    -- swarm case: distributed swarm (nhiều IP × ít request/IP) khiến ip_risk
    -- KHÔNG BAO GIỜ leo tới 0.5 (EMA cần ~4 hit/IP; swarm né đúng điều đó) nên
    -- gate cũ `ip_risk>=0.5 and swarm` khóa chết nhánh ip_ban_ttl=180 bên dưới.
    -- swarm_active + score-block đã là bằng chứng đủ → ban ngay hit đầu.
    -- Guard richness==0: request MANG cookie session (user thật lỡ dính flash-
    -- crowd trip swarm) KHÔNG bị ban:<ip> — vẫn score-block từng request nhưng
    -- tự thông khi đám đông tan, tránh khóa cứng 180s. Bot swarm richness=0.
    local swarm_ban = swarm_active and (ctx.session_richness or 0) == 0

    local should_ban_ip = ip and (
        ip_risk_val >= 0.7
        or swarm_ban
        or viol_count >= 3   -- repeat offender → ban IP kể cả risk thấp
    )

    -- Tier-2 shared-IP immunity: NEVER ban:<ip> on a proven high-user shared IP
    -- (mobile CGNAT / mobile farm / office WAN with real cookied users). One bad
    -- device must not nuke thousands of real users behind the same IP — it is
    -- still banned PER-IDENTITY (ban:<id>) below. Only ctx.ip_shared_verified
    -- (Tier 2, requires real-user evidence) grants this; a UA-rotation bot that
    -- merely looks "shared" (Tier 1) is NOT immune and stays IP-bannable.
    if ctx.ip_shared_verified then
        should_ban_ip = false
    end

    -- KHONG BAO GIO `ban:<ip>` cho dia chi cua mot REVERSE PROXY cong cong.
    --
    -- Cung mot ly le voi Tier-2 ngay tren, nhung dai nay CON DONG NGUOI THAT
    -- HON CGNAT: Cloudflare dinh tuyen theo dia ly nen mot edge phuc vu phan
    -- lon khach cua mot vung. `ban:104.23.211.47` 30 ngay co the la toan bo
    -- khach mot vung mat truy cap vao domain do trong mot thang.
    --
    -- VA NO VO HIEU VOI KE TAN CONG: CF chon edge cho TUNG ket noi, nen bot bi
    -- ban mot edge chi can ket noi lai la sang edge khac. Ta tra gia bang khach
    -- that de doi mot rao chan ma bot di vong trong mot giay.
    --
    -- DO 19-09-2026 tren cloud171-96 — day la lo hong DANG DIEN RA, khong phai
    -- gia thuyet: **72 khoa `ban:<ip>` la IP edge Cloudflare**, TTL ~2.591.000s
    -- (29,99 ngay) — tuc vua duoc ghi vai chuc giay truoc, dang duoc tao lien
    -- tuc. Trong so do co `ban:172.68.26.251` va `ban:162.159.104.57` tren
    -- `in3mien.com`, domain do duoc 391 luot cookie that trong 3h40.
    --
    -- KHONG mien `ban:<id>`: identity van bi chan per-device. Chinh vi `ctx.ip`
    -- vo nghia o day ma ban theo identity moi la thu duy nhat con dung nghia.
    --
    -- `== true` de fail-closed, giong cong cookie_registry ben duoi: day la trao
    -- MIEN TRU nen khong co bang chung duong tinh thi khong mien.
    if ctx.behind_proxy == true then
        should_ban_ip = false
    end

    -- Mien tao `ban:<ip>` cho phien CO BANG CHUNG do chinh host nay cap.
    --
    -- Su co 2026-09-12 (bestcargo.vn): mot quan tri vien dang dang nhap luu
    -- bai bang trinh dung trang — 8 POST `admin-ajax.php`, moi cai 113 KB,
    -- trong 7 giay — bi ban IP. Anh ta KHONG co duong nao thoat: `ip_ban_check`
    -- chay o buoc 2 cua STEPS_COMMON, TRUOC ca cookie fast-path, nen engine
    -- khong bao gio chay va `auth_session_cap` khong bao gio duoc ap. Ban
    -- theo identity (`ban_store.lua`) da co loi thoat nay tu truoc; ban theo
    -- IP thi khong co gi ca. Day la vet bat doi xung do.
    --
    -- VI SAO DOI CA HAI DIEU KIEN, khong chi richness: gui 500 byte cookie rac
    -- la dat `richness 0.80` (do 2026-09-12: mot trinh do `/cgi-bin/php5` dat
    -- nguong do). Mien ban IP chi bang richness se lam mot bot xoay UA tro
    -- thanh KHONG THE ban theo IP — dung `UA-rotation game` ma Tier-2 o tren
    -- sinh ra de chan. Doi them mot cookie do CHINH host cap buoc ke tan cong
    -- phai lay cookie that tu site truoc, va ten do phai nam trong so.
    --
    -- CUC `== true`, KHONG phai `~= false`. Day la trao DAC QUYEN nen phai
    -- fail-closed: khong co bang chung duong tinh thi khong mien. Nguoc voi
    -- cong o `engine.lua` — cho do LAY DI su bao ve nen viet `~= false` de
    -- fail-open. Cung mot truong, hai cuc, moi ben chon sao cho huong hong la
    -- huong an toan. Doi cuc o bat ky ben nao cung tao mot lo hong.
    local ckr = cfg.cookie_registry
    if ckr.ip_ban_exempt
       and ctx.session_cookie_known == true
       and (ctx.session_richness_own or 0) >= (ckr.richness_min or 0.5) then
        should_ban_ip = false
    end

    -- KHONG BAO GIO tu KET AN CHINH MAY NAY — ca theo IP lan theo IDENTITY.
    --
    -- Do 14-09 tren cloud186-126, sau khi ban va IP da chay: `123.30.186.126`
    -- KHONG con dong `banned_ip` nao, nhung van co 8.356 luot `banned_id` —
    -- ban va truoc chi bit mot nua duong. Mot identity duy nhat:
    --
    --     id=aba75ff7ba9f053019a0230d4947e262   ttl=2575401 (29,8 ngay con lai)
    --       ua=WordPress/7.0.4;_https://indochinapost.vn
    --       ua=WordPress/7.1;_https://bestcargo.vn
    --       ua=WordPress/6.2.11;_https://aloinan.com
    --       ua=WordPress/6.9.7;_https://dichthuatchaua.net
    --       ua=WordPress/6.8.8;_https://aloduasap.com
    --
    -- NAM phien ban WordPress, NAM domain, MOT identity. `normalize_ua` rut
    -- `WordPress/7.0.4;_https://...` xuong token truoc dau `/` dau tien, tuc
    -- `"WordPress"`; cong voi IP cua chinh may thi cron cua MOI site tren may
    -- deu bam ra cung mot identity. Mot site cham nguong => toan bo wp-cron
    -- cua ca may an an 30 ngay: bai hen gio, kiem tra cap nhat plugin, tac vu
    -- WooCommerce, backup — chet het tren it nhat 13 domain.
    --
    -- Do 13-09 tren cloud186-126: trong 3.604 luot block co `richness>=0.5`,
    -- 2.010 luot den tu 123.30.186.126 — IP cong cong cua chinh may do. Do la
    -- may chu tu goi minh: wp-cron, kiem tra cap nhat plugin, HTTP giua cac
    -- site cung may. Tat ca ghi `id=-` vi `ip_ban_check` thoat truoc khi
    -- identity duoc tinh. Hau qua: moi wp-cron tren may an 403, im lang, khong
    -- ai bao — chi lo ra khi dem theo IP.
    --
    -- WHITELIST KHONG CUU DUOC. `init.lua` xep `ip_ban_check` TRUOC
    -- `access_layer`, nen dua IP vao whitelist cung khong bao gio kip chay.
    -- Dung vet bat doi xung da lam `auth_session_cap` khong cuu duoc admin
    -- bestcargo.vn hom 12-09. Nen phai chan ngay o cho TAO ban.
    --
    -- `remote_addr == server_addr` chi dung khi client la chinh may nay — qua
    -- ten mien cong cong hoac qua loopback. Client ngoai luon co remote_addr
    -- khac server_addr, nen phep thu nay khong the bi gia mao tu ben ngoai va
    -- khong can khai bao IP cho tung may.
    --
    -- VI SAO MIEN THEO IDENTITY LA AN TOAN, khong phai mot lo hong moi:
    -- `identity = md5(VERSION | ip | ua_norm)` — IP NAM TRONG HAM BAM. Nen
    -- identity `md5(V|123.30.186.126|WordPress)` chi co the sinh ra tu mot
    -- request co `remote_addr` DUNG BANG dia chi do. Khong client ngoai nao tao
    -- duoc no. Pham vi mien khit dung mot nhom: luu luong may tu goi minh.
    --
    -- Bo ca `viol:<id>`, khong chi `ban:<id>`: `viol` la thu leo thang TTL. Giu
    -- lai thi ban an khong duoc ghi nhung tien an van tang, va lan sau co ly do
    -- khac de ban thi no nhay thang len bac 30 ngay. Bo an ma giu tien an la
    -- nua voi.
    --
    -- KHONG phai whitelist: khong short-circuit, pipeline van chay du, va engine
    -- van chan TUNG REQUEST tu-goi neu no dang chan. Chi BAN AN DAI HAN la
    -- khong duoc ghi. Mot cron hong van bi throttle, no chi khong con keo theo
    -- cron cua moi site khac xuong cung.
    --
    -- Danh doi: neu chinh may bi chiem va dung de tan cong cac site cua no, ta
    -- mat lop cam-theo-identity cho luu luong do. Chap nhan — ke da chay duoc ma
    -- tren may khong can vuot WAF, chan theo tung request van con, con cai gia
    -- cua hien trang la toan bo wp-cron chet 30 ngay.
    --
    -- Gioi han da biet: tien trinh bind mot dia chi cuc bo KHAC dia chi dang
    -- lang nghe thi khong khop. Chap nhan — no van chan het hai duong pho bien.
    -- Qua `ip_scope.is_self()`, KHONG so `ctx.ip` voi `server_addr` truc tiep
    -- nhu ban dau. Hai ly do, phat hien 15-09:
    --   1. `ctx.ip` CO THE do `real_ip_header` ghi de tu mot header.
    --      `ctx/init.lua` chi tu choi dia chi NOI BO do header khai, nen dia chi
    --      CONG CONG cua chinh may van lot. Ma day la cong cap MIEN TRU — so voi
    --      gia tri client dat duoc la de ke tan cong tu cap dac quyen bang mot
    --      dong header. `is_self()` so voi `tcp_peer()`, thu khong gia mao duoc.
    --   2. `detection/ip_tour.lua` nay cung can dung phep kiem ay. Hai ban sao
    --      cua mot phep kiem cap dac quyen se lech nhau — cung ly do da gom
    --      `is_private` ve `ip_scope`.
    local self_request = ip_scope.is_self()
    if self_request then
        should_ban_ip = false
    end

    -- Bậc cuối của thang leo — lấy từ cfg.ttl.ban_steps để KHÔNG lệch với thang
    -- identity ở l7/ban/ban_store.lua. 2026-08-06: đổi từ 0 (vĩnh viễn) sang
    -- hữu hạn (30 ngày) — xem chú thích tại config.lua ban_steps.
    local steps       = cfg.ttl.ban_steps
    local persist_ttl = steps[#steps]

    local ip_ban_ttl
    if viol_count >= 4 then
        ip_ban_ttl = persist_ttl -- bậc cuối: confirmed repeat bot
    elseif viol_count >= 3 then
        ip_ban_ttl = 86400       -- 24h: cảnh báo nặng
    elseif ip_risk_val >= 0.95 then
        ip_ban_ttl = 1800        -- 30 phút: bot tấn công tích cực
    elseif ip_risk_val >= 0.85 then
        ip_ban_ttl = 900         -- 15 phút: risk cao
    elseif ip_risk_val >= 0.7 then
        ip_ban_ttl = 300         -- 5 phút: ngưỡng tối thiểu
    else
        ip_ban_ttl = 180         -- 3 phút: swarm case
    end

    red:init_pipeline()

    local now_ts = tostring(ngx.time())

    -- `not self_request`: xem khoi chu thich o tren. Cong nay doi xung voi cong
    -- cua `should_ban_ip` — hai nhanh, mot quy tac: may khong tu ket an chinh no.
    if id and not self_request then
        if ttl and ttl > 0 then
            red:setex("ban:" .. id, ttl, "1")
        else
            red:set("ban:" .. id, "1")
        end
        -- Fresh ban → ACTIVE ngay trong 5 phút đầu, không phải chờ hit kế tiếp.
        red:setex("ban:hit:" .. id, 300, now_ts)
        -- Mỗi lần ban = +1 violation để ban_escalation lũy tiến TTL lần sau.
        -- Trước đây viol chỉ tăng khi rate-limit/challenge-fail → score-based
        -- block (GPTBot/DotBot...) luôn dừng ở step 1 = 5m dù quay lại nhiều lần.
        red:incr("viol:" .. id)
        red:expire("viol:" .. id, cfg.ttl.violation)
    end

    if should_ban_ip then
        if ip_ban_ttl > 0 then
            red:setex("ban:" .. ip, ip_ban_ttl, "1")
        else
            red:set("ban:" .. ip, "1")  -- permanent
        end
        red:setex("ban:hit:" .. ip, 300, now_ts)
    end

    if ctx_json ~= "" then
        -- Cung dieu kien voi nhanh ghi an o tren. Truoc day `id` co mat la chac
        -- chan da ghi an, nen mot `if id` la du; nay khong con dung nua, va ho
        -- so bang chung khong co ban an di kem chi la rac. Bat bien can giu:
        -- `ban_ctx:<x>` ton tai <=> co mot ban an cho <x>.
        if id and not self_request then
            red:setex("ban_ctx:" .. id, ctx_ttl, ctx_json)
        end
        if should_ban_ip then
            -- Guard TTL: `SETEX key 0 val` là LỖI trong Redis, và lỗi trong
            -- pipeline bị nuốt im lặng ⇒ đúng những lệnh cấm nặng nhất lại mất
            -- hồ sơ bằng chứng. Hồ sơ phải sống ÍT NHẤT bằng bản án, nếu không
            -- mọi lần rà soát về sau đều mù (đo 2026-08-06: 8.261 lệnh cấm vĩnh
            -- viễn, chỉ 33 còn ban_ctx).
            local ip_ctx_ttl = (ip_ban_ttl > 0) and ip_ban_ttl or ctx_ttl
            red:setex("ban_ctx:" .. ip, ip_ctx_ttl, ctx_json)
        end
    end

    red:commit_pipeline()
    pool.put(red)

    ngx.log(ngx.WARN,
        "[ban_write]",
        " class=", class,
        " ip=", ip or "?",
        " ip_risk=", string.format("%.3f", ip_risk_val),
        " ban_ip=", tostring(should_ban_ip ~= false and should_ban_ip ~= nil),
        " ip_ttl=", should_ban_ip and ip_ban_ttl or "-",
        " id=", id and id:sub(1, 8) .. "..." or "nil",
        " ttl=", ttl == 0 and "permanent" or tostring(ttl) .. "s",
        " score=", ctx.score or 0,
        " eff=", ctx.effective_score or 0)
end

return _M
