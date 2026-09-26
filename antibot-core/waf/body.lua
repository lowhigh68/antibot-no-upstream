local core = require "antibot.waf.body_core"

local _M = {}

-- BO DO BODY — giai doan 1: CHI QUAN SAT, khong luat nao ban.
--
-- Vi sao chua co luat. Ca phien lam viec da bac bo sau gia thuyet lien tiep bang
-- so lieu that (mu-plugins "backdoor" hoa ra la ban va cua agency SEO;
-- "status=200 nghia la da bi chiem" sai hai lan). Viet luat body ma khong biet
-- body tren dan may nay chua gi la lap lai dung sai lam do — chi khac la hau qua
-- roi vao 43 domain that.
--
-- File nay la LOP TRUY CAP `ngx`: cong loc method/Content-Type, lay than, va
-- dieu phoi doc file tam. Toan bo logic soi nam o `body_core` — Lua thuan,
-- khong `ngx` — vi no phai chay duoc CA trong worker thread.
--
-- ── Doc than: hai duong, va duong thu hai la cai vua mo ─────────────
--   1. Than trong bo nho -> `core.scan` thang.
--   2. Than da ra file tam -> `ngx.run_worker_thread`.
--
-- Duong 2 dong mot vung mu ma nang buffer KHONG BAO GIO dong duoc: buffer 64K
-- thi ke tan cong don 65K, 256K thi don 257K. Doc file o access phase la I/O
-- CHAN tren duong di cua moi request nen truoc day tang nay bo qua han; doc
-- trong thread pool thi khong chan event loop.
--
-- CAN CAU HINH nginx main context:
--     thread_pool antibot_waf_io threads=2 max_queue=128;
-- Pool nho de chan so lan doc 50 MiB dong thoi. Hang day tran thi bao
-- `scan=spill_thread` — KHONG BAO GIO lui ve `io.open` chan tren event loop.
--
-- DA BAT tu 05-09 (cloud168-101 co `--with-threads`). Dieu kien build duoc
-- kiem o buoc `[2b]` cua deploy.sh — TRUOC rsync, de mot may build thieu bi tu
-- choi som chu khong hong nua chung.
--
-- Tat lai chi can them dau `#` trong nginx.conf: code tu bao `scan=nothread`,
-- khong hong gi. Han che HIEN RA trong so lieu chu khong am tham.
local THREAD_POOL   = "antibot_waf_io"
local WORKER_MODULE = "antibot.waf.body_worker"

local INSPECT_METHODS = {
    POST = true, PUT = true, PATCH = true, DELETE = true,
}

-- Mot lan moi worker. Ly do hong o day la LOI CAU HINH, khong phai loi cua
-- request — ghi moi request thi 43 domain do day error.log ma khong them mot
-- bit thong tin nao. Duong bao duoc doc that la cot `scan=` chay lien tuc.
local yelled = {}
local function log_once(reason, detail)
    if yelled[reason] then return end
    yelled[reason] = true
    if ngx and ngx.log then
        ngx.log(ngx.ERR, "[waf] khong soi duoc than: ", reason,
                detail and (" (" .. tostring(detail) .. ")") or "")
    end
end

-- KHONG SOI DUOC khac han DA SOI VA SACH.
--
-- `php` va ba vung luat de NIL chu khong `false`/`0`: neu mot phep thong ke
-- ve sau coi `php=0` la am tinh thi moi ty le deu lech va khong ai biet, vi log
-- trong nhu binh thuong.
--
-- `fn_trunc` mang chinh LY DO. Truoc day cho nay ghi cung chuoi `"spill"` cho ca
-- than spill LAN than rong — nen mot POST multipart rong bi dem la vung mu.
local function unscanned(family, spilled, reason, len)
    return {
        family = family,
        spill  = spilled,
        source = spilled and "file" or "none",
        scan   = reason,
        len    = len or (spilled and -1 or 0),
        php      = nil,
        nargs    = nil,
        -- V7: ba vung deu `nil` — than CHUA duoc soi. Ly do nam o `scan` va
        -- `fn_trunc`, khong o day.
        nonfile_rules  = nil,
        file_rules     = nil,
        filename_rules = nil,
        fn_trunc = (family == "multipart") and reason or nil,
        -- V6. `nil`: than CHUA soi thi khong co ly do "khong chuan tac" nao de noi
        -- — ly do chua soi da nam o `scan`/`fn_trunc`.
        proof = nil,
    }
end

local function default_runner(pool, module_name, fn, ...)
    if not ngx.run_worker_thread then return false, "nothread" end
    return ngx.run_worker_thread(pool, module_name, fn, ...)
end

-- ── B3: luot soi dang bay trong pool — GIAI DOAN DO (roadmap muc 2) ─────────
--
-- `thread_pool` va hang doi cua no la cua TUNG worker (nginx dung pool rieng
-- trong moi worker), nen dem cung o day: bang Lua cap module, song va chet cung
-- worker. KHONG ghi shared dict — khoa theo host la thu ke gui chon, con bang
-- trong worker thi khong co gi ro ri qua reload, khong can TTL.
--
-- Khoa la `server_name`: ten DAU cua server block da khop, nen moi alias cua mot
-- site chung mot so dem, va Host ngau nhien roi vao server mac dinh thay vi de
-- ra mot khoa moi moi lan.
--
-- CHUA CO NGUONG. Nguoi dung 27-09: phan chua xac dinh chinh xac thi ghi lai roi
-- lay log xu ly. Nen o day chi DO — cot `qh`/`qw`/`qhk`/`qwk`/`qms` cua dong
-- `[waf-body]`. Ngan sach (va 503 kem Retry-After khi vuot, nguoi dung chon
-- 27-09) dat SAU, tu chinh so lieu do.
local inflight = { n = 0, kb = 0, host = {} }

local function acquire(key, kb)
    local h = inflight.host[key]
    if not h then h = { n = 0, kb = 0 }; inflight.host[key] = h end
    h.n, h.kb = h.n + 1, h.kb + kb
    inflight.n, inflight.kb = inflight.n + 1, inflight.kb + kb
    return { qh = h.n, qw = inflight.n, qhk = h.kb, qwk = inflight.kb }
end

local function release(key, kb)
    local h = inflight.host[key]
    if h then
        h.n, h.kb = h.n - 1, h.kb - kb
        if h.n <= 0 then inflight.host[key] = nil end
    end
    inflight.n, inflight.kb = inflight.n - 1, inflight.kb - kb
end

local function stamp(b, q)
    for k, v in pairs(q) do b[k] = v end
    return b
end

local function clock_ms(rt)
    if not rt.now then return nil end
    if rt.update_time then rt.update_time() end
    return rt.now() * 1000
end

local function probe(ctx, runner, rt)
    rt = rt or ngx

    -- Cong loc phai RE, no chay cho moi request. `get_method()` khong I/O.
    if not INSPECT_METHODS[rt.req.get_method()] then return end

    local ct = rt.var.http_content_type
    if not ct or ct == "" then return end
    local family = core.ct_family(ct)

    -- `read_body()` nghe thi dat, thuc te khong them gi: `proxy_request_
    -- buffering` khong duoc dat trong repo nay => mac dinh `on` => nginx VON DA
    -- doc va dem tron than truoc khi gui len Apache. (`proxy_buffering off`
    -- trong da_to_openresty.sh la dem PHAN HOI — directive khac.)
    rt.req.read_body()

    local data = rt.req.get_body_data()
    if data ~= nil then
        ctx.waf_body = core.scan(data, ct)
        return
    end

    -- `get_body_data()` tra nil o BA tinh huong. Gop chung lam mot se thoi phong
    -- so spill bang so POST rong, tuc quyet dinh `client_body_buffer_size` tren
    -- mot phep dem sai. Phan biet bang `get_body_file()`.
    local path = rt.req.get_body_file()
    if not path then
        ctx.waf_body = unscanned(family, false, "empty", 0)
        return
    end

    -- B3: dem TRUOC khi dua vao pool, tra NGAY khi co ket qua. `pcall` de mot loi
    -- nem ra tu bo chay van tra luot — neu khong, so dem lech toi het doi worker.
    -- Loi nem ra tinh nhu goi thread that bai (`spill_thread`).
    local key = rt.var.server_name or "-"
    local kb = math.floor((tonumber(rt.var.http_content_length) or 0) / 1024)
    local q = acquire(key, kb)
    local t0 = clock_ms(rt)
    local called, ok, payload = pcall(runner, THREAD_POOL, WORKER_MODULE,
                                      "scan_file", path, ct)
    local t1 = clock_ms(rt)
    release(key, kb)
    if t0 and t1 then q.qms = t1 - t0 end
    if not called then ok, payload = false, ok end

    if not ok then
        local reason = tostring(payload or "spill_thread")
        if reason ~= "nothread" then reason = "spill_thread" end
        log_once(reason, payload)
        ctx.waf_body = stamp(unscanned(family, true, reason), q)
        return
    end

    local result, err, known_len = core.unpack(payload)
    if not result then
        log_once(err or "spill_worker", known_len)
        ctx.waf_body = stamp(unscanned(family, true, err or "spill_worker", known_len), q)
        return
    end

    result.spill, result.source = true, "file"
    ctx.waf_body = stamp(result, q)
end

function _M.probe(ctx)
    return probe(ctx, default_runner, ngx)
end

-- Chi de test: cho phep thay bo chay thread bang mot ham dong bo, va thay
-- `ngx.var`/`ngx.req` bang bang Lua thuong.
function _M._probe_with_runner(ctx, runner, rt)
    return probe(ctx, runner, rt or ngx)
end

_M.THREAD_POOL = THREAD_POOL

return _M
