local _M = {}

local function now(rt)
    if rt and rt.now then return rt.now() end
    return os.clock()
end

local function safe_component(value, limit)
    value = tostring(value or "-"):lower()
    value = value:gsub("[^a-z0-9_.:-]", "_")
    return value:sub(1, limit or 96)
end

local function dict_for(config, rt)
    local telemetry = config and config.telemetry or {}
    if telemetry.enabled == false or not rt or not rt.shared then return nil end
    return rt.shared[telemetry.shared_dict or "antibot_cache"]
end

-- Dem SO LAN GHI THAT BAI thay vi nuot im lang.
--
-- Truoc ban nay `incr` boc trong `pcall` roi bo ket qua. Khi `antibot_cache` day
-- — no dung chung voi du lieu van hanh khac — moi phep ghi that bai va bang so
-- lieu DUNG YEN thay vi giam: doc bang do se thay "khong co tan cong nao", giong
-- het truong hop khong co tan cong. Do la ho loi "canh bao khong den ai" da ghi
-- trong memory: kiem DUONG RA, khong chi kiem phat hien.
--
-- Bo dem loi phai ghi bang chinh `dict` co the dang day, nen no cung co the that
-- bai. Chap nhan: mot khoa duy nhat, do dai co dinh, va la khoa DUY NHAT trong
-- module nay duoc ghi bang `safe_set`-kieu (khong tao khoa moi theo du lieu ke
-- gui). Khi ca no cung khong ghi noi thi so `requests` dung yen — va do la dau
-- hieu doc duoc.
local function incr(dict, key, amount, stats)
    if not dict or type(dict.incr) ~= "function" then return false end
    local ok, res = pcall(dict.incr, dict, key, amount or 1, 0)
    if not (ok and res) then
        if stats then stats.errors = (stats.errors or 0) + 1 end
        return false
    end
    return true
end

function _M.start(ctx, config, rt)
    ctx.waf_telemetry = ctx.waf_telemetry or {}
    ctx.waf_telemetry.started = now(rt)
    ctx.waf_telemetry.recorded = false
    ctx.waf_telemetry.finished = false
    ctx.waf_telemetry.options = config and config.telemetry or {}
end

function _M.record(ctx, state, decision, rt)
    local t = ctx.waf_telemetry or {}
    if t.recorded then return end
    t.recorded = true
    ctx.waf_telemetry = t

    local config = state.config or {}
    local opts = config.telemetry or {}
    local prefix = opts.prefix or "waf:v2:"
    local dict = dict_for(config, rt)

    local stats = {}
    incr(dict, prefix .. "requests", 1, stats)
    incr(dict, prefix .. "action:" .. safe_component(decision.action), 1, stats)
    incr(dict, prefix .. "would:" .. safe_component(decision.would_action), 1, stats)
    if decision.reason then
        incr(dict, prefix .. "decision:" .. safe_component(decision.action) .. ":" ..
                   safe_component(decision.reason), 1, stats)
    end
    if decision.shadow and decision.would_reason then
        incr(dict, prefix .. "shadow:" .. safe_component(decision.would_reason), 1, stats)
    end

    for i = 1, #state.hits do
        local hit = state.hits[i]
        incr(dict, prefix .. "rule:" .. safe_component(hit.rule), 1, stats)
        if hit.excepted then
            incr(dict, prefix .. "excepted:" .. safe_component(hit.rule), 1, stats)
        end
    end

    local body = ctx.waf_body
    if body then
        local scan = safe_component(body.scan or "unknown")
        local bytes = tonumber(body.len)
        if not bytes or bytes < 0 then bytes = 0 end
        t.scan_status = scan
        t.body_bytes = bytes
        t.body_source = body.source
        incr(dict, prefix .. "scan:" .. scan, 1, stats)
        incr(dict, prefix .. "body_bytes_sum", bytes, stats)
        if body.spill then incr(dict, prefix .. "body_spill", 1, stats) end
    end

    if opts.per_host then
        local host = safe_component(state.request.host, opts.host_limit or 96)
        incr(dict, prefix .. "host:" .. host .. ":action:" ..
                   safe_component(decision.action), 1, stats)
    end
    -- Ghi bo dem loi SAU cung: neu cac phep ghi tren that bai thi so nay len,
    -- va `snapshot()` bao ra de nguoi van hanh thay bang so lieu dang KHUYET
    -- chu khong phai dang yen tinh.
    if (stats.errors or 0) > 0 then
        incr(dict, prefix .. "write_errors", stats.errors)
    end
end

function _M.finish(ctx, rt)
    local t = ctx and ctx.waf_telemetry
    if not t or t.finished then return end
    t.finished = true
    local elapsed = (now(rt) - (t.started or now(rt))) * 1000
    if elapsed < 0 then elapsed = 0 end
    t.duration_ms = elapsed

    local config = { telemetry = t.options or {} }
    local opts = config.telemetry or {}
    local prefix = opts.prefix or "waf:v2:"
    local dict = dict_for(config, rt)
    -- Milliseconds are accumulated as integers so averages can be calculated
    -- without storing one key per request.
    -- Hai counter nay cung dem loi ghi. Truoc do chung khong truyen `stats` nen
    -- mot `antibot_cache` day lam chung that bai IM LANG trong khi `write_errors`
    -- van bang 0 — tuc bo dem loi noi "khong co loi" trong luc dang co loi.
    local stats = {}
    incr(dict, prefix .. "latency_ms_sum", math.floor(elapsed + 0.5), stats)
    incr(dict, prefix .. "latency_count", 1, stats)
    if (stats.errors or 0) > 0 then
        incr(dict, prefix .. "write_errors", stats.errors)
    end
end

-- ── DUONG RA. Thieu ham nay thi toan bo module tren la write-only ────────────
--
-- `shared_dict:get_keys()` co hai gioi han that, va ca hai deu duoc xu ly o day
-- chu khong bo qua:
--
--   1. No KHOA toan bo dict trong luc quet. Nen `max` co mac dinh huu han, va
--      ham nay CHI duoc goi tu admin API (do nguoi van hanh bam), khong bao gio
--      tu duong request.
--   2. Voi `max = 0` no tra MOI khoa — tren mot dict dung chung voi du lieu van
--      hanh thi do la hang chuc nghin khoa. Nen `max` mac dinh 2048 va ham bao
--      ra `truncated` de nguoi doc biet minh dang xem mot phan.
--
-- Loc theo `prefix` sau khi quet chu khong truoc: shared_dict khong co API quet
-- theo tien to.
-- Doc theo DANH SACH KHOA BIET TRUOC, khong quet dict.
--
-- Ban dau ham nay goi `get_keys(max)` roi loc theo tien to SAU khi quet. Hai lo,
-- va review chi ra ca hai:
--
--   1. `antibot_cache` dung chung voi du lieu van hanh khac. Neu no co hang chuc
--      nghin khoa thi 2.048 khoa dau CO THE khong chua mot counter WAF nao —
--      endpoint tra `summary` toan 0 kem `truncated = true`, va nguoi doc van de
--      hieu la "khong co su kien". Dung ho loi mot phep do tra ve 0 vi khong do
--      duoc, khong phai vi bang 0.
--   2. `get_keys` KHOA toan bo dict trong luc quet, va `?max=0` thi quet het.
--
-- Tap khoa cua module nay HUU HAN va BIET TRUOC: counter co dinh, cong
-- `rule:<id>` / `excepted:<id>` voi id lay tu REGISTRY, cong `action:<a>` /
-- `would:<a>` voi a thuoc mot tap bon gia tri. Nen doc thang tung khoa bang
-- `dict:get()` — khong khoa dict, khong phu thuoc dict lon bao nhieu, va khong
-- bao gio "khong thay" mot counter dang ton tai.
--
-- `host:<host>:action:<a>` la ngoai le duy nhat: khoa do sinh theo DU LIEU
-- (`per_host = true`, mac dinh tat) nen khong liet ke truoc duoc. Chi nhom do
-- can quet, va chi quet khi `per_host` dang bat.
local ACTIONS = { "allow", "block", "signal", "observe" }
local FIXED = {
    "requests", "latency_ms_sum", "latency_count",
    "body_bytes_sum", "body_spill", "write_errors",
}
-- `scan` lay tu `body.lua`: `ok` cong cac ly do khong soi duoc. Liet ke thay vi
-- quet, va mot gia tri moi xuat hien trong `body.lua` ma quen them o day thi chi
-- MAT mot dong trong bang, khong lam sai con so nao khac.
local SCANS = {
    "ok", "empty", "spill_thread", "spill_worker", "nothread", "unknown",
}

function _M.snapshot(config, rt, max)
    local opts = (config and config.telemetry) or {}
    local prefix = opts.prefix or "waf:v2:"
    local dict = dict_for(config, rt)
    if not dict then
        return nil, "shared dict " .. tostring(opts.shared_dict or "antibot_cache") ..
                    " khong co, hoac telemetry.enabled = false"
    end
    if type(dict.get) ~= "function" then
        return nil, "shared dict khong ho tro get"
    end

    local out, n = {}, 0
    local function take(suffix)
        local v = dict:get(prefix .. suffix)
        if v ~= nil then
            n = n + 1
            out[suffix] = v
        end
    end

    for i = 1, #FIXED do take(FIXED[i]) end
    for i = 1, #SCANS do take("scan:" .. SCANS[i]) end
    for i = 1, #ACTIONS do
        take("action:" .. ACTIONS[i])
        take("would:" .. ACTIONS[i])
    end

    -- `rule:` va `excepted:` theo tung id cua registry; `decision:`/`shadow:`
    -- ghep action voi rule nen cung liet ke duoc day du.
    local ok_reg, registry = pcall(require, "antibot.waf.registry")
    local rules = (ok_reg and registry and registry.all) and registry.all() or {}
    for id in pairs(rules) do
        take("rule:" .. id)
        take("excepted:" .. id)
        take("shadow:" .. id)
        for i = 1, #ACTIONS do take("decision:" .. ACTIONS[i] .. ":" .. id) end
    end

    -- Chi nhom per-host moi phai quet, va chi khi no dang bat.
    local scanned, truncated = 0, false
    if opts.per_host and type(dict.get_keys) == "function" then
        max = tonumber(max) or 2048
        if max < 1 then max = 1 elseif max > 4096 then max = 4096 end
        local ok, keys = pcall(dict.get_keys, dict, max)
        if ok and type(keys) == "table" then
            scanned = #keys
            truncated = (#keys >= max)
            local want = prefix .. "host:"
            for i = 1, #keys do
                local key = keys[i]
                if key:sub(1, #want) == want then
                    local v = dict:get(key)
                    if v ~= nil then
                        n = n + 1
                        out[key:sub(#prefix + 1)] = v
                    end
                end
            end
        end
    end

    -- Trung binh do tre tinh o day chu khong luu mot khoa moi request.
    local sum   = tonumber(out.latency_ms_sum)
    local count = tonumber(out.latency_count)
    local avg   = (sum and count and count > 0) and (sum / count) or nil

    return {
        prefix      = prefix,
        counters    = out,
        counted     = n,
        -- `scanned`/`truncated` gio CHI noi ve nhom per-host. Khi `per_host` tat
        -- thi chung la 0/false va do la su that: khong quet gi vi khong can quet.
        per_host    = opts.per_host and true or false,
        scanned     = scanned,
        truncated   = truncated,
        latency_avg_ms = avg,
        -- Ba con so doc kem nhau tra loi duy nhat cau hoi cua giai doan bong:
        -- `action:allow` la so request KHONG bi chan, `would:block` la so se bi
        -- chan neu bat enforce. Ti le giua chung la con so quyet dinh.
        summary = {
            requests      = tonumber(out.requests) or 0,
            action_allow  = tonumber(out["action:allow"]) or 0,
            action_block  = tonumber(out["action:block"]) or 0,
            would_block   = tonumber(out["would:block"]) or 0,
            write_errors  = tonumber(out.write_errors) or 0,
        },
    }
end

return _M
