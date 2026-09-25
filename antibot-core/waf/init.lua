local _M = {}

local wp_paths  = require "antibot.waf.wordpress.paths"
local exposed   = require "antibot.waf.exposed"
local args      = require "antibot.waf.args"
local body      = require "antibot.waf.body"
local upload    = require "antibot.waf.upload"
local registry  = require "antibot.waf.registry"
local policy    = require "antibot.waf.policy"
local config    = require "antibot.waf.config"
local telemetry = require "antibot.waf.telemetry"
local pool      = require "antibot.core.redis_pool"

local compiled_config = config.compile()
local host_config_cache = {}

local registry_ok, registry_errors = registry.validate_sources({
    exposed   = exposed.RULES,
    args      = args.RULES,
    upload    = upload.UP_RANK,
    wordpress = wp_paths.RULES,
})

-- Call from init_worker_by_lua* before serving traffic. The table is copied;
-- later mutation by its caller cannot change live policy accidentally.
function _M.configure(runtime_config)
    if runtime_config ~= nil and type(runtime_config) ~= "table" then
        return nil, { "config must be a table" }
    end
    local candidate = config.compile(runtime_config)
    local ok, errors = config.validate(candidate)

    local function check_ids(scope, path)
        if type(scope) ~= "table" then return end
        local rules = type(scope.rules) == "table" and scope.rules or {}
        local families = type(scope.families) == "table" and scope.families or {}
        local correlations = type(scope.correlations) == "table" and
                             scope.correlations or {}
        local exceptions = type(scope.exceptions) == "table" and
                           scope.exceptions or {}
        for id in pairs(rules) do
            local meta = registry.get(id)
            if not meta then
                errors[#errors + 1] = path .. ".rules: unknown rule " .. tostring(id)
            elseif meta.family == "correlation" then
                errors[#errors + 1] = path .. ".rules: correlation belongs in correlations: " .. id
            end
        end
        for family in pairs(families) do
            if not registry.has_family(family) then
                errors[#errors + 1] = path .. ".families: unknown family " ..
                                      tostring(family)
            end
        end
        for id in pairs(correlations) do
            local meta = registry.get(id)
            if not meta then
                errors[#errors + 1] = path .. ".correlations: unknown rule " .. tostring(id)
            elseif meta.family ~= "correlation" then
                errors[#errors + 1] = path .. ".correlations: non-correlation rule " .. id
            end
        end
        for i = 1, #exceptions do
            local ex = exceptions[i]
            local id = type(ex) == "table" and ex.rule or nil
            if id and id ~= "*" and not registry.get(id) then
                errors[#errors + 1] = path .. ".exceptions: unknown rule " .. tostring(id)
            end
        end
    end

    check_ids(candidate, "config")
    local domains = type(candidate.domains) == "table" and candidate.domains or {}
    for host, domain in pairs(domains) do
        check_ids(domain, "config.domains." .. tostring(host))
    end
    if not ok or #errors > 0 then return nil, errors end

    compiled_config = candidate
    host_config_cache = {}
    return true
end

local function config_for(host)
    host = config.host(host)
    local domains = type(compiled_config.domains) == "table" and
                    compiled_config.domains or {}
    -- Never create one cache entry per attacker-controlled Host header. Only
    -- configured domains receive dedicated entries; all other hosts share the
    -- immutable default policy while exception matching still uses request.host.
    local cache_key = type(domains[host]) == "table" and host or "\0default"
    local resolved = host_config_cache[cache_key]
    if resolved then return resolved end
    resolved = config.resolve(compiled_config,
                              cache_key == "\0default" and "-" or host)
    if cache_key == "\0default" then resolved.host = nil end
    host_config_cache[cache_key] = resolved
    return resolved
end

local function request_of(rt)
    local method = "GET"
    if rt.req and rt.req.get_method then method = rt.req.get_method() end
    return {
        host   = rt.var.host or "-",
        uri    = rt.var.uri or "/",
        method = method,
    }
end

local function max_field(ctx, field, value)
    value = tonumber(value)
    if value and (tonumber(ctx[field]) or 0) < value then ctx[field] = value end
end

local function record_arg(state, rule_id, target, matched, factor)
    if not rule_id then return end
    local rule = args.RULES[rule_id]
    if not rule then return end
    local hit = policy.emit(state, rule_id,
                            { target = target, matched = matched, factor = factor })

    -- Compatibility bridge for the existing antibot scoring layer. V2 policy
    -- remains independent in ctx.waf_score/ctx.waf_decision. An exception or
    -- observe override must suppress this bridge too; otherwise it would still
    -- affect the old scoring path and the policy would only look configurable.
    if not hit or hit.excepted or hit.action == "observe" then return end
    local field = target == "BODY" and "waf_body_arg" or "waf_arg"
    -- `factor` phai di qua ca cau nay. Cau truyen `rule.score` o thang detector
    -- `[0,1]` (khong phai thang registry) de `compute.lua` nhan y nguyen, nhung
    -- neu bo `factor` thi mot request da duoc policy ha xuong 5% van nap DU
    -- diem vao duong cham diem cu. Hien tai `waf_arg`/`waf_body_arg` deu o
    -- trong so 0 nen khong ai thay; dung luc nao bat trong so len thi factor
    -- bien mat trong im lang — dung ho loi "hai duong, mot duong khong duoc
    -- cap nhat" da mat bon thang o `wp_paths.mark()`.
    local bridged = rule.score
    if factor ~= nil then
        local n = tonumber(factor) or 1
        if n < 0 then n = 0 elseif n > 1 then n = 1 end
        bridged = bridged * n
    end
    max_field(state.ctx, field, bridged)
end

local function find_uri_rule(uri, host, resolved)
    local id = exposed.check(uri)
    if id then return id, exposed.RULES end
    if (resolved.profiles or {}).wordpress ~= false then
        id = wp_paths.check(uri, host)
        if id then return id, wp_paths.RULES end
    end
    return nil, nil
end

local function complete(ctx, state, decision, rt)
    telemetry.record(ctx, state, decision, rt)
    telemetry.finish(ctx, rt)
    return decision
end

local function terminate(ctx, state, decision, rt)
    ctx.action        = "block"
    ctx.action_reason = decision.reason or "waf_v2"
    ctx.ip            = ctx.ip or rt.var.remote_addr or ""
    ctx.req           = ctx.req or {
        uri  = state.request.uri,
        host = state.request.host,
    }

    complete(ctx, state, decision, rt)
    if rt.log then
        rt.log(rt.ERR, "[waf-v2] block rule=", ctx.action_reason,
               " ip=", ctx.ip, " host=", state.request.host,
               " uri=", state.request.uri:sub(1, 160),
               " score=", string.format("%.2f", decision.score or 0))
    end
    rt.exit(403)
    return true
end

-- `factor` cho luat THAM SO tren THAN request.
--
-- VI SAO CAN. `arg_traversal` la tin hieu duy nhat co dan so lon ma khong tach
-- duoc bang noi dung: moi nhom duoi day THAT SU chua `../`, nen khong regex nao
-- phan biet duoc. Do 25-09 tren sau may, nhom theo `matched=` va doi chieu voi
-- thuoc do FP (`wpauth=1` hoac `richness>=0.5` o dong `[waf]` cung `rid`):
--
--   matched                luot    co cookie/auth      doc
--   <multipart>               9     9/9 = 100%         upload cua NGUOI THAT
--   <urlencoded>          4.041     6/4.041 = 0,15%    botnet
--   <page_id,pagename>    1.806     0                  cung bo cong cu
--   <json>                   20     0                  /api/templates/preview
--
-- Nhom `<multipart>` la FP TUYET DOI, 9/9. Doc tung dong: `ct=multipart`
-- `spill=1` `cl=1.125.283 / 1.177.235 / 1.612.016 / 2.000.644`, URI la
-- `/index.php/quatt_admin/catalog_product_gallery/upload/key/...` — Magento
-- admin dang upload anh san pham. `../` nam trong NOI DUNG FILE (ma chinh chu
-- thich `body_core.lua` da du bao: "part 1 filename=\"../../photo.jpg\" -> khop
-- arg_traversal"), khong phai trong tham so.
--
-- VI SAO KHONG DOC `richness`. `waf.run_pre` chay o `init.lua:200`, con
-- `session_richness` nam trong `STEPS_COMMON` o dong 223 — nen luc tinh factor
-- thi `ctx.session_richness` CHUA TON TAI. Doc no o day se luon ra nil va factor
-- thanh hang so, dung ho loi "co doc truoc khi ghi" da mac bon lan trong repo
-- nay. Ba truong duoi day CO san vi `body.probe()` vua chay xong.
--
-- BA TRUC, va moi truc la mot bat bien chu khong phai mot nguong hieu chinh:
--
--   1. `multipart` — dinh dang danh cho FILE, va la truc DUY NHAT duoc dung.
--      `../` trong than multipart nam trong noi dung file voi xac suat ap dao;
--      do 05-09 da ghi dieu tuong tu cho `arg_null_byte` (67/67 luot nam trong
--      noi dung file). Ke gui khong doi duoc dinh dang ma khong doi ban chat
--      request: mot than `multipart/form-data` phai co boundary va part hop le
--      moi den duoc day, va khi do `../` trong part content dung la thu luat
--      nay dang noi sai ve.
--   2. (DA GO) `spill` — xem dinh chinh (1) ben duoi.
--   3. (KHONG hien thuc hoa) `len` rat lon — nhom botnet do duoc 77..242 byte,
--      buoc 15; nhom FP 1,1-2,0 MB. Dan so 9 ca la qua it de dat nguong.
--
-- DINH CHINH 25-09, hai cho, ca hai do review phat hien:
--
-- (1) `spill` DA BI GO khoi danh sach nay. `spill` nghia la "than request da ra
--     file tam vi vuot buffer" — mot dieu kien KE GUI DIEU KHIEN DUOC. Chi can
--     nhoi padding cho mot than urlencoded hoac JSON vuot `client_body_buffer_
--     size` la moi payload traversal trong do tu 35 diem con 1,75. Do la mot
--     duong ha diem MO CHO NGUOI NGOAI, va no te hon han cai FP no chua: truc 1
--     trong lap luan ban dau ("tan cong tham so khong can megabyte") dung theo
--     chieu quan sat nhung sai theo chieu dieu khien — ke tan cong khong bi
--     buoc phai giu payload nho. Con lai `multipart`, thu ma dinh dang chu
--     khong phai kich thuoc quyet dinh.
--
--     Chin ca FP do duoc deu la `multipart` VA `spill`, nen go `spill` khong
--     mat ca nao: `family == "multipart"` van phu du 9/9.
--
-- (2) Ly do "0.05 chu khong 0 de nhan khong mat" tung ghi o day la SAI. Doc
--     `policy.lua:162`: `add_labels` duoc goi khi `not excepted and action ~=
--     "observe"` — no khong doc `score` mot lan nao. Factor 0 lam diem bang 0
--     nhung nhan VAN vao `state.labels`, nen correlation van thay. Giu 0.05
--     thi bay gio la mot lua chon khac: de telemetry phan biet duoc "luat co
--     no nhung bi ha" voi "luat khong no", va de mot nguong diem tuong lai van
--     nhin thay mot phan nho. Khong con la mot rang buoc ky thuat.
--
-- CHUA HIEU CHINH NGUONG `len`: 2 MB la mot moc lay tu dan so 9 ca, va 9 ca la
-- QUA IT de dat nguong. Truc 3 vi vay KHONG duoc hien thuc hoa. Khi telemetry
-- V2 chay du lau, `waf:v2:rule:arg_traversal` cong voi `waf:v2:scan:*` se cho
-- phan bo that.
local function arg_factor_body(b)
    if not b then return nil end
    if tostring(b.family or "") == "multipart" then return 0.05 end
    return nil
end

local function emit_body_facts(ctx, state)
    local b = ctx.waf_body
    if not b then return end

    if b.scan and b.scan ~= "ok" then
        policy.emit(state, "body_scan_incomplete", {
            target = "BODY",
            matched = tostring(b.scan),
        })
    end

    if b.arg_rule then
        record_arg(state, b.arg_rule, "BODY",
                   "<" .. tostring(b.family or "other") .. ":" ..
                   tostring(b.len or -1) .. ">",
                   arg_factor_body(b))
    end

    if b.php == true then
        local hit = policy.emit(state, "body_php_code", {
            target = "BODY",
            matched = "<php-code>",
        })
        if hit and not hit.excepted and hit.action ~= "observe" then
            ctx.waf_body_php = 1
        end
    end

    if b.up_rule then
        local hit = policy.emit(state, b.up_rule, {
            target = "MULTIPART_FILENAME",
            -- Never copy the attacker-controlled filename into persistent logs.
            matched = b.up_rule,
        })
        if hit and not hit.excepted and hit.action ~= "observe" then
            ctx.waf_upload = 1
            ctx.waf_upload_rule = b.up_rule
        end
    end
end

local function fim_factor(uri, detector_rule, rt)
    if not detector_rule or detector_rule.action == "block" then return nil end
    local root = rt.var.document_root
    if not root or root == "" then return nil end
    return tonumber(pool.safe_get(
        "waf:fimnew:" .. root .. wp_paths.script_path(uri)))
end

local function run_pre(ctx, rt)
    ctx = ctx or {}
    local request = request_of(rt)
    if not request.uri or request.uri == "" then return false end

    local resolved = config_for(request.host)
    telemetry.start(ctx, resolved, rt)
    local state = policy.begin(ctx, request, resolved)

    if not registry_ok then
        ctx.waf_registry_errors = registry_errors
        if rt.log then
            rt.log(rt.ERR, "[waf-v2] registry mismatch: ",
                   table.concat(registry_errors, "; "))
        end
    end

    local uri_rule, detector_rules = find_uri_rule(request.uri, request.host, resolved)
    local detector_rule = uri_rule and detector_rules[uri_rule] or nil
    if uri_rule and detector_rule then
        local uri_hit = policy.emit(state, uri_rule,
                                    { target = "URI", matched = request.uri })

        -- Preserve the existing normalized signal consumed by compute.lua.
        if uri_hit and not uri_hit.excepted and uri_hit.action ~= "observe" and
           detector_rule.action ~= "block" then
            max_field(ctx, "waf_wp_path", detector_rule.score)
        end

        -- Hard URI invariants can terminate before reading an upload body. In
        -- shadow/observe mode the request continues so all evidence is measured.
        local early = policy.decide(state, false)
        if early.action == "block" then return terminate(ctx, state, early, rt) end
    end

    -- Di qua `rt` chu khong goi `body.probe(ctx)` thang: `probe` doc `ngx.var`
    -- va `ngx.req` tu global, nen mot test dua `rt` gia lap van bi no doc global
    -- that — helper `_run_pre_with_runtime` khi do KHONG con tinh xac dinh voi
    -- request co than. `rt.waf_body_probe` la mot diem chen chi test dat; production
    -- khong dat nen nhanh duoi chay y nhu truoc.
    if rt.waf_body_probe then
        rt.waf_body_probe(ctx)
    else
        body.probe(ctx)
    end

    local qs = rt.var.args
    if qs and qs ~= "" then
        record_arg(state, args.check(qs), "ARGS", args.describe(qs))
    end
    emit_body_facts(ctx, state)

    -- FIM is evidence, not a verdict. The confidence value generated by
    -- fim.sh scales the rule score and can participate in a shadow correlation.
    local factor = fim_factor(request.uri, detector_rule, rt)
    if factor and factor > 0 then
        if factor > 1 then factor = 1 end
        local fim_hit = policy.emit(state, "fim_new_executable", {
            target  = "URI",
            matched = "<fim-new>",
            factor  = factor,
        })
        if fim_hit and not fim_hit.excepted and fim_hit.action ~= "observe" then
            ctx.waf_fim_new = factor
            max_field(ctx, "waf_wp_path", factor)
        end
    end

    local decision = policy.decide(state, true)
    if decision.action == "block" then return terminate(ctx, state, decision, rt) end
    complete(ctx, state, decision, rt)
    return false
end

function _M.run_pre(ctx)
    return run_pre(ctx, ngx)
end

-- Exposed only for deterministic integration tests; production callers should
-- use run_pre().
function _M._run_pre_with_runtime(ctx, rt)
    return run_pre(ctx, rt)
end

local function target_exists(rt)
    local root = rt.var.document_root
    local uri  = rt.var.uri
    if not root or root == "" or not uri or uri == "" then return nil end
    local fh = io.open(root .. wp_paths.script_path(uri), "r")
    if not fh then return false end
    fh:close()
    return true
end

function _M.run_log(ctx)
    if not ctx then return end
    telemetry.finish(ctx, ngx) -- harmless fallback if access phase aborted early

    local uri_hit = false
    if ctx.waf_hits then
        for i = 1, #ctx.waf_hits do
            if ctx.waf_hits[i].target == "URI" and
               ctx.waf_hits[i].family ~= "filesystem" then
                uri_hit = true
                break
            end
        end
    end

    local public = ctx.waf_v2
    local wordpress_enabled = not public or public.wordpress_enabled ~= false
    local host = ngx.var.host
    local wp = wordpress_enabled and wp_paths.needs_mark(ngx.var.uri, host) or nil
    if not uri_hit and wp == nil then return end

    local exists = target_exists(ngx)
    if uri_hit then ctx.waf_target_exists = exists end
    if wp ~= nil and exists == true then wp_paths.mark(host, wp) end
end

_M.registry_ok = registry_ok
_M.registry_errors = registry_errors

return _M
