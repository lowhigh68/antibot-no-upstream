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
    -- CHI query string (`ARGS`) vao `waf_arg`; moi vung cua THAN — `BODY`,
    -- `BODY_FILE`, `MULTIPART_FILENAME` — vao `waf_body_arg`.
    local field = target == "ARGS" and "waf_arg" or "waf_body_arg"
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

-- ── V7: phat bang chung THAN request theo VUNG ──────────────────────────────
--
-- `body_core.scan` bao ba TAP luat: `nonfile_rules`, `file_rules`,
-- `filename_rules`. Ham duoi day phat MOI (vung, luat) thanh mot hit rieng voi
-- target rieng, va KHONG chon giua chung — review 26-09 lan 2: "phat fact theo
-- vung doc lap; policy quyet dinh rieng".
--
-- Thay cho V4–V6 (`arg_origin` + `reroute_body_arg`): mot `arg_rule` duy nhat cong
-- mot nhan vi tri, va moi lan chon luat cho o do la mot duong ha diem ke gui dieu
-- khien duoc — thu tu part, dinh dang, "luat ngoai tep luon thang".
--
-- Luat nao cho vung nao la viec cua `registry.region_rule` (vd `../` trong NOI
-- DUNG tep -> `body_file_traversal`, observe), khong viet o day. Cung mot luat
-- phat o nhieu target thi policy gop bang max, khong cong hai lan.
local BODY_REGIONS = {
    { field = "nonfile_rules",  region = "nonfile",  target = "BODY" },
    { field = "file_rules",     region = "file",     target = "BODY_FILE" },
    { field = "filename_rules", region = "filename", target = "MULTIPART_FILENAME" },
}

local function emit_body_facts(ctx, state)
    local b = ctx.waf_body
    if not b then return end

    -- `scan == "empty"` KHONG duoc phat luat nay.
    --
    -- Do tren nam may sau hai gio (25-09): `body_scan_incomplete` chiem
    -- 1.353/2.236 dong V2 tren 186-126 va 2.160/3.827 tren 28-246 — hon mot nua
    -- toan bo so lieu cua khung. Va khi boc ra theo `matched=` thi 247/247 luot
    -- tren 171-96 la `empty`, khong mot luot `spill_*` nao.
    --
    -- `empty` la nhanh `get_body_file()` tra nil o `body.lua:113`: than request
    -- RONG THAT, `len = 0`. Mot POST `api_callback` khong co than la chuyen binh
    -- thuong (admin-ajax dat tham so o query string) — do la 215/247 luot.
    --
    -- Gop "khong co gi de soi" voi "co ma soi khong noi" vao mot luat thi luat
    -- do khong tra loi duoc cau nao: khong the doc `body_scan_incomplete` de biet
    -- con vung mu bao lon. Dung ho loi "mot cot tra loi ve mot thu khac voi thu
    -- dang duoc hoi" da lam `exists=1` bao sai cho moi luot `arg_traversal`.
    --
    -- Giu `empty` o TELEMETRY (`waf:v2:scan:empty` van dem, `scan=` van ra log)
    -- chu chi bo khoi phat luat. Khong bia ra gia tri, cung khong dem mot thu
    -- binh thuong nhu mot thieu sot.
    if b.scan and b.scan ~= "ok" and b.scan ~= "empty" then
        policy.emit(state, "body_scan_incomplete", {
            target = "BODY",
            matched = tostring(b.scan),
        })
    end

    -- `matched` KHONG BAO GIO chua noi dung than — chi dinh dang va do dai.
    local matched = "<" .. tostring(b.family or "other") .. ":" ..
                    tostring(b.len or -1) .. ">"
    for i = 1, #BODY_REGIONS do
        local r = BODY_REGIONS[i]
        local list = b[r.field]
        for j = 1, (list and #list or 0) do
            local rule_id = registry.region_rule(list[j], r.region)
            if args.RULES[rule_id] then
                -- Luat tham so: qua `record_arg` de cau noi sang duong cham diem cu
                -- (`ctx.waf_body_arg`, lay max) van nhan.
                record_arg(state, rule_id, r.target, matched)
            else
                -- Luat chi co trong registry (vd `body_file_traversal`): phat thang,
                -- KHONG nap gi vao `ctx.waf_body_arg` — do la ca diem cua viec doi
                -- luat: nhom nay khong dong gop diem cho duong cham diem cu.
                policy.emit(state, rule_id, { target = r.target, matched = matched })
            end
        end
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

-- Cau hinh DANG CHAY, cho nguoi doc so lieu.
--
-- Admin truoc day goi `config.defaults()` de biet dict/prefix cua telemetry —
-- dung khi chua ai goi `configure()`, nhung SAI ngay khi co: no se doc mot dict
-- khac voi dict dang duoc ghi va bao "khong co su kien". Ham nay tra ban that.
--
-- Tra ban SAO: nguoi doc khong sua duoc cau hinh dang chay qua duong nay.
function _M.active_config()
    return config.copy(compiled_config)
end

_M.registry_ok = registry_ok
_M.registry_errors = registry_errors

return _M
