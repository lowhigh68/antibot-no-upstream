local _M = {}

local wp_paths  = require "antibot.waf.wordpress.paths"
local exposed   = require "antibot.waf.exposed"
local args      = require "antibot.waf.args"
local body      = require "antibot.waf.body"
local body_core = require "antibot.waf.body_core"
local upload    = require "antibot.waf.upload"
local routes    = require "antibot.waf.routes"
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
        -- Thu muc phuc vu request NAY. La khoa nhan dien CMS (xem khoi
        -- `root_id` trong `wordpress/paths.lua`): Host header do ke gui chon,
        -- docroot thi khong. Doc cung cho voi ba bien tren vi `rt.var` la mot
        -- phep tra bien nginx -- khong goi hai lan o hai noi.
        dr     = rt.var.document_root,
        -- Muc 5 can content-type de kiem hop dong route. Doc o day chu khong o
        -- cho dung de moi tang nhin cung mot `request` — va `rt.var` la mot phep
        -- tra bien nginx, khong nen goi hai lan o hai noi.
        ct     = rt.var.http_content_type,
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

local function find_uri_rule(uri, host, resolved, docroot)
    local id = exposed.check(uri)
    if id then return id, exposed.RULES end
    if (resolved.profiles or {}).wordpress ~= false then
        id = wp_paths.check(uri, host, docroot)
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
    --
    -- B1: than MULTIPART khong soi het di luat RIENG (`registry.lua`). `matched`
    -- la LY DO — ma `scan` khi khong soi duoc, `fntr_<ma>` khi kenh ten tep dung
    -- giua chung — khong bao gio la noi dung than.
    local blind = b.scan and b.scan ~= "ok" and b.scan ~= "empty"
    if b.family == "multipart" and (blind or body_core.FN_INCOMPLETE[b.fn_trunc]) then
        policy.emit(state, "body_multipart_incomplete", {
            target = "BODY",
            matched = blind and tostring(b.scan) or ("fntr_" .. tostring(b.fn_trunc)),
        })
    elseif blind then
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

    -- ── Buoc 4: bang chung CUNG MOT PART (V8 part record) ───────────────────
    --
    -- Hai correlation cu ghep hai fact TOAN REQUEST, nen `shell.php` rong o part 1
    -- cong `<?php` trong mot form field o part 2 ban y het `shell.php` chua `<?php`.
    -- Nhom nay doi CUNG MOT PART: `name_flags` va `content_flags` cua cung mot
    -- record.
    --
    -- Chay TRUOC `b.up_rule` de `matched` cua no khong bi dedupe cua policy che:
    -- `policy.emit` dedupe theo `rule_id + target`, va day la rule_id KHAC nen hai
    -- ben khong dap nhau — nhung thu tu nay lam log doc duoc theo dung thu tu suy
    -- luan (fact part -> fact request).
    --
    -- `matched` chi mang SLOT va TEN LUAT, tuyet doi khong mang ten tep hay noi dung:
    -- ca hai do ke gui dieu khien, va `waf.log` giu 30 ngay. Cung ly do `uprule=` chi
    -- ghi RULE_ID.
    -- Muc 7 phat o CUNG vong nay nhung NGOAI cong `p.name_flags`: co magic quan
    -- trong nhat dung khi ten SACH (`shell.jpg` mang byte `MZ`), tuc chinh luc cong
    -- do dong. Nen day la fact doc lap theo part, khong phai composite.
    local MAGIC_RULE = {
        magic_exec     = "upload_magic_exec",
        magic_mismatch = "upload_magic_mismatch",
    }

    for i = 1, #(b.parts or {}) do
        local p = b.parts[i]
        local cf = p.content_flags

        -- ── DUONG BYPASS da dong: `scan_state` phai duoc TIEU THU ──────────
        --
        -- `body_core` DA dat `scan_state = "config_trunc"` tu buoc 3, nhung khong
        -- ai doc no — nen `content_flags = false` doc thanh "da soi, sach" cho ca
        -- mot tep cau hinh CHAM TRAN. Payload ne duoc composite:
        --
        --     <512 dong vo hai>
        --     AddType application/x-httpd-php .jpg
        --
        -- Ten `.htaccess` van sinh signal, nhung `upload_apache_handler_content`
        -- khong xuat hien. Mot vung mu KE GUI CHON DUOC.
        --
        -- Phat fact RIENG chu khong coi no la `handler = true`: chung ta KHONG
        -- BIET trong phan bi cat co gi, va bia ra mot ket luan la dung loai loi ma
        -- `body_file_traversal` duoc tach ra de tranh. Fact nay noi dung mot dieu:
        -- "part nay la tep cau hinh va soi khong het".
        if p.scan_state and p.scan_state ~= "ok" then
            policy.emit(state, "upload_config_scan_incomplete", {
                target  = "MULTIPART_PART",
                -- Slot + LY DO, khong ten tep: `config_trunc` la hang so trong ma.
                matched = "slot=" .. tostring(p.slot) .. " " .. tostring(p.scan_state),
            })
        end

        if type(cf) == "table" then
            for flag, rule_id in pairs(MAGIC_RULE) do
                if cf[flag] then
                    -- `matched` mang SLOT, khong mang ten tep lan duoi: ca hai do ke
                    -- gui dat. Slot la mot so thu tu do ta dem, nen an toan.
                    policy.emit(state, rule_id, {
                        target  = "MULTIPART_PART",
                        matched = "slot=" .. tostring(p.slot),
                    })
                end
            end
        end
        if p.name_flags and type(cf) == "table" then
            for flag in pairs(cf) do
                local rule_id = registry.same_part_rule(p.name_flags, flag)
                if rule_id then
                    local hit = policy.emit(state, rule_id, {
                        target  = "MULTIPART_PART",
                        matched = "slot=" .. tostring(p.slot) .. " " ..
                                  tostring(p.name_flags) .. "+" .. tostring(flag),
                    })
                    if hit and not hit.excepted and hit.action ~= "observe" then
                        ctx.waf_upload_same_part = rule_id
                    end
                end
            end
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

-- MOT phep doc `waf:fimnew:` cho moi request, dung chung boi HAI nguoi goi.
--
-- `fim_factor` va `fim_new_direct` dung CHINH XAC cung mot khoa
-- (`waf:fimnew:<docroot><script_path>`) nhung truoc day goi `safe_get` RIENG, nen
-- mot request PHP khop detector non-block tra gia HAI round-trip cho CUNG mot cau
-- hoi (nguoi dung bat 28-09). Trong pham vi MOT request gia tri do khong the doi,
-- nen nho trong `ctx` la du va dung.
--
-- Nho ca ket qua RONG (`false`) chu khong chi ket qua co: neu khong, mot khoa khong
-- ton tai se bi hoi lai lan thu hai — dung cai dang toi uu.
local function fimnew_value(ctx, uri, rt)
    if ctx and ctx.waf_fimnew_read ~= nil then return ctx.waf_fimnew_read end
    local v = nil
    local root = rt.var.document_root
    if root and root ~= "" then
        v = tonumber(pool.safe_get("waf:fimnew:" .. root .. wp_paths.script_path(uri)))
    end
    if ctx then ctx.waf_fimnew_read = (v == nil) and false or v end
    return v
end

local function fim_factor(ctx, uri, detector_rule, rt)
    if not detector_rule or detector_rule.action == "block" then return nil end
    local v = fimnew_value(ctx, uri, rt)
    return v or nil
end

-- ── Muc 8: tep cau hinh vua bi SUA o thu muc cua URI nay ────────────
--
-- KHAC `fim_factor` o ba cho, va ca ba deu co ly do:
--
--   1. KHONG gate bang `detector_rule`. `fim_factor` chi tra loi khi URI khop mot
--      luat duong dan WP, vi no NANG DIEM cua chinh luat do. Nhom nay khong nang
--      diem cua ai — no la mot fact rieng, nen khong phu thuoc luat nao khop.
--   2. Tra khoa theo THU MUC, khong theo file. `.htaccess` gan nhu khong bao gio
--      la URI duoc goi; cai dang quan tam la "co mot `.htaccess` vua doi TRONG
--      THU MUC chua file dang bi goi". Do la co che that cua `AddType`: no doi
--      handler cho ca thu muc.
--   3. Chi mot phep `safe_get`, va chi khi URI co ve la mot tep thuc thi. Mot
--      `GET /anh.png` khong can hoi Redis — `.htaccess` doi khong lam anh thanh
--      ma. Gioi han nay lam so luot tra Redis nho di nhieu lan.
-- Executable VUA XUAT HIEN tren filesystem, KHONG gate bang luat duong dan nao.
--
-- `fim_factor` doi `detector_rule`, nen no chi nang diem cho path WordPress da dang
-- nghi — tuc `fim_new_executable` chua phai bao ve filesystem generic. Ham nay tra
-- loi cau do doc lap.
--
-- Chi hoi Redis khi URI la mot tep PHP CHAY DUOC: `waf:fimnew:` chi duoc ghi cho
-- be mat thuc thi (xem `NAMES` trong `fim.sh`), nen hoi cho `/anh.png` la mot luot
-- tra chac chan miss. `upload.PHP_EXT` la bang DA DO tren fleet.
local function fim_new_direct(ctx, uri, rt)
    local root = rt.var.document_root
    if not root or root == "" then return nil end
    local path = wp_paths.script_path(uri)
    local ext  = path:match("%.([%w]+)$")
    if not ext or not upload.PHP_EXT[ext:lower()] then return nil end
    -- Dung CHUNG phep doc voi `fim_factor` — xem `fimnew_value`.
    local v = fimnew_value(ctx, uri, rt)
    return v or nil
end

-- ── HAI LOI CUA BAN TRUOC, nguoi dung bat 27-09 ─────────────────────
--
-- 1. Loc `upload.PHP_EXT` BIT DUNG CO CHE can bat. `.htaccess` chua
--        AddType application/x-httpd-php .jpg
--    roi ke tan cong goi `/shell.jpg`. `.jpg` khong trong `PHP_EXT`, nen ban truoc
--    KHONG BAO GIO tra khoa — tuc dieu kien loc mau thuan voi chinh ly do luat nay
--    ton tai. Chu thich cu con tu noi "`.htaccess` doi handler cho ca thu muc" ngay
--    ben tren dong loc do.
-- 2. Ba khoa tra TUAN TU = ba round-trip Redis cho moi request PHP.
--
-- Sua ca hai bang MOT khoa theo THU MUC, gia tri la danh sach DUOI bi anh xa
-- (`fim.sh` trich bang dung cu phap ma `upload_content.lua` dung):
--        waf:fimchg:<docroot><thu-muc>/  ->  "jpg,png"   (`.htaccess`)
--        waf:fimchg:<docroot><thu-muc>/  ->  "*"         (`.user.ini`/`php.ini`)
--
-- `*` = "moi duoi PHP": `auto_prepend_file` nap ma cho MOI script PHP trong thu
-- muc, khong doi handler cua duoi nao. Nen voi `*` van giu dieu kien `PHP_EXT` —
-- do la GIOI HAN DUNG cho nhom do, khac han nhom `.htaccess`.
local function fim_config_changed(uri, rt)
    local root = rt.var.document_root
    if not root or root == "" then return nil end
    local path = wp_paths.script_path(uri)

    -- LAY `ext` TRUOC KHI HOI REDIS.
    --
    -- DINH CHINH chu thich cua chinh toi (nguoi dung bat 28-09): ban dau toi viet
    -- "CSS, anh, JS, `/` — moi request khong co duoi". Cau do TU MAU THUAN:
    -- `style.css` CO duoi. Phep sua nay chi bo Redis GET cho `/` va URL KHONG CO
    -- DUOI — nho hon han dieu toi da tuyen bo.
    --
    -- Nen chi phi THAT hien nay van la: moi CSS/JS/anh co duoi = mot GET `fimchg`;
    -- moi PHP/INC = mot GET `fimnew` cong mot GET `fimchg`. Pool giu lai chi phi
    -- TCP setup, khong giu lai lenh Redis lan viec dinh thoi cosocket.
    --
    -- Duong dong THAT la nap cac dau FIM thanh SNAPSHOT vao shared dict theo
    -- generation, roi tra bang table lookup. Chua lam — no la mot thay doi kien
    -- truc rieng, va no can mot con so ve so luong dau FIM dang song tren fleet.
    --
    -- Va phep hoi do KHONG BAO GIO dung duoc cho chung: ca hai nhanh ben duoi
    -- (`*` va danh sach duoi) deu doi `ext`, nen `ext == nil` la `return nil` chac
    -- chan. Tuc day khong phai danh doi do chinh xac lay toc do — no la bo mot
    -- phep hoi KHONG THE doi ket qua.
    local ext = path:match("%.([%w]+)$")
    if not ext then return nil end
    ext = ext:lower()

    local dir = path:match("^(.*/)") or "/"
    -- MOT `safe_get`, khong ba.
    local v = pool.safe_get("waf:fimchg:" .. root .. dir)
    if not v or v == "" then return nil end

    -- BA KHONG GIAN TEN, khong con mot dau `*` mang ba nghia (nguoi dung bat 28-09):
    --
    --   @all     handler ap CA thu muc (`SetHandler`/`ForceType`/`Options +ExecCGI`)
    --            -> MOI duoi, KHONG rang buoc `PHP_EXT`. Day la cho ban truoc sai:
    --            `SetHandler application/x-httpd-php` lam `shell.jpg` CHAY duoc,
    --            nhung `*` bi hieu la "autoload" nen `jpg` khong khop `PHP_EXT` va
    --            request `/shell.jpg` khong bao gi.
    --   @php     autoload tu `.user.ini` -> chi co nghia voi script PHP
    --   @phpini  autoload tu `php.ini` -> TACH RIENG vi pham vi phu thuoc SAPI:
    --            `.user.ini` la co che per-directory CHUAN cua CGI/FastCGI, con
    --            `php.ini` di theo chuoi tim cau hinh cua SAPI/CWD nen KHONG mac
    --            nhien co cung pham vi theo thu muc. Giu rieng cho tới khi do duoc
    --            tren DirectAdmin.
    --   <duoi>   duoi cu the tu `AddType`/`AddHandler`
    -- NHAN TRA VE DI THANG VAO `matched=` cua waf.log, nen moi token phai co nhan
    -- RIENG. Ban truoc gop `@php` va `@phpini` thanh cung mot `"autoload"`, tuc
    -- phep tach chi ton tai o Redis chu KHONG o hanh vi lan so lieu — mai doc log
    -- khong biet hit den tu `.user.ini` hay `php.ini` (nguoi dung bat 28-09). Ma
    -- do la chinh cau hoi can tra loi, vi hai loai co pham vi khac nhau.
    --
    -- Duyet het roi CHON theo do manh, khong `return` ngay: mot thu muc co the co
    -- ca `@all` lan `@php`, va bao cai manh hon la dung.
    local hit_all, hit_ext, hit_php, hit_phpini, hit_exec = false, false, false, false, false
    for e in v:gmatch("[^,]+") do
        if e == "@all" then
            hit_all = true                        -- moi duoi, khong rang buoc PHP_EXT
        elseif e == "@execcgi" then
            -- `Options +ExecCGI` CHI cap quyen chay CGI; no KHONG noi tep nao la
            -- CGI. Mot minh no chua lam gi chay duoc, nen bao RIENG va NHE hon —
            -- gop vao `@all` la bao manh hon su that.
            hit_exec = true
        elseif e == "@php" then
            hit_php = true
        elseif e == "@phpini" then
            hit_phpini = true
        elseif e == "*" then
            -- Khoa CU tu ban truoc, con song tới het TTL 7 ngay. Giu nghia cu
            -- (autoload) de khong doi nghia mot khoa da ghi.
            hit_php = true
        elseif e == ext then
            hit_ext = true
        end
    end

    if hit_all then return "handler_all" end
    if hit_ext then return "handler_ext" end
    if upload.PHP_EXT[ext] then
        -- `.user.ini` truoc `php.ini`: pham vi cua no CHAC CHAN hon (co che
        -- per-directory chuan cua CGI/FastCGI), con `php.ini` di theo chuoi tim cau
        -- hinh cua SAPI/CWD nen chua chac ap cho thu muc nay.
        if hit_php    then return "autoload_userini" end
        if hit_phpini then return "autoload_phpini"  end
    end
    if hit_exec then return "execcgi_only" end
    return nil
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

    -- Muc 5: HOP DONG ENDPOINT. Dat o day, truoc moi thu khac, vi no la phep kiem
    -- RE NHAT trong ca `run_pre` — mot phep tra bang theo path, khong doc than,
    -- khong tra Redis, khong chay regex. Va no khong phu thuoc ket qua nao o duoi.
    --
    -- `matched` la TEN VI PHAM (mot chuoi tu tap co dinh trong `routes.lua`) chu
    -- KHONG phai URI hay content-type: ca hai thu do ke gui dat, va `waf.log` giu
    -- 30 ngay. Route thi doc duoc tu `matched` cua cac dong khac tren cung `rid`.
    -- PHA 1 — CHI method. Content-type va upload can biet co THAN hay khong, nen
    -- chung di o pha 2 sau `body.probe`.
    --
    -- `is_wp_root` la cong overlay: hop dong nay la route CUA WORDPRESS, nen no chi
    -- ap cho host DA duoc chung minh la WordPress bang mot file THAT tren dia. Cung
    -- cong ma `wp_root_unknown` dung — khong viet lai phep kiem thu hai.
    local route_bad, route_name = routes.check_pre(
        request.uri, request.method, wp_paths.is_wp_root, request.host, request.dr)
    if route_bad then
        policy.emit(state, route_bad, { target = "URI", matched = route_name })
    end

    local uri_rule, detector_rules = find_uri_rule(request.uri, request.host, resolved, request.dr)
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

    -- PHA 2 cua hop dong endpoint — SAU `body.probe`, vi hai phep kiem con lai can
    -- biet co THAN hay khong, va `route_upload` can PARSER chung minh co part tep.
    --
    -- `has_body`: mot `GET` mang `Content-Type` la la KHONG duoc sinh fact — khong
    -- co than thi content-type khong rang buoc gi. `ctx.waf_body` ton tai nghia la
    -- `probe` da thay mot than (ke ca khi khong soi duoc).
    local b = ctx.waf_body
    local has_body = b ~= nil and b.scan ~= "empty"
    local post_bad, post_name = routes.check_post(
        request.uri, request.ct, has_body, b, wp_paths.is_wp_root, request.host,
        request.dr)
    if post_bad then
        policy.emit(state, post_bad, { target = "URI", matched = post_name })
    end
    -- `route_multipart` do RIENG va CONG THEM (khong loai tru `route_upload`): con
    -- so nay cho biet `route_upload` bo qua bao nhieu — multipart chi co field, va
    -- multipart KHONG soi duoc. Thieu no thi khong phan biet duoc `route_upload` im
    -- lang vi SACH hay vi KHONG CHUNG MINH DUOC.
    local mp_bad, mp_name = routes.check_multipart(
        request.uri, request.ct, has_body, wp_paths.is_wp_root, request.host,
        request.dr)
    if mp_bad then
        policy.emit(state, mp_bad, { target = "URI", matched = mp_name })
    end

    -- FIM is evidence, not a verdict. The confidence value generated by
    -- fim.sh scales the rule score and can participate in a shadow correlation.
    local factor = fim_factor(ctx, request.uri, detector_rule, rt)
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

    -- Fact DOC LAP: "request dang goi mot executable VUA XUAT HIEN tren
    -- filesystem". `fim_factor` o tren gate bang `detector_rule`, nen tren mot CMS
    -- khac hay site tu viet (`/custom/module/new-shell.php`) no khong bao gio hoi
    -- Redis du FIM DA co khoa. Nhom nay khong phu thuoc luat duong dan nao.
    --
    -- Chay khi `factor` o tren la `nil` HOAC khi no co gia tri: hai nhom dem RIENG,
    -- va chenh lech la thu noi cho biet bao nhieu file moi bi goi NGOAI path WP.
    local direct = fim_new_direct(ctx, request.uri, rt)
    if direct then
        policy.emit(state, "fim_new_exec_direct", {
            target  = "URI",
            -- Muc tin cay tu FIM, khong phai duong dan: duong dan la du lieu ke gui
            -- dieu khien, con `boost` la mot so do chinh ta tinh.
            matched = string.format("%.2f", direct),
        })
    end

    -- Muc 8: tep cau hinh trong CUNG thu muc voi tep thuc thi dang bi goi vua doi.
    -- `matched` mang TEN TEP CAU HINH (`.htaccess`), khong mang duong dan: ba ten do
    -- la hang so trong ma, khong phai chuoi ke gui dat.
    -- DEM vung mu "than co du lieu ma thieu Content-Type". `body.probe` dat co nay
    -- TRUOC cong Content-Type cua no; xem khoi chu thich tai do de biet vi sao dem
    -- truoc khi mo. Chi doc header, khong doc than.
    --
    -- DIEU KIEN la `_group`, KHONG phai `_missing`: `_missing` chi duoc dat cho nhom
    -- `cl_positive`, nen ban truoc BO HET ba nhom con lai (chunked, HTTP/2 khong
    -- khai bao do dai, `Content-Length: 0`) — tuc con so bao cao la can duoi ma
    -- khong noi ra minh la can duoi.
    if ctx.waf_body_ct_group then
        -- `cl=<so>` giu NGUYEN cho nhom `cl_positive` de so lieu 29-09 con so sanh
        -- duoc; ba nhom moi mang TEN NHOM. `postdeploy.sh` muc 16 tach bang dau `=`.
        local m = ctx.waf_body_ct_group
        if ctx.waf_body_ct_missing then
            m = "cl=" .. tostring(ctx.waf_body_ct_missing)
        end
        policy.emit(state, "body_ct_missing", {
            target  = "BODY",
            matched = m,
        })
    end

    local cfg_mark = fim_config_changed(request.uri, rt)
    if cfg_mark then
        policy.emit(state, "fim_config_changed", {
            target  = "URI",
            matched = cfg_mark,
        })
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

-- SENTINEL WordPress: `wp-settings.php` PHAI co tren dia tai goc do.
--
-- VI SAO, va day la mot FP dang chay that: `target_exists` chi kiem TEP DUOC
-- REQUEST co ton tai. Nen mot site TU VIET co mot tep that duoi `/wp-admin/` hay
-- `/wp-content/` (thu muc trung ten, chuyen binh thuong) se duoc danh dau la
-- WordPress, roi BA luat HARD-BLOCK bat len o do. FP la uu tien so mot.
--
-- `fim.sh wpinv` da dung `wp-settings.php` lam dau nhan tu dau (`WPMARK`). Nen
-- truoc ban nay HAI duong co HAI dinh nghia "la WordPress": offline doi sentinel,
-- runtime chi doi "tep nay ton tai". Chinh chu thich tren `_M.is_wp_root` canh
-- bao ve viec nhan doi dinh nghia — va no da bi nhan doi o day.
--
-- KHONG dung `wp-includes/version.php`: dong bo voi `iswp` cua `fim.sh` (xem chu
-- thich tai do — `scan_hot` khong quet `wp-includes/` nen dung no lam tin hieu
-- tat cam o phia offline).
--
-- Chi phi: MOT `io.open` them, va chi khi `needs_mark` da tra ve tien to — tuc
-- toi da mot lan moi 300 giay cho moi thu muc. `io.open` chay duoc o log phase
-- (khong phai cosocket), cung ly do `target_exists` chay duoc o day.
local function wp_sentinel_exists(rt, prefix)
    local root = rt.var.document_root
    if not root or root == "" then return false end
    if root:sub(-1) == "/" then root = root:sub(1, -2) end
    local fh = io.open(root .. (prefix or "") .. "/wp-settings.php", "r")
    if not fh then return false end
    fh:close()
    return true
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
    local dr   = ngx.var.document_root
    local wp = wordpress_enabled and
               wp_paths.needs_mark(ngx.var.uri, host, dr) or nil
    if not uri_hit and wp == nil then return end

    local exists = target_exists(ngx)
    if uri_hit then ctx.waf_target_exists = exists end
    -- Danh dau doi HAI bang chung, khong mot:
    --   `exists`     tep WordPress duoc request co that tren dia
    --   `sentinel`   `wp-settings.php` co that tai goc do
    -- Thieu dieu kien thu hai thi mot site tu viet co thu muc `/wp-content/`
    -- duoc danh dau la WordPress, va ba luat hard-block bat len o do.
    if wp ~= nil and exists == true and wp_sentinel_exists(ngx, wp) then
        wp_paths.mark(host, wp, dr)
    end
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
