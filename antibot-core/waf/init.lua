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
--
-- Day la GRAMMAR cua ben SINH (`htaccess_parse.awk`), va truoc day hai ben khong
-- khop nhau theo HAI huong (nguoi dung bat 30-09):
--
--   · `AddHandler ... .x-y` sinh `ext:x-y`, nhung `path:match("%.([%w]+)$")` tra
--     `nil` cho `/shell.x-y` (`%w` khong gom `-`) -> `return nil` TRUOC ca Redis
--     GET, nen dau do KHONG BAO GIO doc duoc.
--   · `AddHandler ... .a.b` sinh `ext:a.b`, nhung phep match mot doan tra `b`, nen
--     token khong bao gio khop.
--
-- Apache (mod_mime) coi MOI DOAN phan cach boi dau cham la MOT duoi doc lap. Loc ky
-- tu la cach SAI cho viec nay -- Apache khong cam ky tu nao trong doi so cua
-- `AddHandler`, nen mot danh sach ky tu hop le se phai doan truoc moi duoi.
-- MOI DOAN sau dau cham la MOT duoi DOC LAP, theo mod_mime: `x.tar.gz.php` co ba duoi
-- `tar`, `gz`, `php` — KHONG phai `tar.gz.php`/`gz.php`/`php`.
--
-- Ban truoc cua ham nay sinh cac HAU TO thay vi cac DOAN, va no sai theo HAI huong
-- (nguoi dung bat 01-10):
--   · `AddHandler ... .gz` sinh `ext:gz`, nhung `/x.tar.gz.php` khong co hau to `gz`
--     -> BO SOT. Apache thi khop, va no lam tep do chay qua handler cua `.gz`.
--   · `AddHandler ... .gz.php` sinh `ext:gz.php` va hau to `gz.php` KHOP -> bao OAN,
--     trong khi Apache khong coi `gz.php` la mot duoi bao gio.
-- Assertion cu trong `policy_test.lua` ghim dung oracle sai do; da sua cung luc.
local function path_suffixes(path)
    local base = path:match("([^/]+)$")
    if not base then return nil end
    local out, n, first = nil, 0, true
    for seg in base:gmatch("[^.]+") do
        if first then
            -- Doan DAU la TEN tep, khong phai duoi. `.htaccess` (bat dau bang dau
            -- cham) co doan dau la `htaccess`, va Apache cung khong coi do la duoi.
            first = false
        else
            n = n + 1
            out = out or {}
            out[n] = seg:lower()
        end
    end
    return out
end

-- `fim_config_active`, DOI TEN tu `fim_config_changed` (02-10).
--
-- Khoa mang TRANG THAI DANG TON TAI, khong phai su kien "vua doi": `state_marks` ghi
-- lai no MOI LOT QUET du khong co gi thay doi. Do tren fleet: 620/620 lot `fim.log`
-- deu bao `0 key bao WAF` (= khong co tep nao VUA DOI) trong khi van co 12 khoa
-- trang thai song.
--
-- Ten cu tron HAI cau hoi khac nhau vao mot nhan:
--     "co bao nhieu thu muc VUA DOI cau hinh"        -> `fim.log`, `chgcount`
--     "co bao nhieu thu muc DANG co cau hinh nguy hiem" -> khoa nay
-- Doc so lieu `rule=fim_config_changed` trong `waf.log` tra loi cau thu HAI nhung
-- TEN noi cau thu NHAT, nen moi phep dem deu phai giai thich bang mieng.
--
-- KHONG tach thanh hai khoa (`fimcfg:` trang thai + `fimchg:` su kien): bden doc se
-- phai `MGET` HAI chuoi to tien thay vi mot, va hai nguon cho CUNG mot cau hoi la
-- dung cai da sinh ra loi 526-dong (merge o ca hai ben). Nhan tra ve
-- (`handler_all`/`handler_ext`/`autoload_*`/`execcgi_*`) da mo ta DUNG "cau hinh la
-- gi" nen khong doi.
local function fim_config_active(uri, rt)
    local root = rt.var.document_root
    if not root or root == "" then return nil end
    local path = wp_paths.script_path(uri)

    -- ── PATH_INFO cho MOI duoi, khong chi duoi PHP ───────────────────
    --
    -- `script_path` cat PATH_INFO bang `RX_PHP_EXEC`, va bieu thuc do CHI liet ke duoi
    -- PHP (`php[0-9]?|phtml|phar|pht|phps`). Do duoc 03-10 bang chinh `init.lua`:
    --
    --     URI=/shell.jpg/x  CHAIN=[v2,h+:jpg]  ->  nil     (phai la handler_ext)
    --     URI=/a.jpg        CHAIN=[v2,h+:jpg]  ->  handler_ext
    --
    -- Voi `/shell.jpg/x` thi `script_path` tra NGUYEN URI, nen `dir` thanh
    -- `/shell.jpg/` — mot thu muc KHONG TON TAI — va `sufs` lay tu `x` (khong duoi).
    -- Ca hai deu sai: `MGET` tra khoa rac thay vi khoa cua thu muc THAT, va duoi that
    -- (`jpg`) khong duoc xet. Mot `AddHandler php .jpg` o goc thanh KHONG PHAT HIEN.
    --
    -- Cat o day chu KHONG sua `script_path`: ham do co hop dong rieng (khoa
    -- `waf:fimnew:` dung no o CA hai ben ghi/doc, va `wordpress_paths_test.lua` ghim
    -- 67 assertion). Doi no se lam lech cap khoa do. Cau hoi o ham NAY khac: "duoi nao
    -- cua tep THAT can tra", va moi duoi deu co the mang handler.
    -- Chi cat khi phan sau dau `/` KHONG co dau `.`: `/a.jpg/b.css` la mot duong dan
    -- that co the ton tai (thu muc `a.jpg`).
    --
    -- DAY LA MOT PHEP DOAN, khong phai ket luan. URI khong chung minh duoc `/a.jpg/`
    -- la PATH_INFO hay mot thu muc THAT: neu la thu muc that thi `x` la tep that va
    -- Apache KHONG ap mapping `.jpg` cho no — nhan se la FP. Chu thich cu cua toi noi
    -- "huong con lai bo sot, khong bao oan"; review 2 diem 5 bac dung dieu do.
    --
    -- Nen nhan tra ve mang hau to `?pi` khi ket luan den TU PHEP DOAN. Policy doc
    -- `matched=` nen dem duoc bao nhieu lan, va mot nhan `handler_ext?pi` khong bi
    -- nham voi `handler_ext` chac chan. KHONG them `io.open` o access phase: do la hot
    -- path va mot phep cham dia moi request co dang `/x.ext/seg` la chi phi phai do
    -- truoc khi quyet.
    --
    -- `[%w_-]` thay vi `[%w]`: mot duoi nhu `.x-y` duoc parser ho tro nhung mau cu
    -- khong cat duoc (review 2 diem 5).
    --
    -- GIOI HAN con lai, ghi ro: mau khop MOT doan cuoi, nen `/shell.jpg/x/y` chua cat
    -- duoc. Huong bo sot.
    local pi_doan = false
    if path == uri then
        local base, rest = uri:match("^(.-%.[%w_-]+)/([^/]*)$")
        if base and rest and not rest:find(".", 1, true) then
            path = base
            pi_doan = true
        end
    end

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
    -- `sufs == nil` (URL khong co duoi: `/shell`, `/`) KHONG duoc `return` o day.
    --
    -- `@all` sinh tu `SetHandler`/`ForceType`, va hai directive do ap cho MOI tep
    -- trong thu muc — KE CA tep khong co duoi. `SetHandler application/x-httpd-php`
    -- lam `/shell` (khong duoi) chay qua PHP, nhung ban truoc thoat truoc ca Redis GET
    -- nen dau do KHONG BAO GIO doc duoc (nguoi dung bat 01-10; oracle cu trong
    -- `policy_test.lua` ghim chinh cai sai do: `@all + /noext -> nil`).
    --
    -- Nen chi phi Redis tang: truoc day `/` va URL khong duoi duoc bo qua. Do la
    -- danh doi DUNG — bo mot FN that de doi mot GET tren tap URL nho (so request
    -- khong co duoi nho hon han so co duoi).
    local sufs = path_suffixes(path)
    -- `ext` = doan CUOI, dung cho `PHP_EXT` — cau hoi "tep nay co phai script PHP
    -- khong", ma PHP/Apache tra loi bang doan cuoi. `nil` khi khong co duoi, va cac
    -- nhanh doi `PHP_EXT` ben duoi tu loai minh.
    local ext = sufs and sufs[#sufs] or nil

    local dir = path:match("^(.*/)") or "/"

    -- ── TRA CHUOI TO TIEN, khong vat chat hoa ────────────────────────
    --
    -- `.htaccess` ap cho thu muc hien tai VA MOI thu muc con, nen mot `AddHandler` o
    -- webroot phai bat `uploads/a.jpg`. Ban truoc giai quyet bang cach cho `fim.sh`
    -- GHI mot khoa cho TUNG thu muc con. Do la thiet ke SAI, va so lieu tu 171-96
    -- (01-10) chung minh truc tiep:
    --
    --   · 737/737 khoa cua `butkythuatso.com` co gia tri Y HET NHAU
    --     (`ext:php,ext:php7,ext:phtml`) — mot hang so theo cay bi nhan ban 737 lan.
    --   · `fim.sh check` 49s -> 5 phut 23, va VAN cat mat 3.174 thu muc o tran.
    --   · 5.490 khoa, trong khi so thu muc CO tep cau hinh la 11.
    --   · Va no KHONG the phu `uploads/a.jpg` du co tran bao nhieu: manifest chi liet
    --     ke cac duoi PHP, nen mot thu muc chi chua `.jpg` khong bao gio vao danh sach
    --     (nguoi dung bat 01-10 — mau thuan ngay voi muc tieu cua co che).
    --
    -- Nay `fim.sh` ghi DUNG 11 khoa (thu muc CO tep cau hinh), con day tra NGUOC LEN.
    -- MOT `MGET` cho ca chuoi, khong phai mot GET moi tang: do sau that la 0-7 tang
    -- (do tren fleet), nen 8 GET la khong chap nhan duoc tren hot path, con mot `MGET`
    -- 8 khoa la mot round-trip y nhu truoc.
    -- ── HAI TIEN TO trong MOT `MGET`, giai doan di tru ───────────────
    --
    -- Khoa doi tu `waf:fimchg:` sang `waf:fimcfg:` vi no mang TRANG THAI DANG TON
    -- TAI, khong phai su kien "vua doi": `state_marks` ghi lai no moi lot quet du
    -- khong co gi thay doi (tren fleet 620/620 lot deu `0 key bao WAF` nhung van co
    -- 12 khoa trang thai). Ten cu lam telemetry lan hai cau hoi khac nhau — "co bao
    -- nhieu thu muc VUA DOI cau hinh" va "co bao nhieu thu muc DANG co cau hinh
    -- nguy hiem" — va do la dieu nguoi dung bat 01-10.
    --
    -- Doc CA HAI tien to trong CUNG mot `MGET` chu khong hai lan: khoa `fimchg:` cu
    -- con song het TTL 7 ngay, va bo doc chung ngay thi 12 thu muc da danh dau MAT
    -- phat hien cho tới lot `fim.sh` tiep theo. Chuoi moi xep TRUOC chuoi cu, va
    -- vong merge duyet NGUOC nen khoa MOI duoc ap SAU — tuc khoa moi thang khi ca
    -- hai cung ton tai.
    --
    -- HAN CHOT 09-10-2026 (7 ngay tu 02-10): bo nhanh `fimchg:`, va khi do `nk`
    -- tro lai mot nua.
    local keys, nk, ndir = nil, 0, 0
    -- `depth_cut`: co tang NAO bi bo khong. Phai o NGOAI `do` block de nhan tra ve
    -- doc duoc — mot URI dai bat thuong khong duoc im lang.
    local depth_cut = false
    do
        local segs, ns = nil, 0
        local seg = dir
        while seg and seg ~= "" do
            ns = ns + 1
            segs = segs or {}
            segs[ns] = seg
            if seg == "/" then break end
            -- Bo mot tang: `/a/b/` -> `/a/`
            seg = seg:sub(1, #seg - 1):match("^(.*/)")
            -- TRAN do sau: khong de mot URI dai tuy y sinh ra mot `MGET` dai tuy y.
            --
            -- GIU WEBROOT khi bi cat: `break` tran lam `/` KHONG vao `segs`, nen mot
            -- `AddHandler` o webroot bi bo HOAN TOAN. Do 03-10:
            --     URI 13 tang, khoa @ webroot -> `nil`  (dung phai `handler_ext`)
            --     URI  3 tang, khoa @ webroot -> `handler_ext`
            -- Day la FN do dau vao kiem soat duoc, nen phai dat phan tu CUOI thanh `/`
            -- thay vi bo han. Ket qua: mat cac tang GIUA, giu hai dau — tang gan request
            -- nhat (quan trong nhat) va webroot (pham vi rong nhat).
            --
            -- ── GIOI HAN CON LAI, DA QUYET: BO QUA ──────────────────
            --
            -- Neu config nguy hiem DUY NHAT nam o mot tang GIUA bi bo thi ham tra `nil`
            -- va `:cut` khong duoc phat (hau to chi them vao ket qua DA tim thay). Review
            -- 3 diem 3 neu dung.
            --
            -- Nguoi dung quyet 04-10: bo qua. Ly do la cua nguoi dung va no dung —
            -- "gio la 12 tang chu mai la 24 tang thi sao": nang tran la duoi theo mot con
            -- so TUY Y, no khong bien FN thanh khong-FN, chi day nguong ra xa hon. Va
            -- huong dung han (index cac thu muc CO config roi resolve tu do) la THEM MOT
            -- NGUON DU LIEU phai dong bo — dung thu da sinh ra bug 526 dong o `ad7bb4b`,
            -- khi `fim.sh` ghi mot khoa cho TUNG thu muc con.
            --
            -- Do sau quan sat tren fleet: 4 tang (do 02-10 tren 171-96, 60/78 domain co
            -- `.htaccess` long nhau, sau nhat la `.../domains/<d>/public_html/cgi-bin`).
            -- Nen tran 12 con thua gap ba, va `:cut` dem duoc 0 luot trong waf.log.
            if ns >= 12 then
                segs[ns] = "/"
                depth_cut = true
                break
            end
        end
        if segs then
            ndir = ns
            keys = {}
            for i = 1, ns do keys[i] = "waf:fimcfg:" .. root .. segs[i] end
            for i = 1, ns do keys[ns + i] = "waf:fimchg:" .. root .. segs[i] end
            nk = ns * 2
        end
    end
    if not keys then return nil end

    -- `MGET` tra mang theo DUNG thu tu khoa: `keys[1]` la thu muc CUA REQUEST, cac
    -- phan tu sau la to tien cang xa. Merge phai di tu GOC XUONG (Apache doc tu goc),
    -- nen duyet NGUOC mang.
    local vals = pool.safe_mget(keys, nk)
    if type(vals) ~= "table" then return nil end

    -- ── BON TRUC RIENG, roi PRECEDENCE o duoi ────────────────────────
    --
    -- `h` = handler theo duoi, `t` = type theo duoi, `flag` = cac truc "ca thu muc".
    -- Moi bang dung BA trang thai: `nil` chua noi gi | `false` TAT tuong minh | `true`
    -- BAT. Tang GAN hon ghi de tang xa hon, va `false` la mot phep ghi de THAT chu
    -- khong phai "khong co du lieu" — do la cho `nil` khac `false`.
    --
    -- Ban truoc chi co MOT bang `st` cho ca hai truc theo duoi, nen `RemoveType .jpg`
    -- o con xoa luon handler ke thua (ca1: FN) va `AddHandler default-handler .jpg`
    -- khong xoa duoc type ke thua (ca2: FP).
    local h, t, flag = nil, nil, nil
    -- ── MOT GIA TRI MOI TANG: fallback, KHONG phai cong hai snapshot ──
    -- ── GIAI THOAT TEN DUOI ──────────────────────────────────────────
    --
    -- Parser thoat `,` thanh `%2C` va `%` thanh `%25` trong TEN DUOI, vi `fim.sh` ghep
    -- token bang dau phay va Linux cho phep `,` trong ten tep: mot
    -- `AddHandler php .jpg,evil` tung sinh `h+:jpg,evil` -> ben doc hieu thanh token
    -- `h+:jpg` va mot token la `evil`, nen request `x.jpg,evil` KHONG khop (FN, dau vao
    -- do khach kiem soat).
    --
    -- THU TU NGUOC khi giai: `%2C` TRUOC, `%25` CUOI. Nguoc lai thi `%252c` (mot `%`
    -- THAT trong ten duoi) bi giai thanh `%2c` roi thanh `,` — sai han.
    --
    -- Nhan ca `%2c` chu thuong: `tolower` trong parser chay TRUOC khi thoat, nen mot
    -- `%2C` co that trong ten tep thanh `%2c`.
    --
    -- `find` truoc khi `gsub`: hau het ten duoi khong co `%` nao, va day la hot path.
    local function unesc(s)
        if not s:find("%", 1, true) then return s end
        s = s:gsub("%%2[Cc]", ",")
        return (s:gsub("%%25", "%%"))
    end

    local h, t, flag = nil, nil, nil
    -- `keys` xep `ns` khoa MOI (con -> cha) roi `ns` khoa CU (con -> cha). Ban truoc
    -- duyet `i = nk, 1, -1` tren CA mang, nen thu tu ap thuc te la
    --     cu-cha -> cu-con -> moi-cha -> moi-con
    -- KHONG phai thu tu Apache `cha -> con`. Do duoc 03-10 bang chinh `init.lua`:
    --
    --   FN: NEW=[con rong, cha v2,h-:jpg]  OLD=[con ext:jpg, cha rong]
    --       -> `nil`, dung phai `handler_ext` (Apache lay con, va con CU bat .jpg)
    --   FP: NEW=[con v2,@php]  OLD=[con ext:jpg]  cung mot thu muc
    --       -> `handler_ext`, dung phai `nil` (snapshot MOI khong con .jpg)
    --
    -- Hai loi khac nhau: cai dau la THU TU TANG, cai sau la hai snapshot cua CUNG mot
    -- thu muc duoc cong lai. Marker `v2` chi chon GRAMMAR cho tung value, no khong lam
    -- khoa moi THAY THE khoa cu.
    --
    -- Nay: moi tang chon MOT value (moi neu co, nguoc lai cu), roi duyet tu CHA xuong
    -- CON. Van mot `MGET` — chi doi cach ghep cap truoc khi reducer nhan token.
    for i = ndir, 1, -1 do
        local v = vals[i]
        if v == ngx.null or v == "" then v = nil end
        if not v then
            local o = vals[ndir + i]
            if o ~= ngx.null and o ~= "" then v = o end
        end
        if v then
            -- ── MOC PHIEN BAN TRONG GIA TRI ──────────────────────────
            --
            -- `c942edf` doi hop dong token (`ext:`/`@all` -> `h+:`/`@sh+`) ma KHONG doi
            -- tien to khoa, nen trong 7 ngay TTL mot khoa `waf:fimcfg:` co the mang
            -- dang CU hay dang MOI va ben doc phai DOAN tu noi dung. Doan la sai: mot
            -- ten tep that co the sinh token trung ca hai khong gian.
            --
            -- Nay `fim.sh` ghi `v2|<token,...>`. Co moc -> CHI nhanh moi; khong co ->
            -- CHI nhanh di tru. Hai luat KHONG bao gio cham nhau.
            --
            -- Khong dung mot TIEN TO KHOA thu ba (`waf:fimcfg:v2:`) vi `MGET` hien gui
            -- `ns * 2` khoa; them mot tien to thanh `ns * 3` tren HOT PATH moi request.
            -- Moc trong gia tri khong ton them khoa nao.
            --
            -- Moc la mot TOKEN `v2` o DAU danh sach, khong phai tien to `v2|`:
            -- `gen_resp` trong `fim.sh` tach dong `<toks>|<thu-muc>/` bang dau `|` DAU
            -- TIEN, nen mot `|` trong gia tri lam nhanh dirty ghi khoa RAC (do duoc
            -- 03-10: 30 ca do). `fim.sh` dat no o dau, nen so TIEN TO du — khong can
            -- quet ca chuoi tren hot path.
            local v2 = false
            if v:sub(1, 3) == "v2," then v2 = true; v = v:sub(4)
            elseif v == "v2" then v2 = true; v = "" end
            for e in v:gmatch("[^,]+") do
                local p3 = e:sub(1, 3)
                if not v2 then
                    -- ── DANG CU, doc-de-di-tru. HAN CHOT 10-10-2026 ──
                    --
                    -- Dang cu khong tach handler/type, nen no ban vao truc HANDLER
                    -- (manh hon trong thang precedence). Xap xi AN TOAN theo huong giu
                    -- phat hien: mot `AddType php` cu thanh handler thay vi type, va vi
                    -- handler uu tien cao hon, ket qua cuoi khong doi.
                    if e:sub(1, 4) == "ext:" then
                        h = h or {}; h[e:sub(5)] = true
                    elseif p3 == "rm:" then
                        h = h or {}; h[e:sub(4)] = false
                    elseif e == "@all" then
                        flag = flag or {}; flag.sh = true
                    elseif e == "-@all" then
                        -- Dang CU `-@all` phu dinh truc TOAN-THU-MUC, va CHI truc do: o
                        -- hop dong cu mot `AddHandler ... .jpg` van con hieu luc sau
                        -- `SetHandler none`. Dat `ft` (nam DUOI `AddHandler` trong thang)
                        -- chu khong `sh` (muc CAO NHAT — reducer se dung lai va khong xet
                        -- `h`, lam `-@all + ext:jpg` tra `nil`; bo test bat).
                        flag = flag or {}
                        if flag.sh == nil then flag.ft = false else flag.sh = false end
                    elseif e == "@execcgi" then
                        flag = flag or {}; flag.exec = true; flag.exec_noop = nil
                    elseif e == "@execcgi:noop" then
                        flag = flag or {}
                        if flag.exec ~= true or flag.exec_noop then flag.exec_noop = true end
                        flag.exec = true
                    elseif e == "-@execcgi" then
                        flag = flag or {}; flag.exec = false
                    elseif e == "@php" then
                        flag = flag or {}; flag.php = true
                    elseif e == "@phpini" then
                        -- `i == 1` la thu muc CUA REQUEST. Khong con `i == ndir + 1`:
                        -- vong gio chi chay `1..ndir` va chon MOT value moi tang, nen
                        -- chi so khong con mang nghia "tien to nao".
                        if i == 1 then
                            flag = flag or {}; flag.phpini = true
                        end
                    elseif e == "*" then
                        flag = flag or {}; flag.php = true
                    else
                        -- Dang CU NHAT: duoi THO khong tien to. HAN CHOT 06-10-2026.
                        h = h or {}; h[e] = true
                    end
                -- BON trang thai moi truc, va day la ly do `"reset"` khong the la
                -- `nil`: `nil` de tang XA hon ghi vao sau do (merge di tu cha xuong
                -- con), con `"reset"` la mot phat bieu THAT cua tang nay — no xoa
                -- trang thai cung truc nhung CHO reducer roi xuong truc uu tien thap
                -- hon.
                --   true     nguy hiem
                --   false    explicit LANH -> reducer DUNG lai
                --   "reset"  mapping BI GO -> reducer ROI XUONG
                --   nil      khong phat bieu -> ke thua
                elseif p3 == "h+:" then
                    h = h or {}; h[unesc(e:sub(4))] = true
                elseif p3 == "h-:" then
                    h = h or {}; h[unesc(e:sub(4))] = false
                elseif p3 == "h0:" then
                    h = h or {}; h[unesc(e:sub(4))] = "reset"
                elseif p3 == "t+:" then
                    t = t or {}; t[unesc(e:sub(4))] = true
                elseif p3 == "t-:" then
                    t = t or {}; t[unesc(e:sub(4))] = false
                elseif p3 == "t0:" then
                    t = t or {}; t[unesc(e:sub(4))] = "reset"
                elseif e == "@sh+" then
                    flag = flag or {}; flag.sh = true
                elseif e == "@sh-" then
                    flag = flag or {}; flag.sh = false
                elseif e == "@sh0" then
                    flag = flag or {}; flag.sh = "reset"
                elseif e == "@ft+" then
                    flag = flag or {}; flag.ft = true
                elseif e == "@ft-" then
                    flag = flag or {}; flag.ft = false
                elseif e == "@ft0" then
                    flag = flag or {}; flag.ft = "reset"
                elseif e == "@exec+" then
                    -- `@exec+` THAT xoa `exec_noop`: mot thu muc co CA hai nhan thi
                    -- cai SONG quyet dinh. Thieu dong `= nil` nay thi `@exec+` den SAU
                    -- `@exec+:noop` van tra `execcgi_noop` — tuc bao NHE hon su that.
                    flag = flag or {}; flag.exec = true; flag.exec_noop = nil
                elseif e == "@exec+:noop" then
                    -- CHI dat `noop` khi chua co `@exec+` thuc nao. `or` o day giu
                    -- nguyen co SONG neu no da duoc dat o tang gan hon.
                    flag = flag or {}
                    if flag.exec ~= true or flag.exec_noop then flag.exec_noop = true end
                    flag.exec = true
                elseif e == "@exec-" then
                    flag = flag or {}; flag.exec = false
                elseif e == "@php" then
                    flag = flag or {}; flag.php = true
                elseif e == "-@php" then
                    -- `auto_prepend_file=none` TAT TUONG MINH. `false` chu khong `nil`:
                    -- `nil` de tang XA hon ghi vao sau do (vong duyet di tu goc xuong),
                    -- tuc mot thu muc con tat autoload khong rut lai duoc cua cha.
                    flag = flag or {}; flag.php = false
                elseif e == "@phpini" or e == "-@phpini" then
                    -- `@phpini` KHONG ke thua: pham vi cua `php.ini` di theo chuoi tim
                    -- cau hinh cua SAPI/CWD, khong mac nhien theo thu muc. Chi nhan khi
                    -- no o CHINH thu muc cua request (`i == 1`).
                    if i == 1 then
                        flag = flag or {}; flag.phpini = (e == "@phpini")
                    end

                end
            end
        end
    end
    if not h and not t and not flag then return nil end

    -- ── PRECEDENCE, khong phai phep HOAC ─────────────────────────────
    --
    -- Apache quyet dinh handler cua mot tep theo THU TU UU TIEN, va day la thu tu do
    -- (mod_mime + mod_dir, doc tu tai lieu):
    --
    --   1. `SetHandler`      dat handler cho CA thu muc, GHI DE moi thu duoi.
    --   2. `AddHandler <e>`  dat handler cho mot duoi, GHI DE content type.
    --   3. `ForceType`       dat content type cho CA thu muc.
    --   4. `AddType <e>`     dat content type cho mot duoi.
    --
    -- Content type chi tro thanh "chay duoc" khi KHONG co handler nao — do la co che
    -- `AddType application/x-httpd-php .php` cu. Nen muc 3-4 chi duoc xet SAU khi muc
    -- 1-2 khong co phat bieu nao.
    --
    -- Ban truoc gop ca bon thanh `hit_all` / `hit_ext` roi OR lai, nen:
    --   · `SetHandler none` o con khong rut lai `AddHandler php` cua cha  (FN)
    --   · `AddHandler default-handler` o con khong rut lai `AddType php` cua cha (FP)
    -- Hai ca do la ca2/ca3 cua review, va luoi nhom 29 do chung tren duong day-du.
    --
    -- `nil` o moi muc = "chua ai noi gi" -> ROI XUONG muc sau. `false` = TAT TUONG
    -- MINH -> DUNG LAI, khong roi xuong. Day la toan bo ly do phai co ba trang thai.
    local hd = nil                    -- handler hieu luc: nil/true/false
    local qua_duoi = false            -- handler nay den tu MOT DUOI hay ca thu muc

    -- ── HAI QUY TAC, doc tu tai lieu Apache ──────────────────────────
    --
    -- mod_mime, "Files with Multiple Extensions":
    --   "If more than one extension is given that maps onto the same type of metadata,
    --    then the one to the right will be used, except for languages and content
    --    encodings."
    --   "Care should be taken when a file with multiple extensions gets associated with
    --    both a media-type and a handler. This will usually result in the request being
    --    handled by the module associated with the handler."
    --
    -- Hai cau KHONG mau thuan va chung cho hai quy tac KHAC nhau:
    --   1. TRONG cung mot truc: duoi BEN PHAI thang.
    --   2. GIUA cac truc: handler thang media-type.
    --
    -- Ban truoc duyet `sufs` nhu mot TAP va cho `true` thang moi `false`, nen
    --     AddHandler php .php
    --     AddHandler default-handler .jpg
    -- tren `shell.php.jpg` tra `handler_ext` — SAI, vi ca hai dong deu la truc HANDLER
    -- va `.jpg` o ben phai. Day la FP, va toi da BAC BO diem nay mot lan truoc bang mot
    -- lap luan ve `AddType`/`AddLanguage` — lap luan do khong ap cho hai `AddHandler`.
    --
    -- Nhung `AddHandler php .php` + `AddType image/jpeg .jpg` thi VAN chay PHP: hai
    -- truc KHAC nhau, va quy tac 2 cho handler thang. Lo hong upload co dien van bi bat.

    -- `trang_thai_phai_sang_trai`: duyet `sufs` tu PHAI sang TRAI, lay phat bieu DAU
    -- TIEN gap tren truc do. `nil` = truc nay khong noi gi ve bat ky duoi nao cua tep.
    -- `duoi_hieu_luc`: duyet `sufs` tu PHAI sang TRAI, lay phat bieu dau tien gap tren
    -- truc do.
    --
    -- `"reset"` KHONG dung lai o day — no BO QUA duoi do va di tiep sang duoi BEN TRAI
    -- trong CUNG truc. `RemoveHandler .jpg` noi "duoi .jpg khong con handler mapping";
    -- no khong noi gi ve `.php`, nen mot `AddHandler php .php` con hieu luc VAN lam
    -- `shell.php.jpg` chay. Do 04-10:
    --     h+:php + h0:jpg, shell.php.jpg -> `nil`   (dung phai `handler_ext`)
    -- Ban truoc `return s` ke ca khi `s == "reset"`, nen reducer roi xuong truc TYPE
    -- thay vi tim tiep trong truc HANDLER. FN, va ten tep do nguoi gui quyet dinh.
    --
    -- Chi khi het suffix ma chua gap `true`/`false` thi moi roi xuong truc thap hon —
    -- va luc do `nil` tra ve chinh la tin hieu "truc nay khong noi gi".
    local function duoi_hieu_luc(bang)
        if not bang or not sufs then return nil end
        for i = #sufs, 1, -1 do
            local s = bang[sufs[i]]
            if s ~= nil and s ~= "reset" then return s end
        end
        return nil
    end

    -- Muc 1: `SetHandler` — ca thu muc, uu tien cao nhat.
    if flag and flag.sh ~= nil and flag.sh ~= "reset" then hd = flag.sh end

    -- Muc 2: `AddHandler` theo duoi — duoi BEN PHAI thang (quy tac 1).
    if hd == nil then
        local s = duoi_hieu_luc(h)
        -- `"reset"` KHONG dung lai: `RemoveHandler` go mapping, nen Apache duoc phep
        -- roi xuong content type. `false` (explicit-safe) thi DUNG.
        if s ~= nil and s ~= "reset" then hd = s; qua_duoi = true end
    end

    -- Muc 3: `ForceType` — ca thu muc, chi khi KHONG co handler nao phat bieu.
    if hd == nil and flag and flag.ft ~= nil and flag.ft ~= "reset" then hd = flag.ft end

    -- Muc 4: `AddType` theo duoi — thap nhat, cung quy tac phai-sang-trai.
    if hd == nil then
        local s = duoi_hieu_luc(t)
        if s ~= nil and s ~= "reset" then hd = s; qua_duoi = true end
    end

    -- ── NHAN: pham vi cua phat bieu THANG quyet dinh nhan ────────────
    --
    -- `handler_all` khi handler ap CA thu muc (`SetHandler`/`ForceType`) va
    -- `handler_ext` khi no den tu mot duoi. Phan biet nay di thang vao `matched=` cua
    -- waf.log, nen phai dung: `handler_all` nghia la MOI tep trong thu muc chay duoc,
    -- ke ca `shell.jpg` — manh hon han `handler_ext`.
    -- `:cut` = chuoi to tien BI CAT o tran 12 tang, nen ket luan nay doc tu mot tap
    -- khoa KHONG day du. Nhan di thang vao `matched=` cua waf.log, nen hau to la cach
    -- re nhat de dem duoc bao nhieu lan dieu do xay ra that — khong them rule, khong
    -- them signal.
    local hau = (depth_cut and ":cut" or "") .. (pi_doan and "?pi" or "")
    if hd then
        if qua_duoi then return "handler_ext" .. hau end
        return "handler_all" .. hau
    end

    -- `hd == false` la TAT TUONG MINH. Cac truc autoload/ExecCGI o duoi la truc KHAC
    -- (chung khong dat handler), nen van phai xet — mot `SetHandler none` khong tat
    -- `auto_prepend_file`.

    -- Autoload: chi co nghia voi script PHP, nen rang buoc `PHP_EXT` o doan CUOI.
    if ext and upload.PHP_EXT[ext] then
        -- `.user.ini` truoc `php.ini`: pham vi cua no CHAC CHAN hon (co che
        -- per-directory chuan cua CGI/FastCGI), con `php.ini` di theo chuoi tim cau
        -- hinh cua SAPI/CWD nen chua chac ap cho thu muc nay.
        if flag and flag.php    then return "autoload_userini" .. hau end
        if flag and flag.phpini then return "autoload_phpini"  .. hau end
    end

    if flag and flag.exec then
        -- `Options +ExecCGI` CHI cap quyen chay CGI; no KHONG noi tep nao la CGI. Mot
        -- minh no chua lam gi chay duoc, nen bao RIENG va NHE hon.
        --
        -- `:noop` = `AllowOverride` cua webserver KHONG cho `.htaccess` dat `ExecCGI`,
        -- nen dong do khong cap duoc gi. Ghi nhan chu khong bao — xem `fim.sh`.
        if flag.exec_noop then return "execcgi_noop" .. hau end
        return "execcgi_only" .. hau
    end
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

    local cfg_mark = fim_config_active(request.uri, rt)
    if cfg_mark then
        policy.emit(state, "fim_config_active", {
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
