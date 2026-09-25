local _M = {}

-- Configuration is deliberately plain Lua.  It is compiled once per worker by
-- waf.init.configure(), then resolved per host from a small in-worker cache.
-- No request is allowed to mutate DEFAULT.
local DEFAULT = {
    version = "2.0",

    -- observe: collect facts only
    -- shadow:  compute would_action but never terminate a request
    -- enforce: enforce rules whose own mode is also "enforce"
    mode = "enforce",

    profiles = {
        generic   = true,
        wordpress = true,
    },

    -- Score enforcement is intentionally off initially.  Existing hard
    -- invariants still block; ambiguous rules and correlations must earn an
    -- evidence base in shadow mode first.
    score_enforcement = false,
    threshold_mode    = "shadow",
    thresholds = {
        block = 100,
    },

    rules        = {},
    families     = {},
    correlations = {},
    exceptions   = {},
    domains      = {},

    telemetry = {
        enabled       = true,
        shared_dict   = "antibot_cache",
        prefix        = "waf:v2:",
        per_host      = false,
        host_limit    = 96,
    },
}

local function copy(value, seen)
    if type(value) ~= "table" then return value end
    seen = seen or {}
    if seen[value] then return seen[value] end
    local out = {}
    seen[value] = out
    for k, v in pairs(value) do out[copy(k, seen)] = copy(v, seen) end
    return out
end

local function merge(dst, src)
    if type(src) ~= "table" then return dst end
    for k, v in pairs(src) do
        if k ~= "domains" and k ~= "exceptions" then
            if type(v) == "table" and type(dst[k]) == "table" then
                merge(dst[k], v)
            else
                dst[k] = copy(v)
            end
        end
    end
    return dst
end

local function append(dst, src)
    if type(src) ~= "table" then return end
    for i = 1, #src do dst[#dst + 1] = copy(src[i]) end
end

local function clean_host(host)
    host = tostring(host or "-"):lower()
    -- ngx.var.host normally has no port, but tests and non-standard callers may.
    host = host:gsub("%.$", "")
    return host
end

local VALID_MODE = { observe = true, shadow = true, enforce = true }
local VALID_ACTION = { observe = true, signal = true, block = true }

-- ── DANH SACH KHOA DUOC PHEP, va vi sao no bat buoc ──────────────────────────
--
-- Ban dau validator chi kiem GIA TRI cua khoa no biet, va bo qua khoa la trong
-- im lang. Hau qua khong phai "cau hinh khong an" — la "cau hinh trong nhu da
-- an". Bon ca that, do review 25-09 tim ra:
--
--   mod = "shadow"            -> he thong giu mode = "enforce"
--   mdoe = "shadow"           -> rule override khong co hieu luc
--   wordpres = false          -> profile WordPress van bat
--   uri_prefx = "/admin/"     -> exception KHONG con rang buoc URI nao ca,
--                                tuc no ap cho TOAN BO luat tren host do
--
-- Ca thu tu la nguy hiem nhat va nguy hiem theo chieu NGUOC voi ba cai kia: ba
-- cai dau lam cau hinh KHONG duoc ap (an toan hon y muon), cai thu tu lam
-- exception RONG HON y muon. Mot go sai chinh ta mo mot lo tren WAF.
--
-- Nen tu day: khoa la = LOI, o moi scope. Day la lua chon fail-loud co chu y —
-- `configure()` tra `false` va giu cau hinh cu, chu khong im lang chay tiep.
local SCOPE_KEYS = {
    version = true, mode = true, profiles = true,
    score_enforcement = true, threshold_mode = true, thresholds = true,
    rules = true, families = true, correlations = true, exceptions = true,
    domains = true, telemetry = true,
    -- `host` do `resolve()` gan vao ban da resolve. `validate()` chay tren ban
    -- COMPILE nen thuong khong thay, nhung chap nhan de goi validate tren mot
    -- ban resolved khong bao loi oan.
    host = true,
}
local OVERRIDE_KEYS = {
    mode = true, action = true, enabled = true, score = true,
}
local EXCEPTION_KEYS = {
    id = true, rule = true, family = true, host = true, method = true,
    target = true, uri = true, uri_prefix = true, enabled = true,
}
local TELEMETRY_KEYS = {
    enabled = true, shared_dict = true, prefix = true, per_host = true,
    host_limit = true,
}
local THRESHOLD_KEYS = { block = true }

-- Tap `profiles` hop le lay TU REGISTRY chu khong hardcode: neu mai them mot
-- profile thi cho nay tu biet, va nguoc lai `profiles.wordpres = false` bi bat
-- ngay. Nap trong pcall vi `config.lua` phai nap duoc doc lap trong test.
local VALID_PROFILE = { generic = true, wordpress = true }
do
    local ok, registry = pcall(require, "antibot.waf.registry")
    if ok and registry and registry.all then
        local found = {}
        for _, rule in pairs(registry.all()) do
            if rule.profile then found[rule.profile] = true end
        end
        if next(found) then VALID_PROFILE = found end
    end
end

-- Ho luat hop le, cung lay tu registry nhu `VALID_PROFILE`. `pcall` vi
-- `config.lua` phai nap duoc doc lap trong test; khi khong nap duoc thi ham tra
-- `true` (khong chan) chu khong tra `false` (chan het) — mot validator hong khong
-- duoc bien thanh mot validator tu choi moi thu.
-- Khoa giu ban raw trong bang da compile.
--
-- PHAI la CHUOI, khong duoc la bang: `copy()` lam `out[copy(k, seen)] = ...` nen
-- mot khoa bang bi SAO CHEP thanh bang moi, va `resolve()` (goi `copy(compiled)`)
-- se tra ve mot bang khong con khoa nao bang `RAW_KEY` — `validate()` tren ban
-- resolved thay `nil` va bo qua luot kiem raw TRONG IM LANG. Da can nhac cach
-- dung bang lam khoa va bo vi dung ly do do.
--
-- Ten co dau `__` va duoc khai bao trong `SCOPE_KEYS`, nen `reject_unknown`
-- khong bao chinh no la khoa la.
local RAW_KEY = "__raw"

local function registry_has_family(name)
    local ok, registry = pcall(require, "antibot.waf.registry")
    if not (ok and registry and registry.has_family) then return true end
    return registry.has_family(name) and true or false
end

local function reject_unknown(tbl, allowed, path, errors, what)
    for k in pairs(tbl) do
        -- `RAW_KEY` bi bo qua o day chu KHONG duoc dua vao `SCOPE_KEYS`. Neu dua
        -- vao thi no thanh mot khoa HOP LE cho nguoi viet cau hinh, va mot
        -- `__raw = {...}` trong mot domain scope se duoc `merge` GHI DE len ban
        -- raw that — tuc luot kiem raw doc mot ban do ke viet cau hinh chon. Bo
        -- qua o day thi no khong bao loi oan cho khoa do `compile()` dat, ma van
        -- khong mo duong cho ai go no vao.
        if k ~= RAW_KEY and not allowed[k] then
            errors[#errors + 1] = string.format(
                "%s.%s la khoa KHONG duoc biet (%s) — go sai chinh ta?",
                path, tostring(k), what)
        end
    end
end

local function validate_scope(scope, path, errors, allow_domains)
    if type(scope) ~= "table" then
        errors[#errors + 1] = path .. " must be a table"
        return
    end
    reject_unknown(scope, SCOPE_KEYS, path, errors, "scope")
    if scope.mode ~= nil and not VALID_MODE[scope.mode] then
        errors[#errors + 1] = path .. ".mode is invalid"
    end
    if scope.threshold_mode ~= nil and not VALID_MODE[scope.threshold_mode] then
        errors[#errors + 1] = path .. ".threshold_mode is invalid"
    end
    if scope.score_enforcement ~= nil and type(scope.score_enforcement) ~= "boolean" then
        errors[#errors + 1] = path .. ".score_enforcement must be boolean"
    end
    if scope.telemetry ~= nil then
        if type(scope.telemetry) ~= "table" then
            errors[#errors + 1] = path .. ".telemetry must be a table"
        else
            reject_unknown(scope.telemetry, TELEMETRY_KEYS,
                           path .. ".telemetry", errors, "telemetry")
            if scope.telemetry.host_limit ~= nil and
               (type(scope.telemetry.host_limit) ~= "number" or
                scope.telemetry.host_limit < 0) then
                errors[#errors + 1] = path ..
                    ".telemetry.host_limit must be a non-negative number"
            end
            if scope.telemetry.enabled ~= nil and
               type(scope.telemetry.enabled) ~= "boolean" then
                errors[#errors + 1] = path .. ".telemetry.enabled must be boolean"
            end
            for _, field in ipairs({ "shared_dict", "prefix" }) do
                if scope.telemetry[field] ~= nil and
                   type(scope.telemetry[field]) ~= "string" then
                    errors[#errors + 1] = path .. ".telemetry." .. field ..
                                          " must be a string"
                end
            end
            if scope.telemetry.per_host ~= nil and
               type(scope.telemetry.per_host) ~= "boolean" then
                errors[#errors + 1] = path .. ".telemetry.per_host must be boolean"
            end
        end
    end
    if scope.thresholds ~= nil then
        if type(scope.thresholds) ~= "table" then
            errors[#errors + 1] = path .. ".thresholds must be a table"
        else
            reject_unknown(scope.thresholds, THRESHOLD_KEYS,
                           path .. ".thresholds", errors, "thresholds")
            if type(scope.thresholds.block) ~= "number" or
               scope.thresholds.block < 0 then
                errors[#errors + 1] = path .. ".thresholds.block must be non-negative"
            end
        end
    end
    if scope.profiles ~= nil then
        if type(scope.profiles) ~= "table" then
            errors[#errors + 1] = path .. ".profiles must be a table"
        else
            for profile, enabled in pairs(scope.profiles) do
                if not VALID_PROFILE[profile] then
                    errors[#errors + 1] = path .. ".profiles." ..
                        tostring(profile) .. " la profile KHONG ton tai trong" ..
                        " registry — `wordpres = false` se khong tat gi ca"
                end
                if type(enabled) ~= "boolean" then
                    errors[#errors + 1] = path .. ".profiles." .. tostring(profile) ..
                                          " must be boolean"
                end
            end
        end
    end
    for _, section_name in ipairs({ "rules", "families", "correlations" }) do
        local section = scope[section_name]
        if section ~= nil then
            if type(section) ~= "table" then
                errors[#errors + 1] = path .. "." .. section_name .. " must be a table"
            else
                for id, override in pairs(section) do
                    local item = path .. "." .. section_name .. "." .. tostring(id)
                    if type(override) ~= "table" then
                        errors[#errors + 1] = item .. " must be a table"
                    else
                        reject_unknown(override, OVERRIDE_KEYS, item, errors,
                                       section_name .. " override")
                        if override.mode ~= nil and not VALID_MODE[override.mode] then
                            errors[#errors + 1] = item .. ".mode is invalid"
                        end
                        if override.action ~= nil and not VALID_ACTION[override.action] then
                            errors[#errors + 1] = item .. ".action is invalid"
                        end
                        if override.enabled ~= nil and type(override.enabled) ~= "boolean" then
                            errors[#errors + 1] = item .. ".enabled must be boolean"
                        end
                        if override.score ~= nil and
                           (type(override.score) ~= "number" or override.score < 0) then
                            errors[#errors + 1] = item .. ".score must be non-negative"
                        end
                    end
                end
            end
        end
    end
    if scope.exceptions ~= nil then
        if type(scope.exceptions) ~= "table" then
            errors[#errors + 1] = path .. ".exceptions must be an array"
        else
            for i = 1, #scope.exceptions do
                local ex = scope.exceptions[i]
                if type(ex) ~= "table" then
                    errors[#errors + 1] = path .. ".exceptions." .. i ..
                                          " must be a table"
                else
                    -- Go sai o exception la ca duy nhat lam WAF YEU DI chu
                    -- khong phai chi "khong co hieu luc": `uri_prefx` bi bo qua
                    -- nghia la exception mat rang buoc URI va ap cho moi luat.
                    reject_unknown(ex, EXCEPTION_KEYS,
                                   path .. ".exceptions." .. i, errors,
                                   "exception")
                    for _, field in ipairs({
                        "id", "rule", "family", "host", "method", "target",
                        "uri", "uri_prefix",
                    }) do
                        if ex[field] ~= nil and type(ex[field]) ~= "string" then
                            errors[#errors + 1] = path .. ".exceptions." .. i ..
                                "." .. field .. " must be a string"
                        end
                    end
                    if ex.enabled ~= nil and type(ex.enabled) ~= "boolean" then
                        errors[#errors + 1] = path .. ".exceptions." .. i ..
                                              ".enabled must be boolean"
                    end
                    -- `family` phai TON TAI trong registry. Mot ho viet sai
                    -- (`expsure`) lam `exception_matches` so no voi moi
                    -- `rule.family` va khong bao gio khop — exception im lang
                    -- khong co tac dung, va nguoi van hanh tuong da co.
                    if ex.family ~= nil and type(ex.family) == "string" and
                       not registry_has_family(ex.family) then
                        errors[#errors + 1] = path .. ".exceptions." .. i ..
                            ".family = " .. ex.family ..
                            " KHONG ton tai trong registry"
                    end
                    -- PHAI co it nhat mot SELECTOR. `id` chi la ten de truy
                    -- nguoc trong log, no khong loc gi ca — nen mot exception
                    -- chi co `id` se khop MOI luat tren MOI host. Do la cach de
                    -- nhat de tat toan bo WAF bang mot dong trong nhu vo hai, va
                    -- cung ho voi lo `uri_prefx` da chan o tren.
                    do
                        local has = false
                        for _, sel in ipairs({ "rule", "family", "host",
                                               "method", "target", "uri",
                                               "uri_prefix" }) do
                            if ex[sel] ~= nil then has = true; break end
                        end
                        if not has then
                            errors[#errors + 1] = path .. ".exceptions." .. i ..
                                " khong co selector nao (rule/family/host/" ..
                                "method/target/uri/uri_prefix) — no se khop MOI" ..
                                " luat; `id` khong phai selector"
                        end
                    end
                end
            end
        end
    end
    -- `domains` trong mot domain scope: allowlist chap nhan khoa nay (vi
    -- SCOPE_KEYS dung chung cho ca hai cap) nhung `resolve()` KHONG BAO GIO doc
    -- no. Neu khong bao thi mot cau hinh long hai cap trong nhu da ap.
    if not allow_domains and scope.domains ~= nil then
        errors[#errors + 1] = path .. ".domains khong duoc long trong mot domain" ..
            " scope — `resolve()` chi doc `domains` o cap goc"
    end
    if allow_domains and scope.domains ~= nil then
        if type(scope.domains) ~= "table" then
            errors[#errors + 1] = path .. ".domains must be a table"
        else
            for host, domain in pairs(scope.domains) do
                validate_scope(domain, path .. ".domains." .. tostring(host), errors, false)
            end
        end
    end
end

-- Kiem cac truong mà `compile()` NORMALIZE, tuc nhung truong bi bien dang truoc
-- khi `validate_scope` kip nhin thay.
--
-- Lo that: `compile()` lam `out.exceptions = {}` roi `append(...)`, va `append`
-- BO QUA gia tri khong phai table. Nen `exceptions = "invalid"` bien thanh `{}`
-- va vuot qua validator — fail-silent o dung cho toi vua lam fail-loud. Cung the
-- voi `exceptions` thua (`{ [1] = ..., [3] = ... }`): `#src` dung o phan tu nil
-- dau tien nen phan tu thu 3 bi bo, im lang.
local function validate_raw(runtime, errors)
    if runtime == nil then return end
    if type(runtime) ~= "table" then
        errors[#errors + 1] = "config must be a table"
        return
    end

    local function check_exceptions(src, path)
        if src == nil then return end
        if type(src) ~= "table" then
            errors[#errors + 1] = path .. " must be an array, got " .. type(src)
            return
        end
        -- Dem khoa so de bat mang THUA. `#src` khong noi duoc dieu nay: voi
        -- `{ [1]=a, [3]=b }` thi `#src` co the la 1, va phan tu thu 3 bi `append`
        -- bo lai ma khong ai bao.
        local max_index, count = 0, 0
        for k in pairs(src) do
            if type(k) == "number" and k == math.floor(k) and k >= 1 then
                count = count + 1
                if k > max_index then max_index = k end
            else
                errors[#errors + 1] = path .. " co khoa khong phai chi so mang: " ..
                                      tostring(k)
            end
        end
        if max_index ~= count then
            errors[#errors + 1] = string.format(
                "%s la mang THUA (%d phan tu, chi so lon nhat %d) — `append()` se" ..
                " bo cac phan tu sau lo trong", path, count, max_index)
        end
    end

    check_exceptions(runtime.exceptions, "config.exceptions")
    if type(runtime.domains) == "table" then
        for host, domain in pairs(runtime.domains) do
            if type(domain) == "table" then
                check_exceptions(domain.exceptions,
                    "config.domains." .. tostring(host) .. ".exceptions")
            end
        end
    end
end

-- HAI LUOT, co y, va thu tu quan trong:
--   `validate_raw`  doc ban NGUOI VAN HANH VIET, truoc khi `compile` chuan hoa.
--   `validate_scope` doc ban DA compile, noi moi truong da co gia tri mac dinh.
-- Chi luot thu hai thi bo sot dung cac truong bi normalize lam mat dau vet.
function _M.validate(compiled)
    local errors = {}
    -- DA CAN NHAC va bo: thiet ke `validate(compiled, runtime)`. No trong sach hon
    -- nhung lam CHIN noi goi hien co VAN CHAY trong khi bo qua luot kiem moi —
    -- mot tham so tuy chon khong bao gio bat ai them no vao. Giu chu ky mot tham
    -- so de moi noi goi, ke ca noi viet truoc ban nay, tu dong duoc ca hai luot.
    validate_raw(type(compiled) == "table" and compiled[RAW_KEY] or nil, errors)
    validate_scope(compiled, "config", errors, true)
    return #errors == 0, errors
end

function _M.compile(runtime)
    local out = copy(DEFAULT)
    runtime = type(runtime) == "table" and runtime or {}
    merge(out, runtime)
    if runtime.domains == nil then
        out.domains = {}
    elseif type(runtime.domains) ~= "table" then
        out.domains = runtime.domains -- kept so validate() can reject it
    else
        out.domains = {}
        for host, domain in pairs(runtime.domains) do
            out.domains[clean_host(host)] = copy(domain)
        end
    end
    out.exceptions = {}
    append(out.exceptions, DEFAULT.exceptions)
    append(out.exceptions, runtime.exceptions)
    -- Giu ban NGUOI VAN HANH VIET de `validate()` kiem duoc nhung truong ma chinh
    -- `compile()` vua chuan hoa: `exceptions = "invalid"` da thanh `{}` o tren, va
    -- mot mang thua da bi `append` cat bot — ca hai khong con dau vet trong `out`.
    out[RAW_KEY] = runtime
    return out
end

function _M.resolve(compiled, host)
    compiled = compiled or _M.compile()
    host = clean_host(host)

    local out = copy(compiled)
    local domains = compiled.domains or {}
    local domain = domains[host]
    if type(domain) == "table" then
        merge(out, domain)
        out.exceptions = {}
        append(out.exceptions, compiled.exceptions)
        append(out.exceptions, domain.exceptions)
    end
    out.domains = nil
    out.host = host
    return out
end

function _M.host(host)
    return clean_host(host)
end

function _M.defaults()
    return copy(DEFAULT)
end

_M.copy = copy
_M.merge = merge

return _M
