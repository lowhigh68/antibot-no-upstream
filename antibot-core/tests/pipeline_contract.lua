-- Contract test cho root orchestration (`antibot-core/init.lua`).
-- Tat ca dependency duoc thay bang spy nho de ghim thu tu admission/WAF,
-- trust fast-path, capacity slot va log-phase release.

local pass, fail = 0, 0

local function ok(cond, name)
    if cond then pass = pass + 1 else
        fail = fail + 1
        io.stderr:write("FAIL: ", name, "\n")
    end
end

local function eq(got, want, name)
    ok(got == want, name .. " (got=" .. tostring(got)
        .. " want=" .. tostring(want) .. ")")
end

local scenario, events, counts, worker_id
local function event(name) events[#events + 1] = name end
local function event_count(name)
    local n = 0
    for i = 1, #events do if events[i] == name then n = n + 1 end end
    return n
end
local function event_pos(name)
    for i = 1, #events do if events[i] == name then return i end end
end
local function before(a, b, name)
    local pa, pb = event_pos(a), event_pos(b)
    ok(pa ~= nil and pb ~= nil and pa < pb, name)
end
local function exit_for(name) return scenario.exit_at == name end
local function layer(name, method, hook)
    local t = {}
    t[method or "run"] = function(ctx)
        event(name)
        if hook then hook(ctx) end
        return true, exit_for(name)
    end
    return t
end

-- Root dependencies. Loading init.lua below binds only these spies, never
-- Redis/DNS/filesystem.
package.loaded["antibot.core.decision"] = {
    initialize = function(ctx) event("decision.initialize") end,
    finalize_upstream = function(ctx)
        event("decision.finalize")
        if ctx.decision_upstream_reached == nil then
            ctx.decision_upstream_reached = false
        end
    end,
    set = function() return true end,
}
package.loaded["antibot.core.secrets"] = {
    load = function() return { schema_version = 1 } end,
}
package.loaded["antibot.core.ctx"] = layer("ctx.init", "init", function(ctx)
    ctx.ip = "203.0.113.10"
    ctx.ua = ngx.var.http_user_agent or ""
    ctx.req = { uri = ngx.var.uri or "/", host = ngx.var.host or "example.test" }
end)
package.loaded["antibot.core.req_classifier"] = {
    run_fast = function(ctx)
        event("classifier.fast")
        ctx.req_class = scenario.class or "navigation"
        ctx.admission_group = scenario.group
            or (ctx.req_class == "resource" and "resource" or "dynamic")
        return true, false
    end,
    run = function() event("classifier.full"); return true, false end,
}
package.loaded["antibot.core.proxy_origin"] = layer("proxy", "run")
package.loaded["antibot.core.session_richness"] = layer("richness", "run")
package.loaded["antibot.core.iprep"] = layer("iprep", "check")
package.loaded["antibot.core.fingerprint.asn"] = layer("asn", "run")
package.loaded["antibot.core.fingerprint.device_classifier"] = layer("device", "run")
package.loaded["antibot.core.access"] = {
    run = function(ctx)
        event("access")
        if scenario.whitelist then
            ctx.whitelisted = true
            ctx.action = "allow"
            ctx.action_reason = "ip_whitelist"
            return true, true
        end
        return true, false
    end,
}
package.loaded["antibot.core.fingerprint"] = layer(
    "fingerprint", "run", function(ctx)
        ctx.identity = ctx.identity or "identity-normal"
        ctx.fp_light = ctx.fp_light or ctx.identity
    end)
package.loaded["antibot.transport"] = layer("transport", "run")
package.loaded["antibot.l7"] = layer("l7", "run")
package.loaded["antibot.detection"] = layer("detection", "run", function(ctx)
    if scenario.cloud_automation then
        ctx.automation_tier = "cloud_automation"
        ctx.automation_principal = scenario.principal or "grokbot"
        ctx.automation_proof = "contact_cloud_ptr"
        ctx.automation_cloud_claimed = true
    end
end)
package.loaded["antibot.intelligence"] = layer("intelligence", "run")
package.loaded["antibot.enforcement"] = layer("enforcement", "run", function(ctx)
    if scenario.exit_at == "enforcement" then
        ctx.action = "block"
        ctx.action_reason = "test_block"
    end
end)

package.loaded["antibot.l7.admission"] = layer("admission", "run")
package.loaded["antibot.l7.automation_guard"] = {
    run = function(ctx)
        event("automation.guard")
        if scenario.operator then
            ctx.automation_observed = true
            ctx.automation_tier = "operator"
            ctx.automation_principal = scenario.principal or "gptbot"
            ctx.operator_network_verified = true
        end
        return true, exit_for("automation.guard")
    end,
    late_enforce = function()
        event("automation.late")
        return true, exit_for("automation.late")
    end,
}
package.loaded["antibot.l7.operator_concurrency"] = {
    admit = function(ctx)
        event("operator.admit")
        local operator_ok = ctx.automation_tier == "operator"
            and ctx.operator_network_verified == true
        local cloud_ok = ctx.automation_tier == "cloud_automation"
            and ctx.automation_proof == "contact_cloud_ptr"
            and ctx.automation_cloud_claimed == true
        if ngx.is_subrequest or not (operator_ok or cloud_ok) then
            return true, false
        end
        if not ctx.automation_concurrency_admitted then
            ctx.automation_concurrency_admitted = true
            counts.operator_admitted = counts.operator_admitted + 1
        end
        if scenario.exit_at == "operator.admit" then return false, true end
        return true, false
    end,
    after = function(ctx)
        event("operator.after")
        if ctx.automation_concurrency_admitted
           and not ctx.automation_concurrency_released then
            ctx.automation_concurrency_released = true
            counts.operator_released = counts.operator_released + 1
        end
    end,
}
package.loaded["antibot.l7.principal_churn"] = {
    before = function()
        event("principal.before")
        return true, exit_for("principal.before")
    end,
    admit = function()
        event("principal.admit")
        return true, exit_for("principal.admit")
    end,
}
package.loaded["antibot.l7.dynamic_guard"] = {
    before = function()
        event("dynamic.before")
        return true, exit_for("dynamic.before")
    end,
    admit = function(ctx)
        event("dynamic.admit")
        if ctx.admission_group ~= "dynamic" or ngx.is_subrequest then
            return true, false
        end
        if not ctx.dynamic_guard_admitted then
            ctx.dynamic_guard_admitted = true
            counts.dynamic_admitted = counts.dynamic_admitted + 1
        end
        if scenario.exit_at == "dynamic.admit" then return false, true end
        return true, false
    end,
    after = function(ctx)
        event("dynamic.after")
        if ctx.dynamic_guard_admitted and not ctx.dynamic_guard_released then
            ctx.dynamic_guard_released = true
            counts.dynamic_released = counts.dynamic_released + 1
        end
    end,
}
package.loaded["antibot.waf.endpoint_policy"] = {
    run = function(ctx)
        event("endpoint.policy")
        if scenario.endpoint then
            ctx.endpoint_id = scenario.endpoint
            ctx.endpoint_scope = "scope-test"
        end
        return true, false
    end,
}
package.loaded["antibot.l7.endpoint_guard"] = {
    before = function()
        event("endpoint.before")
        return true, exit_for("endpoint.before")
    end,
    admit = function(ctx)
        event("endpoint.admit")
        if ctx.endpoint_id and not ctx.endpoint_admitted then
            ctx.endpoint_admitted = true
            counts.endpoint_admitted = counts.endpoint_admitted + 1
        end
        if scenario.exit_at == "endpoint.admit" then return false, true end
        return true, false
    end,
    after = function(ctx)
        event("endpoint.after")
        if ctx.endpoint_admitted and not ctx.endpoint_released then
            ctx.endpoint_released = true
            counts.endpoint_released = counts.endpoint_released + 1
        end
    end,
}
package.loaded["antibot.l7.circuit_breaker"] = {
    before = function() event("circuit.before"); return true, exit_for("circuit.before") end,
    after = function() event("circuit.after") end,
}
package.loaded["antibot.l7.surge_guard"] = {
    before = function() event("surge.before"); return true, exit_for("surge.before") end,
    admit = function(ctx)
        event("surge.admit")
        if ctx.admission_group ~= "dynamic" or ngx.is_subrequest then
            return true, false
        end
        if not ctx.surge_admitted then
            ctx.surge_admitted = true
            counts.admitted = counts.admitted + 1
        end
        if scenario.exit_at == "surge.admit" then return false, true end
        return true, false
    end,
    after = function(ctx)
        event("surge.after")
        if ctx.surge_admitted and not ctx.surge_released then
            ctx.surge_released = true
            counts.released = counts.released + 1
        end
    end,
}

package.loaded["antibot.detection.fleet"] = {
    run = function() event("fleet.run"); return true, false end,
    aggregate = function() event("fleet.aggregate") end,
    start_timer = function() counts.fleet_timer = counts.fleet_timer + 1 end,
}
package.loaded["antibot.detection.fleet.check_block"] = layer("fleet.block", "run")
package.loaded["antibot.l7.ban.ip_ban_check"] = layer("ipban", "run")
package.loaded["antibot.detection.ip_tour"] = layer("iptour", "run")
package.loaded["antibot.l7.expensive_filter_guard"] = layer("xfilter", "run")
package.loaded["antibot.detection.bot.lite_verify"] = layer("bot.lite", "run")
package.loaded["antibot.l7.rate.res_ip_counter"] = layer("res.counter", "run")
package.loaded["antibot.async.risk_update"] = {
    run = function() counts.risk_calls = counts.risk_calls + 1 end,
}
package.loaded["antibot.async.intel_reporter"] = {
    report = function() counts.intel_reports = counts.intel_reports + 1 end,
}
package.loaded["antibot.async.logger"] = { run = function() event("logger") end }
package.loaded["antibot.async.waf_logger"] = {
    run = function() event("waf.logger") end,
    run_body = function() event("waf.bodylog") end,
    ensure = function() counts.waf_ensure = counts.waf_ensure + 1 end,
}
package.loaded["antibot.core.cookie_registry"] = {
    learn = function() event("cookie.learn") end,
}
package.loaded["antibot.async.memory_guard"] = {
    start = function() counts.memory_starts = counts.memory_starts + 1 end,
}
package.loaded["antibot.core.goodbot_seed"] = { run = function() end }
package.loaded["antibot.waf.runtime_config"] = {}
package.loaded["antibot.waf"] = {
    run_pre = function() event("waf.pre"); return scenario.waf_block == true end,
    run_log = function() event("waf.log") end,
    configure = function() return true end,
}
package.loaded["antibot.core.redis_pool"] = {
    safe_get = function(key)
        event("redis.get:" .. key)
        if scenario.verified_cookie and key == "verified:verified-cookie" then return "1" end
        return nil
    end,
    safe_set = function(key) event("redis.set:" .. key); return true end,
}

-- `core.access.verified_human` — resolver cua duong fast-path (`init.lua:33`).
--
-- PHAI co spy: bo kiem nay `loadfile` truc tiep `init.lua`, KHONG dat
-- `package.path` tro vao `antibot-core/`, nen MOI `require` trong root phai co
-- mot entry o `package.loaded`. Thieu mot cai thi ca bo kiem NO ngay o
-- `require` (`antibot.so not found`) chu khong fail mot assertion — tuc
-- `run.sh` tra rc=1 ma KHONG in dong ket qua nao.
--
-- Do la cach lo 14-10 xuat hien: `init.lua` them `require` module moi va danh
-- sach spy khong di theo. Mot bo kiem spy-based chi an toan khi hai danh sach
-- do cung nhip — `contract_test.lua` ghim dieu nay bang mot assertion rieng.
--
-- Spy giu DUNG hop dong cua ban that: `check_cookie(ctx, opts)` tra
-- `(true, cookie)` khi cookie da verified, `(false, reason)` khi khong; va dat
-- `ctx.verified`/`identity`/`fp_light`. Nhanh `crawler_claim` duoc mo phong
-- bang `scenario.bot_claim_ua` de root co the kiem rang mot UA tu nhan la
-- crawler KHONG di qua cua nguoi.
package.loaded["antibot.core.access.verified_human"] = {
    check_cookie = function(ctx, opts)
        event("verified_human.check")
        -- Nhan dien claim crawler TU UA, dung nhu ban that (`ua_claim`): cac ca
        -- test dat `scenario.ua = "Googlebot/2.1"` chu khong dat mot co rieng,
        -- vi do la cach request that mang bang chung — UA la thu duy nhat co.
        local ua = (ctx and ctx.ua) or ngx.var.http_user_agent or ""
        if ua:lower():find("bot", 1, true)
           or ua:lower():find("spider", 1, true)
           or ua:lower():find("crawler", 1, true) then
            if ctx then
                ctx.verified_human_rejected_bot_claim = true
                -- Giu dung thu tu ban that: co thu hai chi bat khi co cookie
                -- VA ve con hieu luc.
                local c = ngx.var.cookie_antibot_fp
                if c and c ~= "" and scenario.verified_cookie then
                    ctx.verified_human_bot_held_cookie = true
                end
            end
            return false, "crawler_claim"
        end
        local cookie = ngx.var.cookie_antibot_fp
        if not cookie or cookie == "" then return false, "missing" end
        if not scenario.verified_cookie then return false, "unverified" end
        ctx.verified = true
        ctx.identity = cookie
        ctx.fp_light = cookie
        if opts and opts.renew then event("verified_human.renew") end
        return true, cookie
    end,
}

ngx = {
    DEBUG = 0, INFO = 1, WARN = 2, ERR = 3, null = {},
    ctx = {}, var = {}, header = {}, is_subrequest = false,
    log = function() end,
    exit = function(code) counts.exit_code = code; return code end,
    time = function() return 1700000000 end,
    worker = { id = function() return worker_id end },
    timer = {
        at = function(_, fn, ...)
            counts.timer_at = counts.timer_at + 1
            fn(false, ...)
            return true
        end,
    },
    resp = { get_headers = function() return {} end },
}

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end
local root = assert(loadfile(src .. "init.lua"))()

local function reset(s)
    scenario = s or {}
    events = {}
    counts = {
        admitted = 0, released = 0, risk_calls = 0, intel_reports = 0,
        endpoint_admitted = 0, endpoint_released = 0,
        operator_admitted = 0, operator_released = 0,
        dynamic_admitted = 0, dynamic_released = 0,
        timer_at = 0, memory_starts = 0, fleet_timer = 0, waf_ensure = 0,
    }
    worker_id = 1
    ngx.ctx = {}
    ngx.header = {}
    ngx.is_subrequest = scenario.subrequest == true
    ngx.var = {
        uri = scenario.uri or "/index.php", host = "example.test",
        server_name = "example.test", remote_addr = "203.0.113.10",
        http_user_agent = scenario.ua or "Mozilla/5.0 Test",
        cookie_antibot_fp = scenario.verified_cookie and "verified-cookie" or nil,
    }
end

reset()
root.run()
eq(counts.admitted, 1, "dynamic thuong nhan dung mot slot")
eq(counts.dynamic_admitted, 1,
   "dynamic thuong nhan dung mot generic source/docroot slot")
eq(event_count("surge.admit"), 1, "dynamic thuong goi admit dung mot lan")
before("admission", "waf.pre", "admission chay truoc WAF")
before("automation.guard", "admission",
    "automation claim duoc do truoc moi admission fast-exit")
before("proxy", "principal.before",
    "principal churn chi gom source sau khi da xac dinh reverse proxy")
before("principal.before", "admission",
    "principal churn som chay truoc admission fast-exit")
before("admission", "endpoint.policy",
    "broad admission brake chay truoc endpoint overlay")
before("endpoint.before", "waf.pre",
    "endpoint early gate chay truoc WAF")
before("waf.pre", "access", "WAF chay truoc trust/access")
before("access", "detection", "access chay truoc detection")
before("enforcement", "surge.admit", "chi admit sau enforcement")
before("automation.late", "endpoint.admit",
    "cloud tier duoc pace muon truoc moi backend slot")
before("endpoint.admit", "surge.admit",
    "endpoint atomic gate chay truoc global surge accounting")
before("endpoint.admit", "operator.admit",
    "endpoint reject duoc xu ly truoc principal concurrency")
before("principal.admit", "dynamic.admit",
    "JA3 principal churn duoc cap nhat truoc generic backend slot")
before("dynamic.admit", "operator.admit",
    "generic source/docroot slot khong phu thuoc principal")
before("operator.admit", "surge.admit",
    "principal concurrency nam o late-admit truoc surge telemetry")

reset({ operator = true })
root.run()
eq(counts.operator_admitted, 1,
   "proven operator nhan mot principal slot truoc content")
eq(event_count("operator.admit"), 1,
   "operator admit chi chay mot lan moi request")
root.log()
root.log()
eq(counts.operator_released, 1,
   "operator slot release log phase dung mot lan")

reset({ operator = true, waf_block = true })
root.run()
eq(counts.operator_admitted, 0,
   "WAF block khong tieu principal backend slot")

reset({ operator = true, exit_at = "enforcement" })
root.run()
eq(counts.operator_admitted, 0,
   "enforcement block khong tieu principal backend slot")

reset({ operator = true, class = "resource", group = "resource" })
root.run()
eq(counts.operator_admitted, 1,
   "operator resource van vao principal slot, khong phu thuoc URI/class")

reset({ operator = true, subrequest = true })
root.run()
eq(counts.operator_admitted, 0,
   "operator subrequest khong bi dem lap")

reset({ cloud_automation = true })
root.run()
eq(counts.operator_admitted, 1,
   "cloud automation co PTR proof nhan concurrency slot")
before("detection", "automation.late",
   "cloud proof duoc tao truoc late enforcement")
before("automation.late", "operator.admit",
   "cloud rate gate chay truoc cloud concurrency")

reset({ cloud_automation = true, exit_at = "automation.late" })
root.run()
eq(counts.endpoint_admitted, 0,
   "cloud late-rate reject khong tieu endpoint slot")
eq(counts.operator_admitted, 0,
   "cloud late-rate reject khong tieu concurrency slot")
eq(counts.admitted, 0,
   "cloud late-rate reject khong toi surge/backend")

reset({ endpoint = "wp_oembed_embed" })
root.run()
eq(counts.endpoint_admitted, 1, "endpoint backend request nhan dung mot slot")
eq(event_count("endpoint.admit"), 1, "endpoint admit dung mot lan")
root.log()
root.log()
eq(counts.endpoint_released, 1, "endpoint slot release dung mot lan")

reset({ endpoint = "wp_oembed_embed", whitelist = true })
root.run()
eq(counts.endpoint_admitted, 1,
   "whitelist khong bypass endpoint capacity slot")

reset({ endpoint = "wp_oembed_embed", verified_cookie = true })
root.run()
eq(counts.endpoint_admitted, 1,
   "verified cookie khong bypass endpoint capacity slot")

reset({ whitelist = true })
root.run()
eq(ngx.ctx.antibot.action, "allow", "whitelist van allow")
eq(counts.admitted, 1, "whitelist dynamic van nhan capacity slot")
eq(event_count("surge.admit"), 1, "whitelist admit dung mot lan")
eq(event_count("iptour"), 0, "whitelist khong chay post-access detection")
eq(event_count("detection"), 0, "whitelist khong chay full detection")
before("access", "surge.admit", "whitelist chi admit sau access verdict")

reset({ verified_cookie = true })
root.run()
eq(counts.admitted, 1, "verified fast-path nhan mot slot")
eq(event_count("fleet.aggregate"), 1, "verified fast-path van nuoi fleet")
eq(event_count("classifier.full"), 0, "verified fast-path khong tra full classifier")
eq(event_count("access"), 0, "verified fast-path khong lap access lookup")
eq(event_count("detection"), 0, "verified fast-path khong chay detection")
before("waf.pre", "fleet.aggregate", "WAF chay truoc verified resolver")
before("fleet.aggregate", "surge.admit", "verified proof co truoc capacity admit")

reset({ verified_cookie = true, ua = "Googlebot/2.1" })
root.run()
ok(ngx.ctx.antibot.verified ~= true,
   "crawler claim khong duoc nhan verified-human cookie")
eq(ngx.ctx.antibot.verified_human_rejected_bot_claim, true,
   "crawler cookie rejection co provenance")
eq(event_count("fleet.aggregate"), 0,
   "crawler claim khong vao human fast-path fleet shortcut")
eq(event_count("classifier.full"), 1,
   "crawler claim quay ve full classifier")
eq(event_count("detection"), 1,
   "crawler claim di qua bot verification lane")
eq(counts.admitted, 1,
   "crawler claim chi nhan slot sau full enforcement")

reset({ waf_block = true })
root.run()
eq(counts.admitted, 0, "WAF block khong nhan slot")
eq(counts.dynamic_admitted, 0,
   "WAF block khong nhan generic backend slot")
eq(event_count("access"), 0, "WAF block khong vao trust pipeline")
reset({ endpoint = "wp_oembed_embed", waf_block = true })
root.run()
eq(counts.endpoint_admitted, 0,
   "WAF block endpoint khong tieu backend endpoint budget")
reset({ exit_at = "admission" })
root.run()
eq(counts.admitted, 0, "admission block khong nhan slot")
eq(event_count("waf.pre"), 0, "admission block dung truoc WAF")
reset({ exit_at = "enforcement" })
root.run()
eq(counts.admitted, 0, "enforcement block khong nhan slot")
eq(event_count("surge.admit"), 0, "enforcement exit khong goi admit")

reset({ class = "resource", group = "resource" })
root.run()
eq(counts.admitted, 0, "resource khong chiem dynamic slot")
eq(counts.dynamic_admitted, 0,
   "resource khong chiem generic dynamic slot")
reset({ subrequest = true })
root.run()
eq(counts.admitted, 0, "subrequest khong chiem dynamic slot")

reset()
root.run()
root.log()
root.log()
eq(counts.released, 1, "slot release dung mot lan du log bi goi lap")
eq(counts.dynamic_released, 1,
   "generic backend slot release dung mot lan du log bi goi lap")
eq(counts.risk_calls, 2, "moi log invocation goi risk_update dung mot lan")
eq(counts.timer_at, 0, "root khong tao timer boc ngoai risk_update")

reset()
worker_id = 1
root.init_worker()
eq(counts.memory_starts, 0, "worker khac 0 khong chay memory guard")
reset()
worker_id = 0
root.init_worker()
eq(counts.memory_starts, 1, "worker 0 chay memory guard dung mot lan")
eq(counts.fleet_timer, 1, "worker 0 van khoi dong fleet timer")

-- ── Gia tri SHIP THAT trong config.lua ──────────────────────────────
--
-- Moi bo test o tren deu dung config STUB, nen khong cai nao kiem gia tri
-- that se len may. Do duoc bang dot bien 18-10: doi `inflight_status` tu 503
-- sang 429 trong `config.lua` KHONG lam bo test nao do. Mot hang so chi ton
-- tai trong stub la mot hang so khong duoc bao ve.
--
-- Khoi nay chi pin nhung gi dot trien khai oEmbed 18-10 PHU THUOC. No co y
-- khong pin moi truong: them mot nguong vao day la bat nguoi sau phai sua
-- test moi lan tinh chinh, va do la cach bien test thanh vat can.
do
    for _, name in ipairs({
        "antibot.core.config",
        "antibot.waf.endpoint_policy",
        "antibot.l7.endpoint_guard",
        "antibot.l7.operator_concurrency",
    }) do package.loaded[name] = nil end

    local real = dofile(src .. "core/config.lua")
    local eg = real.endpoint_guard or {}
    local dg = real.dynamic_guard or {}
    local pc = real.principal_churn or {}
    local oembed = (eg.endpoints or {}).wp_oembed_embed or {}
    local proxy  = (eg.endpoints or {}).wp_oembed_proxy  or {}
    local html   = (eg.endpoints or {}).wp_html_pathinfo or {}
    local posts  = (eg.endpoints or {}).wp_rest_posts_item or {}
    local tags   = (eg.endpoints or {}).wp_rest_tags_read or {}
    local tag_archive = (eg.endpoints or {}).wp_tag_archive_suffix or {}

    eq(eg.enabled, true, "endpoint_guard bat trong config that")
    eq(eg.inflight_status, 503,
       "inflight reject dung 503 (suc chua), khong phai 429 (toc do)")
    eq(tonumber(eg.retry_after) ~= nil, true, "co Retry-After cho client lui lai")

    -- Production evidence first promoted narrow source/structural axes.  The
    -- broad pressure state may now enforce only through the late selective
    -- policy; reverting to an early blanket 503 is a deployment regression.
    eq(dg.enabled, true, "dynamic_guard generic duoc bat telemetry")
    eq((dg.tenant_client or {}).mode, "enforce",
       "docroot+IP concurrency duoc promote sau production evidence")
    eq((dg.tenant_client or {}).limit, 10,
       "docroot+IP concurrency giu khoang dem browser hop le")
    eq((dg.server_client or {}).mode, "enforce",
       "server+IP concurrency chan source trai qua nhieu tenant")
    eq((dg.server_client or {}).limit, 16,
       "server+IP concurrency giu tran production da do")
    eq((dg.path_spray or {}).mode, "enforce",
       "generic path spray duoc promote doc lap")
    eq((dg.path_spray or {}).min_hits, 12,
       "path spray can du hit truoc khi shed")
    eq((dg.path_spray or {}).min_paths, 8,
       "path spray can da dang path")
    eq((dg.path_spray or {}).min_costly, 2,
       "path spray can completed-cost evidence")
    eq((dg.uri_integrity or {}).mode, "enforce",
       "generic URI integrity enforce protocol invariant")
    eq((dg.pressure or {}).mode, "enforce",
       "backend pressure selective enforcement duoc bat")
    eq((dg.pressure or {}).policy, "cohort",
       "pressure chi shed cohort da tao chi phi")
    eq((dg.pressure or {}).min_samples, 12,
       "pressure cover workload it completion nhung rat dat")
    eq((dg.pressure or {}).work_seconds, 180.0,
       "pressure chi mo tren backend incident lon")
    eq((dg.pressure or {}).first_party_reserve, 4,
       "verified human co ngan sach song nho khi overload")
    eq((dg.pressure or {}).first_party_richness, 0.5,
       "cookie registry phai kem richness truoc khi uu tien")
    eq((dg.pressure or {}).cohort_min_samples, 3,
       "cohort can nhieu slow completion, khong phan quyet tu mot request")
    eq((dg.pressure or {}).cohort_work_seconds, 30.0,
       "cohort phai tu tao backend work dang ke")
    eq((dg.pressure or {}).cohort_min_share, 0.15,
       "cohort phai chiem ty trong incident du lon")
    eq((dg.aborted_pressure or {}).enabled, true,
       "499 occupancy duoc do rieng, khong tron completed pressure")
    eq((dg.aborted_pressure or {}).window, 10,
       "499 telemetry dung cung cua so doi chieu incident")
    eq((dg.server_pressure or {}).mode, "shadow",
       "whole-server pressure phai do production truoc enforce")
    eq((dg.server_pressure or {}).policy, "cohort",
       "whole-server pressure khong duoc blanket shed")
    eq((dg.server_pressure or {}).min_samples, 12,
       "whole-server observer giu floor mau bao thu")
    eq((dg.server_pressure or {}).work_seconds, 180.0,
       "whole-server observer giu work floor de do")
    eq(pc.mode, "enforce",
       "principal churn quarantine duoc promote sau production evidence")
    eq(pc.ip_threshold, 4, "principal churn IP threshold production")
    eq(pc.ja3_threshold, 3, "principal churn JA3 threshold production")

    -- Day la cong DANG CUU HE THONG. Neu ai do ha ve shadow thi phai co mot
    -- phep thu do, khong phai mot lan deploy im lang.
    eq((oembed.inflight or {}).mode, "enforce",
       "oEmbed concurrency ENFORCE — day la cong dang chan tai")
    eq((oembed.inflight or {}).limit, 3,
       "tran concurrency oEmbed = 3 tren moi docroot")

    -- Ba truc con lai PHAI con shadow: chung chua co bang chung FP.
    eq((oembed.rate or {}).mode, "shadow", "rate oEmbed van shadow")
    eq(oembed.shape_mode, "shadow", "shape oEmbed van shadow")
    eq(oembed.cross_host_mode, "shadow", "cross-host oEmbed van shadow")

    -- `wp_oembed_proxy` la duong WordPress editor/admin dung that. Enforce no
    -- la chan nguoi dang soan bai, nen no phai o shadow.
    eq((proxy.inflight or {}).mode, "shadow",
       "oEmbed proxy (editor WordPress) van shadow — khong chan admin")

    -- `.html/tel:` / `.html/sms:` is an exact malformed-shape rule proven by
    -- the incident log.  It must stay independent of the legitimate REST item
    -- rollout, which has only telemetry until fleet data exists.
    eq(html.shape_mode, "enforce", "WP html pathinfo ENFORCE generic")
    eq(html.shape_status, 404, "WP html pathinfo tra local 404")
    eq((html.rate or {}).mode, "off", "html pathinfo khong can rate counter")
    eq((html.inflight or {}).mode, "off", "html pathinfo khong lay backend slot")
    eq((posts.rate or {}).mode, "shadow", "wp/v2 posts item rate van shadow")
    eq((posts.inflight or {}).mode, "shadow", "wp/v2 posts item inflight shadow")
    eq((tags.rate or {}).mode, "shadow", "wp/v2 tags item rate van shadow")
    eq((tags.inflight or {}).mode, "shadow", "wp/v2 tags item inflight shadow")
    eq(((oembed.emergency or {}).mode), "enforce",
       "oEmbed public emergency ENFORCE de cuu backend")
    eq(((tags.emergency or {}).mode), "enforce",
       "wp/v2 tags read emergency ENFORCE de cuu backend")
    eq(((oembed.emergency or {}).retry_after), 300,
       "oEmbed emergency yeu cau crawler lui 300s")
    eq(((tags.emergency or {}).retry_after), 300,
       "tags emergency yeu cau crawler lui 300s")
    eq(((html.swarm or {}).mode), "shadow",
       "html pathinfo swarm chi gan nhan; shape da chan tu request dau")
    eq(((oembed.swarm or {}).mode), "shadow",
       "oEmbed route swarm do xuyen IP nhung emergency van la cong hien tai")
    eq(((tags.swarm or {}).mode), "shadow",
       "tags route swarm mac dinh shadow de khong them FP")
    eq(((posts.swarm or {}).mode), "shadow",
       "posts item route swarm mac dinh shadow")
    for name, endpoint in pairs({
        oembed = oembed, tags = tags, posts = posts, tag_archive = tag_archive,
    }) do
        eq(((endpoint.server_inflight or {}).mode), "shadow",
           name .. " server-inflight bat dau SHADOW")
        eq(((endpoint.server_inflight or {}).require_swarm), true,
           name .. " server-inflight phai co swarm gate")
        eq(((endpoint.server_inflight or {}).status), 503,
           name .. " server-inflight dung capacity status 503")
    end
    eq(tag_archive.shape_mode, "off",
       "tag archive custom rewrite khong bi shape block truc tiep")
    eq(((tag_archive.swarm or {}).mode), "shadow",
       "tag archive swarm chi do, khong block plugin/custom route")
    eq(((tag_archive.swarm or {}).scope), "server",
       "tag archive gom chien dich xuyen domain")
    eq(((html.swarm or {}).networks), 6,
       "route swarm can nhieu source-network, khong chi nhieu request")
    eq(((html.swarm or {}).requests), 12,
       "route swarm can dong thoi du request")
    eq(((html.swarm or {}).scope), "server",
       "route swarm khong bi nhan budget theo so domain")

    -- `automation_guard`: chi operator/contradicted bi chan. `unknown` la noi
    -- khach that bi phan loai nham roi vao; `verified` la Googlebot/Bingbot.
    local aut = real.automation or {}
    local tiers = aut.enforce_tiers or {}
    eq(aut.mode, "enforce", "automation_guard enforce")
    eq(tiers.operator, true, "operator tier bi chan")
    eq(tiers.cloud_automation, true,
       "cloud automation co bang chung duoc pace")
    local suspended = aut.suspended_principals or {}
    eq(suspended.gptbot, true,
       "GPTBot operator bi tam dung de tach nguyen nhan tai production")
    eq(suspended["oai-searchbot"], nil,
       "OAI-SearchBot khong bi dung cung GPTBot")
    eq(suspended["chatgpt-user"], nil,
       "ChatGPT-User khong bi dung cung GPTBot")
    eq(aut.suspend_status, 403,
       "suspension dung 403, tach nghia voi rate throttle 429")
    local conc = real.automation_concurrency or {}
    eq(conc.enabled, true, "operator concurrency bat telemetry")
    eq(conc.mode, "shadow",
       "operator concurrency rollout SHADOW, chua mo GPTBot")
    eq(conc.limit, 3, "operator concurrency shadow candidate N=3")
    eq(((conc.principals or {}).gptbot or {}).mode, "shadow",
       "GPTBot concurrency chua enforce khi suspension con bat")
    eq(((conc.principals or {}).gptbot or {}).limit, 3,
       "GPTBot dung mot pool ba slot tren toan may")
    local cloud_conc = (conc.tiers or {}).cloud_automation or {}
    eq(cloud_conc.mode, "enforce",
       "cloud automation concurrency enforce tu production evidence")
    eq(cloud_conc.limit, 3,
       "cloud principal co ba slot toan may")
    eq(cloud_conc.source_limit, 3,
       "cloud source co ba slot, khong ne bang doi principal")
    local verified_aggressive =
        (conc.tiers or {}).verified_aggressive or {}
    eq(verified_aggressive.mode, "enforce",
       "verified aggressive crawler dung concurrency ngay")
    eq(verified_aggressive.limit, 2,
       "verified aggressive crawler chi giu hai backend slot")

    -- Rollout bat dau o shadow nen telemetry la dau ra duy nhat de quyet dinh
    -- enforce.  Ghim schema de mot lan refactor logger khong bien module thanh
    -- code chay nhung khong the do.
    local logger_file = assert(io.open(src .. "async/logger.lua", "rb"))
    local logger_src = logger_file:read("*a")
    logger_file:close()
    for _, field in ipairs({
        "autcmode=", "autctier=", "autcaxis=", "autcn=", "autclim=",
        "autcsn=", "autcslim=", "autcwould=", "autcthr=", "autcleft=",
        "autcsleft=", "autcdur=", "autcup=", "autcactual=", "autcdeg=",
        "autcexp=",
    }) do
        ok(logger_src:find(field, 1, true) ~= nil,
           "logger giu cot operator concurrency " .. field)
    end
    for _, field in ipairs({
        " pcmode=", " pcaxis=", " pcipn=", " pcj3n=", " pcopen=",
        " pcwould=", " pcthr=", " pcproxy=", " pcdeg=",
        " dgmode=", " dgscope=", " dgtn=", " dgsn=", " dgwould=",
        " dgthr=", " dgcause=", " dgph=", " dgpd=", " dgpc=",
        " dgpath=", " dguri=", " dgpopen=", " dgpmode=",
        " dgpwould=", " dgphalf=", " dgpprobe=", " dgpwork=",
        " dgpn=", " dgpslow=", " dgpcand=", " dgptrans=",
        " dgppol=", " dgpsel=", " dgpswould=", " dgpsthr=",
        " dgpr=", " dgpckind=", " dgpcid=", " dgpcwork=",
        " dgpcn=", " dgpccand=", " dgpcshare=", " dgpcmatch=",
        " dgpattr=",
         " dgab=", " dgabup=", " dgabn=", " dgabw=", " dgabslow=",
         " dgabsn=", " dgabsw=", " dgabsslow=", " dgabdeg=",
         " dgsvmode=", " dgsvopen=", " dgsvwould=", " dgsvthr=",
         " dgsvwork=", " dgsvn=", " dgsvslow=", " dgsvcand=",
         " dgsvtrans=", " dgsvsel=", " dgsvkind=", " dgsvid=",
         " dgsvcwork=", " dgsvcn=", " dgsvcshare=", " dgsvmatch=",
         " dgsvattr=", " dgsvdeg=",
        " dgdur=", " dgup=", " dgactual=", " dgleft=", " dgdeg=",
        " dgexp=",
    }) do
        ok(logger_src:find(field, 1, true) ~= nil,
           "logger giu cot generic dynamic guard " .. field)
    end
    for _, field in ipairs({ " epq=", " epck=" }) do
        ok(logger_src:find(field, 1, true) ~= nil,
           "logger giu cot REST query/cookie " .. field)
    end
    for _, field in ipairs({
        " epsif=", " epsifmode=", " epsifgate=", " epsifover=", " epsifdeg=",
    }) do
        ok(logger_src:find(field, 1, true) ~= nil,
           "logger giu cot endpoint server-inflight " .. field)
    end
    -- `server` DA GO TINH TOAN 18-10. Khong dat han muc -> `consider()` tra ve
    -- ngay, truc chi con dem. Hai vong do tren 28-246 cho thay no khong the
    -- lam truc rang buoc: noi tran gap ba (20/60 -> 45/180) ma so luot vuot
    -- TANG (3937 -> 4781), vi `pair()` cong counter TRUOC `evaluate()` nen
    -- request da bi 429 van cong du chi phi. Va toan bo 22 luot FP vong 2 di
    -- qua truc nay.
    local server_limit = (aut.provisional_limits or {}).server
    eq(server_limit, nil,
       "server-axis KHONG dat han muc — go tinh toan, giu telemetry")
    -- Truc `fleet` (principal toan may) chua duoc ghim thi ai cung ha duoc
    -- trong im lang — dung lo ma MUT 2 phat hien hom nay (moi test dung config
    -- stub nen gia tri SHIP khong co gi bao ve).
    local fleet_limit = ((aut.provisional_limits or {}).fleet or {})
    eq(fleet_limit.short, 10,
       "fleet-axis = 10 / 10s: chan DOT cua mot principal")
    eq(fleet_limit.long, 30,
       "fleet-axis = 30 / 60s: gptbot (autfl 122,7) vuot 4,1x")
    -- BAT BIEN: neu ai dat lai `server`, no PHAI long hon `fleet` nhieu.
    --
    -- Bat bien nay giu lai du `server` dang nil, vi do la cai bay se quay lai:
    -- voi server 60 / fleet 60 thi `server` vo 3937 luot con `fleet` 186, va
    -- vi `server` GOP MOI PRINCIPAL nen claudebot bi chan 20 luot du `autfl`
    -- cua no moi la 12,0/60. Dat lai `server` chat hon `fleet` la tai tao
    -- dung FP do.
    if server_limit ~= nil then
        ok((server_limit.long or 0) > (fleet_limit.long or 0) * 2,
           "server.long phai > 2x fleet.long neu dat lai")
        ok((server_limit.short or 0) > (fleet_limit.short or 0) * 2,
           "server.short phai > 2x fleet.short neu dat lai")
    end
    -- Truc `fleet` la truc rang buoc duy nhat o cap toan may bay gio, nen no
    -- KHONG duoc phep nil — go ca hai thi khong con gi chan phep nhan mau so.
    ok(next(fleet_limit) ~= nil,
       "fleet PHAI co han muc — no la truc toan may duy nhat con tinh toan")
    -- Ban truoc cua khoi nay doi "giu CA HAI truc". So lieu vong 2 tren
    -- 28-246 da BAC BO dieu do: `server` khong the lam truc rang buoc (noi
    -- tran gap ba ma luot vuot tang) va toan bo 22 luot FP di qua no. Bat bien
    -- dung la truc CO PHAN BIET phai ton tai, con tran gop thi khong.
    eq(tiers.unknown, nil, "unknown KHONG bi chan — rao chan FP chinh")
    eq(tiers.verified, nil, "verified (Googlebot/Bingbot) KHONG bi chan")
end

io.write(string.format("pipeline_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
