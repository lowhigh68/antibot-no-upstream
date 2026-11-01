-- P1 contract: remove an axis whose producer was permanently zero, and make
-- partial intelligence execution observable without changing the verdict.

local pass, fail = 0, 0
local function ok(v, n)
    if v then
        pass = pass + 1
    else
        fail = fail + 1
        io.stderr:write("FAIL: ", n, "\n")
    end
end
local function eq(got, want, n)
    ok(got == want,
       n .. " (got=" .. tostring(got) .. " want=" .. tostring(want) .. ")")
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end

local function read(rel)
    local f = assert(io.open(src .. rel, "rb"))
    local s = f:read("*a")
    f:close()
    return s
end

-- The producer had been pinned to zero since ip_classify was removed. Keeping
-- consumers made the axis look alive and invited a future accidental re-enable.
do
    local ctx_src = read("core/ctx/init.lua")
    local score_src = read("intelligence/scoring/compute.lua")
    local corr_src = read("intelligence/correlation/cross_layer_rules.lua")
    local rate_src = read("l7/rate/adaptive_limit.lua")

    ok(ctx_src:find("ctx.ip_score", 1, true) == nil,
       "ctx no longer manufactures a permanent zero ip_score")
    ok(score_src:find('name == "ip_score"', 1, true) == nil,
       "scoring no longer consumes dead ip_score")
    ok(score_src:match("ip_score%s*=%s*25") == nil,
       "dead ip_score weight is removed")
    ok(corr_src:find("bad_ip_rate", 1, true) == nil
       and corr_src:find("ip_risk_cluster", 1, true) == nil,
       "correlations that could never fire are removed")
    ok(rate_src:find("ctx.ip_score", 1, true) == nil,
       "adaptive rate no longer reads dead ip_score")
end

-- A failed sub-layer stays fail-open, all later layers still execute, and the
-- exact failed layer names are retained for the request logger.
do
    local ran = {}
    package.loaded["antibot.intelligence.threat"] = {
        run = function()
            ran.threat = true
            error("threat fixture")
        end,
    }
    package.loaded["antibot.intelligence.correlation"] = {
        run = function(ctx)
            ran.correlation = true
            ctx.corr_rules = {}
        end,
    }
    package.loaded["antibot.intelligence.scoring"] = {
        run = function()
            ran.scoring = true
            error("scoring fixture")
        end,
    }

    local errors = 0
    ngx = {
        ERR = 3,
        log = function(level)
            if level == 3 then errors = errors + 1 end
        end,
    }

    local intelligence = assert(loadfile(src .. "intelligence/init.lua"))()
    local ctx = {}
    local run_ok, run_exit = intelligence.run(ctx)

    eq(run_ok, true, "intelligence keeps the pipeline alive")
    eq(run_exit, false, "degraded intelligence does not terminate request")
    ok(ran.threat and ran.correlation and ran.scoring,
       "one failure does not skip later intelligence layers")
    eq(ctx.intelligence_degraded, true,
       "partial intelligence marks the request degraded")
    eq(table.concat(ctx.intelligence_degraded_layers or {}, ","),
       "threat,scoring", "failed layer provenance is ordered and bounded")
    eq(errors, 2, "each failed layer still emits detailed error log")
end

-- Healthy execution must not invent a degraded state.
do
    package.loaded["antibot.intelligence.threat"] = { run = function() end }
    package.loaded["antibot.intelligence.correlation"] = { run = function() end }
    package.loaded["antibot.intelligence.scoring"] = {
        run = function(ctx) ctx.score = 7 end,
    }

    local intelligence = assert(loadfile(src .. "intelligence/init.lua"))()
    local ctx = {}
    intelligence.run(ctx)
    eq(ctx.score, 7, "healthy scoring result is preserved")
    ok(ctx.intelligence_degraded ~= true,
       "healthy intelligence does not report degradation")
end

-- Self traffic must keep its normal verdict, but behavioral state from one
-- tenant must never become evidence against another tenant on the same
-- server. External key/fingerprint contracts remain byte-for-byte unchanged.
do
    local self_mode = false
    local store, gets, writes = {}, {}, {}

    ngx = {
        DEBUG = 0, WARN = 2,
        var = {
            server_name = "one.test",
            host = "one.test",
            remote_addr = "203.0.113.10",
            realip_remote_addr = "",
            server_addr = "203.0.113.10",
        },
        md5 = function(s) return "md5[" .. s .. "]" end,
        log = function() end,
        timer = { at = function(_, fn) fn(false); return true end },
    }

    package.loaded["antibot.core.ip_scope"] = {
        is_self = function() return self_mode end,
    }
    package.loaded["antibot.core.site_scope"] = nil
    package.loaded["antibot.core.state_scope"] = nil
    package.loaded["antibot.core.site_scope"] = assert(loadfile(
        src .. "core/site_scope.lua"))()

    local red = {}
    function red:get(key)
        gets[#gets + 1] = key
        return store[key]
    end
    function red:setex(key, ttl, value)
        writes[#writes + 1] = { "setex", key, ttl, value }
        store[key] = value
        return "OK"
    end
    function red:del(key)
        writes[#writes + 1] = { "del", key }
        store[key] = nil
        return 1
    end

    local pool = {
        safe_get = function(key)
            gets[#gets + 1] = key
            return store[key]
        end,
        get = function() return red end,
        put = function() end,
    }
    package.loaded["antibot.core.redis_pool"] = pool
    package.loaded["antibot.core.config"] = { ttl = { risk = 86400 } }

    local state_scope = assert(loadfile(src .. "core/state_scope.lua"))()
    package.loaded["antibot.core.state_scope"] = state_scope
    local risk_load = assert(loadfile(
        src .. "intelligence/correlation/risk_load.lua"))()
    local ip_rep = assert(loadfile(
        src .. "intelligence/threat/ip_reputation.lua"))()
    local risk_update = assert(loadfile(src .. "async/risk_update.lua"))()

    -- Historical external namespaces stay unchanged.
    store["risk:external-id"] = "0.2500"
    store["rep:198.51.100.7"] = "0.4000"
    store["ip_risk:198.51.100.7"] = "0.3000"
    local external = {
        identity = "external-id", ip = "198.51.100.7",
        req = { host = "one.test" },
    }
    risk_load.run(external)
    ip_rep.run(external)
    eq(external.risk, 0.25, "external identity risk keeps legacy key")
    eq(external.ip_risk, 0.30, "external IP risk keeps legacy key")
    eq(external.ip_rep, 0.40, "global threat-feed reputation is unchanged")
    eq(gets[#gets - 2], "risk:external-id",
       "external risk read is byte-for-byte compatible")
    eq(gets[#gets], "ip_risk:198.51.100.7",
       "external ip_risk read is byte-for-byte compatible")

    -- Self reads use the selected vhost's primary name, not the raw Host.
    self_mode = true
    store["risk:self:one.test:self-id"] = "0.7000"
    store["ip_risk:self:one.test:203.0.113.10"] = "0.6000"
    local self_one = {
        identity = "self-id", ip = "203.0.113.10",
        req = { host = "www.alias-one.test" },
    }
    ngx.var.host = "www.alias-one.test"
    risk_load.run(self_one)
    ip_rep.run(self_one)
    eq(self_one.risk, 0.70, "self risk is read from target-site namespace")
    eq(self_one.ip_risk, 0.60,
       "self IP risk is read from target-site namespace")

    local alias_key = state_scope.risk_key({
        identity = "self-id", req = { host = "another-alias.test" },
    }, "self-id")
    eq(alias_key, "risk:self:one.test:self-id",
       "raw Host aliases cannot split self state")

    ngx.var.server_name, ngx.var.host = "two.test", "two.test"
    local self_two = {
        identity = "self-id", ip = "203.0.113.10",
        req = { host = "two.test" },
    }
    risk_load.run(self_two)
    ip_rep.run(self_two)
    eq(self_two.risk, 0.0, "self identity risk cannot cross target sites")
    eq(self_two.ip_risk, 0.0, "self IP risk cannot cross target sites")

    -- Writer and readers must share exactly the same scoped key contract.
    self_two.score = 100
    self_two.action = "block"
    self_two.req_class = "navigation"
    self_two.bot_score = 0.8
    risk_update.run(self_two)
    ok(store["risk:self:two.test:self-id"] ~= nil,
       "self risk writer uses the target-site key")
    ok(store["ip_risk:self:two.test:203.0.113.10"] ~= nil,
       "self ip_risk writer uses the target-site key")
    ok(store["risk:self:one.test:self-id"] == "0.7000",
       "updating site two does not mutate site one")

    -- fp_light is the session/graph key. It is scoped only for trusted self
    -- traffic; the coarse identity/network_id used by quarantine stays intact.
    package.loaded["antibot.core.fingerprint.identity"] = {
        build = function(ctx)
            ctx.identity = "coarse-id"
            ctx.network_id = "coarse-id"
        end,
    }
    local build_light = assert(loadfile(
        src .. "core/fingerprint/build_light.lua"))()
    local function fp(site, raw_host, is_self)
        self_mode = is_self
        ngx.var.server_name, ngx.var.host = site, raw_host or site
        local ctx = {
            ip = "203.0.113.10", ua = "curl/7.81.0",
            ja3 = "NO_JA3", req = { host = raw_host or site },
        }
        local run_ok = build_light.run(ctx)
        ok(run_ok, "fingerprint fixture runs")
        return ctx.fp_light, ctx.identity, ctx.network_id
    end

    local ext_one = fp("one.test", "one.test", false)
    local ext_two = fp("two.test", "two.test", false)
    eq(ext_one, ext_two, "external fp_light remains host-independent")

    local fp_one, id_one, net_one = fp(
        "one.test", "www.alias-one.test", true)
    local fp_alias = fp("one.test", "other-alias.test", true)
    local fp_two, id_two, net_two = fp("two.test", "two.test", true)
    eq(fp_one, fp_alias, "self aliases in one vhost share session state")
    ok(fp_one ~= fp_two, "self session/graph state cannot cross target sites")
    eq(id_one, id_two, "self identity remains the established coarse id")
    eq(net_one, net_two,
       "quarantine network_id contract is not silently changed")
end

io.write(string.format("intelligence_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
