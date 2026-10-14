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

io.write(string.format("intelligence_contract: %d qua, %d hong\n", pass, fail))
if fail > 0 then os.exit(1) end
