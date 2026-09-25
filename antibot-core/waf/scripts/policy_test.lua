local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

package.preload["antibot.waf.registry"] = function()
    return dofile(SRC .. "waf/registry.lua")
end

local registry  = require "antibot.waf.registry"
local config    = dofile(SRC .. "waf/config.lua")
local policy    = dofile(SRC .. "waf/policy.lua")
local telemetry = dofile(SRC .. "waf/telemetry.lua")

local pass, fail = 0, 0

local function eq(name, got, want)
    if got == want then
        pass = pass + 1
    else
        fail = fail + 1
        io.write(string.format("SAI  %-48s cho=%s duoc=%s\n",
            name, tostring(want), tostring(got)))
    end
end

local function resolved(runtime, host)
    return config.resolve(config.compile(runtime), host or "example.test")
end

local function state(runtime, host, uri, method)
    local ctx = {}
    local cfg = resolved(runtime, host)
    return ctx, policy.begin(ctx, {
        host = host or "example.test",
        uri = uri or "/index.php",
        method = method or "GET",
    }, cfg)
end

do
    local ctx, st = state()
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("hard invariant is enforced", d.action, "block")
    eq("hard invariant reason", d.reason, "dotfile_exposed")
    eq("decision exported to ctx", ctx.waf_decision, d)
end

do
    local _, st = state({ mode = "shadow" })
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("global shadow allows", d.action, "allow")
    eq("global shadow keeps would_action", d.would_action, "block")
    eq("global shadow flag", d.shadow, true)
end

do
    local _, st = state({
        exceptions = {
            { id = "health-dotfile", rule = "dotfile_exposed",
              host = "example.test", uri_prefix = "/.health/" },
        },
    }, "example.test", "/.health/.probe")
    local hit = policy.emit(st, "dotfile_exposed", { target = "URI" })
    local d = policy.decide(st)
    eq("exception marks hit", hit.excepted, true)
    eq("exception suppresses verdict", d.action, "allow")
    eq("exception suppresses labels", st.labels["path.forbidden"], nil)
    eq("exception suppresses score", st.score, 0)
end

do
    local _, st = state({ profiles = { wordpress = false } })
    local hit, why = policy.emit(st, "wp_plugin_direct", { target = "URI" })
    eq("wordpress profile can be disabled", hit, nil)
    eq("disabled profile reason", why, "profile_disabled")
end

do
    local _, st = state()
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("new correlation starts shadow", d.action, "allow")
    eq("new correlation computes block", d.would_action, "block")
    eq("upload correlation reason", d.reason, "corr_upload_php_payload")
    eq("upload correlation label", st.labels["correlation.upload_php_payload"], true)
end

do
    local _, st = state({
        correlations = {
            corr_upload_php_payload = { mode = "enforce" },
        },
    })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("measured correlation can be promoted", d.action, "block")
end

do
    local _, st = state({
        rules = { dotfile_exposed = { score = 10 } },
    })
    policy.emit(st, "dotfile_exposed", { target = "URI" })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("shadow candidate cannot mask enforce candidate", d.action, "block")
    eq("actual reason remains enforce candidate", d.reason, "dotfile_exposed")
    eq("correlation is not double-counted in score", d.score, 100)
end

do
    local cfg = config.compile({
        mode = "shadow",
        domains = {
            ["strict.test"] = {
                mode = "enforce",
                rules = { dotfile_exposed = { mode = "shadow" } },
            },
        },
    })
    local strict = config.resolve(cfg, "STRICT.TEST.")
    eq("domain override host normalization", strict.host, "strict.test")
    eq("domain override global mode", strict.mode, "enforce")
    eq("domain override rule mode", strict.rules.dotfile_exposed.mode, "shadow")
end

do
    local ok, errors = config.validate(config.compile({ mode = "enfoce" }))
    eq("invalid mode is rejected", ok, false)
    eq("invalid mode reports error", #errors > 0, true)
end

do
    local _, st = state({
        families = { upload = { action = "observe" } },
    })
    policy.emit(st, "upload_php_ext", { target = "MULTIPART_FILENAME" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("family observe does not feed correlation", d.would_action, "allow")
    eq("family observe does not add label", st.labels["upload.executable"], nil)
end

do
    local _, st = state()
    policy.emit(st, "arg_traversal", { target = "ARGS" })
    local score = st.score
    local _, why = policy.emit(st, "arg_traversal", { target = "ARGS" })
    eq("duplicate fact is identified", why, "duplicate")
    eq("duplicate fact does not add score", st.score, score)
end

do
    local _, st = state({
        score_enforcement = true,
        threshold_mode = "shadow",
        thresholds = { block = 80 },
    })
    policy.emit(st, "arg_php_wrapper", { target = "ARGS" })
    policy.emit(st, "body_php_code", { target = "BODY" })
    local d = policy.decide(st)
    eq("score threshold starts shadow", d.action, "allow")
    eq("score threshold would block", d.would_action, "block")
    eq("score threshold reason", d.reason, "score_threshold")
end

do
    local values = {}
    local dict = {}
    function dict:incr(key, amount, initial)
        if values[key] == nil then values[key] = initial or 0 end
        values[key] = values[key] + amount
        return values[key]
    end
    local tick = 10
    local rt = {
        now = function() return tick end,
        shared = { antibot_cache = dict },
    }
    local ctx, st = state()
    telemetry.start(ctx, st.config, rt)
    policy.emit(st, "arg_traversal", { target = "ARGS" })
    local d = policy.decide(st)
    telemetry.record(ctx, st, d, rt)
    telemetry.record(ctx, st, d, rt)
    tick = 10.012
    telemetry.finish(ctx, rt)
    telemetry.finish(ctx, rt)
    eq("telemetry records request once", values["waf:v2:requests"], 1)
    eq("telemetry records rule once", values["waf:v2:rule:arg_traversal"], 1)
    eq("telemetry records latency once", values["waf:v2:latency_count"], 1)
    eq("telemetry latency ms", values["waf:v2:latency_ms_sum"], 12)
end

do
    local ok, errors = registry.validate_sources({ fake = { not_registered = {} } })
    eq("registry detects drift", ok, false)
    eq("registry reports one drift", #errors, 1)
end

io.write(string.format("\npolicy V2: %d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
