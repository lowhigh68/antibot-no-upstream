local registry = require "antibot.waf.registry"

local _M = {}

local ACTION_RANK = { allow = 0, observe = 1, signal = 2, block = 3 }

local function clamp01(n)
    n = tonumber(n)
    if not n then return 1 end
    if n < 0 then return 0 end
    if n > 1 then return 1 end
    return n
end

local function starts_with(s, prefix)
    return type(s) == "string" and type(prefix) == "string" and
           s:sub(1, #prefix) == prefix
end

local function exception_matches(ex, state, rule, evidence)
    if type(ex) ~= "table" or ex.enabled == false then return false end
    if ex.rule and ex.rule ~= "*" and ex.rule ~= rule.id then return false end
    if ex.family and ex.family ~= rule.family then return false end
    if ex.host and tostring(ex.host):lower():gsub("%.$", "") ~= state.request.host then
        return false
    end
    if ex.method and ex.method:upper() ~= state.request.method then return false end
    if ex.target and ex.target ~= evidence.target then return false end
    if ex.uri and ex.uri ~= state.request.uri then return false end
    if ex.uri_prefix and not starts_with(state.request.uri, ex.uri_prefix) then
        return false
    end
    return true
end

local function is_excepted(state, rule, evidence)
    local exceptions = state.config.exceptions or {}
    for i = 1, #exceptions do
        if exception_matches(exceptions[i], state, rule, evidence) then
            return true, exceptions[i].id or ("exception-" .. i)
        end
    end
    return false, nil
end

local function override_for(state, rule)
    local source = rule.family == "correlation" and
                   state.config.correlations or state.config.rules
    local family = state.config.families and state.config.families[rule.family]
    local exact = source and source[rule.id]
    local override = {}
    if type(family) == "table" then
        for k, v in pairs(family) do override[k] = v end
    end
    if type(exact) == "table" then
        for k, v in pairs(exact) do override[k] = v end
    end
    return override
end

local function add_labels(state, rule, evidence)
    for i = 1, #(rule.labels or {}) do
        state.labels[rule.labels[i]] = true
    end
    if type(evidence.labels) == "table" then
        for i = 1, #evidence.labels do state.labels[evidence.labels[i]] = true end
    end
end

local function better_candidate(a, b)
    if not a then return b end
    if not b then return a end
    local ar = ACTION_RANK[a.action] or 0
    local br = ACTION_RANK[b.action] or 0
    if br ~= ar then return br > ar and b or a end
    if (b.score or 0) ~= (a.score or 0) then
        return (b.score or 0) > (a.score or 0) and b or a
    end
    return a
end

function _M.begin(ctx, request, resolved_config)
    ctx = ctx or {}
    request = request or {}
    local state = {
        ctx       = ctx,
        config    = resolved_config or {},
        request   = {
            host   = tostring((resolved_config or {}).host or
                              request.host or "-"):lower():gsub("%.$", ""),
            uri    = tostring(request.uri or "/"),
            method = tostring(request.method or "GET"):upper(),
        },
        hits         = {},
        labels       = {},
        seen         = {},
        score        = 0,
        candidate    = nil,
        enforce_candidate = nil,
        correlations = false,
        unknown      = {},
    }
    -- Keep the public ctx projection acyclic. `state` owns ctx while the
    -- request is evaluated; storing state back inside ctx would create
    -- ctx -> state -> ctx and break generic JSON/log serializers.
    ctx.waf_v2 = {
        version = (resolved_config or {}).version or "2.0",
        wordpress_enabled = ((resolved_config or {}).profiles or {}).wordpress ~= false,
    }
    ctx.waf_hits = ctx.waf_hits or {}
    return state
end

function _M.emit(state, rule_id, evidence)
    evidence = type(evidence) == "table" and evidence or {}
    local rule = registry.get(rule_id)
    if not rule then
        state.unknown[#state.unknown + 1] = rule_id
        return nil, "unknown_rule"
    end

    local profiles = state.config.profiles or {}
    if profiles[rule.profile] == false then return nil, "profile_disabled" end

    local override = override_for(state, rule)
    if override.enabled == false then return nil, "rule_disabled" end

    local target = evidence.target or rule.phase
    local dedupe = rule_id .. "\0" .. tostring(target)
    if state.seen[dedupe] then return state.seen[dedupe], "duplicate" end

    local action = override.action or rule.action
    local mode = override.mode or rule.mode or "enforce"
    local base_score = tonumber(override.score) or tonumber(rule.score) or 0
    local score = base_score * clamp01(evidence.factor)
    local excepted, exception_id = is_excepted(state, rule, {
        target = target,
    })

    local hit = {
        rule          = rule.id,
        version       = rule.version,
        family        = rule.family,
        profile       = rule.profile,
        phase         = rule.phase,
        target        = target,
        matched       = evidence.matched,
        action        = action,
        mode          = mode,
        score         = score,
        severity      = rule.severity,
        confidence    = rule.confidence,
        excepted      = excepted,
        exception_id  = exception_id,
    }
    state.hits[#state.hits + 1] = hit
    state.ctx.waf_hits[#state.ctx.waf_hits + 1] = hit
    state.seen[dedupe] = hit

    -- An exception suppresses both the verdict and the labels.  Otherwise a
    -- skipped rule could still block indirectly through a correlation.
    if not excepted and action ~= "observe" then
        add_labels(state, rule, evidence)
        -- A correlation is a verdict derived from facts already scored. Adding
        -- its nominal severity again would double-count the same evidence and
        -- could let a shadow correlation cross an enforced score threshold.
        if rule.family ~= "correlation" then
            state.score = state.score + score
        end
        if action == "block" then
            state.candidate = better_candidate(state.candidate, hit)
            if mode == "enforce" then
                state.enforce_candidate = better_candidate(state.enforce_candidate, hit)
            end
        end
    end
    return hit
end

local function correlate(state)
    if state.correlations then return end
    state.correlations = true
    local definitions = registry.correlations()
    for i = 1, #definitions do
        local definition = definitions[i]
        local matched = true
        for j = 1, #definition.all do
            if not state.labels[definition.all[j]] then matched = false; break end
        end
        if matched then
            _M.emit(state, definition.id, {
                target = "CORRELATION",
                matched = table.concat(definition.all, "+"),
            })
        end
    end
end

local function score_candidate(state)
    if not state.config.score_enforcement then return nil end
    local threshold = tonumber((state.config.thresholds or {}).block)
    if not threshold or state.score < threshold then return nil end
    return {
        rule       = "score_threshold",
        family     = "policy",
        action     = "block",
        mode       = state.config.threshold_mode or "shadow",
        score      = state.score,
        severity   = 5,
        confidence = 0,
    }
end

function _M.decide(state, with_correlations)
    if with_correlations ~= false then correlate(state) end

    local threshold_candidate = score_candidate(state)
    local candidate = better_candidate(state.candidate, threshold_candidate)
    local enforce_candidate = state.enforce_candidate
    if threshold_candidate and threshold_candidate.mode == "enforce" then
        enforce_candidate = better_candidate(enforce_candidate, threshold_candidate)
    end
    local would_action = candidate and candidate.action or "allow"
    local actual_action = "allow"
    local global_mode = state.config.mode or "enforce"

    if global_mode == "enforce" and enforce_candidate then
        actual_action = enforce_candidate.action
    end

    local decision = {
        action       = actual_action,
        would_action = would_action,
        reason       = (actual_action ~= "allow" and enforce_candidate and
                        enforce_candidate.rule) or (candidate and candidate.rule) or nil,
        would_reason = candidate and candidate.rule or nil,
        mode         = global_mode,
        rule_mode    = candidate and candidate.mode or nil,
        score        = state.score,
        shadow       = actual_action ~= would_action,
    }

    state.ctx.waf_score = state.score
    state.ctx.waf_labels = state.labels
    state.ctx.waf_decision = decision
    state.ctx.waf_v2.score = state.score
    state.ctx.waf_v2.mode = global_mode
    state.ctx.waf_v2.action = actual_action
    state.ctx.waf_v2.would_action = would_action
    return decision
end

function _M.has_label(state, label)
    return state.labels[label] == true
end

return _M
