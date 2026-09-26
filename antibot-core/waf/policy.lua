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
        -- Diem DA TINH cua moi luat: `score` = tong theo luat cua max qua target.
        rule_score   = {},
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
        --
        -- CUNG MOT LUAT o nhieu target tinh MOT lan, lay max; khac luat thi cong.
        -- V7 phat bang chung than theo vung, va `../` trong ten tep nam ca o vung
        -- `nonfile` (header la phan khong phai tep) lan `filename` — cong ca hai la
        -- dem mot bang chung hai lan. Loi nay co tu truoc V7 giua query string va
        -- than: `arg_traversal` o `ARGS` + `BODY` ra 70 thay vi 35 (do 26-09).
        -- Them fact chi co the them luat moi hoac nang max, nen diem khong bao gio
        -- giam khi request co them noi dung.
        if rule.family ~= "correlation" and score > (state.rule_score[rule.id] or 0) then
            state.score = state.score + score - (state.rule_score[rule.id] or 0)
            state.rule_score[rule.id] = score
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

    -- ── HAI TRUC DOC LAP, khong tron ────────────────────────────────────────
    --
    -- Ban truoc tron chung: `reason` uu tien `enforce_candidate` roi ROI VE
    -- `candidate`, con `rule_mode` thi LUON lay tu `candidate`. Nen hai truong
    -- hop sai cung luc:
    --
    --   `action = "allow"` van mang mot `reason` — tu candidate cua che do bong.
    --   Doc log se thay mot request khong bi chan nhung co ly do chan.
    --
    --   `reason = dotfile_exposed` (tu enforce candidate) di cung
    --   `rule_mode = shadow` (tu mot candidate KHAC, manh hon nhung o che do
    --   bong). Hai gia tri mo ta HAI RULE khac nhau tren cung mot dong.
    --
    -- Hom nay chua sai vi moi luat deu `enforce` nen hai candidate trung nhau.
    -- No sai dung luc co mot luat shadow manh hon — tuc dung luc bat dau
    -- promotion, dung luc can doc log chinh xac nhat.
    --
    -- QUY UOC: `reason`/`rule_mode` chi mo ta candidate tao ra PHAN QUYET THAT.
    -- Khi `action = "allow"` thi ca hai la `nil`, va bang chung cua che do bong
    -- nam o nhom `would_*`. Nhu vay khong con cach nao doc lan hai truc: mot
    -- `reason` ton tai nghia la mot request THAT SU bi chan.
    local verdict = (actual_action ~= "allow") and enforce_candidate or nil

    local decision = {
        -- truc THAT: chuyen gi da xay ra
        action       = actual_action,
        reason       = verdict and verdict.rule or nil,
        rule_mode    = verdict and verdict.mode or nil,

        -- truc GIA DINH: chuyen gi se xay ra neu moi luat duoc enforce
        would_action     = would_action,
        would_reason     = candidate and candidate.rule or nil,
        would_rule_mode  = candidate and candidate.mode or nil,

        mode         = global_mode,
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
