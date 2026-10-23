-- Normalized decision ledger.
--
-- Existing `action`/`action_reason` and module-specific telemetry remain the
-- compatibility contract.  This module adds orthogonal semantics so an
-- operator need not infer whether a 403/429 was security, capacity, policy or
-- challenge, nor whether the request reached upstream.
local meta = require "antibot.core.policy_meta"
local _M = {}

local KINDS = {
    security = true, capacity = true, policy = true, challenge = true,
}
local MODES = {
    observe = true, shadow = true, enforce = true, degraded = true,
}

function _M.initialize(ctx)
    if not ctx then return end
    if not ctx.policy_version then
        -- Most requests receive the version from core.policy.resolve() in the
        -- ctx layer.  Direct Lua endpoints can initialize a small ctx of their
        -- own, so query the active local policy here as a safe fallback.
        local ok, policy = pcall(require, "antibot.core.policy")
        ctx.policy_version = ok and policy and policy.current_version
            and policy.current_version() or meta.policy_version
    end
    ctx.decision_schema = ctx.decision_schema or meta.decision_schema
end

function _M.set(ctx, spec)
    if not ctx or type(spec) ~= "table" then return false end
    _M.initialize(ctx)
    local kind = tostring(spec.kind or "")
    local mode = tostring(spec.mode or "enforce")
    if not KINDS[kind] then return false, "invalid decision kind" end
    if not MODES[mode] then return false, "invalid decision mode" end

    ctx.decision_kind    = kind
    ctx.decision_source  = tostring(spec.source or "unknown")
    ctx.decision_rule    = tostring(spec.rule or ctx.action_reason or "-")
    ctx.decision_mode    = mode
    ctx.decision_scope   = tostring(spec.scope or "request")
    ctx.decision_subject = spec.subject ~= nil and tostring(spec.subject) or nil
    ctx.decision_ttl     = tonumber(spec.ttl)
    if spec.upstream ~= nil then
        ctx.decision_upstream_reached = spec.upstream == true
    end
    return true
end

-- Upstream reachability is an outcome, not a policy inference.  It becomes
-- authoritative only in log phase, after nginx exposes upstream_status.
function _M.finalize_upstream(ctx, upstream_status)
    if not ctx then return end
    _M.initialize(ctx)
    if ctx.decision_upstream_reached ~= nil then return end
    local raw = tostring(upstream_status or "")
    ctx.decision_upstream_reached = raw ~= "" and raw ~= "-"
end

return _M
