-- Metadata common to every request/log row.
--
-- `policy_version` is only the fallback for contexts created outside the root
-- request pipeline.  P1.0 normally supplies the digest of the compiled,
-- validated local policy through core.policy.
local _M = {
    decision_schema = "1",
    policy_version  = "builtin-p1.0",
}

return _M
