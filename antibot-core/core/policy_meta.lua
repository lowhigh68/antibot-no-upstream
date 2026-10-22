-- Metadata common to every request/log row.
--
-- P1 will replace the static policy version with the digest of a compiled,
-- validated policy.  P0 deliberately starts with a constant so operators can
-- already distinguish old/new log schemas without changing any verdict.
local _M = {
    decision_schema = "1",
    policy_version  = "2026-10-21-p0",
}

return _M
