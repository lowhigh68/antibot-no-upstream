-- Source-controlled policy candidate for P1.1.
--
-- Workers NEVER load this file.  `waf/scripts/policyctl.sh publish` validates
-- it, runs the full regression suite and atomically publishes JSON under
-- /etc/antibot/policy.  Workers read only active.json/LKG during init_worker.
-- Empty scopes preserve the exact behaviour of core/config.lua.  Unknown
-- keys, sections or wrong types reject the WHOLE candidate before promotion.
--
-- Precedence is fixed:
--   global -> servers[$hostname] -> tenants[$document_root] -> principals[name]
--
return {
    schema = "1",
    version = "2026-10-23-p1.0",

    global = { settings = {} },
    servers = {},
    tenants = {},
    principals = {},
}
