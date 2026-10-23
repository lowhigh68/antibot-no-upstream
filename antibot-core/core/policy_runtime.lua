-- Local policy source for P1.0.
--
-- This file is loaded and validated independently in every worker.  Empty
-- scopes preserve the exact behaviour of core/config.lua.  Unknown keys,
-- unknown sections and wrong value types reject the WHOLE candidate.
--
-- Precedence is fixed:
--   global -> servers[$hostname] -> tenants[$document_root] -> principals[name]
--
-- P1.1 will add signed/staged artifacts, last-known-good persistence and
-- rollback.  Until then this repository file is the only candidate source.
return {
    schema = "1",
    version = "2026-10-23-p1.0",

    global = { settings = {} },
    servers = {},
    tenants = {},
    principals = {},
}
