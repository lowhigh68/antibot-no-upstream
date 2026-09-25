local _M = {}

-- A rule id remains stable because it is an external telemetry contract.  The
-- metadata below is the single place where detectors become policy facts.
local RULES = {}

local function add(id, family, phase, profile, action, mode, score, severity,
                   confidence, labels, why)
    RULES[id] = {
        id         = id,
        version    = 1,
        family     = family,
        phase      = phase,
        profile    = profile,
        action     = action,
        mode       = mode,
        score      = score,
        severity   = severity,
        confidence = confidence,
        labels     = labels or {},
        why        = why,
    }
end

-- Generic URI invariants.
add("dotfile_exposed", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "exposure.secret" })
add("dump_exposed", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "exposure.backup" })
add("wellknown_exec", "exposure", "uri", "generic", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })

-- Generic argument/body facts.  They are signals, not verdicts.
add("arg_traversal", "argument", "request", "generic", "signal", "enforce",
    35, 3, 0.80, { "attack.traversal" })
add("arg_php_wrapper", "argument", "request", "generic", "signal", "enforce",
    50, 4, 0.92, { "attack.php_wrapper" })
add("arg_null_byte", "argument", "request", "generic", "signal", "enforce",
    50, 4, 0.95, { "attack.null_byte" })
add("body_php_code", "body", "request_body", "generic", "signal", "enforce",
    50, 4, 0.75, { "body.php_code" })
add("body_scan_incomplete", "body", "request_body", "generic", "observe", "enforce",
    0, 1, 1.00, { "body.scan_incomplete" })

-- Upload names.  Scores are deliberately non-terminal until fleet data says
-- otherwise; the exact sub-label is retained for tuning.
add("upload_apache_config", "upload", "request_body", "generic", "signal", "enforce",
    45, 5, 0.90, { "upload.config", "upload.handler_config" })
add("upload_php_config", "upload", "request_body", "generic", "signal", "enforce",
    40, 5, 0.88, { "upload.config", "upload.php_config" })
add("upload_foreign_config", "upload", "request_body", "generic", "signal", "enforce",
    5, 2, 0.35, { "upload.config", "upload.foreign_config" })
add("upload_config_case", "upload", "request_body", "generic", "signal", "enforce",
    20, 3, 0.55, { "upload.config", "upload.case_variant" })
add("upload_php_ext", "upload", "request_body", "generic", "signal", "enforce",
    40, 5, 0.90, { "upload.executable" })
add("upload_php_double", "upload", "request_body", "generic", "signal", "enforce",
    45, 5, 0.92, { "upload.executable", "upload.double_extension" })
add("upload_php_legacy_ext", "upload", "request_body", "generic", "signal", "enforce",
    15, 3, 0.45, { "upload.possible_executable" })

-- WordPress is an optional overlay, never the generic foundation.
add("wp_upload_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable", "wordpress.upload_exec" })
add("wp_content_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })
add("wp_root_unknown", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    25, 3, 0.55, { "path.direct_php", "wordpress.root_unknown" })
add("wp_plugin_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    12.5, 2, 0.45, { "path.direct_php", "wordpress.plugin_direct" })
add("wp_muplugin_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    25, 3, 0.70, { "path.direct_php", "wordpress.muplugin_direct" })
add("wp_theme_direct", "wordpress_path", "uri", "wordpress", "signal", "enforce",
    12.5, 2, 0.45, { "path.direct_php", "wordpress.theme_direct" })
add("wp_includes_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })
add("wp_admin_includes_exec", "wordpress_path", "uri", "wordpress", "block", "enforce",
    100, 5, 0.99, { "path.forbidden", "path.executable" })

-- Filesystem evidence and policy correlations.  New block-capable correlations
-- start in shadow mode and require an explicit measured promotion.
add("fim_new_executable", "filesystem", "uri", "generic", "signal", "enforce",
    50, 4, 0.85, { "fs.new_executable" })
add("corr_upload_php_payload", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.96, { "correlation.upload_php_payload" })
add("corr_upload_config_php_payload", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.96, { "correlation.upload_config_php_payload" })
add("corr_new_direct_executable", "correlation", "decision", "generic", "block", "shadow",
    100, 5, 0.95, { "correlation.new_direct_executable" })

local CORRELATIONS = {
    {
        id = "corr_upload_php_payload",
        all = { "upload.executable", "body.php_code" },
    },
    {
        id = "corr_upload_config_php_payload",
        all = { "upload.handler_config", "body.php_code" },
    },
    {
        id = "corr_new_direct_executable",
        all = { "fs.new_executable", "path.direct_php" },
    },
}

function _M.get(id)
    return RULES[id]
end

function _M.all()
    return RULES
end

function _M.correlations()
    return CORRELATIONS
end

function _M.has_family(name)
    for _, rule in pairs(RULES) do
        if rule.family == name then return true end
    end
    return false
end

-- Catch detector/catalog drift during startup or tests.  This does not mutate
-- detector tables and therefore cannot change the behaviour of V1.
function _M.validate_sources(sources)
    local errors = {}
    for source, rules in pairs(sources or {}) do
        for id in pairs(rules or {}) do
            local meta = RULES[id]
            if not meta then
                errors[#errors + 1] = source .. ": missing registry rule " .. id
            elseif source == "wordpress" and meta.profile ~= "wordpress" then
                errors[#errors + 1] = source .. ": wrong profile for " .. id
            end
        end
    end
    return #errors == 0, errors
end

return _M
