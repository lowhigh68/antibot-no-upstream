-- Cheap endpoint classifier for the generic endpoint-cost guard.
--
-- This file is policy, not a rate limiter.  It turns WordPress route syntax
-- (pretty REST URLs, `rest_route=`, and sub-directory installs) into a bounded
-- endpoint id.  `l7/endpoint_guard.lua` owns counters and enforcement.
--
-- IMPORTANT: the WordPress overlay is applied only after the existing
-- filesystem/inventory gate proves the corresponding (docroot, prefix) is a
-- WordPress root.  A custom application is therefore free to use `/wp-json`
-- without inheriting WordPress policy.

local _M       = {}
local wp_paths = require "antibot.waf.wordpress.paths"

local MAX_ARGS       = 32
local MAX_URL_LENGTH = 2048

local function lower(s)
    return tostring(s or ""):lower()
end

local function trim_trailing_slash(path)
    if path ~= "/" then path = path:gsub("/+$", "") end
    return path ~= "" and path or "/"
end

local function scalar(value)
    return type(value) == "string" and value or nil
end

local function get_args(opts)
    if opts and opts.args then return opts.args, opts.args_error end
    if not ngx.req or not ngx.req.get_uri_args then return {}, "unavailable" end
    return ngx.req.get_uri_args(MAX_ARGS)
end

local function percent_decode(s)
    s = tostring(s or ""):gsub("+", " ")
    return (s:gsub("%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end))
end

local function raw_values(raw, wanted)
    local values = {}
    for pair in tostring(raw or ""):gmatch("[^&;]+") do
        local name, value = pair:match("^([^=]*)=?(.*)$")
        if percent_decode(name) == wanted then
            values[#values + 1] = percent_decode(value)
        end
    end
    if #values == 0 then return nil end
    if #values == 1 then return values[1] end
    return values
end

local function routed_value(value)
    if type(value) == "string" then return value, false end
    if type(value) ~= "table" then return nil, false end

    local first
    for i = 1, #value do
        local candidate = type(value[i]) == "string" and value[i] or nil
        if candidate then
            first = first or candidate
            local normalized = trim_trailing_slash(lower(candidate))
            if normalized:sub(1, 1) ~= "/" then
                normalized = "/" .. normalized
            end
            -- A duplicated routing parameter must not let a protected route
            -- hide behind a benign first value.  Pick the sensitive member;
            -- shape telemetry below records that the route was ambiguous.
            if normalized == "/oembed/1.0/embed"
               or normalized == "/oembed/1.0/proxy"
               or normalized == "/wp/v2/users" then
                return candidate, true
            end
        end
    end
    return first, true
end

-- Return (WordPress prefix, canonical REST path, source).  The prefix is the
-- filesystem/site prefix expected by wp_paths.is_wp_root(): "" for a root
-- install, "/blog" for a sub-directory install.
local function canonical_rest(uri, args)
    local raw_path = lower(uri):match("^([^?]*)") or "/"
    local had_trailing_slash = raw_path:sub(-1) == "/"
    local path = trim_trailing_slash(raw_path)
    local prefix, rest = path:match("^(.-)/wp%-json(/.*)$")
    if rest then
        prefix = trim_trailing_slash(prefix)
        if prefix == "/" then prefix = "" end
        return prefix, trim_trailing_slash(rest), "pretty"
    end

    local routed, route_ambiguous = routed_value(args and args.rest_route)
    if not routed or routed == "" then return nil end
    routed = trim_trailing_slash(lower(routed))
    if routed:sub(1, 1) ~= "/" then routed = "/" .. routed end

    -- WordPress accepts `/?rest_route=...` and `/index.php?rest_route=...`.
    -- For a sub-directory install the corresponding forms are `/blog/` and
    -- `/blog/index.php`.  Do not infer a prefix from arbitrary paths.
    if path:sub(-10) == "/index.php" then
        prefix = path:sub(1, -11)
    elseif path == "/" then
        prefix = ""
    elseif had_trailing_slash then
        prefix = path
    else
        return nil
    end
    prefix = trim_trailing_slash(prefix)
    if prefix == "/" then prefix = "" end
    return prefix, routed, "rest_route", route_ambiguous
end
_M.canonical_rest = canonical_rest

local function endpoint_for(rest, method, args)
    rest = trim_trailing_slash(rest)
    method = tostring(method or "GET"):upper()

    if rest == "/oembed/1.0/embed" then
        return "wp_oembed_embed"
    end
    if rest == "/oembed/1.0/proxy" then
        return "wp_oembed_proxy"
    end
    if rest == "/wp/v2/users" then
        if method == "GET" or method == "HEAD" then
            return "wp_users_collection"
        end
        return "wp_users_mutation"
    end

    -- `_embed` is not the oEmbed provider endpoint.  It asks the REST server
    -- to expand linked resources and can multiply application work, so it gets
    -- a separate, deliberately broad telemetry family.
    if args and args._embed ~= nil then return "wp_rest_embed_expand" end
    return nil
end
_M.endpoint_for = endpoint_for

local function normalize_host(host)
    host = lower(host):gsub("%.$", "")
    if host:sub(1, 1) == "[" then
        return host:match("^(%b[])")
    end
    host = host:gsub(":%d+$", "")
    if host == "" or host:find("[^%w%.%-]", 1) then return nil end
    return host
end

local function url_host(url)
    if type(url) ~= "string" or #url == 0 or #url > MAX_URL_LENGTH then
        return nil
    end
    local authority = url:match("^[Hh][Tt][Tt][Pp][Ss]?://([^/%?#]+)")
    if not authority or authority:find("@", 1, true) then return nil end
    return normalize_host(authority)
end

local function without_www(host)
    return host and host:gsub("^www%.", "") or nil
end

local function url_relation(url, request_host)
    local target = url_host(url)
    local current = normalize_host(request_host)
    if not target or not current then return "invalid" end
    if target == current then return "same" end
    if without_www(target) == without_www(current) then return "www_alias" end
    return "cross"
end
_M.url_relation = url_relation

local OEMBED_ARGS = {
    url = true, format = true, maxwidth = true,
    -- WordPress REST infrastructure may append this even though it is not a
    -- route argument.  Treating it as hostile would create needless FP.
    _locale = true,
    rest_route = true,
}

local function validate_oembed(args, method)
    if method ~= "GET" and method ~= "HEAD" then
        return "bad_method", "-"
    end
    local url = scalar(args.url)
    local relation = url_relation(url, ngx.var.host)
    if relation == "invalid" then return "bad_url", relation end

    local format = args.format
    if format ~= nil then
        format = scalar(format)
        if not format or (lower(format) ~= "json" and lower(format) ~= "xml") then
            return "bad_format", relation
        end
    end

    local width = args.maxwidth
    if width ~= nil then
        width = scalar(width)
        local n = width and tonumber(width) or nil
        if not n or n < 1 or n > 8192 or n ~= math.floor(n) then
            return "bad_maxwidth", relation
        end
    end

    for name in pairs(args) do
        if not OEMBED_ARGS[name] then return "unknown_arg", relation end
    end
    return "ok", relation
end

local function validate_users(args)
    for _, name in ipairs({ "per_page", "offset" }) do
        local value = args[name]
        if value ~= nil then
            value = scalar(value)
            local n = value and tonumber(value) or nil
            if not n or n < 0 or n ~= math.floor(n) then return "bad_" .. name end
            if name == "per_page" and n > 100 then return "bad_per_page" end
        end
    end
    if args.search ~= nil or args.include ~= nil or args.offset ~= nil
       or args.slug ~= nil or args.roles ~= nil or args.capabilities ~= nil then
        return "scan"
    end
    return "ok"
end

-- The capacity scope is the DOCROOT, deliberately not `docroot|prefix`.
--
-- The budget exists to protect one PHP-FPM pool, and the pool is per docroot.
-- A path prefix does not create a second pool, so making it part of the key
-- splits one site's budget into several and multiplies the real ceiling.
--
-- Measured on cloud28-246, 18-10-2026, thailandtranslation.net: the live URIs
-- are `/vi/wp-json/...`, `/ja/wp-json/...`, `/zh/wp-json/...`, `/TH/wp-json/...`
-- — WPML/Polylang language prefixes on ONE WordPress install sharing ONE
-- `public_html`. Keyed with the prefix, each language got its own in-flight
-- budget, so a configured limit of 3 became an effective 3 per language. The
-- shadow row `epif=15/3` is that arithmetic made visible: fifteen concurrent
-- requests against a pool of ten workers, while every single language bucket
-- still looked individually plausible.
--
-- The prefix is still passed to `is_wp_root()` above, because "is this a
-- WordPress root" genuinely is a per-directory question. Only the capacity
-- key drops it. `document_root` is already normalized without a trailing
-- slash on the whole fleet (see `wordpress/paths.lua`), so no extra
-- normalization is needed to keep `/a/b` and `/a/b/` from splitting.
local function scope_id(docroot)
    local raw = tostring(docroot or "")
    if raw:sub(-1) == "/" then raw = raw:sub(1, -2) end
    if ngx.md5 then return ngx.md5(raw):sub(1, 16) end
    raw = raw:lower():gsub("[^%w%-_]", "_")
    return raw:sub(1, 64)
end

function _M.run(ctx, opts)
    ctx = ctx or {}
    local raw_args = ngx.var.args or ""
    local uri = ngx.var.uri or (ctx.req and ctx.req.uri) or "/"
    local low_uri = lower(uri)

    -- Zero parsing/Redis work for the overwhelming majority of requests.
    local pretty_rest = low_uri:find("/wp%-json") ~= nil
    local raw_rest = pretty_rest and nil or raw_values(raw_args, "rest_route")
    if not pretty_rest and raw_rest == nil then
        return true, false
    end

    local args, args_err = get_args(opts)
    args = type(args) == "table" and args or {}
    -- get_uri_args intentionally caps parsing work.  The two routing keys are
    -- security boundaries, so recover all of their occurrences from the raw
    -- bounded Nginx request line: putting `rest_route` after argument 32 or
    -- duplicating it must not bypass endpoint classification.
    args.rest_route = raw_rest or raw_values(raw_args, "rest_route")
        or args.rest_route
    args._embed = raw_values(raw_args, "_embed") or args._embed
    local prefix, rest, source, route_ambiguous = canonical_rest(uri, args)
    if not rest then return true, false end

    local method = tostring(ngx.var.request_method
        or (ctx.req and ctx.req.method) or "GET"):upper()
    local endpoint = endpoint_for(rest, method, args)
    if not endpoint then return true, false end

    ctx.endpoint_candidate = endpoint
    ctx.endpoint_route_source = source

    local host = ngx.var.host or (ctx.req and ctx.req.host) or ""
    local docroot = ngx.var.document_root or ""
    local is_wp = (opts and opts.is_wp_root) or wp_paths.is_wp_root
    local proven = is_wp and is_wp(host, prefix, docroot)
    if proven ~= true then
        ctx.endpoint_policy_state = proven == nil and "lookup_failed" or "not_wp"
        if proven == nil then ctx.endpoint_policy_degraded = true end
        return true, false
    end

    ctx.endpoint_policy_state = "wp"
    ctx.endpoint_id = endpoint
    ctx.endpoint_scope = scope_id(docroot)
    ctx.endpoint_wp_prefix = prefix

    if args_err == "truncated" then
        ctx.endpoint_shape = "args_truncated"
    elseif route_ambiguous then
        ctx.endpoint_shape = "duplicate_rest_route"
    elseif endpoint == "wp_oembed_embed" or endpoint == "wp_oembed_proxy" then
        ctx.endpoint_shape, ctx.endpoint_url_relation = validate_oembed(args, method)
    elseif endpoint == "wp_users_collection" then
        ctx.endpoint_shape = validate_users(args)
    else
        ctx.endpoint_shape = "ok"
    end

    return true, false
end

return _M
