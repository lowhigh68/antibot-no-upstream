-- P1.3 offline feedback/replay tool.
--
-- This file is never required by an nginx worker.  It consumes immutable
-- incident bundles produced by waf/scripts/feedbackctl.sh and replays only
-- facts that production already evaluated (`*would=true`).  It deliberately
-- does NOT reconstruct Redis counters or pretend that a flat log line can
-- simulate a new threshold.  New thresholds must first run in shadow; a later
-- shadow->enforce promotion can then be judged against labelled evidence.

local cjson = require "cjson.safe"

local LABELS = {
    true_bot = true,
    legit_automation = true,
    human_fp = true,
    capacity_only = true,
}

local AXES = {
    { name = "automation", fields = { "autwould" } },
    { name = "automation_concurrency", fields = { "autcwould" } },
    { name = "principal_churn", fields = { "pcwould" } },
    { name = "endpoint_guard", fields = { "epwould" } },
    { name = "dynamic_guard", fields = { "dgwould" } },
    -- `dgpwould` is the old blanket-open observation.  The actual selective
    -- candidate is `dgpswould`; replaying the blanket bit would overstate FP.
    { name = "dynamic_pressure", fields = { "dgpswould" } },
    { name = "dynamic_server_pressure", fields = { "dgsvwould" } },
    { name = "surge_guard", fields = { "sgwould" } },
    { name = "circuit_breaker", fields = { "cbwould" } },
}

local function die(message)
    io.stderr:write("FEEDBACK_ERROR ", tostring(message), "\n")
    return false
end

local function read_bounded(path, maximum)
    local fh, err = io.open(path, "rb")
    if not fh then return nil, "cannot read " .. path .. ": " .. tostring(err) end
    local raw = fh:read(maximum + 1)
    fh:close()
    if not raw then return nil, "cannot read " .. path end
    if #raw > maximum then return nil, path .. " exceeds " .. maximum .. " bytes" end
    return raw
end

local function read_json(path)
    local raw, err = read_bounded(path, 1024 * 1024)
    if not raw then return nil, err end
    local value, decode_err = cjson.decode(raw)
    if value == nil then return nil, "invalid JSON in " .. path .. ": " .. tostring(decode_err) end
    return value
end

local function scalar_token(value, maximum)
    value = tostring(value or "")
    if value == "" or #value > maximum or value:find("[%z\r\n]") then return nil end
    return value
end

local function parse_fields(line)
    local out = {}
    for token in tostring(line):gmatch("%S+") do
        local key, value = token:match("^([%a_][%w_]*)=(.*)$")
        if key and out[key] == nil then out[key] = value end
    end
    return out
end

local function sorted_keys(set)
    local out = {}
    for key in pairs(set or {}) do out[#out + 1] = key end
    table.sort(out)
    return out
end

local function manifest_from_env()
    local evidence = os.getenv("FB_EVIDENCE")
    local output_id = scalar_token(os.getenv("FB_ID"), 96)
    local label = scalar_token(os.getenv("FB_LABEL"), 32)
    local actor = scalar_token(os.getenv("FB_ACTOR"), 96)
    local note = scalar_token(os.getenv("FB_NOTE"), 512)
    local filters = scalar_token(os.getenv("FB_FILTERS"), 1024)
    local digest = scalar_token(os.getenv("FB_SHA256"), 64)
    local source_host = scalar_token(os.getenv("FB_HOST"), 255)
    local source_log = scalar_token(os.getenv("FB_SOURCE_LOG"), 512)
    local from_ts = tonumber(os.getenv("FB_FROM"))
    local to_ts = tonumber(os.getenv("FB_TO"))
    local created_at = tonumber(os.getenv("FB_CREATED"))
    local expires_at = tonumber(os.getenv("FB_EXPIRES"))

    if not evidence or not output_id or not label or not LABELS[label]
       or not actor or not note or not filters or not digest
       or not digest:match("^[0-9a-f]+$") or #digest ~= 64
       or not source_host or not source_log
       or not from_ts or not to_ts or not created_at or not expires_at
       or from_ts > to_ts or created_at > expires_at then
        return die("manifest environment is missing or invalid")
    end

    local fh, err = io.open(evidence, "rb")
    if not fh then return die("cannot read evidence: " .. tostring(err)) end
    local rows, bytes = 0, 0
    local pvers, schemas = {}, {}
    for line in fh:lines() do
        bytes = bytes + #line + 1
        if bytes > 64 * 1024 * 1024 then fh:close(); return die("evidence exceeds 64 MiB") end
        local fields = parse_fields(line)
        local ts = tonumber(fields.ts)
        if not ts or ts < from_ts or ts > to_ts then
            fh:close(); return die("evidence row is outside the declared interval")
        end
        if not fields.pver or fields.pver == "-" or not fields.dschema
           or fields.dschema == "-" then
            fh:close(); return die("evidence row lacks pver/dschema")
        end
        pvers[fields.pver] = true
        schemas[fields.dschema] = true
        rows = rows + 1
        if rows > 50000 then fh:close(); return die("evidence exceeds 50000 rows") end
    end
    fh:close()
    if rows == 0 then return die("evidence is empty") end

    local manifest = {
        schema = "1",
        id = output_id,
        label = label,
        created_at = created_at,
        expires_at = expires_at,
        from_ts = from_ts,
        to_ts = to_ts,
        actor = actor,
        note = note,
        filters = filters,
        source_host = source_host,
        source_log = source_log,
        evidence_file = "evidence.log",
        evidence_sha256 = digest,
        rows = rows,
        bytes = bytes,
        policy_versions = sorted_keys(pvers),
        decision_schemas = sorted_keys(schemas),
        contains_request_metadata = true,
    }
    local raw, encode_err = cjson.encode(manifest)
    if not raw then return die("cannot encode manifest: " .. tostring(encode_err)) end
    io.write(raw, "\n")
    return true
end

local function validate_manifest(value, path)
    if type(value) ~= "table" or tostring(value.schema or "") ~= "1" then
        return nil, path .. " has unsupported schema"
    end
    if not LABELS[value.label] then return nil, path .. " has invalid label" end
    for _, key in ipairs({ "id", "actor", "note", "filters", "source_host",
                           "source_log", "evidence_file", "evidence_sha256" }) do
        if type(value[key]) ~= "string" or value[key] == "" then
            return nil, path .. " lacks " .. key
        end
    end
    if value.evidence_file ~= "evidence.log" then
        return nil, path .. " references an unsafe evidence path"
    end
    for _, key in ipairs({ "created_at", "expires_at", "from_ts", "to_ts", "rows" }) do
        if type(value[key]) ~= "number" then return nil, path .. " lacks numeric " .. key end
    end
    if value.rows < 1 or value.rows > 50000 or value.from_ts > value.to_ts
       or value.created_at > value.expires_at then
        return nil, path .. " has inconsistent bounds"
    end
    return value
end

local function dirname(path)
    return path:match("^(.*)/[^/]+$") or "."
end

local function row_candidates(fields)
    local hits = {}
    for i = 1, #AXES do
        local axis = AXES[i]
        for j = 1, #axis.fields do
            if fields[axis.fields[j]] == "true" then
                hits[axis.name] = true
                break
            end
        end
    end
    return hits
end

local function rejected(action)
    return action == "block" or action == "challenge" or action == "throttled"
end

local function replay_one(manifest_path, now, totals)
    local value, err = read_json(manifest_path)
    if not value then return nil, err end
    local manifest, valid_err = validate_manifest(value, manifest_path)
    if not manifest then return nil, valid_err end
    if manifest.expires_at < now then
        totals.expired = totals.expired + 1
        io.write("incident=", manifest.id, " label=", manifest.label,
                 " state=expired rows=", manifest.rows, "\n")
        return true
    end

    local evidence_path = dirname(manifest_path) .. "/" .. manifest.evidence_file
    local fh, open_err = io.open(evidence_path, "rb")
    if not fh then return nil, "cannot read " .. evidence_path .. ": " .. tostring(open_err) end

    local seen_rows, candidate_rows, actual_rejects = 0, 0, 0
    local axis_counts = {}
    local capacity_security = 0
    for line in fh:lines() do
        local fields = parse_fields(line)
        seen_rows = seen_rows + 1
        local hits = row_candidates(fields)
        local any = false
        for axis in pairs(hits) do
            any = true
            axis_counts[axis] = (axis_counts[axis] or 0) + 1
            totals.axes[axis] = (totals.axes[axis] or 0) + 1
        end
        if any then candidate_rows = candidate_rows + 1 end
        if rejected(fields.action) then actual_rejects = actual_rejects + 1 end
        if manifest.label == "capacity_only"
           and (fields.dkind == "security" or fields.dkind == "challenge")
           and rejected(fields.action) then
            capacity_security = capacity_security + 1
        end
    end
    fh:close()
    if seen_rows ~= manifest.rows then
        return nil, manifest.id .. " row count changed after capture"
    end

    totals.active = totals.active + 1
    local label_totals = totals.labels[manifest.label]
    label_totals.incidents = label_totals.incidents + 1
    label_totals.rows = label_totals.rows + seen_rows
    label_totals.candidates = label_totals.candidates + candidate_rows
    label_totals.actual_rejects = label_totals.actual_rejects + actual_rejects
    label_totals.capacity_security = label_totals.capacity_security + capacity_security
    if manifest.label == "human_fp" and candidate_rows > 0 then
        totals.human_fp_candidate_rows = totals.human_fp_candidate_rows + candidate_rows
    end

    local axis_tokens = {}
    for _, axis in ipairs(sorted_keys(axis_counts)) do
        axis_tokens[#axis_tokens + 1] = axis .. ":" .. tostring(axis_counts[axis])
    end
    io.write("incident=", manifest.id, " label=", manifest.label,
             " state=active rows=", seen_rows,
             " actual_rejects=", actual_rejects,
             " candidate_rows=", candidate_rows,
             " axes=", (#axis_tokens > 0 and table.concat(axis_tokens, ",") or "-"),
             "\n")
    return true
end

local function command_replay(now, paths)
    now = tonumber(now)
    if not now then return die("replay requires numeric now") end
    if #paths == 0 then
        io.write("REPLAY_NO_DATA active=0 expired=0\n")
        return true
    end
    local totals = {
        active = 0, expired = 0, human_fp_candidate_rows = 0, axes = {}, labels = {},
    }
    for label in pairs(LABELS) do
        totals.labels[label] = {
            incidents = 0, rows = 0, candidates = 0,
            actual_rejects = 0, capacity_security = 0,
        }
    end
    for i = 1, #paths do
        local ok, err = replay_one(paths[i], now, totals)
        if not ok then return die(err) end
    end
    for _, label in ipairs({ "true_bot", "legit_automation", "human_fp", "capacity_only" }) do
        local s = totals.labels[label]
        io.write("label=", label, " incidents=", s.incidents,
                 " rows=", s.rows, " candidates=", s.candidates,
                 " actual_rejects=", s.actual_rejects,
                 " capacity_security=", s.capacity_security, "\n")
    end
    for _, axis in ipairs(sorted_keys(totals.axes)) do
        io.write("axis=", axis, " candidate_rows=", totals.axes[axis], "\n")
    end
    if totals.labels.human_fp.rows == 0 then
        io.write("REPLAY_COVERAGE human_fp=0 note=no_false_positive_claim\n")
    end
    if totals.human_fp_candidate_rows > 0 then
        io.write("REPLAY_BLOCK human_fp_candidate_rows=",
                 totals.human_fp_candidate_rows, "\n")
        return "blocked"
    end
    io.write("REPLAY_OK active=", totals.active, " expired=", totals.expired,
             " human_fp_candidate_rows=0\n")
    return true
end

local function command_list(now, paths)
    now = tonumber(now)
    if not now then return die("list requires numeric now") end
    local active, expired = 0, 0
    local labels = {}
    for label in pairs(LABELS) do labels[label] = 0 end
    for i = 1, #paths do
        local value, err = read_json(paths[i])
        if not value then return die(err) end
        local manifest, valid_err = validate_manifest(value, paths[i])
        if not manifest then return die(valid_err) end
        local state = manifest.expires_at < now and "expired" or "active"
        if state == "active" then active = active + 1; labels[manifest.label] = labels[manifest.label] + 1
        else expired = expired + 1 end
        io.write("incident=", manifest.id, " label=", manifest.label,
                 " state=", state, " rows=", manifest.rows,
                 " from=", manifest.from_ts, " to=", manifest.to_ts,
                 " expires=", manifest.expires_at, " actor=", manifest.actor, "\n")
    end
    io.write("feedback active=", active, " expired=", expired)
    for _, label in ipairs({ "true_bot", "legit_automation", "human_fp", "capacity_only" }) do
        io.write(" ", label, "=", labels[label])
    end
    io.write("\n")
    return true
end

local command = arg[1]
local success
if command == "manifest" then
    success = manifest_from_env()
elseif command == "replay" then
    local paths = {}
    for i = 3, #arg do paths[#paths + 1] = arg[i] end
    success = command_replay(arg[2], paths)
elseif command == "list" then
    local paths = {}
    for i = 3, #arg do paths[#paths + 1] = arg[i] end
    success = command_list(arg[2], paths)
else
    success = die("usage: feedback_tool.lua manifest | replay <now> <manifest...> | list <now> <manifest...>")
end

-- `resty` exit status is not trusted by the shell wrapper; exact markers are
-- authoritative.  Still return non-zero where the runtime propagates it.
if success == false or success == "blocked" then os.exit(1) end
