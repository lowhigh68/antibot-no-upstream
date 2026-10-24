-- Offline policy artifact tool.  It is never required by an nginx worker.
--
-- Commands:
--   validate <candidate.lua|candidate.json> <normalized.json>
--   promote  <normalized.json> <state-dir>
--   rollback <state-dir>
--
-- policyctl.sh supplies the mandatory full regression gate between validate
-- and promote.  All target writes use a temp file in the target directory,
-- fsync it, then os.rename it over the pointer file.
local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
table.insert(package.loaders, 1, function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    local errors = {}
    for _, path in ipairs({ SRC .. rel .. ".lua", SRC .. rel .. "/init.lua" }) do
        local chunk, err = loadfile(path)
        if chunk then return chunk end
        errors[#errors + 1] = err
    end
    return table.concat(errors, "\n")
end)

local cjson = require "cjson.safe"
local policy = require "antibot.core.policy"
local store = require "antibot.core.policy_store"

local function die(message)
    io.stderr:write("POLICY_ERROR ", tostring(message), "\n")
    return false
end

local function read_bounded(path)
    local fh, err = io.open(path, "rb")
    if not fh then return nil, "cannot read " .. path .. ": " .. tostring(err) end
    local raw = fh:read(store.max_bytes() + 1)
    fh:close()
    if not raw or raw == "" then return nil, path .. " is empty" end
    if #raw > store.max_bytes() then return nil, path .. " is too large" end
    return raw
end

local function read_json(path)
    local raw, err = read_bounded(path)
    if not raw then return nil, err end
    local value, decode_err = cjson.decode(raw)
    if value == nil then return nil, "invalid JSON: " .. tostring(decode_err) end
    return value
end

local function read_candidate(path)
    if path:lower():match("%.json$") then return read_json(path) end
    local chunk, load_err = loadfile(path)
    if not chunk then return nil, "cannot load candidate: " .. tostring(load_err) end
    local ok, value = pcall(chunk)
    if not ok then return nil, "candidate raised an error: " .. tostring(value) end
    if type(value) ~= "table" then return nil, "candidate must return a table" end
    return value
end

local function validation_error(errors)
    if type(errors) ~= "table" then return tostring(errors) end
    local out = {}
    for i = 1, #errors do out[#out + 1] = tostring(errors[i]) end
    return table.concat(out, "; ")
end

local function encode(value)
    local ok, raw = pcall(cjson.encode, value)
    if not ok or not raw then return nil, tostring(raw) end
    return raw .. "\n"
end

local function write_plain(path, raw)
    local fh, err = io.open(path, "wb")
    if not fh then return nil, "cannot create " .. path .. ": " .. tostring(err) end
    local ok, write_err = fh:write(raw)
    if ok then ok, write_err = fh:flush() end
    local close_ok, close_err = fh:close()
    if not ok then return nil, "cannot write " .. path .. ": " .. tostring(write_err) end
    if not close_ok then return nil, "cannot close " .. path .. ": " .. tostring(close_err) end
    return true
end

local ffi_ok, ffi = pcall(require, "ffi")
if ffi_ok then
    ffi.cdef[[
        int open(const char *pathname, int flags, ...);
        int close(int fd);
        int fsync(int fd);
        int chmod(const char *pathname, unsigned int mode);
    ]]
end
local O_RDONLY, O_DIRECTORY = 0, 65536

local function fsync_path(path, directory)
    if not ffi_ok then return nil, "LuaJIT FFI is required for durable promotion" end
    local flags = directory and (O_RDONLY + O_DIRECTORY) or O_RDONLY
    local fd = ffi.C.open(path, flags)
    if fd < 0 then return nil, "cannot open for fsync: " .. path end
    local rc = ffi.C.fsync(fd)
    ffi.C.close(fd)
    if rc ~= 0 then return nil, "fsync failed: " .. path end
    return true
end

local function dirname(path)
    return path:match("^(.*)/[^/]+$") or "."
end

local nonce = 0
local function atomic_write(path, raw)
    nonce = nonce + 1
    local tmp = path .. ".tmp." .. tostring(os.time()) .. "."
        .. tostring(nonce) .. "." .. tostring(math.random(100000, 999999))
    local ok, err = write_plain(tmp, raw)
    if not ok then return nil, err end
    if ffi_ok then ffi.C.chmod(tmp, 416) end -- 0640
    ok, err = fsync_path(tmp, false)
    if not ok then os.remove(tmp); return nil, err end
    local renamed, rename_err = os.rename(tmp, path)
    if not renamed then
        os.remove(tmp)
        return nil, "cannot rename " .. tmp .. " to " .. path .. ": "
            .. tostring(rename_err)
    end
    ok, err = fsync_path(dirname(path), true)
    if not ok then return nil, err end
    return true
end

local function valid_json_bytes(path)
    local value, err = read_json(path)
    if not value then return nil, err end
    local compiled, compile_err = policy.compile(value)
    if not compiled then return nil, validation_error(compile_err) end
    local raw, encode_err = encode(value)
    if not raw then return nil, encode_err end
    return raw, compiled.policy_version
end

local function command_validate(candidate_path, output_path)
    local value, err = read_candidate(candidate_path)
    if not value then return die(err) end
    local compiled, errors = policy.compile(value)
    if not compiled then return die(validation_error(errors)) end
    local raw, encode_err = encode(value)
    if not raw then return die(encode_err) end
    local ok, write_err = write_plain(output_path, raw)
    if not ok then return die(write_err) end
    io.write("POLICY_VALID version=", compiled.policy_version, "\n")
    return true
end

local function command_promote(candidate_path, state_dir)
    local candidate_raw, version_or_err = valid_json_bytes(candidate_path)
    if not candidate_raw then return die(version_or_err) end
    local active = state_dir .. "/active.json"
    local lkg = state_dir .. "/last-good.json"

    -- Preserve only a currently valid active artifact.  If it is corrupt,
    -- retain an already valid LKG; if neither exists this is first bootstrap,
    -- so seed LKG with the tested candidate before publishing active.
    local lkg_raw = valid_json_bytes(active)
    if not lkg_raw then lkg_raw = valid_json_bytes(lkg) end
    if not lkg_raw then lkg_raw = candidate_raw end

    local ok, err = atomic_write(lkg, lkg_raw)
    if not ok then return die("cannot persist LKG: " .. tostring(err)) end
    ok, err = atomic_write(active, candidate_raw)
    if not ok then return die("cannot publish active: " .. tostring(err)) end
    io.write("POLICY_PROMOTED version=", version_or_err, "\n")
    return true
end

local function command_rollback(state_dir)
    local lkg = state_dir .. "/last-good.json"
    local active = state_dir .. "/active.json"
    local raw, version_or_err = valid_json_bytes(lkg)
    if not raw then return die("invalid LKG: " .. tostring(version_or_err)) end
    local ok, err = atomic_write(active, raw)
    if not ok then return die("cannot restore active: " .. tostring(err)) end
    io.write("POLICY_ROLLED_BACK version=", version_or_err, "\n")
    return true
end

local command, first, second = arg[1], arg[2], arg[3]
local success
if command == "validate" and first and second then
    success = command_validate(first, second)
elseif command == "promote" and first and second then
    success = command_promote(first, second)
elseif command == "rollback" and first then
    success = command_rollback(first)
else
    success = die("usage: policy_tool.lua validate <candidate> <normalized.json> | "
        .. "promote <normalized.json> <state-dir> | rollback <state-dir>")
end

-- Some `resty` builds return zero even after os.exit/error.  policyctl.sh does
-- not trust this status; it requires the exact success marker emitted above.
if not success then os.exit(1) end
