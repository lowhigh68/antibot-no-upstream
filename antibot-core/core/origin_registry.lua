-- Runtime registry for host-bound reverse-proxy proofs.
--
-- Redis is the durable control plane.  The request path never opens Redis: it
-- reads one compact record from the existing `antibot_cache` shared dict.
-- Cryptographic validity alone is deliberately insufficient; a token must
-- also name the currently active generation for its (rule, zone).

local _M = {}

local cjson = require "cjson.safe"
local pool  = require "antibot.core.redis_pool"

local SET_KEY      = "proxy:origin:zones"
local REDIS_PREFIX = "proxy:origin:zone:"
local SH_PREFIX    = "oproxy:zone:"
local SEEN_PREFIX  = "oproxy:seen:"
local INDEX_KEY    = "oproxy:index"
local SEEN_TTL     = 86400
local SYNC_SECONDS = 60

local function dict()
    return ngx and ngx.shared and ngx.shared.antibot_cache or nil
end

local function normalize_name(value)
    return tostring(value or ""):lower():gsub("%.$", "")
end

local function valid_dns_name(value)
    if type(value) ~= "string" or #value < 1 or #value > 253 then return false end
    if value:find("..", 1, true) or value:sub(1, 1) == "." then return false end
    for label in value:gmatch("[^.]+") do
        if #label > 63
           or (not label:match("^[a-z0-9][a-z0-9%-]*[a-z0-9]$")
               and not label:match("^[a-z0-9]$")) then
            return false
        end
    end
    return true
end

local function normalize_rule(value)
    value = tostring(value or ""):lower()
    if #value < 1 or #value > 64
       or not value:match("^[a-z0-9][a-z0-9_%-]*$") then
        return nil
    end
    return value
end

local function valid_generation(value)
    return type(value) == "string" and #value == 32
       and value:match("^[0-9a-f]+$") ~= nil
end

local function member(rule, zone)
    return rule .. "|" .. zone
end

local function shared_key(rule, zone)
    return SH_PREFIX .. rule .. ":" .. zone
end

local function redis_key(rule, zone)
    return REDIS_PREFIX .. rule .. ":" .. zone
end

local function seen_key(rule, zone, generation)
    return SEEN_PREFIX .. rule .. ":" .. zone .. ":" .. generation
end

local function validate_state(state)
    if type(state) ~= "table" then return nil, "state" end
    local rule = normalize_rule(state.rule)
    local zone = normalize_name(state.zone)
    local status = tostring(state.state or "")
    local generation = tostring(state.generation or ""):lower()
    if not rule then return nil, "rule" end
    if not valid_dns_name(zone) then return nil, "zone" end
    if status ~= "pending" and status ~= "active" and status ~= "revoked" then
        return nil, "status"
    end
    if not valid_generation(generation) then return nil, "generation" end
    return {
        schema     = 1,
        rule       = rule,
        zone       = zone,
        state      = status,
        generation = generation,
        revision   = math.max(tonumber(state.revision) or 1, 1),
        updated_at = tonumber(state.updated_at) or 0,
        updated_by = tostring(state.updated_by or "-"):sub(1, 128),
    }
end

function _M.get(rule, zone)
    rule = normalize_rule(rule)
    zone = normalize_name(zone)
    if not rule or not valid_dns_name(zone) then return nil, "invalid" end
    local d = dict()
    if not d then return nil, "registry_unavailable" end
    local raw = d:get(shared_key(rule, zone))
    if not raw then return nil, "registry_missing" end
    local state = cjson.decode(raw)
    state = validate_state(state)
    if not state then return nil, "registry_corrupt" end
    return state
end

function _M.check(rule, zone, generation)
    local state, err = _M.get(rule, zone)
    if not state then return nil, err end
    if state.generation ~= generation then return nil, "generation_mismatch", state end
    if state.state ~= "active" then return nil, state.state, state end
    return true, "active", state
end

function _M.set_local(raw_state)
    local state, err = validate_state(raw_state)
    if not state then return nil, err end
    local d = dict()
    if not d then return nil, "registry_unavailable" end

    -- A slower periodic sync must not overwrite a newer Admin mutation.
    local current = _M.get(state.rule, state.zone)
    if current and (current.revision or 0) > state.revision then
        return true, "newer_local"
    end
    local encoded = cjson.encode(state)
    if not encoded then return nil, "encode" end
    local ok, set_err = d:set(shared_key(state.rule, state.zone), encoded)
    if not ok then return nil, set_err or "shared_set" end
    return true, state
end

function _M.observe_pending(rule, zone, generation)
    local state = _M.get(rule, zone)
    if not state or state.state ~= "pending"
       or state.generation ~= generation then return false end
    local d = dict()
    if not d then return false end
    return d:set(seen_key(state.rule, state.zone, generation), ngx.time(), SEEN_TTL)
       and true or false
end

function _M.was_seen(rule, zone, generation)
    rule = normalize_rule(rule)
    zone = normalize_name(zone)
    if not rule or not valid_dns_name(zone) or not valid_generation(generation) then
        return false
    end
    local d = dict()
    return d and d:get(seen_key(rule, zone, generation)) ~= nil or false
end

function _M.persist(red, raw_state)
    local state, err = validate_state(raw_state)
    if not state then return nil, err end
    local payload = cjson.encode(state)
    if not payload then return nil, "encode" end

    local ok, tx_err = red:multi()
    if not ok then return nil, tx_err or "multi" end
    red:sadd(SET_KEY, member(state.rule, state.zone))
    red:set(redis_key(state.rule, state.zone), payload)
    local replies, exec_err = red:exec()
    if not replies then return nil, exec_err or "exec" end
    local local_ok, local_err = _M.set_local(state)
    if not local_ok then return nil, local_err end
    return true, state
end

function _M.read(red, rule, zone)
    rule = normalize_rule(rule)
    zone = normalize_name(zone)
    if not rule or not valid_dns_name(zone) then return nil, "invalid" end
    local raw, err = red:get(redis_key(rule, zone))
    if not raw or raw == ngx.null then return nil, err or "missing" end
    local value = cjson.decode(raw)
    local state, state_err = validate_state(value)
    if not state then return nil, state_err end
    if state.rule ~= rule or state.zone ~= zone then return nil, "key_mismatch" end
    return state
end

function _M.list(red)
    local members, err = red:smembers(SET_KEY)
    if not members then return nil, err or "smembers" end
    if members == ngx.null then return {}, nil end
    local refs, keys = {}, {}
    for i = 1, #members do
        local rule, zone = tostring(members[i]):match("^([^|]+)|(.+)$")
        rule = normalize_rule(rule)
        zone = normalize_name(zone)
        if rule and valid_dns_name(zone) then
            refs[#refs + 1] = { rule = rule, zone = zone }
            keys[#keys + 1] = redis_key(rule, zone)
        end
    end
    if #keys == 0 then return {} end

    -- One round-trip independent of zone count. The root caller MUST guard
    -- start() with worker_id == 0; this module intentionally owns no worker
    -- election. Admin also calls list(); the request hot path never reaches Redis.
    local values, mget_err = red:mget(unpack(keys))
    if not values then return nil, mget_err or "mget" end
    local out = {}
    for i = 1, #refs do
        local raw = values[i]
        if raw and raw ~= ngx.null then
            local state = validate_state(cjson.decode(raw))
            if state and state.rule == refs[i].rule and state.zone == refs[i].zone then
                state.seen = _M.was_seen(state.rule, state.zone, state.generation)
                out[#out + 1] = state
            else
                ngx.log(ngx.WARN, "[origin_registry] invalid persisted record key=",
                        keys[i])
            end
        end
    end
    table.sort(out, function(a, b)
        if a.rule == b.rule then return a.zone < b.zone end
        return a.rule < b.rule
    end)
    return out
end

function _M.sync_from_redis()
    local red, err = pool.get()
    if not red then return nil, err or "redis" end
    local states, list_err = _M.list(red)
    pool.put(red)
    if not states then return nil, list_err end

    local d = dict()
    if not d then return nil, "registry_unavailable" end
    local old_index = tostring(d:get(INDEX_KEY) or "")
    local keep, next_index = {}, {}
    for i = 1, #states do
        local state = states[i]
        local key = shared_key(state.rule, state.zone)
        keep[key] = true
        next_index[#next_index + 1] = key
        _M.set_local(state)
    end
    for key in old_index:gmatch("[^\n]+") do
        if not keep[key] then d:delete(key) end
    end
    d:set(INDEX_KEY, table.concat(next_index, "\n"))
    return true, #states
end

local function sync_timer(premature)
    if premature then return end
    local ok, count_or_err = _M.sync_from_redis()
    if not ok then
        ngx.log(ngx.ERR, "[origin_registry] sync failed: ", tostring(count_or_err))
    end
end

function _M.start()
    local ok, err = ngx.timer.at(0, sync_timer)
    if not ok then return nil, err end
    local every_ok, every_err = ngx.timer.every(SYNC_SECONDS, sync_timer)
    if not every_ok then return nil, every_err end
    return true
end

_M._validate_state_for_test = validate_state
_M._shared_key_for_test = shared_key
_M._seen_key_for_test = seen_key

return _M
