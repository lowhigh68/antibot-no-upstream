local _M = {}

local cjson     = require "cjson"
local random    = require "resty.random"
local pool      = require "antibot.core.redis_pool"
local inventory = require "antibot.core.domain_inventory"
local registry  = require "antibot.core.origin_registry"
local proof     = require "antibot.core.origin_proof"
local security  = require "antibot.admin.security"

local RULE = "cloudflare"

local function reply(status, value)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(cjson.encode(value))
end

local function generation()
    local bytes, err = random.bytes(16, true)
    if not bytes or #bytes ~= 16 then return nil, err or "secure random unavailable" end
    return (bytes:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function load_inventory()
    local entries, err, source = inventory.load()
    return entries or {}, err, source
end

function _M.render()
    local domains, inv_err, source = load_inventory()
    local red, redis_err = pool.get()
    if not red then
        return reply(503, {
            ok = false, error = "Redis: " .. tostring(redis_err),
            inventory_ok = inv_err == nil, inventory_error = inv_err,
        })
    end
    local states, state_err = registry.list(red)
    pool.put(red)
    if not states then
        return reply(503, { ok = false, error = tostring(state_err) })
    end

    local by_zone, present = {}, {}
    for i = 1, #states do
        if states[i].rule == RULE then by_zone[states[i].zone] = states[i] end
    end
    for i = 1, #domains do
        local item = domains[i]
        present[item.domain] = true
        local state = by_zone[item.domain]
        item.proxy_state = state and state.state or "off"
        item.generation = state and state.generation or nil
        item.seen = state and state.seen or false
        item.updated_at = state and state.updated_at or nil
    end
    local orphaned = {}
    for zone, state in pairs(by_zone) do
        if not present[zone] then orphaned[#orphaned + 1] = state end
    end
    table.sort(orphaned, function(a, b) return a.zone < b.zone end)
    return reply(200, {
        ok = true,
        inventory_ok = inv_err == nil,
        inventory_error = inv_err,
        inventory_source = source,
        domains = domains,
        orphaned = orphaned,
    })
end

local function next_state(old, status, gen, principal)
    return {
        schema = 1,
        rule = RULE,
        zone = old and old.zone or nil,
        state = status,
        generation = gen,
        revision = (old and tonumber(old.revision) or 0) + 1,
        updated_at = ngx.time(),
        updated_by = principal and principal.username or "admin",
    }
end

local function persist(red, state)
    local ok, err = registry.persist(red, state)
    if not ok then return nil, tostring(err) end
    return true
end

function _M.mutate(principal)
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    local ok_json, req = pcall(cjson.decode, body)
    if not ok_json or type(req) ~= "table" then
        security.audit(principal, "proxy_invalid_json", "-", "denied", "-", "-")
        return reply(400, { ok = false, error = "Invalid JSON" })
    end
    local valid, validation_err = security.validate_payload(req, #body)
    if not valid then
        security.audit(principal, req.action or "-", req.zone or "-",
                       "denied", "-", validation_err)
        return reply(validation_err == "mutation body too large" and 413 or 400,
                     { ok = false, error = validation_err })
    end

    local domains, inv_err = load_inventory()
    local zone = tostring(req.zone or ""):lower():gsub("%.$", "")
    local red, redis_err = pool.get()
    if not red then
        security.audit(principal, req.action, zone, "redis_error", "-", "-")
        return reply(503, { ok = false, error = "Redis: " .. tostring(redis_err) })
    end
    local old = registry.read(red, RULE, zone)
    local before = old and (old.state .. ":" .. old.generation:sub(1, 8)) or "off"
    local result, status = nil, 200

    if req.action == "proxy_cf_enable" then
        if inv_err then
            result, status = { ok = false, error = inv_err }, 503
        elseif not inventory.contains(domains, zone) then
            result, status = { ok = false, error = "zone is not in DirectAdmin inventory" }, 400
        elseif old and old.state == "active" then
            result, status = { ok = false, error = "zone is already active" }, 409
        else
            local gen = old and old.state == "pending" and old.generation or nil
            if not gen then gen = generation() end
            if not gen then
                result, status = { ok = false, error = "secure random unavailable" }, 503
            else
                local state = next_state(old, "pending", gen, principal)
                state.zone = zone
                local saved, save_err = persist(red, state)
                if not saved then
                    result, status = { ok = false, error = save_err }, 503
                else
                    local token, token_err = proof.issue(zone, RULE, gen)
                    if not token then
                        result, status = { ok = false, error = token_err }, 503
                    else
                        result = {
                            ok = true, state = "pending", zone = zone,
                            generation = gen, token = token,
                            header = "X-Antibot-Origin-Proof",
                            instruction = "Cloudflare must OVERWRITE this header, then wait for seen=true before Activate",
                        }
                    end
                end
            end
        end
    elseif req.action == "proxy_cf_activate" then
        if not old or old.state ~= "pending" then
            result, status = { ok = false, error = "zone is not pending" }, 409
        elseif not registry.was_seen(RULE, zone, old.generation) then
            result, status = { ok = false, error = "token has not been observed through Cloudflare" }, 409
        else
            local state = next_state(old, "active", old.generation, principal)
            state.zone = zone
            local saved, save_err = persist(red, state)
            if not saved then result, status = {ok=false,error=save_err}, 503
            else result = {ok=true,state="active",zone=zone,generation=old.generation} end
        end
    elseif req.action == "proxy_cf_disable" then
        if not old then
            result, status = { ok = false, error = "zone has no registry record" }, 404
        elseif old.state == "revoked" then
            result = { ok = true, state = "revoked", zone = zone }
        else
            local state = next_state(old, "revoked", old.generation, principal)
            state.zone = zone
            local saved, save_err = persist(red, state)
            if not saved then result, status = {ok=false,error=save_err}, 503
            else result = {ok=true,state="revoked",zone=zone} end
        end
    end

    pool.put(red)
    local after = result and result.state or (result and result.error) or "unknown"
    security.audit(principal, req.action, zone,
                   result and result.ok and "ok" or "denied", before, after)
    return reply(status, result or { ok = false, error = "unsupported action" })
end

return _M
