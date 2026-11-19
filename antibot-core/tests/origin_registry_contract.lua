local pass, fail = 0, 0
local cjson = require "cjson"
local function ok(v, name)
    if v then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL origin_registry: ", name, "\n") end
end
local function eq(got, want, name)
    ok(got == want, name .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local src = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1) ~= "/" then src = src .. "/" end
local loader = function(name)
    local rel = name:match("^antibot%.(.+)$")
    if not rel then return nil end
    rel = rel:gsub("%.", "/")
    return loadfile(src .. rel .. ".lua") or loadfile(src .. rel .. "/init.lua")
end
table.insert(package.loaders, 1, loader)

local old_ngx = _G.ngx
local old_pool = package.loaded["antibot.core.redis_pool"]
local cache, warnings = {}, {}
local now = 1000
local dict = {
    get = function(_, k) return cache[k] end,
    set = function(_, k, v) cache[k] = v; return true end,
    delete = function(_, k) cache[k] = nil end,
}
_G.ngx = {
    null = {}, ERR = 3, WARN = 4,
    time = function() return now end,
    shared = { antibot_cache = dict },
    timer = { at = function() return true end, every = function() return true end },
    log = function(_, ...)
        local parts = {...}
        for i = 1, #parts do parts[i] = tostring(parts[i]) end
        warnings[#warnings + 1] = table.concat(parts)
    end,
}

local redis_data, members, mget_calls = {}, {}, 0
local red = {
    multi = function() return "OK" end,
    sadd = function(_, _, value) members[value] = true; return 1 end,
    set = function(_, key, value) redis_data[key] = value; return "OK" end,
    exec = function() return {1, "OK"} end,
    get = function(_, key) return redis_data[key] or ngx.null end,
    mget = function(_, ...)
        mget_calls = mget_calls + 1
        local out, keys = {}, {...}
        for i = 1, #keys do out[i] = redis_data[keys[i]] or ngx.null end
        return out
    end,
    smembers = function()
        local out = {}; for value in pairs(members) do out[#out + 1] = value end
        return out
    end,
}
package.loaded["antibot.core.redis_pool"] = {
    get = function() return red end,
    put = function() end,
}
package.loaded["antibot.core.origin_registry"] = nil
local registry = require "antibot.core.origin_registry"
local gen = "0123456789abcdef0123456789abcdef"

local pending = {
    rule="cloudflare", zone="example.test", state="pending",
    generation=gen, revision=1, updated_at=now, updated_by="admin",
}
local saved = registry.persist(red, pending)
ok(saved, "pending state persists")
local active, reason = registry.check("cloudflare", "example.test", gen)
eq(active, nil, "pending token is not authorized")
eq(reason, "pending", "pending reason")
eq(registry.was_seen("cloudflare", "example.test", gen), false, "unseen initially")
ok(registry.observe_pending("cloudflare", "example.test", gen), "pending observation")
eq(registry.was_seen("cloudflare", "example.test", gen), true, "seen becomes true")

local wrong = "ffffffffffffffffffffffffffffffff"
active, reason = registry.check("cloudflare", "example.test", wrong)
eq(active, nil, "old generation rejected")
eq(reason, "generation_mismatch", "generation mismatch reason")

local active_state = {
    rule="cloudflare", zone="example.test", state="active",
    generation=gen, revision=2, updated_at=now+1, updated_by="admin",
}
ok(registry.persist(red, active_state), "active state persists")
eq(registry.check("cloudflare", "example.test", gen), true, "active exact generation")

-- A stale timer result cannot roll back a newer Admin mutation.
registry.set_local(pending)
local current = registry.get("cloudflare", "example.test")
eq(current.state, "active", "lower revision cannot overwrite local state")

local revoked = {
    rule="cloudflare", zone="example.test", state="revoked",
    generation=gen, revision=3, updated_at=now+2, updated_by="admin",
}
ok(registry.persist(red, revoked), "revoked state persists")
active, reason = registry.check("cloudflare", "example.test", gen)
eq(active, nil, "revoked token rejected")
eq(reason, "revoked", "revoked reason")

local listed = registry.list(red)
eq(#listed, 1, "registry list returns one zone")
eq(listed[1].state, "revoked", "registry list current state")
eq(mget_calls, 1, "registry list uses one MGET round-trip")

-- The Redis set/key says good.test, while the signed payload claims another
-- zone. Never let payload identity override the key that selected it.
members["cloudflare|good.test"] = true
redis_data["proxy:origin:zone:cloudflare:good.test"] = cjson.encode({
    schema=1, rule="cloudflare", zone="attacker.test", state="active",
    generation=gen, revision=9, updated_at=now+9, updated_by="fixture",
})
warnings = {}
listed = registry.list(red)
eq(#listed, 1, "mismatched persisted zone is not loaded")
ok(#warnings == 1
   and warnings[1]:find("invalid persisted record key=", 1, true) ~= nil
   and warnings[1]:find("cloudflare:good.test", 1, true) ~= nil,
   "mismatched persisted zone emits warning")

local bad = registry._validate_state_for_test({
    rule="cloudflare", zone="evil_example.test", state="active",
    generation=gen,
})
eq(bad, nil, "invalid DNS zone rejected")

package.loaded["antibot.core.origin_registry"] = nil
package.loaded["antibot.core.redis_pool"] = old_pool
for i=#package.loaders,1,-1 do if package.loaders[i] == loader then table.remove(package.loaders,i) end end
_G.ngx = old_ngx

print(("origin_registry_contract: %d qua, %d hong"):format(pass, fail))
if fail > 0 then os.exit(1) end
