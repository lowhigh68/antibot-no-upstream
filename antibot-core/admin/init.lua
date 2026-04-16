local _M = {}
local pool = require "antibot.core.redis_pool"
local cjson = require "cjson"

local AUTH_USER = "admin-antibot"
local AUTH_PASS = "Vungoimora@6868@2025"

local function auth()
    local h = ngx.req.get_headers()["authorization"]
    if not h then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot v4.3.6"'
        ngx.exit(401); return false
    end
    local encoded = h:match("Basic%s+(.+)")
    local decoded = ngx.decode_base64(encoded or "")
    if decoded ~= AUTH_USER .. ":" .. AUTH_PASS then
        ngx.header["WWW-Authenticate"] = 'Basic realm="AntiBot v4.3.6"'
        ngx.exit(401); return false
    end
    return true
end

local function scan_keys(red, pattern, limit)
    local cursor, results, scanned = "0", {}, 0
    limit = limit or 500
    repeat
        local res = red:scan(cursor, "MATCH", pattern, "COUNT", 100)
        if not res then break end
        cursor = res[1]
        for _, k in ipairs(res[2]) do
            table.insert(results, k)
            scanned = scanned + 1
            if scanned >= limit then return results end
        end
    until cursor == "0"
    return results
end

local function time_ago(ts)
    if not ts then return "-" end
    local diff = ngx.time() - tonumber(ts)
    if diff < 60 then return diff.."s ago"
    elseif diff < 3600 then return math.floor(diff/60).."m ago"
    else return math.floor(diff/3600).."h ago" end
end

local function handle_whitelist_api()
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    local ok, req = pcall(cjson.decode, body)
    if not ok or not req then
        ngx.status = 400
        ngx.say(cjson.encode({error="Invalid JSON"}))
        return
    end

    local red, err = pool.get()
    if not red then
        ngx.status = 500
        ngx.say(cjson.encode({error="Redis: "..tostring(err)}))
        return
    end

    local action = req.action
    local result = {}

    if action == "wl_ip_add" and req.ip then
        red:set("wl:" .. req.ip, "1")
        red:del("ban:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." whitelisted & unbanned"}

    elseif action == "wl_ip_del" and req.ip then
        red:del("wl:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." removed from whitelist"}

    elseif action == "unban_ip" and req.ip then
        red:del("ban:" .. req.ip)
        red:del("rep:" .. req.ip)
        result = {ok=true, msg="IP "..req.ip.." unbanned"}

    elseif action == "unban_id" and req.id then
        local id = req.id
        red:del("ban:"      .. id)
        red:del("risk:"     .. id)
        red:del("viol:"     .. id)
        red:del("verified:" .. id)
        result = {ok=true, msg="Identity "..id:sub(1,16).."... unbanned & cleared"}

    elseif action == "wl_url_add" and req.prefix then
        local prefix = req.prefix
        red:sadd("wl:url_set", prefix)
        local members = red:smembers("wl:url_set") or {}
        red:set("wl:url_list", table.concat(members, "\n"))
        result = {ok=true, msg="URL prefix '"..prefix.."' whitelisted"}

    elseif action == "wl_url_del" and req.prefix then
        local prefix = req.prefix
        red:srem("wl:url_set", prefix)
        local members = red:smembers("wl:url_set") or {}
        red:set("wl:url_list", table.concat(members, "\n"))
        result = {ok=true, msg="URL prefix '"..prefix.."' removed"}

    elseif action == "ua_add" and req.pattern then
        local pat = req.pattern
        red:sadd("badbot:ua_custom_set", pat)
        red:del("badbot:ua_patterns")
        result = {ok=true, msg="Bad bot pattern '"..pat.."' added. Cache cleared."}

    elseif action == "ua_del" and req.pattern then
        local pat = req.pattern
        red:srem("badbot:ua_custom_set", pat)
        red:del("badbot:ua_patterns")
        result = {ok=true, msg="Pattern '"..pat.."' removed. Cache cleared."}

    elseif action == "goodbot_dns_add" and req.name and req.suffixes then
        red:set("goodbot:dns:" .. req.name:lower(), req.suffixes)
        result = {ok=true, msg="Good bot DNS: "..req.name.." → "..req.suffixes}

    elseif action == "goodbot_dns_del" and req.name then
        red:del("goodbot:dns:" .. req.name:lower())
        result = {ok=true, msg="Good bot DNS removed: "..req.name}

    elseif action == "asn_type_set" and req.asn and req.itype then
        red:set("asn:type:" .. req.asn, req.itype)
        result = {ok=true, msg="ASN "..req.asn.." type → "..req.itype}

    elseif action == "asn_type_del" and req.asn then
        red:del("asn:type:" .. req.asn)
        result = {ok=true, msg="ASN "..req.asn.." type override removed"}

    elseif action == "ja3_allow" and req.hash then
        red:set("ja3:allow:" .. req.hash, "1")
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... added to allowlist"}

    elseif action == "ja3_block" and req.hash then
        red:set("ja3:block:" .. req.hash, "1")
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... added to blocklist"}

    elseif action == "ja3_remove" and req.hash then
        red:del("ja3:allow:" .. req.hash)
        red:del("ja3:block:" .. req.hash)
        result = {ok=true, msg="JA3 "..req.hash:sub(1,8).."... removed"}

    elseif action == "ua_sync" then
        local ok2 = os.execute(
            "bash /usr/local/openresty/nginx/conf/scripts/ua_sync.sh > " ..
            "/var/log/ua_sync.log 2>&1 &")
        result = {ok=true, msg="UA sync triggered. Check /var/log/ua_sync.log"}

    else
        result = {ok=false, msg="Unknown action: "..(action or "nil")}
    end

    pool.put(red)
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(result))
end

local function render_data()
    ngx.header["Content-Type"] = "application/json; charset=utf-8"

    local red, err = pool.get()
    if not red then
        ngx.say(cjson.encode({error="Redis: "..tostring(err)}))
        return
    end

    local ban_keys  = scan_keys(red, "ban:*",      5000)
    local rep_keys  = scan_keys(red, "rep:*",      5000)
    local risk_keys = scan_keys(red, "risk:*",     5000)
    local rate_keys = scan_keys(red, "rl:*",       2000)
    local wl_ip_keys = scan_keys(red, "wl:*",      1000)
    local nonce_keys    = scan_keys(red, "nonce:*",    500)
    local verified_keys = scan_keys(red, "verified:*", 500)
    local stat_keys     = scan_keys(red, "stat:*",    2000)
    local ban_ctx_keys  = scan_keys(red, "ban_ctx:*",  500)
    local ua_count     = red:get("badbot:ua_count") or "0"
    local ua_sync_time = red:get("badbot:ua_sync_time") or "never"
    local ua_custom    = red:smembers("badbot:ua_custom_set") or {}

    local function is_ipv4(s)
        return s ~= "" and s:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
    end
    local function is_identity(s)
        return s ~= "" and #s == 32 and s:match("^[0-9a-f]+$") ~= nil
    end

    local ban_ip_list, ban_id_list = {}, {}
    for _, k in ipairs(ban_keys) do
        local v = k:gsub("^ban:", "")
        if is_ipv4(v) then
            local rep     = red:get("rep:"..v)     or "0"
            local ip_risk = red:get("ip_risk:"..v) or "0"
            local ttl     = red:ttl(k)
            table.insert(ban_ip_list, {
                ip=v,
                rep=tonumber(rep) or 0,
                ip_risk=tonumber(ip_risk) or 0,
                ttl=ttl > 0 and (math.floor(ttl/60).."m") or "perm"
            })
        elseif is_identity(v) then
            local risk = red:get("risk:"..v) or "0"
            local ttl  = red:ttl(k)
            table.insert(ban_id_list, {
                id=v, risk=tonumber(risk) or 0,
                ttl=ttl > 0 and (math.floor(ttl/60).."m") or "perm"
            })
        end
        if #ban_ip_list >= 50 and #ban_id_list >= 50 then break end
    end
    table.sort(ban_ip_list,  function(a,b) return math.max(a.rep,a.ip_risk) > math.max(b.rep,b.ip_risk) end)
    table.sort(ban_id_list,  function(a,b) return a.risk > b.risk end)

    local high_risk = {}
    for _, k in ipairs(risk_keys) do
        local fp  = k:gsub("^risk:", "")
        local val = tonumber(red:get(k)) or 0
        if val >= 0.5 then
            table.insert(high_risk, {id=fp, risk=val})
        end
        if #high_risk >= 15 then break end
    end
    table.sort(high_risk, function(a,b) return a.risk > b.risk end)

    local rep_ips = {}
    for _, k in ipairs(rep_keys) do
        local key = k:gsub("^rep:", "")
        if not key:find(":", 1, true) and is_ipv4(key) then
            local val = tonumber(red:get(k)) or 0
            if val > 0 then
                table.insert(rep_ips, {ip=key, score=val})
            end
        end
        if #rep_ips >= 20 then break end
    end
    table.sort(rep_ips, function(a,b) return a.score > b.score end)

    local rate_abusers = {}
    for _, k in ipairs(rate_keys) do
        local key = k:gsub("^rl:", "")
        local val = tonumber(red:get(k)) or 0
        if val >= 100 then
            if is_ipv4(key) then
                table.insert(rate_abusers, {key=key, kind="ip",       rate=val})
            elseif is_identity(key) then
                table.insert(rate_abusers, {key=key, kind="identity", rate=val})
            end
        end
        if #rate_abusers >= 30 then break end
    end
    table.sort(rate_abusers, function(a,b) return a.rate > b.rate end)

    local wl_ips = {}
    for _, k in ipairs(wl_ip_keys) do
        if k:match("^wl:%d+%.%d+%.%d+%.%d+$") then
            table.insert(wl_ips, (k:gsub("^wl:", "")))
        end
    end

    local wl_urls = {}
    local url_members = red:smembers("wl:url_set") or {}
    for _, u in ipairs(url_members) do
        table.insert(wl_urls, u)
    end
    table.sort(wl_urls)

    local last_sync  = red:get("threat:last_sync") or "-"
    local stats_raw  = red:get("threat:stats")
    local tsync      = {ip_loaded=0, asn_loaded=0, last_sync=last_sync}
    if stats_raw then
        local ok2, obj = pcall(cjson.decode, stats_raw)
        if ok2 then
            tsync.ip_loaded  = obj.ip  or 0
            tsync.asn_loaded = obj.asn or 0
        end
    end

    local today = os.date("%Y%m%d")
    local domain_map = {}

    local device_map = {}  -- global across all domains
    local intent_map      = {}  -- bot vs human vs ambiguous
    local intent_by_device = {}  -- intent per device group

    for _, k in ipairs(stat_keys) do
        local host, action, date = k:match("^stat:([^:]+):([^:]+):(%d+)$")
        if host and action and date == today
           and action ~= "req" and not action:match("^score_") then
            if not domain_map[host] then
                domain_map[host] = {req=0,allow=0,monitor=0,challenge=0,block=0}
            end
            local val = tonumber(red:get(k)) or 0
            local d = domain_map[host]
            if     action == "allow"     then d.allow     = val
            elseif action == "monitor"   then d.monitor   = val
            elseif action == "challenge" then d.challenge = val
            elseif action == "block"     then d.block     = val
            end

            -- Device group stats
            local dg = action:match("^dev_(%w+)$")
            if dg and not dg:find("_block") and not dg:find("_challenge") then
                if not device_map[dg] then
                    device_map[dg] = {total=0, block=0, challenge=0}
                end
                device_map[dg].total = (device_map[dg].total or 0) + val
            end
            local dg2, act2 = action:match("^dev_(%w+)_(block)$")
            if not dg2 then dg2, act2 = action:match("^dev_(%w+)_(challenge)$") end
            if dg2 and act2 then
                if not device_map[dg2] then
                    device_map[dg2] = {total=0, block=0, challenge=0}
                end
                if act2 == "block" then
                    device_map[dg2].block = (device_map[dg2].block or 0) + val
                elseif act2 == "challenge" then
                    device_map[dg2].challenge = (device_map[dg2].challenge or 0) + val
                end
            end

            -- Intent per device group (ibd_desktop_bot, ibd_mobile_human...)
            local dg_ibd, ig_ibd = action:match("^ibd_(%w+)_(%w+)$")
            if dg_ibd and ig_ibd then
                if not intent_by_device then intent_by_device = {} end
                if not intent_by_device[dg_ibd] then
                    intent_by_device[dg_ibd] = {bot=0,human=0,ambiguous=0,good_bot=0}
                end
                intent_by_device[dg_ibd][ig_ibd] =
                    (intent_by_device[dg_ibd][ig_ibd] or 0) + val
            end

            -- Intent stats
            local ig = action:match("^intent_(%w+)$")
            if ig and not ig:find("_block") and not ig:find("_challenge") then
                if not intent_map[ig] then intent_map[ig] = {total=0, block=0, challenge=0} end
                intent_map[ig].total = (intent_map[ig].total or 0) + val
            end
            local ig2, ia2 = action:match("^intent_(%w+)_(block)$")
            if not ig2 then ig2, ia2 = action:match("^intent_(%w+)_(challenge)$") end
            if ig2 and ia2 then
                if not intent_map[ig2] then intent_map[ig2] = {total=0, block=0, challenge=0} end
                if ia2 == "block" then
                    intent_map[ig2].block = (intent_map[ig2].block or 0) + val
                else
                    intent_map[ig2].challenge = (intent_map[ig2].challenge or 0) + val
                end
            end
        end
    end
    for _, k in ipairs(stat_keys) do
        local host, action, date = k:match("^stat:([^:]+):([^:]+):(%d+)$")
        if host and action == "req" and date == today then
            if domain_map[host] then
                domain_map[host].req = tonumber(red:get(k)) or 0
            end
        end
    end

    -- Build device stats list
    local device_stats = {}
    local GROUP_ORDER = {"mobile","tablet","desktop","unknown"}
    for _, g in ipairs(GROUP_ORDER) do
        local s = device_map[g] or {total=0, block=0, challenge=0}
        local active = math.max(0, s.total - s.block - s.challenge)
        table.insert(device_stats, {
            group     = g,
            total     = s.total,
            active    = active,
            challenge = s.challenge,
            block     = s.block,
        })
    end

    local domain_list = {}
    for host, s in pairs(domain_map) do
        table.insert(domain_list, {
            host=host, req=s.req, allow=s.allow,
            monitor=s.monitor, challenge=s.challenge, block=s.block,
        })
    end
    table.sort(domain_list, function(a,b) return a.req > b.req end)

    local ban_ctx_list = {}
    for _, k in ipairs(ban_ctx_keys) do
        local key = (k:gsub("^ban_ctx:", ""))
        if key:match("^%d+%.%d+%.%d+%.%d+$") then
            local raw = red:get(k)
            if raw then
                local ok2, obj = pcall(cjson.decode, raw)
                if ok2 and obj then
                    local ttl_left = red:ttl(k)
                    table.insert(ban_ctx_list, {
                        ip       = key,
                        identity = obj.identity or "",
                        domain   = obj.domain   or "?",
                        score    = obj.score     or 0,
                        action   = obj.action    or "block",
                        ttl      = ttl_left > 0 and (math.floor(ttl_left/60).."m") or "perm",
                    })
                end
            end
        end
        if #ban_ctx_list >= 50 then break end
    end
    table.sort(ban_ctx_list, function(a,b) return a.score > b.score end)

    -- Good bot DNS registry
    local goodbot_keys = scan_keys(red, "goodbot:dns:*", 200)
    local goodbot_dns = {}
    for _, k in ipairs(goodbot_keys) do
        local name = k:gsub("^goodbot:dns:", "")
        local suffixes = red:get(k) or ""
        table.insert(goodbot_dns, {name=name, suffixes=suffixes})
    end
    table.sort(goodbot_dns, function(a,b) return a.name < b.name end)

    -- ASN type overrides
    local asn_type_keys = scan_keys(red, "asn:type:*", 500)
    local asn_types = {}
    for _, k in ipairs(asn_type_keys) do
        local asn = k:gsub("^asn:type:", "")
        local itype = red:get(k) or "?"
        table.insert(asn_types, {asn=asn, itype=itype})
    end
    table.sort(asn_types, function(a,b) return a.asn < b.asn end)

    -- JA3 overrides
    local ja3_allow_keys = scan_keys(red, "ja3:allow:*", 200)
    local ja3_block_keys = scan_keys(red, "ja3:block:*", 200)
    local ja3_list = {}
    for _, k in ipairs(ja3_allow_keys) do
        table.insert(ja3_list, {hash=k:gsub("^ja3:allow:",""), status="allow"})
    end
    for _, k in ipairs(ja3_block_keys) do
        table.insert(ja3_list, {hash=k:gsub("^ja3:block:",""), status="block"})
    end

    -- Unknown UA samples để debug
    local ua_unknown_samples = red:lrange("stat:ua_unknown_sample", 0, 19) or {}

    pool.put(red)

    local function arr(t)
        if not t or #t == 0 then
            return setmetatable({}, cjson.array_mt)
        end
        return t
    end

    ngx.say(cjson.encode({
        summary = {
            ban_total     = #ban_keys,
            ban_ip        = #ban_ip_list,
            ban_id        = #ban_id_list,
            rep_total     = #rep_keys,
            risk_total    = #risk_keys,
            rate_total    = #rate_abusers,
            wl_ip_total   = #wl_ips,
            wl_url_total  = #wl_urls,
            pending       = #nonce_keys,
            verified      = #verified_keys,
        },
        ban_ip_list  = arr(ban_ip_list),
        ban_id_list  = arr(ban_id_list),
        high_risk    = arr(high_risk),
        rep_ips      = arr(rep_ips),
        rate_abusers = arr(rate_abusers),
        wl_ips       = arr(wl_ips),
        wl_urls      = arr(wl_urls),
        threat_sync  = tsync,
        domain_stats = arr(domain_list),
        ban_ctx_list = arr(ban_ctx_list),
        ua_info = {
            count     = tonumber(ua_count) or 0,
            sync_time = ua_sync_time,
            custom    = arr(ua_custom),
        },
        goodbot_dns  = arr(goodbot_dns),
        asn_types    = arr(asn_types),
        ja3_list     = arr(ja3_list),
        device_stats         = arr(device_stats),
        ua_unknown_samples   = arr(ua_unknown_samples),
        intent_by_device     = intent_by_device,
        intent_stats         = {
            bot       = intent_map["bot"]       or {total=0,block=0,challenge=0},
            human     = intent_map["human"]     or {total=0,block=0,challenge=0},
            good_bot  = intent_map["good_bot"]  or {total=0,block=0,challenge=0},
            ambiguous = intent_map["ambiguous"] or {total=0,block=0,challenge=0},
        },
    }))
end

local function render_dashboard()
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say([[<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AntiBot v4.3.6 — SOC Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
.hdr{background:#161b22;border-bottom:1px solid #30363d;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.hdr h1{color:#58a6ff;font-size:18px;font-weight:600}
.badge{font-size:11px;padding:3px 9px;border-radius:20px;border:1px solid #30363d;color:#8b949e}
.badge.live{border-color:#3fb950;color:#3fb950}
.main{padding:20px 24px;max-width:1400px;margin:0 auto}
.tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #30363d;padding-bottom:0}
.tab{padding:8px 16px;cursor:pointer;font-size:13px;color:#8b949e;border-bottom:2px solid transparent;margin-bottom:-1px}
.tab.active{color:#58a6ff;border-color:#58a6ff}
.tab:hover{color:#e6edf3}
.pane{display:none}.pane.active{display:block}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}
@media(max-width:900px){.g4{grid-template-columns:1fr 1fr}.g2,.g3{grid-template-columns:1fr}}
.sc{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:18px;text-align:center}
.sv{font-size:32px;font-weight:700;line-height:1.1;margin-bottom:2px}
.sl{font-size:12px;color:#8b949e}
.red{color:#f85149}.orange{color:#f0883e}.green{color:#3fb950}.blue{color:#58a6ff}.gray{color:#8b949e}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:16px}
.card h2{font-size:14px;font-weight:600;margin-bottom:12px;display:flex;align-items:center;gap:6px}
.dot{width:7px;height:7px;border-radius:50%;background:#3fb950;display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#21262d;color:#8b949e;font-weight:500;text-align:left;padding:7px 10px;border-bottom:1px solid #30363d}
td{padding:7px 10px;border-bottom:1px solid #21262d}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1c2129}
.tag{display:inline-block;font-size:10px;padding:2px 7px;border-radius:10px;font-weight:500}
.tag-red{background:#3d1a1a;color:#f85149;border:1px solid #5c2323}
.tag-orange{background:#2d1f0e;color:#f0883e;border:1px solid #4d3213}
.tag-blue{background:#0e1f3d;color:#58a6ff;border:1px solid #1347a0}
.tag-green{background:#0e2d1a;color:#3fb950;border:1px solid #1a5c30}
.tag-gray{background:#1c2129;color:#8b949e;border:1px solid #30363d}
.mono{font-family:monospace;font-size:11px}
.bar-w{background:#21262d;border-radius:3px;overflow:hidden;width:70px;display:inline-block;vertical-align:middle;margin-right:5px;height:5px}
.bar{height:5px;border-radius:3px;transition:width .4s}
.inp{background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:13px;width:260px}
.inp:focus{border-color:#58a6ff;outline:none}
.btn{padding:6px 14px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500}
.btn-blue{background:#1347a0;color:#58a6ff}.btn-blue:hover{background:#1a5cbf}
.btn-red{background:#3d1a1a;color:#f85149}.btn-red:hover{background:#5c2323}
.btn-green{background:#0e2d1a;color:#3fb950}.btn-green:hover{background:#1a5c30}
.btn-gray{background:#21262d;color:#8b949e}.btn-gray:hover{background:#2d333b}
.wl-form{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
.msg{font-size:12px;padding:6px 12px;border-radius:6px;margin-top:8px;display:none}
.msg.ok{background:#0e2d1a;color:#3fb950;border:1px solid #1a5c30}
.msg.err{background:#3d1a1a;color:#f85149;border:1px solid #5c2323}
#status{font-size:12px;color:#3fb950}
</style>
</head>
<body>

<div class="hdr">
  <h1>🛡 AntiBot v4.3.6 — SOC Dashboard</h1>
  <div style="display:flex;gap:10px;align-items:center">
    <span id="status">Loading...</span>
    <span class="badge live">● LIVE</span>
  </div>
</div>

<div class="main">

  <!-- -->
  <div class="tabs">
    <div class="tab active" onclick="showTab('overview')">📊 Overview</div>
    <div class="tab" onclick="showTab('bans')">🚫 Bans</div>
    <div class="tab" onclick="showTab('threats')">🔴 Threats</div>
    <div class="tab" onclick="showTab('whitelist')">✅ Whitelist</div>
    <div class="tab" onclick="showTab('sync')">📡 Feed Sync</div>
    <div class="tab" onclick="showTab('domains')">🌐 Domains</div>
    <div class="tab" onclick="showTab('intelligence')">🧠 Intelligence</div>
    <div class="tab" onclick="showTab('devices')">📱 Devices</div>
  </div>

  <!-- -->
  <div id="tab-overview" class="pane active">
    <div class="g4" style="grid-template-columns:repeat(5,1fr)">
      <div class="sc"><div class="sv red" id="s-ban">—</div><div class="sl">Banned IPs</div></div>
      <div class="sc"><div class="sv red" id="s-banid">—</div><div class="sl">Banned Identities</div></div>
      <div class="sc"><div class="sv orange" id="s-rep">—</div><div class="sl">Threat Feed IPs</div></div>
      <div class="sc"><div class="sv blue" id="s-risk">—</div><div class="sl">High Risk IDs</div></div>
      <div class="sc"><div class="sv gray" id="s-chal">—</div><div class="sl">Pending Challenge</div></div>
    </div>
    <div class="g4">
      <div class="sc"><div class="sv" id="s-rate">—</div><div class="sl">Rate Abusers</div></div>
      <div class="sc"><div class="sv green" id="s-wlip">—</div><div class="sl">Whitelisted IPs</div></div>
      <div class="sc"><div class="sv green" id="s-wlurl">—</div><div class="sl">Whitelisted URLs</div></div>
      <div class="sc"><div class="sv" id="s-verif">—</div><div class="sl">Verified Sessions</div></div>
    </div>
    <div class="g2">
      <div class="card">
        <h2><span class="dot"></span>Top Banned IPs</h2>
        <table><thead><tr><th>IP</th><th>Rep</th><th>Level</th><th>Action</th></tr></thead>
        <tbody id="t-ban-ip"></tbody></table>
      </div>
      <div class="card">
        <h2>⚡ Rate Abusers</h2>
        <table><thead><tr><th>Key</th><th>Kind</th><th>Requests</th><th>Level</th></tr></thead>
        <tbody id="t-rate"></tbody></table>
      </div>
    </div>
  </div>

  <!-- -->
  <div id="tab-bans" class="pane">
    <div class="card">
      <h2>🚫 Banned IPs &amp; Identities <span id="ban-count" class="tag tag-red">0</span></h2>
      <table><thead><tr><th>IP</th><th>Rep Score</th><th>Level</th><th>Action</th></tr></thead>
      <tbody id="t-ban-ip-full"></tbody></table>
    </div>
    <div class="card">
      <h2>🔒 Banned Identities <span id="banid-count" class="tag tag-red">0</span></h2>
      <table><thead><tr><th>Identity</th><th>Risk</th><th>Level</th><th>Action</th></tr></thead>
      <tbody id="t-ban-fp"></tbody></table>
    </div>
  </div>

  <!-- -->
  <div id="tab-threats" class="pane">
    <div class="g2">
      <div class="card">
        <h2>🔴 Threat Intelligence Feed</h2>
        <table><thead><tr><th>IP</th><th>Score</th><th>Level</th></tr></thead>
        <tbody id="t-rep"></tbody></table>
      </div>
      <div class="card">
        <h2>⚠️ High Risk Identities</h2>
        <table><thead><tr><th>Identity</th><th>Risk</th><th>Level</th></tr></thead>
        <tbody id="t-risk"></tbody></table>
      </div>
    </div>
  </div>

  <!-- -->
  <div id="tab-whitelist" class="pane">
    <div class="card">
      <h2>✅ IP Whitelist</h2>
      <div class="wl-form">
        <input class="inp" id="inp-wl-ip" placeholder="1.2.3.4" type="text">
        <button class="btn btn-green" onclick="wlAction('wl_ip_add','ip','inp-wl-ip')">+ Whitelist IP</button>
        <button class="btn btn-red" onclick="wlAction('unban_ip','ip','inp-wl-ip')">Unban IP</button>
        <button class="btn btn-gray" onclick="wlAction('wl_ip_del','ip','inp-wl-ip')">Remove WL</button>
      </div>
      <div class="msg" id="msg-ip"></div>
      <table><thead><tr><th>IP</th><th>Action</th></tr></thead>
      <tbody id="t-wl-ip"></tbody></table>
    </div>
    <div class="card">
      <h2>✅ URL Prefix Whitelist</h2>
      <div style="margin-bottom:8px;font-size:12px;color:#8b949e">
        Thêm URL prefix để bypass antibot (VD: /media/, /fpc/, /api/)
      </div>
      <div class="wl-form">
        <input class="inp" id="inp-wl-url" placeholder="/api/v1/" type="text">
        <button class="btn btn-green" onclick="wlAction('wl_url_add','prefix','inp-wl-url')">+ Add URL</button>
        <button class="btn btn-gray" onclick="wlAction('wl_url_del','prefix','inp-wl-url')">Remove</button>
      </div>
      <div class="msg" id="msg-url"></div>
      <table><thead><tr><th>URL Prefix</th><th>Action</th></tr></thead>
      <tbody id="t-wl-url"></tbody></table>
    </div>
  </div>

  <!-- -->
  <div class="card" style="margin-top:16px">
    <h2>🤖 Bad Bot UA Patterns</h2>
    <div style="display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap">
      <div class="sc" style="padding:12px 20px;min-width:120px">
        <div class="sv blue" id="ua-count">—</div>
        <div class="sl">Total Patterns</div>
      </div>
      <div class="sc" style="padding:12px 20px;min-width:160px">
        <div style="font-size:12px;color:#8b949e;margin-bottom:4px">Last Sync</div>
        <div id="ua-sync-time" style="font-size:13px">—</div>
      </div>
      <div style="display:flex;align-items:center">
        <button class="btn btn-blue" onclick="uaSync()">🔄 Sync Now</button>
      </div>
    </div>
    <div class="wl-form">
      <input class="inp" id="inp-ua-pat" placeholder="BadBotName" type="text">
      <button class="btn btn-red" onclick="uaAction('ua_add')">+ Block UA</button>
      <button class="btn btn-gray" onclick="uaAction('ua_del')">Remove</button>
    </div>
    <div class="msg" id="msg-ua"></div>
    <div style="font-size:12px;color:#8b949e;margin:8px 0">Custom patterns (thêm thủ công):</div>
    <table><thead><tr><th>Custom UA Pattern</th><th>Action</th></tr></thead>
    <tbody id="t-ua-custom"></tbody></table>
  </div>

  <!-- -->
  <div id="tab-sync" class="pane">
    <div class="g3">
      <div class="sc"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">Last Sync</div><div id="sync-time" style="font-size:14px">—</div></div>
      <div class="sc"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">IPs Loaded</div><div id="sync-ip" style="font-size:28px;font-weight:700;color:#58a6ff">—</div></div>
      <div class="sc"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">ASNs Loaded</div><div id="sync-asn" style="font-size:28px;font-weight:700;color:#3fb950">—</div></div>
    </div>
  </div>

  <!-- -->
  <div id="tab-domains" class="pane">
    <div class="card">
      <h2>🌐 Domain Traffic — Hôm nay</h2>
      <table>
        <thead><tr>
          <th>Domain</th><th>Total</th><th>Clean</th>
          <th>Monitor</th><th>Challenge</th><th>Block</th><th>Block%</th>
        </tr></thead>
        <tbody id="t-domain-stats"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>🚫 Recent Bans by Domain</h2>
      <table>
        <thead><tr>
          <th>IP</th><th>Identity</th><th>Domain</th><th>Score</th><th>Expires</th><th>Action</th>
        </tr></thead>
        <tbody id="t-ban-domain"></tbody>
      </table>
    </div>
  </div>

</div><!-- -->

  <!-- intelligence pane -->
  <div id="tab-intelligence" class="pane">
    <div class="g2">
      <div class="card">
        <h2>🤖 Good Bot DNS Registry</h2>
        <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
          Bots tự xưng là crawler sẽ được DNS-verified theo domain suffix đã đăng ký.
        </div>
        <div class="wl-form">
          <input class="inp" id="inp-gb-name" placeholder="googlebot" type="text" style="width:130px">
          <input class="inp" id="inp-gb-sfx" placeholder="googlebot.com,google.com" type="text" style="width:240px">
          <button class="btn btn-green" onclick="goodbotDnsAdd()">+ Add</button>
        </div>
        <table><thead><tr><th>Bot Name</th><th>DNS Suffixes</th><th>Action</th></tr></thead>
        <tbody id="t-goodbot-dns"></tbody></table>
      </div>
      <div class="card">
        <h2>🌐 ASN Type Overrides</h2>
        <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
          Override phân loại ASN từ GeoLite2. Dùng khi asn_org không có keyword đủ rõ.
        </div>
        <div class="wl-form">
          <input class="inp" id="inp-asn" placeholder="16509" type="text" style="width:100px">
          <select id="sel-asn-type" style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:13px">
            <option value="datacenter">datacenter</option>
            <option value="vpn">vpn</option>
            <option value="tor">tor</option>
            <option value="residential">residential</option>
            <option value="business">business</option>
          </select>
          <button class="btn btn-blue" onclick="asnTypeSet()">Set</button>
        </div>
        <table><thead><tr><th>ASN</th><th>Type</th><th>Action</th></tr></thead>
        <tbody id="t-asn-types"></tbody></table>
      </div>
    </div>
    <div class="card">
      <h2>🔐 JA3 TLS Fingerprint</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
        Allowlist: browser JA3 từ production log. Blocklist: known bot TLS fingerprint.
      </div>
      <div class="wl-form">
        <input class="inp" id="inp-ja3" placeholder="32-char hex JA3 hash" type="text" style="width:320px">
        <button class="btn btn-green" onclick="ja3Action('ja3_allow')">+ Allow</button>
        <button class="btn btn-red" onclick="ja3Action('ja3_block')">Block</button>
      </div>
      <table><thead><tr><th>JA3 Hash</th><th>Status</th><th>Action</th></tr></thead>
      <tbody id="t-ja3-list"></tbody></table>
    </div>
  </div>

</div><!-- -->

  <!-- Devices pane -->
  <div id="tab-devices" class="pane">
    <div class="g4" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
      <div class="sc">
        <div class="sv blue" id="dev-mobile-total">—</div>
        <div class="sl">📱 Mobile Requests</div>
      </div>
      <div class="sc">
        <div class="sv blue" id="dev-tablet-total">—</div>
        <div class="sl">📟 Tablet Requests</div>
      </div>
      <div class="sc">
        <div class="sv blue" id="dev-desktop-total">—</div>
        <div class="sl">🖥 Desktop Requests</div>
      </div>
      <div class="sc">
        <div class="sv gray" id="dev-unknown-total">—</div>
        <div class="sl">❓ Unknown Requests</div>
      </div>
    </div>
    <div class="g2">
      <div class="card">
        <h2>📱 Device Distribution — Hôm nay</h2>
        <table>
          <thead><tr>
            <th>Device</th><th>Total</th>
            <th class="green">Active</th>
            <th class="orange">Challenge</th>
            <th class="red">Blocked</th>
            <th>Block%</th>
            <th class="red">Bot%</th>
            <th class="green">Human%</th>
          </tr></thead>
          <tbody id="t-device-stats"></tbody>
        </table>
      </div>
      <div class="card">
        <h2>🚫 Blocked by Device Type — Hôm nay</h2>
        <div id="dev-bar-chart" style="padding:8px 0"></div>
      </div>
    </div>
    <div class="card" style="margin-top:0">
      <h2>🎯 Intent Classification — Hôm nay</h2>
      <div style="font-size:12px;color:var(--color-text-secondary);margin-bottom:10px">
        Phân loại request theo hành vi thực tế, không phụ thuộc loại thiết bị.
      </div>
      <table>
        <thead><tr>
          <th>Intent</th><th>Total</th>
          <th class="green">Active</th>
          <th class="orange">Challenge</th>
          <th class="red">Blocked</th>
          <th>Block%</th>
        </tr></thead>
        <tbody id="t-intent-stats"></tbody>
      </table>
    </div>
    <div class="card" style="margin-top:0">
      <h2>❓ Unknown Device — UA Samples (24h gần nhất)</h2>
      <div style="font-size:12px;color:#8b949e;margin-bottom:8px">
        UA không nhận dạng được. Thường là bot tools (curl, python-requests, scrapy...) đã được ua_anomaly bắt.
        Nếu thấy UA trông như browser thật → cần thêm rule vào device_classifier.lua.
      </div>
      <table><thead><tr><th>User-Agent</th></tr></thead>
      <tbody id="t-ua-unknown"></tbody></table>
    </div>
  </div>

<script>
// ── Helpers ───────────────────────────────────────────────────
function tag(score){
  if(score>=0.8) return '<span class="tag tag-red">CRITICAL</span>'
  if(score>=0.6) return '<span class="tag tag-orange">HIGH</span>'
  if(score>=0.4) return '<span class="tag tag-blue">MEDIUM</span>'
  return '<span class="tag tag-gray">LOW</span>'
}
function rateTag(r){
  if(r>=100) return '<span class="tag tag-red">FLOOD</span>'
  if(r>=50)  return '<span class="tag tag-orange">HIGH</span>'
  return '<span class="tag tag-blue">ELEVATED</span>'
}
function bar(v,w){
  w=w||70
  var c=v>=0.8?'#f85149':v>=0.5?'#f0883e':'#3fb950'
  return '<div class="bar-w" style="width:'+w+'px"><div class="bar" style="width:'+Math.round(v*100)+'%;background:'+c+'"></div></div>'
}
function trunc(s,n){return s&&s.length>n?s.substring(0,n)+'…':s||'-'}
function setText(id,v){var e=document.getElementById(id);if(e)e.textContent=v}
function setHTML(id,v){var e=document.getElementById(id);if(e)e.innerHTML=v}
function showTab(name){
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'))
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'))
  document.getElementById('tab-'+name).classList.add('active')
  event.target.classList.add('active')
}

// ── Whitelist API ──────────────────────────────────────────────
function wlAction(action,field,inputId){
  var val=document.getElementById(inputId).value.trim()
  if(!val){alert('Vui lòng nhập giá trị');return}
  var body={action:action}
  body[field]=val
  var msgId=inputId.includes('url')?'msg-url':'msg-ip'
  fetch('/antibot-admin/wl',{
    method:'POST',
    credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)
  })
  .then(r=>r.json())
  .then(d=>{
    var el=document.getElementById(msgId)
    el.className='msg '+(d.ok?'ok':'err')
    el.textContent=d.msg||d.error||'Done'
    el.style.display='block'
    setTimeout(()=>el.style.display='none',3000)
    if(d.ok){document.getElementById(inputId).value='';load()}
  })
}
function removeWlIp(ip){
  if(!confirm('Remove whitelist: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_ip_del',ip:ip})
  }).then(()=>load())
}
function removeWlUrl(prefix){
  if(!confirm('Remove whitelist URL: '+prefix+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_url_del',prefix:prefix})
  }).then(()=>load())
}
function unbanIp(ip){
  if(!confirm('Unban IP: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'unban_ip',ip:ip})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function unbanId(id){
  if(!confirm('Unban Identity: '+id.substring(0,16)+'...?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'unban_id',id:id})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}

// ── Main data load ─────────────────────────────────────────────
function load(){
  fetch('/antibot-admin/data', {credentials:'include'})
  .then(r=>{
    if(!r.ok) throw new Error('HTTP '+r.status)
    return r.json()
  })
  .then(d=>{
    var s=d.summary
    setText('s-ban',   s.ban_ip)
    setText('s-banid', s.ban_id)
    setText('s-rep',  s.rep_total)
    setText('s-risk', s.risk_total)
    setText('s-chal', s.pending)
    setText('s-rate', s.rate_total)
    setText('s-wlip', s.wl_ip_total)
    setText('s-wlurl',s.wl_url_total)
    setText('s-verif',s.verified)
    setText('ban-count',   s.ban_ip + s.ban_id)
    setText('banid-count', s.ban_id)

    // Overview: top banned IPs
    var bt=''
    for(var r of (d.ban_ip_list||[]).slice(0,10)){
      var risk=Math.max(r.rep||0, r.ip_risk||0)
      var src=(r.ip_risk||0)>=(r.rep||0)?'Behavior':'Feed'
      bt+=`<tr><td class="mono">${r.ip}</td>
      <td>${bar(risk)}${(risk*100).toFixed(0)}% <span class="gray" style="font-size:10px">(${src})</span></td>
      <td>${tag(risk)}</td>
      <td class="gray" style="font-size:11px">${r.ttl||'-'}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px" onclick="unbanIp('${r.ip}')">Unban</button></td></tr>`
    }
    setHTML('t-ban-ip', bt||nodata(4))

    // Bans tab: full IP list
    var btf=''
    for(var r of d.ban_ip_list||[]){
      var risk=Math.max(r.rep||0, r.ip_risk||0)
      var src=(r.ip_risk||0)>=(r.rep||0)?'Behavior':'Feed'
      btf+=`<tr><td class="mono">${r.ip}</td>
      <td>${bar(risk)}${(risk*100).toFixed(0)}% <span class="gray" style="font-size:10px">(${src})</span></td>
      <td>${tag(risk)}</td>
      <td class="gray" style="font-size:11px">${r.ttl||'-'}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px" onclick="unbanIp('${r.ip}')">Unban</button>
          <button class="btn btn-green" style="font-size:11px;padding:2px 7px;margin-left:4px" onclick="wlFromBan('${r.ip}')">Whitelist</button></td></tr>`
    }
    setHTML('t-ban-ip-full', btf||nodata(4))

    // Bans tab: Identity list
    var bfp=''
    for(var r of d.ban_id_list||[]){
      bfp+=`<tr><td class="mono">${trunc(r.id,28)}</td><td>${bar(r.risk)}${(r.risk*100).toFixed(0)}%</td><td>${tag(r.risk)}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px" onclick="unbanId('${r.id}')">Unban</button></td></tr>`
    }
    setHTML('t-ban-fp', bfp||nodata(4))

    // Threats: rep IPs
    var rt=''
    for(var r of d.rep_ips||[]){
      rt+=`<tr><td class="mono">${r.ip}</td><td>${bar(r.score)}${(r.score*100).toFixed(0)}%</td><td>${tag(r.score)}</td></tr>`
    }
    setHTML('t-rep', rt||nodata(3))

    // Threats: high risk FP
    var rk=''
    for(var r of d.high_risk||[]){
      rk+=`<tr><td class="mono">${trunc(r.id,20)}</td><td>${bar(r.risk)}${(r.risk*100).toFixed(0)}%</td><td>${tag(r.risk)}</td></tr>`
    }
    setHTML('t-risk', rk||nodata(3))

    // Rate abusers (IP + Identity)
    var ra=''
    for(var r of d.rate_abusers||[]){
      var kb=r.kind==='identity'?'<span class="tag tag-blue" style="font-size:9px">ID</span>':'<span class="tag tag-gray" style="font-size:9px">IP</span>'
      ra+=`<tr><td class="mono">${trunc(r.key,24)}</td><td>${kb}</td><td><b>${r.rate}</b> req</td><td>${rateTag(r.rate)}</td></tr>`
    }
    setHTML('t-rate', ra||nodata(4))

    // Whitelist IPs
    var wi=''
    for(var ip of d.wl_ips||[]){
      wi+=`<tr><td class="mono">${ip}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="removeWlIp('${ip}')">Remove</button></td></tr>`
    }
    setHTML('t-wl-ip', wi||nodata(2))

    // Whitelist URLs
    var wu=''
    for(var u of d.wl_urls||[]){
      wu+=`<tr><td class="mono">${u}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="removeWlUrl('${u}')">Remove</button></td></tr>`
    }
    setHTML('t-wl-url', wu||nodata(2))

    // Feed sync
    var ts=d.threat_sync||{}
    setText('sync-time', ts.last_sync||'-')
    setText('sync-ip',   (ts.ip_loaded||0).toLocaleString())
    setText('sync-asn',  (ts.asn_loaded||0).toLocaleString())

    setText('status','Updated: '+new Date().toLocaleTimeString('vi-VN'))
    renderDomains(d)
    renderDevices(d)
    // UA info
    if(d.ua_info){
      setText('ua-count', (d.ua_info.count||0).toLocaleString())
      setText('ua-sync-time', d.ua_info.sync_time||'never')
      var uc=''
      for(var p of (d.ua_info.custom||[])){
        uc+=`<tr><td class="mono">${p}</td>
        <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px"
            onclick="removeUaCustom('${p}')">Remove</button></td></tr>`
      }
      setHTML('t-ua-custom', uc||nodata(2))
    }
    // Intelligence tab data — inside .then(d) so 'd' is in scope
    // Good bot DNS
    var gb=''
    for(var r of (d.goodbot_dns||[])){
      gb+=`<tr><td class="mono">${r.name}</td><td class="mono gray">${r.suffixes}</td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="goodbotDnsDel('${r.name}')">Remove</button></td></tr>`
    }
    setHTML('t-goodbot-dns', gb||nodata(3))
    // ASN type overrides
    var at=''
    for(var r of (d.asn_types||[])){
      at+=`<tr><td class="mono">AS${r.asn}</td><td><span class="tag tag-${r.itype==='datacenter'?'orange':r.itype==='tor'?'red':'blue'}">${r.itype}</span></td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="asnTypeDel('${r.asn}')">Remove</button></td></tr>`
    }
    setHTML('t-asn-types', at||nodata(3))
    // JA3 list
    var jl=''
    for(var r of (d.ja3_list||[])){
      var sc=r.status==='allow'?'tag-green':'tag-red'
      jl+=`<tr><td class="mono" style="font-size:10px">${r.hash}</td>
      <td><span class="tag ${sc}">${r.status}</span></td>
      <td><button class="btn btn-gray" style="font-size:11px;padding:2px 7px" onclick="ja3Remove('${r.hash}')">Remove</button></td></tr>`
    }
    setHTML('t-ja3-list', jl||nodata(3))
  })
  .catch(e=>setText('status','Error: '+e.message))
}

function renderDomains(d){
  // Domain stats table
  var ds=''
  for(var r of (d.domain_stats||[])){
    var total=r.req||0
    var blk=r.block||0
    var pct=total>0?((blk/total)*100).toFixed(1)+'%':'0%'
    var cls=blk>100?'red':blk>20?'orange':'green'
    ds+=`<tr>
      <td class="mono"><b>${r.host}</b></td>
      <td>${total.toLocaleString()}</td>
      <td class="green">${(r.allow||0).toLocaleString()}</td>
      <td class="gray">${(r.monitor||0).toLocaleString()}</td>
      <td class="orange">${(r.challenge||0).toLocaleString()}</td>
      <td class="red">${blk.toLocaleString()}</td>
      <td class="${cls}"><b>${pct}</b></td>
    </tr>`
  }
  setHTML('t-domain-stats', ds||nodata(7))

  // Ban context table
  var bc=''
  for(var r of (d.ban_ctx_list||[])){
    bc+=`<tr>
      <td class="mono">${r.ip}</td>
      <td class="mono gray" style="font-size:10px">${trunc(r.identity||'',16)}</td>
      <td class="mono">${r.domain}</td>
      <td>${bar(r.score/100)}${r.score}</td>
      <td class="gray" style="font-size:11px">${r.ttl}</td>
      <td><button class="btn btn-red" style="font-size:11px;padding:2px 7px"
          onclick="unbanIp('${r.ip}')">Unban IP</button>
          <button class="btn btn-green" style="font-size:11px;padding:2px 7px;margin-left:4px"
          onclick="wlFromBan('${r.ip}')">Whitelist</button></td>
    </tr>`
  }
  setHTML('t-ban-domain', bc||nodata(6))
}

function nodata(cols){
  return `<tr><td colspan="${cols}" style="text-align:center;color:#484f58;padding:16px">Không có dữ liệu</td></tr>`
}
function uaAction(action){
  var pat=document.getElementById('inp-ua-pat').value.trim()
  if(!pat){alert('Nhập pattern UA');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:action,pattern:pat})
  }).then(r=>r.json()).then(d=>{
    var el=document.getElementById('msg-ua')
    el.className='msg '+(d.ok?'ok':'err')
    el.textContent=d.msg
    el.style.display='block'
    setTimeout(()=>el.style.display='none',3000)
    if(d.ok){document.getElementById('inp-ua-pat').value='';load()}
  })
}
function uaSync(){
  if(!confirm('Sync UA patterns từ github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ua_sync'})
  }).then(r=>r.json()).then(d=>alert(d.msg))
}
function removeUaCustom(pat){
  if(!confirm('Remove UA pattern: '+pat+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ua_del',pattern:pat})
  }).then(()=>load())
}
function goodbotDnsAdd(){
  var name=document.getElementById('inp-gb-name').value.trim()
  var sfx=document.getElementById('inp-gb-sfx').value.trim()
  if(!name||!sfx){alert('Nhập bot name và DNS suffixes');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'goodbot_dns_add',name:name,suffixes:sfx})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function goodbotDnsDel(name){
  if(!confirm('Remove good bot: '+name+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'goodbot_dns_del',name:name})
  }).then(r=>r.json()).then(d=>{load()})
}
function asnTypeSet(){
  var asn=document.getElementById('inp-asn').value.trim()
  var itype=document.getElementById('sel-asn-type').value
  if(!asn){alert('Nhập ASN number');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'asn_type_set',asn:asn,itype:itype})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function asnTypeDel(asn){
  if(!confirm('Remove ASN override: '+asn+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'asn_type_del',asn:asn})
  }).then(r=>r.json()).then(d=>{load()})
}
function ja3Action(action){
  var hash=document.getElementById('inp-ja3').value.trim()
  if(!hash||hash.length!==32){alert('Nhập JA3 hash (32 hex chars)');return}
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:action,hash:hash})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}
function ja3Remove(hash){
  if(!confirm('Remove JA3: '+hash.substring(0,8)+'...?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'ja3_remove',hash:hash})
  }).then(r=>r.json()).then(d=>{load()})
}
function wlFromBan(ip){
  if(!confirm('Whitelist & unban IP: '+ip+'?'))return
  fetch('/antibot-admin/wl',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({action:'wl_ip_add',ip:ip})
  }).then(r=>r.json()).then(d=>{alert(d.msg);load()})
}

function renderDevices(d){
  var devs = d.device_stats || []
  var icons = {mobile:'📱',tablet:'📟',desktop:'🖥',unknown:'❓'}
  var labels = {mobile:'Mobile',tablet:'Tablet',desktop:'Desktop',unknown:'Unknown'}

  // Summary cards
  for(var dev of devs){
    setText('dev-'+dev.group+'-total', (dev.total||0).toLocaleString())
  }

  // Table — với Bot%/Human% từ intent_by_device
  var rows = ''
  var ibd  = d.intent_by_device || {}
  var maxTotal = Math.max(1, ...devs.map(d=>d.total||0))
  for(var dev of devs){
    var total   = dev.total     || 0
    var active  = dev.active    || 0
    var chal    = dev.challenge || 0
    var blk     = dev.block     || 0
    var pct     = total > 0 ? ((blk/total)*100).toFixed(1)+'%' : '0%'
    var cls     = blk > total*0.3 ? 'red' : blk > total*0.1 ? 'orange' : 'green'
    // Bot% = bot confirmed; Human% = human + good_bot; ambiguous = phần còn lại
    var dg      = dev.group
    var nBot    = (ibd[dg] && ibd[dg].bot)      || 0
    var nHuman  = ((ibd[dg] && ibd[dg].human)   || 0)
                + ((ibd[dg] && ibd[dg].good_bot) || 0)
    var hasIbd  = ibd[dg] && (nBot + nHuman) > 0
    var botPct  = hasIbd ? ((nBot/total)*100).toFixed(0)+'%'   : '-'
    var humPct  = hasIbd ? ((nHuman/total)*100).toFixed(0)+'%' : '-'
    var botCls  = nBot > total*0.5 ? 'red' : nBot > total*0.2 ? 'orange' : 'gray'
    var humCls  = nHuman > total*0.5 ? 'green' : 'gray'
    rows += '<tr>'
      + '<td><b>' + (icons[dev.group]||'') + ' ' + (labels[dev.group]||dev.group) + '</b></td>'
      + '<td>' + total.toLocaleString() + '</td>'
      + '<td class="green">' + active.toLocaleString() + '</td>'
      + '<td class="orange">' + chal.toLocaleString() + '</td>'
      + '<td class="red">' + blk.toLocaleString() + '</td>'
      + '<td class="' + cls + '"><b>' + pct + '</b></td>'
      + '<td class="' + botCls + '"><b>' + botPct + '</b></td>'
      + '<td class="' + humCls + '"><b>' + humPct + '</b></td>'
      + '</tr>'
  }
  setHTML('t-device-stats', rows || nodata(8))

  // Bar chart
  var chart = ''
  for(var dev of devs){
    var total  = dev.total   || 0
    var blk    = dev.block   || 0
    var chal   = dev.challenge || 0
    var active = dev.active  || 0
    if(total === 0) continue
    var wPct   = Math.round((total/maxTotal)*100)
    var blkW   = total > 0 ? Math.round((blk/total)*100)  : 0
    var chalW  = total > 0 ? Math.round((chal/total)*100) : 0
    var actW   = 100 - blkW - chalW
    chart += '<div style="margin-bottom:14px">'
      + '<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
      + '<span style="font-size:12px">' + (icons[dev.group]||'') + ' ' + (labels[dev.group]||dev.group) + '</span>'
      + '<span style="font-size:11px;color:#8b949e">' + total.toLocaleString() + ' reqs</span>'
      + '</div>'
      + '<div style="background:#21262d;border-radius:4px;height:18px;overflow:hidden;display:flex">'
      + '<div style="width:'+actW+'%;background:#3fb950;transition:width .4s" title="Active: '+active+'"></div>'
      + '<div style="width:'+chalW+'%;background:#f0883e;transition:width .4s" title="Challenge: '+chal+'"></div>'
      + '<div style="width:'+blkW+'%;background:#f85149;transition:width .4s" title="Block: '+blk+'"></div>'
      + '</div>'
      + '<div style="display:flex;gap:12px;margin-top:3px;font-size:10px;color:#8b949e">'
      + '<span style="color:#3fb950">■ Active: '+active.toLocaleString()+'</span>'
      + '<span style="color:#f0883e">■ Challenge: '+chal.toLocaleString()+'</span>'
      + '<span style="color:#f85149">■ Block: '+blk.toLocaleString()+'</span>'
      + '</div>'
      + '</div>'
  }
  setHTML('dev-bar-chart', chart || '<div style="color:#8b949e;font-size:12px;padding:16px">Chưa có dữ liệu hôm nay</div>')

  // Unknown UA samples
  var samples = d.ua_unknown_samples || []
  var sr = ''
  for(var ua of samples){
    var cls = ua.match(/python|curl|go-http|java|scrapy|okhttp|requests/i)
      ? 'red' : ua.match(/mozilla|webkit|gecko/i) ? 'orange' : 'gray'
    sr += '<tr><td class="mono ' + cls + '" style="font-size:11px;word-break:break-all">' + ua + '</td></tr>'
  }
  setHTML('t-ua-unknown', sr || nodata(1))

  // Intent stats
  var intents = d.intent_stats || {}
  var irows = ''
  var imap = [
    {key:'bot',      label:'🤖 Bot',        cls:'red'},
    {key:'ambiguous',label:'❓ Ambiguous',   cls:'orange'},
    {key:'human',    label:'👤 Human',       cls:'green'},
    {key:'good_bot', label:'✅ Good Bot',    cls:'blue'},
  ]
  for(var im of imap){
    var s = intents[im.key] || {total:0,block:0,challenge:0}
    var active = Math.max(0, s.total - (s.block||0) - (s.challenge||0))
    var pct = s.total > 0 ? ((s.block/s.total)*100).toFixed(1)+'%' : '0%'
    irows += '<tr>'
      + '<td><b class="'+im.cls+'">'+im.label+'</b></td>'
      + '<td>'+s.total.toLocaleString()+'</td>'
      + '<td class="green">'+active.toLocaleString()+'</td>'
      + '<td class="orange">'+((s.challenge||0)).toLocaleString()+'</td>'
      + '<td class="red">'+((s.block||0)).toLocaleString()+'</td>'
      + '<td class="'+im.cls+'"><b>'+pct+'</b></td>'
      + '</tr>'
  }
  setHTML('t-intent-stats', irows || nodata(6))
}

setInterval(load,10000)
load()
</script>
</body>
</html>]])
end

function _M.router()
    if not auth() then return end

    local uri = (ngx.var.uri or ""):gsub("//+","/"):gsub("/+$","")
    local method = ngx.var.request_method or "GET"

    if uri == "/antibot-admin" or uri == "/antibot-admin/index" then
        return render_dashboard()
    end
    if uri == "/antibot-admin/data" then
        return render_data()
    end
    if uri == "/antibot-admin/wl" and method == "POST" then
        return handle_whitelist_api()
    end

    ngx.status = 404
    ngx.say("Not found")
end

return _M
