-- Behavioral contract for host-bound actor quarantine (q2).

local SRC = os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1) ~= "/" then SRC = SRC .. "/" end
local pass, fail = 0, 0
local function ok(v, n)
    if v then pass = pass + 1
    else fail = fail + 1; io.stderr:write("FAIL quarantine: ", n, "\n") end
end
local function eq(got, want, n)
    ok(got == want, n .. " got=" .. tostring(got) .. " want=" .. tostring(want))
end

local real_md5 = ngx.md5
ngx = {
    DEBUG=0, INFO=1, WARN=2, ERR=3,
    md5=real_md5, null={}, time=function() return 1800000000 end,
    log=function() end, say=function() end,
    exit=function(code) ngx._exit=code end,
    status=200, header={},
    var={server_name="one.test",host="one.test",http_accept="",http_user_agent="",scheme="https"},
}

local cfg = {
    ttl={violation=172800},
    network_quarantine={enabled=true,steps={300,3600,86400},violation_ttl=172800},
}
package.loaded["antibot.core.config"] = cfg
package.loaded["antibot.core.decision"] = {set=function() return true end}
package.loaded["antibot.core.ip_scope"] = {is_self=function(ctx) return ctx.is_self == true end}
local identity = assert(loadfile(SRC .. "core/fingerprint/identity.lua"))()
package.loaded["antibot.core.fingerprint.identity"] = identity
package.loaded["antibot.core.site_scope"] = assert(loadfile(SRC .. "core/site_scope.lua"))()
local quarantine = assert(loadfile(SRC .. "core/network_quarantine.lua"))()
package.loaded["antibot.core.network_quarantine"] = quarantine

local ACTOR = string.rep("a",32)
local function ctx(extra)
    local c={ip="198.51.100.44",ua="Mozilla/5.0 Chrome/149.0",req={host="one.test"},
        req_class="navigation",action="block",action_reason="score_threshold",
        score=120,effective_score=90,actor_id=ACTOR,actor_kind="signed_current",
        actor_presented=true,actor_valid=true}
    for k,v in pairs(extra or {}) do c[k]=v end
    return c
end

eq(quarantine.keys(ctx{actor_presented=false},"host"),nil,
   "unpresented SID cannot address durable state")
eq(quarantine.keys(ctx{actor_valid=false},"host"),nil,
   "invalid SID cannot address durable state")
local one=quarantine.keys(ctx(),"host")
eq(one.ban,"q2:one.test:"..ACTOR,"q2 key includes host and actor")
eq(one.viol,"q2v:one.test:"..ACTOR,"q2 ladder has separate namespace")
ngx.var.server_name,ngx.var.host="two.test","two.test"
local two=quarantine.keys(ctx(),"global")
ok(two.ban~=one.ban,"actor sentence cannot cross host")
eq(two.scope,"host","global request is forced to host scope")
ngx.var.server_name,ngx.var.host="one.test","one.test"
ok(quarantine.keys(ctx{ip_is_aggregate=true},"host")~=nil,
   "valid actor remains precise behind aggregate proxy")
eq(quarantine.legacy_keys(ctx()),nil,"legacy collective keys cannot be re-enabled")

-- In-memory Redis with the production EVAL contract.
local store,ttls,writes={},{},{}
local red={queued=nil}
local function write(op,key,value,ttl)
    writes[#writes+1]={op=op,key=key,value=value,ttl=ttl}
    if op=="del" then store[key],ttls[key]=nil,nil
    elseif op=="setex" then store[key],ttls[key]=value,ttl
    elseif op=="expire" then ttls[key]=ttl
    elseif op=="incr" then store[key]=(tonumber(store[key]) or 0)+1
    elseif op=="set" then store[key],ttls[key]=value,-1 end
end
function red:get(k) if self.queued then self.queued[#self.queued+1]={"get",k};return "QUEUED" end return store[k] end
function red:ttl(k) if self.queued then self.queued[#self.queued+1]={"ttl",k};return "QUEUED" end return ttls[k] or -2 end
function red:setex(k,t,v) write("setex",k,v,t);return true end
function red:del(k) write("del",k);return true end
function red:init_pipeline() self.queued={} end
function red:commit_pipeline()
    local q=self.queued or {};self.queued=nil;local out={}
    for i,v in ipairs(q) do
        if v[1]=="get" then out[i]=store[v[2]]
        elseif v[1]=="ttl" then out[i]=ttls[v[2]] or -2 end
    end
    return out
end
function red:eval(_script,nkeys,...)
    eq(nkeys,4,"atomic claim uses four q2 keys")
    local a={...};local ban,viol,hit,context=a[1],a[2],a[3],a[4]
    if store[ban]=="1" then
        write("setex",hit,a[6],300)
        return {0,tonumber(store[viol]) or 0,ttls[ban] or -2}
    end
    local n=(tonumber(store[viol]) or 0)+1
    local count=tonumber(a[7]);local index=math.min(math.max(n,1),count)
    local ttl=tonumber(a[8+index])
    write("incr",viol);write("expire",viol,nil,tonumber(a[5]))
    write("setex",ban,"1",ttl);write("setex",hit,a[6],300)
    if a[8] and a[8]~="" then write("setex",context,a[8],ttl) end
    return {1,n,ttl}
end
function red:publish() return true end

local pool={
    get=function() return red end,put=function() end,
    safe_get=function(k) return store[k] end,
    safe_set=function(k,v,ttl) write("setex",k,v,ttl);return true end,
}
package.loaded["antibot.core.redis_pool"]=pool
local challenge_calls=0
package.loaded["antibot.enforcement.challenge"]={run=function() challenge_calls=challenge_calls+1;return true end}
package.loaded["antibot.detection.bot.ua_claim"]={claims_good_bot=function() return false end}

local escalation=assert(loadfile(SRC.."enforcement/ban/ban_escalation.lua"))()
local writer=assert(loadfile(SRC.."enforcement/ban/ban_store_write.lua"))()
local reader=assert(loadfile(SRC.."l7/ban/ban_store.lua"))()
local ip_reader=assert(loadfile(SRC.."l7/ban/ip_ban_check.lua"))()

local no_actor=ctx{actor_presented=false,actor_id=nil}
escalation.run(no_actor);writer.run(no_actor)
eq(no_actor.ban_persisted,false,"live block without actor is not persisted")
eq(no_actor.ban_suppressed,"no_presented_actor","suppression reason is measurable")
eq(#writes,0,"stateless scanner creates no Redis sentence")

local first=ctx();escalation.run(first);writer.run(first)
eq(first.ban_persisted,true,"presented actor gets host sentence")
eq(first.ban_created,true,"first incident creates sentence")
eq(first.ban_id_kind,"actor","sentence subject is actor")
eq(first.ban_scope,"host","sentence scope is host")
eq(store["q2:one.test:"..ACTOR],"1","q2 seal written")
eq(store["q2v:one.test:"..ACTOR],1,"first violation recorded")
ok(store["ban:"..first.ip]==nil,"writer never creates collective IP ban")
ok(store["qban:one.test:"..ACTOR]==nil and store["gban:"..ACTOR]==nil,
   "writer never refreshes old collective namespaces")

local concurrent=ctx();escalation.run(concurrent);writer.run(concurrent)
eq(concurrent.ban_created,false,"existing seal is not a new incident")
eq(concurrent.ban_violation,1,"concurrent hit does not advance ladder")

-- Different host with the same signed actor id is independent.
ngx.var.server_name,ngx.var.host="two.test","two.test"
local other=ctx();escalation.run(other);writer.run(other)
eq(other.ban_created,true,"same actor id on another host is isolated")
eq(store["q2:two.test:"..ACTOR],"1","second host has distinct q2 key")
ngx.var.server_name,ngx.var.host="one.test","one.test"

local self=ctx{is_self=true};escalation.run(self);writer.run(self)
eq(self.ban_persisted,false,"self traffic never gets actor sentence")

-- Read path: no actor performs no Redis lookup; q2 HTML is recoverable and
-- non-HTML is blocked locally. Old qban/gban state is never consulted.
writes={};local clean=ctx{actor_presented=false,actor_id=nil}
local _,ex=reader.run(clean);eq(ex,false,"no actor continues live pipeline")
eq(#writes,0,"no actor lookup is zero-write")

ngx.var.http_accept="text/html"
local nav=ctx();nav.req.accept="text/html"
local _,nav_exit=reader.run(nav)
eq(nav_exit,true,"sealed actor HTML enters recovery challenge")
eq(nav.action_reason,"actor_quarantine_challenge","recovery reason is actor-specific")
eq(challenge_calls,1,"challenge invoked once")

ngx.var.http_accept="application/json"
local api=ctx();api.req.accept="application/json";ngx._exit=nil
local _,api_exit=reader.run(api)
eq(api_exit,true,"sealed actor API is blocked")
eq(api.action_reason,"actor_quarantine","block reason is actor-specific")
eq(ngx._exit,403,"q2 block returns 403")

store["q2:one.test:"..ACTOR]=nil
store["qban:one.test:"..ACTOR]="1";store["gban:"..ACTOR]="1"
local old=ctx();local _,old_exit=reader.run(old)
eq(old_exit,false,"old network-UA sentences are not dual-read")

-- Collective IP state is now capacity-only. Old long automatic TTLs stay in
-- Redis for forensics but cannot block a reassigned address; a permanent
-- operator seal and a short capacity brake remain effective.
store["ban:198.51.100.44"]="1";ttls["ban:198.51.100.44"]=2592000
local long_ip=ctx();ngx._exit=nil
local _,long_exit=ip_reader.run(long_ip)
eq(long_exit,false,"old 30-day automatic IP sentence is ignored")
eq(long_ip.ip_ban_legacy_ignored,true,"ignored old IP sentence is measurable")

ttls["ban:198.51.100.44"]=300
local short_ip=ctx();ngx._exit=nil
local _,short_exit=ip_reader.run(short_ip)
eq(short_exit,true,"short IP capacity brake remains active")
eq(ngx._exit,403,"short IP brake returns 403")

ttls["ban:198.51.100.44"]=-1
local manual_ip=ctx();ngx._exit=nil
local _,manual_exit=ip_reader.run(manual_ip)
eq(manual_exit,false,"old permanent automatic IP sentence is ignored")
store["ban:manual:198.51.100.44"]="1"
local explicit_ip=ctx();ngx._exit=nil
local _,explicit_exit=ip_reader.run(explicit_ip)
eq(explicit_exit,true,"explicit manual IP namespace remains active")
eq(explicit_ip.ip_ban_manual,true,"manual provenance is measurable")

-- `network_id` khong con la chu the cua an nao, nhung no VAN la khoa tuong
-- quan ngan han, nen ranh gioi browser/crawler cua `normalize_ua` phai giu.
-- Ba ca duoi day la rao chan cua d3290e9 (lo CUBOT): chung doc lap hoan toan
-- voi thiet ke q2, va sau khi suite nay duoc viet lai thi KHONG suite nao con
-- goi `identity._normalize_ua` — `l7_regression` chi phu ve classifier
-- (`req_class`), `goodbot_contract` chi phu ve registry.
do
    eq(identity._normalize_ua(
        "Mozilla/5.0 (Linux; Android 14; CUBOT-X70) AppleWebKit/537.36 " ..
        "Chrome/121.0 Mobile Safari/537.36"), "Chrome/121",
       "ten thiet bi chua BOT van nam trong ro browser")
    eq(identity._normalize_ua(
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
        :sub(1, 4), "bot:", "crawler canonical van tach khoi ro browser")
    -- `BOT_TOKENS` chua `facebookexternal`, khong chua ca ten san pham, nen
    -- nhan dung la token do — khong phai `facebookexternalhit`.
    eq(identity._normalize_ua(
        "facebookexternalhit/1.1 Facebot Twitterbot/1.0"),
       "bot:facebookexternal",
       "UA ghep nhieu scraper lay token o dau chuoi")
end

print(("quarantine_contract: %d qua, %d hong"):format(pass,fail))
if fail>0 then os.exit(1) end
