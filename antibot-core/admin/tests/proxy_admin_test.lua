local SRC=os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if SRC:sub(-1)~="/" then SRC=SRC.."/" end
local cjson=require "cjson"
local pass,fail=0,0
local function ok(v,n) if v then pass=pass+1 else fail=fail+1;io.stderr:write("FAIL proxy_admin: ",n,"\n") end end
local function eq(a,b,n) ok(a==b,n.." got="..tostring(a).." want="..tostring(b)) end

local names={"resty.random","antibot.core.redis_pool","antibot.core.domain_inventory",
 "antibot.core.origin_registry","antibot.core.origin_proof","antibot.admin.security",
 "antibot.admin.proxy"}
local old={};for _,n in ipairs(names)do old[n]=package.loaded[n] end
local oldngx=_G.ngx
local body,says="",{}
_G.ngx={status=200,header={},time=function()return 1234 end,
 req={read_body=function()end,get_body_data=function()return body end},
 say=function(v)says[#says+1]=v end}

local random_counter=0
package.loaded["resty.random"]={bytes=function()
 random_counter=random_counter+1;return string.rep(string.char(random_counter),16)
end}
local state,seen=nil,false
package.loaded["antibot.core.redis_pool"]={get=function()return{}end,put=function()end}
package.loaded["antibot.core.domain_inventory"]={
 load=function()return{{domain="example.test",owner="alice"}},nil,"fixture" end,
 contains=function(_,z)return z=="example.test" end,
}
package.loaded["antibot.core.origin_registry"]={
 read=function()return state end,
 persist=function(_,s)state=s;return true,s end,
 was_seen=function()return seen end,
 list=function()return state and {state} or {} end,
}
package.loaded["antibot.core.origin_proof"]={issue=function(z,r,g)return "v2."..z.."."..g..".mac" end}
package.loaded["antibot.admin.security"]={
 validate_payload=function()return true end,audit=function()end,
}
package.loaded["antibot.admin.proxy"]=nil
local admin=assert(loadfile(SRC.."admin/proxy.lua"))()
local principal={username="operator"}
local function mutate(action,zone)
 body=cjson.encode({action=action,zone=zone or "example.test"});says={};ngx.status=200
 admin.mutate(principal)
 return cjson.decode(says[#says]),ngx.status
end
local out,status=mutate("proxy_cf_enable","outside.test")
eq(status,400,"zone outside inventory rejected")
eq(state,nil,"outside zone creates no pending state")
out,status=mutate("proxy_cf_enable")
eq(status,200,"enable status")
eq(out.state,"pending","enable creates pending")
ok(out.token:match("^v2%.example%.test%."),"enable returns V2 token")
local first=out.generation
out,status=mutate("proxy_cf_activate")
eq(status,409,"unseen token cannot activate")
seen=true;out,status=mutate("proxy_cf_activate")
eq(status,200,"seen token activates")
eq(state.state,"active","active persisted")
out,status=mutate("proxy_cf_disable")
eq(status,200,"disable status")
eq(state.state,"revoked","disable revokes")
seen=false;out,status=mutate("proxy_cf_enable")
eq(status,200,"re-enable status")
ok(out.generation~=first,"re-enable rotates generation")

for _,n in ipairs(names)do package.loaded[n]=old[n] end
_G.ngx=oldngx
print(("proxy_admin_test: %d qua, %d hong"):format(pass,fail))
if fail>0 then os.exit(1) end
