local pass, fail = 0, 0
local function ok(v, name)
    if v then pass=pass+1 else fail=fail+1; io.stderr:write("FAIL domain_inventory: ",name,"\n") end
end
local function eq(a,b,name) ok(a==b,name.." got="..tostring(a).." want="..tostring(b)) end

local src=os.getenv("ANTIBOT_SRC") or "./antibot-core/"
if src:sub(-1)~="/" then src=src.."/" end
local inventory=assert(loadfile(src.."core/domain_inventory.lua"))()
local path=os.tmpname()
local f=assert(io.open(path,"w"))
f:write("Example.COM: alice\n")
f:write("shop.example.net: bob # managed\n")
f:write("example.com: duplicate\n")
f:write("evil_example.net: invalid\n")
f:write("# comment\n")
f:close()
local rows,err=inventory.load(path)
os.remove(path)
ok(rows~=nil and err==nil,"inventory file loads")
eq(#rows,2,"deduplicates and rejects invalid names")
eq(rows[1].domain,"example.com","normalizes and sorts")
eq(rows[1].owner,"alice","retains owner")
eq(inventory.contains(rows,"EXAMPLE.COM."),true,"contains normalizes input")
eq(inventory.contains(rows,"attacker.test"),false,"traffic-only host absent")
local missing,missing_err=inventory.load(path..".missing")
ok(missing==nil and tostring(missing_err):find("cannot read",1,true)~=nil,
   "missing inventory fails explicitly")
print(("domain_inventory_contract: %d qua, %d hong"):format(pass,fail))
if fail>0 then os.exit(1) end
