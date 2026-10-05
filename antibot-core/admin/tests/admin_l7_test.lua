-- admin_l7_test.lua — kiem endpoint `/antibot-admin/l7`.
--
-- VI SAO CAN. Endpoint nay la DUONG RA cua bo dem `l7adm:dicterr:*`. Bo dem do
-- ra doi vi `error.log` khong dang tin (`last_dict_error` per-worker,
-- rate-limit 60s -> 0 dong trong khi antibot.log co 17 luot). Mot duong ra
-- khong duoc kiem thi y nhu khong co duong ra — ho loi
-- `feedback_alert_reaches_nobody`, da bat nam lan.
--
-- Bo nay TRICH ham `render_l7` roi chay THAT thay vi nap ca `admin/init.lua`
-- (module do require mot chuoi dai va dung `ngx` o nhieu cho). Danh doi: neu ai
-- doi TEN ham thi phep trich thay bai ngay chu khong im lang.
--
-- CHAY:  resty antibot-core/admin/tests/admin_l7_test.lua
-- Ma thoat: 0 = moi con so khop, 1 = co lech.
local cjson = require "cjson"
local out = {}
local fake = {
    header = {}, say = function(s) out[#out+1] = s end,
    shared = {}, var = {}, status = 200,
    exit = function() end, log = function() end, ERR = 4,
}
local src = io.open((os.getenv("ANTIBOT_SRC") or "./antibot-core/") .. "admin/init.lua"):read("a")
-- Trich DUNG ham render_l7 chu khong nap ca module (no co require chuoi dai).
local body = src:match("(local function render_l7%(%).-\nend\n)")
assert(body, "khong trich duoc render_l7")
local function run(stats)
    out = {}
    fake.shared = { antibot_stats = stats }
    local env = { ngx = fake, cjson = cjson, tonumber = tonumber,
                  ipairs = ipairs, next = next, tostring = tostring,
                  pairs = pairs, type = type }
    local chunk = assert(loadstring(body .. "\nreturn render_l7"))
    setfenv(chunk, env)
    chunk()()
    return cjson.decode(out[1])
end

local Dict = {}
Dict.__index = Dict
function Dict.new(d) return setmetatable({ d = d or {} }, Dict) end
function Dict:get(k) return self.d[k] end
function Dict:get_keys(n)
    local ks = {}
    for k in pairs(self.d) do ks[#ks+1] = k end
    return ks
end

local p, f = 0, 0
local function eq(got, want, msg)
    if got == want then p = p + 1
    else f = f + 1; print(("HONG %s: got=%s want=%s"):format(msg, tostring(got), tostring(want))) end
end

-- 1. dict THIEU KHAI BAO -> available=false, KHAC HAN "bo dem = 0"
local r = run(nil)
eq(r.available, false, "dict nil -> available=false")
eq(type(r.reason), "string", "dict nil co reason")
eq(r.dicterr, nil, "dict nil KHONG tra bo dem")

-- 2. dict CO nhung RONG -> available=true, ba khoa deu 0
r = run(Dict.new({}))
eq(r.available, true, "dict rong -> available=true")
eq(r.dicterr_total, 0, "dict rong -> total=0")
eq(r.dicterr.full, 0, "dict rong -> full=0 (DA do, bang 0)")
eq(r.dicterr.missing, 0, "dict rong -> missing=0")

-- 3. dict CO so lieu
r = run(Dict.new({
    ["l7adm:dicterr:full"] = 17,
    ["l7adm:dicterr:missing"] = 2,
    ["khoa:khac"] = 999,          -- phai bi BO QUA
}))
eq(r.dicterr.full, 17, "doc dung full")
eq(r.dicterr.missing, 2, "doc dung missing")
eq(r.dicterr_total, 19, "total = tong CHI cac khoa dicterr")
eq(r.keys_seen, 3, "keys_seen dem ca khoa khong lien quan")
eq(r.truncated, nil, "3 khoa -> khong truncated")

print(("ADMIN_L7_OK %d qua, %d hong"):format(p, f))
if f > 0 then os.exit(1) end
