-- T — kiem HOP DONG GIUA CAC MODULE, khong phai hanh vi cua mot ham.
--
-- CHAY: ./run.sh
--
-- VI SAO BO TEST NAY TON TAI. Ngay 2026-09-03, `waf_arg` duoc them vao
-- (f9124a3) va TAT CA unit test deu xanh — trong khi tin hieu do bi hai cua
-- thoat tin cay trong `antibot/init.lua` nuot sach voi moi client co cookie
-- verified. Unit test cua args.lua khong the thay lo do: no kiem mot ham, con
-- loi nam o CHO NOI GIUA hai file.
--
-- Day khong phai integration test that (do can nginx song + cookie verified).
-- Day la kiem CAU TRUC: doi chieu hai danh sach o hai file phai khop nhau. No
-- bat duoc dung lop loi da lot, va chay duoc trong cong [3b] khong can ha tang.
--
-- Cai no KHONG chung minh, noi ro de khong ai tuong nham:
--   - khong chung minh diem so thuc su toi enforcement
--   - khong chung minh thu tu cac buoc trong pipeline
--   - khong chung minh gi ve race hay timer

local SRC = os.getenv("ANTIBOT_SRC")
if not SRC or SRC == "" then
    io.write("thieu bien moi truong ANTIBOT_SRC\n"); os.exit(2)
end

local pass, fail = 0, 0
local function bad(fmt, ...)
    fail = fail + 1
    io.write(string.format(fmt, ...))
end

local function slurp(path)
    local fh = io.open(path, "r")
    if not fh then return nil end
    local s = fh:read("*a")
    fh:close()
    return s
end

local compute = slurp(SRC .. "intelligence/scoring/compute.lua")
local root    = slurp(SRC .. "init.lua")
if not compute or not root then
    io.write("khong doc duoc compute.lua hoac init.lua\n"); os.exit(2)
end

-- ── 1. Moi tin hieu `waf_*` phai co mat trong `waf_signal` ───────────
--
-- `waf_signal(ctx)` trong antibot/init.lua quyet dinh tin hieu WAF nao du suc
-- vo hieu hoa cookie fast-path. Thieu mot cai la tin hieu do bi nuot IM LANG
-- voi moi client da giai PoW — tuc dung lo hong ma ca tang WAF sinh ra de bit.
io.write("\nhop dong: tin hieu WAF <-> cua thoat tin cay\n")

local guard = root:match("local function waf_signal%b()(.-)\nend")
if not guard then
    bad("  SAI  khong tim thay ham `waf_signal` trong init.lua\n")
else
    -- Lay ten tin hieu tu DEFAULT_WEIGHTS: dong dang `waf_xxx = <so>,`
    local names, n = {}, 0
    for name in compute:gmatch("\n%s*(waf_[%w_]+)%s*=%s*%d") do
        n = n + 1
        names[n] = name
    end

    if n == 0 then
        bad("  SAI  khong tim thay tin hieu `waf_*` nao trong DEFAULT_WEIGHTS\n")
    else
        io.write(string.format("  tim thay %d tin hieu waf_* trong compute.lua\n", n))
        for i = 1, n do
            local nm = names[i]
            if guard:find("ctx." .. nm, 1, true) then
                pass = pass + 1
            else
                bad("  SAI  `%s` co trong DEFAULT_WEIGHTS nhung KHONG co trong " ..
                    "waf_signal()\n       => tin hieu nay bi nuot voi moi client " ..
                    "co cookie verified\n", nm)
            end
        end
    end
end

-- ── 2. Moi tin hieu `waf_*` phai co nhanh trong `get_signal` ─────────
--
-- Dang ky trong DEFAULT_WEIGHTS ma quen `get_signal` thi trong so co that nhung
-- gia tri luon 0 — dong gop bang khong, va khong co loi nao bao.
io.write("\nhop dong: DEFAULT_WEIGHTS <-> get_signal\n")

for name in compute:gmatch("\n%s*(waf_[%w_]+)%s*=%s*%d") do
    if compute:find('name == "' .. name .. '"', 1, true) then
        pass = pass + 1
    else
        bad("  SAI  `%s` co trong DEFAULT_WEIGHTS nhung KHONG co nhanh trong " ..
            "get_signal()\n       => trong so co that nhung gia tri luon 0\n", name)
    end
end

-- ── 3. Moi rule_id phai co mat trong bang RULES cua module minh ──────
--
-- `waf/init.lua` tra `rules[rule_id]` roi doc `.action`/`.score`. Mot rule_id
-- duoc `check()` tra ve ma thieu muc trong RULES se lam ca lan cham luat do bi
-- bo qua im lang (`if not rule then return false end`).
io.write("\nhop dong: rule_id tra ve <-> bang RULES\n")

local function check_rules(file, label)
    local src = slurp(SRC .. file)
    if not src then bad("  SAI  khong doc duoc %s\n", file) return end

    -- rule_id do `check()` tra ve: dong dang `return "xxx_yyy"`
    local seen = {}
    for id in src:gmatch('return%s+"([%w_]+)"') do seen[id] = true end

    for id in pairs(seen) do
        -- Bang RULES khai dang `xxx_yyy = { action = ...`
        if src:find(id .. "%s*=%s*{%s*action") then
            pass = pass + 1
        else
            bad("  SAI  %s: `check()` tra ve `%s` nhung khong co muc trong RULES\n" ..
                "       => lan cham luat do bi bo qua im lang\n", label, id)
        end
    end
end

check_rules("waf/wp_paths.lua", "wp_paths")
check_rules("waf/exposed.lua",  "exposed")
check_rules("waf/args.lua",     "args")

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
