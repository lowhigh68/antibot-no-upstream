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
-- NO CHI DANG TIN THEO MOT CHIEU. Bo test nay TIM CHUOI trong ma nguon, khong
-- phan tich cu phap Lua. Mot chuoi `name == "waf_arg"` nam trong mot khoi chu
-- thich, hoac trong mot nhanh khong bao gio chay, van lam phep kiem qua. Nen:
--   BAO DO  => chac chan co loi. Sua truoc khi deploy.
--   BAO XANH => khong chung minh duoc gi ca.
-- Sua duoc chuyen do thi phai viet mot bo phan tich cu phap Lua, va cai gia do
-- khong xung voi mot lop lint. Ghi ro ra day de khong ai doc mau xanh thanh mot
-- bao dam.
--
-- Nhung thu khac no KHONG chung minh, noi ro de khong ai tuong nham:
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

-- ── 1. `waf_signal` phai KHOP DUNG tap tin hieu co trong so > 0 ──────
--
-- `waf_signal(ctx)` trong antibot/init.lua quyet dinh tin hieu WAF nao du suc
-- vo hieu hoa cookie fast-path. Kiem HAI CHIEU, va chieu thu hai moi la cai da
-- thieu:
--
--   trong so > 0  PHAI co trong waf_signal
--       Thieu => tin hieu bi nuot IM LANG voi moi client da giai PoW, tuc dung
--       lo hong ma ca tang WAF sinh ra de bit. Da xay ra that voi `waf_arg`.
--
--   trong so == 0  KHONG DUOC co trong waf_signal
--       Thua => "che do quan sat" khong con la quan sat. Tin hieu cong 0 diem
--       nhung van day request qua het pipeline, noi mot tin hieu KHAC co the
--       dua no len challenge. waf.log ghi `rule=arg_traversal ... final=
--       challenge` va nguoi doc ket luan luat gay FP — trong khi that ra no
--       doi phan quyet qua duong DOI LUONG. Do la lech am tham dung tren cot
--       sinh ra de chong lech.
--
-- Vi tieu chi la TRONG SO chu khong phai ten, danh sach trong init.lua khong
-- con phai nho bang tay: ngay nang `waf_arg` len khoi 0, chieu mot bao do va
-- noi phai them gi.
io.write("\nhop dong: tin hieu WAF <-> cua thoat tin cay\n")

local guard = root:match("local function waf_signal%b()(.-)\nend")
if not guard then
    bad("  SAI  khong tim thay ham `waf_signal` trong init.lua\n")
else
    -- Lay ten VA trong so tu DEFAULT_WEIGHTS: dong dang `waf_xxx = <so>,`
    local names, weights, n = {}, {}, 0
    for name, w in compute:gmatch("\n%s*(waf_[%w_]+)%s*=%s*([%d%.]+)") do
        n = n + 1
        names[n] = name
        weights[name] = tonumber(w)
    end

    if n == 0 then
        bad("  SAI  khong tim thay tin hieu `waf_*` nao trong DEFAULT_WEIGHTS\n")
    else
        io.write(string.format("  tim thay %d tin hieu waf_* trong compute.lua\n", n))
        for i = 1, n do
            local nm = names[i]
            -- Neo bien tu: khong co no thi `ctx.waf_arg` khop nham vao mot ten dai hon
            -- co cung tien to, va do la mot lan BAO XANH SAI.
            local in_guard = guard:find("ctx%." .. nm .. "%f[%W]") ~= nil
            local enforced = (weights[nm] or 0) > 0

            if enforced and not in_guard then
                bad("  SAI  `%s` co trong so %s nhung KHONG co trong waf_signal()\n" ..
                    "       => tin hieu nay bi nuot voi moi client co cookie verified\n",
                    nm, tostring(weights[nm]))
            elseif not enforced and in_guard then
                bad("  SAI  `%s` co trong so 0 nhung LAI co trong waf_signal()\n" ..
                    "       => che do quan sat dang doi luong request, khong con\n" ..
                    "          la quan sat. Bo no khoi waf_signal, hoac nang trong so.\n",
                    nm)
            else
                pass = pass + 1
            end
        end
    end
end

-- ── 1b. CHIEU NGUOC: moi `ctx.waf_*` trong guard phai co trong DEFAULT_WEIGHTS
--
-- Vong lap o tren duyet danh sach TEN LAY TU compute.lua, nen no khong bao gio
-- nhin thay mot cai ten CHI ton tai trong `waf_signal()`. Ai do them thang
-- `ctx.waf_new_signal` vao guard ma quen dang ky trong DEFAULT_WEIGHTS thi:
--   - guard tra ve truthy => pha fast-path
--   - `compute.lua` khong co trong so => 0 diem
-- Tuc mot tin hieu doi LUONG DI cua request nhung khong doi diem, va khong co
-- gi bao. Dung dang loi da phai sua o `f69b896`, chi khac chieu.
io.write("\nhop dong: chieu nguoc — guard -> DEFAULT_WEIGHTS\n")

if guard then
    for nm in guard:gmatch("ctx%.(waf_[%w_]+)") do
        if compute:find("\n%s*" .. nm .. "%s*=%s*%d") then
            pass = pass + 1
        else
            bad("  SAI  `ctx.%s` co trong waf_signal() nhung KHONG co trong " ..
                "DEFAULT_WEIGHTS\n       => pha fast-path ma khong dong gop " ..
                "diem nao\n", nm)
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

-- `rules_file` tach rieng vi tu 05-09 hai thu KHONG con o cung mot file:
-- `args.lua` giu bang RULES, con `check()` da chuyen xuong `body_core.lua` —
-- ban Lua thuan, vi ban chay trong `ngx.run_worker_thread` khong duoc dung
-- `ngx.re`. Quen tham so nay thi phep kiem tim `return "arg_..."` trong
-- args.lua, khong thay gi, va BAO XANH voi 0 lan kiem — dung kieu bao xanh
-- rong ma ca file nay canh bao o dau.
local function check_rules(file, label, rules_file)
    local src = slurp(SRC .. file)
    if not src then bad("  SAI  khong doc duoc %s\n", file) return end
    local rules_src = src
    if rules_file then
        rules_src = slurp(SRC .. rules_file)
        if not rules_src then bad("  SAI  khong doc duoc %s\n", rules_file) return end
    end

    -- rule_id do `check()` tra ve: dong dang `return "xxx_yyy"`
    local seen, n = {}, 0
    for id in src:gmatch('return%s+"([%w_]+)"') do
        if not seen[id] then seen[id] = true; n = n + 1 end
    end
    if n == 0 then
        bad("  SAI  %s: khong tim thay rule_id nao trong %s\n" ..
            "       => phep kiem nay dang khong kiem gi ca\n", label, file)
        return
    end

    for id in pairs(seen) do
        -- Bang RULES khai dang `xxx_yyy = { action = ...`
        if rules_src:find(id .. "%s*=%s*{%s*action") then
            pass = pass + 1
        else
            bad("  SAI  %s: `check()` tra ve `%s` nhung khong co muc trong RULES\n" ..
                "       => lan cham luat do bi bo qua im lang\n", label, id)
        end
    end
end

check_rules("waf/wp_paths.lua",  "wp_paths")
check_rules("waf/exposed.lua",   "exposed")
check_rules("waf/body_core.lua", "args (loi dung chung)", "waf/args.lua")

-- ── 4. `args.check` phai la CHINH ham cua loi, khong phai ban sao ────
--
-- Hai ban cai dat cua cung ba luat da lech that: ban `ngx.re` cu khong
-- `lower()` lai sau moi vong giai ma, nen `%50hp%3A%2F%2Finput` giai ra
-- `Php://input` va truot mau chu thuong — mot bypass hoan chinh cua
-- `arg_php_wrapper`. Trung lap la BAT BUOC ve kien truc neu ai do viet lai ban
-- `ngx.re`, nen chan ngay o day.
io.write("\nhop dong: args.check <-> body_core.check_args\n")

local args_src = slurp(SRC .. "waf/args.lua")
if not args_src then
    bad("  SAI  khong doc duoc waf/args.lua\n")
elseif not args_src:find("_M%.check%s*=%s*core%.check_args") then
    bad("  SAI  `args.lua` khong con uy quyen `check` xuong `body_core`\n" ..
        "       => hai ban cai dat cua cung ba luat, va chung se lech\n")
elseif args_src:find("ngx%.re%.") then
    bad("  SAI  `args.lua` con goi `ngx.re.*`\n" ..
        "       => ban nay khong chay duoc trong worker thread\n")
else
    pass = pass + 1
end

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
