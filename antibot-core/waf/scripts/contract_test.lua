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

-- ── 0. MOI file .lua phai BIEN DICH DUOC ────────────────────────────
--
-- `nginx -t` KHONG bat duoc loi cu phap trong nhung module chi duoc `require`
-- luc chay: no chi kiem cau hinh, khong nap cay Lua. Nen mot dau ngoac thieu
-- trong, vi du, `enforcement/challenge/init.lua` se im lang di qua ca `-t` lan
-- `reload`, roi no o request DAU TIEN cham vao no — tuc la o tren may that,
-- voi khach that.
--
-- Cong nay dac biet can vi may dev KHONG CO Lua: khong co gi giua "viet xong"
-- va "day len fleet". Do dung la cach ma `RX_FILENAME` hong (8dfafd2) di lot
-- toi tan git.
--
-- `loadfile` chi BIEN DICH, khong chay — nen an toan voi moi module, ke ca
-- nhung module cham `ngx` ngay o than file.
io.write("bien dich duoc: moi file .lua\n")
do
    local ph = io.popen("find '" .. SRC .. "' -name '*.lua' -type f 2>/dev/null")
    if not ph then
        bad("  SAI  khong chay duoc `find` de duyet cay nguon\n")
    else
        local n, broken = 0, 0
        for path in ph:lines() do
            n = n + 1
            local chunk, err = loadfile(path)
            if not chunk then
                broken = broken + 1
                -- cat tien to bang do dai, KHONG bang `gsub`: SRC la duong
                -- dan that nen co the chua `-` hay `.`, ca hai deu la ky tu
                -- dac biet trong mau Lua.
                bad("  SAI  %s\n       %s\n", path:sub(#SRC + 1), tostring(err))
            end
        end
        ph:close()
        if n == 0 then
            bad("  SAI  khong tim thay file .lua nao duoi %s\n", SRC)
        elseif broken == 0 then
            pass = pass + 1
            io.write(string.format("  OK   %d file\n", n))
        end
    end
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
-- `fn` GIOI HAN pham vi quet vao dung mot ham. Bat buoc tu 05-09: `body_core`
-- con chua `ct_family` (`return "multipart"`, `return "json"`...) va `enc`
-- (`return "1"`, `return "0"`), nen quet ca file thi tam chuoi vo can bi bao la
-- rule_id thieu muc RULES. Cung meo `%b()(.-)\nend` da dung cho `waf_signal`:
-- `end` phai o cot 0 nen `end` thut vao cua vong lap ben trong khong khop.
local function check_rules(file, label, rules_file, fn)
    local src = slurp(SRC .. file)
    if not src then bad("  SAI  khong doc duoc %s\n", file) return end
    local rules_src = src
    if rules_file then
        rules_src = slurp(SRC .. rules_file)
        if not rules_src then bad("  SAI  khong doc duoc %s\n", rules_file) return end
    end

    local scope = src
    if fn then
        scope = src:match("local function " .. fn .. "%b()(.-)\nend")
        if not scope then
            bad("  SAI  %s: khong tim thay ham `%s` trong %s\n", label, fn, file)
            return
        end
    end

    -- rule_id do `check()` tra ve: dong dang `return "xxx_yyy"`
    local seen, n = {}, 0
    for id in scope:gmatch('return%s+"([%w_]+)"') do
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
check_rules("waf/body_core.lua", "args (loi dung chung)", "waf/args.lua",
            "check_args_lower")

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

-- ── 5. Trang challenge <-> endpoint /antibot/verify ─────────────────
--
-- BO TEST NAY RA DOI VI MOT LOI DA SONG RAT LAU MA MOI NUA DEU "DUNG".
--
-- `challenge/init.lua` gui ket qua PoW bang `fetch()`. `verify_token.lua` tra
-- ve mot TRANG HTML co `window.location.replace(dest)`. Doc rieng tung file thi
-- khong file nao sai. Nhung `fetch` VUT than phan hoi, nen trang do khong bao
-- gio chay: `localStorage` khong duoc ghi, va client roi xuong duong lui
-- `document.referrer` — TRONG voi khach vao lan dau (go URL, bookmark, quet QR,
-- mo tu app) — nen moi lien ket sau bi nem ve `/`.
--
-- Do la dung MOT LOAI loi da lap lai suot: mot GIA TRI di qua RANH GIOI va hai
-- ben hieu khac nhau. `php = false` vs nil. `fntr` co vs ly do. `dec()` tra
-- `"-"` vs nil qua ranh gioi thread. Mau regex viet trong long string vs cai
-- PCRE nhan. Hai ban cai dat cua `args.check`.
--
-- Nen phep kiem dung KHONG phai la them test cho tung nua, ma la GHIM HOP DONG
-- giua chung. Bon phep duoi day la hop dong do.
io.write("\nhop dong: trang challenge <-> /antibot/verify\n")

local ch = slurp(SRC .. "enforcement/challenge/init.lua")
local vt = slurp(SRC .. "enforcement/challenge/verify_token.lua")

if not ch or not vt then
    bad("  SAI  khong doc duoc challenge/init.lua hoac verify_token.lua\n")
else
    -- 5a. Client phai GUI dich den. Thieu no thi may chu chi con Referer, va
    --     Referer trong voi dung nhom khach vao lan dau.
    if ch:find("'dest'", 1, true) then pass = pass + 1 else
        bad("  SAI  trang challenge khong gui truong `dest`\n" ..
            "       => may chu phai doan dich bang Referer, va Referer TRONG\n" ..
            "          voi khach vao lan dau => moi lien ket sau ve `/`\n")
    end

    -- 5b. May chu phai tra thu ma `fetch` DOC DUOC.
    if vt:find("application/json", 1, true) then pass = pass + 1 else
        bad("  SAI  /antibot/verify khong tra JSON\n" ..
            "       => client dung `fetch`, than phan hoi bi vut. Mot trang\n" ..
            "          HTML tu chuyen huong o day KHONG BAO GIO chay.\n")
    end

    -- 5c. Client phai DOC cai do. (Truoc day kiem `r.json()` cua `fetch`;
    --     client nay dung XHR nen phep doc la `JSON.parse`.)
    if ch:find("JSON.parse", 1, true) then pass = pass + 1 else
        bad("  SAI  trang challenge khong doc JSON tra ve\n" ..
            "       => dich den dung nam o may chu ma khong toi duoc client\n")
    end

    -- 5d. Dich den la du lieu do CLIENT gui, nen phai duoc kiem. Mot gia tri
    --     tu do dat vao `Location:` la open redirect; lot `\r\n` la header
    --     injection.
    if vt:find("safe_dest", 1, true) then pass = pass + 1 else
        bad("  SAI  verify_token khong kiem `dest` truoc khi dung\n" ..
            "       => open redirect, va header injection neu lot CR/LF\n")
    end
end

-- ── 6. Trang challenge phai KET THUC DUOC tren moi nhanh ────────────
--
-- Muc 5 ghim NOI DUNG hai nua noi voi nhau. Muc nay ghim mot thu khac han:
-- MAY TRANG THAI cua trang phai co diem dung tren MOI nhanh.
--
-- Vi sao can rieng mot muc. Trieu chung "giai challenge treo, mai khong xong"
-- da duoc va nhieu lan, moi lan mot nguyen nhan: `crypto.subtle` khong ton tai
-- ngoai secure context (va bo sinh config CO chay antibot tren `listen 80`),
-- `setTimeout(0)` moi lan bam bi tran 4ms roi bi ha xuong 1s khi tab chay nen,
-- `fetch` khong co han gio, `document.referrer` trong. Bon nguyen nhan, bon
-- ban va — va lan nao cung "xong" cho toi nguyen nhan thu nam.
--
-- Cai chung cua ca bon: MOT NHANH KHONG CO DIEM DUNG. Nen phep kiem dung khong
-- phai la liet ke bon nguyen nhan do, ma la ghim cac THUOC TINH khien trang
-- khong the treo — ke ca vi mot nguyen nhan chua ai biet.
--
-- Chi kiem trong CHUOI HTML sinh ra trang, khong kiem ca file: chu thich trong
-- file co nhac ten `crypto.subtle`, `fetch`, `referrer` de giai thich vi sao
-- chung bi go. Khong khoanh vung thi chinh loi giai thich se lam test do.
io.write("\nhop dong: trang challenge phai ket thuc duoc\n")

local function page_of(src)
    if not src then return nil end
    return src:match("string%.format%(%[=%[(.-)%]=%]")
end

local page = page_of(ch)

if not page then
    bad("  SAI  khong tach duoc chuoi HTML trong challenge/init.lua\n" ..
        "       => hoac file da doi cau truc, hoac chuoi dai khong dong\n")
else
    -- 6a. Khong duoc phu thuoc thu co the BIEN MAT MA KHONG BAO LOI.
    --     Moi ten duoi day, khi vang mat, deu nem loi ra ngoai IIFE hoac
    --     tao mot Promise bi tu choi ma khong ai bat => con quay quay mai.
    local forbidden = {
        ["crypto.subtle"]   = "khong ton tai ngoai secure context (khach vao bang http://)",
        ["TextEncoder"]     = "khong co tren WebView cu",
        ["URLSearchParams"] = "khong co tren WebView cu",
        ["document.referrer"] = "TRONG voi khach vao lan dau => nem ho ve `/`",
    }
    local dirty = false
    for name, why in pairs(forbidden) do
        if page:find(name, 1, true) then
            dirty = true
            bad("  SAI  trang challenge dung `" .. name .. "`\n" ..
                "       => " .. why .. "\n")
        end
    end
    -- `fetch(` rieng: ten qua ngan de tim tho, phai co dau mo ngoac.
    if page:find("fetch%s*%(") then
        dirty = true
        bad("  SAI  trang challenge dung `fetch(`\n" ..
            "       => khong co han gio; Promise treo thi `.catch` khong chay\n")
    end
    if not dirty then pass = pass + 1 end

    -- 6b. Luoi cuoi cung cho nguyen nhan CHUA BIET. Day la phep kiem quan
    --     trong nhat o muc nay: no khong can biet cai gi hong.
    if page:find("WATCHDOG_MS", 1, true) then pass = pass + 1 else
        bad("  SAI  trang challenge khong co dong ho canh\n" ..
            "       => mot nguyen nhan moi = mot nhanh treo moi, khong co day\n")
    end

    -- 6c. Vong tai lai phai co TRAN. Khong tran thi 403 lap vo han va nguoi
    --     dung chi thay mot con quay khong doi.
    if page:find("MAX_RELOAD", 1, true) then pass = pass + 1 else
        bad("  SAI  vong tai lai sau 403 khong co tran\n")
    end

    -- 6d. Moi lan gui phai co han gio rieng.
    if page:find("xhr.timeout", 1, true) then pass = pass + 1 else
        bad("  SAI  yeu cau verify khong co han gio\n" ..
            "       => doi mang / app vao nen / TCP nua mo = treo vinh vien\n")
    end

    -- 6e. JS bi tat cung phai co mot man hinh noi duoc dieu gi.
    if page:find("<noscript>", 1, true) then pass = pass + 1 else
        bad("  SAI  khong co <noscript>\n")
    end

    -- 6f. Ban SHA-256 tu viet PHAI tu kiem truoc khi dung. Mot ban sai ma im
    --     lang con te hon treo: no gui len loi giai khong hop le va an 403 mai.
    if page:find("ba7816bf8f01cfea414140de5dae2223"
                 .. "b00361a396177a9cb410ff61f20015ad", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  SHA-256 trong trang khong tu kiem bang vector chuan\n")
    end

    -- 6g. Chuoi nay di qua `string.format`. MOT dau `%` le lam ca trang khong
    --     dung duoc — va loi do khong lo ra o bat ky test don vi nao, giong het
    --     ca `RX_FILENAME` viet trong long string hoi 2026-09.
    local i, stray, nq = 1, 0, 0
    while true do
        local p = page:find("%%", i)
        if not p then break end
        local two = page:sub(p, p + 1)
        if two == "%%" then i = p + 2
        elseif two == "%q" then nq = nq + 1; i = p + 2
        else stray = stray + 1; i = p + 1 end
    end
    if stray > 0 then
        bad("  SAI  co %d dau `%%` le trong chuoi challenge\n" ..
            "       => `string.format` se hong hoac nuot ky tu\n", stray)
    else
        pass = pass + 1
    end
    -- So `%q` phai KHOP so doi so truyen vao (token, difficulty, id, cid).
    if nq == 4 then pass = pass + 1 else
        bad("  SAI  co %d cho `%%q` nhung ham truyen 4 doi so\n", nq)
    end
end

-- 6h. Trang challenge KHONG duoc nam lai trong bo nho dem: no mang mot nonce
--     dung mot lan va nam o dung URL bai viet. Lay lai ban cu = giai bang
--     token da chet = 403 = tai lai = vong lap khong loi thoat.
if ch and ch:find("no%-store") then pass = pass + 1 else
    bad("  SAI  trang challenge khong dat Cache-Control: no-store\n" ..
        "       => trinh duyet lay lai ban cu sau khi verify => vong lap\n")
end

-- ── 7. Nguong quyet dinh: MOT nguon, va cac hang so dan xuat phai theo ──
--
-- Truoc thay doi nay, nguong nam o HAI noi va khong noi nao doc noi kia:
-- `cfg.thresholds` ghi challenge=80/block=100 kem chu thich giai thich vi sao
-- da nang len, con engine viet cung 55/80. KHONG mot dong nao doc
-- `cfg.thresholds`. Nen lan hieu chinh do chua bao gio co hieu luc — va nguoi
-- sua config khong co cach nao biet.
--
-- Do lai la dung MOT LOAI loi da lap lai suot: mot gia tri di qua ranh gioi va
-- hai ben hieu khac nhau. Nen phep kiem khong phai la "config bang 55" (roi se
-- lac hau ngay khi ai do doi chinh sach), ma la BAT BIEN giua cac con so.
io.write("\nhop dong: nguong quyet dinh\n")

local engine_src = slurp(SRC .. "enforcement/decision/engine.lua")
local cfg_src    = slurp(SRC .. "core/config.lua")

local function num(src, pat)
    if not src then return nil end
    return tonumber(src:match(pat))
end

if not engine_src or not cfg_src then
    bad("  SAI  khong doc duoc engine.lua hoac config.lua\n")
else
    -- Doc trong THAN BANG `_M.thresholds`, khong doc ca file: chu thich phia
    -- tren bang co nhac "challenge=80" de giai thich, va mot mau tho se doc
    -- nham chinh loi giai thich do.
    local tbl = cfg_src:match("_M%.thresholds%s*=%s*{(.-)}") or ""
    local MON = tonumber(tbl:match("monitor%s*=%s*(%d+)"))
    local CHA = tonumber(tbl:match("challenge%s*=%s*(%d+)"))
    local BLO = tonumber(tbl:match("block%s*=%s*(%d+)"))

    if not MON or not CHA or not BLO then
        bad("  SAI  khong doc duoc `_M.thresholds` trong config.lua\n")
    else
        -- 7a. Engine PHAI doc config, khong duoc viet cung lai.
        if engine_src:find("cfg%.thresholds") then pass = pass + 1 else
            bad("  SAI  engine.lua khong doc `cfg.thresholds`\n" ..
                "       => nguong lai co hai nguon, va sua config vo tac dung\n")
        end

        -- 7b. Thu tu co ban.
        if MON < CHA and CHA < BLO then pass = pass + 1 else
            bad("  SAI  nguong khong tang dan: monitor=%d challenge=%d block=%d\n",
                MON, CHA, BLO)
        end

        -- 7c. San cua kill-switch phai NAM TREN nguong tuong ung, neu khong
        --     thi kill-switch khong kill gi ca. Chung duoc dan xuat trong
        --     engine, nen o day chi kiem viec dan xuat con nguyen.
        if engine_src:find("KILL_CHALLENGE_EFF%s*=%s*T%.CHALLENGE")
           and engine_src:find("KILL_BLOCK_EFF%s*=%s*T%.BLOCK") then
            pass = pass + 1
        else
            bad("  SAI  KILL_*_EFF khong con dan xuat tu nguong\n" ..
                "       => nang nguong se lam resource kill-switch chet lang:\n" ..
                "          san 60 duoi challenge 80 = chi con monitor\n")
        end

        -- 7d. Hai kill-switch cho class bi giam diem la PHAN TRAM nen KHONG
        --     tu di theo nguong. Day la cho de chet lang nhat.
        local SR = num(engine_src, "local KILL_DAMP_SOFT_RAW%s*=%s*([%d%.]+)")
        local SP = num(engine_src, "local KILL_DAMP_SOFT_PCT%s*=%s*([%d%.]+)")
        local HR = num(engine_src, "local KILL_DAMP_HARD_RAW%s*=%s*([%d%.]+)")
        local HP = num(engine_src, "local KILL_DAMP_HARD_PCT%s*=%s*([%d%.]+)")
        if not (SR and SP and HR and HP) then
            bad("  SAI  khong doc duoc hang so KILL_DAMP_* trong engine.lua\n")
        elseif SR * SP < CHA then
            bad("  SAI  kill_damp_soft chet lang: raw %d x %.2f = %.1f < challenge %d\n" ..
                "       => class bi giam diem khong con len duoc challenge\n",
                SR, SP, SR * SP, CHA)
        elseif HR * HP < BLO then
            bad("  SAI  kill_damp_hard chet lang: raw %d x %.2f = %.1f < block %d\n" ..
                "       => ca 20.9.70.139 trong CLAUDE.md se khong con bi chan\n",
                HR, HP, HR * HP, BLO)
        else
            pass = pass + 1
        end

        -- 7e. Nguong ha khi ip_risk cao phai THAP HON nguong thuong, neu
        --     khong thi no khong ha gi ca.
        local CAP = num(engine_src, "local IP_RISK_CHALLENGE_CAP%s*=%s*(%d+)")
        if CAP and CAP < CHA then pass = pass + 1 else
            bad("  SAI  IP_RISK_CHALLENGE_CAP=%s khong thap hon challenge=%d\n",
                tostring(CAP), CHA)
        end
    end
end

-- ── 8. Trang thai mot lan thach do: phat <-> kiem ───────────────────
--
-- Verifier cu chi kiem `sha256(token .. n)` co tien to dung roi xoa
-- `nonce:<identity>`. No KHONG kiem token co phai do may chu phat hay khong,
-- nen mot bot chi can tim MOT cap (token, n) hop le DUNG MOT LAN roi dung lai
-- mai mai, cho moi danh tinh, moi ten mien. Chi phi PoW bi triet tieu.
--
-- Loi thu hai bi loi thu nhat CHE: `nonce_store` dung SETNX theo danh tinh va
-- `challenge/init.lua` bo qua ket qua, nen hai tab nhan token moi trong khi
-- Redis giu nonce cu. Vi token khong duoc kiem nen khong ai thay. Sua nua
-- truoc ma giu nua sau thi loi bi che se thanh loi verify that.
io.write("\nhop dong: trang thai mot lan thach do\n")

local ns = slurp(SRC .. "enforcement/challenge/nonce_store.lua")

if not ns or not ch or not vt then
    bad("  SAI  khong doc duoc nonce_store/challenge/verify_token\n")
else
    -- 8a. Trang thai phai khoa theo LAN thach do, khong theo danh tinh.
    -- `:setnx` chu khong phai `setnx`: bat LOI GOI HAM (`red:setnx(...)`),
    -- khong bat chu SETNX trong chinh doan chu thich giai thich vi sao no bi go.
    if ns:find("chal:", 1, true) and not ns:find(":setnx", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  nonce_store khong ghi `chal:<cid>` hoac con dung SETNX\n" ..
            "       => hai tab dung chung mot khoa: tab sau de tab truoc\n")
    end

    -- 8b. Client phai GUI ma cua lan thach do do.
    if ch:find("'c', cid", 1, true) then pass = pass + 1 else
        bad("  SAI  trang challenge khong gui ma lan thach do\n")
    end

    -- 8c. Verifier phai DOC trang thai va SO SANH token.
    if vt:find("chal:", 1, true) and vt:find("const_eq", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  verify_token khong doi chieu token voi trang thai da luu\n" ..
            "       => PoW tinh truoc mot lan roi dung lai vo han\n")
    end

    -- 8d. Tieu thu phai NGUYEN TU: chi ke nhan DEL == 1 moi duoc di tiep.
    if vt:find('red:del%("chal:"') and vt:find("~= 1") then
        pass = pass + 1
    else
        bad("  SAI  verify_token khong tieu thu trang thai nguyen tu\n")
    end

    -- 8e. Khoa cu phai BIEN MAT hoan toan khoi ca hai nua.
    if not ns:find('"nonce:"', 1, true)
       and not vt:find('"nonce:"', 1, true) then
        pass = pass + 1
    else
        bad("  SAI  con sot khoa `nonce:<identity>` cu\n" ..
            "       => hai so do song song, va chung se lech\n")
    end
end

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
