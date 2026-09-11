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

-- ── 9. Thang ba nac cua cipher list JA3 ─────────────────────────────
--
-- Ghim CAU TRUC, khong ghim GIA TRI: nguoi van hanh se doi
-- `cfg.tls.ja3_cipher` giua off/probe/on, nen mot phep kiem "phai bang off"
-- se chan deploy dung luc dang trien khai. Cai phai giu nguyen la hai tinh
-- chat an toan cua thang do.
io.write("\nhop dong: thang cipher list JA3\n")

local ja3_src = slurp(SRC .. "transport/tls/ja3.lua")
local cfgsrc  = slurp(SRC .. "core/config.lua")

if not ja3_src or not cfgsrc then
    bad("  SAI  khong doc duoc ja3.lua hoac config.lua\n")
else
    -- 9a. Nac giua PHAI khong the tu bat. Chi so sanh voi "on" moi duoc phep
    --     xoa co partial; thieu phep so sanh do thi "probe" lam doi hash JA3
    --     cua toan bo dan may ma khong ai chu y.
    if ja3_src:find('CIPHER_MODE == "on"', 1, true) then pass = pass + 1 else
        bad("  SAI  ja3.lua khong con gac `CIPHER_MODE == \"on\"`\n" ..
            "       => nac `probe` se doi hash JA3 that => fp_light doi mot\n" ..
            "          luot tren toan dan may, ngoai y muon\n")
    end

    -- 9b. KHONG duoc doan hinh dang tra ve cua API. Doan sai => danh sach
    --     cipher rong => ja3_allowlist cham `cipher_count < 5` = 0.6 x 50
    --     = 30 diem oan cho TAT CA.
    if ja3_src:find('type(raw) == "table"', 1, true)
       and ja3_src:find('type(raw) == "string"', 1, true) then
        pass = pass + 1
    else
        bad("  SAI  parse_ciphers khong con xu ly ca bang lan chuoi byte\n" ..
            "       => doan sai hinh dang = 30 diem oan cho moi client\n")
    end

    -- 9c. Phai co nac de KIEM. Khong co `probe` thi chi con off/on, tuc la
    --     nhay thang vao thay doi hanh vi ma khong co buoc quan sat nao.
    if cfgsrc:find("ja3_cipher", 1, true) and ja3_src:find("cipher_probe", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  mat nac `probe` (log `[ja3] cipher_probe`)\n" ..
            "       => len `on` la doan, khong phai do\n")
    end

    -- 9d. Cot log phai ton tai, neu khong thi ca cuoc trien khai la mu.
    local lg = slurp(SRC .. "async/logger.lua")
    if lg and lg:find("ja3c=", 1, true) and lg:find("j3m=", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  antibot.log thieu cot `ja3c=` hoac `j3m=`\n" ..
            "       => khong doc duoc API co lay duoc cipher khong, va\n" ..
            "          khong thay duoc ja3_allowlist_miss khi len `on`\n")
    end
end
-- ── 10. parse_ciphers: CHAY THAT, khong tim chuoi ───────────────────
--
-- Muc 9 tim chuoi trong ma nguon. Dau file nay da ghi ro dieu do khong chung
-- minh duoc gi — mot phep so sanh nam trong khoi chu thich van lam no xanh.
-- Voi thang cipher, mau xanh gia dat hon o moi cho khac: bat nac "on" doi
-- chinh sach cham diem cua CA DAN MAY trong mot lan reload.
--
-- Nen muc nay NAP module va GOI HAM. `ja3.lua` khong dung `ngx` nao o muc
-- top-level va `require` config duoc boc pcall, nen `loadfile` chay duoc kho
-- ma khong can ha tang gi.
io.write("\nhanh vi: parse_ciphers (chay that)\n")

local ja3_chunk = loadfile(SRC .. "transport/tls/ja3.lua")
if not ja3_chunk then
    bad("  SAI  khong nap duoc transport/tls/ja3.lua\n")
else
    local ok_load, ja3_mod = pcall(ja3_chunk)
    local pc = ok_load and type(ja3_mod) == "table" and ja3_mod._parse_ciphers
    if not pc then
        bad("  SAI  ja3.lua khong lo `_parse_ciphers` (muc 10 khong chay duoc)\n")
    else
        -- Moi ca: {nhan, dau vao, so cipher mong doi, `valid` mong doi}
        local cases = {
            -- Bang so hop le: 5 suite that cua mot ClientHello TLS 1.3.
            { "bang so hop le",
              { 4865, 4866, 4867, 49195, 49199 }, 5, true },
            -- Chuoi byte: 0x1301 0x1302 = TLS_AES_128/256_GCM_SHA384.
            { "chuoi byte chan",
              "\19\1\19\2", 2, true },
            -- GREASE (0x0a0a) phai bi loai, phan con lai giu nguyen.
            { "GREASE bi loai",
              { 0x0a0a, 4865, 4866 }, 2, true },
            -- DO DAI LE = doc lech khung 2 byte. Phai VUT CA DANH SACH.
            { "chuoi byte le -> khong hop le",
              "\19\1\19", 0, false },
            -- Mot phan tu khong phai so = hieu sai kieu tra ve. Vut ca danh sach.
            { "bang co phan tu rac -> khong hop le",
              { 4865, "rac" }, 0, false },
            -- Ngoai 0..65535 = khong phai cipher id.
            { "so ngoai khoang -> khong hop le",
              { 4865, 70000 }, 0, false },
            -- API tra nil (khong ton tai / loi da nuot).
            { "nil -> khong hop le",
              nil, 0, false },
        }

        for _, c in ipairs(cases) do
            local label, input, want_n, want_valid = c[1], c[2], c[3], c[4]
            local ok_call, out, shape, valid = pcall(pc, input)
            if not ok_call then
                bad("  SAI  parse_ciphers nem loi voi ca `%s`: %s\n",
                    label, tostring(out))
            elseif #out ~= want_n then
                bad("  SAI  `%s`: mong %d cipher, nhan %d (shape=%s)\n",
                    label, want_n, #out, tostring(shape))
            elseif valid ~= want_valid then
                bad("  SAI  `%s`: mong valid=%s, nhan %s (shape=%s)\n",
                    label, tostring(want_valid), tostring(valid),
                    tostring(shape))
            else
                pass = pass + 1
            end
        end

        -- 10b. SAN PHAI KHOP VOI NGUONG PHAT O PHIA BEN KIA.
        --
        -- `ja3.lua` chi bo co `partial` khi so cipher >= MIN_PLAUSIBLE_CIPHERS.
        -- `ja3_allowlist.lua` phat 0.6 (x trong so 50 = 30 diem) khi
        -- `cipher_count < 5`. Neu san tut xuong duoi 5 thi moi danh sach nam
        -- giua hai con so do duoc cong bo la "JA3 day du" roi an 30 diem oan —
        -- dung con duong ma san nay sinh ra de chan.
        local min = ja3_mod._MIN_PLAUSIBLE_CIPHERS
        local allow_src = slurp(SRC .. "intelligence/threat/ja3_allowlist.lua")
        -- Bat MA THAT (`if cipher_count < N then`), khong bat chu thich — dung cai
    -- bay ma chinh dau file nay canh bao.
    local pen = allow_src and allow_src:match("if%s+cipher_count%s*<%s*(%d+)%s+then")
        if type(min) ~= "number" then
            bad("  SAI  ja3.lua khong lo `_MIN_PLAUSIBLE_CIPHERS`\n")
        elseif not pen then
            bad("  SAI  khong tim thay nguong `cipher_count < N` trong ja3_allowlist.lua\n")
        elseif min < tonumber(pen) then
            bad("  SAI  san %d < nguong phat %s\n" ..
                "       => danh sach %d..%d cipher se duoc cong bo la JA3 day\n" ..
                "          du roi an 0.6 x 50 = 30 diem oan\n",
                min, pen, min, tonumber(pen) - 1)
        else
            pass = pass + 1
        end

        -- ── 10c. TRI-STATE `tls13`: round-trip serialize -> deserialize ──
        --
        -- Bug that, 2026-09-07:
        --     is_tls13 = (parts[1] == "?") and nil or (parts[1] == "1")
        -- Trong Lua `x and nil or y` KHONG BAO GIO tra ve duoc nil — ve giua
        -- bang nil nen `and` cho nil, roi thang sang ve `or` => "?" thanh
        -- **false**. Ma `false` co nghia "client chao TLS 1.2", va
        -- `consistency_check` nhanh `tls12` cong +0.35 x 55 = 19,25 diem cho
        -- moi client ma loi duy nhat la TA doc khong noi.
        --
        -- Muc 9 (tim chuoi) KHONG bat duoc: chuoi "?" van nam trong ma nguon
        -- nen mau van xanh. Chi round-trip that moi bat.
        local ser, deser = ja3_mod._serialize, ja3_mod._deserialize
        if type(ser) ~= "function" or type(deser) ~= "function" then
            bad("  SAI  ja3.lua khong lo `_serialize`/`_deserialize`\n")
        else
            local rt = {
                { "true  -> 1 -> true",  true,  true  },
                { "false -> 0 -> false", false, false },
                { "nil   -> ? -> nil",   nil,   nil   },
            }
            for i = 1, 3 do
                local c = rt[i]
                local label, input, want = c[1], c[2], c[3]
                local ok_s, payload = pcall(ser, input, {}, {}, {}, {}, true)
                if not ok_s then
                    bad("  SAI  serialize nem loi voi `%s`: %s\n",
                        label, tostring(payload))
                else
                    local ok_d, out = pcall(deser, payload)
                    if not ok_d or type(out) ~= "table" then
                        bad("  SAI  deserialize hong voi `%s`\n", label)
                    elseif out.is_tls13 ~= want then
                        bad("  SAI  `%s`: mong %s, nhan %s (payload=%q)\n",
                            label, tostring(want), tostring(out.is_tls13),
                            payload)
                    else
                        pass = pass + 1
                    end
                end
            end

            -- Nua con lai cua cung mot bug: sua "?" ma van de RAC roi vao
            -- `false` thi cua cong diem oan chua dong. Rac phai ra nil.
            for _, junk in ipairs({ "x", "", "01", "true", "?!" }) do
                local out = deser(junk .. "|||||1")
                if out and out.is_tls13 ~= nil then
                    bad("  SAI  rac %q giai ma thanh %s, phai la nil\n",
                        junk, tostring(out.is_tls13))
                else
                    pass = pass + 1
                end
            end
        end

        -- ── 10d. Extension VANG khac extension CO MA THAN RONG ───────────
        --
        -- Vang = su that ve client, JA3 ma hoa bang truong rong => ok=true.
        -- Than 0 byte = khung hong (RFC 8422 doi 2 byte do dai, RFC 4492 doi
        -- 1 byte) => ok=false. Gop hai cai lam mot thi mot ClientHello di dang
        -- sinh ra DUNG chuoi JA3 cua client hop le khong gui extension — mot
        -- va cham bat chuoc duoc.
        local pg, pf = ja3_mod._parse_groups, ja3_mod._parse_pt_fmts
        if type(pg) ~= "function" or type(pf) ~= "function" then
            bad("  SAI  ja3.lua khong lo `_parse_groups`/`_parse_pt_fmts`\n")
        else
            -- BA cua vao cua cung mot lo hong, khong phai hai:
            --   VANG han          -> hop le (su that ve client)
            --   than 0 byte       -> hong
            --   than co truong do dai, KHAI BAO danh sach rong -> hong
            -- Cua thu ba lot qua moi phep kiem cu (`0 % 2 == 0`, `2+0 == 2`)
            -- roi tra `{}, true`, tuc sinh ra DUNG chuoi JA3 cua client hop le
            -- khong gui extension.
            local ec = {
                { "supported_groups VANG        -> ok",   pg, nil, true  },
                { "supported_groups than rong   -> hong", pg, "",  false },
                { "supported_groups khai bao 0  -> hong", pg,
                  string.char(0, 0), false },
                { "ec_point_formats VANG        -> ok",   pf, nil, true  },
                { "ec_point_formats than rong   -> hong", pf, "",  false },
                { "ec_point_formats khai bao 0  -> hong", pf,
                  string.char(0), false },
            }
            for i = 1, 6 do
                local c = ec[i]
                local label, fn, input, want = c[1], c[2], c[3], c[4]
                local ok_call, _, okflag = pcall(fn, input)
                if not ok_call then
                    bad("  SAI  `%s` nem loi\n", label)
                elseif okflag ~= want then
                    bad("  SAI  `%s`: mong ok=%s, nhan %s\n",
                        label, tostring(want), tostring(okflag))
                else
                    pass = pass + 1
                end
            end
        end

        -- ── 10e. `supported_versions`: BA TRANG THAI, va cua thu ba ──────
        --
        -- `false` phai co nghia "client KHONG chao TLS 1.3" — mot SU THAT —
        -- chu khong duoc kiem luon nghia "doc hong", vi `consistency_check`
        -- doc `ctx.tls13_offered == false` roi cong 0.35 x 55 = 19,25 diem.
        -- Truoc day phan nay nam INLINE trong `capture()` nen khong co cach
        -- nao kiem bang test hanh vi; nay tach thanh `_parse_versions`.
        local pv = ja3_mod._parse_versions
        if type(pv) ~= "function" then
            bad("  SAI  ja3.lua khong lo `_parse_versions`\n")
        else
            local vc = {
                { "vang han ext 43           -> false", nil,                 false },
                { "than rong                 -> nil",   "",                  nil   },
                { "KHAI BAO do dai 0         -> nil",   string.char(0),      nil   },
                { "khai bao le               -> nil",   string.char(3,3,3),  nil   },
                { "khai bao khong khop than  -> nil",   string.char(4,3,4),  nil   },
                { "co 0x0304                 -> true",  string.char(2,3,4),  true  },
                { "chi co 0x0303             -> false", string.char(2,3,3),  false },
                { "0x0304 o vi tri 2         -> true",  string.char(4,3,3,3,4), true },
            }
            for i = 1, 8 do
                local c = vc[i]
                local label, input, want = c[1], c[2], c[3]
                local ok_call, got = pcall(pv, input)
                if not ok_call then
                    bad("  SAI  `%s` nem loi: %s\n", label, tostring(got))
                elseif got ~= want then
                    bad("  SAI  `%s`: mong %s, nhan %s\n",
                        label, tostring(want), tostring(got))
                else
                    pass = pass + 1
                end
            end
        end
    end
end


-- ── 11. Cong `ext_ok`: extension khong dung duoc thi KHONG duoc goi la
--        JA3 day du ────────────────────────────────────────────────────
--
-- Cung hinh dang muc 10, truc khac. `parse_ciphers` da co cong; nhung mot JA3
-- co du 5 cipher ma danh sach extension RONG (API thieu/loi) hoac MAT THU TU
-- (lua-resty-core < 0.1.25 tra bang bam) van tung duoc cong bo la day du:
--   • rong    -> `ja3_allowlist` dem browser_ext_count = 0 -> ext_score 0.4
--                x trong so 50 = 20 diem oan
--   • mat thu tu -> hash doi giua cac lan duyet bang -> fp_light churn,
--                `sess:` mo coi, va `ja3:allow:` dat tay khong bao gio khop
io.write("\nhanh vi: cong ext_ok cua JA3\n")

local ja3_b = slurp(SRC .. "transport/tls/ja3.lua")
if not ja3_b then
    bad("  SAI  khong doc duoc transport/tls/ja3.lua\n")
else
    -- 11a. Co phai co ca hai ve trong dieu kien ha `is_partial` khong.
    if ja3_b:find("and data%.ext_ok") then pass = pass + 1 else
        bad("  SAI  run() khong con doi hoi `data.ext_ok` truoc khi bo partial\n" ..
            "       => extension rong/mat thu tu van thanh JA3 day du\n")
    end

    -- 11b. Co phai `ext_ok` that su di qua duoc shared dict khong. Neu chi tinh
    --      o capture ma khong serialize thi run() luon doc ra nil.
    if ja3_b:find("ext_ok and \"1\" or \"0\"", 1, true)
       and ja3_b:find("ext_ok     = parts[6]", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  `ext_ok` khong duoc serialize/deserialize\n" ..
            "       => co tinh o capture nhung run() doc ra nil\n")
    end

    -- 11c. Payload CU (4 hoac 5 truong, con nam trong shared dict toi da 300s
    --      sau reload) phai van giai ma duoc. Them truong vao GIUA la gay het.
    local des = ja3_b:match("local function deserialize.-\nend")
    if des and des:find("#parts < 4", 1, true) then pass = pass + 1 else
        bad("  SAI  deserialize khong con chap nhan payload 4 truong\n" ..
            "       => moi ket noi mo truoc reload mat JA3 trong 300s\n")
    end

    -- 11d. Hai bo phan tich extension phai TU CHOI du lieu bi cat ngan, chu
    --      khong `math.min` cho vua roi tra ve nhu binh thuong.
    if not ja3_b:find("math%.min%(pos %+ len %- 1, #ext_data%)")
       and not ja3_b:find("math%.min%(1 %+ flen, #ext_data%)")
       and ja3_b:find("return {}, false", 1, true) then
        pass = pass + 1
    else
        bad("  SAI  parse_supported_groups/parse_ec_point_formats quay lai\n" ..
            "       cat theo `math.min` => cong bo mot JA3 sai ma khong ai biet\n")
    end
end

-- ── 12. `tls13` la CLIENT CHAO, khong phai phien ban DA THUONG LUONG ──
--
-- Ten cu `ctx.tls13` moi goi lan sua sau doc no thanh "phien ban TLS that".
-- No KHONG phai: no doc tu extension `supported_versions` cua ClientHello.
-- Voi tang `mismatch` thi "client tu nhan gi" moi dung la thu can so — nhung
-- dieu do phai nam trong TEN, khong phai trong chu thich (CLAUDE.md cua repo
-- nay: chu thich sai co he thong).
io.write("\nhop dong: ten truong tls13\n")
do
    local leftovers = {}
    for _, rel in ipairs({
        "transport/tls/ja3.lua",
        "intelligence/correlation/consistency_check.lua",
        "transport/http2/pseudo_header.lua",
        "enforcement/decision/engine.lua",
        "async/logger.lua",
    }) do
        local s = slurp(SRC .. rel)
        if s and s:find("ctx%.tls13[^_]") then leftovers[#leftovers+1] = rel end
    end
    if #leftovers == 0 then pass = pass + 1 else
        bad("  SAI  con `ctx.tls13` (khong hau to `_offered`) tai: %s\n" ..
            "       => hai ten cho mot truong, dung sai ngu nghia la chuyen som muon\n",
            table.concat(leftovers, ", "))
    end
end

-- ── 13. `fp_light` KHONG duoc bam tu `h2_sig` ────────────────────────────
--
-- Do 2026-09-07 tren 5 may, trong pham vi tung ket noi TLS: 1213/1228
-- (98,8%) ket noi H2 co `fp_light` doi la ket noi co `h2_sig` doi. Ba trong
-- sau thanh phan cua `h2_sig` la thuoc tinh cua REQUEST, khong phai cua
-- client (`transport/http2/signature.lua:3`).
--
-- Hai cach lam hong lai, muc nay chan ca hai:
--   1. doi `table.concat(components, "|", 1, HASH_PARTS)` ve `(components, "|")`
--   2. bo `h2_sig` khoi CA `components` — se rut mau so `fp_quality` tu 5
--      xuong 4, day client H2 thieu ja3+asn tu 0,60 xuong 0,50 => qua nguong
--      0,55 => +5 diem `fp_degraded` oan. Nen `#components` PHAI con la 5.
io.write("\nfp_light: khong bam tu h2_sig\n")
do
    local src = slurp(SRC .. "core/fingerprint/build_light.lua")
    if not src then
        bad("  SAI  khong doc duoc core/fingerprint/build_light.lua\n")
    else
        local n = src:match("local%s+HASH_PARTS%s*=%s*(%d+)")
        if n ~= "4" then
            bad("  SAI  HASH_PARTS = %s, phai la 4 (ip|ua|asn|ja3)\n",
                tostring(n))
        else pass = pass + 1 end

        -- Bat DONG LENH THAT, khong bat chu thich.
        local hash_line = src:match("\n%s*ctx%.fp_light%s*=%s*([^\n]+)")
        if not hash_line then
            bad("  SAI  khong tim thay dong gan `ctx.fp_light`\n")
        elseif not hash_line:find("HASH_PARTS", 1, true) then
            bad("  SAI  ctx.fp_light bam ma KHONG gioi han HASH_PARTS:\n" ..
                "         %s\n" ..
                "       => h2_sig quay lai trong bam => fp_light churn moi\n" ..
                "          request H2 => sess:<fp_light> vun nat.\n", hash_line)
        else pass = pass + 1 end

        local qual_line = src:match("\n%s*ctx%.fp_quality%s*=%s*([^\n]+)")
        if not qual_line then
            bad("  SAI  khong tim thay dong gan `ctx.fp_quality`\n")
        elseif not qual_line:find("#components", 1, true) then
            bad("  SAI  fp_quality khong con chia cho `#components`:\n" ..
                "         %s\n" ..
                "       => neu mau so tut ve 4 thi client H2 thieu ja3+asn\n" ..
                "          roi tu 0,60 xuong 0,50 => +5 diem oan.\n", qual_line)
        else pass = pass + 1 end
    end

    -- 13b. HANH VI, khong phai tim chuoi. `HASH_PARTS == 4` KHONG khoa duoc
    -- THU TU: doi `components` de `h2_sig` len vi tri 4 thi ba phep kiem tren
    -- van xanh ma bug quay lai nguyen ven. Chi goi ham that moi bat duoc.
    --
    -- `build_light.lua` require `identity` o top-level khong boc pcall, ma
    -- thu muc trong cay nguon ten `antibot-core` chu khong phai `antibot` nen
    -- `require` khong giai duoc. Nap san mot ban gia — muc nay kiem CACH BAM,
    -- khong kiem `identity`.
    package.preload["antibot.core.fingerprint.identity"] = function()
        return { build = function() end }
    end
    local bl_chunk = loadfile(SRC .. "core/fingerprint/build_light.lua")
    if not bl_chunk then
        bad("  SAI  khong nap duoc core/fingerprint/build_light.lua\n")
    else
        local ok_bl, bl = pcall(bl_chunk)
        if not ok_bl or type(bl) ~= "table" or type(bl.run) ~= "function" then
            bad("  SAI  build_light.lua khong tra ve module co `run`\n")
        else
            local function mk(h2s, ja3)
                return { ip = "1.2.3.4", ua = "Mozilla/5.0", ja3 = ja3,
                         asn = { asn_number = 12345 }, h2_sig = h2s }
            end
            local a, b, c = mk("AAA", "J1"), mk("BBB", "J1"), mk("AAA", "J2")
            -- GIỮ kết quả `pcall`. Vứt đi thì một lỗi ném ra SAU khi
            -- `ctx.fp_light` đã được gán sẽ bị nuốt trọn: ba phép so bên dưới
            -- vẫn xanh trong khi `run()` thật ra đã chết giữa chừng. Hôm nay
            -- sau dòng gán chỉ còn khối `fp_degraded` gọi `ngx.log`, nhưng
            -- test tồn tại để bắt cái NGÀY MAI thêm vào. Và đây đúng là hình
            -- dạng lỗi cả mục 10 đang chặn: "không biết" bị nhét thành "biết".
            local errs = {}
            for _, t in ipairs({ { "a", a }, { "b", b }, { "c", c } }) do
                local ok_run, err_run = pcall(bl.run, t[2])
                if not ok_run then
                    errs[#errs + 1] = t[1] .. ": " .. tostring(err_run)
                end
            end
            if #errs > 0 then
                bad("  SAI  build_light.run NEM LOI: %s\n",
                    table.concat(errs, " | "))
            end

            if not a.fp_light then
                bad("  SAI  build_light.run khong dat `fp_light`\n")
            else
                if a.fp_light ~= b.fp_light then
                    bad("  SAI  CHI `h2_sig` doi ma `fp_light` DOI THEO.\n" ..
                        "       => h2_sig quay lai trong bam. Do 2026-09-07:\n" ..
                        "          1235/1250 ket noi H2 churn la vi no.\n")
                else pass = pass + 1 end

                if a.fp_light == c.fp_light then
                    bad("  SAI  `ja3` doi ma `fp_light` KHONG doi => ja3 da\n" ..
                        "       roi khoi bam, mat mot thanh phan van tay THAT.\n")
                else pass = pass + 1 end

                if type(a.fp_quality) ~= "number" then
                    bad("  SAI  build_light.run khong dat `fp_quality`\n")
                elseif a.fp_quality < 0.999 then
                    bad("  SAI  fp_quality = %.3f, mong 1.000 khi du ca 5\n" ..
                        "       thanh phan => mau so da tut khoi 5 => client\n" ..
                        "       H2 thieu ja3+asn roi tu 0,60 xuong 0,50 =\n" ..
                        "       +5 diem `fp_degraded` oan.\n", a.fp_quality)
                else pass = pass + 1 end
            end
        end
    end
end


-- ── 14. RANH GIOI API: `nil` vs `nil, err` ───────────────────────────────
--
-- `ngx.ssl.clienthello` dung quy uoc chung cua lua-resty-core: extension VANG
-- tra `nil` tron, con DOC LOI tra `nil, err`. Nhan moi gia tri dau ma vut gia
-- tri thu hai la bien "khong doc duoc" thanh "khong ton tai" — dung con bug
-- ba cua truoc, chi dich len tang API.
--
-- HAI LOP KIEM, vi hai kieu hong khac nhau va khong lop nao thay duoc lop kia:
--   14a/14b HANH VI — hai ham thuan quyet dinh DUNG chua. Bat duoc viec ai do
--           xoa `ext_ok = false` o nhanh api_err, thu ma tim-chuoi khong thay.
--   14c NGUON — cho GOI co nhan gia tri thu hai khong. Ham thuan co dung den
--           may cung vo nghia neu `err` khong bao gio toi duoc no; luc do
--           `api_state(true, nil, nil)` tra "absent" va cua lai mo nguyen.
io.write("\nja3: ranh gioi API tra `nil, err`\n")
do
    local src = slurp(SRC .. "transport/tls/ja3.lua")
    local ja3_chunk = loadfile(SRC .. "transport/tls/ja3.lua")
    local ja3m
    if ja3_chunk then
        local ok_l, m = pcall(ja3_chunk)
        if ok_l then ja3m = m end
    end

    if not src or type(ja3m) ~= "table" then
        bad("  SAI  khong nap duoc transport/tls/ja3.lua\n")
    else
        -- 14a. `api_state`: BON trang thai, khong phai hai.
        local st = ja3m._api_state
        if type(st) ~= "function" then
            bad("  SAI  ja3.lua khong lo `_api_state`\n")
        else
            local cases = {
                -- ok_call, value, err            -> mong doi
                { true,  "\003\004", nil,   "ok"      },
                { true,  nil,        nil,   "absent"  },
                { true,  nil,        "boom","api_err" },
                { false, "loi lua",  nil,   "throw"   },
                -- gia tri co that + err rac: KHONG duoc doc thanh loi
                { true,  "\003\004", "x",   "ok"      },
            }
            for i = 1, #cases do
                local c   = cases[i]
                local got = st(c[1], c[2], c[3])
                if got ~= c[4] then
                    bad("  SAI  api_state(%s,%s,%s) = %s, mong %s\n",
                        tostring(c[1]), tostring(c[2]), tostring(c[3]),
                        tostring(got), c[4])
                else pass = pass + 1 end
            end
        end

        -- 14b. `read_ext_list`: BON trang thai vao, HAI quyet dinh ra.
        --
        -- Day la muc chan duoc con regression dat nhat: `absent` phai GIU
        -- `ext_ok`, con `api_err`/`throw` phai HA no. Lan nguoc hai cai do la
        -- hoac cong bo JA3 thieu extension la day du (mo cua cho nac cipher
        -- "on"), hoac danh dau moi ClientHello hop le khong gui
        -- `supported_groups` la "thieu".
        local rl = ja3m._read_ext_list
        if type(rl) ~= "function" then
            bad("  SAI  ja3.lua khong lo `_read_ext_list`\n")
        else
            local function parse_ok(v)   return { 23, 24 }, true  end
            local function parse_bad(v)  return {},         false end

            local cases = {
                -- state,     parser,    mong ok,  nhan
                { "absent",   parse_bad, true,
                  "vang that => ext_ok GIU NGUYEN (client duoc phep khong gui)" },
                { "api_err",  parse_ok,  false,
                  "doc loi => ext_ok PHAI ha, du parser co noi gi" },
                { "throw",    parse_ok,  false,
                  "pcall bat loi => ext_ok PHAI ha" },
                { "ok",       parse_ok,  true,
                  "doc duoc + parser xanh => giu" },
                { "ok",       parse_bad, false,
                  "doc duoc + parser do => ha" },
            }
            for i = 1, #cases do
                local c = cases[i]
                local list, ok_flag = rl(c[1], "\000\002\000\023", c[2])
                if ok_flag ~= c[3] then
                    bad("  SAI  read_ext_list(%s) tra ok=%s, mong %s\n" ..
                        "       %s\n",
                        c[1], tostring(ok_flag), tostring(c[3]), c[4])
                elseif type(list) ~= "table" then
                    bad("  SAI  read_ext_list(%s) khong tra bang\n", c[1])
                else pass = pass + 1 end
            end

            -- `api_err` va `throw` phai tra DANH SACH RONG, khong duoc de lot
            -- ket qua cua parser ra ngoai: mot danh sach nua voi con te hon
            -- danh sach rong vi no van di vao chuoi JA3.
            for _, s in ipairs({ "api_err", "throw" }) do
                local list = rl(s, "\000\002\000\023", parse_ok)
                if #list ~= 0 then
                    bad("  SAI  read_ext_list(%s) tra %d phan tu, phai rong\n",
                        s, #list)
                else pass = pass + 1 end
            end
        end

        -- 14c. NGUON: `err` co toi duoc ham thuan khong.
        for _, t in ipairs({ { "0x002b", "supported_versions" },
                             { "0x000a", "supported_groups"   },
                             { "0x000b", "ec_point_formats"   } }) do
            local pat = "local%s+[%w_]+%s*,%s*[%w_]+%s*=%s*"
                        .. "ssl_clt%.get_client_hello_ext%(" .. t[1] .. "%)"
            if not src:find(pat) then
                bad("  SAI  %s (%s): khong nhan gia tri thu hai cua\n" ..
                    "       get_client_hello_ext => `err` khong bao gio toi\n" ..
                    "       api_state, va loi API thanh 'extension vang'.\n",
                    t[2], t[1])
            else pass = pass + 1 end
        end

        for _, t in ipairs({ "get_client_hello_ext_present",
                             "get_client_hello_ciphers" }) do
            local pat = "local%s+[%w_]+%s*,%s*[%w_]+%s*,%s*[%w_]+%s*="
                        .. "%s*\n?%s*pcall%(ssl_clt%." .. t
            if not src:find(pat) then
                bad("  SAI  pcall(%s) khong nhan bien thu ba:\n" ..
                    "       API loi cho ra `true, nil, err` va `err` roi mat.\n", t)
            else pass = pass + 1 end
        end

        -- 14d. Log loi API phai CO TRAN. Mot ban thu vien hong he thong se
        -- sinh mot dong ERR moi bat tay TLS — hang tram nghin dong/ngay, tu
        -- tay giet chinh file dung de chan doan.
        --
        -- HANH VI, khong phai hinh thuc. Ban 14d dau tien chi grep regex nen
        -- no xanh voi CA hai cai dat: counter chung va counter theo loai. Ma
        -- counter chung chinh la khiem khuyet — no khong phai "lay mau it di",
        -- no la "co loai KHONG BAO GIO in".
        local bump = ja3m._bump
        if type(bump) ~= "function" then
            bad("  SAI  ja3m._bump khong duoc export => 14d khong kiem duoc\n")
        else
            -- Lan dau cua MOI loai phai in ngay.
            local t1 = {}
            local n_a, say_a = bump(t1, "a")
            local n_b, say_b = bump(t1, "b")
            if not (n_a == 1 and say_a and n_b == 1 and say_b) then
                bad("  SAI  bump: lan dau cua moi loai phai in va dem rieng\n" ..
                    "       (a=%s/%s b=%s/%s) => counter dung chung\n",
                    tostring(n_a), tostring(say_a),
                    tostring(n_b), tostring(say_b))
            else pass = pass + 1 end

            -- HAI LOAI XEN KE DEU DAN. Voi counter chung, "b" roi vao cac lan
            -- chan nen `% 200 == 1` KHONG BAO GIO dung => b im lang vinh vien.
            local t2, said_a, said_b = {}, 0, 0
            for _ = 1, 400 do
                local _, sa = bump(t2, "a"); if sa then said_a = said_a + 1 end
                local _, sb = bump(t2, "b"); if sb then said_b = said_b + 1 end
            end
            if said_a ~= 2 or said_b ~= 2 then
                bad("  SAI  bump: 400 loi xen ke moi loai -> a in %d lan, " ..
                    "b in %d lan (phai 2/2).\n" ..
                    "       Mot loai bi loai kia che = dung chung counter.\n",
                    said_a, said_b)
            else pass = pass + 1 end

            -- Va van phai CO TRAN: 400 loi cung loai chi duoc 2 dong.
            local t3, said = {}, 0
            for _ = 1, 400 do
                local _, s = bump(t3, "a"); if s then said = said + 1 end
            end
            if said ~= 2 then
                bad("  SAI  bump: 400 loi cung loai in %d dong (phai 2)\n", said)
            else pass = pass + 1 end

            -- Dem in ra phai la cua CHINH loai do, khong phai tong worker.
            local t4 = {}
            for _ = 1, 50 do bump(t4, "on_ao") end
            local n_hiem = bump(t4, "hiem")
            if n_hiem ~= 1 then
                bad("  SAI  bump: loai hiem dem ra %d, phai 1 " ..
                    "(dang dem tong cua worker)\n", n_hiem)
            else pass = pass + 1 end
        end

        -- NGUON: moi nhanh "doc hong" phai di qua bo lay mau, khong con
        -- `ngx.log(ngx.ERR` tran trui. `cipher_invalid` la nhanh bi bo sot o
        -- ban truoc: no ghi ERR o CA hai nac probe VA on.
        for _, nm in ipairs({ "supported_groups", "point_formats",
                              "supported_versions" }) do
            if not src:find('log_api_err%("' .. nm) then
                bad("  SAI  nhanh %s khong di qua log_api_err (ERR khong tran)\n",
                    nm)
            else pass = pass + 1 end
        end
        -- `ext_present_hash` va `ext_present_unavail` la THUOC TINH PHIEN BAN
        -- thu vien, khong phai su co: tren lua-resty-core cu chung ghi mot
        -- dong MOI BAT TAY ma khong can loi gi ca. Chung phai co tran.
        for _, nm in ipairs({ "cipher_invalid", "ext_not_ok", "cipher_too_few",
                              "sv_parse", "ext_present_type",
                              "ext_present_hash", "ext_present_throw",
                              "ext_present_unavail",
                              "sg_truncated", "pf_truncated" }) do
            if not src:find('log_sampled%("' .. nm) then
                bad("  SAI  nhanh %s ghi ERR khong qua log_sampled:\n" ..
                    "       mot API hong he thong = mot dong moi bat tay TLS.\n",
                    nm)
            else pass = pass + 1 end
        end
        -- Token ma `do_sang.sh` dang dem phai con nguyen.
        if not src:find('"cipher_invalid shape="') then
            bad("  SAI  mat token `cipher_invalid shape=` => do_sang.sh mu\n")
        else pass = pass + 1 end
    end
end

-- ── hanh vi: is_browser_pattern (chay that) ──────────────────────────
--
-- NAP TU NGUON, KHONG `require`. `ua_check.lua` mo dau bang
-- `require "antibot.core.redis_pool"` va `ngx.shared.antibot_ua_cache`, ma
-- `run.sh` goi `resty` KHONG kem lua_package_path lan shdict do — `loadfile`
-- ca module se hong VINH VIEN, tuc mot test do mai mai ma khong ai doc nua.
-- Ham nay THUAN (chi doc tham so `ua`, khong upvalue) nen trich than ham ra
-- `load()` la chay that duoc. Ai them upvalue vao no thi goi se no => bao do,
-- dung y.
io.write("\nhanh vi: is_browser_pattern (chay that)\n")
local uc_src = slurp(SRC .. "detection/bot/ua_check.lua")
local fn_src = uc_src and uc_src:match("(local function is_browser_pattern.-\nend)")
if not fn_src then
    bad("  SAI  khong trich duoc `is_browser_pattern` tu ua_check.lua\n")
else
    local chunk, lerr = load(fn_src .. "\nreturn is_browser_pattern")
    local ok_c, f = false, nil
    if chunk then ok_c, f = pcall(chunk) end
    if not ok_c or type(f) ~= "function" then
        bad("  SAI  khong nap duoc `is_browser_pattern`: %s\n", tostring(lerr))
    else
        -- {nhan, UA, ket qua mong doi}
        local ua_cases = {
            { "Chrome desktop",
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
              "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36", true },
            -- DAY la nhanh CHET cua ban cu: UA Firefox khong he co
            -- `AppleWebKit/`, nen `AppleWebKit AND (… or Firefox)` luon sai.
            { "Firefox desktop",
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) " ..
              "Gecko/20100101 Firefox/119.0", true },
            -- Ba ca duoi day bi ban cu loai OAN: co AppleWebKit nhung khong
            -- co token `Chrome/`.
            { "Safari macOS",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " ..
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 " ..
              "Safari/605.1.15", true },
            { "Chrome tren iOS (CriOS)",
              "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) " ..
              "AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.0.0 " ..
              "Mobile/15E148 Safari/604.1", true },
            { "Firefox tren iOS (FxiOS)",
              "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) " ..
              "AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/119.0 " ..
              "Mobile/15E148 Safari/605.1.15", true },
            { "Edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " ..
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 " ..
              "Safari/537.36 Edg/139.0.0.0", true },
            { "curl",            "curl/8.4.0",            false },
            { "Go client",       "Go-http-client/2.0",    false },
            { "python requests", "python-requests/2.31.0", false },
            { "chuoi rong",      "",                      false },
        }
        for _, c in ipairs(ua_cases) do
            local got = f(c[2]) and true or false
            if got ~= c[3] then
                bad("  SAI  is_browser_pattern(%s) = %s, phai %s\n",
                    c[1], tostring(got), tostring(c[3]))
            else pass = pass + 1 end
        end
        -- TEN THUONG HIEU khong duoc quay lai. Ban cu hardcode `Chrome/` va
        -- `Firefox/` — vi pham chinh nguyen tac ghi o dau `ua_check.lua`
        -- ("No specific bot names, company names, or tool names are
        -- hardcoded") va do la goc cua nhanh chet.
        if fn_src:find("Firefox/", 1, true) or fn_src:find("Chrome/", 1, true) then
            bad("  SAI  is_browser_pattern lai hardcode TEN TRINH DUYET.\n" ..
                "       Khoa vao token dong co (AppleWebKit/ , Gecko/) thay vi ten.\n")
        else pass = pass + 1 end
    end
end

-- ── moi tin hieu waf_* co trong so PHAI co noi GAN no ────────────────
--
-- Phep kiem hai chieu o muc 1 doi chieu `compute.lua` voi `init.lua`. No KHONG
-- nhin thay truong hop te nhat: ten co trong DEFAULT_WEIGHTS, co trong
-- `waf_signal`, hop dong bao XANH — nhung khong mot dong ma nao GAN
-- `ctx.<ten>`, nen tin hieu vinh vien bang 0. Do dung la cach `wp_paths.mark()`
-- chet trong im lang bon thang.
--
-- Tim phep GAN (`ctx.<ten> =`), khong phai phep DOC. `waf_signal` va
-- `get_signal` chi doc, nen chung khong duoc tinh — vi vay chi quet trong
-- `waf/`, noi duy nhat co quyen dat co nay.
io.write("\nhop dong: tin hieu co trong so phai co noi GAN\n")
do
    local waf_init = slurp(SRC .. "waf/init.lua") or ""
    local waf_body = slurp(SRC .. "waf/body.lua") or ""
    local setters  = waf_init .. "\n" .. waf_body
    local n_checked = 0
    for name, w in compute:gmatch("\n%s*(waf_[%w_]+)%s*=%s*([%d%.]+)") do
        if tonumber(w) > 0 then
            n_checked = n_checked + 1
            -- `%f[%W]` neo bien tu: khong co no thi `ctx.waf_arg =` khop nham
            -- vao `ctx.waf_arg_x =`, tuc mot lan BAO XANH SAI.
            if not setters:find("ctx%." .. name .. "%f[%W]%s*=") then
                bad("  SAI  `%s` co trong so %s nhung KHONG CHO NAO gan\n" ..
                    "       `ctx.%s = ...` trong waf/. Tin hieu se vinh vien\n" ..
                    "       bang 0 va hop dong hai chieu van bao xanh.\n",
                    name, w, name)
            else pass = pass + 1 end
        end
    end
    if n_checked == 0 then
        bad("  SAI  khong tin hieu waf_* nao co trong so > 0 — muc nay khong kiem gi\n")
    else
        io.write(string.format("  %d tin hieu co trong so, deu co noi gan\n", n_checked))
    end
end

io.write(string.format("\n%d qua, %d hong\n", pass, fail))
os.exit(fail == 0 and 0 or 1)
