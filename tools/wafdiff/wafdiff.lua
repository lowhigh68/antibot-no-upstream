-- wafdiff — fuzz VI SAI giua `waf/body_core.lua` va parser multipart THAT cua
-- PHP (`php-cgi` + `dump.php`). Roadmap WAF muc 3 (review 26-09 lan 2): "neu WAF
-- tra proof=ok, moi byte `projection()` bo di phai thuc su la noi dung `$_FILES`
-- theo PHP; khong byte nao PHP dua vao `$_POST` duoc phep bi bo."
--
-- Thuoc tinh kiem tren MOI ca:
--   P1  NGUY HIEM  `pf=ok` -> moi gia tri `$_POST` con NGUYEN trong ban chieu.
--   P6  NGUY HIEM  luat tham so trong mot gia tri `$_POST` phai co o `nonfile`.
--   P7  NGUY HIEM  luat trong BAT KY byte PHP thay (noi dung tep, ten tep) phai co
--                  o IT NHAT mot vung — khong vung mu.
--   P8  NGUY HIEM  luat trong ten tep PHP doc ra (`full_path`, TRUOC basename) phai
--                  o vung `filename`; va khi `pf=ok` ca o `nonfile` — header khong
--                  bao gio la noi dung tep. P7 chi hoi HOP cac vung nen khong thay
--                  "dung luat, sai vung".
--   P5  NGUY HIEM  ten tep PHP thay (sau basename) ma `upload.check_filename` bat
--                  thi `up_rule` cua WAF phai nghiem trong it nhat bang.
--   P9  LOI        luat trong noi dung tep PHP: `pf=ok` -> o vung `file`; khong ->
--                  o `nonfile` (quet phang).
--   P3  LOI        spill (worker, qua pack/unpack) = memory (`core.scan`).
--   P2  THONG TIN  khoang tep cua WAF vs noi dung `$_FILES`, tach theo ly do:
--                  `filename=""`, trung ten, con lai (giu ca de xem tay).
-- P5/P8 bo sot khi kenh ten tep DA KHAI BAO dung giua chung (`FN_INCOMPLETE`, B1)
-- chi dem la thong tin; bo sot khong khai bao moi la vi pham.
-- Oracle phai qua mot than biet truoc ket qua truoc vong lap, va MOI ca phai doc
-- duoc — mot ca PHP khong doc duoc la ma 2, khong phai "0 vi pham".
-- Chay qua `run.sh`. Ma thoat: 0 sach, 1 co vi pham NGUY HIEM/LOI, 2 khong chay
-- duoc / khong bao dam duoc ket qua.
local SRC    = os.getenv("ANTIBOT_SRC")
local DUMP   = os.getenv("WAFDIFF_DUMP")
local PHPCGI = os.getenv("PHPCGI") or "php-cgi"
local N      = tonumber(os.getenv("N") or "") or 1500
local SEED   = tonumber(os.getenv("SEED") or "") or os.time()
local OUT    = os.getenv("OUT")   -- run.sh dat: thu muc tam RIENG cua lan chay
if not SRC or not DUMP or not OUT then
    io.write("wafdiff: thieu ANTIBOT_SRC/WAFDIFF_DUMP/OUT — chay qua run.sh\n"); os.exit(2)
end
for _, m in ipairs({ "upload", "body_core", "body_worker" }) do
    package.preload["antibot.waf." .. m] = function()
        return dofile(SRC .. "waf/" .. m .. ".lua")
    end
end
local core   = require "antibot.waf.body_core"
local worker = require "antibot.waf.body_worker"
local upload = require "antibot.waf.upload"
local cjson  = require "cjson.safe"
-- Khong ghi duoc OUT thi moi lan goi PHP ben duoi hong — dung o day voi ma 2,
-- khong de no thanh loi Lua (ma 1, trung ma "co vi pham").
local st = os.execute("rm -rf '" .. OUT .. "' && mkdir -p '" .. OUT .. "'")
local probe_fh = (st == 0 or st == true) and io.open(OUT .. "/.ghi-thu", "wb")
if not probe_fh then io.write("wafdiff: khong ghi duoc vao " .. OUT .. "\n"); os.exit(2) end
probe_fh:close()
math.randomseed(SEED)

local function rint(a, b) return math.random(a, b) end
local function pick(t) return t[math.random(1, #t)] end
local function chance(p) return math.random() < p end
local seq = 0
local function token() seq = seq + 1; return string.format("Q%07dZ", seq) end

local BS = string.char(92)
local CRLF = "\r\n"
local PAY = { "../../etc/passwd", ".." .. BS .. "win", "php://input", "phar://x",
              "%00", "x%2e%2e%2fy", "<?php echo 1; ?>", "data://text", "1..5", "chu" }
local NAMES  = { "a", "path", "file", "x", "upload", "data" }
local FNAMES = { "a.jpg", "shell.php", "x.php.jpg", ".htaccess", "../../s.php",
                 "doc.pdf", "q.phar", "a b.png", "", ".user.ini", "s.PHP" }
local BOUNDS = { "----WebKitFormBoundaryAbC123", "B", "x-y_z", "q'()+_./:=?-9", "AaB03x" }

-- Noi dung mot part: moc duy nhat + manh gay nhieu cau truc (LF tran truoc
-- `--B`, tien to boundary, NUL, CR/LF le) + tai trong luat tham so. `clean`:
-- chi tai trong va NUL — than giu DANG CHUAN TAC de phu cac thuoc tinh `pf=ok`.
local function content(B, clean)
    local out = { token() }
    for _ = 1, rint(0, 3) do
        local k = clean and pick({ 4, 8, 9, 10, 11, 12 }) or rint(1, 12)
        if     k == 1 then out[#out + 1] = "\n--" .. B
        elseif k == 2 then out[#out + 1] = "\r\n--" .. B .. "zz"
        elseif k == 3 then out[#out + 1] = "--" .. B .. "--"
        elseif k == 4 then out[#out + 1] = "\0"
        elseif k == 5 then out[#out + 1] = "\r"
        elseif k == 6 then out[#out + 1] = "\n"
        elseif k == 7 then out[#out + 1] = "\r\n"
        else out[#out + 1] = pick(PAY) end
        out[#out + 1] = token()
    end
    return table.concat(out)
end

local function head_lines(p)
    local nm, fn = p.name, p.filename
    local function q(v) return '"' .. v .. '"' end
    local cd
    if p.variant == "single" then
        cd = "form-data; name='" .. nm .. "'" .. (fn and ("; filename='" .. fn .. "'") or "")
    elseif p.variant == "star" and fn then
        cd = "form-data; name=" .. q(nm) .. "; filename*=UTF-8''" .. fn
    elseif p.variant == "space" and fn then
        cd = "form-data; name=" .. q(nm) .. "; filename =" .. q(fn)
    elseif p.variant == "order" and fn then
        cd = "form-data; filename=" .. q(fn) .. "; name=" .. q(nm)
    elseif p.variant == "noquote" then
        cd = "form-data; name=" .. nm .. (fn and ("; filename=" .. fn) or "")
    else
        cd = "form-data; name=" .. q(nm) .. (fn and ("; filename=" .. q(fn)) or "")
    end
    local lines = { (p.hcase or "Content-Disposition") .. ": " .. cd }
    if p.dup then
        lines[#lines + 1] = "Content-Disposition: form-data; name=" .. q(p.dup) ..
                            (p.dupfn and ("; filename=" .. q(p.dupfn)) or "")
        if p.dupfirst then lines[1], lines[2] = lines[2], lines[1] end
    end
    if p.ctype then lines[#lines + 1] = "Content-Type: " .. p.ctype end
    if p.extra then lines[#lines + 1] = p.extra end
    if p.nulh then lines[1] = lines[1]:gsub('name="', 'name="' .. "\0", 1) end
    if p.fold then lines[1] = lines[1]:gsub("; name", ";\r\n name", 1) end
    return lines
end

local function gen_part(B, clean)
    local p = { name = pick(NAMES) .. rint(1, 99) }
    if chance(0.5) then
        p.filename = pick(FNAMES)
        if chance(0.4) then p.ctype = pick({ "image/jpeg", "application/octet-stream", "text/plain" }) end
    end
    if clean then
        p.content, p.dnl, p.hnl, p.cnl = content(B, true), CRLF, CRLF, CRLF
        return p
    end
    if chance(0.25) then p.variant = pick({ "single", "star", "space", "order", "noquote" }) end
    if chance(0.08) then
        p.dup = pick(NAMES) .. rint(100, 199)
        if chance(0.5) then p.dupfn = pick(FNAMES) end
        p.dupfirst = chance(0.5)
    end
    if chance(0.08) then p.hcase = pick({ "content-disposition", "CONTENT-DISPOSITION" }) end
    if chance(0.06) then
        p.extra = pick({ "X-A: b", "Content-Transfer-Encoding: binary", "content-type: text/html" })
    end
    if chance(0.04) then p.nulh = true end
    if chance(0.05) then p.fold = true end
    p.content = content(B)
    p.dnl = chance(0.05) and "\n" or "\r\n"   -- sau dau phan cach
    p.hnl = chance(0.06) and "\n" or "\r\n"   -- cuoi moi dong header
    p.cnl = chance(0.05) and "\n" or "\r\n"   -- truoc dau phan cach ke tiep
    return p
end

local function build(B, parts, opt)
    local out = {}
    if opt.pre then out[#out + 1] = opt.pre end
    for _, p in ipairs(parts) do
        out[#out + 1] = "--" .. B .. p.dnl .. table.concat(head_lines(p), p.hnl) ..
                        p.hnl .. p.hnl .. p.content .. p.cnl
    end
    out[#out + 1] = "--" .. B .. "--" .. (opt.closenl or "\r\n")
    if opt.epi then out[#out + 1] = opt.epi end
    return table.concat(out)
end

local function gen_ct(B)
    local k = rint(1, 10)
    if k <= 6 then return "multipart/form-data; boundary=" .. B end
    if k == 7 then return 'multipart/form-data; boundary="' .. B .. '"' end
    if k == 8 then return "multipart/form-data;boundary=" .. B end
    if k == 9 then return "multipart/form-data; xboundary=zz; boundary=" .. B end
    return "multipart/form-data; charset=utf-8; boundary=" .. B
end

local function gen_case()
    local B = pick(BOUNDS)
    local clean = chance(0.4)   -- dang chuan tac: phu cac thuoc tinh `pf=ok`
    local parts = {}
    for i = 1, (chance(0.03) and pick({ 63, 64, 65 }) or rint(1, 4)) do
        parts[i] = gen_part(B, clean)
    end
    if clean then
        return build(B, parts, {}), "multipart/form-data; boundary=" .. B
    end
    local opt = {}
    if chance(0.05) then opt.pre = pick({ "rac\r\n", "\r\n", "preamble\r\n" }) end
    if chance(0.05) then
        opt.epi = pick({ "epi", "\r\n", "--" .. B .. "\r\n" ..
                         'Content-Disposition: form-data; name="late"' .. "\r\n\r\n" ..
                         token() .. "../../late\r\n--" .. B .. "--\r\n" })
    end
    if chance(0.03) then opt.closenl = "" end
    local body = build(B, parts, opt)
    if chance(0.05) then body = body:sub(1, rint(0, #body)) end
    return body, gen_ct(B)
end

-- PHP THAT. Content-Type qua file de khong phai quote no trong lenh shell.
local function php_parse(body, ct)
    local bf, cf = OUT .. "/cur.body", OUT .. "/cur.ct"
    local fh = io.open(bf, "wb"); fh:write(body); fh:close()
    fh = io.open(cf, "wb"); fh:write(ct); fh:close()
    local cmd = "REQUEST_METHOD=POST CONTENT_TYPE=\"$(cat '" .. cf .. "')\"" ..
                " CONTENT_LENGTH=" .. #body .. " SCRIPT_FILENAME='" .. DUMP .. "'" ..
                " REDIRECT_STATUS=1 " .. PHPCGI ..
                " -d file_uploads=1 -d enable_post_data_reading=1" ..
                " -d max_file_uploads=1000 -d upload_max_filesize=64M" ..
                " -d post_max_size=64M -d max_input_vars=100000" ..
                " -d display_errors=0 -d error_reporting=0 < '" .. bf .. "' 2>/dev/null"
    local p = io.popen(cmd)
    local out = p:read("*a"); p:close()
    return cjson.decode(out:match("\r?\n\r?\n(.*)$") or out)
end

local function list(t) return t and table.concat(t, ",") or "-" end
local function set(t) local s = {}; for _, v in ipairs(t or {}) do s[v] = true end; return s end
local function rules(s, binary) return core.rules_in_lower(s:lower(), false, binary, {}) end
-- `cjson.null` (tep loi upload) la userdata TRUTHY — chi giai ma khi la chuoi.
local function s64(v) return type(v) == "string" and ngx.decode_base64(v) or nil end

local viol, info, n_cases, n_proof, oracle_fail = {}, {}, 0, 0, 0
local KEEP = tonumber(os.getenv("KEEP") or "") or 5
local function save(kind, k, body, ct)
    local base = string.format("%s/%s-%d", OUT, kind, k)
    local f = assert(io.open(base .. ".body", "wb")); f:write(body); f:close()
    f = assert(io.open(base .. ".ct", "wb")); f:write(ct); f:close()
    return base
end
local function flag(kind, msg, body, ct)
    viol[kind] = (viol[kind] or 0) + 1
    if viol[kind] > KEEP then return end
    io.write(string.format("  %s #%d: %s  [%s.body]\n", kind, viol[kind], msg,
                           save(kind, viol[kind], body, ct)))
end
-- Nhu `flag` nhung KHONG phai vi pham: dem vao `info` va giu ca de xem tay.
local function note(kind, body, ct)
    info[kind] = (info[kind] or 0) + 1
    if info[kind] <= KEEP then save(kind, info[kind], body, ct) end
end
local function bump(kind) info[kind] = (info[kind] or 0) + 1 end

-- P2: vi sao mot khoang tep CUA WAF khong khop noi dung tep nao PHP giu lai. Chi
-- than `pf=ok` (dang chuan tac) toi day, nen dong Content-Disposition cua part la
-- `form-data; name="X"; filename="Y"` roi CRLF — doc duoc bang mot mau co dinh.
local CD_FILE = '; name="([^"]*)"; filename="([^"]*)"\r\n'
local function part_of(body, at)
    local nm, fn, pos = nil, nil, 1
    while true do
        local a, b, n, f = body:find(CD_FILE, pos)
        if not a or a >= at then return nm, fn end
        nm, fn, pos = n, f, b + 1
    end
end

local spill_tmp = OUT .. "/spill.body"
local function check(body, ct)
    n_cases = n_cases + 1
    local r = core.scan(body, ct)

    local fh = assert(io.open(spill_tmp, "wb")); fh:write(body); fh:close()
    local sp = core.unpack(worker.scan_file(spill_tmp, ct))
    if not sp or list(sp.nonfile_rules) ~= list(r.nonfile_rules)
       or list(sp.file_rules) ~= list(r.file_rules)
       or list(sp.filename_rules) ~= list(r.filename_rules)
       or sp.proof ~= r.proof or sp.up_rule ~= r.up_rule then
        flag("P3", "spill khac memory", body, ct)
    end

    -- Oracle hong KHONG phai thong tin: ca do khong duoc kiem gi. Dem, va mot lan
    -- chay co ca hong thi thoat 2 — "0 vi pham" chi co nghia khi PHP doc MOI ca.
    local php = php_parse(body, ct)
    if type(php) ~= "table" or type(php.post) ~= "table" or type(php.files) ~= "table" then
        oracle_fail = oracle_fail + 1
        note("ORACLE_hong", body, ct)
        return
    end

    local ranges = core.file_ranges(body, ct)
    local proof = ranges ~= nil
    if proof then n_proof = n_proof + 1 end
    local proj = proof and core.projection(body, ranges) or body
    local nonfile, file, fname = set(r.nonfile_rules), set(r.file_rules), set(r.filename_rules)
    local all = {}
    for _, s in ipairs({ nonfile, file, fname }) do for k in pairs(s) do all[k] = true end end
    -- B1: kenh ten tep DA KHAI BAO dung giua chung (`FN_INCOMPLETE`) — bo sot ten
    -- tep khi do la dieu da biet, da phat `body_multipart_incomplete`: dem rieng.
    -- Bo sot KHONG khai bao moi la vi pham.
    local declared = core.FN_INCOMPLETE[r.fn_trunc]

    for _, pv in ipairs(php.post) do
        local v = s64(pv.value) or ""
        if v ~= "" then
            if proof and not proj:find(v, 1, true) then
                flag("P1", "gia tri $_POST bi coi la noi dung tep", body, ct)
            end
            -- `pf=ok`: ban chieu quet `binary=false`; khong: quet phang multipart
            -- `binary=true` (gioi han da biet: NUL tho khong tach duoc khoi tep).
            for id in pairs(rules(v, not proof)) do
                if not nonfile[id] then
                    flag("P6", "luat " .. id .. " trong $_POST khong o nonfile", body, ct)
                end
            end
        end
    end

    -- P7 hoi "co vung nao bao khong" (HOP cac vung). P8/P9 hoi "co DUNG vung
    -- khong": mot luat dung ma sai vung la mot duong ha diem (`registry.region_rule`
    -- doi luat theo vung) hoac mot FP, va P7 khong thay duoc.
    local php_c = {}
    for _, pf in ipairs(php.files) do
        local c = s64(pf.content)
        if c and c ~= "" then
            php_c[c] = (php_c[c] or 0) + 1
            for id in pairs(rules(c, true)) do
                if not all[id] then
                    flag("P7", "luat " .. id .. " trong noi dung tep khong o vung nao", body, ct)
                elseif proof and not file[id] then
                    flag("P9", "luat " .. id .. " trong noi dung tep PHP khong o vung file (pf=ok)", body, ct)
                elseif not proof and not nonfile[id] then
                    flag("P9", "luat " .. id .. " trong noi dung tep khong o nonfile (pf khac ok)", body, ct)
                end
            end
        end
        local nm = s64(pf.name) or ""
        if nm ~= "" then
            local want = upload.check_filename(nm)
            if want and upload.worse_up(r.up_rule, want) ~= r.up_rule then
                if declared then bump("P5_da_khai_bao_B1")
                else
                    flag("P5", string.format("PHP thay ten %q -> %s, up_rule=%s",
                                             nm, want, tostring(r.up_rule)), body, ct)
                end
            end
        end
        -- Luat trong ten tep kiem tren ten PHP doc ra TRUOC basename (`full_path`):
        -- ten sau basename da mat `../`, nen kiem tren no la kiem rong.
        local full = s64(pf.full_path) or nm
        if full ~= "" then
            for id in pairs(rules(full, false)) do
                if not all[id] then
                    flag("P7", "luat " .. id .. " trong ten tep khong o vung nao", body, ct)
                else
                    if not fname[id] then
                        if declared then bump("P8_da_khai_bao_B1")
                        else flag("P8", "luat " .. id .. " trong ten tep PHP doc khong o vung filename", body, ct) end
                    end
                    -- Header KHONG BAO GIO la noi dung tep: voi `pf=ok` ten tep phai nam
                    -- trong ban chieu. Thieu o day = `file_ranges` nuot header, tuc luat
                    -- cua ten tep bi doi thanh luat noi dung tep.
                    if proof and not nonfile[id] then
                        flag("P8", "luat " .. id .. " trong ten tep khong o nonfile du pf=ok", body, ct)
                    end
                end
            end
        end
    end

    if proof then
        local cnt = {}
        for n in body:gmatch(CD_FILE) do cnt[n] = (cnt[n] or 0) + 1 end
        for _, rg in ipairs(ranges) do
            local c = body:sub(rg[1], rg[2])
            if (php_c[c] or 0) > 0 then
                php_c[c] = php_c[c] - 1
            else
                -- Hai ly do PHP bo noi dung ma WAF van coi la tep: `filename=""` (PHP bao
                -- UPLOAD_ERR_NO_FILE) va hai part tep TRUNG TEN (PHP ghi de). Ngoai hai
                -- ly do do thi giu ca de xem tay.
                local nm, fn = part_of(body, rg[1])
                if fn == "" then bump("P2_chi_WAF_filename_rong")
                elseif nm and (cnt[nm] or 0) > 1 then bump("P2_chi_WAF_trung_ten")
                else note("P2_chi_WAF_chua_giai_thich", body, ct) end
            end
        end
        for _, k in pairs(php_c) do
            if k > 0 then info.P2_chi_PHP_coi_la_tep = (info.P2_chi_PHP_coi_la_tep or 0) + k end
        end
    end
end

-- ── ORACLE phai DUNG truoc khi tin no ────────────────────────────────────────
--
-- Mot dump.php sai, hoac PHP khong doc than multipart, thi moi phep kiem ben duoi
-- RONG — va rong thi ra "0 vi pham". Nen truoc vong lap: mot than chuan tac biet
-- truoc ket qua; lech la thoat 2.
do
    local B = "AaB03x"
    local body = "--" .. B .. CRLF .. 'Content-Disposition: form-data; name="p"' .. CRLF .. CRLF ..
                 "gia-tri-p" .. CRLF .. "--" .. B .. CRLF ..
                 'Content-Disposition: form-data; name="f"; filename="d/a.jpg"' .. CRLF .. CRLF ..
                 "noi-dung-f" .. CRLF .. "--" .. B .. "--" .. CRLF
    local php = php_parse(body, "multipart/form-data; boundary=" .. B)
    local p = type(php) == "table" and type(php.post) == "table" and php.post[1]
    local f = type(php) == "table" and type(php.files) == "table" and php.files[1]
    if not (p and f and s64(p.value) == "gia-tri-p" and s64(f.name) == "a.jpg"
            and s64(f.content) == "noi-dung-f") then
        io.write("wafdiff: ORACLE SAI — PHP khong doc dung mot than chuan tac biet truoc ket qua\n")
        os.exit(2)
    end
    if s64(f.full_path) ~= "d/a.jpg" then
        io.write("wafdiff: PHP khong co `full_path` (can >= 8.1) — luat trong ten tep chi\n" ..
                 "         kiem duoc tren ten SAU basename\n")
    end
end

io.write(string.format("wafdiff: seed %d, %d ca ngau nhien, ket qua loi o %s\n", SEED, N, OUT))
-- Loi CUA CHINH bo kiem phai ra ma 2: `resty` tra 1 cho loi Lua khong bat, trung
-- voi ma "co vi pham".
local ran, err = pcall(function()
    for _ = 1, N do check(gen_case()) end

    -- "Than cat tai MOI vi tri byte" (review): ba than chuan tac co tep va field.
    for _, B in ipairs({ "----WebKitFormBoundaryAbC123", "q'()+_./:=?-9", "B" }) do
        local body = build(B, {
            { name = "path", content = token() .. "../../x" .. token(), dnl = "\r\n", hnl = "\r\n", cnl = "\r\n" },
            { name = "f", filename = "a.jpg", ctype = "image/jpeg",
              content = token() .. "php://input" .. token(), dnl = "\r\n", hnl = "\r\n", cnl = "\r\n" },
        }, {})
        local ct = "multipart/form-data; boundary=" .. B
        for cut = 0, #body do check(body:sub(1, cut), ct) end
    end
end)
if not ran then io.write("wafdiff: bo kiem hong: " .. tostring(err) .. "\n"); os.exit(2) end

local DESC = {
    P1 = "NGUY HIEM  gia tri $_POST bi WAF coi la noi dung tep",
    P6 = "NGUY HIEM  luat trong $_POST khong o vung nonfile",
    P7 = "NGUY HIEM  luat PHP thay nhung khong vung nao bao",
    P8 = "NGUY HIEM  luat trong ten tep sai vung (khong o filename; hoac khong o nonfile khi pf=ok)",
    P5 = "NGUY HIEM  ten tep nguy hiem PHP thay ma up_rule nhe hon",
    P9 = "LOI        luat trong noi dung tep sai vung",
    P3 = "LOI        spill khac memory",
}
io.write(string.format("\nwafdiff: %d ca, %d ca pf=ok (seed %d)\n", n_cases, n_proof, SEED))
local bad = 0
for _, k in ipairs({ "P1", "P6", "P7", "P8", "P5", "P9", "P3" }) do
    bad = bad + (viol[k] or 0)
    io.write(string.format("  %-3s %6d  %s\n", k, viol[k] or 0, DESC[k]))
end
local keys = {}
for k in pairs(info) do keys[#keys + 1] = k end
table.sort(keys)
for _, k in ipairs(keys) do io.write(string.format("  (thong tin) %s: %d\n", k, info[k])) end
if bad > 0 then os.exit(1) end
if oracle_fail > 0 then
    io.write(string.format("wafdiff: %d ca PHP KHONG doc duoc — ket qua KHONG bao dam\n", oracle_fail))
    os.exit(2)
end
os.exit(0)
