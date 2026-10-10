-- admin_fim_test.lua — kiem endpoint `/antibot-admin/fim`, cot `sections`.
--
-- VI SAO CAN. Endpoint nay la DUONG RA cua `fim.sh` toi mat nguoi (the dashboard
-- "File la co the chay duoc"). Do tu code 10-10: `fim.sh` ghi `$CRITLOG` bang BA
-- khoi dang `=== ... ===` + dong chi tiet thut le (SHADOW handler-strip — chinh
-- chu ky thegioibds, ton dong mu-plugins, khuon md5x3). Khong khoi nao mang tien
-- to `MUPLUG `/`CRITICAL `. Truoc ban nay the chi dem hai tien to do, nen mot
-- phat hien CHI co khoi `===` cho dem = 0 va JS an ca the — phat hien nam trong
-- log nhung VO HINH tren dashboard, dung ho `feedback_alert_reaches_nobody`.
--
-- Bo nay TRICH ham `render_fim` roi chay THAT, gia `io.open` tro vao mot chuoi
-- log dung trong bo nho. Giong `admin_l7_test`: doi TEN ham thi phep trich thay
-- bai ngay chu khong im lang.
--
-- CHAY:  resty antibot-core/admin/tests/admin_fim_test.lua
-- Ma thoat: 0 = moi con so khop, 1 = co lech.
local cjson = require "cjson"
local out = {}
local fake = {
    header = {}, say = function(s) out[#out+1] = s end,
    shared = {}, var = {}, status = 200,
    exit = function() end, log = function() end, ERR = 4,
}
local SRC = (os.getenv("ANTIBOT_SRC") or "./antibot-core/")
local src = io.open(SRC .. "admin/init.lua"):read("a")
-- Trich DUNG ham render_fim. No co the chua cac ham long nhau, nen bat toi dong
-- `^end` o cot 0 dau tien sau khi vao ham — khuon giong `render_l7`.
local body = src:match("(local function render_fim%(%).-\nend\n)")
assert(body, "khong trich duoc render_fim")

-- Noi dung `$CRITLOG` gia cho moi lan chay. render_fim goi io.open; ta thay no
-- bang mot io gia doc tu chuoi `logtext`.
local logtext, log_missing, log_errno = "", false, nil
local function fake_lines(s)
    local pos = 1
    return function()
        if pos > #s then return nil end
        local nl = s:find("\n", pos, true)
        local line
        if nl then line = s:sub(pos, nl - 1); pos = nl + 1
        else line = s:sub(pos); pos = #s + 1 end
        return line
    end
end
-- `io.open` tra BA gia tri khi that bai: nil, thong bao, errno. Do duoc bang
-- `resty` 10-10: ENOENT -> 2, EACCES -> 13. Gia dung ba gia tri do, vi
-- `render_fim` phan biet nguyen nhan bang chinh errno.
local fake_io = {
    open = function(_, _)
        if log_missing then
            local en = log_errno or 2
            local msg = (en == 13) and "Permission denied"
                                    or "No such file or directory"
            return nil, "/x: " .. msg, en
        end
        return {
            lines = function() return fake_lines(logtext) end,
            close = function() end,
        }
    end,
}

local function run(text, missing, errno)
    out = {}
    logtext = text or ""
    log_missing = missing or false
    log_errno = errno
    -- FIM_CRITLOG / FIM_MAX_LINES la upvalue cap module trong init.lua, ngoai
    -- than ham trich ra. Cap lai trong env de ham chay doc lap. Gia tri CRITLOG
    -- khong dung (io gia bo qua ten); MAX_LINES giu dung 200 nhu ban that.
    local env = { ngx = fake, cjson = cjson, io = fake_io,
                  FIM_CRITLOG = "/x", FIM_MAX_LINES = 200,
                  tonumber = tonumber, tostring = tostring,
                  ipairs = ipairs, pairs = pairs, type = type,
                  setmetatable = setmetatable }
    local chunk = assert(loadstring(body .. "\nreturn render_fim"))
    setfenv(chunk, env)
    chunk()()
    return cjson.decode(out[1])
end

local p, f = 0, 0
local function eq(got, want, msg)
    if got == want then p = p + 1
    else f = f + 1; print(("HONG %s: got=%s want=%s"):format(msg, tostring(got), tostring(want))) end
end

-- 1. file THIEU -> exists=false, KHAC HAN "sach". Phan biet nay la ca ly do route
--    ton tai; gop hai cai lai la loi da giet wp_paths.mark() 4 thang.
local r = run(nil, true, 2)
eq(r.exists, false, "file thieu -> exists=false")
eq(type(r.reason), "string", "file thieu co reason")

-- 1b. ENOENT -> `never_run`, KHONG phai "sach" va KHONG phai "mat quyen".
--     `fim.sh` tao file RONG o moi lan chay (dong 243-245), nen khong co file
--     la bang chung chac chan rang chua lan chay nao hoan tat -> buoc 1 chua song.
eq(r.cause, "never_run", "errno 2 -> cause=never_run")
eq(r.errno, 2, "errno 2 duoc tra nguyen")

-- 1c. EACCES -> `no_permission`. HANH DONG KHAC HAN 1b: can `chgrp nginx`,
--     khong phai `fim.sh baseline`. Gop hai cai mot cau la de nguoi van hanh doan.
r = run(nil, true, 13)
eq(r.exists, false, "khong doc duoc -> exists=false")
eq(r.cause, "no_permission", "errno 13 -> cause=no_permission")
eq(r.errno, 13, "errno 13 duoc tra nguyen")

-- 2. file RONG -> exists=true nhung moi con dem = 0 (the se tu an)
--    DAY LA PHAN BIET QUAN TRONG NHAT: rong = "da chay, SACH THAT", khac han
--    khong-co-file = "chua chay". Ca hai deu cho the an/khong co dong nao, nhung
--    mot cai la tin tot con cai kia la buoc 1 chua song. `exists` giu ranh gioi.
r = run("", false)
eq(r.exists, true, "file rong -> exists=true (da chay, SACH)")
eq(r.cause, nil, "rong: KHONG co cause (khong phai loi)")
eq(r.muplug, 0, "rong: muplug=0")
eq(r.critical, 0, "rong: critical=0")
eq(r.sections, 0, "rong: sections=0")

-- 3. CHI khoi `===` (ca thegioibds: go handler PHP). Truoc ban nay day la cho
--    the BIEN MAT. `sections` phai dem, `muplug`/`critical` van 0.
local shadow = table.concat({
    "=== 2026-10-10 03:00 [full] SHADOW: thu muc plugin/theme GO handler PHP ===",
    "  /home/u/domains/x/public_html/wp-content/plugins/kgtlppodzv/Fox-C/",
    "      @ft-,h-:php,h-:shtml,t-:php",
    "  (1 thu muc. GO handler PHP = .php tai ve dang TEXT thay vi chay.)",
}, "\n")
r = run(shadow, false)
eq(r.exists, true, "shadow: exists=true")
eq(r.muplug, 0, "shadow: KHONG phai muplug")
eq(r.critical, 0, "shadow: KHONG phai critical")
eq(r.sections, 1, "shadow: dem DUOC 1 khoi `===`")

-- 4. tieu de `=== ... ===` dem theo SO KHOI, khong theo so dong chi tiet. Hai
--    khoi + nhieu dong thut le -> sections=2.
local two = table.concat({
    "=== 2026-10-10 03:00 [full] SHADOW: thu muc plugin/theme GO handler PHP ===",
    "  /a/b/Fox-C/",
    "      @ft-,h-:php",
    "=== 2026-10-10 03:30 [full] KHUON XAC THUC md5x3 ===",
    "     1234  /a/b/shell.php",
    "  (md5(md5(md5( = mat khau webshell)",
}, "\n")
r = run(two, false)
eq(r.sections, 2, "hai khoi -> sections=2")
eq(r.muplug, 0, "hai khoi: muplug=0")

-- 5. tron: MUPLUG + CRITICAL + mot khoi `===`. Ba bac dem RIENG, khong lan nhau.
local mixed = table.concat({
    "MUPLUG /a/wp-content/mu-plugins/x.php",
    "MUPLUG /a/wp-content/mu-plugins/y.php",
    "CRITICAL /a/wp-content/uploads/2026/01/z.php",
    "=== 2026-10-10 [full] SHADOW: thu muc plugin/theme GO handler PHP ===",
    "  /a/b/Fox-C/",
    "      h-:php",
}, "\n")
r = run(mixed, false)
eq(r.muplug, 2, "tron: muplug=2")
eq(r.critical, 1, "tron: critical=1")
eq(r.sections, 1, "tron: sections=1")

print(("ADMIN_FIM_OK %d qua, %d hong"):format(p, f))
if f > 0 then os.exit(1) end
