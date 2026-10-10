-- admin_fimwaf_test.lua — kiem endpoint `/antibot-admin/fimwaf` (tab WAF).
--
-- VI SAO CAN. Endpoint nay PARSE dinh dang dong cua `fim.sh` roi GOM theo
-- domain. Ca hai deu la hop dong lien tep: neu `fim.sh` doi dinh dang hoac neu
-- phep trich domain sai thi bang hien SAI chu khong hien LOI — mot bang trong
-- doc thanh "sach" trong khi that ra khong parse duoc gi. Dung ho loi
-- `feedback_read_log_schema_first`.
--
-- Dinh dang duoc ghim o day, doc tu `fim.sh` 10-10:
--   dong 2931: "%-8s %-3s %s  sc=%d\n"       -> mot file
--   dong 2921: "%-8s %-3s %4d file trong %s" -> gom nhom (so file PHAI dem dung)
--
-- Bo nay TRICH `render_fimwaf` + `tail_lines` + `parse_fim_line` roi chay THAT
-- tren tep tam that (khong gia `io`): `tail_lines` dung `seek`, nen gia `io` se
-- kiem mot thu khac han cai chay tren production.
--
-- CHAY:  resty antibot-core/admin/tests/admin_fimwaf_test.lua
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

-- Trich ba manh: hai ham phu + ham chinh. Chung nam lien nhau trong init.lua.
local tl  = src:match("(local function tail_lines%(path, want%).-\nend\n)")
local fz  = src:match("(local function fim_zone%(path%).-\nend\n)")
local pf  = src:match("(local function parse_fim_line%(s%).-\nend\n)")
local rk  = src:match("(local FIM_RANK = %b{})")
local body= src:match("(local function render_fimwaf%(%).-\nend\n)")
assert(tl,   "khong trich duoc tail_lines")
assert(fz,   "khong trich duoc fim_zone")
assert(pf,   "khong trich duoc parse_fim_line")
assert(rk,   "khong trich duoc FIM_RANK")
assert(body, "khong trich duoc render_fimwaf")

local tmpdir = os.getenv("TMPDIR") or "/tmp"
local CRIT = tmpdir .. "/abfw_crit.log"
local FULL = tmpdir .. "/abfw_full.log"

local function write(path, text)
    local f = assert(io.open(path, "w"))
    f:write(text)
    f:close()
end
local function rm(path) os.remove(path) end

-- Chay ham that. `FIM_CRITLOG`/`FIM_FULLLOG`/`FIM_MAX_LINES` la upvalue cap
-- module, cap lai qua env — tro vao tep TAM chu khong phai duong dan that.
-- `chunk` nho de BUOC vong lui khoi chay nhieu lan. Voi 256 KB that thi moi
-- fixture o duoi deu gon trong MOT khoi, nen nhanh `pos > 0` (bo dong bi cat
-- giua) KHONG BAO GIO chay va phep kiem muc 10 khong kiem duoc gi — do dung
-- bang dot bien 10-10: go nhanh do ma test van xanh.
local function run(domain, crit_path, full_path, chunk)
    out = {}
    fake.var = { arg_domain = domain }
    local env = {
        ngx = fake, cjson = cjson, io = io, os = os,
        table = table, string = string, math = math,
        tonumber = tonumber, tostring = tostring,
        ipairs = ipairs, pairs = pairs, type = type,
        setmetatable = setmetatable,
        FIM_CRITLOG   = crit_path or CRIT,
        FIM_FULLLOG   = full_path or FULL,
        FIM_MAX_LINES = 200,
        FIMWAF_TAIL   = 4096,
        FIMWAF_CHUNK  = chunk or (256 * 1024),
    }
    local chunk = assert(loadstring(
        tl .. "\n" .. rk .. "\n" .. fz .. "\n" .. pf .. "\n" ..
        body .. "\nreturn render_fimwaf"))
    setfenv(chunk, env)
    chunk()()
    return cjson.decode(out[1])
end

local p, f = 0, 0
local function eq(got, want, msg)
    if got == want then p = p + 1
    else f = f + 1; print(("HONG %s: got=%s want=%s"):format(msg, tostring(got), tostring(want))) end
end

local H = "/home/u1/domains/"

-- 1. Tep KHONG co -> never_run. Phan biet nay giu nguyen tu `/fim`: `fim.sh`
--    tao tep RONG o moi lan chay, nen khong co tep = chua lan nao xong.
rm(CRIT); rm(FULL)
local r = run(nil, tmpdir .. "/abfw_khong-ton-tai")
eq(r.available, false, "tep thieu -> available=false")
eq(r.cause, "never_run", "tep thieu -> cause=never_run")

-- 2. Tep RONG -> available=true, khong domain nao. KHAC HAN never_run: day la
--    "da chay, SACH THAT". Hai cai cho bang trong nhu nhau nen de lan nhat.
write(CRIT, "")
r = run(nil)
eq(r.available, true, "tep rong -> available=true (da chay, SACH)")
eq(#r.domains, 0, "tep rong -> 0 domain")
eq(r.cause, nil, "tep rong -> KHONG co cause")

-- 3. Trich DOMAIN tu duong dan, va gom theo domain. `mt=` la epoch THO
--    (`fim.sh` in epoch vi `strftime` la gawk-only).
--    1760000000 = 2025-10-09, 1760086400 = 2025-10-10.
write(CRIT, table.concat({
    "=== FIM 2026-10-10 03:00 [full] -- 3 thay doi, 3 dang chu y ===",
    "CRITICAL NEW  " .. H .. "a.com/public_html/wp-content/uploads/x.php  sc=45  mt=1760000000",
    "CRITICAL CHG  " .. H .. "a.com/public_html/.htaccess  sc=30  mt=1760086400",
    "HIGH     NEW  " .. H .. "b.com/public_html/t.php  sc=20  mt=1760000000",
}, "\n") .. "\n")
r = run(nil)
eq(#r.domains, 2, "hai domain")
eq(r.domains[1].domain, "a.com", "a.com len dau (diem cao hon)")
eq(r.domains[1].files, 2, "a.com: 2 file")
eq(r.domains[1].newn, 1, "a.com: 1 NEW")
eq(r.domains[1].chgn, 1, "a.com: 1 CHG")
eq(r.domains[1].detected, "2026-10-10 03:00", "`detected` = moc dong tieu de")
eq(r.domains[2].domain, "b.com", "b.com thu hai")

-- 3b. DIEM: lay CAO NHAT trong domain, khong phai tong. 45 va 30 -> 45.
--     Tong (75) se lam mot domain nhieu tep diem thap vuot mot webshell that.
eq(r.domains[1].score, 45, "diem = CAO NHAT (45), khong phai tong (75)")

-- 3c. TEP NANG NHAT: tra loi "file nao" ma khong phai bam vao domain.
eq(r.domains[1].worst,
   H .. "a.com/public_html/wp-content/uploads/x.php",
   "`worst` = tep co diem cao nhat")

-- 3d. MTIME: lay MOI NHAT, va KHAC `detected`. Day la hai cau hoi khac nhau —
--     "file doi luc nao" vs "fim.sh chay luc nao".
eq(r.domains[1].mtime, 1760086400, "mtime = MOI NHAT trong domain")

-- 3e. VUNG tach rieng khoi diem: `uploads` va `webroot` deu phai co mat.
eq(#r.domains[1].zones_list, 2, "a.com co HAI vung")
eq(r.domains[1].zones_list[1], "uploads", "vung dau: uploads")
eq(r.domains[1].zones_list[2], "webroot", "vung hai: webroot (.htaccess tang 0)")

-- 3f. Truong lam viec KHONG duoc gui di.
eq(r.domains[1].zseen, nil, "`zseen` bi loai truoc khi gui")
eq(r.domains[1].worst_sc, nil, "`worst_sc` bi loai truoc khi gui")

-- 4. DIEM quyet dinh thu tu, KHONG phai so file va KHONG phai nhan vi tri.
--    `b.com` 1 tep 60 diem phai dung TREN `a.com` 5 tep 10 diem.
--    Day la LOI nguoi dung bat 10-10: ban truoc sap theo nhan `CRITICAL` nen
--    moi domain WordPress deu CRITICAL va cot do khong phan biet duoc gi.
local t = { "=== FIM 2026-10-10 04:00 [full] -- x ===" }
for i = 1, 5 do
    t[#t+1] = "CRITICAL NEW  " .. H .. "a.com/public_html/wp-includes/f" .. i .. ".php  sc=10"
end
t[#t+1] = "HIGH     NEW  " .. H .. "b.com/public_html/wp-content/mu-plugins/z.php  sc=60"
write(CRIT, table.concat(t, "\n") .. "\n")
r = run(nil)
eq(r.domains[1].domain, "b.com", "60 diem (nhan HIGH) > 5 tep 10 diem (nhan CRITICAL)")
eq(r.domains[1].score, 60, "diem cao nhat len dau")
eq(r.domains[2].files, 5, "a.com van dem du 5")
eq(r.domains[2].score, 10, "a.com diem 10 du nhan la CRITICAL")

-- 5. Dong GOM NHOM: "4 file trong <dir>" phai dem 4, KHONG phai 1. Day la hinh
--    dang vu 20-09 (mot dot nhieu file vao mu-plugins) nen dem sai la bo sot
--    chinh ca nang nhat.
write(CRIT, table.concat({
    "=== FIM 2026-10-10 05:00 [full] -- x ===",
    "MUPLUG   NEW     4 file trong " .. H .. "c.com/public_html/wp-content/mu-plugins  (MOT DOT -- o day khong co cap nhat hop le)",
}, "\n") .. "\n")
r = run(nil)
eq(#r.domains, 1, "dong gom nhom: 1 domain")
eq(r.domains[1].domain, "c.com", "trich domain tu dong gom nhom")
eq(r.domains[1].files, 4, "dong gom nhom dem 4 file, KHONG phai 1")
-- 5b. Dong gom nhom KHONG co `sc=`, nen `score` phai o 0 MA `ungraded` > 0.
--     Hai thu khac nhau: "da cham, 0 diem" vs "chua cham tung tep". Hien thi
--     phai noi duoc, neu khong nguoi doc tuong domain nay sach.
eq(r.domains[1].score, 0, "dong gom nhom: score=0 (khong co sc=)")
eq(r.domains[1].ungraded, 1, "dong gom nhom: ungraded=1 -> 'chua cham tung tep'")
eq(r.domains[1].worst, nil, "dong gom nhom: khong co tep nang nhat")

-- 6. Dong KHONG phai liet ke phai bi BO QUA: tieu de, `!!`, dong thut le cua
--    khoi SHADOW. Neu chung lot vao thi bang co domain rac.
write(CRIT, table.concat({
    "=== FIM 2026-10-10 06:00 [full] -- 0 thay doi ===",
    "!! thieu redis-cli -- phat hien van chay",
    "=== 2026-10-10 06:00 [full] SHADOW: thu muc plugin/theme GO handler PHP ===",
    "  " .. H .. "d.com/public_html/wp-content/plugins/kgtlppodzv/Fox-C/",
    "      @ft-,h-:php",
    "  (1 thu muc. GO handler PHP = .php tai ve dang TEXT thay vi chay.)",
}, "\n") .. "\n")
r = run(nil)
eq(r.available, true, "chi co tieu de+thut le -> van available")
eq(#r.domains, 0, "dong tieu de/!!/thut le KHONG thanh domain")

-- 7. CHI TIET theo domain, doc tu `fim.log`. Chi dong cua domain duoc chon.
write(CRIT, table.concat({
    "=== FIM 2026-10-10 07:00 [full] -- x ===",
    "CRITICAL NEW  " .. H .. "a.com/public_html/wp-content/uploads/x.php  sc=45",
}, "\n") .. "\n")
write(FULL, table.concat({
    "=== FIM 2026-10-10 07:00 [full] -- 3 thay doi ===",
    "CRITICAL NEW  " .. H .. "a.com/public_html/wp-content/uploads/x.php  sc=45  mt=1760000000",
    "ROUTINE  CHG  " .. H .. "a.com/public_html/wp-content/plugins/p/readme.txt  sc=1  mt=1760086400",
    "HIGH     NEW  " .. H .. "zz.com/public_html/other.php  sc=20",
}, "\n") .. "\n")
r = run("a.com")
eq(r.domain, "a.com", "tra ve ten domain da chon")
eq(#r.detail, 2, "chi 2 dong cua a.com (bo zz.com)")
-- DIEM len dau, KHONG phai moi nhat. Cau nguoi doc hoi sau khi bam vao mot
-- domain la "cai nao dang lo", chu khong phai "cai nao vua xay ra": mot tep 45
-- diem tu hom qua quan trong hon `readme.txt` 1 diem 5 phut truoc.
eq(r.detail[1].score, 45, "diem cao len dau (45 truoc 1)")
eq(r.detail[1].kind, "NEW", "tep 45 diem la NEW")
eq(r.detail[2].score, 1, "tep 1 diem xuong duoi du no MOI hon")
eq(r.detail[1].ts, "2026-10-10 07:00", "chi tiet co moc phat hien")
eq(r.detail[1].mtime, 1760000000, "chi tiet co mtime")
eq(r.detail[1].zone, "uploads", "chi tiet co vung")

-- 7b. ROUTINE CHI co trong `fim.log`, khong co trong critical — day la ca ly do
--     dung HAI nguon. Neu chi dung critical thi dong `CHG` nay bien mat.
eq(r.detail[2].label, "ROUTINE", "fim.log co ROUTINE (critical thi khong)")

-- 8. Domain KHONG co trong fim.log -> detail rong, nhung KHONG phai loi.
r = run("khongcodomainnay.com")
eq(r.available, true, "domain la -> van available")
eq(#r.detail, 0, "domain la -> detail rong")
eq(r.detail_error, nil, "detail rong KHAC detail_error")

-- 9. `?domain=` BAN: ky tu lop Lua / duong dan phai bi tu choi, khong duoc di
--    vao mau. Bi tu choi thi coi nhu khong truyen -> khong co khoa `domain`.
r = run("../../etc/passwd")
eq(r.domain, nil, "duong dan bi tu choi")
r = run("a.com%")
eq(r.domain, nil, "ky tu lop Lua bi tu choi")
r = run("a.com")
eq(r.domain, "a.com", "ten domain hop le duoc nhan")

-- 10. `tail_lines` KHONG nap ca tep: tep > 1 khoi, chi giu N dong cuoi.
--     Viet 500 dong, `FIM_MAX_LINES=200` -> dong dau tien bi cat.
local big = { "=== FIM 2026-10-10 08:00 [full] -- x ===" }
for i = 1, 500 do
    big[#big+1] = "HIGH     NEW  " .. H .. "big.com/public_html/f" .. i .. ".php  sc=10"
end
write(CRIT, table.concat(big, "\n") .. "\n")
r = run(nil)
eq(r.crit_shown, 200, "chi soi 200 dong cuoi, khong nap het 501")
eq(r.domains[1].files, 200, "dem dung so dong da soi")

-- 11. NHIEU KHOI: `chunk` nho buoc vong lui chay nhieu lan, nen dong dau tien
--     doc duoc bi CAT GIUA. Khoi do phai bo di, neu khong thi mot duong dan
--     khuyet dau ("om/public_html/...") lot vao bang va trich ra domain SAI.
--     Phep kiem muc 10 KHONG bat duoc viec nay (fixture gon trong 1 khoi).
--     An toan nay dua tren MOT bat bien cua `tail_lines`: vong lui chi `break`
--     khi `nl > want`, nen buffer luon co NHIEU HON `want` dong va phep cat
--     `from` loai bo dong khuyet. Doi `>` thanh `>=` la dong khuyet LOT vao —
--     nen assertion duoi ghim HE QUA do, khong ghim cach hien thuc.
r = run(nil, nil, nil, 512)
eq(r.crit_shown, 200, "nhieu khoi: van dung 200 dong cuoi")
eq(r.domains[1].domain, "big.com", "nhieu khoi: domain KHONG bi cat dau")
eq(#r.domains, 1, "nhieu khoi: khong sinh domain rac tu dong bi cat")
-- Mot dong bi cat giua se KHONG parse ra domain `big.com` (duong dan khuyet
-- dau), nen no hoac thanh domain rac hoac thanh "(khong ro domain)". Dem dung
-- 200 file tren DUNG mot domain la bang chung khong co dong khuyet nao lot.
eq(r.domains[1].files, 200, "nhieu khoi: dung 200 file, khong thieu khong thua")

-- 12. BAT BIEN that cua `tail_lines`: `FIMWAF_CHUNK` phai LON HON do dai mot
--     dong. Dung thi mot khoi luon mang du dong de phep cat `from` loai bo dong
--     khuyet. Day la dieu kien duy nhat lam no gay, nen ghim bang mot `chunk`
--     nho hon mot dong (dong o fixture ~75 byte) va doi hoi NO VAN khong sinh
--     domain rac — neu ai ha `FIMWAF_CHUNK` xuong qua thap, phep nay do.
r = run(nil, nil, nil, 16)
eq(#r.domains, 1, "chunk < 1 dong: van KHONG sinh domain rac")
eq(r.domains[1].domain, "big.com", "chunk < 1 dong: domain van dung")

rm(CRIT); rm(FULL)
print(("ADMIN_FIMWAF_OK %d qua, %d hong"):format(p, f))
if f > 0 then os.exit(1) end
