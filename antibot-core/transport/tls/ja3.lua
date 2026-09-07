local _M = {}

-- Đọc MỘT LẦN lúc nạp module, không đọc trong `capture()`. Phase
-- `ssl_client_hello` là nơi mọi lỗi Lua đều HUỶ BẮT TAY, nên càng ít việc chạy
-- trong đó càng tốt. `pcall` + mặc định "off": thiếu config thì hành xử y như
-- trước, không bao giờ tự bật.
local _cfg_ok, _cfg = pcall(require, "antibot.core.config")
local CIPHER_MODE =
    (_cfg_ok and _cfg and _cfg.tls and _cfg.tls.ja3_cipher) or "off"

-- ============================================================
-- Cross-phase bridge: ssl_client_hello_by_lua → access_by_lua
--
-- ngx.ctx KHÔNG persist giữa hai phase trên OpenResty 1.21+.
-- Dùng lua_shared_dict antibot_tls làm bridge.
--
-- RELAY 2 NHỊP (từ 2026-07-31). Vì sao không ghi thẳng md5(client_random) ở
-- phase ClientHello như trước: ĐO ĐƯỢC rằng OpenSSL chưa nạp client_random khi
-- callback ClientHello chạy — get_client_random(32) trả về 32 byte 0 trên MỌI
-- handshake ⇒ md5 = hằng số 70bc8f4b ⇒ cả dict chỉ có 1 entry, còn access phase
-- lại tính ra random THẬT nên không bao giờ khớp. Triệu chứng đánh lừa: ~20%
-- request "có ja3" (những request mà access phase cũng trả zero) đều mang CÙNG
-- một hash — không phải fingerprint của chúng, mà của handshake ghi sau cùng.
--
--   Nhịp 1 — ssl_client_hello_by_lua: parse được ClientHello (chỉ phase này có
--            ngx.ssl.clienthello.*) nhưng chưa có client_random → ghi tạm dưới
--            md5(raw_client_addr()), TTL ngắn.
--   Nhịp 2 — ssl_certificate_by_lua: client_random ĐÃ nạp (đo: zero=false) →
--            đọc entry tạm, ghi lại dưới md5(client_random), xoá entry tạm.
--            Gọi từ ja3s.capture() — không phải sửa 99 per-domain conf.
--   Đọc   — access_by_lua: md5(client_random), không đổi.
--
-- Cửa sổ va chạm của khoá tạm chỉ là khoảng cách giữa hai callback của CÙNG một
-- handshake (micro giây) → NAT chung IP không gây nhầm fingerprint.
-- ngx.var KHÔNG dùng được ở phase ClientHello (OpenResty 1.21+) nên
-- remote_addr:remote_port không phải lựa chọn.
--
-- Key format : "tls:<md5_of_client_random>"  /  tạm: "tlsq:<md5_of_client_addr>"
-- Value      : "tls13_flag|ext1-ext2|curve1-curve2|pt1-pt2"
-- TTL        : 300s (cover HTTP/2 long-lived + HTTP/1.1 keepalive)
-- HTTP/2     : nhiều request cùng handshake → cùng client_random → cùng key
-- ============================================================

local SHARED_DICT_NAME = "antibot_tls"
local TLS_KEY_PREFIX   = "tls:"
local TLS_KEY_TTL      = 300
local TMP_KEY_PREFIX   = "tlsq:"
-- 5s, KHÔNG dài hơn: đây là cửa sổ duy nhất mà hai client sau cùng một NAT có
-- thể nhầm fingerprint của nhau (xem promote ở run()). Cả hai đường tiêu thụ
-- entry tạm đều xảy ra trong vài mili giây sau ClientHello nên 5s đã rất dư.
local TMP_KEY_TTL      = 5

-- Bộ đếm rate-limit cho log chẩn đoán (per-worker, 1/200).
local _cap_n   = 0
local _relay_n = 0
local _relok_n = 0
local _prom_n  = 0
local _diag_n  = 0

-- Khoá THẬT: md5(client_random) — unique per handshake.
-- Dùng ở ssl_certificate_by_lua* (nhịp 2) và access_by_lua* (đọc).
-- KHÔNG dùng được ở ssl_client_hello_by_lua*: ở đó random toàn byte 0.
-- Chuỗi toàn 0 bị TỪ CHỐI làm khoá — nếu chấp nhận, mọi client rơi vào tình
-- trạng đó sẽ dùng chung một ô và nhận fingerprint của nhau.
local function get_random_key()
    local ok, ssl_lib = pcall(require, "ngx.ssl")
    if not ok then
        return nil, "ngx.ssl module unavailable"
    end
    local random, err = ssl_lib.get_client_random(32)
    if not random or #random == 0 then
        return nil, err or "no client_random (plain HTTP?)"
    end
    if random:find("[^%z]") == nil then
        return nil, "zero client_random"
    end
    return ngx.md5(random)
end

-- Khoá TẠM: md5(raw_client_addr) — 4 byte (IPv4) / 16 byte (IPv6) nhị phân.
-- Là thứ duy nhất định danh được kết nối ở phase ClientHello (ngx.var bị disable).
local function get_addr_key()
    local ok, ssl_lib = pcall(require, "ngx.ssl")
    if not ok then
        return nil, "ngx.ssl module unavailable"
    end
    local ok2, addr, _, err = pcall(ssl_lib.raw_client_addr)
    if not ok2 then
        return nil, "raw_client_addr threw: " .. tostring(addr)
    end
    if not addr or #addr == 0 then
        return nil, err or "no client addr"
    end
    return ngx.md5(addr)
end

local function is_grease(val)
    if not val or val == 0 then return false end
    local lo = val % 256
    local hi = math.floor(val / 256) % 256
    return lo == hi and lo % 16 == 10
end

local function u16(s, pos)
    local a, b = s:byte(pos, pos + 1)
    if not a or not b then return nil, pos end
    return a * 256 + b, pos + 2
end

-- Hai bộ phân tích dưới đây trả thêm `ok`, cùng một lý do với `parse_ciphers`:
-- **độ dài KHAI BÁO không khớp dữ liệu CÓ THẬT nghĩa là ta đang đọc một
-- extension bị cắt**, không phải "thừa/thiếu vài byte". Bản trước dùng
-- `math.min(..., #ext_data)` để lặng lẽ cắt theo phần đọc được rồi trả về như
-- một danh sách bình thường — tức công bố một JA3 sai mà không ai biết.
--
-- Vắng extension thì `ok = true`: client không gửi `supported_groups` là một
-- sự thật về client, và JA3 vốn mã hoá sự vắng mặt đó bằng trường rỗng.
-- Chỉ "khai báo rồi cắt ngắn" mới là hỏng.
local function parse_supported_groups(ext_data)
    -- VẮNG HẲN và CÓ MẶT NHƯNG THÂN RỖNG là hai chuyện khác nhau. Vắng =
    -- sự thật về client, JA3 mã hoá bằng trường rỗng. Thân 0 byte thì RFC 8422
    -- cấm (bắt buộc 2 byte độ dài) ⇒ đó là khung hỏng, phải báo `ok=false`.
    -- Gộp hai cái làm một khiến một ClientHello dị dạng sinh ra ĐÚNG chuỗi JA3
    -- của client hợp lệ không gửi extension — một va chạm bắt chước được.
    if not ext_data then return {}, true end
    if #ext_data == 0 then return {}, false end
    if #ext_data < 2 then return {}, false end
    local curves = {}
    local len, pos = u16(ext_data, 1)
    if not len then return {}, false end
    -- Theo RFC 8422 thân extension DÀI ĐÚNG BẰNG 2 + len. Kiểm `==`, không
    -- phải `>`: byte THỪA cũng là dấu hiệu ta đang đọc sai khung, y như byte
    -- THIẾU. Chấp nhận phần dư là quay lại đúng lối fail-soft vừa bỏ.
    -- `len == 0` LA CUA THU BA cua cung mot lo hong. Than co mat, truong do
    -- dai co mat, nhung KHAI BAO danh sach rong — RFC 8422 cam (NamedGroupList
    -- toi thieu 2 byte). Truoc day no lot qua `len % 2 == 0` va `2+0 == 2` roi
    -- tra `{}, true`, tuc sinh ra DUNG chuoi JA3 cua client hop le khong gui
    -- extension. Hai cua kia (`nil`, than rong) da chan; cua nay thi chua.
    if len < 2 or len % 2 ~= 0 or 2 + len ~= #ext_data then return {}, false end
    local bound = pos + len - 1
    while pos + 1 <= bound do
        local g; g, pos = u16(ext_data, pos)
        if not g then return {}, false end
        if not is_grease(g) then curves[#curves + 1] = g end
    end
    return curves, true
end

local function parse_ec_point_formats(ext_data)
    -- Cùng lý do với `parse_supported_groups`: RFC 4492 bắt buộc 1 byte độ
    -- dài, nên thân 0 byte là khung hỏng chứ không phải "không gửi".
    if not ext_data then return {}, true end
    if #ext_data == 0 then return {}, false end
    local fmts = {}
    local flen = ext_data:byte(1)
    if not flen then return {}, false end
    -- RFC 4492: thân dài ĐÚNG BẰNG 1 + flen, và ECPointFormatList tối thiểu 1
    -- phần tử. `flen == 0` lọt qua `1+0 == 1` — cùng cửa thứ ba như
    -- `supported_groups`.
    if flen < 1 or 1 + flen ~= #ext_data then return {}, false end
    for i = 2, 1 + flen do fmts[#fmts + 1] = ext_data:byte(i) end
    return fmts, true
end

-- BA TRẠNG THÁI, không phải hai. `false` phải có nghĩa "client KHÔNG chào TLS
-- 1.3" — một SỰ THẬT — chứ không được kiêm luôn nghĩa "đọc hỏng", vì
-- `consistency_check` đọc `ctx.tls13_offered == false` rồi cộng 0.35 (nhánh
-- `tls12`, 19,25 điểm). Gộp hai nghĩa vào một giá trị là biến một lỗi ĐỌC
-- thành một hình PHẠT.
--   nil   = không đọc được (thân dị dạng) → mọi luật bỏ qua
--   false = có đọc được, và KHÔNG có 0x0304 (kể cả khi vắng hẳn ext 43)
--   true  = có 0x0304
--
-- Con bug này có BA CỬA VÀO, đã bịt cả ba:
--   1. payload dict ghi "?" rồi `decode_tls13` trả `false`  (sửa 5757ebd)
--   2. extension CÓ MẶT nhưng thân 0 byte                    (sửa b41e567)
--   3. thân hợp lệ nhưng KHAI BÁO danh sách rỗng (`list_len == 0`) — lọt qua
--      `0 % 2 == 0` và `1 + 0 == 1` rồi rơi vào nhánh "đọc được" ⇒ `false`.
--      RFC 8446 đòi `versions<2..254>`, nên 0 là dị dạng.
--
-- Tách khỏi `capture()` để `contract_test` gọi được trực tiếp — phần này trước
-- đây nằm inline nên không có cách nào kiểm bằng test hành vi. Không dùng
-- `ngx` ở đây; lỗi trả về cho caller ghi log.
local function parse_supported_versions(sv_data)
    if not sv_data then return false end          -- vắng hẳn = sự thật
    if #sv_data == 0 then return nil, "than rong" end

    local list_len = sv_data:byte(1)
    if not list_len or list_len < 2 or list_len % 2 ~= 0
       or 1 + list_len ~= #sv_data then
        return nil, "di dang khai bao=" .. tostring(list_len)
                    .. " than=" .. #sv_data
    end

    for i = 2, list_len, 2 do
        if sv_data:byte(i) == 0x03 and sv_data:byte(i + 1) == 0x04 then
            return true
        end
    end
    return false
end

local function build_ja3_str(ver, ciphers, exts, curves, pt_fmts)
    local function join(t)
        if not t or #t == 0 then return "" end
        local parts = {}
        for i, v in ipairs(t) do parts[i] = tostring(v) end
        return table.concat(parts, "-")
    end
    return ("%d,%s,%s,%s,%s"):format(
        ver, join(ciphers), join(exts), join(curves), join(pt_fmts))
end

-- ── ĐỌC CIPHER LIST MÀ KHÔNG ĐOÁN HÌNH DẠNG TRẢ VỀ ──────────────────────
--
-- `get_client_hello_ciphers()` có thể trả BẢNG số hoặc CHUỖI byte thô (2 byte
-- big-endian mỗi cipher) tuỳ phiên bản. Đoán sai thì danh sách rỗng ⇒
-- `ja3_allowlist` chấm `cipher_count < 5 → 0.6` ⇒ **30 điểm oan cho tất cả**.
-- Nên xử lý CẢ HAI, và trả về kèm nhãn hình dạng để nấc `probe` in ra sự thật
-- thay vì để ai đó suy luận.
--
-- TRẢ VỀ THÊM `valid`, và đó là điểm cốt yếu. Bản trước fail-soft: chuỗi lẻ
-- byte thì bỏ byte cuối, phần tử bảng hỏng thì bỏ phần tử — rồi vẫn công bố
-- kết quả như một cipher list bình thường. Nghĩa là **đầu vào hỏng có thể
-- thành "JA3 đầy đủ"**: chỉ cần sót lại 1 cipher là `is_partial=false`, và
-- `ja3_allowlist` thấy `cipher_count < 5` nên chấm 0.6 × trọng số 50 =
-- **30 điểm** cho một client mà ta chỉ đơn giản là đọc hỏng.
--
-- Fail-soft đúng chỗ là "mất JA3", KHÔNG phải "JA3 sai được tin". Nên khi
-- không chắc, ta trả `valid=false` và phía gọi vứt cả danh sách — hành vi y
-- hệt nấc "off", tức đúng cái fail-safe đã chạy suốt từ trước tới nay.
local function parse_ciphers(raw)
    if type(raw) == "table" then
        local out = {}
        for _, v in ipairs(raw) do
            local n = tonumber(v)
            -- Một phần tử không phải số nguyên trong 0..65535 nghĩa là ta đang
            -- hiểu sai kiểu trả về — bỏ RIÊNG nó đi là tự lừa mình.
            if not n or n ~= math.floor(n) or n < 0 or n > 65535 then
                return {}, "table_bad", false
            end
            if not is_grease(n) then out[#out + 1] = n end
        end
        return out, "table", true
    end
    if type(raw) == "string" then
        -- Độ dài LẺ = ta đọc lệch khung 2 byte, không phải "thừa một byte".
        -- Bản trước bỏ byte cuối rồi đọc tiếp, tức công bố một dãy đã lệch.
        if #raw % 2 ~= 0 then
            return {}, "string_odd", false
        end
        local out = {}
        for i = 1, #raw - 1, 2 do
            local n = raw:byte(i) * 256 + raw:byte(i + 1)
            if not is_grease(n) then out[#out + 1] = n end
        end
        return out, "string", true
    end
    return {}, type(raw), false
end

-- Số cipher tối thiểu để một danh sách được coi là ĐỌC ĐƯỢC.
--
-- KHÔNG phải con số tuỳ ý: nó PHẢI ≥ ngưỡng `cipher_count < 5` trong
-- `intelligence/threat/ja3_allowlist.lua`. Dưới ngưỡng đó allowlist chấm 0.6 ×
-- trọng số 50 = 30 điểm. Nói cách khác, mọi danh sách mà ta công bố là "đầy
-- đủ" nhưng lại ngắn hơn 5 đều tự động thành 30 điểm phạt — nên thà giữ
-- `partial` (0 điểm) còn hơn.
--
-- Không có ClientHello THẬT nào của trình duyệt dưới 5 cipher; TLS 1.3 tối
-- thiểu đã 3 suite bắt buộc cộng các suite 1.2 để tương thích ngược.
-- `contract_test` mục 10b ghim hai con số này không lệch nhau.
local MIN_PLAUSIBLE_CIPHERS = 5

local function serialize(is_tls13, extensions, curves, pt_fmts, ciphers, ext_ok)
    local function join(t)
        if not t or #t == 0 then return "" end
        local parts = {}
        for i, v in ipairs(t) do parts[i] = tostring(v) end
        return table.concat(parts, "-")
    end
    -- Trường 5 và 6 THÊM VÀO CUỐI, cố ý: `deserialize` vẫn chấp nhận payload
    -- 4 trường, nên các bản ghi cũ còn nằm trong shared dict lúc reload không
    -- bị hỏng. Thêm vào giữa là gãy hết.
    return string.format("%s|%s|%s|%s|%s|%s",
        (is_tls13 == nil) and "?" or (is_tls13 and "1" or "0"),
        join(extensions),
        join(curves),
        join(pt_fmts),
        join(ciphers),
        ext_ok and "1" or "0")
end

-- `x and nil or y` KHÔNG BAO GIỜ trả về được `nil`. Vế giữa là `nil` ⇒ `and`
-- cho `nil` ⇒ rơi thẳng sang vế `or`. Nên `"?"` từng giải mã thành `false`,
-- tức "client KHÔNG chào TLS 1.3", trong khi sự thật là "ta KHÔNG ĐỌC ĐƯỢC".
--
-- Hai thứ đó dẫn tới hai hành động khác nhau: `intelligence/correlation/
-- consistency_check.lua` nhánh `tls12` gác đúng bằng `ctx.tls13_offered ==
-- false` và cộng +0.35 × 55 = **19,25 điểm**. Cả nỗ lực dựng trạng thái thứ ba
-- ở `serialize` (ghi `"?"`) bị hàm này nuốt mất ngay khi đọc lại.
-- DANH SÁCH TRẮNG, không phải danh sách đen: chỉ "1" và "0" mới là câu trả
-- lời; MỌI thứ khác — "?", "", nil, rác do payload cắt ngắn — đều là "không
-- biết". Viết kiểu `if s == "?" then return nil end; return s == "1"` thì rác
-- vẫn sập thành `false`, tức lặp lại đúng con bug đang sửa ở một cửa khác.
local function decode_tls13(s)
    if s == "1" then return true  end
    if s == "0" then return false end
    return nil
end

local function deserialize(val)
    if not val then return nil end
    local parts = {}
    for segment in (val .. "|"):gmatch("([^|]*)|") do
        parts[#parts + 1] = segment
    end
    if #parts < 4 then return nil end

    local function split_nums(s)
        local t = {}
        if s and s ~= "" then
            for n in s:gmatch("[^-]+") do
                local num = tonumber(n)
                if num then t[#t + 1] = num end
            end
        end
        return t
    end

    return {
        -- "?" = capture khong doc duoc supported_versions -> nil (BA trang
        -- thai). Payload cu chi co "1"/"0" nen khong bi anh huong.
        is_tls13   = decode_tls13(parts[1]),
        extensions = split_nums(parts[2]),
        curves     = split_nums(parts[3]),
        pt_fmts    = split_nums(parts[4]),
        -- `parts[5]` là nil với payload cũ (4 trường) còn nằm trong shared dict
        -- lúc reload. `split_nums(nil)` trả {} nên không cần nhánh riêng.
        ciphers    = split_nums(parts[5]),
        -- `parts[6]` nil = payload do bản CŨ ghi, còn sót trong cửa sổ reload
        -- (tối đa TLS_KEY_TTL = 300s). Coi là hợp lệ để hành vi trong cửa sổ đó
        -- đúng bằng hành vi trước khi sửa — không tự dưng siết thêm giữa lúc
        -- reload, cũng không tự dưng nới ra.
        ext_ok     = parts[6] ~= "0",
    }
end

-- PHÒNG VỆ BẮT BUỘC: mọi lỗi Lua trong phase ssl_client_hello đều HUỶ BẮT TAY
-- → sập HTTPS diện rộng. Sự cố 2026-04-22: `ngx.var` bị vô hiệu ở phase này
-- ("API disabled in the current context") giết handshake, âm thầm 3 tháng.
-- capture_unsafe() có thể ném; wrapper NUỐT mọi lỗi — JA3 mất là chấp nhận được,
-- HTTPS sập thì không.
function _M.capture()
    local ok, err = pcall(_M.capture_unsafe)
    if not ok then
        ngx.log(ngx.ERR, "[ja3] capture ERROR (đã nuốt, handshake tiếp tục): ",
                tostring(err))
    end
end

function _M.capture_unsafe()
    local ok, ssl_clt = pcall(require, "ngx.ssl.clienthello")
    if not ok then
        ngx.log(ngx.ERR, "[ja3] require ngx.ssl.clienthello failed: ",
                tostring(ssl_clt))
        return
    end

    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then
        ngx.log(ngx.ERR, "[ja3] shared dict '", SHARED_DICT_NAME, "' not found")
        return
    end

    local addr_key, err = get_addr_key()
    if not addr_key then
        ngx.log(ngx.ERR, "[ja3] capture_miss reason=no_addr_key err=",
                tostring(err))
        return
    end

    -- ── `tls13` PHẢI CÓ NGHĨA LÀ TLS 1.3, KHÔNG PHẢI "CÓ EXTENSION 43" ──
    --
    -- Bản trước: `is_tls13 = (extension 0x002b tồn tại)`. Extension đó là
    -- `supported_versions` — nó CHỨA danh sách phiên bản, và sự tồn tại của nó
    -- chỉ nói "client biết cú pháp TLS 1.3", không nói "client đề nghị 1.3".
    --
    -- Vì sao phải đúng: `intelligence/correlation/consistency_check.lua` đọc
    -- `ctx.tls13_offered == false` như "client đi TLS 1.2" và cộng 0.35 (nhánh `tls12`,
    -- 19,25 điểm), còn `transport/http2/pseudo_header.lua` so nó với bảng
    -- `KNOWN_PATTERNS`. Hai chỗ đó diễn giải trường này như PHIÊN BẢN THẬT.
    --
    -- Thân extension: 1 byte độ dài danh sách, rồi từng phiên bản 2 byte
    -- big-endian. 0x0304 = TLS 1.3. GREASE nằm lẫn trong danh sách và bị bỏ
    -- qua tự nhiên vì ta chỉ tìm đúng một giá trị.
    --
    -- ẢNH HƯỞNG THỰC TẾ GẦN BẰNG KHÔNG, và đó là chủ ý: client gửi extension
    -- 43 mà không liệt 0x0304 là hợp lệ nhưng gần như không tồn tại. Đây là
    -- sửa cho trường ĐÚNG NGHĨA, không phải để đổi số liệu.
    -- BA TRẠNG THÁI, không phải hai. `false` phải có nghĩa "client KHÔNG chào
    -- TLS 1.3" — một SỰ THẬT — chứ không được kiêm luôn nghĩa "đọc hỏng".
    -- Vì `consistency_check` đọc `ctx.tls13_offered == false` rồi cộng 0.35
    -- (nhánh `tls12`, 19,25 điểm): gộp hai nghĩa vào một giá trị là biến một
    -- lỗi ĐỌC thành một hình PHẠT, đúng con đường đã bịt ở trục cipher.
    --   nil   = không đọc được (thân dị dạng)  → mọi luật bỏ qua
    --   false = có đọc được, và KHÔNG có 0x0304 (kể cả khi vắng hẳn ext 43)
    --   true  = có 0x0304
    local is_tls13, sv_err = parse_supported_versions(
                                 ssl_clt.get_client_hello_ext(0x002b))
    if sv_err then
        ngx.log(ngx.ERR, "[ja3] supported_versions ", sv_err, " -> tls13=nil")
    end

    -- ── DANH SÁCH EXTENSION VÀ CỜ `ext_ok` ───────────────────────────────
    --
    -- JA3 mã hoá extension theo ĐÚNG THỨ TỰ client gửi. Mất thứ tự thì hash
    -- không còn là fingerprint — nó đổi giữa các lần duyệt bảng, nên:
    --   • `fp_light` churn (fp_light = md5(ip+ua+asn+ja3) từ 73b413d — `ja3`
    --     là MỘT PHẦN TƯ cái băm, nên nó chũn là chũn thẳng vào identity)
    --   • `sess:` mồ côi, counter reset
    --   • `ja3:allow:`/`ja3:block:` người vận hành đặt tay KHÔNG BAO GIỜ khớp
    --
    -- Còn extension RỖNG (API thiếu hoặc lỗi) thì tệ theo kiểu khác: chuỗi JA3
    -- có trường extension trống ⇒ `ja3_allowlist` đếm `browser_ext_count = 0`
    -- ⇒ `ext_score = 0.4` × trọng số 50 = **20 điểm oan**. Cùng đúng hình dạng
    -- ca "30 điểm oan" của cipher, chỉ khác trục.
    --
    -- Nên `ext_ok` PHẢI đi cùng payload sang access phase, và `run()` chỉ hạ
    -- `ja3_partial` khi cipher hợp lệ VÀ extension hợp lệ. Thiếu bất kỳ vế nào
    -- thì giữ `partial` — tức đúng hành vi nấc "off", 0 điểm.
    local extensions = {}
    local ext_ok     = false
    if type(ssl_clt.get_client_hello_ext_present) == "function" then
        local ok2, ext_present = pcall(ssl_clt.get_client_hello_ext_present)
        if ok2 and type(ext_present) == "table" then
            if ext_present[1] ~= nil then
                -- MỘT phần tử sai kiểu là HỎNG CẢ DANH SÁCH, không phải "bỏ
                -- riêng nó". Cùng triết lý với `parse_ciphers`: bỏ lẻ tẻ rồi
                -- công bố phần còn lại chính là công bố một thứ tự đã thiếu
                -- mục — mà JA3 mã hoá extension THEO THỨ TỰ.
                ext_ok = true
                for _, etype in ipairs(ext_present) do
                    if type(etype) ~= "number" then
                        ext_ok = false
                        ngx.log(ngx.ERR, "[ja3] ext_present co phan tu khong ",
                                "phai so: ", type(etype))
                        break
                    end
                    if not is_grease(etype) then
                        extensions[#extensions + 1] = etype
                    end
                end
            else
                -- Bảng băm: `pairs()` KHÔNG bảo đảm thứ tự. Vẫn thu thập để
                -- nấc `probe` đếm được, nhưng KHÔNG bao giờ gọi đây là JA3
                -- đầy đủ. Chỉ xảy ra với lua-resty-core < 0.1.25 (đo
                -- 2026-09-06: cả 5 máy đang 0.1.33/0.1.34).
                ngx.log(ngx.ERR,  "[ja3] ext_present is hash — order lost, ",
                        "upgrade lua-resty-core >= 0.1.25")
                for etype in pairs(ext_present) do
                    if type(etype) == "number" and not is_grease(etype) then
                        extensions[#extensions + 1] = etype
                    end
                end
            end
        elseif not ok2 then
            ngx.log(ngx.ERR,  "[ja3] get_client_hello_ext_present error: ",
                    tostring(ext_present))
        end
    else
        ngx.log(ngx.ERR,  "[ja3] get_client_hello_ext_present unavailable, ",
                "upgrade lua-resty-core >= 0.1.25")
    end

    -- Extension rỗng không bao giờ là một JA3 đầy đủ, kể cả khi API chạy êm.
    if #extensions == 0 then ext_ok = false end

    local curves  = {}
    local sg_data = ssl_clt.get_client_hello_ext(0x000a)
    if sg_data then
        local ok_sg
        curves, ok_sg = parse_supported_groups(sg_data)
        if not ok_sg then
            ext_ok = false
            ngx.log(ngx.ERR, "[ja3] supported_groups cat ngan len=", #sg_data)
        end
    end

    local pt_fmts = {}
    local pf_data = ssl_clt.get_client_hello_ext(0x000b)
    if pf_data then
        local ok_pf
        pt_fmts, ok_pf = parse_ec_point_formats(pf_data)
        if not ok_pf then
            ext_ok = false
            ngx.log(ngx.ERR, "[ja3] point_formats cat ngan len=", #pf_data)
        end
    end

    -- CIPHER LIST — chỉ chạm khi được bật tường minh.
    --
    -- `pcall` RIÊNG cho lời gọi này: nó là API mới nhất trong cả hàm, và một
    -- lỗi Lua ở phase `ssl_client_hello` không phải là "mất JA3" mà là **huỷ
    -- bắt tay TLS** (sự cố 2026-04-22). Hỏng ở đây phải rơi về danh sách rỗng,
    -- tức đúng hành vi của nấc "off", chứ không được lan ra ngoài.
    local ciphers, shape, valid = {}, "skipped", true
    if CIPHER_MODE ~= "off"
       and type(ssl_clt.get_client_hello_ciphers) == "function" then
        local ok3, raw = pcall(ssl_clt.get_client_hello_ciphers)
        if ok3 then
            ciphers, shape, valid = parse_ciphers(raw)
        else
            shape, valid = "error", false
            ngx.log(ngx.ERR, "[ja3] get_client_hello_ciphers loi (da nuot): ",
                    tostring(raw))
        end

        -- ĐỌC HỎNG THÌ KHÔNG GHI GÌ CẢ, thay vì ghi một dãy đã lệch.
        -- Đây là chỗ chặn duy nhất cần thiết: `run()` chỉ thấy payload đã qua
        -- cửa này, nên không phải mang thêm cờ `valid` qua shared dict (tức
        -- không phải đổi định dạng payload lần thứ hai).
        if not valid then
            ciphers = {}
            ngx.log(ngx.ERR, "[ja3] cipher_invalid shape=", shape,
                    " → bo ca danh sach, giu partial")
        end

        -- Lấy mẫu 1/200 ở mức ERR — đây là DÒNG DUY NHẤT nói cho ta biết API
        -- thật sự trả về cái gì. Không có nó thì việc lên nấc "on" là đoán.
        if _cap_n % 200 == 1 then
            ngx.log(ngx.ERR, "[ja3] cipher_probe mode=", CIPHER_MODE,
                    " shape=", shape, " valid=", tostring(valid),
                    " n=", #ciphers,
                    " first=", tostring(ciphers[1]),
                    " last=", tostring(ciphers[#ciphers]))
        end
    end

    local val = serialize(is_tls13, extensions, curves, pt_fmts, ciphers, ext_ok)
    local set_ok, set_err = shared:set(TMP_KEY_PREFIX .. addr_key, val,
                                       TMP_KEY_TTL)
    if not set_ok then
        ngx.log(ngx.ERR, "[ja3] capture_miss reason=set_failed err=",
                tostring(set_err))
        return
    end

    _cap_n = _cap_n + 1
    if _cap_n % 200 == 1 then
        ngx.log(ngx.ERR, "[ja3] capture_ok tmp=", addr_key:sub(1, 8),
                " n=", _cap_n, " tls13=", tostring(is_tls13),
                " #exts=", #extensions, " ext_ok=", tostring(ext_ok))
    end
end

-- ============================================================
-- Nhịp 2 — gọi từ ssl_certificate_by_lua* (qua ja3s.capture()).
-- Đổi khoá tạm (theo IP) sang khoá thật (theo client_random).
-- Caller ĐÃ bọc pcall; hàm này vẫn tự phòng vệ để lỗi không lan sang ja3s.
-- ============================================================
function _M.relay()
    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then return end

    local addr_key = get_addr_key()
    if not addr_key then return end

    local tmp_key = TMP_KEY_PREFIX .. addr_key
    local val = shared:get(tmp_key)
    if not val then
        -- Không có entry tạm: handshake nối lại phiên (ClientHello callback vẫn
        -- chạy nhưng entry đã hết TTL), hoặc capture() thoát sớm.
        _relay_n = _relay_n + 1
        if _relay_n % 200 == 1 then
            ngx.log(ngx.ERR, "[ja3] relay_miss reason=no_tmp tmp=",
                    addr_key:sub(1, 8), " n=", _relay_n)
        end
        return
    end

    local rand_key, err = get_random_key()
    if not rand_key then
        _relay_n = _relay_n + 1
        if _relay_n % 200 == 1 then
            ngx.log(ngx.ERR, "[ja3] relay_miss reason=no_random err=",
                    tostring(err), " n=", _relay_n)
        end
        return
    end

    shared:set(TLS_KEY_PREFIX .. rand_key, val, TLS_KEY_TTL)
    -- Xoá luôn để thu hẹp cửa sổ va chạm NAT của đường promote ở run().
    shared:delete(tmp_key)

    -- So `relay_ok n` với `capture_ok n` trong cùng một cửa sổ, cùng worker:
    --   xấp xỉ nhau  ⇒ certificate callback chạy cho mọi handshake
    --   thấp hơn hẳn ⇒ handshake nối lại phiên bỏ qua certificate callback
    --                  ⇒ phần chênh lệch đó phải nhờ đường promote ở run()
    _relok_n = _relok_n + 1
    if _relok_n % 200 == 1 then
        ngx.log(ngx.ERR, "[ja3] relay_ok n=", _relok_n)
    end
end

-- Chẩn đoán vì sao run() không lấy được JA3.
-- Ba đường thoát dẫn tới ja3=nil trước đây đều return IM LẶNG (hoặc log DEBUG,
-- bị lọc) → một tính năng bảo mật chết 3 tháng mà error.log không một dấu vết.
-- Rate-limit 1/200 để không bloat log ở traffic cao (per-worker counter).
--
-- PHẢI là ngx.ERR, KHÔNG phải ngx.WARN: run() chạy ở access phase, tức trong
-- per-domain server block, mà da_to_openresty.sh ghi đè
-- `error_log /var/log/nginx/domains/<fqdn>.error.log;` KHÔNG kèm level →
-- mặc định `error` → mọi dòng WARN bị lọc sạch, không ghi ở đâu cả
-- (global error_log `warn` chỉ áp cho server không override — gần như không có).
-- Đã kiểm chứng 2026-07-31: WARN cho ra 0 dòng ở cả global/per-domain/antibot.log.
local function diag_miss(reason, extra)
    _diag_n = _diag_n + 1
    if _diag_n % 200 ~= 1 then return end
    ngx.log(ngx.ERR, "[ja3] run_miss reason=", reason,
            " n=", _diag_n, " ", extra or "")
end

function _M.run(ctx)
    local shared = ngx.shared[SHARED_DICT_NAME]
    if not shared then
        diag_miss("no_shared_dict")
        ctx.ja3 = nil; ctx.ja3_raw = nil; ctx.ja3_partial = nil
        ctx.tls_version = nil; ctx.tls13_offered = nil
        return
    end

    local bridge_key, err = get_random_key()
    if not bridge_key then
        -- HTTP plain (err="no client_random"), hoặc access phase trả 32 byte 0
        -- (err="zero client_random"). Trường hợp sau THÀ MẤT JA3 còn hơn dùng:
        -- khoá zero là hằng số nên mọi client rơi vào đó sẽ đọc chung một ô và
        -- nhận fingerprint của nhau — chính là bug đã đo 2026-07-31.
        -- (KHÔNG dùng ctx.h2_is_h2: transport/init.lua chạy tls.run TRƯỚC
        --  http2.run nên trường đó luôn nil ở đây.)
        diag_miss("no_bridge_key", "err=" .. tostring(err)
                  .. " scheme=" .. tostring(ngx.var.scheme))
        ctx.ja3            = nil
        ctx.ja3_raw        = nil
        ctx.ja3_partial    = nil
        ctx.tls_version    = nil
        ctx.tls13_offered          = nil
        return
    end

    local key = TLS_KEY_PREFIX .. bridge_key
    local val = shared:get(key)

    if not val then
        -- ĐƯỜNG CỨU: handshake NỐI LẠI PHIÊN không gửi certificate → certificate
        -- callback không chạy → nhịp 2 không chạy → không có entry dưới khoá thật.
        -- Nhưng callback ClientHello VẪN chạy, nên entry tạm (theo IP) vẫn có.
        -- Với keepalive_timeout 65s + ssl_session_cache 10m, nối lại phiên là
        -- đường phổ biến NHẤT — đo 2026-07-31: dict_miss chiếm 143/173 mẫu miss.
        --
        -- Thăng cấp entry tạm sang khoá thật rồi dùng luôn. Request đầu tiên của
        -- kết nối trả giá tra 2 lần; mọi request sau trúng thẳng khoá thật.
        --
        -- ĐÁNH ĐỔI: entry tạm khoá theo IP, nên hai client sau cùng một NAT cùng
        -- nối lại phiên trong TMP_KEY_TTL=5s có thể nhận fingerprint của nhau.
        -- Cửa sổ 5s + nhịp 2 đã xoá entry tạm cho mọi handshake mới ⇒ phần dư
        -- rất nhỏ. Chấp nhận: thà lệch trong 5s còn hơn mất JA3 ở 83% request.
        local addr = ngx.var.binary_remote_addr
        if addr and #addr > 0 then
            local tmp_key = TMP_KEY_PREFIX .. ngx.md5(addr)
            local tmp_val = shared:get(tmp_key)
            if tmp_val then
                shared:set(key, tmp_val, TLS_KEY_TTL)
                val = tmp_val
                _prom_n = _prom_n + 1
                if _prom_n % 200 == 1 then
                    ngx.log(ngx.ERR, "[ja3] promote n=", _prom_n)
                end
            end
        end
    end

    if not val then
        -- Không cứu được. Còn lại: kết nối mở trước reload, entry hết TTL 300s,
        -- hoặc dict đầy → LRU evict (eviction KHÔNG báo lỗi ở set → im lặng).
        -- `free` phân biệt trường hợp cuối: tụt gần 0 ⇒ dict quá nhỏ.
        local sample = ""
        if (_diag_n + 1) % 200 == 1 then
            local ok_k, keys = pcall(shared.get_keys, shared, 4)
            if ok_k and type(keys) == "table" then
                local out = {}
                for i, k in ipairs(keys) do out[i] = k:sub(1, 12) end
                sample = " dict=[" .. table.concat(out, ",") .. "]"
            else
                sample = " dict=<get_keys failed>"
            end
        end
        diag_miss("dict_miss", "key=" .. bridge_key:sub(1, 8)
                  .. " free=" .. tostring(shared:free_space())
                  .. " cap=" .. tostring(shared:capacity())
                  .. sample)
        ctx.ja3            = nil
        ctx.ja3_raw        = nil
        ctx.ja3_partial    = nil
        ctx.tls_version    = nil
        ctx.tls13_offered          = nil
        return
    end

    -- Không xóa key: HTTP/2 multiplexing nhiều request/connection
    -- Key tự expire sau TLS_KEY_TTL giây

    local data = deserialize(val)
    if not data then
        ngx.log(ngx.ERR, "[ja3] deserialize failed val=", tostring(val))
        ctx.ja3 = nil; ctx.tls13_offered = nil; ctx.ja3_partial = nil
        return
    end

    -- ── VÌ SAO KHÔNG CÓ CIPHER LIST, VÀ VÌ SAO ĐÓ LÀ CHỦ ĐỘNG ──────────
    --
    -- `ja3_stream.lua` ĐÃ BỊ XOÁ (2026-09-06). Nó đọc ClientHello ở tầng
    -- `stream{}` preread, mà kiến trúc này KHÔNG có `stream{}`: OpenResty kết
    -- thúc TLS/HTTP rồi `proxy_pass` sang Apache, nên `$remote_addr` là IP thật
    -- của khách. Thêm một tầng stream đọc rồi chuyển tiếp lại ClientHello vừa
    -- có thể phá bắt tay, vừa làm rối định tuyến — đó là đánh đổi kiến trúc CÓ
    -- CHỦ Ý, không phải chỗ bị bỏ sót.
    --
    -- Hệ quả đo được: `is_partial` LUÔN true ⇒ số JA3 đầy đủ trên toàn đàn máy
    -- là **0**. `intelligence/threat/ja3_db.lua` và `ja3_allowlist.lua` đều gác
    -- `ja3_partial` nên chúng chưa từng chạy — đó là fail-safe đúng.
    --
    -- CÒN MỘT ĐƯỜNG KHÁC, KHÔNG ĐỤNG TỚI KIẾN TRÚC:
    -- `ngx.ssl.clienthello.get_client_hello_ciphers()` lấy được cipher NGAY
    -- trong `ssl_client_hello_by_lua`. Đo 2026-09-06 trên cả 5 máy
    -- (OpenResty 1.29.2.3 / 1.31.1.1, lua-resty-core 0.1.33 / 0.1.34): API này
    -- **CÓ**. Chưa dùng vì bật nó là một thay đổi CHÍNH SÁCH chứ không phải sửa
    -- lỗi — xem `transport/CLAUDE.md` mục 2026-09-06.
    -- Nấc "probe" ĐẾM cipher nhưng KHÔNG đưa vào hash. Đó là toàn bộ ý nghĩa
    -- của nấc giữa: chuỗi JA3 và `ja3_partial` y hệt nấc "off", nên hành vi
    -- chấm điểm không đổi một chút nào, mà `ja3c=` trong antibot.log vẫn cho
    -- thấy API có lấy được cipher hay không và lấy được bao nhiêu.
    local captured   = data.ciphers or {}
    local ciphers    = {}
    local is_partial = true

    ctx.ja3_cipher_n = #captured

    -- SÀN `MIN_PLAUSIBLE_CIPHERS`, không phải `> 0`.
    --
    -- `> 0` là ngưỡng sai vì nó không hỏi "đọc có đúng không" mà hỏi "có đọc
    -- được gì không". Một danh sách 1–4 cipher lọt qua `> 0` sẽ được công bố là
    -- JA3 ĐẦY ĐỦ, rồi `ja3_allowlist` chấm ngay `cipher_count < 5 → 0.6` ×
    -- trọng số 50 = **30 điểm** — cho một client mà lỗi duy nhất là ta đọc hụt.
    --
    -- Giữ `partial` thì `ja3_allowlist` thoát sớm ở cổng `ctx.ja3_partial` và
    -- cộng 0 điểm. Hai đường đều là "mất thông tin", nhưng một đường mất im
    -- lặng còn đường kia phạt oan.
    if CIPHER_MODE == "on"
       and #captured >= MIN_PLAUSIBLE_CIPHERS
       and data.ext_ok then
        ciphers    = captured
        is_partial = false
    elseif CIPHER_MODE == "on" and #captured > 0 and not data.ext_ok then
        -- Cipher đủ nhưng extension không dùng được: mất thứ tự, rỗng, hoặc
        -- `supported_groups`/`ec_point_formats` bị cắt ngắn. JA3 dựng từ đó
        -- không ổn định giữa các request nên không được coi là đầy đủ.
        ngx.log(ngx.ERR, "[ja3] ext_not_ok n_cipher=", #captured,
                " #exts=", #(data.extensions or {}),
                " → giu partial ip=", ctx.ip or "?")
    elseif CIPHER_MODE == "on" and #captured > 0 then
        ngx.log(ngx.ERR, "[ja3] cipher_too_few n=", #captured,
                " min=", MIN_PLAUSIBLE_CIPHERS, " → giu partial ip=",
                ctx.ip or "?")
    end

    local tls_version = 0x0303
    local ja3_str  = build_ja3_str(tls_version, ciphers,
                                   data.extensions, data.curves, data.pt_fmts)
    local ja3_hash = ngx.md5(ja3_str)

    ctx.ja3            = ja3_hash
    ctx.ja3_raw        = ja3_str
    ctx.ja3_partial    = is_partial
    ctx.tls_version    = tls_version
    -- ĐỔI TÊN 2026-09-06: `offered`, không phải "phiên bản đã thương lượng".
    -- Đây là điều client GỬI trong `supported_versions`, không phải điều
    -- OpenSSL chốt với nó. Với tầng `mismatch` thì "client tự nhận gì" mới
    -- đúng là thứ cần so — nhưng tên cũ (`tls13`) mời gọi lần sửa sau đọc nó
    -- thành phiên bản thật. Cột log vẫn là `tls13=` để các script phân tích
    -- đang dùng không gãy.
    ctx.tls13_offered  = data.is_tls13

    ngx.log(ngx.DEBUG,
        "[ja3] run: key=", bridge_key:sub(1, 8),
        " hash=", ja3_hash,
        " tls13=", tostring(ctx.tls13_offered),
        " partial=", tostring(is_partial),
        " #exts=", #data.extensions,
        " #curves=", #data.curves)
end

-- ── LOI RA CHO KIEM THU, KHONG PHAI API ──────────────────────────────
--
-- `contract_test` muc 10 goi thang hai thu nay. Ly do phai lo chung ra: cac
-- muc kiem khac cua bo test do TIM CHUOI trong ma nguon, ma chinh dau file
-- contract_test da ghi "BAO XANH => khong chung minh duoc gi ca". Voi thang
-- cipher thi mau xanh do KHONG DU: bat nac "on" la doi chinh sach cham diem
-- tren toan dan may, nen cho nay phai co phep kiem CHAY THAT ham.
--
-- Khong module nao trong san pham duoc goi hai truong nay.
_M._parse_ciphers        = parse_ciphers
_M._MIN_PLAUSIBLE_CIPHERS = MIN_PLAUSIBLE_CIPHERS

-- Cùng lý do, cho trạng thái BA NGÔI của `tls13`. Bug `"?"` → `false` sống
-- được vì test chỉ TÌM CHUỖI trong mã nguồn: một phép so sánh sai vẫn cho
-- mẫu xanh. Round-trip `serialize` → `deserialize` là thứ duy nhất bắt được.
_M._serialize            = serialize
_M._deserialize          = deserialize
_M._parse_groups         = parse_supported_groups
_M._parse_pt_fmts        = parse_ec_point_formats
_M._parse_versions       = parse_supported_versions

return _M
