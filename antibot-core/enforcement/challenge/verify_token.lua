local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"
local identity_mod = require "antibot.core.fingerprint.identity"

local ffi = require "ffi"
local C   = ffi.C

pcall(function()
    ffi.cdef([[
        typedef struct sha256_ctx_st SHA256_CTX;
        unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
        unsigned char *HMAC(const void *evp_md,
                            const void *key, int key_len,
                            const unsigned char *data, size_t data_len,
                            unsigned char *md, unsigned int *md_len);
        const void *EVP_sha256(void);
    ]])
end)

local function sha256_hex(data)
    local md = ffi.new("unsigned char[32]")
    local ok = pcall(function() C.SHA256(data, #data, md) end)
    if not ok then return nil end
    local hex = {}
    for i = 0, 31 do hex[i+1] = string.format("%02x", md[i]) end
    return table.concat(hex)
end

-- `hmac_sha256_hex` đã bị gỡ cùng `issue_ls_token` — nó không còn nơi dùng.
-- Khai báo `HMAC`/`EVP_sha256` trong `ffi.cdef` ở trên giữ nguyên: nó vô hại,
-- và `issue_token.lua` vẫn khai báo y hệt cho phần phát token.

local function check_canvas_consistency(red, id, ip, canvas_hash)
    if not canvas_hash or canvas_hash == "" or canvas_hash == "err" then return end
    local fp_key   = "fp:canvas:" .. id
    local existing = red:get(fp_key)
    if existing == ngx.null then existing = nil end
    if existing and existing ~= "" and existing ~= canvas_hash then
        red:incr("fp:canvas_change:" .. id)
        red:expire("fp:canvas_change:" .. id, 3600)
        ngx.log(ngx.INFO, "[verify] canvas_inconsistency id=", id:sub(1,8))
    else
        red:setex(fp_key, cfg.ttl.fp or 86400, canvas_hash)
    end
end

local function flag_fast_solve(red, id, solve_ms_str)
    local solve_ms = tonumber(solve_ms_str)
    if not solve_ms then return end
    if solve_ms < 50 then
        red:incr("fp:fast_solve:" .. id)
        red:expire("fp:fast_solve:" .. id, 3600)
    end
end

-- Ground truth: client vừa GIẢI ĐƯỢC PoW ⇒ gần như chắc chắn là trình duyệt
-- thật ⇒ mọi signal đứng trong top-3 của request đã bị thách đố là ỨNG VIÊN FP.
-- Nhãn do `challenge/nonce_store.lua` ghi lúc phát thách đố.
--
-- CHỈ ĐO, KHÔNG NỐI NGƯỢC VÀO TRỌNG SỐ. `async/adaptive_weight.lua` được thiết
-- kế đúng kiểu vòng lặp tự động đó và giờ là code chết; một vòng lặp không có
-- người kiểm tra sẽ để nhãn nhiễu ăn mòn cả mô hình. Giai đoạn này chỉ để đọc:
--   redis-cli --scan --pattern 'fp_cand:*' | while read k; do
--       echo "$(redis-cli GET $k) $k"; done | sort -rn
--   grep -F '[fp_sample]' /var/log/nginx/domains/*.error.log
--
-- Prefix `fp_cand:` (FP candidate) — KHÔNG dùng `fp:` vì trong file này `fp:` đã
-- mang nghĩa fingerprint (`fp:canvas:`, `fp:fast_solve:`).
local FP_CAND_TTL = 604800   -- 7 ngày: đủ tích luỹ qua nhiều đợt hiệu chỉnh

local function consume_label(red, id, ctx)
    local raw, gerr = red:get("label:" .. id)
    if not raw or raw == ngx.null then
        -- KHÔNG được im lặng: đây là đường thoát duy nhất khiến toàn bộ nguồn
        -- ground-truth không sinh dữ liệu, và im lặng thì không phân biệt được
        -- "chưa ai giải" với "hook không chạy". `label:` dùng chung TTL 60s với
        -- `nonce:`, mà nonce vừa được xoá thành công ở trên ⇒ label PHẢI còn.
        -- Nếu dòng này xuất hiện đều đặn thì khoá lệch hoặc kết nối Redis lỗi.
        ngx.log(ngx.ERR, "[fp_sample] no_label id=", id:sub(1, 8),
                " err=", tostring(gerr))
        return
    end
    red:del("label:" .. id)

    local f = {}
    for seg in (raw .. "|"):gmatch("([^|]*)|") do f[#f + 1] = seg end
    if #f < 7 then return end

    -- Bot render JS cũng giải được PoW — đã xảy ra 2026-07-07 với crawler của
    -- Meta (giải canvas PoW rồi vào lane người-dùng, né trần rate good-bot).
    -- Ghi lại để thấy, nhưng KHÔNG tính vào mẫu "người thật".
    if f[7] == "1" then
        ngx.log(ngx.ERR, "[fp_sample] SKIP bot-claim id=", id:sub(1, 8),
                " top=", f[5])
        return
    end

    ngx.log(ngx.ERR, "[fp_sample] solved id=", id:sub(1, 8),
            " score=", f[1], " eff=", f[2], " class=", f[3],
            " reason=", f[4], " top=", f[5], " mm=", f[6],
            " ip=", tostring(ctx.ip or "-"))

    -- `[%w_]+` chứ KHÔNG phải `[^,]+`: tên signal luôn là định danh thuần, còn
    -- `[^,]+` từng nuốt cả đoạn văn bản lọt vào do lỗi phân cách và tạo ra khoá
    -- rác kiểu `fp_cand: top:[bot_score=57%`. Lọc chặt ở phía đọc để một lỗi
    -- định dạng phía ghi không bao giờ làm bẩn được Redis.
    for name in f[5]:gmatch("[%w_]+") do
        local k = "fp_cand:" .. name
        red:incr(k)
        red:expire(k, FP_CAND_TTL)
    end
end

-- Build device_id từ UA + canvas hash — IP-independent và JA3-independent.
--
-- Tại sao canvas thay JA3:
--   Kiến trúc no-stream → JA3 luôn partial → build_device_id(ua, ja3) = nil
--   Canvas được capture bởi JS beacon, lưu vào beacon_data:{id}
--   Canvas ổn định theo GPU/driver — thay đổi khi đổi thiết bị/GPU
--   Phù hợp làm device identifier IP-independent
--
-- Tại sao không dùng JA3 nữa:
--   ja3=- với mọi request trong kiến trúc no-stream
--   → verified:device không bao giờ được set → tầng 2 vô hiệu
--
-- Canvas hash được đọc từ 2 nguồn theo thứ tự ưu tiên:
--   1. POST args.cv — có ngay khi verify (user vừa submit challenge)
--   2. Redis fp:canvas:{id} — từ verify lần trước (user quay lại)
local function build_device_id(ua, canvas_hash)
    if not ua or ua == "" then return nil end
    if not canvas_hash or canvas_hash == ""
       or canvas_hash == "err" or canvas_hash == "0" then
        return nil
    end
    return ngx.md5("device_canvas|" .. ua .. "|" .. canvas_hash)
end

-- ĐÍCH ĐẾN SAU KHI VERIFY — chỉ nhận ĐƯỜNG DẪN, không nhận URL.
--
-- Trang challenge gửi `location.pathname + location.search` của chính nó. Đó là
-- dữ liệu do CLIENT gửi, nên phải kiểm — một giá trị tự do đặt vào `Location:`
-- là open redirect, và nếu lọt `\r\n` thì là header injection.
--
-- Bốn phép kiểm, mỗi phép bịt một thứ khác nhau:
--   phải bắt đầu bằng `/`          — chặn `https://evil/`
--   ký tự thứ hai không là `/`|`\` — `//evil` và `/\evil` là URL TUYỆT ĐỐI với
--                                    trình duyệt, đây là dạng bị quên nhiều nhất
--   không `\r` `\n` `\0`           — header injection
--   dài tối đa 512                 — không cho nhồi
--
-- KHÔNG lọc theo danh sách ký tự cho phép: đường dẫn tiếng Việt có dấu là bình
-- thường trên đàn máy này, và một danh sách trắng ASCII sẽ ném chúng về `/`.
local MAX_DEST_LEN = 512
local function safe_dest(s)
    if type(s) ~= "string" or s == "" or #s > MAX_DEST_LEN then return nil end
    if s:sub(1, 1) ~= "/" then return nil end
    local c2 = s:sub(2, 2)
    if c2 == "/" or c2 == "\\" then return nil end
    if s:find("\r", 1, true) or s:find("\n", 1, true)
       or s:find("\0", 1, true) then return nil end
    return s
end

-- Referer là ĐƯỜNG LÙI cho những trang challenge cũ còn trong bộ nhớ trình
-- duyệt lúc triển khai — chúng chưa gửi `dest`. Cắt lấy phần đường dẫn rồi cho
-- qua đúng bộ kiểm ở trên, chứ không tin nguyên URL.
local function dest_from_referer(ref)
    if not ref or ref == "" then return nil end
    return safe_dest(ref:match("^https?://[^/]+(/[^%s]*)$"))
end

-- Chuỗi JSON. `safe_dest` đã loại ký tự điều khiển nên chỉ còn `"` và `\`.
local function json_str(s)
    return '"' .. s:gsub('[\\"]', "\\%0") .. '"'
end

local function grant_verified(ctx, id, verified_ttl, canvas_hash, dest_arg)
    -- Key 1: cookie key (primary)
    pool.safe_set("verified:" .. id, "1", verified_ttl)

    -- Key 2: early_id (ip+ua) — same-IP fallback
    local ua = ngx.var.http_user_agent or ""
    local early_id = identity_mod.build_from(ctx.ip, ua)
    if early_id and early_id ~= id then
        pool.safe_set("verified:" .. early_id, "1", verified_ttl)
    end

    -- Key 3: device fingerprint (ua+canvas) — IP-independent fallback.
    -- Thay JA3 bằng canvas vì kiến trúc no-stream không capture được JA3.
    -- Canvas ổn định theo GPU/driver, không phụ thuộc IP hay TLS stack.
    -- Handles: đổi mạng WiFi→4G, Safari ITP xóa cookie, cookie expire,
    --          iCloud Private Relay, DHCP reassign.
    local device_id = build_device_id(ua, canvas_hash)
    if device_id then
        pool.safe_set("verified:device:" .. device_id, "1", verified_ttl)
        -- Bind device_id với (UA, IP /16) để whitelist.lua lookup ANTI cross-
        -- network leak. Trước đây chỉ bind UA → bot rotate IP cross-country
        -- với UA phổ biến của user thật bypass toàn bộ verify chain.
        -- /16 vẫn cho phép user di chuyển trong cùng carrier (4G/WiFi VN).
        local ip = ctx.ip or ""
        local ip16 = ip:match("^(%d+%.%d+)%.")
        if ip16 then
            local ua_hash = ngx.md5(ua)
            local key     = "device_ua:" .. ua_hash .. ":" .. ip16
            pool.safe_set(key, device_id, verified_ttl)
            ngx.log(ngx.INFO, "[verify] device_canvas_id=", device_id:sub(1,8),
                    " canvas=", canvas_hash:sub(1,8),
                    " ip16=", ip16)
        else
            ngx.log(ngx.ERR, "[verify] cannot bind device — invalid IP format")
        end
    else
        ngx.log(ngx.DEBUG, "[verify] no device_id: canvas missing")
    end

    -- Cookie với Secure flag
    local scheme = ngx.var.scheme or "http"
    local cookie_flags = "antibot_fp=" .. id
        .. "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" .. tostring(verified_ttl)
    if scheme == "https" then
        cookie_flags = cookie_flags .. "; Secure"
    end
    ngx.header["Set-Cookie"] = cookie_flags

    ctx.verified = true
    ngx.log(ngx.INFO, "[verify] passed id=", id:sub(1,8),
            " ip=", ctx.ip or "?",
            " device_id=", device_id and device_id:sub(1,8) or "nil")

    -- ── ĐÁP LẠI MỘT `fetch`, KHÔNG PHẢI MỘT LẦN ĐIỀU HƯỚNG ──────────
    --
    -- Đây là chỗ hai nửa của tầng challenge từng nói hai ngôn ngữ khác nhau, và
    -- đó mới là lỗi — không phải một dòng nào sai.
    --
    -- Bản cũ trả về một TRANG HTML: `<meta refresh>` + `localStorage.setItem`
    -- + `window.location.replace(dest)`. Trang đó chỉ chạy nếu trình duyệt
    -- ĐIỀU HƯỚNG tới nó. Nhưng `challenge/init.lua` gửi bằng `fetch()`, và
    -- fetch VỨT thân phản hồi. Hậu quả dây chuyền:
    --   1. `localStorage.setItem('ab_token')` KHÔNG BAO GIỜ chạy — và cũng
    --      không nơi nào đọc `ab_token`, không nơi nào gửi nó lên lại. Một
    --      tính năng chết hoàn toàn.
    --   2. `window.location.replace(dest)` không chạy, nên client rơi xuống
    --      nhánh `window.location.href = returnUrl`, với
    --      `returnUrl = document.referrer || '/'`.
    --   3. Khách VÀO LẦN ĐẦU (gõ URL, bookmark, quét QR, mở từ app, click
    --      quảng cáo có `rel=noreferrer`) KHÔNG CÓ referrer → về thẳng `/`.
    --      Mọi liên kết sâu đều mất sau lần verify đầu tiên.
    --
    -- Và mỉa mai: máy chủ BIẾT đích đúng (nó nằm trong `dest`), rồi vứt đi vì
    -- client không đọc được câu trả lời.
    --
    -- Vì `issue_ls_token` luôn trả về giá trị (HMAC không hỏng), nhánh HTML là
    -- nhánh CHẠY THẬT, còn nhánh 302 đúng đắn thì không bao giờ tới. Tức một
    -- tính năng chết đã ép luồng đi vào đúng nhánh hỏng.
    --
    -- Nay trả về JSON — dạng mà một `fetch` ĐỌC ĐƯỢC. Giữ lại nhánh 302 thì
    -- cũng chạy, nhưng fetch tự đi theo redirect và TẢI TRANG ĐÍCH một lần vô
    -- ích trước khi trình duyệt điều hướng tới nó lần nữa.
    local dest = safe_dest(dest_arg)
              or dest_from_referer(ngx.var.http_referer)
              or "/"

    ngx.status = 200
    ngx.header["Content-Type"]  = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say('{"ok":true,"dest":' .. json_str(dest) .. '}')
    ngx.exit(200)
end

function _M.run(ctx)
    ngx.req.read_body()
    local args   = ngx.req.get_post_args()
    local token  = args and args.token
    local n_str  = args and args.n
    local fp_arg = args and args.fp

    if not token or not n_str then
        ctx.verified = false
        ngx.log(ngx.ERR, "[verify] missing token/n ip=", ctx.ip)
        ngx.exit(400)
        return false
    end

    local id = fp_arg or ngx.var.cookie_antibot_fp or nil
    if not id or id == "" then
        ctx.verified = false
        ngx.log(ngx.ERR, "[verify] missing identity ip=", ctx.ip)
        ngx.exit(400)
        return false
    end

    ctx.identity = id
    ctx.fp_light = id

    local difficulty = cfg.pow.difficulty
    local pow_hash   = sha256_hex(token .. n_str)

    if not pow_hash or pow_hash:sub(1, #difficulty) ~= difficulty then
        ngx.log(ngx.ERR, "[verify] PoW failed id=", id:sub(1,8))
        ctx.verified = false
        pool.safe_incr("viol:" .. id, cfg.ttl.violation)
        ngx.exit(403)
        return false
    end

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[verify] redis unavailable: ", tostring(err))
        ctx.verified = false; ngx.exit(500); return false
    end

    local deleted = red:del("nonce:" .. id)

    if deleted == 0 then
        local already = red:get("verified:" .. id)
        if already == ngx.null then already = nil end

        if already == "1" then
            -- Safe retry — đọc canvas từ Redis (đã lưu lần verify trước)
            local canvas_raw = red:get("fp:canvas:" .. id)
            if canvas_raw == ngx.null then canvas_raw = nil end
            pool.put(red)
            -- ERR chứ không INFO: đây là nhánh return SỚM, KHÔNG chạm
            -- consume_label → mọi verify đi lối này đều không sinh nhãn
            -- ground-truth. Cần thấy được tỷ lệ của nó.
            ngx.log(ngx.ERR, "[verify] retry_already_verified id=", id:sub(1,8))
            grant_verified(ctx, id, cfg.ttl.verified or 7200, canvas_raw or "", args and args.dest)
            return true
        end

        pool.put(red)
        ngx.log(ngx.ERR, "[verify] nonce not found (replay?) id=", id:sub(1,8))
        ctx.verified = false; ngx.exit(403); return false
    end

    local verified_ttl = cfg.ttl.verified or 7200
    local canvas_hash  = args and args.cv or ""
    local solve_ms     = args and args.sm or ""

    check_canvas_consistency(red, id, ctx.ip or "", canvas_hash)
    flag_fast_solve(red, id, solve_ms)
    consume_label(red, id, ctx)
    pool.put(red)

    grant_verified(ctx, id, verified_ttl, canvas_hash, args and args.dest)
    return true
end

function _M.handle()
    local ctx = ngx.ctx.antibot or {}
    ngx.ctx.antibot = ctx
    ctx.ip = ngx.var.remote_addr
    _M.run(ctx)
end

return _M
