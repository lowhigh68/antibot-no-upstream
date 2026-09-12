-- Sổ tên cookie mà TỪNG HOST thực sự cấp phát.
--
-- VẤN ĐỀ NÓ GIẢI. `session_richness` chỉ đếm KHỐI LƯỢNG cookie:
--     0.5*min(bytes/500,1) + 0.3*min(n/4,1) + 0.3*has_auth + 0.2*has_csrf
-- và `has_auth` CHỈ có nghĩa "có header Authorization". WordPress xác thực bằng
-- COOKIE, nên admin WordPress không bao giờ nhận 0,3 điểm đó — điểm của họ trần
-- ở 0,80, TRÙNG KHÍT với một scanner gửi 4 cookie rác nặng 500 byte. Đo
-- 2026-09-12 trên 5 máy: một trình dò `/cgi-bin/php5` vẫn đạt `richness >= 0.5`,
-- tức ngưỡng mà `auth_session_cap` dùng làm CỬA TIN CẬY.
--
-- Ý TƯỞNG. Cookie của người dùng thật do CHÍNH SITE ĐÓ cấp qua `Set-Cookie`;
-- cookie của scanner do nó tự bịa. Sổ này học tên cookie từ phản hồi, rồi cửa
-- tin cậy hỏi: request này có mang tên nào trong sổ của host không.
--
-- VÌ SAO HỌC chứ không dùng DANH SÁCH TÊN. Cookie đăng nhập của WordPress là
-- `wordpress_logged_in_<md5 của siteurl>` — hậu tố KHÁC NHAU ở từng site, nên
-- không danh sách tĩnh nào viết ra được. Học thì bắt đúng tên thật. Và nó tự
-- đúng với Joomla, Laravel, app tự viết — những thứ một danh sách sẽ bỏ sót.
--
-- BA TRẠNG THÁI, và đây là toàn bộ tính an toàn FP của nó:
--   true  = host này có sổ, và request mang ít nhất một tên trong sổ
--   false = host này CÓ sổ, và request KHÔNG mang tên nào trong đó
--   nil   = host này CHƯA có sổ  -> cửa tin cậy giữ nguyên hành vi cũ
-- Cửa chỉ được phép SIẾT khi có hiểu biết dương tính (`false`). Không biết thì
-- không siết. Nhờ vậy ngày bật lên, không một host nào đổi hành vi cho tới khi
-- nó tự học xong.
--
-- GIỚI HẠN, ghi thẳng để không ai tưởng đã kín: một kẻ tấn công chịu khó gửi
-- một request thường trước để nhận `PHPSESSID` rồi mang nó theo thì qua được
-- cửa này. Nó KHÔNG chứng minh "đã đăng nhập" — nó chứng minh "đã từng nói
-- chuyện với chính site này". Đổi lại, dân số scanner đo được (gửi cùng một mớ
-- cookie rác cho mọi host) thì trượt sạch.
--
-- KHOÁ THEO `server_name`, KHÔNG theo `Host`. `Host` do client gửi nên giả
-- được — đúng lỗ đã làm hỏng việc đánh dấu host WordPress trước đây (một
-- `GET /wp-admin/` với Host giả ghi cờ 30 ngày cho host bất kỳ). `server_name`
-- là tên vhost đã khớp. Thêm một lợi ích: domain pointer/alias dùng chung một
-- sổ, đúng với thực tế chúng dùng chung docroot.
local _M = {}

local pool  = require "antibot.core.redis_pool"
local cache = ngx.shared.antibot_cache

local KEY      = "waf:ckn:"
local TTL      = 2592000   -- 30 ngày: sổ phải sống lâu hơn mọi kỳ nghỉ của admin
local LIST_TTL = 300       -- shm: nhớ danh sách của host trong 5 phút
local SEEN_TTL = 3600      -- shm: nhớ "tên này học rồi" trong 1 giờ

-- TRẦN CHỐNG PHÌNH. Một site trên hosting chia sẻ có thể `Set-Cookie` bao nhiêu
-- tên tuỳ ý — kể cả tên sinh ngẫu nhiên mỗi request. Không có trần thì khoá
-- Redis phình vô hạn và `antibot_cache` bị đá hết sạch, đúng lớp lỗi đã cắn ở
-- `wp_paths`. 24 tên là dư cho mọi CMS thật (WordPress đầy đủ dùng ~6).
local MAX_NAMES = 24
local MAX_LEN   = 512

-- Bộ ký tự cookie-name hợp lệ theo RFC 6265, TRỪ dấu phẩy — vì dấu phẩy là ký
-- tự phân cách của chính chuỗi lưu trong Redis. Một tên chứa nó sẽ tự chẻ thành
-- hai mục và làm hỏng sổ.
local NAME_OK = "^[A-Za-z0-9_%-%.~%$%*%+!'%%&#^`|]+$"

local function host_key()
    -- `server_name` rỗng hoặc `_` ở khối catch-all: lùi về `host`. Trần MAX_NAMES
    -- vẫn chặn phình, và catch-all thì mọi tên dồn vào một sổ — chấp nhận được,
    -- vì đó là đường lùi chứ không phải đường chính.
    local h = ngx.var.server_name
    if not h or h == "" or h == "_" then h = ngx.var.host end
    if not h or h == "" then return nil end
    return h
end

-- Tên cookie trong một chuỗi `Set-Cookie`: phần trước dấu `=` đầu tiên.
local function cookie_name(sc)
    if type(sc) ~= "string" then return nil end
    local eq = sc:find("=", 1, true)
    if not eq or eq < 2 then return nil end
    local name = sc:sub(1, eq - 1):gsub("^%s+", ""):gsub("%s+$", "")
    if #name == 0 or #name > 64 then return nil end
    if not name:match(NAME_OK) then return nil end
    return name
end

-- ── HỌC — chạy ở LOG PHASE ──────────────────────────────────────────
--
-- COSOCKET BỊ CẤM ở `log_by_lua`, nên mọi phép chạm Redis phải qua
-- `ngx.timer.at(0, ...)`. Gọi thẳng `pool.safe_*` ở đây sẽ hỏng TRONG IM LẶNG —
-- đúng thứ đã giết `wp_paths.mark()` bốn tháng.
--
-- Đường nhanh không chạm Redis: `antibot_cache` nhớ từng (host, tên) trong 1
-- giờ, nên một site đang chạy chỉ sinh vài phép ghi mỗi giờ chứ không phải mỗi
-- lần `Set-Cookie`.
function _M.learn(ctx)
    if not cache then return end

    local ok, headers = pcall(ngx.resp.get_headers)
    if not ok or not headers then return end
    local sc = headers["set-cookie"]
    if not sc then return end
    if type(sc) == "string" then sc = { sc } end

    local host = host_key()
    if not host then return end

    local fresh
    for i = 1, #sc do
        local name = cookie_name(sc[i])
        if name then
            local seen_key = "ckn1:" .. host .. ":" .. name
            if not cache:get(seen_key) then
                cache:set(seen_key, 1, SEEN_TTL)
                fresh = fresh or {}
                fresh[#fresh + 1] = name
            end
        end
    end
    if not fresh then return end

    ngx.timer.at(0, function(premature)
        if premature then return end
        local rkey = KEY .. host
        local cur  = pool.safe_get(rkey) or ""

        local have, n = {}, 0
        for nm in cur:gmatch("[^,]+") do
            have[nm] = true
            n = n + 1
        end

        local added = false
        for i = 1, #fresh do
            local nm = fresh[i]
            if not have[nm] and n < MAX_NAMES
               and (#cur + #nm + 1) <= MAX_LEN then
                cur   = (cur == "") and nm or (cur .. "," .. nm)
                have[nm] = true
                n     = n + 1
                added = true
            end
        end

        -- Ghi kể cả khi không thêm tên nào? KHÔNG. Chỉ ghi khi sổ thực sự đổi.
        -- Ghi lại y nguyên chỉ để gia hạn TTL sẽ biến "30 ngày" thành vĩnh viễn
        -- chừng nào site còn chạy — đúng lỗi tự-gia-hạn đã sửa ở
        -- `session_richness` (`richness:max:<id>`). Sổ phải tự hết hạn nếu site
        -- ngừng cấp cookie.
        if added then
            pool.safe_set(rkey, cur, TTL)
            -- Đẩy bản mới vào shm ngay để phía đọc không phải chờ hết 5 phút.
            cache:set("cknl:" .. host, cur, LIST_TTL)
        end
    end)
end

-- ── DÙNG — chạy ở ACCESS PHASE ──────────────────────────────────────
--
-- Cosocket dùng được ở đây, nhưng vẫn đệm qua `antibot_cache` 5 phút: một
-- `safe_get` cho mỗi host mỗi 5 phút thay vì mỗi request.
--
-- Trả về true / false / nil — xem khối đầu file. `nil` KHÔNG được phép biến
-- thành `false` ở bất kỳ chỗ nào phía sau.
function _M.known(ctx, cookie_header)
    if not cookie_header or cookie_header == "" then return nil end

    local host = host_key()
    if not host then return nil end

    local list
    if cache then
        list = cache:get("cknl:" .. host)
    end
    if list == nil then
        list = pool.safe_get(KEY .. host) or ""
        if cache then cache:set("cknl:" .. host, list, LIST_TTL) end
    end
    -- Chưa học được gì về host này: KHÔNG biết, không phải "không có".
    if list == "" then return nil end

    local have = {}
    for nm in list:gmatch("[^,]+") do have[nm] = true end

    for pair in cookie_header:gmatch("[^;]+") do
        local nm = pair:match("^%s*([^=%s]+)")
        if nm and have[nm] then return true end
    end
    return false
end

return _M
