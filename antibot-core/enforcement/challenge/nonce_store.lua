local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

-- ── TRẠNG THÁI CỦA MỘT LẦN THÁCH ĐỐ, KHOÁ THEO LẦN — KHÔNG THEO DANH TÍNH ──
--
-- Bản trước lưu `nonce:<identity>` bằng **SETNX**, và `challenge/init.lua`
-- **bỏ qua kết quả trả về**. Hai tab, hoặc một lần F5, sẽ nhận một token MỚI
-- trong khi Redis vẫn giữ nonce CŨ. Lỗi đó tồn tại được vì `verify_token`
-- không hề kiểm token có phải do máy chủ phát hành hay không — nó chỉ kiểm
-- `nonce:<id>` còn tồn tại rồi xoá. Tức là **một lỗi đang che một lỗi khác**:
-- sửa phần kiểm token mà giữ nguyên SETNX thì lỗi kia lập tức thành lỗi verify
-- thật, và nạn nhân đúng là người mở hai tab.
--
-- Nên khoá đổi từ danh tính sang **một mã ngẫu nhiên cho mỗi lần thách đố**:
--
--   chal:<challenge_id> = identity | md5(token) | difficulty | issued_at
--
-- Hai tab ⇒ hai `challenge_id` ⇒ hai bản ghi độc lập ⇒ cả hai giải được. Và
-- `SETEX` thay `SETNX`: không còn khoá nào để đụng nên không còn gì để chối.
--
-- Lưu **md5 của token**, không lưu token: một lần lỡ `MONITOR`/dump Redis thì
-- không ai cầm được token còn hiệu lực. Với mục đích này md5 là đủ — thứ cần
-- là kháng tiền ảnh trên một chuỗi 256-bit ngẫu nhiên, không phải kháng va chạm.
local function clean(s)
    return (tostring(s or "-"):gsub("[|\r\n]", "/"))
end

-- Ảnh chụp bối cảnh lúc PHÁT thách đố, để đối chiếu khi client GIẢI được.
--
-- Vì sao cần: hệ thống KHÔNG có nguồn ground-truth nào. `async/adaptive_weight.lua`
-- được viết để nhận feedback nhưng không ai gọi nó với feedback → code chết. Mọi
-- lần hiệu chỉnh trọng số tới nay đều là bới log thủ công và suy đoán.
-- Client giải được PoW thì gần như chắc chắn là trình duyệt thật ⇒ mọi signal
-- đứng trong top-3 của chính request bị thách đố đó là ỨNG VIÊN FP.
--
-- Thiên lệch phải nhớ khi đọc số: chỉ dán nhãn được dải `challenge` (request bị
-- `block` không có cơ hội giải), và bot render JS cũng giải được — đã xảy ra
-- 2026-07-07 với crawler của Meta. Cờ cuối cùng đánh dấu UA tự khai là bot để
-- `verify_token` loại khỏi mẫu.
--
-- Định dạng: score|eff|class|reason|top_signals|mm_rules|ua_claims_bot
--
-- BẮT BUỘC làm sạch `|` khỏi mọi trường: `ctx.action_reason` do
-- `enforcement/explain.lua` dựng ra **đã chứa sẵn `|`** (dạng
-- "score=66.6 class=navigation | top:[...] | rules:[]") → không làm sạch thì nó
-- tự tách thành nhiều trường và đẩy lệch toàn bộ chỉ số phía sau.
local function build_label(ctx)
    local names = {}
    if type(ctx.top_signals) == "table" then
        for i, s in ipairs(ctx.top_signals) do
            names[i] = tostring(s.signal or s.name or "?")
        end
    end
    local ua_l = (ctx.ua or ""):lower()
    local bot_claim = (ua_l:find("bot", 1, true)
                    or ua_l:find("spider", 1, true)
                    or ua_l:find("crawler", 1, true)) and "1" or "0"
    return string.format("%.1f|%.1f|%s|%s|%s|%s|%s",
        ctx.score or 0,
        ctx.effective_score or 0,
        clean(ctx.req_class),
        clean(ctx.action_reason):sub(1, 48),
        clean(table.concat(names, ",")),
        clean(ctx.mm_rules),
        bot_claim)
end

-- `math.randomseed` KHÔNG được gọi ở bất kỳ đâu trong cây nguồn này, nên
-- `math.random` trả về CÙNG MỘT DÃY sau mỗi lần khởi động, ở mọi worker. Với
-- một khoá Redis thì đó là đụng khoá hàng loạt: hai worker phát hai thách đố
-- khác nhau nhưng cùng `challenge_id`, bản sau đè bản trước, và người đến
-- trước ăn 403. Nên mã này lấy từ nguồn ngẫu nhiên thật của OpenResty.
local random_ok, random = pcall(require, "resty.random")

local function to_hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function new_cid(id)
    if random_ok and random and random.bytes then
        local b = random.bytes(16, true)
        if b and #b == 16 then return to_hex(b) end
    end
    -- Đường lùi khi không có `resty.random`: `$request_id` do chính nginx sinh
    -- ra cho mỗi request (16 byte ngẫu nhiên). Vẫn KHÔNG dùng `math.random`.
    return ngx.md5(tostring(ngx.var.request_id or "")
                   .. "|" .. tostring(ngx.worker.pid())
                   .. "|" .. tostring(ngx.now())
                   .. "|" .. tostring(id))
end

function _M.run(ctx)
    local id = ctx.identity or ctx.fp_light
    if not id or id == "" or not ctx.token or ctx.token == "" then
        ngx.log(ngx.ERR, "[challenge] thieu identity hoac token, khong luu duoc")
        return false
    end

    local difficulty = (ctx.pow and ctx.pow.difficulty)
                    or (cfg.pow and cfg.pow.difficulty) or "000"
    local cid = new_cid(id)
    local rec = table.concat({
        id, ngx.md5(ctx.token), difficulty, tostring(ngx.time())
    }, "|")

    local red, err = pool.get()
    if not red then
        ngx.log(ngx.ERR, "[challenge] redis unavailable: ", tostring(err))
        return false
    end

    local ttl = cfg.ttl.nonce
    local ok, serr = red:setex("chal:" .. cid, ttl, rec)
    if ok then
        -- Nhãn cũng khoá theo LẦN thách đố. Trước đây là `label:<identity>`,
        -- nên hai tab thì tab sau ghi đè nhãn của tab trước và mẫu
        -- ground-truth bị gán sai bối cảnh.
        red:setex("label:" .. cid, ttl, build_label(ctx))
    end
    pool.put(red)

    if not ok then
        ngx.log(ngx.ERR, "[challenge] khong ghi duoc chal:", cid,
                " err=", tostring(serr))
        return false
    end

    ctx.challenge_id = cid
    return true
end

return _M
