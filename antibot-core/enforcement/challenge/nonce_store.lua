local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

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
local function clean(s)
    return (tostring(s or "-"):gsub("[|\r\n]", "/"))
end

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

function _M.run(ctx, nonce)
    local id = ctx.identity or ctx.fp_light
    if not id or not nonce then return false end

    local red, err = pool.get()
    if not red then return false end

    local ok = red:setnx("nonce:" .. id, nonce)
    if ok == 1 then
        red:expire("nonce:" .. id, cfg.ttl.nonce)
        -- Cùng TTL với nonce: nhãn chỉ có nghĩa trong đúng vòng thách đố này.
        red:setex("label:" .. id, cfg.ttl.nonce, build_label(ctx))
    end
    pool.put(red)

    if ok ~= 1 then
        ngx.log(ngx.WARN, "[nonce] replay attempt or collision id=", id)
        return false
    end
    return true
end

return _M
