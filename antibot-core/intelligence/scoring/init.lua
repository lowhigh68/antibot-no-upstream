local _M = {}

-- `signal_merge.lua` và `context_vector.lua` ĐÃ BỊ XOÁ (2026-09-06).
--
-- Cả hai chạy trên MỌI request đã chấm điểm, dựng bảng, rồi không ai đọc:
--   signal_merge   → `ctx.signals`              — chỉ được ghi, không nơi nào đọc
--   context_vector → `ctx.context_multipliers`  — chỉ được ghi, không nơi nào đọc
--                    `ctx.is_api_request`       — chỉ được ghi, không nơi nào đọc
--
-- `compute.lua` là nơi DUY NHẤT dựng `ctx.score`, và nó đi thẳng từ
-- `DEFAULT_WEIGHTS` + `get_signal()`, không hề chạm vào ba trường trên. Nên hai
-- module kia là CPU đốt mỗi request để không đổi lấy gì.
--
-- Chúng còn kéo theo một tín hiệu chết nữa: `ja3_rep` trông như "có người
-- dùng" đúng vì hai module này đọc nó — mà chính chúng lại không được ai đọc.
-- Một tầng chết che một tầng chết.
local compute = require "antibot.intelligence.scoring.compute"

function _M.run(ctx)
    compute.run(ctx)
end

return _M
