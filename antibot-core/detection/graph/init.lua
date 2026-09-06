local _M = {}

-- `collect_path.lua` và `graph_score.lua` ĐÃ BỊ XOÁ (2026-09-06).
--   collect_path → `ctx.path = ctx.session or {}` : không nơi nào đọc `ctx.path`
--   graph_score  → `ctx.graph_score = ctx.graph_score or 0.0` và cùng thế với
--                  `graph_flag`. Cả hai đã được `core/ctx/init.lua` khởi tạo
--                  0.0, nên `or` không bao giờ chạy vế phải: module này KHÔNG
--                  tạo ra điểm nào. Giá trị thật của `graph_flag` do
--                  `pattern_detect.lua` ghi, ngay trước đó.
local seq_builder  = require "antibot.detection.graph.sequence_builder"
local pattern      = require "antibot.detection.graph.pattern_detect"

function _M.run(ctx)
    seq_builder.run(ctx)
    pattern.run(ctx)
end

return _M
