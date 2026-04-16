local _M = {}

local function detect_loop(seq)
    if #seq < 3 then return 0.0 end
    local counts = {}
    for _, uri in ipairs(seq) do
        counts[uri] = (counts[uri] or 0) + 1
    end
    local max_count = 0
    for _, c in pairs(counts) do
        if c > max_count then max_count = c end
    end
    if max_count >= 4 then return 0.9
    elseif max_count == 3 then return 0.6
    elseif max_count == 2 then return 0.2
    end
    return 0.0
end

local function detect_sequential_scan(seq)
    if #seq < 4 then return 0.0 end
    local numeric_seq = 0
    local prev_n = nil
    for _, uri in ipairs(seq) do
        local n = tonumber(uri:match("/(%d+)$") or uri:match("=(%d+)$"))
        if n and prev_n and n == prev_n + 1 then
            numeric_seq = numeric_seq + 1
        end
        prev_n = n
    end
    if numeric_seq >= 3 then return 0.8 end
    return 0.0
end

local function detect_single_page(seq)
    if #seq < 5 then return 0.0 end
    local first = seq[1]
    local all_same = true
    for _, uri in ipairs(seq) do
        if uri ~= first then all_same = false; break end
    end
    return all_same and 0.95 or 0.0
end

function _M.run(ctx)
    local seq = ctx.seq or {}
    if #seq == 0 then ctx.graph_flag = 0.0; return end

    local loop_score  = detect_loop(seq)
    local scan_score  = detect_sequential_scan(seq)
    local single_score= detect_single_page(seq)

    ctx.graph_flag = math.min(1.0, math.max(loop_score, scan_score, single_score))

    if ctx.graph_flag > 0.5 then
        ngx.log(ngx.DEBUG, "[graph] pattern detected flag=",
            string.format("%.2f", ctx.graph_flag),
            " seq_len=", #seq)
    end
end

return _M
