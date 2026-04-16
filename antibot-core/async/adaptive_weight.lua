local _M   = {}
local pool = require "antibot.core.redis_pool"
local cfg  = require "antibot.core.config"

local LEARN_RATE_FP  = 0.02
local LEARN_RATE_FN  = 0.05
local MIN_WEIGHT     = 5
local MAX_WEIGHT     = 100

function _M.run(ctx, feedback)
    if not feedback then return end

    local top = ctx.top_signals
    if not top or #top == 0 then return end

    ngx.timer.at(0, function()
        local red, err = pool.get()
        if not red then return end

        for _, sig in ipairs(top) do
            local name   = sig.signal
            if not name then goto continue end

            local current = tonumber(red:hget("model:weight", name))
                         or cfg.weights[name]
                         or 20

            local new_w
            if feedback == "tp" then
                new_w = current + LEARN_RATE_FP * current
            elseif feedback == "fp" then
                new_w = current - LEARN_RATE_FN * current
            end

            if new_w then
                new_w = math.max(MIN_WEIGHT, math.min(MAX_WEIGHT, new_w))
                red:hset("model:weight", name,
                         string.format("%.2f", new_w))
            end

            ::continue::
        end

        pool.put(red)
    end)
end

return _M
