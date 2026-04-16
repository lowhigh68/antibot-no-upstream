local _M = {}

local trigger = require "antibot.detection.browser.trigger"
local inject  = require "antibot.detection.browser.inject"
local collect = require "antibot.detection.browser.collect"
local store   = require "antibot.detection.browser.store"
local canvas  = require "antibot.detection.browser.canvas"
local webgl   = require "antibot.detection.browser.webgl"
local entropy = require "antibot.detection.browser.entropy"

function _M.run(ctx)
    collect.run(ctx)

    if ctx.browser then
        canvas.run(ctx)
        webgl.run(ctx)
        entropy.run(ctx)
        store.run(ctx)
    else
        trigger.run(ctx)
        -- Read inject_candidate (tentative flag from access phase).
        -- Do NOT read browser_needed here — that confirmed state is set later
        -- in header_filter_by_lua_block after verifying the actual response
        -- Content-Type. Reading it here would always return nil/false.
        if ctx.inject_candidate then
            inject.run(ctx)
        end
    end
end

return _M
