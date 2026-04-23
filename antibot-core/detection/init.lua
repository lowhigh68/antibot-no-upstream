local _M = {}

local anomaly      = require "antibot.detection.anomaly"
local behavior     = require "antibot.detection.behavior"
local bot          = require "antibot.detection.bot"
local browser      = require "antibot.detection.browser"
local cluster      = require "antibot.detection.cluster"
local graph        = require "antibot.detection.graph"
local session      = require "antibot.detection.session"
local wp_hardening = require "antibot.detection.wp_hardening"

local function should_run(ctx, layer_name)
    local skip = ctx.skip_layers
    if not skip then return true end
    return not skip[layer_name]
end

function _M.run(ctx)

    if should_run(ctx, "bot") then
        bot.run(ctx)
    end

    if should_run(ctx, "anomaly") then
        anomaly.run(ctx)
    end

    if should_run(ctx, "behavior") then
        behavior.run(ctx)
    end

    if should_run(ctx, "session") then
        session.run(ctx)
    end

    -- wp_hardening: signals WordPress-specific cho POST wp-login.php/xmlrpc.php.
    -- Chạy sau session để query sess_nav:<fp> phản ánh cả request hiện tại.
    -- Không qua should_run vì api_callback class skip session — nhưng bruteforce
    -- bot POST không Sec-Fetch chính là api_callback và đây là case cần bắt nhất.
    wp_hardening.run(ctx)

    if should_run(ctx, "cluster") then
        cluster.run(ctx)
    end

    if should_run(ctx, "graph") then
        graph.run(ctx)
    end

    if should_run(ctx, "browser") then
        browser.run(ctx)
    end

    return true, false
end

return _M
