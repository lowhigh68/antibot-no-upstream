local _M    = {}
local pool  = require "antibot.core.redis_pool"
local cjson = require "cjson.safe"

-- Auto-seed Redis với default good-bot DNS registry từ JSON data file.
-- Chỉ ghi key chưa tồn tại → admin override qua redis-cli SET vẫn được giữ.
-- Path tương đối với nginx prefix: /usr/local/openresty/nginx/.
-- Khi deploy via git pull, file goodbot.json đi cùng codebase → auto sync.

local CONFIG_PATH = ngx.config.prefix() .. "conf/antibot/core/data/goodbot.json"

function _M.run()
    local f, err = io.open(CONFIG_PATH, "r")
    if not f then
        ngx.log(ngx.ERR,
            "[goodbot_seed] config missing: ", CONFIG_PATH,
            " err=", tostring(err),
            " — antibot deploy không đầy đủ, kiểm tra file bằng git pull")
        return
    end
    local content = f:read("*a")
    f:close()

    local data, perr = cjson.decode(content)
    if not data or not data.bots then
        ngx.log(ngx.ERR,
            "[goodbot_seed] invalid JSON: ", tostring(perr),
            " — file ", CONFIG_PATH, " bị corrupt")
        return
    end

    local seeded, skipped = 0, 0
    for name, suffixes in pairs(data.bots) do
        if type(suffixes) == "table" and #suffixes > 0 then
            local key = "goodbot:dns:" .. name
            local existing = pool.safe_get(key)
            if existing and existing ~= "" then
                -- Admin đã set sẵn (override) → không ghi đè
                skipped = skipped + 1
            else
                pool.safe_set(key, table.concat(suffixes, ","))
                seeded = seeded + 1
            end
        end
    end

    ngx.log(ngx.INFO,
        "[goodbot_seed] version=", data.version or "?",
        " seeded=", seeded,
        " skipped=", skipped,
        " (skipped = admin override sẵn, không ghi đè)")
end

return _M
