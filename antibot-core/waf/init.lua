local _M = {}
local wp_paths = require "antibot.waf.wp_paths"

-- Tầng WAF. Khác mọi tầng khác ở MỘT điểm quyết định: nó chạy TRƯỚC các cửa
-- thoát tin cậy trong `init.lua`, không phải sau.
--
-- Vì sao. `init.lua:_M.run()` mở đầu bằng:
--
--     if check_verified_cookie(ctx) then return end        -- trước cả STEPS_COMMON
--     ...
--     if ctx.verified or ctx.whitelisted then return end
--
-- Cookie `antibot_fp` sống `cfg.ttl.verified` = 7200s. Với quản lý bot đó là
-- thiết kế đúng: giải PoW rồi thì đừng bắt giải lại. Với WAF thì đó là lỗ —
-- giải PoW một lần (`cfg.pow.difficulty = "000"`, trình duyệt xong trong vài
-- chục ms) là có HAI GIỜ upload webshell không bị soi một byte nào.
--
-- Antibot chấm điểm AI gửi request. WAF soi CÁI GÌ nằm trong request đó. Danh
-- tính đã xác minh không nói gì về nội dung, nên trần tin cậy không được phép
-- che tầng này. Đây là lý do `run_pre` tồn tại tách khỏi `STEPS_*`.
--
-- Đổi lại, tầng này phải RẺ và phải TỰ LO ctx: nó chạy trước `ctx_layer.init`
-- nên không có gì trong `ctx` ngoài những thứ tự nó điền.

function _M.run_pre(ctx)
    local uri = ngx.var.uri
    if not uri or uri == "" then return false end

    -- Loopback: wp-cron và health check nội bộ đi đường này. `$remote_addr` ở
    -- đây là IP client thật (không có upstream block) nên 127.0.0.1 đúng nghĩa
    -- là do chính máy phát ra. Không miễn cả dải private: LAN vẫn phải soi.
    local ip = ngx.var.remote_addr or ""
    if ip == "127.0.0.1" or ip == "::1" then return false end

    local host = ngx.var.host or "-"

    local rule_id = wp_paths.check(uri, host)
    if not rule_id then return false end

    local rule = wp_paths.RULES[rule_id]
    if not rule then return false end

    ctx.waf_hits = ctx.waf_hits or {}
    ctx.waf_hits[#ctx.waf_hits + 1] = {
        rule    = rule_id,
        target  = "URI",
        matched = uri,
        action  = rule.action,
        score   = rule.score,
    }

    if rule.action ~= "block" then
        -- Chỉ góp điểm. `engine.lua` quyết cùng ba tầng tin cậy
        -- (good_bot_verified / ip_shared_verified / auth_session_cap), đúng
        -- nguyên tắc: luật WAF ĐÓNG GÓP tín hiệu, không tự ra phán quyết.
        if (ctx.waf_wp_path or 0) < rule.score then
            ctx.waf_wp_path = rule.score
        end
        return false
    end

    -- `log_by_lua` chạy sau `ngx.exit`, nên phải đặt action/action_reason ở đây,
    -- nếu không antibot.log ra `reason=-`.
    ctx.action        = "block"
    ctx.action_reason = rule_id
    ctx.ip            = ctx.ip or ip
    ctx.req           = ctx.req or { uri = uri, host = host }

    -- ngx.ERR chứ không WARN: access phase, error_log per-domain ép mức `error`
    -- nên WARN bị lọc câm. Cùng lý do đã ghi trong wp_hardening.lua.
    ngx.log(ngx.ERR, "[waf] block rule=", rule_id,
            " ip=", ip, " host=", host, " uri=", uri:sub(1, 160))

    ngx.exit(403)
    return true
end

return _M
