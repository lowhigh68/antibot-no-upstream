local _M    = {}
local pool  = require "antibot.core.redis_pool"
local cjson = require "cjson.safe"

-- Auto-seed Redis với default good-bot DNS registry từ JSON data file.
-- `goodbot.json` là NGUỒN CHUẨN: mỗi lần reload, seed ghi đè khoá của chính nó
-- bằng nội dung file, và chỉ chừa lại mục người vận hành đặt tạm (nhận ra qua
-- TTL — xem khối chú thích trong `run()`).
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

    -- ── TTL LÀ DẤU VẾT NGUỒN GỐC (2026-08-31) ─────────────────
    -- Bản cũ: "chỉ ghi khoá CHƯA tồn tại". Một dòng, hai lỗi:
    --
    --   1. SỬA SUFFIX TRONG `goodbot.json` KHÔNG CÓ TÁC DỤNG. Khoá đã tồn tại
    --      ⇒ rơi vào nhánh `skipped` ⇒ file đổi, Redis đứng yên. Không log,
    --      không lỗi. Đổi `googlebot` xong reload rồi tưởng đã xong.
    --   2. GỠ MỘT TÊN KHỎI FILE KHÔNG GỠ KHỎI REDIS. Khoá không TTL, sống mãi.
    --      `deploy.sh` (dòng ~141) ghi lại đã trả giá hai lần, ahrefsbot là ca
    --      gần nhất; nó phải mọc thêm cờ `--goodbot <tên>` để xoá tay.
    --
    -- Cách phân biệt "khoá của seed" với "override người vận hành cố ý đặt" mà
    -- KHÔNG cần thêm khoá đánh dấu: dùng chính TTL.
    --
    --   TTL = -1  (có khoá, không hạn)  → của seed  → GHI ĐÈ bằng nội dung file
    --   TTL = -2  (không có khoá)       → chưa seed → GHI MỚI
    --   TTL >= 0  (có hạn)              → admin đặt tạm → GIỮ, để nó tự hết hạn
    --
    -- `admin/init.lua` giờ ghi mục thêm tay bằng `SETEX` 7 ngày, nên nó rơi vào
    -- nhánh thứ ba. Hết hạn thì lượt reload kế tiếp seed lại từ file ⇒ hệ tự
    -- kéo về đúng nội dung trong git. Cùng nguyên tắc fail-closed của khoá
    -- `mon:` bên enforcement: hỏng thì siết, không phải hỏng thì mở.
    --
    -- ⚠ ĐỔI HÀNH VI: chú thích đầu file trước đây hứa "admin override qua
    -- redis-cli SET vẫn được giữ". KHÔNG CÒN ĐÚNG — `SET` trần không TTL giờ
    -- bị coi là khoá của seed và sẽ bị ghi đè. Muốn đè tay thì dùng
    -- `SET goodbot:dns:<tên> "<suffixes>" EX 604800`, hoặc bấm nút trên admin.
    --
    -- Vẫn KHÔNG tự xoá khoá thừa (kiểu ahrefsbot): TTL phân biệt được "seed" với
    -- "admin đặt tạm", nhưng không phân biệt được "seed đời cũ" với "ai đó cố ý
    -- SET tay từ trước khi có quy ước này". Xoá nhầm một bot đang chạy tệ hơn
    -- giữ một khoá thừa, nên việc đó vẫn để `deploy.sh --goodbot <tên>`.

    local names, values = {}, {}
    for name, suffixes in pairs(data.bots) do
        if type(suffixes) == "table" and #suffixes > 0 then
            names[#names + 1]  = name
            values[#names]     = table.concat(suffixes, ",")
        end
    end

    -- Một round-trip cho toàn bộ registry thay vì 41 lượt `safe_get`.
    local ttls, perr = pool.pipeline(function(red)
        for i = 1, #names do
            red:ttl("goodbot:dns:" .. names[i])
        end
    end)
    if not ttls then
        ngx.log(ngx.ERR,
            "[goodbot_seed] pipeline TTL lỗi: ", tostring(perr),
            " — BỎ QUA lượt seed này, registry giữ nguyên trạng")
        return
    end

    local to_write = {}
    local kept = 0
    for i = 1, #names do
        -- Đọc hỏng ⇒ mặc định GHI. Hai kiểu hỏng, chọn kiểu nhẹ hơn: ghi đè
        -- nhầm một override tạm (mất sớm vài ngày) nhẹ hơn là không ghi và để
        -- nội dung file không bao giờ tới được Redis — đúng lỗi đang sửa.
        local ttl = tonumber(ttls[i]) or -2
        if ttl >= 0 then
            kept = kept + 1
        else
            to_write[#to_write + 1] = i
        end
    end

    local written = 0
    if #to_write > 0 then
        local ok3, werr = pool.pipeline(function(red)
            for _, i in ipairs(to_write) do
                red:set("goodbot:dns:" .. names[i], values[i])
            end
        end)
        if ok3 then
            written = #to_write
        else
            ngx.log(ngx.ERR, "[goodbot_seed] pipeline SET lỗi: ", tostring(werr))
        end
    end

    -- Seed ptr_only flags. Bot trong list này skip forward DNS check
    -- vì rotating IP pool (Meta crawler infra) khiến forward A trả về
    -- IP khác trong pool → fail oan.
    -- Ghi vô điều kiện: giá trị luôn là "1" nên ghi đè là no-op, và không có
    -- đường admin nào ghi khoá này nên không có override cần bảo vệ.
    local ptr_only_count = 0
    if type(data.ptr_only) == "table" and #data.ptr_only > 0 then
        pool.pipeline(function(red)
            for _, name in ipairs(data.ptr_only) do
                red:set("goodbot:ptr_only:" .. name:lower(), "1")
            end
        end)
        ptr_only_count = #data.ptr_only
    end

    ngx.log(ngx.WARN,
        "[goodbot_seed] version=", data.version or "?",
        " total=", #names,
        " written=", written,
        " kept_override=", kept,
        " ptr_only=", ptr_only_count,
        " (written = đồng bộ từ goodbot.json; kept_override = mục thêm tay còn hạn)")
end

return _M
